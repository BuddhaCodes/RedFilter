using System.Collections.ObjectModel;
using System.IO;
using Avalonia.Threading;
using RedFilter.Core.Processes;
using RedFilter.Core.Qos;
using RedFilter.Core.Settings;
using RedFilter.Core.Text;
using RedFilter.Platform;

namespace RedFilter.ViewModels;

public sealed class NetworkViewModel : ObservableObject, IDisposable
{
    private readonly IProcessNetworkSource _source;
    private readonly IQosPolicyStore _qos;
    private readonly SettingsStore _store;
    private readonly IQosElevation? _elevationBroker;
    private readonly Action? _shutdown;
    private readonly IUserPrompt? _prompt;
    private readonly CancellationTokenSource _cancel = new();
    private readonly string? _selfPath = Environment.ProcessPath;

    // Every QoS change (apply, reconcile, turn off) runs under this gate, so an in-flight reconcile
    // can never re-create policies right after "Turn filter off" removed them.
    private readonly SemaphoreSlim _qosGate = new(1, 1);
    private readonly HashSet<string> _limitedPaths = new(StringComparer.OrdinalIgnoreCase);

    // "Only the game has internet": Windows Firewall blocks for every other program using the network.
    private readonly IFirewallBlockStore? _firewall;
    private readonly HashSet<string> _blockedPaths = new(StringComparer.OrdinalIgnoreCase);
    private volatile SoloGameOptions? _solo;
    private string? _firewallFingerprint;
    private DateTime _lastFirewallCheckUtc = DateTime.MinValue;
    private int _blockedCount;
    private static readonly TimeSpan ReconcileInterval = TimeSpan.FromSeconds(2);
    private static readonly TimeSpan VerifyInterval = TimeSpan.FromSeconds(60);
    private static readonly TimeSpan SnapshotMaxAge = TimeSpan.FromSeconds(3);

    private string _ownerText = "Ningún programa tiene prioridad. La red se reparte con normalidad.";
    private string _status = "Leyendo programas…";
    private string _elevation = "";
    private bool _filterOn;
    private bool _busy;
    private bool _isAdmin;
    private ProcessRowViewModel? _selected;
    private ThrottleChoice? _throttle;
    private volatile string? _ownerPath;
    private int? _ownerPid;
    private QosLaunchRequest? _pendingLaunch;
    private volatile bool _filterActive;
    private long _throttleBits;
    private DateTime _lastReconcileUtc = DateTime.MinValue;
    private DateTime _lastVerifyUtc = DateTime.MinValue;
    private string? _appliedFingerprint;
    private volatile SnapshotStamp? _latest;
    private int _started;

    public NetworkViewModel(
        IProcessNetworkSource source,
        IQosPolicyStore qos,
        SettingsStore store,
        bool isAdmin,
        QosLaunchRequest? pendingLaunch = null,
        IQosElevation? elevation = null,
        Action? shutdown = null,
        IUserPrompt? prompt = null,
        IFirewallBlockStore? firewall = null)
    {
        _firewall = firewall;
        _source = source;
        _qos = qos;
        _store = store;
        _isAdmin = isAdmin;
        _pendingLaunch = isAdmin ? pendingLaunch : null;
        _elevationBroker = elevation;
        _shutdown = shutdown;
        _prompt = prompt;
        ThrottleChoices = new ObservableCollection<ThrottleChoice>
        {
            new() { Label = "256 Kbps (estricto)", BitsPerSecond = 256_000 },
            new() { Label = "1 Mbps (equilibrado)", BitsPerSecond = 1_000_000 },
            new() { Label = "5 Mbps (suave)", BitsPerSecond = 5_000_000 }
        };
        var settings = store.Load();
        _throttle = ThrottleChoices.FirstOrDefault(choice => choice.BitsPerSecond == settings.ThrottleBitsPerSecond)
            ?? ThrottleChoices[1];
        _throttleBits = _throttle.BitsPerSecond;
        _ownerPath = settings.NetworkOwnerPath;
        _ownerPid = settings.NetworkOwnerPid;
        if (isAdmin)
        {
            Elevation = "Abierto como administrador.";
        }
        else
        {
            Elevation = "Windows pedirá permiso de administrador al priorizar.";
            Status = "Leyendo programas…";
        }
    }

    public ObservableCollection<ProcessRowViewModel> Processes { get; } = new();

    /// <summary>Programs using the network right now, one row per program, busiest first.</summary>
    public ObservableCollection<ProgramRow> Programs { get; } = new();

    public bool VpnActive { get => _vpnActive; set { if (Set(ref _vpnActive, value)) Raise(nameof(VpnNote)); } }
    public string VpnName { get => _vpnName; set { if (Set(ref _vpnName, value)) Raise(nameof(VpnNote)); } }
    public string VpnNote => VpnActive
        ? $"{VpnName} está activo: todo sale cifrado por el túnel, así que la prioridad por programa puede no notarse. Lo que sí funciona es dar prioridad a este PC en el router."
        : "";
    private bool _vpnActive;
    private string _vpnName = "";

    public bool IsAdmin => _isAdmin;

    /// <summary>True while other programs on this PC are cut off from the internet.</summary>
    public bool SoloGameOn => _solo != null;
    public int BlockedCount => _blockedCount;

    /// <summary>
    /// Cuts every other program using the network off from the internet with Windows Firewall, except
    /// Windows itself, the game's folder, Steam and (optionally) Discord. New programs are blocked as
    /// they appear. Needs administrator rights; returns false without them. Called again while on, it
    /// only changes the exceptions: programs blocked so far stay blocked unless the new options keep them.
    /// </summary>
    public async Task<bool> StartSoloGameAsync(SoloGameOptions options)
    {
        if (!_isAdmin || _firewall == null)
            return false;
        _solo = options;
        _firewallFingerprint = null;
        var settings = _store.Load();
        settings.FirewallBlocksActive = true;
        _store.Save(settings);
        await ReconcileFirewallAsync();
        return _solo != null;
    }

    /// <summary>Removes every block RedFilter added, so all programs get their internet back.</summary>
    public async Task StopSoloGameAsync()
    {
        _solo = null;
        if (_firewall == null || !_isAdmin)
            return;
        await _qosGate.WaitAsync(_cancel.Token);
        try
        {
            await _firewall.RemoveAllAsync(_cancel.Token);
            _blockedPaths.Clear();
            _firewallFingerprint = null;
            _blockedCount = 0;
            var settings = _store.Load();
            settings.FirewallBlocksActive = false;
            _store.Save(settings);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            Status = "No se pudieron quitar los bloqueos del firewall: " + ex.Message;
        }
        finally
        {
            _qosGate.Release();
        }
    }

    // Programs that start using the network while the mode is on are blocked too. Programs blocked
    // earlier stay blocked even though they have no connections any more (that is the point).
    private async Task ReconcileFirewallAsync()
    {
        var solo = _solo;
        if (solo == null || _firewall == null)
            return;
        _lastFirewallCheckUtc = DateTime.UtcNow;
        await _qosGate.WaitAsync(_cancel.Token);
        try
        {
            if (_solo == null)
                return;
            var snapshot = await GetSnapshotAsync();
            var desired = FirewallBlockPlanner.Build(snapshot.Processes, solo, _blockedPaths);
            var fingerprint = FirewallBlockPlanner.Fingerprint(desired);
            if (fingerprint == _firewallFingerprint)
                return;
            await _firewall.ApplyAsync(desired, _cancel.Token);
            _firewallFingerprint = fingerprint;
            _blockedPaths.Clear();
            foreach (var block in desired)
                _blockedPaths.Add(block.AppPath);
            _blockedCount = desired.Count;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            Post(() => Status = "No se pudo aplicar el bloqueo del firewall: " + ex.Message);
        }
        finally
        {
            _qosGate.Release();
        }
    }


    /// <summary>The running Dota 2 process, from the last process sample.</summary>
    public ProcessNetworkRow? FindDota() => _latest is { } latest ? GameDetector.FindDota(latest.Snapshot.Processes) : null;

    public bool HasPriority(string? path) =>
        FilterOn && path != null && string.Equals(_ownerPath, path, StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Gives the game priority on this PC without asking again (the game mode already asked). Without
    /// administrator rights Windows asks for them and RedFilter restarts; returns false in that case.
    /// </summary>
    public async Task<bool> PrioritizeGameAsync(ProcessNetworkRow game, long otherProgramsUploadBits)
    {
        if (string.IsNullOrWhiteSpace(game.ExecutablePath))
        {
            Status = "Windows no deja ver la ruta de Dota 2, así que no se le puede dar prioridad en este PC.";
            return false;
        }

        var rate = QosPolicyPlanner.NormalizeThrottle(otherProgramsUploadBits);
        if (HasPriority(game.ExecutablePath) && Interlocked.Read(ref _throttleBits) == rate)
            return true;
        if (!_isAdmin)
        {
            RequestElevation(new QosLaunchRequest(false, game.Pid, game.ExecutablePath, game.Name, rate));
            return false;
        }

        await ApplyOwnerAsync(game.Pid, game.Name, game.ExecutablePath, rate);
        return HasPriority(game.ExecutablePath);
    }

    /// <summary>Ends the game's priority when the game mode ends. Only when RedFilter can do it without restarting.</summary>
    public async Task EndGamePriorityAsync(string? path)
    {
        if (_isAdmin && (path == null ? FilterOn : HasPriority(path)))
            await RemoveFilterAsync();
    }

    public Task PrioritizeAsync(ProgramRow program)
    {
        Selected = Processes.FirstOrDefault(row => row.Pid == program.Pid);
        return GiveNetworkAsync();
    }
    public ObservableCollection<ThrottleChoice> ThrottleChoices { get; }

    public ProcessRowViewModel? Selected
    {
        get => _selected;
        set
        {
            if (Set(ref _selected, value))
                Raise(nameof(CanGiveNetwork));
        }
    }

    public ThrottleChoice? Throttle
    {
        get => _throttle;
        set
        {
            if (!Set(ref _throttle, value) || value == null)
                return;
            Interlocked.Exchange(ref _throttleBits, value.BitsPerSecond);
            var settings = _store.Load();
            settings.ThrottleBitsPerSecond = value.BitsPerSecond;
            _store.Save(settings);
            if (_filterActive)
                _ = Task.Run(() => ReconcileAsync(force: true));
        }
    }

    public string OwnerText { get => _ownerText; private set => Set(ref _ownerText, value); }
    public string Status { get => _status; set => Set(ref _status, value); }
    public string Elevation { get => _elevation; private set => Set(ref _elevation, value); }
    public bool FilterOn
    {
        get => _filterOn;
        private set
        {
            _filterActive = value;
            if (Set(ref _filterOn, value))
                Raise(nameof(CanTurnOff));
        }
    }
    public bool Busy { get => _busy; private set { if (Set(ref _busy, value)) { Raise(nameof(CanGiveNetwork)); Raise(nameof(CanTurnOff)); } } }
    public bool CanGiveNetwork => !Busy && Selected != null;
    public bool CanTurnOff => !Busy && (FilterOn || !_isAdmin);

    public void Start()
    {
        if (Interlocked.Exchange(ref _started, 1) != 0)
            return;
        Task.Run(() => LoopAsync(_cancel.Token));
    }

    public async Task InitializeAsync()
    {
        if (!_isAdmin)
            return;

        // Firewall rules survive a reboot. Blocks left over from a session that ended badly, with the
        // Dota 2 mode no longer on, are removed so no program stays without internet.
        var start = _store.Load();
        if (_firewall != null && start.FirewallBlocksActive && start.GameMode == null)
        {
            try
            {
                await _firewall.RemoveAllAsync(_cancel.Token);
                start.FirewallBlocksActive = false;
                _store.Save(start);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                Status = "Quedaron bloqueos del firewall de una sesión anterior y no se pudieron quitar: " + ex.Message;
            }
        }

        if (_pendingLaunch is { } pending)
        {
            _pendingLaunch = null;
            if (pending.Clear)
            {
                await RemoveFilterAsync();
                return;
            }

            if (string.IsNullOrWhiteSpace(pending.Path))
            {
                Status = "Windows reinició RedFilter sin la ruta del programa, así que no se cambió nada.";
                return;
            }

            var name = string.IsNullOrWhiteSpace(pending.Name) ? Path.GetFileName(pending.Path) : pending.Name;
            await ApplyOwnerAsync(pending.Pid ?? 0, name, pending.Path, pending.ThrottleBitsPerSecond ?? Throttle?.BitsPerSecond ?? 1_000_000);
            return;
        }

        await _qosGate.WaitAsync(_cancel.Token);
        try
        {
            var policies = await _qos.ReadAsync(_cancel.Token);
            var owner = policies.FirstOrDefault(policy => policy.Name == QosPolicyPlanner.OwnerPolicyName);
            if (owner == null)
            {
                FilterOn = false;
                OwnerText = "Ningún programa tiene prioridad. La red se reparte con normalidad.";
                return;
            }

            _limitedPaths.Clear();
            foreach (var policy in policies)
            {
                if (policy.Name.StartsWith(QosPolicyPlanner.LimitPrefix, StringComparison.Ordinal) && !string.IsNullOrWhiteSpace(policy.AppPath))
                    _limitedPaths.Add(policy.AppPath.Trim());
            }

            _appliedFingerprint = null;
            _ownerPath = owner.AppPath ?? _ownerPath;
            FilterOn = true;
            var settings = _store.Load();
            var name = settings.NetworkOwnerName ?? (string.IsNullOrWhiteSpace(_ownerPath) ? "a program" : Path.GetFileName(_ownerPath));
            _ownerPid = string.Equals(settings.NetworkOwnerPath, _ownerPath, StringComparison.OrdinalIgnoreCase) ? settings.NetworkOwnerPid : null;
            OwnerText = DescribeOwner(name, _ownerPid, _ownerPath);
            Status = "Hay una prioridad activa de una sesión anterior.";
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            Status = ex.Message;
        }
        finally
        {
            _qosGate.Release();
        }
    }

    public async Task GiveNetworkAsync()
    {
        var selected = Selected;
        if (selected == null)
        {
            Status = "Elige un programa primero.";
            return;
        }

        if (string.IsNullOrWhiteSpace(selected.Path))
        {
            Status = "Windows no deja ver la ruta de ese programa, y la prioridad se aplica por ruta. Elige otro.";
            return;
        }

        var rate = QosPolicyPlanner.NormalizeThrottle(Interlocked.Read(ref _throttleBits));
        var confirmed = await ConfirmAsync(
            $"¿Dar prioridad a {selected.Name}?\n\n" +
            $"Los demás programas de este PC quedarán limitados a {RateText.BitsPerSecond(rate)} de subida mientras dure la prioridad. Las descargas no se limitan." +
            (VpnActive ? "\n\nCon la VPN encendida, este límite puede no notarse; la prioridad del PC en el router sí funciona." : "") +
            (_isAdmin ? "" : "\n\nWindows pedirá permiso de administrador y RedFilter se reiniciará."));
        if (!confirmed)
            return;

        if (!_isAdmin)
        {
            RequestElevation(new QosLaunchRequest(false, selected.Pid, selected.Path, selected.Name, rate));
            return;
        }

        await ApplyOwnerAsync(selected.Pid, selected.Name, selected.Path, rate);
    }

    public async Task TurnOffAsync()
    {
        var confirmed = await ConfirmAsync(
            "¿Quitar la prioridad y volver a repartir la red con normalidad?" +
            (_isAdmin ? "" : "\n\nWindows pedirá permiso de administrador y RedFilter se reiniciará."));
        if (!confirmed)
            return;

        if (!_isAdmin)
        {
            RequestElevation(new QosLaunchRequest(true, null, null, null, null));
            return;
        }

        await RemoveFilterAsync();
    }

    private async Task ApplyOwnerAsync(int pid, string name, string path, long rate)
    {
        Busy = true;
        try
        {
            await _qosGate.WaitAsync(_cancel.Token);
            try
            {
                var snapshot = await GetSnapshotAsync();
                var owner = snapshot.Processes.FirstOrDefault(process =>
                        string.Equals(process.ExecutablePath, path, StringComparison.OrdinalIgnoreCase))
                    ?? snapshot.Processes.FirstOrDefault(process => process.Pid == pid)
                    ?? new ProcessNetworkRow(pid, name, path, 0, 0, 0, 0);
                if (!string.Equals(_ownerPath, path, StringComparison.OrdinalIgnoreCase))
                    _limitedPaths.Clear();
                var plan = QosPolicyPlanner.Build(owner, snapshot.Processes, rate, _selfPath, _limitedPaths, snapshot.ConnectionsAvailable);
                await _qos.ApplyAsync(plan.Policies, _cancel.Token);
                RememberApplied(plan);
                Interlocked.Exchange(ref _throttleBits, plan.ThrottleBitsPerSecond);
                _ownerPath = plan.OwnerPath;
                _ownerPid = plan.OwnerPid;
                FilterOn = true;
                OwnerText = DescribeOwner(plan.OwnerName, plan.OwnerPid, plan.OwnerPath);
                Status = string.Join(" ", plan.Notes);
                SaveOwner(plan.OwnerName, plan.OwnerPid, plan.OwnerPath, plan.ThrottleBitsPerSecond);
                MarkOwnerRows();
            }
            finally
            {
                _qosGate.Release();
            }
        }
        catch (OperationCanceledException)
        {
        }
        catch (Exception ex)
        {
            Status = ex.Message;
        }
        finally
        {
            Busy = false;
        }
    }

    private async Task RemoveFilterAsync()
    {
        Busy = true;
        try
        {
            // Waits for any reconcile that is already talking to Windows QoS.
            await _qosGate.WaitAsync(_cancel.Token);
            try
            {
                await _qos.RemoveAllAsync(_cancel.Token);
                FilterOn = false;
                _ownerPath = null;
                _ownerPid = null;
                _limitedPaths.Clear();
                _appliedFingerprint = null;
                OwnerText = "Ningún programa tiene prioridad. La red se reparte con normalidad.";
                Status = "Prioridad quitada. La red vuelve a repartirse con normalidad.";
                SaveOwner(null, null, null, Interlocked.Read(ref _throttleBits));
                MarkOwnerRows();
            }
            finally
            {
                _qosGate.Release();
            }
        }
        catch (OperationCanceledException)
        {
        }
        catch (Exception ex)
        {
            Status = ex.Message;
        }
        finally
        {
            Busy = false;
        }
    }

    private void RequestElevation(QosLaunchRequest request)
    {
        if (_elevationBroker == null)
        {
            Status = "Hace falta permiso de administrador.";
            return;
        }

        Busy = true;
        Status = "Windows está pidiendo permiso de administrador…";
        if (!_elevationBroker.TryRelaunch(request, out var failure))
        {
            Busy = false;
            Status = failure;
            return;
        }

        Status = "RedFilter se reinicia como administrador…";
        _shutdown?.Invoke();
    }

    public void Dispose()
    {
        // Closing RedFilter gives every program its internet back: nothing would be left to lift the
        // blocks when Dota closes. The router part stays until the mode is switched off.
        if (_solo != null && _firewall != null && _isAdmin)
        {
            _solo = null;
            try
            {
                if (Task.Run(() => _firewall.RemoveAllAsync(CancellationToken.None)).Wait(TimeSpan.FromSeconds(10)))
                {
                    var settings = _store.Load();
                    settings.FirewallBlocksActive = false;
                    _store.Save(settings);
                }
            }
            catch (AggregateException)
            {
                // The next elevated start removes them (FirewallBlocksActive stays set).
            }
        }

        _cancel.Cancel();
    }

    private sealed record SnapshotStamp(ProcessNetworkSnapshot Snapshot, DateTime TakenUtc);

    // Reuse the snapshot the refresh loop took a moment ago instead of reading every process and
    // connection again. Only sample on a worker thread when it is stale.
    private async Task<ProcessNetworkSnapshot> GetSnapshotAsync()
    {
        var latest = _latest;
        if (latest != null && DateTime.UtcNow - latest.TakenUtc < SnapshotMaxAge)
            return latest.Snapshot;
        var snapshot = await Task.Run(_source.Sample);
        _latest = new SnapshotStamp(snapshot, DateTime.UtcNow);
        return snapshot;
    }

    private void RememberApplied(QosPlan plan)
    {
        _appliedFingerprint = QosPolicyPlanner.Fingerprint(plan.Policies);
        _lastVerifyUtc = DateTime.UtcNow;
        _limitedPaths.Clear();
        foreach (var policy in plan.Policies)
        {
            if (!policy.IsOwner)
                _limitedPaths.Add(policy.AppPath);
        }
    }

    private async Task LoopAsync(CancellationToken cancellationToken)
    {
        // QoS policy restore must not block the program list. A slow PowerShell
        // query used to leave the page on "Leyendo programas…".
        if (_isAdmin)
            _ = PostAsync(InitializeAsync);
        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                var snapshot = _source.Sample();
                _latest = new SnapshotStamp(snapshot, DateTime.UtcNow);
                Post(() => ApplySnapshot(snapshot));
                await Task.Delay(TimeSpan.FromSeconds(1), cancellationToken);
                if (_filterActive && DateTime.UtcNow - _lastReconcileUtc > ReconcileInterval)
                    await ReconcileAsync(force: false);
                if (_solo != null && DateTime.UtcNow - _lastFirewallCheckUtc > ReconcileInterval)
                    await ReconcileFirewallAsync();
            }
            catch (OperationCanceledException)
            {
                return;
            }
            catch (Exception ex)
            {
                Post(() => Status = ex.Message);
            }
        }
    }

    private void ApplySnapshot(ProcessNetworkSnapshot snapshot)
    {
        var selectedPid = Selected?.Pid;
        var byPid = Processes.ToDictionary(row => row.Pid);
        var seen = new HashSet<int>();
        foreach (var process in snapshot.Processes)
        {
            seen.Add(process.Pid);
            var owner = FilterOn && _ownerPath != null &&
                string.Equals(process.ExecutablePath, _ownerPath, StringComparison.OrdinalIgnoreCase);
            if (byPid.TryGetValue(process.Pid, out var row))
                row.Update(process, owner);
            else
                Processes.Add(new ProcessRowViewModel(process, owner));
        }

        for (var i = Processes.Count - 1; i >= 0; i--)
        {
            if (!seen.Contains(Processes[i].Pid))
                Processes.RemoveAt(i);
        }

        if (selectedPid != null && Selected == null)
            Selected = Processes.FirstOrDefault(row => row.Pid == selectedPid);

        var ordered = Processes
            .OrderByDescending(row => row.DownloadBps + row.UploadBps)
            .ThenBy(row => row.Name, StringComparer.OrdinalIgnoreCase)
            .ToList();
        for (var target = 0; target < ordered.Count; target++)
        {
            var current = Processes.IndexOf(ordered[target]);
            if (current != target)
                Processes.Move(current, target);
        }

        UpdatePrograms();

        if (!Busy && IsProgressStatus(Status))
        {
            Status = snapshot.ThroughputAvailable
                ? "Elige un programa de la lista para darle prioridad."
                : "Elige un programa de la lista para darle prioridad. Las velocidades por programa solo se ven con RedFilter abierto como administrador; mientras tanto se ordena por conexiones.";
        }
    }

    private void UpdatePrograms()
    {
        var groups = Processes
            .Where(row => row.Connections > 0 && !string.IsNullOrWhiteSpace(row.Path))
            .GroupBy(row => row.Path, StringComparer.OrdinalIgnoreCase)
            .Select(group => new ProgramRow
            {
                Pid = group.OrderByDescending(row => row.DownloadBps + row.UploadBps).First().Pid,
                Name = group.First().Name,
                Path = group.Key,
                BytesPerSecond = group.Sum(row => row.DownloadBps + row.UploadBps),
                Connections = group.Sum(row => row.Connections),
                IsOwner = group.Any(row => row.IsOwner),
                Protected = QosPolicyPlanner.IsProtected(group.First().Source)
            })
            .Where(program => !program.Protected || program.IsOwner)
            .OrderByDescending(program => program.IsOwner)
            .ThenByDescending(program => program.BytesPerSecond)
            .ThenByDescending(program => program.Connections)
            .Take(14)
            .ToList();
        Programs.Clear();
        foreach (var program in groups)
            Programs.Add(program);
    }

    private static bool IsProgressStatus(string status) =>
        status.StartsWith("Leyendo", StringComparison.Ordinal)
        || status.StartsWith("Elige un programa de la lista", StringComparison.Ordinal)
        || status.StartsWith("TCP throughput", StringComparison.Ordinal)
        || status.StartsWith("Network counters", StringComparison.Ordinal);

    // Keeps the policy set in step with running programs. Building the plan is cheap; PowerShell only
    // runs when the plan changed (a new program started using the network, or the limit changed), or
    // once a minute to confirm nobody removed the policies behind RedFilter's back.
    private async Task ReconcileAsync(bool force)
    {
        if (!_isAdmin)
            return;
        bool entered;
        try
        {
            entered = force ? await _qosGate.WaitAsync(Timeout.Infinite, _cancel.Token) : await _qosGate.WaitAsync(0);
        }
        catch (OperationCanceledException)
        {
            return;
        }

        if (!entered)
            return;
        try
        {
            _lastReconcileUtc = DateTime.UtcNow;
            var ownerPath = _ownerPath;
            if (!_filterActive || string.IsNullOrWhiteSpace(ownerPath))
                return;
            var snapshot = await GetSnapshotAsync();
            var owner = snapshot.Processes.FirstOrDefault(process =>
                string.Equals(process.ExecutablePath, ownerPath, StringComparison.OrdinalIgnoreCase));
            owner ??= new ProcessNetworkRow(_ownerPid ?? 0, Path.GetFileNameWithoutExtension(ownerPath) ?? "program", ownerPath, 0, 0, 0, 0);
            var plan = QosPolicyPlanner.Build(owner, snapshot.Processes, Interlocked.Read(ref _throttleBits), _selfPath, _limitedPaths, snapshot.ConnectionsAvailable);
            var fingerprint = QosPolicyPlanner.Fingerprint(plan.Policies);
            if (!force && fingerprint == _appliedFingerprint && DateTime.UtcNow - _lastVerifyUtc < VerifyInterval)
                return;
            await _qos.ApplyAsync(plan.Policies, _cancel.Token);
            RememberApplied(plan);
            if (force)
                Post(() => Status = string.Join(" ", plan.Notes));
        }
        catch (OperationCanceledException)
        {
        }
        catch (Exception ex)
        {
            Post(() => Status = ex.Message);
        }
        finally
        {
            _qosGate.Release();
        }
    }

    private void MarkOwnerRows()
    {
        foreach (var row in Processes)
        {
            var owner = FilterOn && _ownerPath != null &&
                string.Equals(row.Source.ExecutablePath, _ownerPath, StringComparison.OrdinalIgnoreCase);
            row.Update(row.Source, owner);
        }
    }

    private void SaveOwner(string? name, int? pid, string? path, long throttle)
    {
        var settings = _store.Load();
        settings.NetworkOwnerName = name;
        settings.NetworkOwnerPid = pid;
        settings.NetworkOwnerPath = path;
        settings.ThrottleBitsPerSecond = throttle;
        _store.Save(settings);
    }

    private static string DescribeOwner(string name, int? pid, string? path)
    {
        var pidText = pid is > 0 ? $" (PID {pid})" : "";
        var file = string.IsNullOrWhiteSpace(path) ? name : Path.GetFileName(path);
        return $"Prioridad: {file}. Los demás programas van limitados.";
    }

    private async Task<bool> ConfirmAsync(string message)
    {
        if (_prompt == null)
            return false;
        return await _prompt.ConfirmAsync(message);
    }

    private void Post(Action action)
    {
        if (Dispatcher.UIThread.CheckAccess())
            action();
        else
            Dispatcher.UIThread.Post(action);
    }

    private Task PostAsync(Func<Task> action)
    {
        var done = new TaskCompletionSource();
        Dispatcher.UIThread.Post(async () =>
        {
            try
            {
                await action();
                done.TrySetResult();
            }
            catch (Exception ex)
            {
                done.TrySetException(ex);
            }
        });
        return done.Task;
    }
}
