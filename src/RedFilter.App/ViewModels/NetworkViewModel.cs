using System.Collections.ObjectModel;
using System.IO;
using System.Windows;
using RedFilter.Core.Processes;
using RedFilter.Core.Qos;
using RedFilter.Core.Settings;
using RedFilter.Core.Text;

namespace RedFilter.ViewModels;

public sealed class NetworkViewModel : ObservableObject, IDisposable
{
    private readonly IProcessNetworkSource _source;
    private readonly IQosPolicyStore _qos;
    private readonly SettingsStore _store;
    private readonly SynchronizationContext _ui;
    private readonly CancellationTokenSource _cancel = new();
    private readonly string? _selfPath = Environment.ProcessPath;

    private string _ownerText = "No program owns the network. Sharing is normal.";
    private string _status = "Reading processes…";
    private string _elevation = "";
    private bool _filterOn;
    private bool _busy;
    private bool _isAdmin;
    private ProcessRowViewModel? _selected;
    private ThrottleChoice? _throttle;
    private string? _ownerPath;
    private int? _ownerPid;
    private DateTime _lastReconcileUtc = DateTime.MinValue;
    private int _reconcileGate;

    public NetworkViewModel(IProcessNetworkSource source, IQosPolicyStore qos, SettingsStore store, bool isAdmin)
    {
        _source = source;
        _qos = qos;
        _store = store;
        _isAdmin = isAdmin;
        _ui = SynchronizationContext.Current ?? new SynchronizationContext();
        ThrottleChoices = new ObservableCollection<ThrottleChoice>
        {
            new() { Label = "Strict — 256 Kbps", BitsPerSecond = 256_000 },
            new() { Label = "Balanced — 1 Mbps", BitsPerSecond = 1_000_000 },
            new() { Label = "Light — 5 Mbps", BitsPerSecond = 5_000_000 }
        };
        var settings = store.Load();
        _throttle = ThrottleChoices.FirstOrDefault(choice => choice.BitsPerSecond == settings.ThrottleBitsPerSecond)
            ?? ThrottleChoices[1];
        _ownerPath = settings.NetworkOwnerPath;
        _ownerPid = settings.NetworkOwnerPid;
        Elevation = isAdmin
            ? "Running as administrator. QoS changes are allowed."
            : "Not running as administrator. Windows will refuse QoS changes until you restart RedFilter from an elevated prompt.";
        if (!isAdmin)
            Status = "RedFilter needs to run as administrator to change Windows QoS policies. The program manifest requests elevation. Start RedFilter.exe and accept the User Account Control prompt.";
    }

    public ObservableCollection<ProcessRowViewModel> Processes { get; } = new();
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
            var settings = _store.Load();
            settings.ThrottleBitsPerSecond = value.BitsPerSecond;
            _store.Save(settings);
            if (_filterOn)
                _ = ReconcileAsync(force: true);
        }
    }

    public string OwnerText { get => _ownerText; private set => Set(ref _ownerText, value); }
    public string Status { get => _status; set => Set(ref _status, value); }
    public string Elevation { get => _elevation; private set => Set(ref _elevation, value); }
    public bool FilterOn { get => _filterOn; private set { if (Set(ref _filterOn, value)) Raise(nameof(CanTurnOff)); } }
    public bool Busy { get => _busy; private set { if (Set(ref _busy, value)) { Raise(nameof(CanGiveNetwork)); Raise(nameof(CanTurnOff)); } } }
    public bool CanGiveNetwork => !Busy && Selected != null;
    public bool CanTurnOff => !Busy && FilterOn;

    public void Start() => Task.Run(() => LoopAsync(_cancel.Token));

    public async Task InitializeAsync()
    {
        if (!_isAdmin)
            return;
        try
        {
            var policies = await _qos.ReadAsync(_cancel.Token);
            var owner = policies.FirstOrDefault(policy => policy.Name == QosPolicyPlanner.OwnerPolicyName);
            if (owner == null)
            {
                FilterOn = false;
                OwnerText = "No program owns the network. Sharing is normal.";
                return;
            }

            FilterOn = true;
            _ownerPath = owner.AppPath ?? _ownerPath;
            var settings = _store.Load();
            var name = settings.NetworkOwnerName ?? (string.IsNullOrWhiteSpace(_ownerPath) ? "a program" : Path.GetFileName(_ownerPath));
            _ownerPid = string.Equals(settings.NetworkOwnerPath, _ownerPath, StringComparison.OrdinalIgnoreCase) ? settings.NetworkOwnerPid : null;
            OwnerText = DescribeOwner(name, _ownerPid, _ownerPath);
            Status = "A RedFilter QoS policy is already active from this Windows session.";
        }
        catch (Exception ex)
        {
            Status = ex.Message;
        }
    }

    public async Task GiveNetworkAsync()
    {
        var selected = Selected;
        if (selected == null)
        {
            Status = "Select a process first.";
            return;
        }

        if (!_isAdmin)
        {
            Status = "Creating QoS policies needs an elevated process. Restart RedFilter as administrator.";
            return;
        }

        var rate = QosPolicyPlanner.NormalizeThrottle(Throttle?.BitsPerSecond ?? 1_000_000);
        var answer = MessageBox.Show(
            $"Give network priority to {selected.Name} (PID {selected.Pid})?\n\n" +
            $"Windows will mark that program's traffic with DSCP {QosPolicyPlanner.OwnerDscp} and limit outbound traffic from other ordinary programs to {RateText.BitsPerSecond(rate)}.\n\n" +
            "The policy matches the program path, so every process running the same program is included. Downloads are not limited. Windows system processes are left alone.",
            "RedFilter",
            MessageBoxButton.OKCancel,
            MessageBoxImage.Information);
        if (answer != MessageBoxResult.OK)
            return;

        Busy = true;
        try
        {
            var snapshot = _source.Sample();
            var owner = snapshot.Processes.FirstOrDefault(process => process.Pid == selected.Pid) ?? selected.Source;
            var plan = QosPolicyPlanner.Build(owner, snapshot.Processes, rate, _selfPath);
            await _qos.ApplyAsync(plan.Policies, _cancel.Token);
            _ownerPath = plan.OwnerPath;
            _ownerPid = plan.OwnerPid;
            FilterOn = true;
            OwnerText = DescribeOwner(plan.OwnerName, plan.OwnerPid, plan.OwnerPath);
            Status = string.Join(" ", plan.Notes);
            SaveOwner(plan.OwnerName, plan.OwnerPid, plan.OwnerPath, plan.ThrottleBitsPerSecond);
            MarkOwnerRows();
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

    public async Task TurnOffAsync()
    {
        if (!_isAdmin)
        {
            Status = "Removing QoS policies needs an elevated process. Restart RedFilter as administrator.";
            return;
        }

        var answer = MessageBox.Show(
            "Turn the filter off and restore normal sharing?\n\nRedFilter will remove every QoS policy whose name starts with RedFilter-.",
            "RedFilter",
            MessageBoxButton.OKCancel,
            MessageBoxImage.Information);
        if (answer != MessageBoxResult.OK)
            return;

        Busy = true;
        try
        {
            await _qos.RemoveAllAsync(_cancel.Token);
            FilterOn = false;
            _ownerPath = null;
            _ownerPid = null;
            OwnerText = "No program owns the network. Sharing is normal.";
            Status = "The filter is off. RedFilter QoS policies were removed.";
            SaveOwner(null, null, null, Throttle?.BitsPerSecond ?? 1_000_000);
            MarkOwnerRows();
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

    public void Dispose() => _cancel.Cancel();

    private async Task LoopAsync(CancellationToken cancellationToken)
    {
        if (_isAdmin)
            await PostAsync(InitializeAsync);
        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(TimeSpan.FromSeconds(1), cancellationToken);
                var snapshot = _source.Sample();
                Post(() => ApplySnapshot(snapshot));
                if (FilterOn && !Busy && DateTime.UtcNow - _lastReconcileUtc > TimeSpan.FromSeconds(3))
                    await ReconcileAsync(force: false);
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

        if (!string.IsNullOrWhiteSpace(snapshot.Warning) && !FilterOn && !Busy &&
            (Status.StartsWith("Reading", StringComparison.Ordinal) || Status.StartsWith("TCP throughput", StringComparison.Ordinal)))
            Status = snapshot.Warning;
    }

    private async Task ReconcileAsync(bool force)
    {
        if (!_isAdmin || string.IsNullOrWhiteSpace(_ownerPath))
            return;
        if (Interlocked.Exchange(ref _reconcileGate, 1) == 1)
            return;
        try
        {
            var snapshot = _source.Sample();
            var owner = snapshot.Processes.FirstOrDefault(process =>
                string.Equals(process.ExecutablePath, _ownerPath, StringComparison.OrdinalIgnoreCase));
            owner ??= new ProcessNetworkRow(_ownerPid ?? 0, Path.GetFileNameWithoutExtension(_ownerPath) ?? "program", _ownerPath, 0, 0, 0, 0);
            var plan = QosPolicyPlanner.Build(owner, snapshot.Processes, Throttle?.BitsPerSecond ?? 1_000_000, _selfPath);
            await _qos.ApplyAsync(plan.Policies, _cancel.Token);
            _lastReconcileUtc = DateTime.UtcNow;
            if (force)
                Post(() => Status = string.Join(" ", plan.Notes));
        }
        catch (Exception ex)
        {
            Post(() => Status = ex.Message);
        }
        finally
        {
            Interlocked.Exchange(ref _reconcileGate, 0);
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
        return $"Network owner: {file}{pidText}. Other ordinary programs are limited.";
    }

    private void Post(Action action) => _ui.Post(_ => action(), null);

    private Task PostAsync(Func<Task> action)
    {
        var done = new TaskCompletionSource();
        _ui.Post(async _ =>
        {
            try
            {
                await action();
                done.SetResult();
            }
            catch (Exception ex)
            {
                done.SetException(ex);
            }
        }, null);
        return done.Task;
    }
}
