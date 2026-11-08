using System.Collections.ObjectModel;
using System.Globalization;
using System.Text.RegularExpressions;
using Avalonia.Threading;
using RedFilter.Core.Router;
using RedFilter.Core.Router.TpLink;
using RedFilter.Core.Settings;
using RedFilter.Core.Text;
using RedFilter.Platform;

namespace RedFilter.ViewModels;

/// <summary>
/// "Mi Wi-Fi": connects to the home router on its own, ranks the Wi-Fi devices by how much they are
/// using right now, and blocks or limits one of them. Every change is confirmed first and read back
/// from the router afterwards.
/// </summary>
public sealed class WifiViewModel : ObservableObject, IDisposable
{
    private static readonly TimeSpan PollInterval = TimeSpan.FromSeconds(5);
    // Download caps offered by "Limitar" (kbps). Upload gets a quarter, like an ADSL line.
    private static readonly int[] DownloadChoices = { 256, 512, 1024, 2048 };
    private static readonly Regex RepeaterName = new(@"^(RE\d{3,4}|.*(repeater|extender|repetidor|mesh|deco).*)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

    private readonly SettingsStore _store;
    private readonly Func<RouterEndpoint, IRouterTransport> _transportFactory;
    private readonly IUserPrompt _prompt;
    private readonly CancellationTokenSource _cancel = new();
    private TdW8961Session? _session;
    private LocalNetworkInfo _local;
    private string _status = "Buscando tu router…";
    private string _routerName = "";
    private bool _connected;
    private bool _needsPassword;
    private bool _busy;
    private int _loopStarted;

    public WifiViewModel(SettingsStore store, Func<RouterEndpoint, IRouterTransport> transportFactory, IUserPrompt prompt, LocalNetworkInfo local)
    {
        _store = store;
        _transportFactory = transportFactory;
        _prompt = prompt;
        _local = local;
    }

    public ObservableCollection<WifiDeviceRow> Devices { get; } = new();
    public ObservableCollection<WifiDeviceRow> ListedOffline { get; } = new();

    public string Status { get => _status; private set { if (Set(ref _status, value)) _statusSetUtc = DateTime.UtcNow; Raise(nameof(HasStatus)); } }
    public bool HasStatus => Connected && !string.IsNullOrWhiteSpace(Status);
    private DateTime _statusSetUtc = DateTime.UtcNow;

    // Summary shown above the list, refreshed with every read of the router.
    private string _connectedText = "";
    private string _limitedText = "";
    private string _blockedText = "";
    private string _savedListText = "";
    private int _savedListCount;
    public string ConnectedText { get => _connectedText; private set => Set(ref _connectedText, value); }
    public string LimitedText { get => _limitedText; private set { if (Set(ref _limitedText, value)) Raise(nameof(HasLimited)); } }
    public string BlockedText { get => _blockedText; private set { if (Set(ref _blockedText, value)) Raise(nameof(HasBlocked)); } }
    public string SavedListText { get => _savedListText; private set => Set(ref _savedListText, value); }
    public bool HasLimited => LimitedText.Length > 0;
    public bool HasBlocked => BlockedText.Length > 0;
    public bool HasSavedList => _savedListCount > 0;
    public bool HasNotice => SavedListText.Length > 0;
    public string RouterName { get => _routerName; private set => Set(ref _routerName, value); }
    public bool Connected { get => _connected; private set { if (Set(ref _connected, value)) Raise(nameof(ShowConnect)); } }
    public bool NeedsPassword { get => _needsPassword; private set { if (Set(ref _needsPassword, value)) Raise(nameof(ShowConnect)); } }
    public bool ShowConnect => !Connected;
    public bool Busy { get => _busy; private set => Set(ref _busy, value); }
    public bool HasListedOffline => ListedOffline.Count > 0;
    public string Address => _store.Load().RouterAddress is { Length: > 0 } saved ? saved : "http://" + (_local.Gateway ?? "192.168.1.1");

    /// <summary>Signs in with the saved password, or asks for it on first use.</summary>
    public async Task StartAsync()
    {
        _local = await Task.Run(LocalNetworkInfo.Read);
        var password = _store.LoadPassword();
        if (string.IsNullOrEmpty(password))
        {
            NeedsPassword = true;
            Status = _local.Gateway == null
                ? "No encuentro tu router. Comprueba que estás conectado a tu red."
                : $"Escribe la contraseña de tu router ({_local.Gateway}) para ver quién usa tu Wi-Fi.";
            return;
        }

        await ConnectAsync(password, remember: false);
    }

    public async Task ConnectAsync(string password, bool remember)
    {
        if (string.IsNullOrEmpty(password))
        {
            Status = "Escribe la contraseña del router.";
            return;
        }

        Busy = true;
        Status = "Conectando con el router…";
        try
        {
            var settings = _store.Load();
            if (!RouterEndpoint.TryParse(Address, out var endpoint, out var error))
            {
                Status = error;
                return;
            }

            var username = string.IsNullOrWhiteSpace(settings.RouterUsername) ? "admin" : settings.RouterUsername!;
            using (var probe = _transportFactory(endpoint!))
            {
                if (_local.VpnActive && !await CanReachAsync(probe, endpoint!))
                {
                    Status = $"No llego al router porque {_local.VpnName} manda todo por el túnel. En WireGuard, quita \"Block untunneled traffic\" o excluye 192.168.1.0/24.";
                    NeedsPassword = true;
                    return;
                }

                if (!await TdW8961Session.LooksLikeThisRouterAsync(probe, endpoint!, _cancel.Token))
                {
                    Status = $"{endpoint!.Origin} no parece un TP-Link TD-W8961N. No he enviado la contraseña.";
                    NeedsPassword = true;
                    return;
                }
            }

            _session?.Dispose();
            _session = new TdW8961Session(_transportFactory, endpoint!, username, password);
            await _session.ConnectAsync(_cancel.Token);

            if (remember)
            {
                _store.SavePassword(password);
                settings.RouterAddress = endpoint!.Origin.ToString().TrimEnd('/');
                settings.RouterUsername = username;
                _store.Save(settings);
            }

            NeedsPassword = false;
            Connected = true;
            RouterName = "TP-Link TD-W8961N · " + endpoint!.Host;
            await RefreshAsync();
            StartLoop();
        }
        catch (OperationCanceledException)
        {
        }
        catch (RouterException ex)
        {
            Connected = false;
            NeedsPassword = true;
            Status = ex.Message;
        }
        finally
        {
            Busy = false;
        }
    }

    public void ForgetPassword()
    {
        _store.SavePassword(null);
        _session?.Dispose();
        _session = null;
        Connected = false;
        NeedsPassword = true;
        Devices.Clear();
        ListedOffline.Clear();
        Raise(nameof(HasListedOffline));
        Status = "Contraseña olvidada. Escríbela de nuevo para conectar.";
    }

    public async Task RefreshAsync()
    {
        if (_session == null)
            return;
        try
        {
            var snapshot = await _session.RunAsync(client => client.ReadAsync(_cancel.Token), _cancel.Token);
            Apply(snapshot);
        }
        catch (OperationCanceledException)
        {
        }
        catch (RouterException ex)
        {
            Status = "No pude leer el router: " + ex.Message;
        }
    }

    public async Task BlockAsync(WifiDeviceRow row)
    {
        if (_session == null)
            return;
        if (row.IsThisPc)
        {
            await _prompt.ChooseAsync("Este dispositivo es este PC. Si lo bloqueas, te quedas sin Wi-Fi y sin acceso al router para deshacerlo, así que RedFilter no lo hace.", new[] { "Entendido" });
            return;
        }

        if (row.IsRepeater && !await _prompt.ConfirmAsync(
                $"{row.Name} parece un repetidor. Bloquearlo deja sin Wi-Fi a todos los dispositivos que se conectan a través de él.\n\n¿Bloquearlo de todas formas?"))
            return;

        Busy = true;
        try
        {
            var state = await _session.RunAsync(client => client.ReadAccessControlAsync(_cancel.Token), _cancel.Token);
            var others = state.Macs.Where(mac => !mac.Equals(row.Mac, StringComparison.OrdinalIgnoreCase)).ToList();

            // This PC must never end up on an active block list.
            foreach (var own in others.Where(_local.IsOwnMac).ToList())
            {
                await _session.RunAsync(client => client.RemoveFromListAsync(own, _cancel.Token), _cancel.Token);
                others.Remove(own);
            }

            if (state.Mode != AccessControlMode.DenyListed && others.Count > 0)
            {
                var names = string.Join("\n", others.Select(mac => "•  " + Describe(mac)));
                var choice = await _prompt.ChooseAsync(
                    "La lista de bloqueo de tu router ya tiene estos dispositivos, aunque el bloqueo estaba apagado:\n\n" + names +
                    $"\n\nAl bloquear a {row.Name} se enciende el bloqueo, y ellos también se quedarían sin Wi-Fi.",
                    new[] { "Cancelar", "Bloquearlos también", $"Quitarlos y bloquear solo a {row.Name}" });
                if (choice is < 1)
                    return;
                if (choice == 2)
                {
                    foreach (var mac in others)
                        await _session.RunAsync(client => client.RemoveFromListAsync(mac, _cancel.Token), _cancel.Token);
                }
            }
            else if (!await _prompt.ConfirmAsync(
                         $"¿Bloquear a {row.Name} ({row.Mac}) del Wi-Fi?\n\nSe desconectará y no podrá volver a entrar hasta que lo desbloquees aquí. Al aplicar el cambio, el router puede cortar el Wi-Fi a todos unos segundos.\n\nOjo: el bloqueo es por MAC y solo para el Wi-Fi. No afecta a lo conectado por cable, y un móvil con \"dirección MAC privada/aleatoria\" puede volver a entrar si cambia de MAC."))
            {
                return;
            }

            await _session.RunAsync(client => client.BlockAsync(row.Mac, _cancel.Token), _cancel.Token);
            Status = $"{row.Name} está bloqueado. Puedes desbloquearlo cuando quieras.";
            await RefreshAsync();
        }
        catch (OperationCanceledException)
        {
        }
        catch (RouterException ex)
        {
            Status = ex.Message;
        }
        finally
        {
            Busy = false;
        }
    }

    public async Task UnblockAsync(WifiDeviceRow row)
    {
        if (_session == null)
            return;
        Busy = true;
        try
        {
            var state = await _session.RunAsync(client => client.RemoveFromListAsync(row.Mac, _cancel.Token), _cancel.Token);
            Status = state.Mode == AccessControlMode.Disabled
                ? $"{row.Name} ya puede conectarse. La lista quedó vacía y el bloqueo se apagó."
                : $"{row.Name} ya puede conectarse.";
            await RefreshAsync();
        }
        catch (OperationCanceledException)
        {
        }
        catch (RouterException ex)
        {
            Status = ex.Message;
        }
        finally
        {
            Busy = false;
        }
    }

    private WifiSnapshot? _lastSnapshot;
    private DateTime _lastRebalanceUtc = DateTime.MinValue;

    public bool GameModeActive => _store.Load().GameMode != null;

    /// <summary>This PC's address on the router: its own DHCP lease, or what Windows reports.</summary>
    private string? PcIp() =>
        _lastSnapshot?.Leases.FirstOrDefault(lease => _local.IsOwnMac(lease.Mac))?.Ip ?? _local.LanIp;

    /// <summary>
    /// Router half of the Dota 2 mode. Saves how to undo it before changing anything, then gives this
    /// PC a guaranteed share and caps every other device. Returns a line for the status.
    /// </summary>
    public async Task<string> StartGameModeAsync()
    {
        if (_session == null || !Connected)
            throw new RouterException("Conecta primero con el router (pestaña Mi Wi-Fi).");
        await RefreshAsync();
        var pcIp = PcIp() ?? throw new RouterException("No sé qué IP tiene este PC en tu red, así que no puedo reservarle la línea.");

        Busy = true;
        try
        {
            var plan = await _session.RunAsync(async client =>
            {
                var settings = _store.Load();
                // A retry after the router logged us out must not take the half-applied game rules as "before".
                if (settings.GameMode == null)
                {
                    var before = await client.ReadShapingAsync(_cancel.Token);
                    settings.GameMode = new GameModeBackup
                    {
                        TotalUpKbps = before.TotalUpKbps,
                        TotalDownKbps = before.TotalDownKbps,
                        Limits = TdW8961Client.SaveLimits(before),
                        PcIp = pcIp,
                        StartedUtc = DateTime.UtcNow
                    };
                    _store.Save(settings);
                }

                var backup = settings.GameMode;
                var shaping = await client.EnsureLineTotalsAsync(_cancel.Token);
                var snapshot = await client.ReadAsync(_cancel.Token);
                var plan = GameModePlanner.Build(shaping.TotalUpKbps, shaping.TotalDownKbps, pcIp,
                    snapshot.Leases.Select(lease => lease.Ip), backup.Limits);
                foreach (var ip in plan.AllRules.Select(rule => rule.Ip).Where(ip => !backup.TouchedIps.Contains(ip)))
                    backup.TouchedIps.Add(ip);
                _store.Save(settings);
                await client.ApplyGameModeAsync(plan, _cancel.Token);
                return plan;
            }, _cancel.Token);

            _lastRebalanceUtc = DateTime.UtcNow;
            await RefreshAsync();
            return $"Router: este PC tiene reservados {GameModePlanner.Describe(plan.Pc.DownFloorKbps ?? 0)} de bajada y {GameModePlanner.Describe(plan.Pc.UpFloorKbps ?? 0)} de subida; " +
                   $"los otros {plan.Others.Count} dispositivos comparten como mucho {GameModePlanner.Describe(plan.OthersDownKbps)} / {GameModePlanner.Describe(plan.OthersUpKbps)}.";
        }
        finally
        {
            Busy = false;
            Raise(nameof(GameModeActive));
        }
    }

    /// <summary>Puts the router back the way it was before the game mode.</summary>
    public async Task<string> StopGameModeAsync()
    {
        var settings = _store.Load();
        if (settings.GameMode is not { } backup)
            return "";
        if (_session == null)
            throw new RouterException("Conecta con el router para quitar los límites del modo Dota 2.");

        Busy = true;
        try
        {
            await _session.RunAsync(client => client.RestoreGameModeAsync(backup, _cancel.Token), _cancel.Token);
            settings = _store.Load();
            settings.GameMode = null;
            _store.Save(settings);
            await RefreshAsync();
            return backup.Limits.Count > 0
                ? "Router: límites del modo quitados; volvieron los límites que tenías antes."
                : "Router: límites del modo quitados; la red vuelve a repartirse con normalidad.";
        }
        finally
        {
            Busy = false;
            Raise(nameof(GameModeActive));
        }
    }

    /// <summary>
    /// A device that joins during the game mode gets its rule too. Runs at most every 30 s, and only
    /// when the router shows an IP the mode has not capped yet.
    /// </summary>
    public async Task RebalanceGameModeAsync()
    {
        var backup = _store.Load().GameMode;
        if (backup?.PcIp == null || _session == null || _lastSnapshot == null || Busy || DateTime.UtcNow - _lastRebalanceUtc < TimeSpan.FromSeconds(30))
            return;
        var fresh = _lastSnapshot.Leases.Select(lease => lease.Ip).Where(ip => ip != backup.PcIp && !backup.TouchedIps.Contains(ip)).ToList();
        _lastRebalanceUtc = DateTime.UtcNow;
        if (fresh.Count == 0)
            return;
        try
        {
            Status = $"Modo Dota 2: {fresh.Count} dispositivo(s) nuevo(s); repartiendo otra vez…";
            await StartGameModeAsync();
        }
        catch (RouterException ex)
        {
            Status = ex.Message;
        }
    }

    public async Task LimitAsync(WifiDeviceRow row)
    {
        if (_session == null)
            return;
        if (row.Ip is not { } ip)
        {
            await _prompt.ChooseAsync($"El router no le dio una IP a {row.Name} (no aparece en su tabla DHCP), y los límites de velocidad del router van por IP.", new[] { "Entendido" });
            return;
        }

        var intro = row.IsThisPc
            ? "Este dispositivo es este PC. Limitarlo frena también tu propia conexión (el panel del router sigue funcionando).\n\n"
            : row.IsRepeater
                ? $"{row.Name} parece un repetidor. El límite va por IP, y los dispositivos conectados a través de él suelen tener su propia IP, así que probablemente solo frene al repetidor.\n\n"
                : "";
        var labels = DownloadChoices.Select(down => $"{Speed(down)} (subida {Speed(UploadFor(down))})").ToList();
        var choice = await _prompt.ChooseAsync(
            intro +
            $"¿A cuánto limitar a {row.Name} ({row.Ip})?\n\n" +
            "El router fijará su IP en el DHCP para que el límite no se pierda si la cambia. Si es el primer límite, también le dirá al router la velocidad real de tu línea (el 90% de la sincronización ADSL).",
            new[] { "Cancelar" }.Concat(labels).ToList());
        if (choice < 1)
            return;

        var down = DownloadChoices[choice - 1];
        Busy = true;
        try
        {
            var rule = await _session.RunAsync(client => client.LimitAsync(row.Mac, ip, UploadFor(down), down, _cancel.Token), _cancel.Token);
            Status = $"{row.Name} está limitado a {Speed(rule.DownCeilingKbps ?? down)} de bajada y {Speed(rule.UpCeilingKbps ?? UploadFor(down))} de subida.";
            await RefreshAsync();
        }
        catch (OperationCanceledException)
        {
        }
        catch (RouterException ex)
        {
            Status = ex.Message;
        }
        finally
        {
            Busy = false;
        }
    }

    public async Task RemoveLimitAsync(WifiDeviceRow row)
    {
        if (_session == null || row.Ip is not { } ip)
            return;
        Busy = true;
        try
        {
            var state = await _session.RunAsync(client => client.RemoveLimitAsync(ip, _cancel.Token), _cancel.Token);
            Status = state.Rules.Count == 0
                ? $"{row.Name} ya no tiene límite. No queda ningún límite y la línea volvió a \"sin límite\" en el router."
                : $"{row.Name} ya no tiene límite.";
            await RefreshAsync();
        }
        catch (OperationCanceledException)
        {
        }
        catch (RouterException ex)
        {
            Status = ex.Message;
        }
        finally
        {
            Busy = false;
        }
    }

    private static int UploadFor(int downKbps) => Math.Max(64, downKbps / 4);

    private static string Speed(int kbps) => RateText.BitsPerSecond(kbps * 1000L);

    public void Dispose()
    {
        _cancel.Cancel();
        _session?.Dispose();
    }

    private void StartLoop()
    {
        if (Interlocked.Exchange(ref _loopStarted, 1) != 0)
            return;
        _ = Task.Run(async () =>
        {
            while (!_cancel.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(PollInterval, _cancel.Token);
                }
                catch (OperationCanceledException)
                {
                    return;
                }

                if (Connected)
                    await Dispatcher.UIThread.InvokeAsync(async () => { if (!Busy) await RefreshAsync(); });
            }
        });
    }

    private bool _gameModeForRows;
    private Dictionary<string, string?> _names = new(StringComparer.OrdinalIgnoreCase);

    private string Describe(string mac)
    {
        var name = _names.TryGetValue(mac, out var known) && !string.IsNullOrWhiteSpace(known) ? known : "Dispositivo sin nombre";
        return _local.IsOwnMac(mac) ? $"{name} ({mac}) — este PC" : $"{name} ({mac})";
    }

    private void Apply(WifiSnapshot snapshot)
    {
        _lastSnapshot = snapshot;
        var gameMode = GameModeActive;
        _names = snapshot.Leases.ToDictionary(lease => lease.Mac, lease => lease.Name, StringComparer.OrdinalIgnoreCase);
        var connected = snapshot.Devices.Where(device => device.Connected).ToList();
        var busiest = connected.Count == 0 ? 0 : connected.Max(device => device.PacketsPerSecond);

        _gameModeForRows = gameMode;
        Devices.Clear();
        var rank = 0;
        foreach (var device in connected)
        {
            rank++;
            Devices.Add(Row(device, rank, busiest));
        }

        ListedOffline.Clear();
        foreach (var device in snapshot.Devices.Where(device => !device.Connected))
            ListedOffline.Add(Row(device, 0, busiest));
        Raise(nameof(HasListedOffline));

        var limited = snapshot.Devices.Count(device => device.Limited && !_local.IsOwnMac(device.Mac));
        var blocked = snapshot.Devices.Count(device => device.Blocked);
        ConnectedText = Devices.Count == 1 ? "1 conectado" : $"{Devices.Count} conectados";
        LimitedText = limited == 0 ? "" : gameMode ? $"{limited} frenados por el modo Dota" : limited == 1 ? "1 limitado" : $"{limited} limitados";
        BlockedText = blocked == 0 ? "" : blocked == 1 ? "1 bloqueado" : $"{blocked} bloqueados";

        // Entries saved on the router's block list while blocking is off do nothing, but they would be
        // blocked the moment blocking is switched on. Say so plainly and offer to clear them.
        _savedListCount = snapshot.AccessControl.Mode == AccessControlMode.Disabled ? snapshot.AccessControl.Macs.Count : 0;
        SavedListText = _savedListCount == 0 ? "" :
            (_savedListCount == 1 ? "Tu router tiene 1 dispositivo guardado" : $"Tu router tiene {_savedListCount} dispositivos guardados") +
            " en su lista de bloqueo, pero el bloqueo está apagado, así que ahora no les afecta. Si bloqueas a alguien, también quedarían bloqueados.";
        Raise(nameof(HasSavedList));
        if (snapshot.AccessControl.Mode == AccessControlMode.AllowListed)
        {
            _savedListCount = 0;
            SavedListText = "Tu router solo deja entrar a los dispositivos de su lista (modo \"Allow Listed\"). RedFilter no cambia ese modo, así que no puede bloquear desde aquí.";
        }
        Raise(nameof(HasSavedList));
        Raise(nameof(HasNotice));

        // Action results stay on screen for a while, then the line clears.
        if (DateTime.UtcNow - _statusSetUtc > TimeSpan.FromSeconds(20))
            Status = "";
    }

    private WifiDeviceRow Row(WifiDevice device, int rank, double busiest)
    {
        var name = string.IsNullOrWhiteSpace(device.Name) ? "Dispositivo sin nombre" : device.Name!;
        return new WifiDeviceRow
        {
            Mac = device.Mac,
            Ip = device.Ip,
            Name = name,
            Detail = device.Ip ?? "Sin IP",
            Rank = rank > 0 ? rank.ToString(CultureInfo.InvariantCulture) : "",
            PacketsPerSecond = device.PacketsPerSecond,
            Share = busiest <= 0 ? 0 : device.PacketsPerSecond / busiest,
            Activity = device.Connected ? UsageLevel(device.PacketsPerSecond, busiest) : "Desconectado",
            Rate = device.Connected && device.PacketsPerSecond >= 1 ? $"{device.PacketsPerSecond:0} paquetes/s" : "",
            IsThisPc = _local.IsOwnMac(device.Mac),
            IsRepeater = RepeaterName.IsMatch(name),
            Blocked = device.Blocked,
            OnList = device.OnAccessList,
            LimitDownKbps = device.LimitDownKbps,
            LimitUpKbps = device.LimitUpKbps,
            GameMode = _gameModeForRows
        };
    }

    /// <summary>Packets per second mean little to most people; say how much, relative to the busiest device.</summary>
    internal static string UsageLevel(double packetsPerSecond, double busiest)
    {
        if (packetsPerSecond < 1)
            return "Sin uso";
        var share = busiest <= 0 ? 0 : packetsPerSecond / busiest;
        if (packetsPerSecond >= 40 && share >= 0.6)
            return "Uso alto";
        if (packetsPerSecond >= 10 && share >= 0.2)
            return "Uso medio";
        return "Uso bajo";
    }

    /// <summary>Takes every saved entry off the router's block list while blocking is off.</summary>
    public async Task ClearSavedListAsync()
    {
        if (_session == null || _lastSnapshot == null)
            return;
        var macs = _lastSnapshot.AccessControl.Mode == AccessControlMode.Disabled ? _lastSnapshot.AccessControl.Macs.ToList() : new List<string>();
        if (macs.Count == 0)
            return;
        var names = string.Join("\n", macs.Select(mac => "•  " + Describe(mac)));
        if (!await _prompt.ConfirmAsync("¿Quitar de la lista de bloqueo del router a estos dispositivos?\n\n" + names +
                                        "\n\nAhora no están bloqueados; esto solo evita que se bloqueen sin querer más adelante."))
            return;

        Busy = true;
        try
        {
            foreach (var mac in macs)
                await _session.RunAsync(client => client.RemoveFromListAsync(mac, _cancel.Token), _cancel.Token);
            Status = "Lista de bloqueo limpia.";
            await RefreshAsync();
        }
        catch (OperationCanceledException)
        {
        }
        catch (RouterException ex)
        {
            Status = ex.Message;
        }
        finally
        {
            Busy = false;
        }
    }

    private static async Task<bool> CanReachAsync(IRouterTransport transport, RouterEndpoint endpoint)
    {
        try
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(4));
            await transport.SendAsync(new RouterHttpRequest { Url = endpoint.Append("/login.htm") }, timeout.Token);
            return true;
        }
        catch (Exception ex) when (ex is RouterException or OperationCanceledException)
        {
            return false;
        }
    }
}

public sealed class WifiDeviceRow
{
    public required string Mac { get; init; }
    public string? Ip { get; init; }
    public required string Name { get; init; }
    public required string Detail { get; init; }
    public required string Rank { get; init; }
    public required string Activity { get; init; }
    public double PacketsPerSecond { get; init; }
    public double Share { get; init; }
    public bool IsThisPc { get; init; }
    public bool IsRepeater { get; init; }
    public bool Blocked { get; init; }
    public bool OnList { get; init; }
    public int? LimitDownKbps { get; init; }
    public int? LimitUpKbps { get; init; }
    /// <summary>While the Dota 2 mode is on, its rules are managed by the mode, not by these buttons.</summary>
    public bool GameMode { get; init; }

    public required string Rate { get; init; }

    public bool Limited => LimitDownKbps != null || LimitUpKbps != null;
    public string LimitText => GameMode
        ? IsThisPc ? "Reservado" : LimitDownKbps is { } d ? "Modo Dota · " + RateText.BitsPerSecond(d * 1000L) : "Modo Dota"
        : LimitDownKbps is { } down ? "Limitado · " + RateText.BitsPerSecond(down * 1000L) : "Limitado";

    /// <summary>One word for the state column: what the router is doing to this device right now.</summary>
    public string State => Blocked ? "Bloqueado" : Limited ? LimitText : "Normal";
    public string StateKind => Blocked ? "bad" : Limited ? (GameMode ? "hot" : "warn") : "muted";
    public bool StateBad => StateKind == "bad";
    public bool StateWarn => StateKind == "warn";
    public bool StateHot => StateKind == "hot";
    public string StateTip => Blocked
        ? "Está en la lista de bloqueo del router y no puede conectarse al Wi-Fi."
        : Limited
            ? $"El router lo frena a {LimitDownKbps} kbps de bajada y {LimitUpKbps} kbps de subida."
            : OnList ? "Está guardado en la lista de bloqueo, pero el bloqueo está apagado: no le afecta." : "Sin límites.";

    /// <summary>Small tags next to the name: who this is, not what is being done to it.</summary>
    public string Role => IsThisPc ? "Este PC" : IsRepeater ? "Repetidor" : "";
    public bool HasRole => Role.Length > 0;
    public string Tooltip => $"MAC {Mac}" + (IsRepeater ? "\nLo que se conecta a través de este repetidor aparece como un solo dispositivo." : "");

    public bool CanBlock => !IsThisPc && !Blocked;
    public bool CanLimit => !GameMode && !Blocked && !Limited && Ip != null;
    public bool CanRemoveLimit => !GameMode && Limited && Ip != null;
    public bool CanUnblock => Blocked;
    public bool CanForget => OnList && !Blocked;

    /// <summary>The one undo action shown on the row itself; everything else lives in the "⋯" menu.</summary>
    public string PrimaryLabel => CanUnblock ? "Desbloquear" : CanRemoveLimit ? "Quitar límite" : "";
    public bool HasPrimary => PrimaryLabel.Length > 0;
    public bool HasMenu => CanLimit || CanBlock || CanForget;
    public string ForgetLabel => Blocked ? "Desbloquear" : "Quitar de la lista";
    public double BarWidth => Math.Round(Math.Clamp(Share, 0, 1) * 120);
}
