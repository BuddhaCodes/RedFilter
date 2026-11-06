using System.Collections.ObjectModel;
using System.Globalization;
using System.Text.RegularExpressions;
using Avalonia.Threading;
using RedFilter.Core.Router;
using RedFilter.Core.Router.TpLink;
using RedFilter.Core.Settings;
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

    public string Status { get => _status; private set => Set(ref _status, value); }
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
                         $"¿Bloquear a {row.Name} ({row.Mac}) del Wi-Fi?\n\nSe desconectará y no podrá volver a entrar hasta que lo desbloquees aquí. Al aplicar el cambio, el router puede cortar el Wi-Fi a todos unos segundos."))
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

    private Dictionary<string, string?> _names = new(StringComparer.OrdinalIgnoreCase);

    private string Describe(string mac)
    {
        var name = _names.TryGetValue(mac, out var known) && !string.IsNullOrWhiteSpace(known) ? known : "Dispositivo sin nombre";
        return _local.IsOwnMac(mac) ? $"{name} ({mac}) — este PC" : $"{name} ({mac})";
    }

    private void Apply(WifiSnapshot snapshot)
    {
        _names = snapshot.Leases.ToDictionary(lease => lease.Mac, lease => lease.Name, StringComparer.OrdinalIgnoreCase);
        var connected = snapshot.Devices.Where(device => device.Connected).ToList();
        var busiest = connected.Count == 0 ? 0 : connected.Max(device => device.PacketsPerSecond);

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

        var top = Devices.FirstOrDefault(row => row.PacketsPerSecond >= 1);
        var mode = snapshot.AccessControl.Mode switch
        {
            AccessControlMode.DenyListed => $"Bloqueo encendido ({snapshot.AccessControl.Macs.Count} en la lista).",
            AccessControlMode.AllowListed => "Tu router solo admite los dispositivos de su lista (modo \"Allow Listed\"); RedFilter no cambia ese modo.",
            _ => snapshot.AccessControl.Macs.Count > 0
                ? $"Bloqueo apagado, pero la lista del router tiene {snapshot.AccessControl.Macs.Count} dispositivo(s) guardado(s)."
                : "Nadie bloqueado."
        };
        Status = (top == null
            ? $"{Devices.Count} dispositivos en tu Wi-Fi, ninguno usando la red ahora mismo. "
            : $"{Devices.Count} dispositivos en tu Wi-Fi. Ahora mismo el que más usa es {top.Name}. ") + mode;
    }

    private WifiDeviceRow Row(WifiDevice device, int rank, double busiest)
    {
        var name = string.IsNullOrWhiteSpace(device.Name) ? "Dispositivo sin nombre" : device.Name!;
        return new WifiDeviceRow
        {
            Mac = device.Mac,
            Name = name,
            Detail = string.Join("  ·  ", new[] { device.Ip, device.Mac }.Where(text => !string.IsNullOrWhiteSpace(text))),
            Rank = rank > 0 ? rank.ToString(CultureInfo.InvariantCulture) : "",
            PacketsPerSecond = device.PacketsPerSecond,
            Share = busiest <= 0 ? 0 : device.PacketsPerSecond / busiest,
            Activity = device.Connected
                ? device.PacketsPerSecond < 1 ? "Sin actividad" : $"{device.PacketsPerSecond:0} paquetes/s"
                : "Desconectado",
            IsThisPc = _local.IsOwnMac(device.Mac),
            IsRepeater = RepeaterName.IsMatch(name),
            Blocked = device.Blocked,
            OnList = device.OnAccessList
        };
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

    public string Badge => IsThisPc ? "Este PC" : Blocked ? "Bloqueado" : IsRepeater ? "Repetidor" : OnList ? "En la lista" : "";
    public bool HasBadge => Badge.Length > 0;
    public bool CanBlock => !IsThisPc && !Blocked;
    public bool CanUnblock => OnList;
    public string UnblockLabel => Blocked ? "Desbloquear" : "Quitar de la lista";
    public double BarWidth => Math.Round(Math.Clamp(Share, 0, 1) * 160);
}
