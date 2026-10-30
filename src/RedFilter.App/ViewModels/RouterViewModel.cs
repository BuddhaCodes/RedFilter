using System.Collections.ObjectModel;
using RedFilter.Core.Router;
using RedFilter.Core.Settings;
using RedFilter.Core.Text;

namespace RedFilter.ViewModels;

public sealed class RouterViewModel : ObservableObject
{
    private readonly SettingsStore _store;
    private readonly RouterWorkflow _workflow;
    private readonly Func<string?> _gateway;
    private readonly IUserPrompt? _prompt;
    private string? _password;

    private string _address = "";
    private string _username = "";
    private string _brand = "auto";
    private string _model = "";
    private string _status = "";
    private string _top = "";
    private bool _passwordSaved;
    private bool _busy;
    private ClientRowViewModel? _selected;
    private RouterCapabilities _capabilities = RouterCapabilities.None;
    private RouterUsageKind _usageKind = RouterUsageKind.None;

    public RouterViewModel(SettingsStore store, Func<RouterEndpoint, IRouterTransport> transportFactory, Func<string?> gateway, IUserPrompt? prompt = null)
    {
        _store = store;
        _workflow = new RouterWorkflow(transportFactory);
        _gateway = gateway;
        _prompt = prompt;
        Brands = new ObservableCollection<BrandChoice>
        {
            new() { Id = "auto", Label = "Detect automatically" },
            new() { Id = "openwrt", Label = "OpenWrt" },
            new() { Id = "asuswrt", Label = "ASUSWRT" },
            new() { Id = "fritz", Label = "FRITZ!Box" }
        };
        Load();
    }

    public ObservableCollection<BrandChoice> Brands { get; }
    public ObservableCollection<ClientRowViewModel> Clients { get; } = new();

    public string Address { get => _address; set { if (Set(ref _address, value)) RefreshIdle(); } }
    public string Username { get => _username; set { if (Set(ref _username, value)) RefreshIdle(); } }
    public string Brand
    {
        get => _brand;
        set
        {
            if (!Set(ref _brand, value))
                return;
            Raise(nameof(SelectedBrand));
            RefreshIdle();
        }
    }

    public BrandChoice? SelectedBrand
    {
        get => Brands.FirstOrDefault(choice => choice.Id == _brand);
        set
        {
            if (value == null || value.Id == _brand)
                return;
            Brand = value.Id;
        }
    }
    public string Model { get => _model; set => Set(ref _model, value); }
    public string Status { get => _status; set => Set(ref _status, value); }
    public string Top { get => _top; private set => Set(ref _top, value); }
    public bool PasswordSaved
    {
        get => _passwordSaved;
        private set
        {
            if (Set(ref _passwordSaved, value))
                Raise(nameof(PasswordNote));
        }
    }

    public string PasswordNote => PasswordSaved
        ? "A password is already saved for this Windows user."
        : "No password is saved yet.";
    public bool Busy { get => _busy; private set { if (Set(ref _busy, value)) RaiseActions(); } }

    public ClientRowViewModel? Selected
    {
        get => _selected;
        set { if (Set(ref _selected, value)) RaiseActions(); }
    }

    public bool CanDisconnect => !Busy && _capabilities.Disconnect && Selected is { Source.IsWireless: true };
    public bool CanBlock => !Busy && _capabilities.Block && Selected != null;
    public bool CanUnblock => !Busy && _capabilities.Unblock && Selected is { Source.IsBanned: true };
    public bool CanAllowReconnect => !Busy && _capabilities.AllowReconnect && Selected is { Source.IsBanned: true };
    public bool CanPrioritize => !Busy && _capabilities.SetPriority && Selected?.Source.IpAddress is { Length: > 0 };
    public bool CanClearPriority => CanPrioritize && Selected?.Source.HasPriority == true;
    public bool CanWake => !Busy && _capabilities.Wake && Selected != null;
    public bool ShowPriority => _capabilities.SetPriority;
    public bool ShowWake => _capabilities.Wake;

    public void Load()
    {
        var settings = _store.Load();
        _address = settings.RouterAddress ?? "";
        _username = settings.RouterUsername ?? "";
        _brand = string.IsNullOrWhiteSpace(settings.Brand) ? "auto" : settings.Brand;
        _model = settings.RouterModel ?? "";
        _password = _store.LoadPassword();
        PasswordSaved = !string.IsNullOrEmpty(_password);
        Raise(nameof(Address));
        Raise(nameof(Username));
        Raise(nameof(Brand));
        Raise(nameof(SelectedBrand));
        Raise(nameof(Model));
        Status = IdleStatus();
        Top = "";
    }

    public void UsePassword(string? typed)
    {
        if (!string.IsNullOrEmpty(typed))
        {
            _password = typed;
            PasswordSaved = true;
        }
    }

    public void Save(string? typedPassword)
    {
        if (!string.IsNullOrWhiteSpace(Address) && !RouterEndpoint.TryParse(Address, out _, out var error))
        {
            Status = error;
            return;
        }

        if (!string.IsNullOrEmpty(typedPassword))
            _password = typedPassword;
        var settings = _store.Load();
        settings.RouterAddress = Address.Trim();
        settings.RouterUsername = Username.Trim();
        settings.Brand = Brand;
        settings.RouterModel = string.IsNullOrWhiteSpace(Model) ? null : Model.Trim();
        _store.Save(settings);
        if (!string.IsNullOrEmpty(typedPassword))
            _store.SavePassword(typedPassword);
        PasswordSaved = !string.IsNullOrEmpty(_password);
        Status = string.IsNullOrEmpty(typedPassword) && PasswordSaved
            ? "Settings saved. The stored password was left unchanged. " + IdleStatus()
            : "Settings saved on this PC. " + IdleStatus();
    }

    public void ClearPassword()
    {
        _password = null;
        _store.SavePassword(null);
        PasswordSaved = false;
        Status = "The saved router password was removed. " + IdleStatus();
    }

    public void UseGateway()
    {
        var gateway = _gateway();
        if (string.IsNullOrWhiteSpace(gateway))
        {
            Status = "Windows did not report a default gateway. Type the router address yourself.";
            return;
        }

        Address = "http://" + gateway;
        Status = $"Filled the address with this PC's default gateway ({gateway}). Nothing was contacted yet.";
    }

    public async Task TestAsync()
    {
        Busy = true;
        try
        {
            var inspection = await _workflow.TestAsync(Address, Username, _password, Brand, CancellationToken.None);
            ApplyInspection(inspection);
            if (inspection.Success)
            {
                var settings = _store.Load();
                settings.RouterAddress = Address.Trim();
                settings.RouterUsername = Username.Trim();
                settings.Brand = inspection.Brand ?? Brand;
                settings.RouterModel = inspection.Model;
                _store.Save(settings);
                if (!string.IsNullOrWhiteSpace(inspection.Brand))
                    Brand = inspection.Brand;
                if (!string.IsNullOrWhiteSpace(inspection.Model))
                    Model = inspection.Model;
            }
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

    public async Task RefreshAsync()
    {
        if (_workflow.Session == null)
        {
            Status = "There is no router session yet. Choose Test connection first. " + IdleStatus();
            return;
        }

        Busy = true;
        try
        {
            var list = await _workflow.RefreshAsync(CancellationToken.None);
            if (list == null)
            {
                Status = "There is no router session yet. Choose Test connection first.";
                return;
            }

            _usageKind = list.UsageKind;
            ReplaceClients(list.Clients);
            Status = list.Note;
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

    public Task DisconnectAsync() => RunClientAction(
        "Disconnect this client from Wi-Fi? This sends one admin request. The client can join again.",
        client => _workflow.Session!.DisconnectAsync(client.Mac, CancellationToken.None));

    public Task BlockAsync() => RunClientAction(
        "Block this client for 30 minutes? This sends one admin request. It is not repeated.",
        client => _workflow.Session!.BlockAsync(client.Mac, CancellationToken.None));

    public Task UnblockAsync() => RunClientAction(
        "Clear the temporary ban? The client can join again. On OpenWrt this also sends one disassociate.",
        client => _workflow.Session!.UnblockAsync(client.Mac, CancellationToken.None));

    public Task AllowReconnectAsync() => RunClientAction(
        "Allow this client to reconnect by clearing the temporary ban?",
        client => _workflow.Session!.UnblockAsync(client.Mac, CancellationToken.None));

    public Task PrioritizeAsync() => RunClientAction(
        "Give this client realtime priority on the FRITZ!Box?",
        client => _workflow.Session!.SetPriorityAsync(client, true, CancellationToken.None));

    public Task ClearPriorityAsync() => RunClientAction(
        "Clear realtime priority for this client?",
        client => _workflow.Session!.SetPriorityAsync(client, false, CancellationToken.None));

    public Task WakeAsync() => RunClientAction(
        "Send Wake-on-LAN to this client through the FRITZ!Box?",
        client => _workflow.Session!.WakeAsync(client.Mac, CancellationToken.None));

    private async Task RunClientAction(string confirm, Func<RouterClient, Task<RouterActionResult>> action)
    {
        var selected = Selected;
        if (selected == null)
        {
            Status = "Select a client first.";
            return;
        }

        if (_workflow.Session == null)
        {
            Status = "There is no router session. Choose Test connection first.";
            return;
        }

        if (_prompt == null || !await _prompt.ConfirmAsync(confirm + "\n\n" + selected.Name + "  " + selected.Mac))
            return;

        Busy = true;
        try
        {
            var result = await action(selected.Source);
            if (result.Success && _workflow.Session != null)
            {
                var list = await _workflow.Session.GetClientsAsync(CancellationToken.None);
                _usageKind = list.UsageKind;
                ReplaceClients(list.Clients);
            }

            Status = result.Message;
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

    private void ApplyInspection(RouterInspection inspection)
    {
        _capabilities = inspection.Capabilities;
        _usageKind = inspection.UsageKind;
        ReplaceClients(inspection.Clients);
        Status = inspection.Status;
        RaiseActions();
        Raise(nameof(ShowPriority));
        Raise(nameof(ShowWake));
    }

    private void ReplaceClients(IReadOnlyList<RouterClient> clients)
    {
        var ranked = clients
            .Select(client => new { Client = client, Score = Score(client) })
            .OrderByDescending(item => item.Score)
            .ThenBy(item => item.Client.Name)
            .ToList();
        Clients.Clear();
        for (var i = 0; i < ranked.Count; i++)
        {
            var item = ranked[i];
            Clients.Add(new ClientRowViewModel
            {
                Name = string.IsNullOrWhiteSpace(item.Client.Name) ? "(name not reported)" : item.Client.Name!,
                Mac = item.Client.Mac,
                Ip = item.Client.IpAddress ?? "",
                Connection = item.Client.ConnectionLabel,
                Usage = Usage(item.Client),
                Rank = item.Score > 0 && i < 3 ? (i + 1).ToString() : "",
                Score = item.Score,
                Source = item.Client
            });
        }

        var top = Clients.Where(row => row.Rank.Length > 0).Select(row => row.Name).ToList();
        Top = top.Count == 0
            ? "No usage ranking yet."
            : _usageKind switch
            {
                RouterUsageKind.TransferredBytes => "Top by transferred bytes: " + string.Join(", ", top) + ".",
                RouterUsageKind.ReportedRate => "Top by the rate the router reported: " + string.Join(", ", top) + ".",
                RouterUsageKind.LinkSpeed => "Highest Wi-Fi link speed: " + string.Join(", ", top) + ". This is not a live byte counter.",
                _ => "Clients are listed. The router did not return usage figures."
            };
    }

    private static long Score(RouterClient client)
    {
        var bytes = (client.RxBytes ?? 0) + (client.TxBytes ?? 0);
        if (bytes > 0)
            return bytes;
        if (!string.IsNullOrWhiteSpace(client.ReportedRate))
            return 1;
        return client.LinkSpeedMbps ?? 0;
    }

    private static string Usage(RouterClient client)
    {
        if (client.RxBytes != null || client.TxBytes != null)
            return "rx " + RateText.ByteCount(client.RxBytes ?? 0) + ", tx " + RateText.ByteCount(client.TxBytes ?? 0);
        if (!string.IsNullOrWhiteSpace(client.ReportedRate))
            return client.ReportedRate;
        if (client.LinkSpeedMbps is > 0)
            return client.LinkSpeedMbps + " Mbit/s link";
        return "not reported";
    }

    private string IdleStatus()
    {
        var missing = new List<string>();
        if (string.IsNullOrWhiteSpace(Address))
            missing.Add("router address");
        if (string.IsNullOrWhiteSpace(Username) && Brand != "fritz")
            missing.Add("admin username");
        if (!PasswordSaved)
            missing.Add("admin password");
        if (missing.Count == 0)
            return "Saved settings are ready. Choose Test connection to sign in. RedFilter contacts only this address and does not guess a password.";
        return "Still missing: " + string.Join(", ", missing) + ". The client list stays empty until a supported router answers. RedFilter does not guess credentials and does not scan the network.";
    }

    private void RefreshIdle()
    {
        if (_workflow.Session == null && !Busy)
            Status = IdleStatus();
    }

    private void RaiseActions()
    {
        Raise(nameof(CanDisconnect));
        Raise(nameof(CanBlock));
        Raise(nameof(CanUnblock));
        Raise(nameof(CanAllowReconnect));
        Raise(nameof(CanPrioritize));
        Raise(nameof(CanClearPriority));
        Raise(nameof(CanWake));
    }
}
