namespace RedFilter.Core.Router.TpLink;

/// <summary>One Wi-Fi device as the app shows it: what the router reports, joined with DHCP names.</summary>
public sealed record WifiDevice(
    string Mac,
    string? Name,
    string? Ip,
    bool Connected,
    bool OnAccessList,
    bool Blocked,
    double PacketsPerSecond,
    long TotalPackets,
    double? TxRateMbps);

public sealed record WifiSnapshot(
    IReadOnlyList<WifiDevice> Devices,
    AccessControlState AccessControl,
    IReadOnlyList<DhcpLease> Leases);

/// <summary>
/// Talks to the web interface of a TP-Link TD-W8961N v5 (Realtek firmware) over an already
/// signed-in transport. Every change is one form post, followed by reading the page back to
/// confirm what the router actually stored.
/// </summary>
public sealed class TdW8961Client
{
    private readonly IRouterTransport _transport;
    private readonly RouterEndpoint _endpoint;
    private readonly WifiUsageTracker _usage = new();

    public TdW8961Client(IRouterTransport transport, RouterEndpoint endpoint)
    {
        _transport = transport;
        _endpoint = endpoint;
    }

    public async Task<WifiSnapshot> ReadAsync(CancellationToken cancellationToken)
    {
        var stations = TdW8961Pages.ParseStations(await GetAsync(TdW8961Pages.StationsPage, cancellationToken));
        var leases = TdW8961Pages.ParseDhcp(await GetAsync(TdW8961Pages.DhcpPage, cancellationToken));
        var access = await ReadAccessControlAsync(cancellationToken);
        var rates = _usage.Update(stations, DateTime.UtcNow);
        var byMac = leases.ToDictionary(lease => lease.Mac, StringComparer.OrdinalIgnoreCase);

        var devices = new List<WifiDevice>();
        foreach (var station in stations)
        {
            byMac.TryGetValue(station.Mac, out var lease);
            var listed = access.Contains(station.Mac);
            devices.Add(new WifiDevice(
                station.Mac,
                lease?.Name,
                lease?.Ip,
                true,
                listed,
                listed && access.Mode == AccessControlMode.DenyListed,
                rates.TryGetValue(station.Mac, out var rate) ? rate : 0,
                station.TotalPackets,
                station.TxRateMbps));
        }

        // Devices on the block list are shown even when they are not connected, so they can be unblocked.
        foreach (var mac in access.Macs.Where(mac => devices.All(device => !device.Mac.Equals(mac, StringComparison.OrdinalIgnoreCase))))
        {
            byMac.TryGetValue(mac, out var lease);
            devices.Add(new WifiDevice(mac, lease?.Name, lease?.Ip, false, true, access.Mode == AccessControlMode.DenyListed, 0, 0, null));
        }

        var ordered = devices
            .OrderByDescending(device => device.PacketsPerSecond)
            .ThenByDescending(device => device.TotalPackets)
            .ThenBy(device => device.Name ?? device.Mac, StringComparer.OrdinalIgnoreCase)
            .ToList();
        return new WifiSnapshot(ordered, access, leases);
    }

    public async Task<AccessControlState> ReadAccessControlAsync(CancellationToken cancellationToken) =>
        TdW8961Pages.ParseAccessControl(await GetAsync(TdW8961Pages.AccessControlPage, cancellationToken));

    /// <summary>
    /// Puts one MAC on the list and switches the list to "Deny Listed". The caller must already have
    /// dealt with any other MAC on the list, because switching the mode blocks all of them.
    /// </summary>
    public async Task<AccessControlState> BlockAsync(string mac, CancellationToken cancellationToken)
    {
        var normalized = MacAddress.RequireUnicast(mac);
        var state = await ReadAccessControlAsync(cancellationToken);
        if (state.Mode == AccessControlMode.AllowListed)
        {
            throw new RouterException(
                "The router's Wi-Fi access list is in \"Allow Listed\" mode, where only listed devices may connect. " +
                "RedFilter will not switch that mode, because it could lock out every other device.");
        }

        if (!state.Contains(normalized))
            await PostAsync(TdW8961Pages.AccessControlForm, TdW8961Pages.AddToAccessListBody(normalized, state.Mode), cancellationToken);
        if (state.Mode != AccessControlMode.DenyListed)
            await PostAsync(TdW8961Pages.AccessControlForm, TdW8961Pages.SetAccessModeBody(AccessControlMode.DenyListed), cancellationToken);

        var after = await ReadAccessControlAsync(cancellationToken);
        if (!after.Contains(normalized) || after.Mode != AccessControlMode.DenyListed)
            throw new RouterException("The router did not confirm the block. Open its Access Control List page to check it.");
        return after;
    }

    /// <summary>Takes one MAC off the list. When the list ends up empty, blocking is switched off.</summary>
    public async Task<AccessControlState> RemoveFromListAsync(string mac, CancellationToken cancellationToken)
    {
        var normalized = MacAddress.RequireUnicast(mac);
        var state = await ReadAccessControlAsync(cancellationToken);
        if (state.Contains(normalized))
            await PostAsync(TdW8961Pages.AccessControlForm, TdW8961Pages.RemoveFromAccessListBody(normalized, state.Macs.Count), cancellationToken);

        var after = await ReadAccessControlAsync(cancellationToken);
        if (after.Contains(normalized))
            throw new RouterException("The router did not confirm the removal. Open its Access Control List page to check it.");
        if (after.Macs.Count == 0 && after.Mode == AccessControlMode.DenyListed)
        {
            await PostAsync(TdW8961Pages.AccessControlForm, TdW8961Pages.SetAccessModeBody(AccessControlMode.Disabled), cancellationToken);
            after = await ReadAccessControlAsync(cancellationToken);
        }

        return after;
    }

    private async Task<string> GetAsync(string page, CancellationToken cancellationToken)
    {
        var response = await _transport.SendAsync(new RouterHttpRequest { Url = _endpoint.Append("/" + page) }, cancellationToken);
        return Check(response, page);
    }

    private async Task PostAsync(string form, string body, CancellationToken cancellationToken)
    {
        var response = await _transport.SendAsync(new RouterHttpRequest
        {
            Method = HttpMethod.Post,
            Url = _endpoint.Append("/" + form),
            Body = body,
            ContentType = "application/x-www-form-urlencoded"
        }, cancellationToken);
        Check(response, form);
    }

    private static string Check(RouterHttpResponse response, string page)
    {
        if (response.StatusCode is 401 or 403 || TdW8961Pages.IsLoginPage(response.Body))
            throw new RouterException("The router session expired.") { SessionExpired = true };
        if (response.StatusCode is < 200 or >= 400)
            throw new RouterException($"The router answered {page} with HTTP {response.StatusCode}.");
        return response.Body;
    }
}
