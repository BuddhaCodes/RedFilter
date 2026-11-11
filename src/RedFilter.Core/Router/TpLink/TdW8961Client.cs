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
    double? TxRateMbps,
    int? LimitUpKbps = null,
    int? LimitDownKbps = null)
{
    public bool Limited => LimitUpKbps != null || LimitDownKbps != null;
}

public sealed record WifiSnapshot(
    IReadOnlyList<WifiDevice> Devices,
    AccessControlState AccessControl,
    IReadOnlyList<DhcpLease> Leases,
    ShapingState? Shaping = null);

/// <summary>
/// Talks to the web interface of a TP-Link TD-W8961N v5 (Realtek firmware) over an already
/// signed-in transport. Every change is one form post, followed by reading the page back to
/// confirm what the router actually stored.
/// </summary>
public sealed class TdW8961Client
{
    private readonly IRouterTransport _transport;
    private readonly RouterEndpoint _endpoint;
    private readonly WifiUsageTracker _usage;

    /// <param name="usage">
    /// Keeps the packet counters between reads. The session passes the same tracker to every client it
    /// creates, so signing in again does not reset "packets per second" to zero for one poll.
    /// </param>
    public TdW8961Client(IRouterTransport transport, RouterEndpoint endpoint, WifiUsageTracker? usage = null)
    {
        _transport = transport;
        _endpoint = endpoint;
        _usage = usage ?? new WifiUsageTracker();
    }

    public async Task<WifiSnapshot> ReadAsync(CancellationToken cancellationToken)
    {
        var stations = TdW8961Pages.ParseStations(await GetAsync(TdW8961Pages.StationsPage, cancellationToken));
        var leases = TdW8961Pages.ParseDhcp(await GetAsync(TdW8961Pages.DhcpPage, cancellationToken));
        var access = await ReadAccessControlAsync(cancellationToken);
        var shaping = await TryReadShapingAsync(cancellationToken);
        var rates = _usage.Update(stations, DateTime.UtcNow);
        var byMac = leases.ToDictionary(lease => lease.Mac, StringComparer.OrdinalIgnoreCase);

        var devices = new List<WifiDevice>();
        foreach (var station in stations)
        {
            byMac.TryGetValue(station.Mac, out var lease);
            var listed = access.Contains(station.Mac);
            var limit = LimitFor(shaping, lease?.Ip);
            devices.Add(new WifiDevice(
                station.Mac,
                lease?.Name,
                lease?.Ip,
                true,
                listed,
                listed && access.Mode == AccessControlMode.DenyListed,
                rates.TryGetValue(station.Mac, out var rate) ? rate : 0,
                station.TotalPackets,
                station.TxRateMbps,
                limit?.UpCeilingKbps,
                limit?.DownCeilingKbps));
        }

        // Devices on the block list are shown even when they are not connected, so they can be unblocked.
        foreach (var mac in access.Macs.Where(mac => devices.All(device => !device.Mac.Equals(mac, StringComparison.OrdinalIgnoreCase))))
        {
            byMac.TryGetValue(mac, out var lease);
            var limit = LimitFor(shaping, lease?.Ip);
            devices.Add(new WifiDevice(mac, lease?.Name, lease?.Ip, false, true, access.Mode == AccessControlMode.DenyListed, 0, 0, null,
                limit?.UpCeilingKbps, limit?.DownCeilingKbps));
        }

        var ordered = devices
            .OrderByDescending(device => device.PacketsPerSecond)
            .ThenByDescending(device => device.TotalPackets)
            .ThenBy(device => device.Name ?? device.Mac, StringComparer.OrdinalIgnoreCase)
            .ToList();
        return new WifiSnapshot(ordered, access, leases, shaping);
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

    public async Task<ShapingState> ReadShapingAsync(CancellationToken cancellationToken) =>
        TdW8961LimitPages.ParseShaping(await GetAsync(TdW8961LimitPages.ShapingPage, cancellationToken));

    public async Task<StaticLeaseState> ReadStaticLeasesAsync(CancellationToken cancellationToken) =>
        TdW8961LimitPages.ParseStaticLeases(await GetAsync(TdW8961LimitPages.StaticDhcpPage, cancellationToken));

    public async Task<LineSpeed?> ReadLineSpeedAsync(CancellationToken cancellationToken) =>
        TdW8961LimitPages.ParseLineSpeed(await GetAsync(TdW8961LimitPages.StatusPage, cancellationToken));

    /// <summary>
    /// Caps one device's speed. Traffic shaping rules match an IP, so the device's current IP is first
    /// fixed in the router's DHCP (otherwise the limit would stop working when the IP changes). If the
    /// line bandwidth is still "unlimited", it is set a little below the DSL sync speed (85% down, 80% up) so the router knows
    /// how much there is to share. Any older limit for the same IP is replaced. Every step is read back.
    /// </summary>
    public async Task<ShapingRule> LimitAsync(string mac, string ip, int upKbps, int downKbps, CancellationToken cancellationToken)
    {
        var normalized = MacAddress.RequireUnicast(mac);
        if (upKbps <= 0 || downKbps <= 0)
            throw new RouterException("A speed limit must be above 0 kbps.");

        await KeepIpAsync(normalized, ip, cancellationToken);

        var shaping = await ReadShapingAsync(cancellationToken);
        if (shaping.TotalUpKbps == 0 || shaping.TotalDownKbps == 0)
        {
            var line = await ReadLineSpeedAsync(cancellationToken);
            if (line != null)
            {
                var (totalUp, totalDown) = GameModePlanner.ShapingTotals(line);
                await PostAsync(TdW8961LimitPages.ShapingForm, TdW8961LimitPages.SetTotalsBody(totalUp, totalDown), cancellationToken);
                shaping = await ReadShapingAsync(cancellationToken);
            }
        }

        // A ceiling above the line total means nothing to the router; keep it inside.
        if (shaping.TotalUpKbps > 0)
            upKbps = Math.Min(upKbps, shaping.TotalUpKbps);
        if (shaping.TotalDownKbps > 0)
            downKbps = Math.Min(downKbps, shaping.TotalDownKbps);

        shaping = await RemoveLimitsForAsync(ip, shaping, cancellationToken);
        await PostAsync(TdW8961LimitPages.ShapingForm, TdW8961LimitPages.AddLimitBody(ip, upKbps, downKbps), cancellationToken);

        var after = await ReadShapingAsync(cancellationToken);
        var rule = after.LimitsFor(ip).FirstOrDefault(rule => rule.UpCeilingKbps == upKbps && rule.DownCeilingKbps == downKbps);
        return rule ?? throw new RouterException("The router did not confirm the speed limit. Open its IP QoS > Traffic Shaping page to check it.");
    }

    /// <summary>
    /// Removes the limit for one IP. When no shaping rule is left, the line bandwidth goes back to
    /// "unlimited" (0), the way the router ships. The fixed IP in DHCP is kept: it does no harm.
    /// </summary>
    public async Task<ShapingState> RemoveLimitAsync(string ip, CancellationToken cancellationToken)
    {
        var after = await RemoveLimitsForAsync(ip, await ReadShapingAsync(cancellationToken), cancellationToken);
        if (after.Rules.Count == 0 && (after.TotalUpKbps != 0 || after.TotalDownKbps != 0))
        {
            await PostAsync(TdW8961LimitPages.ShapingForm, TdW8961LimitPages.SetTotalsBody(0, 0), cancellationToken);
            after = await ReadShapingAsync(cancellationToken);
        }

        return after;
    }

    /// <summary>
    /// Makes sure the router knows the line speed for sharing. Returns the totals in use; when they
    /// were "unlimited", sets them a little below the DSL sync speed (85% down, 80% up).
    /// </summary>
    public async Task<ShapingState> EnsureLineTotalsAsync(CancellationToken cancellationToken)
    {
        var shaping = await ReadShapingAsync(cancellationToken);
        if (shaping.TotalUpKbps > 0 && shaping.TotalDownKbps > 0)
            return shaping;
        var line = await ReadLineSpeedAsync(cancellationToken)
            ?? throw new RouterException("The router does not show the DSL line speed right now, so RedFilter cannot share it. Is the line connected?");
        var (up, down) = GameModePlanner.ShapingTotals(line);
        await PostAsync(TdW8961LimitPages.ShapingForm, TdW8961LimitPages.SetTotalsBody(up, down), cancellationToken);
        shaping = await ReadShapingAsync(cancellationToken);
        if (shaping.TotalUpKbps <= 0 || shaping.TotalDownKbps <= 0)
            throw new RouterException("The router did not confirm the line speed. Open its IP QoS > Traffic Shaping page to check it.");
        return shaping;
    }

    /// <summary>
    /// Puts the game-mode rules on the router: one per IP, replacing whatever single-IP rule was there.
    /// Rules already in place are left alone, so calling this again when a device joins only touches
    /// what changed. Every rule is read back.
    /// </summary>
    public async Task<ShapingState> ApplyGameModeAsync(GameModePlan plan, CancellationToken cancellationToken)
    {
        var state = await ReadShapingAsync(cancellationToken);
        if (state.TotalUpKbps != plan.TotalUpKbps || state.TotalDownKbps != plan.TotalDownKbps)
        {
            await PostAsync(TdW8961LimitPages.ShapingForm, TdW8961LimitPages.SetTotalsBody(plan.TotalUpKbps, plan.TotalDownKbps), cancellationToken);
            state = await ReadShapingAsync(cancellationToken);
        }

        foreach (var rule in plan.AllRules)
        {
            if (GameModePlanner.IsInPlace(state, rule))
                continue;
            state = await RemoveLimitsForAsync(rule.Ip, state, cancellationToken);
            await PostAsync(TdW8961LimitPages.ShapingForm,
                TdW8961LimitPages.AddRuleBody(rule.Ip, rule.UpFloorKbps, rule.UpCeilingKbps, rule.DownFloorKbps, rule.DownCeilingKbps),
                cancellationToken);
            state = await ReadShapingAsync(cancellationToken);
            if (!GameModePlanner.IsInPlace(state, rule))
                throw new RouterException($"The router did not confirm the game-mode rule for {rule.Ip}. It may be full; open its IP QoS > Traffic Shaping page to check it.");
        }

        return state;
    }

    /// <summary>
    /// Undoes the game mode: removes the rules it put on the IPs it touched, puts back the limits the
    /// user had before, and restores the line totals. Best effort on each step, then one error if any failed.
    /// </summary>
    public async Task<ShapingState> RestoreGameModeAsync(GameModeBackup backup, CancellationToken cancellationToken)
    {
        var state = await ReadShapingAsync(cancellationToken);
        foreach (var ip in backup.TouchedIps.Distinct(StringComparer.Ordinal))
            state = await RemoveLimitsForAsync(ip, state, cancellationToken);

        foreach (var limit in backup.Limits)
        {
            if (limit.UpCeilingKbps is not { } up || limit.DownCeilingKbps is not { } down || state.LimitsFor(limit.Ip).Count > 0)
                continue;
            await PostAsync(TdW8961LimitPages.ShapingForm, TdW8961LimitPages.AddLimitBody(limit.Ip, up, down), cancellationToken);
            state = await ReadShapingAsync(cancellationToken);
        }

        // With no rule left the line goes back to "unlimited", whatever the totals were before: totals
        // without rules still cap the whole line at 85-90% and make everything feel slower.
        var (wantUp, wantDown) = state.Rules.Count == 0 ? (0, 0) : (backup.TotalUpKbps, backup.TotalDownKbps);
        if (state.TotalUpKbps != wantUp || state.TotalDownKbps != wantDown)
        {
            await PostAsync(TdW8961LimitPages.ShapingForm, TdW8961LimitPages.SetTotalsBody(wantUp, wantDown), cancellationToken);
            state = await ReadShapingAsync(cancellationToken);
        }

        if (backup.TouchedIps.Any(ip => state.LimitsFor(ip).Any(rule => !backup.Limits.Any(limit => limit.Ip == ip))))
            throw new RouterException("The router still shows game-mode rules. Open its IP QoS > Traffic Shaping page to check it.");
        return state;
    }

    /// <summary>
    /// Line totals with no rule left do nothing useful but cap the whole line; puts them back to
    /// "unlimited". Returns the state afterwards (its rules are limits the user set by hand).
    /// </summary>
    public async Task<ShapingState> ClearIdleTotalsAsync(CancellationToken cancellationToken)
    {
        var state = await ReadShapingAsync(cancellationToken);
        if (state.Rules.Count == 0 && (state.TotalUpKbps != 0 || state.TotalDownKbps != 0))
        {
            await PostAsync(TdW8961LimitPages.ShapingForm, TdW8961LimitPages.SetTotalsBody(0, 0), cancellationToken);
            state = await ReadShapingAsync(cancellationToken);
        }

        return state;
    }

    /// <summary>The single-IP limits on the router right now, to save before the game mode replaces them.</summary>
    public static List<SavedLimit> SaveLimits(ShapingState state) =>
        state.Rules
            .Where(rule => rule.OnlyMatchesSourceIp && rule.SourceIp != null)
            .GroupBy(rule => rule.SourceIp!, StringComparer.Ordinal)
            .Select(group => new SavedLimit(group.Key, group.First().UpCeilingKbps, group.First().DownCeilingKbps))
            .ToList();

    private async Task KeepIpAsync(string mac, string ip, CancellationToken cancellationToken)
    {
        var statics = await ReadStaticLeasesAsync(cancellationToken);
        if (!statics.InPool(ip))
            return; // Outside the DHCP pool: the device has a fixed IP of its own, and the router refuses to pin it.

        var mine = statics.Leases.FirstOrDefault(lease => lease.Mac.Equals(mac, StringComparison.OrdinalIgnoreCase));
        if (mine != null)
        {
            if (mine.Ip == ip)
                return;
            throw new RouterException(
                $"This device already has the fixed IP {mine.Ip} in the router, but it is using {ip} right now. " +
                "Reconnect it to the Wi-Fi so it takes its fixed IP, then limit it again.");
        }

        if (statics.Leases.Any(lease => lease.Ip == ip))
            throw new RouterException($"The router keeps {ip} for another device, so RedFilter cannot fix it for this one.");

        await PostAsync(TdW8961LimitPages.StaticDhcpForm, TdW8961LimitPages.AddStaticLeaseBody(ip, mac, statics.LeaseTime), cancellationToken);
        var after = await ReadStaticLeasesAsync(cancellationToken);
        if (!after.Leases.Any(lease => lease.Ip == ip && lease.Mac.Equals(mac, StringComparison.OrdinalIgnoreCase)))
            throw new RouterException("The router did not confirm the fixed IP. Open its LAN > DHCP Static IP page to check it.");
    }

    private async Task<ShapingState> RemoveLimitsForAsync(string ip, ShapingState state, CancellationToken cancellationToken)
    {
        // The "Remove" indexes shift after each removal, so remove one rule and read the page again.
        for (var attempts = 0; attempts < 16; attempts++)
        {
            var rule = state.LimitsFor(ip).FirstOrDefault();
            if (rule == null)
                return state;
            await PostAsync(TdW8961LimitPages.ShapingForm, TdW8961LimitPages.RemoveRuleBody(rule.RemoveIndex), cancellationToken);
            var after = await ReadShapingAsync(cancellationToken);
            if (after.LimitsFor(ip).Count >= state.LimitsFor(ip).Count)
                throw new RouterException("The router did not confirm removing the speed limit. Open its IP QoS > Traffic Shaping page to check it.");
            state = after;
        }

        throw new RouterException("The router kept showing a speed limit for this device after removing it.");
    }

    private async Task<ShapingState?> TryReadShapingAsync(CancellationToken cancellationToken)
    {
        try
        {
            return await ReadShapingAsync(cancellationToken);
        }
        catch (RouterException ex) when (!ex.SessionExpired)
        {
            // Limits are extra information; the device list still works without them.
            return null;
        }
    }

    private static ShapingRule? LimitFor(ShapingState? shaping, string? ip) =>
        shaping == null || ip == null ? null : shaping.LimitsFor(ip).FirstOrDefault();

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
