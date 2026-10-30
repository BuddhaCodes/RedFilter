using System.Globalization;
using System.Text.Json;

namespace RedFilter.Core.Router;

public static class OpenWrtClient
{
    // hostapd multiplies ban_time by 1000 and stores it in a signed 32-bit microsecond field.
    // 30 minutes stays inside that field. A longer value can wrap.
    public const int BanMilliseconds = 30 * 60 * 1000;

    private static readonly RouterCapabilities Caps = new(
        ListClients: true,
        Disconnect: true,
        Block: true,
        Unblock: true,
        AllowReconnect: true,
        SetPriority: false,
        Wake: false,
        Limitations: "OpenWrt disconnect, block, and unblock each send one hostapd admin request for the selected client. " +
                     "A block lasts 30 minutes in the router's memory and ends if the router restarts. " +
                     "Unblock clears that ban. OpenWrt also sends one disassociate as part of clearing it. " +
                     "Broadcast and group addresses are rejected.");

    public static async Task<IRouterSession> LoginAsync(
        IRouterTransport transport,
        RouterEndpoint endpoint,
        string username,
        string password,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(username))
            throw new RouterException("Admin username is missing. OpenWrt ubus needs the username, usually root.");

        var loginBody = JsonSerializer.Serialize(new
        {
            jsonrpc = "2.0",
            id = 1,
            method = "call",
            @params = new object[]
            {
                "00000000000000000000000000000000",
                "session",
                "login",
                new { username, password }
            }
        });
        var response = await PostAsync(transport, endpoint, loginBody, password, cancellationToken);
        var payload = Ubus.Unwrap(response, password, login: true);
        var session = payload.TryGetProperty("ubus_rpc_session", out var sessionElement)
            ? sessionElement.GetString()
            : null;
        if (string.IsNullOrWhiteSpace(session))
            throw new RouterException("OpenWrt accepted the call but did not return a session id.");

        var model = "OpenWrt";
        var firmware = (string?)null;
        try
        {
            var boardJson = await CallAsync(transport, endpoint, session, "system", "board", password, cancellationToken);
            var board = Ubus.Unwrap(boardJson, password, login: false);
            if (board.ValueKind == JsonValueKind.Object)
            {
                if (board.TryGetProperty("model", out var modelElement) && modelElement.GetString() is { Length: > 0 } modelName)
                    model = modelName;
                if (board.TryGetProperty("release", out var release) && release.ValueKind == JsonValueKind.Object)
                {
                    var distribution = release.TryGetProperty("distribution", out var distributionElement) ? distributionElement.GetString() : "OpenWrt";
                    var version = release.TryGetProperty("version", out var versionElement) ? versionElement.GetString() : null;
                    firmware = string.IsNullOrWhiteSpace(version) ? distribution : $"{distribution} {version}";
                }
            }
        }
        catch (RouterException ex) when (ex.Message.Contains("ubus status", StringComparison.Ordinal))
        {
            firmware = "Board information is missing: " + ex.Message;
        }

        return new Session(transport, endpoint, session, password, model, firmware);
    }

    private static async Task<string> CallAsync(
        IRouterTransport transport,
        RouterEndpoint endpoint,
        string session,
        string target,
        string method,
        string password,
        CancellationToken cancellationToken,
        object? arguments = null)
    {
        var body = JsonSerializer.Serialize(new
        {
            jsonrpc = "2.0",
            id = 1,
            method = "call",
            @params = new object?[] { session, target, method, arguments ?? new { } }
        });
        return await PostAsync(transport, endpoint, body, password, cancellationToken);
    }

    private static async Task<string> PostAsync(
        IRouterTransport transport,
        RouterEndpoint endpoint,
        string body,
        string password,
        CancellationToken cancellationToken)
    {
        var response = await transport.SendAsync(new RouterHttpRequest
        {
            Method = HttpMethod.Post,
            Url = endpoint.Append("/ubus"),
            Body = body,
            ContentType = "application/json"
        }, cancellationToken);
        if (response.StatusCode is < 200 or >= 300)
        {
            throw new RouterException(
                $"OpenWrt ubus returned HTTP {response.StatusCode}. {SecretText.Excerpt(response.Body, password)}");
        }

        return response.Body;
    }

    private sealed class Session : IRouterSession
    {
        private readonly IRouterTransport _transport;
        private readonly RouterEndpoint _endpoint;
        private readonly string _session;
        private readonly string _password;

        public Session(IRouterTransport transport, RouterEndpoint endpoint, string session, string password, string? model, string? firmware)
        {
            _transport = transport;
            _endpoint = endpoint;
            _session = session;
            _password = password;
            Model = model;
            Firmware = firmware;
        }

        public string Brand => "OpenWrt";
        public string? Model { get; }
        public string? Firmware { get; }
        public RouterCapabilities Capabilities => Caps;

        public async Task<RouterClientList> GetClientsAsync(CancellationToken cancellationToken)
        {
            var objects = await ListHostapdAsync(cancellationToken);
            var notes = new List<string>();
            if (objects.Count == 0)
                notes.Add("No hostapd.* object was listed. Wireless clients cannot be read until hostapd is running and this login can see it.");

            var names = await TryHostHintsAsync(notes, cancellationToken);
            var clients = new Dictionary<string, RouterClient>(StringComparer.OrdinalIgnoreCase);
            foreach (var target in objects)
            {
                string json;
                try
                {
                    json = await CallAsync(_transport, _endpoint, _session, target, "get_clients", _password, cancellationToken);
                }
                catch (RouterException ex)
                {
                    notes.Add($"{target} get_clients failed: {ex.Message}");
                    continue;
                }

                JsonElement payload;
                try
                {
                    payload = Ubus.Unwrap(json, _password, login: false);
                }
                catch (RouterException ex)
                {
                    notes.Add($"{target} get_clients failed: {ex.Message}");
                    continue;
                }

                var band = Band(payload);
                if (!payload.TryGetProperty("clients", out var table) || table.ValueKind != JsonValueKind.Object)
                    continue;

                foreach (var entry in table.EnumerateObject())
                {
                    if (!MacAddress.TryNormalize(entry.Name, out var mac))
                        continue;
                    names.TryGetValue(mac, out var hint);
                    var rx = NestedLong(entry.Value, "bytes", "rx");
                    var tx = NestedLong(entry.Value, "bytes", "tx");
                    var signal = JsonLong(entry.Value, "signal");
                    var rateRx = NestedLong(entry.Value, "rate", "rx");
                    var rateTx = NestedLong(entry.Value, "rate", "tx");
                    var label = $"Wi-Fi {band} on {target}";
                    if (signal != null)
                        label += $", {signal} dBm";
                    if (rateRx != null || rateTx != null)
                        label += $", PHY rx {rateRx ?? 0} / tx {rateTx ?? 0} kbps";
                    clients[mac] = new RouterClient(
                        mac,
                        hint.Name,
                        hint.Ip,
                        true,
                        false,
                        label,
                        rx,
                        tx,
                        null,
                        null,
                        null);
                }
            }

            foreach (var target in objects)
            {
                try
                {
                    var json = await CallAsync(_transport, _endpoint, _session, target, "list_bans", _password, cancellationToken);
                    var payload = Ubus.Unwrap(json, _password, login: false);
                    if (!payload.TryGetProperty("clients", out var banned) || banned.ValueKind != JsonValueKind.Array)
                        continue;
                    foreach (var item in banned.EnumerateArray())
                    {
                        var raw = item.ValueKind == JsonValueKind.String ? item.GetString() : null;
                        if (!MacAddress.TryNormalize(raw, out var mac))
                            continue;
                        if (clients.TryGetValue(mac, out var existing))
                        {
                            clients[mac] = existing with { IsBanned = true, ConnectionLabel = existing.ConnectionLabel + ", banned" };
                        }
                        else
                        {
                            names.TryGetValue(mac, out var hint);
                            clients[mac] = new RouterClient(mac, hint.Name, hint.Ip, true, true, $"Banned on {target}", null, null, null, null, null);
                        }
                    }
                }
                catch (RouterException ex)
                {
                    notes.Add($"{target} list_bans failed: {ex.Message}");
                }
            }

            var note = notes.Count == 0
                ? "Usage is the byte counters reported by hostapd."
                : string.Join(" ", notes);
            return new RouterClientList(clients.Values.OrderBy(client => client.Mac).ToList(), RouterUsageKind.TransferredBytes, note);
        }

        public Task<RouterActionResult> DisconnectAsync(string mac, CancellationToken cancellationToken) =>
            KickAsync(mac, banMilliseconds: null, cancellationToken);

        public Task<RouterActionResult> BlockAsync(string mac, CancellationToken cancellationToken) =>
            KickAsync(mac, BanMilliseconds, cancellationToken);

        public Task<RouterActionResult> UnblockAsync(string mac, CancellationToken cancellationToken) =>
            ClearBanAsync(mac, cancellationToken);

        public Task<RouterActionResult> SetPriorityAsync(RouterClient client, bool priority, CancellationToken cancellationToken) =>
            Task.FromResult(new RouterActionResult(false, "OpenWrt hostapd has no priority action in this app. " + Caps.Limitations));

        public Task<RouterActionResult> WakeAsync(string mac, CancellationToken cancellationToken) =>
            Task.FromResult(new RouterActionResult(false, "Wake-on-LAN is not implemented for OpenWrt. " + Caps.Limitations));

        private async Task<RouterActionResult> KickAsync(string mac, int? banMilliseconds, CancellationToken cancellationToken)
        {
            var address = MacAddress.RequireUnicast(mac);
            var objects = await ListHostapdAsync(cancellationToken);
            if (objects.Count == 0)
                return new RouterActionResult(false, "No hostapd interface is available, so the client was not changed.");

            var arguments = banMilliseconds is null
                ? (object)new { addr = address, reason = 5, deauth = true }
                : new { addr = address, reason = 5, deauth = true, ban_time = banMilliseconds.Value };

            var errors = new List<string>();
            var sent = 0;
            foreach (var target in objects)
            {
                try
                {
                    var json = await CallAsync(_transport, _endpoint, _session, target, "del_client", _password, cancellationToken, arguments);
                    Ubus.Unwrap(json, _password, login: false);
                    sent++;
                }
                catch (RouterException ex)
                {
                    errors.Add($"{target}: {ex.Message}");
                }
            }

            if (sent == 0)
                return new RouterActionResult(false, "The router did not accept the request. " + string.Join(" ", errors));

            var action = banMilliseconds is null
                ? $"Disconnected {address} with one request on {sent} radio{(sent == 1 ? "" : "s")}. The client can join again."
                : $"Blocked {address} for 30 minutes with one request on {sent} radio{(sent == 1 ? "" : "s")}. The ban is stored in router memory.";
            if (errors.Count > 0)
                action += " Some radios reported: " + string.Join(" ", errors);
            return new RouterActionResult(true, action);
        }

        private async Task<RouterActionResult> ClearBanAsync(string mac, CancellationToken cancellationToken)
        {
            var address = MacAddress.RequireUnicast(mac);
            var objects = await ListHostapdAsync(cancellationToken);
            if (objects.Count == 0)
                return new RouterActionResult(false, "No hostapd interface is available, so the ban was not changed.");

            var arguments = new { addr = address, reason = 1, deauth = false, ban_time = 0 };
            var sent = 0;
            var errors = new List<string>();
            foreach (var target in objects)
            {
                try
                {
                    var json = await CallAsync(_transport, _endpoint, _session, target, "del_client", _password, cancellationToken, arguments);
                    Ubus.Unwrap(json, _password, login: false);
                    sent++;
                }
                catch (RouterException ex)
                {
                    errors.Add($"{target}: {ex.Message}");
                }
            }

            if (sent == 0)
                return new RouterActionResult(false, "The ban was not cleared. " + string.Join(" ", errors));
            return new RouterActionResult(true,
                $"Cleared the ban for {address}. OpenWrt also sends one disassociate while doing that. The client can join again.");
        }

        private async Task<List<string>> ListHostapdAsync(CancellationToken cancellationToken)
        {
            var body = JsonSerializer.Serialize(new
            {
                jsonrpc = "2.0",
                id = 1,
                method = "list",
                @params = new object[] { _session, "hostapd.*" }
            });
            var response = await PostAsync(_transport, _endpoint, body, _password, cancellationToken);
            using var document = Parse(response);
            if (!document.RootElement.TryGetProperty("result", out var result))
                throw new RouterException("OpenWrt ubus list did not return a result. " + SecretText.Excerpt(response, _password));

            var names = new List<string>();
            if (result.ValueKind == JsonValueKind.Object)
            {
                foreach (var property in result.EnumerateObject())
                {
                    if (property.Name.StartsWith("hostapd.", StringComparison.Ordinal))
                        names.Add(property.Name);
                }
            }

            return names;
        }

        private async Task<Dictionary<string, (string? Name, string? Ip)>> TryHostHintsAsync(List<string> notes, CancellationToken cancellationToken)
        {
            var map = new Dictionary<string, (string? Name, string? Ip)>(StringComparer.OrdinalIgnoreCase);
            try
            {
                var json = await CallAsync(_transport, _endpoint, _session, "luci-rpc", "getHostHints", _password, cancellationToken);
                var payload = Ubus.Unwrap(json, _password, login: false);
                if (payload.ValueKind != JsonValueKind.Object)
                    return map;
                foreach (var entry in payload.EnumerateObject())
                {
                    if (!MacAddress.TryNormalize(entry.Name, out var mac) || entry.Value.ValueKind != JsonValueKind.Object)
                        continue;
                    var name = JsonString(entry.Value, "name");
                    var ip = JsonString(entry.Value, "ipv4");
                    if (ip == null && entry.Value.TryGetProperty("ipv4", out var ipv4) && ipv4.ValueKind == JsonValueKind.Array)
                        ip = ipv4.EnumerateArray().Select(item => item.GetString()).FirstOrDefault(value => !string.IsNullOrWhiteSpace(value));
                    map[mac] = (name, ip);
                }
            }
            catch (RouterException ex)
            {
                notes.Add("Names are missing because luci-rpc getHostHints failed: " + ex.Message);
            }

            return map;
        }
    }

    private static JsonDocument Parse(string json)
    {
        try
        {
            return JsonDocument.Parse(json);
        }
        catch (JsonException)
        {
            throw new RouterException("The address did not return OpenWrt ubus JSON. " + SecretText.Excerpt(json, null));
        }
    }

    private static string Band(JsonElement payload)
    {
        if (!payload.TryGetProperty("freq", out var freq) || !freq.TryGetInt32(out var mhz))
            return "radio";
        if (mhz >= 5925)
            return "6 GHz";
        if (mhz >= 3000)
            return "5 GHz";
        if (mhz > 0)
            return "2.4 GHz";
        return "radio";
    }

    private static string? JsonString(JsonElement element, string name)
    {
        if (!element.TryGetProperty(name, out var value))
            return null;
        return value.ValueKind switch
        {
            JsonValueKind.String => value.GetString(),
            JsonValueKind.Number => value.ToString(),
            _ => null
        };
    }

    private static long? JsonLong(JsonElement element, string name)
    {
        if (!element.TryGetProperty(name, out var value))
            return null;
        if (value.ValueKind == JsonValueKind.Number && value.TryGetInt64(out var number))
            return number;
        if (value.ValueKind == JsonValueKind.String && long.TryParse(value.GetString(), NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsed))
            return parsed;
        return null;
    }

    private static long? NestedLong(JsonElement element, string objectName, string name)
    {
        if (!element.TryGetProperty(objectName, out var child) || child.ValueKind != JsonValueKind.Object)
            return null;
        return JsonLong(child, name);
    }
}

internal static class Ubus
{
    public static JsonElement Unwrap(string json, string? secret, bool login)
    {
        JsonDocument document;
        try
        {
            document = JsonDocument.Parse(json);
        }
        catch (JsonException)
        {
            throw new RouterException("The address did not return OpenWrt ubus JSON. " + SecretText.Excerpt(json, secret));
        }

        var root = document.RootElement;
        if (root.TryGetProperty("error", out var error))
            throw new RouterException("OpenWrt ubus error: " + SecretText.Excerpt(error.ToString(), secret));
        if (!root.TryGetProperty("result", out var result))
            throw new RouterException("OpenWrt ubus response had no result. " + SecretText.Excerpt(json, secret));
        if (result.ValueKind == JsonValueKind.Array)
        {
            if (result.GetArrayLength() == 0)
                throw new RouterException("OpenWrt ubus returned an empty result.");
            var code = result[0].GetInt32();
            if (code != 0)
            {
                throw new RouterException(login && code == 6
                    ? "Login failed. OpenWrt rejected the username or password (ubus status 6)."
                    : Status(code));
            }

            if (result.GetArrayLength() == 1)
                return default;
            return result[1].Clone();
        }

        return result.Clone();
    }

    private static string Status(int code) => code switch
    {
        2 => "OpenWrt rejected the arguments (ubus status 2, invalid argument).",
        3 => "OpenWrt does not provide that method (ubus status 3, not found).",
        4 => "OpenWrt could not find that object (ubus status 4, not found).",
        6 => "OpenWrt denied the request (ubus status 6, permission denied).",
        7 => "OpenWrt timed out (ubus status 7).",
        8 => "OpenWrt does not support that operation (ubus status 8).",
        _ => $"OpenWrt returned ubus status {code}."
    };
}
