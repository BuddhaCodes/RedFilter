using System.Globalization;
using System.Text;
using System.Text.Json;

namespace RedFilter.Core.Router;

public static class AsusWrtClient
{
    private static readonly RouterCapabilities Caps = new(
        ListClients: true,
        Disconnect: false,
        Block: false,
        Unblock: false,
        AllowReconnect: false,
        SetPriority: false,
        Wake: false,
        Limitations: "ASUSWRT lists clients through its local appGet.cgi admin API. " +
                     "Disconnect, block, unblock, and reconnect are not sent. " +
                     "The stock admin API has no confirmed request that drops one Wi-Fi client, " +
                     "and restarting wireless would disconnect every device.");

    public static async Task<IRouterSession> LoginAsync(
        IRouterTransport transport,
        RouterEndpoint endpoint,
        string username,
        string password,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(username))
            throw new RouterException("Admin username is missing. ASUSWRT needs the router admin username.");

        var token = Convert.ToBase64String(Encoding.UTF8.GetBytes(username + ":" + password));
        var response = await transport.SendAsync(new RouterHttpRequest
        {
            Method = HttpMethod.Post,
            Url = endpoint.Append("/login.cgi"),
            Body = "login_authorization=" + Uri.EscapeDataString(token),
            ContentType = "application/x-www-form-urlencoded",
            Headers = new Dictionary<string, string>
            {
                ["User-Agent"] = "asusrouter-Android-DUTUtil-1.0.0.201"
            }
        }, cancellationToken);

        if (response.StatusCode is < 200 or >= 300)
        {
            throw new RouterException(
                $"ASUSWRT login returned HTTP {response.StatusCode}. {SecretText.Excerpt(response.Body, password)}");
        }

        string? asusToken = null;
        try
        {
            using var document = JsonDocument.Parse(response.Body);
            if (document.RootElement.TryGetProperty("asus_token", out var tokenElement))
                asusToken = tokenElement.GetString();
        }
        catch (JsonException)
        {
            asusToken = null;
        }

        if (string.IsNullOrWhiteSpace(asusToken))
        {
            throw new RouterException(
                "Login failed. ASUSWRT did not return a session token. " + SecretText.Excerpt(response.Body, password));
        }

        var session = new Session(transport, endpoint, asusToken, password);
        var (model, firmware) = await session.ReadIdentityAsync(cancellationToken);
        session.Model = model;
        session.Firmware = firmware;
        return session;
    }

    private sealed class Session : IRouterSession
    {
        private readonly IRouterTransport _transport;
        private readonly RouterEndpoint _endpoint;
        private readonly string _token;
        private readonly string _password;

        public Session(IRouterTransport transport, RouterEndpoint endpoint, string token, string password)
        {
            _transport = transport;
            _endpoint = endpoint;
            _token = token;
            _password = password;
        }

        public string Brand => "ASUSWRT";
        public string? Model { get; set; }
        public string? Firmware { get; set; }
        public RouterCapabilities Capabilities => Caps;

        public async Task<RouterClientList> GetClientsAsync(CancellationToken cancellationToken)
        {
            var body = await HookAsync("get_clientlist()", cancellationToken);
            JsonDocument document;
            try
            {
                document = JsonDocument.Parse(body);
            }
            catch (JsonException)
            {
                throw new RouterException(
                    "Logged in, but the ASUSWRT client list was not JSON. " + SecretText.Excerpt(body, _password));
            }

            using (document)
            {
                var root = document.RootElement;
                if (root.TryGetProperty("get_clientlist", out var nested))
                    root = nested;
                if (root.ValueKind != JsonValueKind.Object)
                    throw new RouterException("Logged in, but the ASUSWRT client list had an unexpected shape.");

                var clients = new List<RouterClient>();
                var reported = false;
                foreach (var property in root.EnumerateObject())
                {
                    if (!MacAddress.TryNormalize(property.Name, out var mac) || property.Value.ValueKind != JsonValueKind.Object)
                        continue;
                    var online = JsonString(property.Value, "isOnline");
                    if (online is "0")
                        continue;
                    var name = First(JsonString(property.Value, "nickName"), JsonString(property.Value, "name"));
                    var ip = JsonString(property.Value, "ip");
                    var wireless = JsonString(property.Value, "isWL") is not ("0" or "" or null);
                    var curRx = JsonString(property.Value, "curRx");
                    var curTx = JsonString(property.Value, "curTx");
                    var totalRx = JsonLong(property.Value, "totalRx");
                    var totalTx = JsonLong(property.Value, "totalTx");
                    if (!string.IsNullOrWhiteSpace(curRx) || !string.IsNullOrWhiteSpace(curTx))
                        reported = true;
                    var rssi = JsonString(property.Value, "rssi");
                    var ssid = JsonString(property.Value, "ssid");
                    var connection = wireless ? "Wi-Fi" : "LAN";
                    if (!string.IsNullOrWhiteSpace(ssid))
                        connection += " " + ssid;
                    if (!string.IsNullOrWhiteSpace(rssi) && rssi != "0")
                        connection += $", RSSI {rssi}";
                    var rate = string.IsNullOrWhiteSpace(curRx) && string.IsNullOrWhiteSpace(curTx)
                        ? null
                        : $"rx {curRx} / tx {curTx}";
                    clients.Add(new RouterClient(
                        mac,
                        name,
                        ip,
                        wireless,
                        false,
                        connection,
                        totalRx,
                        totalTx,
                        rate,
                        null,
                        null));
                }

                var kind = reported ? RouterUsageKind.ReportedRate : RouterUsageKind.TransferredBytes;
                var note = clients.Count == 0
                    ? "Login succeeded. ASUSWRT returned no online clients."
                    : reported
                        ? "Current rx/tx values are shown as the router reported them. " + Caps.Limitations
                        : "ASUSWRT did not fill curRx/curTx. Totals are used when they are numbers. " + Caps.Limitations;
                return new RouterClientList(clients, kind, note);
            }
        }

        public Task<RouterActionResult> DisconnectAsync(string mac, CancellationToken cancellationToken) =>
            Task.FromResult(Unavailable("Disconnect"));

        public Task<RouterActionResult> BlockAsync(string mac, CancellationToken cancellationToken) =>
            Task.FromResult(Unavailable("Block"));

        public Task<RouterActionResult> UnblockAsync(string mac, CancellationToken cancellationToken) =>
            Task.FromResult(Unavailable("Unblock"));

        public Task<RouterActionResult> SetPriorityAsync(RouterClient client, bool priority, CancellationToken cancellationToken) =>
            Task.FromResult(Unavailable("Priority"));

        public Task<RouterActionResult> WakeAsync(string mac, CancellationToken cancellationToken) =>
            Task.FromResult(Unavailable("Wake-on-LAN"));

        public async Task<(string? Model, string? Firmware)> ReadIdentityAsync(CancellationToken cancellationToken)
        {
            var model = await TryNvramAsync("productid", cancellationToken);
            var firmware = await TryNvramAsync("firmver", cancellationToken);
            var build = await TryNvramAsync("buildno", cancellationToken);
            if (!string.IsNullOrWhiteSpace(build))
                firmware = string.IsNullOrWhiteSpace(firmware) ? build : firmware + "." + build;
            return (model, firmware);
        }

        private async Task<string?> TryNvramAsync(string key, CancellationToken cancellationToken)
        {
            try
            {
                var body = await HookAsync($"nvram_get({key})", cancellationToken);
                var trimmed = body.Trim().Trim('"');
                if (trimmed.StartsWith('{') || trimmed.StartsWith('['))
                {
                    using var document = JsonDocument.Parse(trimmed);
                    return FindString(document.RootElement, key) ?? FindString(document.RootElement, "nvram_get");
                }

                return trimmed.Length is > 0 and < 80 ? trimmed : null;
            }
            catch (RouterException)
            {
                return null;
            }
        }

        private async Task<string> HookAsync(string hook, CancellationToken cancellationToken)
        {
            var response = await _transport.SendAsync(new RouterHttpRequest
            {
                Method = HttpMethod.Post,
                Url = _endpoint.Append("/appGet.cgi"),
                Body = "hook=" + Uri.EscapeDataString(hook),
                ContentType = "application/x-www-form-urlencoded",
                Headers = new Dictionary<string, string>
                {
                    ["User-Agent"] = "asusrouter-Android-DUTUtil-1.0.0.201",
                    ["Cookie"] = "asus_token=" + _token
                }
            }, cancellationToken);
            if (response.StatusCode is < 200 or >= 300)
            {
                throw new RouterException(
                    $"ASUSWRT {hook} returned HTTP {response.StatusCode}. {SecretText.Excerpt(response.Body, _password)}");
            }

            return response.Body;
        }

        private static RouterActionResult Unavailable(string action) =>
            new(false, $"{action} was not sent. {Caps.Limitations}");

        private static string? FindString(JsonElement element, string name)
        {
            if (element.ValueKind == JsonValueKind.Object)
            {
                foreach (var property in element.EnumerateObject())
                {
                    if (property.Name.Equals(name, StringComparison.OrdinalIgnoreCase) && property.Value.ValueKind == JsonValueKind.String)
                        return property.Value.GetString();
                    var nested = FindString(property.Value, name);
                    if (nested != null)
                        return nested;
                }
            }

            return null;
        }
    }

    private static string? JsonString(JsonElement element, string name)
    {
        if (!element.TryGetProperty(name, out var value))
            return null;
        return value.ValueKind switch
        {
            JsonValueKind.String => value.GetString(),
            JsonValueKind.Number => value.ToString(),
            JsonValueKind.True => "1",
            JsonValueKind.False => "0",
            _ => null
        };
    }

    private static long? JsonLong(JsonElement element, string name)
    {
        var text = JsonString(element, name);
        return long.TryParse(text, NumberStyles.Integer, CultureInfo.InvariantCulture, out var value) ? value : null;
    }

    private static string? First(params string?[] values) =>
        values.FirstOrDefault(value => !string.IsNullOrWhiteSpace(value));
}
