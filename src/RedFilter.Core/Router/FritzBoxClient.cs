using System.Globalization;
using System.Net;
using System.Text;
using System.Xml.Linq;

namespace RedFilter.Core.Router;

public static class FritzBoxClient
{
    private const string HostsService = "urn:dslforum-org:service:Hosts:1";
    private const string DeviceInfoService = "urn:dslforum-org:service:DeviceInfo:1";

    private static readonly RouterCapabilities Caps = new(
        ListClients: true,
        Disconnect: false,
        Block: false,
        Unblock: false,
        AllowReconnect: false,
        SetPriority: true,
        Wake: true,
        Limitations: "FRITZ!Box lists clients through the documented TR-064 API. " +
                     "The speed figure is link speed in Mbit/s, not a live byte counter. " +
                     "Realtime priority and Wake-on-LAN are available. " +
                     "TR-064 has no documented action that disconnects one Wi-Fi client or edits the MAC filter, so those actions are not sent.");

    public static async Task<IRouterSession> LoginAsync(
        IRouterTransport transport,
        RouterEndpoint endpoint,
        string username,
        string password,
        CancellationToken cancellationToken)
    {
        var loginUrl = endpoint.Append("/login_sid.lua?version=2");
        var page = await transport.SendAsync(new RouterHttpRequest { Url = loginUrl }, cancellationToken);
        if (page.StatusCode is < 200 or >= 300 || !page.Body.Contains("SessionInfo", StringComparison.Ordinal))
        {
            throw new RouterException(
                $"This address did not return a FRITZ!Box login_sid.lua page (HTTP {page.StatusCode}). {SecretText.Excerpt(page.Body, password)}");
        }

        var (_, blockTime) = FritzChallenge.ReadLoginPage(page.Body);
        if (blockTime > 0)
        {
            throw new RouterException(
                $"The FRITZ!Box asked for a wait of {blockTime} seconds before another login. RedFilter did not send the password.");
        }

        // The web-interface SID is not needed: every call below uses TR-064 with digest authentication,
        // which also checks the credentials. Skipping the web login avoids counting against the
        // FRITZ!Box login-failure delay and leaving an open web session behind.

        var descriptionUrl = new Uri($"http://{endpoint.Host}:49000/tr64desc.xml");
        RouterHttpResponse description;
        try
        {
            description = await transport.SendAsync(new RouterHttpRequest { Url = descriptionUrl }, cancellationToken);
        }
        catch (RouterException ex)
        {
            throw new RouterException(
                "Login to the FRITZ!Box web interface succeeded, but TR-064 on port 49000 did not answer. " +
                "Client list, priority, and Wake-on-LAN need TR-064. " +
                "In the FRITZ!Box UI, enable Home Network > Network > Network Settings > Allow access for applications, if it is off. " +
                ex.Message);
        }

        if (description.StatusCode is < 200 or >= 300)
        {
            throw new RouterException(
                $"Login succeeded, but TR-064 description at {descriptionUrl} returned HTTP {description.StatusCode}. " +
                "Enable TR-064 (Allow access for applications) on the FRITZ!Box. " +
                SecretText.Excerpt(description.Body, password));
        }

        var document = XmlValues.Parse(description.Body);
        var services = document.Descendants()
            .Where(element => element.Name.LocalName == "service")
            .Select(element => new Tr64Service(
                XmlValues.Text(element, "serviceType") ?? "",
                XmlValues.Text(element, "serviceId") ?? "",
                XmlValues.Text(element, "controlURL") ?? ""))
            .Where(service => service.ServiceType.Length > 0 && service.ControlUrl.Length > 0)
            .ToList();
        var hosts = services.FirstOrDefault(service => service.ServiceType == HostsService);
        if (hosts == null)
        {
            throw new RouterException(
                "TR-064 answered, but the description has no Hosts:1 service. The client list cannot be read from this device.");
        }

        var model = XmlValues.Text(document, "modelName") ?? XmlValues.Text(document, "friendlyName") ?? "FRITZ!Box";
        var session = new Session(transport, endpoint, username, password, hosts, services, model);
        await session.VerifyCredentialsAsync(cancellationToken);
        session.Firmware = await session.TrySoftwareVersionAsync(cancellationToken);
        return session;
    }

    private sealed class Session : IRouterSession
    {
        private readonly IRouterTransport _transport;
        private readonly RouterEndpoint _endpoint;
        private readonly string _username;
        private readonly string _password;
        private readonly Tr64Service _hosts;
        private readonly IReadOnlyList<Tr64Service> _services;
        private readonly DigestClient _digest;

        public Session(
            IRouterTransport transport,
            RouterEndpoint endpoint,
            string username,
            string password,
            Tr64Service hosts,
            IReadOnlyList<Tr64Service> services,
            string model)
        {
            _transport = transport;
            _endpoint = endpoint;
            _username = username;
            _password = password;
            _hosts = hosts;
            _services = services;
            _digest = new DigestClient(transport, username, password);
            Model = model;
        }

        public async Task VerifyCredentialsAsync(CancellationToken cancellationToken)
        {
            try
            {
                await SoapAsync(_hosts, "GetHostNumberOfEntries", "", cancellationToken);
            }
            catch (RouterException ex) when (ex.Message.Contains("HTTP 401", StringComparison.Ordinal))
            {
                throw new RouterException("Login failed. The FRITZ!Box rejected the username or password over TR-064.");
            }
        }

        public string Brand => "FRITZ!Box";
        public string? Model { get; }
        public string? Firmware { get; set; }
        public RouterCapabilities Capabilities => Caps;

        public async Task<RouterClientList> GetClientsAsync(CancellationToken cancellationToken)
        {
            var clients = new List<RouterClient>();
            var note = "Link speed is the FRITZ!Box Mbit/s figure, not a live byte counter.";
            try
            {
                var path = await SoapValueAsync(_hosts, "X_AVM-DE_GetHostListPath", "", "NewX_AVM-DE_HostListPath", cancellationToken);
                if (!string.IsNullOrWhiteSpace(path))
                    clients = await ReadListAsync(path, cancellationToken);
            }
            catch (RouterException ex)
            {
                note = "The host-list path failed (" + ex.Message + "). Falling back to one TR-064 entry per host.";
            }

            if (clients.Count == 0)
                clients = await ReadIndexedHostsAsync(cancellationToken);

            if (clients.Count == 0)
                note += " The router returned no hosts.";
            return new RouterClientList(clients, RouterUsageKind.LinkSpeed, note + " " + Caps.Limitations);
        }

        public Task<RouterActionResult> DisconnectAsync(string mac, CancellationToken cancellationToken) =>
            Task.FromResult(new RouterActionResult(false, "Disconnect was not sent. " + Caps.Limitations));

        public Task<RouterActionResult> BlockAsync(string mac, CancellationToken cancellationToken) =>
            Task.FromResult(new RouterActionResult(false, "Block was not sent. " + Caps.Limitations));

        public Task<RouterActionResult> UnblockAsync(string mac, CancellationToken cancellationToken) =>
            Task.FromResult(new RouterActionResult(false, "Unblock was not sent. " + Caps.Limitations));

        public async Task<RouterActionResult> SetPriorityAsync(RouterClient client, bool priority, CancellationToken cancellationToken)
        {
            if (string.IsNullOrWhiteSpace(client.IpAddress))
                return new RouterActionResult(false, "Priority needs the client's IP address, and this row does not have one.");
            if (!IPAddress.TryParse(client.IpAddress, out _))
                return new RouterActionResult(false, "Priority was not sent because the IP address is not valid.");

            var body =
                $"<NewIPAddress>{Escape(client.IpAddress)}</NewIPAddress>" +
                $"<NewX_AVM-DE_Priority>{(priority ? "1" : "0")}</NewX_AVM-DE_Priority>";
            await SoapAsync(_hosts, "X_AVM-DE_SetPrioritizationByIP", body, cancellationToken);
            return new RouterActionResult(true,
                priority
                    ? $"Asked the FRITZ!Box to give realtime priority to {client.IpAddress}."
                    : $"Asked the FRITZ!Box to clear realtime priority for {client.IpAddress}.");
        }

        public async Task<RouterActionResult> WakeAsync(string mac, CancellationToken cancellationToken)
        {
            var address = MacAddress.RequireUnicast(mac);
            await SoapAsync(_hosts, "X_AVM-DE_WakeOnLANByMACAddress", $"<NewMACAddress>{address}</NewMACAddress>", cancellationToken);
            return new RouterActionResult(true, $"Sent a Wake-on-LAN request for {address} through TR-064.");
        }

        public async Task<string?> TrySoftwareVersionAsync(CancellationToken cancellationToken)
        {
            var info = _services.FirstOrDefault(service => service.ServiceType == DeviceInfoService);
            if (info == null)
                return null;
            try
            {
                return await SoapValueAsync(info, "GetInfo", "", "NewSoftwareVersion", cancellationToken);
            }
            catch (RouterException)
            {
                return null;
            }
        }

        private async Task<List<RouterClient>> ReadListAsync(string path, CancellationToken cancellationToken)
        {
            var url = Resolve(path);
            var response = await _digest.SendAsync(new RouterHttpRequest { Url = url }, cancellationToken);
            if (response.StatusCode is < 200 or >= 300)
                throw new RouterException($"The host list returned HTTP {response.StatusCode}.");
            var document = XmlValues.Parse(response.Body);
            return XmlValues.Items(document).Select(ReadItem).Where(client => client != null).Cast<RouterClient>().ToList();
        }

        private async Task<List<RouterClient>> ReadIndexedHostsAsync(CancellationToken cancellationToken)
        {
            var countText = await SoapValueAsync(_hosts, "GetHostNumberOfEntries", "", "NewHostNumberOfEntries", cancellationToken);
            if (!int.TryParse(countText, out var count))
                return new List<RouterClient>();
            count = Math.Clamp(count, 0, 256);
            var clients = new List<RouterClient>();
            for (var index = 0; index < count; index++)
            {
                var xml = await SoapAsync(_hosts, "GetGenericHostEntry", $"<NewIndex>{index}</NewIndex>", cancellationToken);
                var document = XmlValues.Parse(xml);
                var macText = XmlValues.Text(document, "NewMACAddress");
                if (!MacAddress.TryNormalize(macText, out var mac))
                    continue;
                var active = XmlValues.Text(document, "NewActive") is "1" or "true";
                if (!active)
                    continue;
                var type = XmlValues.Text(document, "NewInterfaceType") ?? "";
                clients.Add(new RouterClient(
                    mac,
                    XmlValues.Text(document, "NewHostName"),
                    XmlValues.Text(document, "NewIPAddress"),
                    type.Contains("802.11", StringComparison.OrdinalIgnoreCase),
                    false,
                    string.IsNullOrWhiteSpace(type) ? "Connected" : type,
                    null,
                    null,
                    null,
                    null,
                    null));
            }

            return clients;
        }

        private static RouterClient? ReadItem(XElement item)
        {
            if (!MacAddress.TryNormalize(XmlValues.Text(item, "MACAddress"), out var mac))
                return null;
            var active = XmlValues.Text(item, "Active");
            if (active is "0" or "false")
                return null;
            var type = XmlValues.Text(item, "InterfaceType") ?? "";
            var speedText = XmlValues.Text(item, "X_AVM-DE_Speed");
            int? speed = int.TryParse(speedText, out var parsed) ? parsed : null;
            var priority = XmlValues.Text(item, "X_AVM-DE_Priority");
            var name = XmlValues.Text(item, "X_AVM-DE_FriendlyName");
            if (string.IsNullOrWhiteSpace(name))
                name = XmlValues.Text(item, "HostName");
            var label = string.IsNullOrWhiteSpace(type) ? "Connected" : type;
            if (speed is > 0)
                label += $", link {speed} Mbit/s";
            if (priority is "1" or "true")
                label += ", realtime priority";
            return new RouterClient(
                mac,
                name,
                XmlValues.Text(item, "IPAddress"),
                type.Contains("802.11", StringComparison.OrdinalIgnoreCase),
                false,
                label,
                null,
                null,
                null,
                speed,
                priority is "1" or "true" ? true : priority is "0" or "false" ? false : null);
        }

        private Uri Resolve(string path)
        {
            if (Uri.TryCreate(path, UriKind.Absolute, out var absolute) && absolute.Scheme is "http" or "https")
            {
                if (!absolute.Host.Equals(_endpoint.Host, StringComparison.OrdinalIgnoreCase))
                    throw new RouterException($"The FRITZ!Box returned a list URL on {absolute.Host}. RedFilter will not contact that host.");
                return absolute;
            }

            var relative = path.StartsWith('/') ? path : "/" + path;
            return new Uri($"http://{_endpoint.Host}:49000{relative}");
        }

        private async Task<string?> SoapValueAsync(Tr64Service service, string action, string inner, string resultName, CancellationToken cancellationToken)
        {
            var xml = await SoapAsync(service, action, inner, cancellationToken);
            return XmlValues.Text(XmlValues.Parse(xml), resultName);
        }

        private async Task<string> SoapAsync(Tr64Service service, string action, string inner, CancellationToken cancellationToken)
        {
            var control = Resolve(service.ControlUrl);
            var envelope =
                "<?xml version=\"1.0\" encoding=\"utf-8\"?>" +
                "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">" +
                "<s:Body>" +
                $"<u:{action} xmlns:u=\"{service.ServiceType}\">{inner}</u:{action}>" +
                "</s:Body></s:Envelope>";
            var response = await _digest.SendAsync(new RouterHttpRequest
            {
                Method = HttpMethod.Post,
                Url = control,
                Body = envelope,
                ContentType = "text/xml",
                Headers = new Dictionary<string, string>
                {
                    ["SOAPACTION"] = $"\"{service.ServiceType}#{action}\""
                }
            }, cancellationToken);
            if (response.StatusCode is < 200 or >= 300)
            {
                throw new RouterException(
                    $"TR-064 {action} returned HTTP {response.StatusCode}. {SecretText.Excerpt(response.Body, _password)}");
            }

            var document = XmlValues.Parse(response.Body);
            if (document.Descendants().Any(element => element.Name.LocalName == "Fault"))
            {
                var fault = XmlValues.Text(document, "errorDescription") ?? XmlValues.Text(document, "faultstring");
                throw new RouterException($"TR-064 {action} failed: {fault ?? "the router returned a SOAP fault."}");
            }

            return response.Body;
        }

        private static string Escape(string value) =>
            value.Replace("&", "&amp;", StringComparison.Ordinal)
                .Replace("<", "&lt;", StringComparison.Ordinal)
                .Replace(">", "&gt;", StringComparison.Ordinal);
    }

    private sealed record Tr64Service(string ServiceType, string ServiceId, string ControlUrl);
}
