using System.Text.Json;
using RedFilter.Core.Processes;
using RedFilter.Core.Qos;
using RedFilter.Core.Router;
using RedFilter.Core.Settings;

namespace RedFilter.Core.Tests;

public sealed class FritzChallengeTests
{
    [Fact]
    public void Pbkdf2MatchesTheAvmExample()
    {
        var response = FritzChallenge.Calculate("2$10000$5A1711$2000$5A1722", "1example!");
        Assert.Equal("5A1722$1798a1672bca7c6463d6b245f82b53703b0f50813401b03e4045a5861e689adb", response);
    }

    [Fact]
    public void Md5UsesUtf16Le()
    {
        var response = FritzChallenge.Calculate("1234567z", "äbc");
        Assert.Equal("1234567z-9e224a41eeefa284df7bb0f26c2913e2", response);
    }
}

public sealed class MacAddressTests
{
    [Theory]
    [InlineData("aa-bb-cc-dd-ee-ff", "AA:BB:CC:DD:EE:FF")]
    [InlineData("aabbccddeeff", "AA:BB:CC:DD:EE:FF")]
    public void Normalizes(string raw, string expected)
    {
        Assert.True(MacAddress.TryNormalize(raw, out var mac));
        Assert.Equal(expected, mac);
    }

    [Theory]
    [InlineData("FF:FF:FF:FF:FF:FF")]
    [InlineData("01:00:5E:00:00:01")]
    [InlineData("not-a-mac")]
    public void RejectsBroadcastAndGroup(string raw)
    {
        var error = Assert.Throws<RouterException>(() => MacAddress.RequireUnicast(raw));
        Assert.False(string.IsNullOrWhiteSpace(error.Message));
    }
}

public sealed class RouterEndpointTests
{
    [Fact]
    public void AddsHttpAndKeepsTheHost()
    {
        var endpoint = RouterEndpoint.Parse("192.168.1.1");
        Assert.Equal("http://192.168.1.1/", endpoint.Origin.AbsoluteUri);
        Assert.False(endpoint.HostIsPublicIp);
    }

    [Fact]
    public void RejectsASubnet()
    {
        var ok = RouterEndpoint.TryParse("192.168.1.0/24", out _, out var error);
        Assert.False(ok);
        Assert.Contains("subnet", error, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void RejectsCredentialsInTheAddress()
    {
        var ok = RouterEndpoint.TryParse("http://admin:secret@192.168.1.1", out _, out var error);
        Assert.False(ok);
        Assert.Contains("password", error, StringComparison.OrdinalIgnoreCase);
    }
}

public sealed class QosPlannerTests
{
    [Fact]
    public void LimitsOtherProgramsAndSkipsSystemProcesses()
    {
        var owner = Row(10, "game", @"C:\Games\game.exe", 2);
        var processes = new[]
        {
            owner,
            Row(11, "game", @"C:\Games\game.exe", 1),
            Row(20, "chrome", @"C:\Apps\chrome.exe", 4),
            Row(21, "chrome", @"C:\Apps\chrome.exe", 1),
            Row(4, "System", null, 3),
            Row(30, "svchost", @"C:\Windows\System32\svchost.exe", 8),
            Row(40, "mystery", null, 2)
        };

        var plan = QosPolicyPlanner.Build(owner, processes, 1_000_000, @"C:\RedFilter\RedFilter.exe");

        Assert.Equal(2, plan.Policies.Count);
        Assert.Contains(plan.Policies, policy => policy.IsOwner && policy.ThrottleBitsPerSecond == null && policy.Dscp == 46);
        var limit = Assert.Single(plan.Policies, policy => !policy.IsOwner);
        Assert.Equal(@"C:\Apps\chrome.exe", limit.AppPath);
        Assert.Equal(1_000_000, limit.ThrottleBitsPerSecond);
        Assert.Contains(plan.Notes, note => note.Contains("svchost", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(plan.Notes, note => note.Contains("1 process", StringComparison.Ordinal));
    }

    [Fact]
    public void RefusesAZeroThrottle()
    {
        Assert.Equal(64_000, QosPolicyPlanner.NormalizeThrottle(0));
    }

    [Fact]
    public void ScriptEscapesQuotesAndStaysInTheActiveStore()
    {
        var script = NetQosScript.Apply(
            new[] { "RedFilter-Limit-ABCDEF123456" },
            new[]
            {
                new QosPolicySpec("RedFilter-Owner", @"C:\Program Files\O'Brien\game.exe", true, 46, null)
            });

        Assert.Contains("PolicyStore ActiveStore", script, StringComparison.Ordinal);
        Assert.Contains(@"C:\Program Files\O''Brien\game.exe", script, StringComparison.Ordinal);
        Assert.DoesNotContain("GroupPolicy", script, StringComparison.Ordinal);
        Assert.Contains("DSCPAction 46", script, StringComparison.Ordinal);
    }

    [Fact]
    public void ParserAcceptsOneObjectOrAnArray()
    {
        var one = NetQosPolicyParser.Parse("""{"Name":"RedFilter-Owner","AppPathNameMatchCondition":"C:\\game.exe","ThrottleRateActionBitsPerSecond":null,"DSCPAction":46}""");
        var policy = Assert.Single(one);
        Assert.Equal(46, policy.Dscp);
        Assert.Null(policy.ThrottleBitsPerSecond);

        var none = NetQosPolicyParser.Parse("noise\n[]\n");
        Assert.Empty(none);
    }

    private static ProcessNetworkRow Row(int pid, string name, string? path, int connections) =>
        new(pid, name, path, connections, 0, 0, 0);
}

public sealed class SettingsStoreTests
{
    [Fact]
    public void PasswordIsNotWrittenToTheJsonFile()
    {
        var directory = Path.Combine(Path.GetTempPath(), "redfilter-tests-" + Guid.NewGuid().ToString("N"));
        var store = new SettingsStore(directory, new PlainProtector());
        store.Save(new AppSettings { RouterAddress = "http://192.168.1.1", RouterUsername = "root" });
        store.SavePassword("super-secret-password");

        var json = File.ReadAllText(store.SettingsPath);
        Assert.DoesNotContain("super-secret-password", json, StringComparison.Ordinal);
        Assert.Equal("super-secret-password", store.LoadPassword());
        store.SavePassword(null);
        Assert.Null(store.LoadPassword());
    }

    private sealed class PlainProtector : ISecretProtector
    {
        public byte[] Protect(byte[] plaintext) => plaintext;
        public byte[] Unprotect(byte[] ciphertext) => ciphertext;
    }
}

public sealed class RouterClientTests
{
    [Fact]
    public async Task UnknownRouterDoesNotReceiveThePassword()
    {
        var transport = new ScriptedTransport(request => new RouterHttpResponse
        {
            StatusCode = 200,
            Body = "<html><title>Archer C6</title><body>TP-LINK</body></html>"
        });
        var workflow = new RouterWorkflow(_ => transport);
        var result = await workflow.TestAsync("http://192.168.0.1", "admin", "super-secret-password", "auto", CancellationToken.None);

        Assert.False(result.Success);
        Assert.Contains("TP-Link", result.Status, StringComparison.Ordinal);
        Assert.DoesNotContain(transport.Calls, call => (call.Body ?? "").Contains("super-secret-password", StringComparison.Ordinal));
    }

    [Fact]
    public async Task OpenWrtDisconnectIsOneUnicastRequest()
    {
        var transport = new ScriptedTransport(request =>
        {
            var body = request.Body ?? "";
            if (body.Contains("\"login\"", StringComparison.Ordinal))
                return Json("""{"jsonrpc":"2.0","id":1,"result":[0,{"ubus_rpc_session":"abc"}]}""");
            if (body.Contains("\"board\"", StringComparison.Ordinal))
                return Json("""{"jsonrpc":"2.0","id":1,"result":[0,{"model":"Test AP","release":{"distribution":"OpenWrt","version":"24.10.0"}}]}""");
            if (body.Contains("\"list\"", StringComparison.Ordinal))
                return Json("""{"jsonrpc":"2.0","id":1,"result":{"hostapd.phy0-ap0":{"del_client":{}}}}""");
            if (body.Contains("get_clients", StringComparison.Ordinal))
            {
                return Json("""{"jsonrpc":"2.0","id":1,"result":[0,{"freq":5180,"clients":{"AA:BB:CC:DD:EE:FF":{"signal":-40,"bytes":{"rx":1000,"tx":2000},"rate":{"rx":65000,"tx":65000}}}}]}""");
            }

            if (body.Contains("list_bans", StringComparison.Ordinal))
                return Json("""{"jsonrpc":"2.0","id":1,"result":[0,{"clients":[]}]}""");
            if (body.Contains("getHostHints", StringComparison.Ordinal))
                return Json("""{"jsonrpc":"2.0","id":1,"result":[0,{"aa:bb:cc:dd:ee:ff":{"name":"phone","ipv4":"192.168.1.20"}}]}""");
            if (body.Contains("del_client", StringComparison.Ordinal))
                return Json("""{"jsonrpc":"2.0","id":1,"result":[0]}""");
            return new RouterHttpResponse { StatusCode = 404, Body = "missing" };
        });

        var endpoint = RouterEndpoint.Parse("http://192.168.1.1");
        var session = await OpenWrtClient.LoginAsync(transport, endpoint, "root", "secret", CancellationToken.None);
        Assert.Equal("Test AP", session.Model);
        var clients = await session.GetClientsAsync(CancellationToken.None);
        var client = Assert.Single(clients.Clients);
        Assert.Equal("phone", client.Name);
        Assert.Equal(1000, client.RxBytes);

        var callsBefore = transport.Calls.Count;
        var blocked = await session.BlockAsync("AA:BB:CC:DD:EE:FF", CancellationToken.None);
        Assert.True(blocked.Success);
        var kicks = transport.Calls.Skip(callsBefore).Where(call => (call.Body ?? "").Contains("del_client", StringComparison.Ordinal)).ToList();
        var kick = Assert.Single(kicks);
        Assert.Contains("\"ban_time\":1800000", kick.Body, StringComparison.Ordinal);
        Assert.DoesNotContain("FF:FF:FF:FF:FF:FF", kick.Body, StringComparison.Ordinal);
        await Assert.ThrowsAsync<RouterException>(() => session.DisconnectAsync("FF:FF:FF:FF:FF:FF", CancellationToken.None));
    }

    [Fact]
    public async Task AsusListsClientsAndDoesNotSendADisconnect()
    {
        var transport = new ScriptedTransport(request =>
        {
            if (request.Url.AbsolutePath.Contains("login.cgi", StringComparison.Ordinal))
                return Json("""{"asus_token":"token-1"}""");
            var body = request.Body ?? "";
            if (body.Contains("get_clientlist", StringComparison.Ordinal))
            {
                return Json("""{"get_clientlist":{"AA:BB:CC:DD:EE:FF":{"name":"laptop","nickName":"","ip":"192.168.1.9","mac":"AA:BB:CC:DD:EE:FF","isOnline":"1","isWL":"1","curRx":"120","curTx":"40","totalRx":"10","totalTx":"4","rssi":"-50","ssid":"Home"},"maclist":[]}}""");
            }

            return Json("""{"productid":"RT-AX86U"}""");
        });
        var session = await AsusWrtClient.LoginAsync(transport, RouterEndpoint.Parse("http://192.168.50.1"), "admin", "secret", CancellationToken.None);
        var before = transport.Calls.Count;
        var result = await session.DisconnectAsync("AA:BB:CC:DD:EE:FF", CancellationToken.None);
        Assert.False(result.Success);
        Assert.Contains("not sent", result.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(before, transport.Calls.Count);
        var clients = await session.GetClientsAsync(CancellationToken.None);
        Assert.Equal("laptop", clients.Clients[0].Name);
    }

    [Fact]
    public async Task FritzPriorityUsesTr064()
    {
        var transport = new ScriptedTransport(request =>
        {
            if (request.Url.AbsolutePath.Contains("login_sid.lua", StringComparison.Ordinal))
            {
                if (request.Method == HttpMethod.Get)
                {
                    return Xml("""<SessionInfo><SID>0000000000000000</SID><Challenge>2$10000$5A1711$2000$5A1722</Challenge><BlockTime>0</BlockTime></SessionInfo>""");
                }

                return Xml("""<SessionInfo><SID>0123456789abcdef</SID></SessionInfo>""");
            }

            if (request.Url.AbsolutePath.Contains("tr64desc.xml", StringComparison.Ordinal))
            {
                return Xml("""
                    <root>
                      <device>
                        <modelName>FRITZ!Box 7590</modelName>
                        <serviceList>
                          <service>
                            <serviceType>urn:dslforum-org:service:Hosts:1</serviceType>
                            <serviceId>urn:dslforum-org:service:Hosts:1</serviceId>
                            <controlURL>/upnp/control/hosts</controlURL>
                          </service>
                          <service>
                            <serviceType>urn:dslforum-org:service:DeviceInfo:1</serviceType>
                            <serviceId>urn:dslforum-org:service:DeviceInfo:1</serviceId>
                            <controlURL>/upnp/control/deviceinfo</controlURL>
                          </service>
                        </serviceList>
                      </device>
                    </root>
                    """);
            }

            if (request.Headers == null || !request.Headers.ContainsKey("Authorization"))
            {
                return new RouterHttpResponse
                {
                    StatusCode = 401,
                    Authenticate = new[] { "Digest realm=\"test\", nonce=\"abc\", qop=\"auth\"" }
                };
            }

            var body = request.Body ?? "";
            if (body.Contains("GetInfo", StringComparison.Ordinal))
                return Xml("""<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><NewSoftwareVersion>8.02</NewSoftwareVersion></s:Body></s:Envelope>""");
            if (body.Contains("X_AVM-DE_SetPrioritizationByIP", StringComparison.Ordinal))
                return Xml("""<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body></s:Body></s:Envelope>""");
            return Xml("""<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><faultstring>no</faultstring></s:Body></s:Envelope>""");
        });

        var session = await FritzBoxClient.LoginAsync(transport, RouterEndpoint.Parse("http://192.168.178.1"), "", "1example!", CancellationToken.None);
        Assert.Equal("FRITZ!Box 7590", session.Model);
        Assert.Equal("8.02", session.Firmware);
        var client = new RouterClient("AA:BB:CC:DD:EE:FF", "pc", "192.168.178.24", true, false, "802.11", null, null, null, 866, false);
        var result = await session.SetPriorityAsync(client, true, CancellationToken.None);
        Assert.True(result.Success);
        Assert.Contains(transport.Calls, call => (call.Body ?? "").Contains("X_AVM-DE_SetPrioritizationByIP", StringComparison.Ordinal) && (call.Body ?? "").Contains("192.168.178.24", StringComparison.Ordinal));
        var disconnect = await session.DisconnectAsync(client.Mac, CancellationToken.None);
        Assert.False(disconnect.Success);
        Assert.Contains("not sent", disconnect.Message, StringComparison.OrdinalIgnoreCase);
    }

    private static RouterHttpResponse Json(string body) => new() { StatusCode = 200, Body = body };
    private static RouterHttpResponse Xml(string body) => new() { StatusCode = 200, Body = body };

    private sealed class ScriptedTransport : IRouterTransport
    {
        private readonly Func<RouterHttpRequest, RouterHttpResponse> _handle;
        public List<RouterHttpRequest> Calls { get; } = new();
        public ScriptedTransport(Func<RouterHttpRequest, RouterHttpResponse> handle) => _handle = handle;
        public bool UsedUntrustedCertificate => false;
        public Task<RouterHttpResponse> SendAsync(RouterHttpRequest request, CancellationToken cancellationToken)
        {
            Calls.Add(request);
            return Task.FromResult(_handle(request));
        }
        public void Dispose() { }
    }
}
