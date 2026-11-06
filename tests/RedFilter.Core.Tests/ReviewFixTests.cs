using System.Text.Json;
using System.Text.RegularExpressions;
using RedFilter.Core.Processes;
using RedFilter.Core.Qos;
using RedFilter.Core.Router;
using RedFilter.Core.Settings;

namespace RedFilter.Core.Tests;

public sealed class QosPayloadTests
{
    [Theory]
    [InlineData(@"C:\Program Files\O'Brien\game.exe")]
    [InlineData("C:\\Users\\x\\a\u2019; Write-Host PWNED; \u2019\\app.exe")]
    [InlineData("C:\\Users\\x\\a\u2018$(Start-Process calc)\u201B\\app.exe")]
    [InlineData("C:\\Users\\x\\a\u201A`whoami`\"\\app.exe")]
    [InlineData(@"C:\Juegos\Fútbol\juego.exe")]
    public void PathsTravelAsAsciiJsonDataAndRoundTrip(string path)
    {
        var payload = NetQosScript.ApplyPayload(
            new[] { "RedFilter-Limit-ABCDEF123456" },
            new[]
            {
                new QosPolicySpec(QosPolicyPlanner.OwnerPolicyName, path, true, 46, null),
                new QosPolicySpec(QosPolicyPlanner.LimitName(path), path, false, 8, 1_000_000)
            });

        // PowerShell treats U+2018..U+201B as quote characters. None of them, nor any other
        // non-ASCII character, may reach the elevated process unescaped.
        Assert.All(payload, ch => Assert.True(ch < 128, $"Non-ASCII character U+{(int)ch:X4} in the payload."));
        Assert.DoesNotContain(path, NetQosScript.Script, StringComparison.Ordinal);

        using var document = JsonDocument.Parse(payload);
        var root = document.RootElement;
        Assert.Equal("apply", root.GetProperty("op").GetString());
        Assert.Equal("RedFilter-Limit-ABCDEF123456", root.GetProperty("remove")[0].GetString());
        var add = root.GetProperty("add");
        Assert.Equal(path, add[0].GetProperty("path").GetString());
        Assert.True(add[0].GetProperty("owner").GetBoolean());
        Assert.Equal(46, add[0].GetProperty("dscp").GetInt32());
        Assert.Equal(JsonValueKind.Null, add[0].GetProperty("rate").ValueKind);
        Assert.Equal(1_000_000, add[1].GetProperty("rate").GetInt64());
    }

    [Fact]
    public void PayloadRejectsUnsafeNamesControlCharactersAndZeroRates()
    {
        Assert.Throws<InvalidOperationException>(() =>
            NetQosScript.ApplyPayload(new[] { "RedFilter-*" }, Array.Empty<QosPolicySpec>()));
        Assert.Throws<InvalidOperationException>(() =>
            NetQosScript.ApplyPayload(Array.Empty<string>(), new[] { new QosPolicySpec("RedFilter-Owner", "C:\\a\nb.exe", true, 46, null) }));
        Assert.Throws<InvalidOperationException>(() =>
            NetQosScript.ApplyPayload(Array.Empty<string>(), new[] { new QosPolicySpec("RedFilter-Limit-ABC", @"C:\a.exe", false, 8, 1_000) }));
        Assert.Throws<InvalidOperationException>(() =>
            NetQosScript.ApplyPayload(Array.Empty<string>(), new[] { new QosPolicySpec("Other-Policy", @"C:\a.exe", true, 46, null) }));
    }

    [Fact]
    public void QueryAndClearAreFixedRequests()
    {
        Assert.Equal("""{"op":"query"}""", NetQosScript.QueryPayload());
        Assert.Equal("""{"op":"clear"}""", NetQosScript.ClearPayload());
    }

    [Fact]
    public void ParserDropsADscpValueOutsideInt32()
    {
        var policy = Assert.Single(NetQosPolicyParser.Parse(
            """[{"Name":"RedFilter-Owner","AppPathNameMatchCondition":"C:\\a.exe","DSCPAction":9999999999}]"""));
        Assert.Null(policy.Dscp);
    }
}

public sealed class QosPlannerActivityTests
{
    [Fact]
    public void OnlyActiveProgramsAreLimitedAndEarlierLimitsStay()
    {
        var owner = Row(10, "game", @"C:\Games\game.exe", 2);
        var processes = new[]
        {
            owner,
            Row(20, "chrome", @"C:\Apps\chrome.exe", 3),
            Row(30, "notepad", @"C:\Windows\notepad.exe", 0),
            Row(40, "sync", @"C:\Apps\sync.exe", 0)
        };
        var keep = new[] { @"C:\Apps\sync.exe", @"C:\Apps\exited.exe", @"C:\Windows\System32\svchost.exe" };

        var plan = QosPolicyPlanner.Build(owner, processes, 1_000_000, null, keep, requireActivity: true);
        var limited = plan.Policies.Where(policy => !policy.IsOwner).Select(policy => policy.AppPath).ToList();

        Assert.Contains(@"C:\Apps\chrome.exe", limited);
        Assert.Contains(@"C:\Apps\sync.exe", limited);
        Assert.Contains(@"C:\Apps\exited.exe", limited);
        Assert.DoesNotContain(@"C:\Windows\notepad.exe", limited);
        Assert.DoesNotContain(@"C:\Windows\System32\svchost.exe", limited);
        Assert.Contains(plan.Notes, note => note.Contains("DSCP", StringComparison.Ordinal));

        var reordered = QosPolicyPlanner.Build(owner, processes.Reverse().ToArray(), 1_000_000, null, keep, requireActivity: true);
        Assert.Equal(QosPolicyPlanner.Fingerprint(plan.Policies), QosPolicyPlanner.Fingerprint(reordered.Policies));
    }

    [Fact]
    public void WithoutConnectionCountsEveryProgramWithAPathIsLimited()
    {
        var owner = Row(10, "game", @"C:\Games\game.exe", 0);
        var plan = QosPolicyPlanner.Build(owner, new[] { owner, Row(30, "notepad", @"C:\Windows\notepad.exe", 0) }, 1_000_000, null);
        Assert.Contains(plan.Policies, policy => policy.AppPath == @"C:\Windows\notepad.exe");
    }

    [Fact]
    public void FingerprintChangesWithTheLimit()
    {
        var owner = Row(10, "game", @"C:\Games\game.exe", 1);
        var processes = new[] { owner, Row(20, "chrome", @"C:\Apps\chrome.exe", 3) };
        var slow = QosPolicyPlanner.Build(owner, processes, 256_000, null);
        var fast = QosPolicyPlanner.Build(owner, processes, 5_000_000, null);
        Assert.NotEqual(QosPolicyPlanner.Fingerprint(slow.Policies), QosPolicyPlanner.Fingerprint(fast.Policies));
    }

    [Fact]
    public void ServiceHostTrafficPointsToDeliveryOptimization()
    {
        var owner = Row(10, "game", @"C:\Games\game.exe", 2);
        var plan = QosPolicyPlanner.Build(owner, new[] { owner, Row(30, "svchost", @"C:\Windows\System32\svchost.exe", 8) }, 1_000_000, null);
        Assert.Contains(plan.Notes, note => note.Contains("Optimización de distribución", StringComparison.Ordinal));
    }

    private static ProcessNetworkRow Row(int pid, string name, string? path, int connections) =>
        new(pid, name, path, connections, 0, 0, 0);
}

public sealed class SettingsAtomicTests
{
    [Fact]
    public void SaveLeavesNoTempFilesAndACorruptFileLoadsDefaults()
    {
        var directory = Path.Combine(Path.GetTempPath(), "redfilter-tests-" + Guid.NewGuid().ToString("N"));
        var store = new SettingsStore(directory, new PlainProtector());
        store.Save(new AppSettings { RouterAddress = "http://192.168.1.1", RouterCertificateHost = "192.168.1.1", RouterCertificateSha256 = "AB" });
        Assert.Equal("AB", store.Load().RouterCertificateSha256);
        store.SavePassword("pw");
        store.Save(new AppSettings { RouterAddress = "http://192.168.1.2" });

        Assert.Empty(Directory.GetFiles(directory, "*.tmp"));
        Assert.Equal("http://192.168.1.2", store.Load().RouterAddress);
        Assert.Equal("pw", store.LoadPassword());

        File.WriteAllText(store.SettingsPath, "{ not json");
        Assert.Equal("auto", store.Load().Brand);
    }

    private sealed class PlainProtector : ISecretProtector
    {
        public byte[] Protect(byte[] plaintext) => plaintext;
        public byte[] Unprotect(byte[] ciphertext) => ciphertext;
    }
}

public sealed class RouterSessionTests
{
    [Fact]
    public async Task ExpiredOpenWrtSessionSignsInAgainOnce()
    {
        var logins = 0;
        var refreshing = false;
        var refused = 0;
        var transport = new Scripted(request =>
        {
            var body = request.Body ?? "";
            if (request.Method == HttpMethod.Get)
                return Ok("<html><title>OpenWrt - LuCI</title></html>");
            if (body.Contains("\"login\"", StringComparison.Ordinal))
            {
                logins++;
                return Ok($$"""{"jsonrpc":"2.0","id":1,"result":[0,{"ubus_rpc_session":"s{{logins}}"}]}""");
            }

            if (body.Contains("\"board\"", StringComparison.Ordinal))
                return Ok("""{"jsonrpc":"2.0","id":1,"result":[0,{"model":"AP"}]}""");
            if (body.Contains("\"list\"", StringComparison.Ordinal))
            {
                // After the first refresh starts, the old session is refused, as an expired session would be.
                if (refreshing && body.Contains("\"s1\"", StringComparison.Ordinal))
                {
                    refused++;
                    return Ok("""{"jsonrpc":"2.0","id":1,"error":{"code":-32002,"message":"Access denied"}}""");
                }

                return Ok("""{"jsonrpc":"2.0","id":1,"result":{"hostapd.wlan0":{}}}""");
            }

            if (body.Contains("get_clients", StringComparison.Ordinal))
                return Ok("""{"jsonrpc":"2.0","id":1,"result":[0,{"clients":{"AA:BB:CC:DD:EE:01":{}}}]}""");
            // A bare [0] used to become a default JsonElement and throw InvalidOperationException.
            if (body.Contains("list_bans", StringComparison.Ordinal))
                return Ok("""{"jsonrpc":"2.0","id":1,"result":[0]}""");
            return Ok("""{"jsonrpc":"2.0","id":1,"result":[0,{}]}""");
        });

        var workflow = new RouterWorkflow(_ => transport);
        var first = await workflow.TestAsync("http://192.168.1.1", "root", "secret", "auto", CancellationToken.None);
        Assert.True(first.Success, first.Status);
        Assert.Single(first.Clients);

        refreshing = true;
        var list = await workflow.RefreshAsync(CancellationToken.None);

        Assert.NotNull(list);
        Assert.Single(list!.Clients);
        Assert.Equal(1, refused);
        Assert.Equal(2, logins);
    }

    [Fact]
    public async Task WrongPasswordIsNotRetriedAsAnExpiredSession()
    {
        var logins = 0;
        var transport = new Scripted(request =>
        {
            if (request.Method == HttpMethod.Get)
                return Ok("<title>OpenWrt</title>");
            logins++;
            return Ok("""{"jsonrpc":"2.0","id":1,"result":[6]}""");
        });

        var workflow = new RouterWorkflow(_ => transport);
        var result = await workflow.TestAsync("http://192.168.1.1", "root", "wrong", "auto", CancellationToken.None);

        Assert.False(result.Success);
        Assert.Contains("rejected the username or password", result.Status, StringComparison.Ordinal);
        Assert.Equal(1, logins);
    }

    [Fact]
    public async Task FritzReusesTheDigestChallengeAndSkipsTheWebLogin()
    {
        var unauthenticated = 0;
        var transport = new Scripted(request =>
        {
            if (request.Url.AbsolutePath.Contains("login_sid.lua", StringComparison.Ordinal))
                return Ok("""<SessionInfo><SID>0000000000000000</SID><Challenge>2$10$5A1711$10$5A1722</Challenge><BlockTime>0</BlockTime></SessionInfo>""");
            if (request.Url.AbsolutePath.Contains("tr64desc.xml", StringComparison.Ordinal))
                return Ok("""<root><device><serviceList><service><serviceType>urn:dslforum-org:service:Hosts:1</serviceType><serviceId>h</serviceId><controlURL>/upnp/control/hosts</controlURL></service></serviceList></device></root>""");
            if (request.Headers == null || !request.Headers.ContainsKey("Authorization"))
            {
                unauthenticated++;
                return new RouterHttpResponse { StatusCode = 401, Authenticate = new[] { "Digest realm=\"r\", nonce=\"n\", qop=\"auth\"" } };
            }

            var body = request.Body ?? "";
            if (body.Contains("GetHostNumberOfEntries", StringComparison.Ordinal))
                return Ok("""<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><NewHostNumberOfEntries>3</NewHostNumberOfEntries></s:Body></s:Envelope>""");
            if (body.Contains("GetGenericHostEntry", StringComparison.Ordinal))
                return Ok("""<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><NewMACAddress>AA:BB:CC:DD:EE:02</NewMACAddress><NewActive>1</NewActive></s:Body></s:Envelope>""");
            return Ok("""<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body></s:Body></s:Envelope>""");
        });

        var session = await FritzBoxClient.LoginAsync(transport, RouterEndpoint.Parse("http://192.168.178.1"), "admin", "pw", CancellationToken.None);
        var clients = await session.GetClientsAsync(CancellationToken.None);

        Assert.Equal(3, clients.Clients.Count);
        Assert.Equal(1, unauthenticated);
        Assert.DoesNotContain(transport.Calls, call =>
            call.Method == HttpMethod.Post && call.Url.AbsolutePath.Contains("login_sid.lua", StringComparison.Ordinal));
        var counts = transport.Calls
            .Where(call => call.Headers?.ContainsKey("Authorization") == true)
            .Select(call => Regex.Match(call.Headers!["Authorization"], "nc=([0-9a-f]{8})").Groups[1].Value)
            .ToList();
        Assert.True(counts.Count > 3);
        Assert.Equal(counts.Count, counts.Distinct().Count());
    }

    [Fact]
    public async Task FritzWrongPasswordIsReportedClearly()
    {
        var transport = new Scripted(request =>
        {
            if (request.Url.AbsolutePath.Contains("login_sid.lua", StringComparison.Ordinal))
                return Ok("""<SessionInfo><SID>0000000000000000</SID><Challenge>abc</Challenge><BlockTime>0</BlockTime></SessionInfo>""");
            if (request.Url.AbsolutePath.Contains("tr64desc.xml", StringComparison.Ordinal))
                return Ok("""<root><serviceList><service><serviceType>urn:dslforum-org:service:Hosts:1</serviceType><controlURL>/h</controlURL></service></serviceList></root>""");
            return new RouterHttpResponse { StatusCode = 401, Authenticate = new[] { "Digest realm=\"r\", nonce=\"n\"" } };
        });

        var error = await Assert.ThrowsAsync<RouterException>(() =>
            FritzBoxClient.LoginAsync(transport, RouterEndpoint.Parse("http://192.168.178.1"), "admin", "wrong", CancellationToken.None));
        Assert.Contains("rejected the username or password", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AsusSurvivesBadNvramJsonAndReportsAnExpiredToken()
    {
        var expired = false;
        var transport = new Scripted(request =>
        {
            if (request.Url.AbsolutePath.Contains("login.cgi", StringComparison.Ordinal))
                return Ok("""{"asus_token":"t"}""");
            var body = request.Body ?? "";
            if (body.Contains("nvram_get", StringComparison.Ordinal))
                return Ok("{ broken json");
            return expired
                ? Ok("<script>top.location.href='/Main_Login.asp';</script>")
                : Ok("""{"get_clientlist":{}}""");
        });

        var session = await AsusWrtClient.LoginAsync(transport, RouterEndpoint.Parse("http://192.168.50.1"), "admin", "pw", CancellationToken.None);
        Assert.Null(session.Model);

        expired = true;
        var error = await Assert.ThrowsAsync<RouterException>(() => session.GetClientsAsync(CancellationToken.None));
        Assert.True(error.SessionExpired);
    }

    private static RouterHttpResponse Ok(string body) => new() { StatusCode = 200, Body = body };

    private sealed class Scripted : IRouterTransport
    {
        private readonly Func<RouterHttpRequest, RouterHttpResponse> _handle;
        public Scripted(Func<RouterHttpRequest, RouterHttpResponse> handle) => _handle = handle;
        public List<RouterHttpRequest> Calls { get; } = new();
        public bool UsedUntrustedCertificate => false;

        public Task<RouterHttpResponse> SendAsync(RouterHttpRequest request, CancellationToken cancellationToken)
        {
            Calls.Add(request);
            return Task.FromResult(_handle(request));
        }

        public void Dispose()
        {
        }
    }
}
