using System.Web;
using RedFilter.Core.Router;
using RedFilter.Core.Router.TpLink;

namespace RedFilter.Core.Tests;

// The HTML below was captured from a TD-W8961N v5 (firmware "Mar 7 2024").
public sealed class TdW8961Tests
{
    private const string Stations = """
        <table>
        <tr class="data_common_sth">
             <th>MAC Address</th>
             <th>Tx Packet</th>
             <th>Rx Packet</th>
             <th>Tx Rate (Mbps)</th>
             <th>Power Saving</th>
             <th>Expired Time (s)</th>
        </tr>
        <tr>
        <tr bgcolor=#b7b7b7><td><font size=2>28:d0:43:8b:2b:a4</td><td><font size=2>156027</td><td><font size=2>124141</td><td><font size=2>27</td><td><font size=2>no</td><td><font size=2>300</td></tr><tr bgcolor=#b7b7b7><td><font size=2>f4:1a:9c:39:3a:00</td><td><font size=2>162835</td><td><font size=2>91184</td><td><font size=2>65</td><td><font size=2>no</td><td><font size=2>300</td></tr><tr bgcolor=#b7b7b7><td><font size=2>5e:6a:d2:37:a3:c1</td><td><font size=2>40786</td><td><font size=2>29037</td><td><font size=2>216</td><td><font size=2>no</td><td><font size=2>300</td></tr><tr bgcolor=#b7b7b7><td><font size=2>32:cc:b6:25:48:bc</td><td><font size=2>8451</td><td><font size=2>6185</td><td><font size=2>43.3</td><td><font size=2>no</td><td><font size=2>300</td></tr>
        </tr>
        </table>
        """;

    private const string Dhcp = """
        <table>
        <tr>
             <th>Name</th>
             <th>IP Address</th>
             <th>MAC Address</th>
             <th>Expiry(s)</th>
             <th>Type</th>
        </tr>
        <TR>
        <TD bgcolor="#b7b7b7">Galaxy-A07</TD>
        <TD bgcolor="#b7b7b7">192.168.1.105</TD>
        <TD bgcolor="#b7b7b7">32:cc:b6:25:48:bc</TD>
        <TD bgcolor="#b7b7b7">In 0 days 23:56:16</TD>
        <TD bgcolor="#b7b7b7">Automatic</TD>
        </TR>
        <TR>
        <TD bgcolor="#b7b7b7">Redmi-10A</TD>
        <TD bgcolor="#b7b7b7">192.168.1.111</TD>
        <TD bgcolor="#b7b7b7">f4:1a:9c:39:3a:00</TD>
        <TD bgcolor="#b7b7b7">In 0 days 23:44:40</TD>
        <TD bgcolor="#b7b7b7">Automatic</TD>
        </TR>
        <TR>
        <TD bgcolor="#b7b7b7">Redmi-Note-14</TD>
        <TD bgcolor="#b7b7b7">192.168.1.104</TD>
        <TD bgcolor="#b7b7b7">d8:93:d4:82:55:02</TD>
        <TD bgcolor="#b7b7b7">In 0 days 23:44:06</TD>
        <TD bgcolor="#b7b7b7">Automatic</TD>
        </TR>
        <TR>
        <TD bgcolor="#b7b7b7">Shakyamuni</TD>
        <TD bgcolor="#b7b7b7">192.168.1.109</TD>
        <TD bgcolor="#b7b7b7">28:d0:43:8b:2b:a4</TD>
        <TD bgcolor="#b7b7b7">In 0 days 23:43:20</TD>
        <TD bgcolor="#b7b7b7">Automatic</TD>
        </TR>
        <TR>
        <TD bgcolor="#b7b7b7">RE1500X</TD>
        <TD bgcolor="#b7b7b7">192.168.1.101</TD>
        <TD bgcolor="#b7b7b7">5e:6a:d2:37:a3:c1</TD>
        <TD bgcolor="#b7b7b7">In 0 days 23:49:32</TD>
        <TD bgcolor="#b7b7b7">Automatic</TD>
        </TR>
        </table>
        """;

    [Fact]
    public void ParsesTheActiveWirelessClientTable()
    {
        var stations = TdW8961Pages.ParseStations(Stations);

        Assert.Equal(4, stations.Count);
        var first = stations.Single(station => station.Mac == "28:D0:43:8B:2B:A4");
        Assert.Equal(156027, first.TxPackets);
        Assert.Equal(124141, first.RxPackets);
        Assert.Equal(27, first.TxRateMbps);
        Assert.False(first.PowerSaving);
        Assert.Equal(43.3, stations.Single(station => station.Mac == "32:CC:B6:25:48:BC").TxRateMbps);
    }

    [Fact]
    public void ParsesTheDhcpTable()
    {
        var leases = TdW8961Pages.ParseDhcp(Dhcp);

        Assert.Equal(5, leases.Count);
        Assert.Contains(leases, lease => lease is { Name: "RE1500X", Ip: "192.168.1.101", Mac: "5E:6A:D2:37:A3:C1" });
    }

    [Fact]
    public void ParsesTheAccessListAndItsMode()
    {
        var state = TdW8961Pages.ParseAccessControl(AccessPage(AccessControlMode.Disabled, "28d0438b2ba4", "2c0b97ebc1c4"));

        Assert.Equal(AccessControlMode.Disabled, state.Mode);
        Assert.Equal(new[] { "28:D0:43:8B:2B:A4", "2C:0B:97:EB:C1:C4" }, state.Macs);
        Assert.Empty(state.Blocked);
        Assert.True(state.Contains("28-d0-43-8b-2b-a4"));
    }

    [Fact]
    public void AnUnreadableModeIsAnErrorNotAGuess()
    {
        Assert.Throws<RouterException>(() => TdW8961Pages.ParseAccessControl("<html>nothing</html>"));
    }

    [Fact]
    public void RecognizesTheLoginPage()
    {
        Assert.True(TdW8961Pages.IsLoginPage("<title>Router</title><script>function hex_md5(s){}</script> Router Login User Name: Password:"));
        Assert.False(TdW8961Pages.IsLoginPage(Stations));
    }

    [Fact]
    public void LoginSendsOnlyMd5DigestsLikeTheRouterPage()
    {
        var body = TdW8961Login.Body("admin", "admin");
        Assert.Equal("usernameEncrypt=21232f297a57a5a743894a0e4a801fc3&passwordEncrypt=21232f297a57a5a743894a0e4a801fc3&submit.htm%3Flogin.htm=Send", body);
        Assert.DoesNotContain("password=", body, StringComparison.Ordinal);
    }

    [Fact]
    public void AnExpiredSessionRedirectCountsAsTheLoginPage()
    {
        Assert.True(TdW8961Pages.IsLoginPage("<script language='javascript'>parent.location=\"/login.htm\"</script></head><body></body></html>"));
    }

    [Fact]
    public void FormBodiesMatchTheRouterForms()
    {
        Assert.Equal(
            "wlanAcEnabled=0&checkWPS2=1&mac=F41A9C393A00&addFilterMac=Add&submit.htm%3Fwlactrl.htm=Send",
            TdW8961Pages.AddToAccessListBody("f4:1a:9c:39:3a:00", AccessControlMode.Disabled));
        Assert.Equal(
            "wlanAcEnabled=2&checkWPS2=1&setFilterMode=Apply%20Changes&mac=&submit.htm%3Fwlactrl.htm=Send",
            TdW8961Pages.SetAccessModeBody(AccessControlMode.DenyListed));
        Assert.Equal(
            "select=f41a9c393a00&totalNum=3&deleteSelFilterMac=Delete%20Selected&submit.htm%3Fwlactrl.htm=Send",
            TdW8961Pages.RemoveFromAccessListBody("F4:1A:9C:39:3A:00", 3));
        Assert.Throws<RouterException>(() => TdW8961Pages.AddToAccessListBody("FF:FF:FF:FF:FF:FF", AccessControlMode.Disabled));
    }

    [Fact]
    public void UsageRanksByPacketsPerSecondNotByTotals()
    {
        var tracker = new WifiUsageTracker();
        var start = new DateTime(2026, 11, 1, 12, 0, 0, DateTimeKind.Utc);
        tracker.Update(new[] { Station("AA:00:00:00:00:01", 1_000_000), Station("AA:00:00:00:00:02", 10) }, start);
        var rates = tracker.Update(new[] { Station("AA:00:00:00:00:01", 1_000_010), Station("AA:00:00:00:00:02", 5_010) }, start.AddSeconds(5));

        Assert.True(rates["AA:00:00:00:00:02"] > rates["AA:00:00:00:00:01"]);

        // A device that reconnects restarts its counters; that is not a negative rate.
        var after = tracker.Update(new[] { Station("AA:00:00:00:00:01", 3), Station("AA:00:00:00:00:02", 5_010) }, start.AddSeconds(10));
        Assert.True(after["AA:00:00:00:00:01"] >= 0);
    }

    [Fact]
    public async Task ReadJoinsNamesAndKeepsListedDevicesThatAreOffline()
    {
        var router = new FakeRouter(AccessControlMode.Disabled, "28:D0:43:8B:2B:A4", "2C:0B:97:EB:C1:C4");
        var client = new TdW8961Client(router, RouterEndpoint.Parse("http://192.168.1.1"));

        var snapshot = await client.ReadAsync(CancellationToken.None);

        Assert.Equal(5, snapshot.Devices.Count);
        Assert.Contains(snapshot.Devices, device => device is { Name: "Redmi-10A", Ip: "192.168.1.111", Connected: true, Blocked: false });
        var offline = Assert.Single(snapshot.Devices, device => !device.Connected);
        Assert.Equal("2C:0B:97:EB:C1:C4", offline.Mac);
        Assert.True(offline.OnAccessList);
        Assert.False(offline.Blocked);
    }

    [Fact]
    public async Task BlockAddsThenSwitchesToDenyAndUnblockSwitchesOffWhenEmpty()
    {
        var router = new FakeRouter(AccessControlMode.Disabled);
        var client = new TdW8961Client(router, RouterEndpoint.Parse("http://192.168.1.1"));

        var blocked = await client.BlockAsync("f4:1a:9c:39:3a:00", CancellationToken.None);
        Assert.Equal(AccessControlMode.DenyListed, blocked.Mode);
        Assert.Equal(new[] { "F4:1A:9C:39:3A:00" }, blocked.Macs);
        Assert.Equal(2, router.Posts.Count);
        Assert.Contains("addFilterMac", router.Posts[0], StringComparison.Ordinal);
        Assert.Contains("setFilterMode", router.Posts[1], StringComparison.Ordinal);

        var cleared = await client.RemoveFromListAsync("F4:1A:9C:39:3A:00", CancellationToken.None);
        Assert.Empty(cleared.Macs);
        Assert.Equal(AccessControlMode.Disabled, cleared.Mode);
    }

    [Fact]
    public async Task AllowListModeIsNeverChanged()
    {
        var router = new FakeRouter(AccessControlMode.AllowListed, "28:D0:43:8B:2B:A4");
        var client = new TdW8961Client(router, RouterEndpoint.Parse("http://192.168.1.1"));

        await Assert.ThrowsAsync<RouterException>(() => client.BlockAsync("F4:1A:9C:39:3A:00", CancellationToken.None));
        Assert.Empty(router.Posts);
    }

    [Fact]
    public async Task TheLoginPageMeansTheSessionExpired()
    {
        var router = new FakeRouter(AccessControlMode.Disabled) { LoggedOut = true };
        var client = new TdW8961Client(router, RouterEndpoint.Parse("http://192.168.1.1"));

        var error = await Assert.ThrowsAsync<RouterException>(() => client.ReadAsync(CancellationToken.None));
        Assert.True(error.SessionExpired);
    }

    private static WifiStation Station(string mac, long packets) => new(mac, packets, 0, null, null);

    private static string AccessPage(AccessControlMode mode, params string[] compactMacs)
    {
        var rows = string.Concat(compactMacs.Select(mac =>
            $"""<tr><td align=center width="45%" bgcolor="#C0C0C0"><font size="2">{mac}</td><td align=center width="20%" bgcolor="#C0C0C0"><input type="radio" name="select" value="{mac}"></td></tr>"""));
        return $"""
            <select onclick="updateState()" name="wlanAcEnabled" size="1"><option value="0">Disable</option><option value="1">Allow Listed</option><option value="2">Deny Listed</option></select>
            <form action=form2WlAc.cgi method=POST name="formWlAcDel"><table>{rows}<INPUT TYPE="HIDDEN" NAME="totalNum" VALUE="{compactMacs.Length}"></table>
            <script>wlanDisabled=0;wlanMode=0;
            document.formWlAcAdd.wlanAcEnabled.selectedIndex={(int)mode};
            updateState();</script>
            """;
    }

    /// <summary>A tiny stand-in for the router: it serves the three pages and applies the access-list form posts.</summary>
    private sealed class FakeRouter : IRouterTransport
    {
        private readonly List<string> _list;
        private AccessControlMode _mode;

        public FakeRouter(AccessControlMode mode, params string[] macs)
        {
            _mode = mode;
            _list = macs.ToList();
        }

        public bool LoggedOut { get; init; }
        public List<string> Posts { get; } = new();
        public bool UsedUntrustedCertificate => false;

        public Task<RouterHttpResponse> SendAsync(RouterHttpRequest request, CancellationToken cancellationToken)
        {
            if (LoggedOut)
                return Ok("<title>Router</title> Router Login User Name: Password:");
            var page = request.Url.AbsolutePath.TrimStart('/');
            if (request.Method == HttpMethod.Post)
            {
                Posts.Add(request.Body ?? "");
                var form = HttpUtility.ParseQueryString(request.Body ?? "");
                if (form["addFilterMac"] != null && MacAddress.TryNormalize(form["mac"], out var add) && !_list.Contains(add))
                    _list.Add(add);
                if (form["setFilterMode"] != null)
                    _mode = (AccessControlMode)int.Parse(form["wlanAcEnabled"]!);
                if (form["deleteSelFilterMac"] != null && MacAddress.TryNormalize(form["select"], out var remove))
                    _list.Remove(remove);
                return Ok("<html>ok</html>");
            }

            return page switch
            {
                TdW8961Pages.StationsPage => Ok(Stations),
                TdW8961Pages.DhcpPage => Ok(Dhcp),
                TdW8961Pages.AccessControlPage => Ok(AccessPage(_mode, _list.Select(mac => mac.Replace(":", "").ToLowerInvariant()).ToArray())),
                _ => Task.FromResult(new RouterHttpResponse { StatusCode = 404, Body = "missing" })
            };
        }

        public void Dispose()
        {
        }

        private static Task<RouterHttpResponse> Ok(string body) => Task.FromResult(new RouterHttpResponse { StatusCode = 200, Body = body });
    }
}
