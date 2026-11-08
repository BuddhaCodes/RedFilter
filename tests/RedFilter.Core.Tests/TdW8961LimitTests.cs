using System.Web;
using RedFilter.Core.Router;
using RedFilter.Core.Router.TpLink;

namespace RedFilter.Core.Tests;

// Captured from a TD-W8961N v5 (firmware "Mar 7 2024") after adding one shaping rule for
// 192.168.1.250 (up 1000, down 4000) and the fixed IP 192.168.1.250 -> 02:00:00:00:00:01.
public sealed class TdW8961LimitTests
{
    private static string ShapingPage(int totalUp, int totalDown, string rows) => $"""
        <form action="form2IPQoSTc.cgi" method=POST name=qostc>
        <table><tbody>
        <tr>
              <th width="30%">Total Bandwidth(0, Unlimited):</th>
              <td>UP Stream
        <input type="text" name=total size="6" maxlength="6"
        	value="{totalUp}"
        >kbps
        </td>
        </tr>
        <tr>
        <th>&nbsp;</th>
                    <td>Down Stream
        <input type="text" name=downtotal size="6" maxlength="6"
        	value="{totalDown}"
        >kbps
        </td>
        </tr>
        </tbody></table>
        </form>
        <form action="form2IPQoSTc.cgi" method=POST name=qostcrule>
        <table>
        <tbody>
        <tr>
              <th rowspan="2">ID</th>
              <th rowspan="2">Wan Itf</th>
              <th rowspan="2">Protocol</th>
              <th rowspan="2">Src Port</th>
              <th rowspan="2">Dst Port</th>
              <th rowspan="2">Src IP</th>
              <th rowspan="2">Dst IP</th>
              <th colspan="2">Garanted Bandwidth(Kbps)</th>
              <th colspan="2">Max Bandwidth(Kbps)</th>
              <th rowspan="2">Remove</th>
        </tr>
        <tr>
              <th>Up Floor</th>
              <th>Down Floor</th>
              <th>Up Ceiling</th>
              <th>Down Ceiling</th>
        </tr>
        {rows}
        </tbody>
        </table>
        <select name='intf' size="1" colspan="3">
                 <option value=255>(Click to Select)</option>
        	<option value=2>WAN0 </option>
        </select>
        </form>
        """;

    private static string ShapingRow(int id, string srcIp, int upCeiling, int downCeiling, string protocol = " ", string dstIp = " ", int upFloor = -1, int downFloor = -1) => $"""
        <TR>
        <TD align=center bgcolor="#C0C0C0">{id + 1}</TD>
        <TD align=center bgcolor="#C0C0C0">WAN0</TD>
        <TD align=center bgcolor="#C0C0C0">{protocol}</TD>
        <TD align=center bgcolor="#C0C0C0"> </TD>
        <TD align=center bgcolor="#C0C0C0"> </TD>
        <TD align=center bgcolor="#C0C0C0">{srcIp}</TD>
        <TD align=center bgcolor="#C0C0C0">{dstIp}</TD>
        <TD align=center bgcolor="#C0C0C0">{upFloor}</TD>
        <TD align=center bgcolor="#C0C0C0">{downFloor}</TD>
        <TD align=center bgcolor="#C0C0C0">{upCeiling}</TD>
        <TD align=center bgcolor="#C0C0C0">{downCeiling}</TD>
        <TD align=center bgcolor="#C0C0C0"><input type="checkbox" name="removeQ" value="{id}"></TD>
        </TR>
        """;

    private static string StaticPage(params (string Ip, string Mac)[] leases)
    {
        var tables = string.Concat(leases.Select((lease, i) =>
            $"DhcpIpTables[{i}]=new dhcpIptable({lease.Ip.Replace('.', ',')},\"{lease.Mac}\");\n"));
        var rows = string.Concat(leases.Select((lease, i) => $"""
            <TR>
            <TD align=center bgcolor="#C0C0C0"><input type="radio" name="select" value="{i + 1}" onClick="postDhcpIp( '{lease.Ip}', '{lease.Mac}')"></TD>
            <TD align=center bgcolor="#C0C0C0">{lease.Ip}</TD>
            <TD align=center bgcolor="#C0C0C0">{lease.Mac}</TD>
            </TR>
            """));
        return $$"""
            <SCRIPT>
            function checkPoolIP(ipaddr,macaddr)
            {
            var DhcpIpTables=new Array();
            	lanip1=192;
            	lanip2=168;
            	lanip3=1;
            	lanip4=1;
            	startip=100;
            	endip=254;
            {{tables}};
            }
            </SCRIPT>
            <form action="form2Dhcpip.cgi" method=POST name="dhcpip">
            <input type="hidden" name="ltime" value=
            1440
            >
            <table>
            <tr>
                <th width="10%">Select</th>
                <th>IP Address</th>
                <th>MAC Address</th>
            </tr>
            {{rows}}
            </table>
            <input type="hidden" NAME="submit.htm?dhcpip.htm" value='Send'>
            </form>
            """;
    }

    private const string Status = """
        <tr><th>Operational Status</th><td>G992.5 AnnexM</td></tr>
        <tr><th>Upstream Speed</th><td>1148&nbsp;kbps</td></tr>
        <tr><th>Downstream Speed</th><td>4607&nbsp;kbps</td></tr>
        """;

    [Fact]
    public void ParsesTheShapingPageAsTheRouterShowsIt()
    {
        var state = TdW8961LimitPages.ParseShaping(ShapingPage(0, 0, ShapingRow(0, "192.168.1.250/32", 1000, 4000)));

        Assert.Equal(0, state.TotalUpKbps);
        Assert.Equal(0, state.TotalDownKbps);
        var rule = Assert.Single(state.Rules);
        Assert.Equal(0, rule.RemoveIndex);
        Assert.Equal("192.168.1.250", rule.SourceIp);
        Assert.True(rule.OnlyMatchesSourceIp);
        Assert.Null(rule.UpFloorKbps);
        Assert.Equal(1000, rule.UpCeilingKbps);
        Assert.Equal(4000, rule.DownCeilingKbps);
        Assert.Single(state.LimitsFor("192.168.1.250"));
        Assert.Empty(state.LimitsFor("192.168.1.25"));
    }

    [Fact]
    public void RulesThatMatchMoreThanTheSourceIpAreNotTreatedAsLimits()
    {
        var state = TdW8961LimitPages.ParseShaping(ShapingPage(1000, 4000,
            ShapingRow(0, "192.168.1.105/32", 100, 200, protocol: "TCP") + ShapingRow(1, "192.168.1.0/24", 100, 200)));

        Assert.Equal(2, state.Rules.Count);
        Assert.Empty(state.LimitsFor("192.168.1.105"));
        Assert.Null(state.Rules[1].SourceIp);
    }

    [Fact]
    public void ParsesTheEmptyShapingPageAndRefusesAPageWithoutTotals()
    {
        Assert.Empty(TdW8961LimitPages.ParseShaping(ShapingPage(0, 0, "")).Rules);
        Assert.Throws<RouterException>(() => TdW8961LimitPages.ParseShaping("<html>nothing</html>"));
    }

    [Fact]
    public void ParsesStaticLeasesAndThePool()
    {
        var state = TdW8961LimitPages.ParseStaticLeases(StaticPage(("192.168.1.250", "02:00:00:00:00:01")));

        Assert.Equal("1440", state.LeaseTime);
        Assert.True(state.InPool("192.168.1.105"));
        Assert.False(state.InPool("192.168.1.50"));
        Assert.False(state.InPool("10.0.0.105"));
        var lease = Assert.Single(state.Leases);
        Assert.Equal(new StaticLease(1, "192.168.1.250", "02:00:00:00:00:01"), lease);
        Assert.Empty(TdW8961LimitPages.ParseStaticLeases(StaticPage()).Leases);
    }

    [Fact]
    public void ReadsTheLineSpeedFromTheStatusPage()
    {
        Assert.Equal(new LineSpeed(1148, 4607), TdW8961LimitPages.ParseLineSpeed(Status));
        Assert.Null(TdW8961LimitPages.ParseLineSpeed("<td>Upstream Speed</td><td>0 kbps</td>"));
    }

    [Fact]
    public void FormBodiesMatchWhatTheRouterAccepted()
    {
        Assert.Equal(
            "removeRuleList=&intf=2&proto=0&srcip=192.168.1.250&srcnetmask=255.255.255.255&dstip=&dstnetmask=&uprateFloor=&uprateCeiling=1000&downrateFloor=&downrateCeiling=4000&addRule=Apply&submit.htm%3Fipqostc.htm=Send",
            TdW8961LimitPages.AddLimitBody("192.168.1.250", 1000, 4000));
        Assert.StartsWith("removeRuleList=0&save=Save%2FApply&intf=255&", TdW8961LimitPages.RemoveRuleBody(0));
        Assert.Equal("total=1033&downtotal=4146&applyItflimit=Apply&submit.htm%3Fipqostc.htm=Send", TdW8961LimitPages.SetTotalsBody(1033, 4146));
        Assert.Equal(
            "ltime=1440&ipaddr=192.168.1.250&macaddr=020000000001&submit.htm%3Fdhcpip.htm=Send",
            TdW8961LimitPages.AddStaticLeaseBody("192.168.1.250", "02:00:00:00:00:01", "1440"));
        Assert.Equal(
            "ltime=1440&ipaddr=192.168.1.250&macaddr=020000000001&delete=Delete%20Selected&select=1&submit.htm%3Fdhcpip.htm=Send",
            TdW8961LimitPages.RemoveStaticLeaseBody(new StaticLease(1, "192.168.1.250", "02:00:00:00:00:01"), "1440"));
        Assert.Throws<RouterException>(() => TdW8961LimitPages.AddLimitBody("192.168.1.250/24", 1, 1));
        Assert.Throws<RouterException>(() => TdW8961LimitPages.AddLimitBody("192.168.1.250", -1, 1));
    }

    [Fact]
    public async Task LimitFixesTheIpSetsTheLineTotalsAndReadsTheRuleBack()
    {
        var router = new FakeLimitRouter();
        var client = new TdW8961Client(router, RouterEndpoint.Parse("http://192.168.1.1"));

        var rule = await client.LimitAsync("f4:1a:9c:39:3a:00", "192.168.1.111", 256, 1024, CancellationToken.None);

        Assert.Equal(256, rule.UpCeilingKbps);
        Assert.Equal(1024, rule.DownCeilingKbps);
        Assert.Contains(("192.168.1.111", "F4:1A:9C:39:3A:00"), router.Static);
        Assert.Equal((918, 3915), router.Totals); // 80% up / 85% down of the 1148/4607 kbps sync speed
        Assert.Equal(3, router.Posts.Count);
        Assert.Contains("form2Dhcpip.cgi", router.Posts[0], StringComparison.Ordinal);
        Assert.Contains("applyItflimit", router.Posts[1], StringComparison.Ordinal);
        Assert.Contains("addRule", router.Posts[2], StringComparison.Ordinal);

        var snapshot = await client.ReadAsync(CancellationToken.None);
        var device = snapshot.Devices.Single(d => d.Mac == "F4:1A:9C:39:3A:00");
        Assert.True(device.Limited);
        Assert.Equal(1024, device.LimitDownKbps);
        Assert.False(snapshot.Devices.Single(d => d.Mac == "28:D0:43:8B:2B:A4").Limited);
    }

    [Fact]
    public async Task LimitingAgainReplacesTheOldRuleAndKeepsTheFixedIp()
    {
        var router = new FakeLimitRouter();
        var client = new TdW8961Client(router, RouterEndpoint.Parse("http://192.168.1.1"));
        await client.LimitAsync("F4:1A:9C:39:3A:00", "192.168.1.111", 256, 1024, CancellationToken.None);
        router.Posts.Clear();

        await client.LimitAsync("F4:1A:9C:39:3A:00", "192.168.1.111", 512, 2048, CancellationToken.None);

        var rule = Assert.Single(router.Rules);
        Assert.Equal((512, 2048), (rule.Up, rule.Down));
        Assert.Single(router.Static);
        Assert.Equal(2, router.Posts.Count); // remove + add; the fixed IP and totals were already there
    }

    [Fact]
    public async Task CeilingsAreKeptInsideTheLineTotals()
    {
        var router = new FakeLimitRouter();
        var client = new TdW8961Client(router, RouterEndpoint.Parse("http://192.168.1.1"));

        var rule = await client.LimitAsync("F4:1A:9C:39:3A:00", "192.168.1.111", 99_999, 99_999, CancellationToken.None);

        Assert.Equal(918, rule.UpCeilingKbps);
        Assert.Equal(3915, rule.DownCeilingKbps);
    }

    [Fact]
    public async Task RemovingTheLastLimitPutsTheLineBackToUnlimited()
    {
        var router = new FakeLimitRouter();
        var client = new TdW8961Client(router, RouterEndpoint.Parse("http://192.168.1.1"));
        await client.LimitAsync("F4:1A:9C:39:3A:00", "192.168.1.111", 256, 1024, CancellationToken.None);
        await client.LimitAsync("32:CC:B6:25:48:BC", "192.168.1.105", 256, 1024, CancellationToken.None);

        var first = await client.RemoveLimitAsync("192.168.1.111", CancellationToken.None);
        Assert.Single(first.Rules);
        Assert.Equal((918, 3915), router.Totals);

        var last = await client.RemoveLimitAsync("192.168.1.105", CancellationToken.None);
        Assert.Empty(last.Rules);
        Assert.Equal((0, 0), router.Totals);
        Assert.Equal(2, router.Static.Count); // fixed IPs stay
    }

    [Fact]
    public async Task AnIpKeptForAnotherDeviceIsRefusedBeforeAnyRuleIsAdded()
    {
        var router = new FakeLimitRouter();
        router.Static.Add(("192.168.1.111", "AA:BB:CC:00:00:01"));
        var client = new TdW8961Client(router, RouterEndpoint.Parse("http://192.168.1.1"));

        await Assert.ThrowsAsync<RouterException>(() => client.LimitAsync("F4:1A:9C:39:3A:00", "192.168.1.111", 256, 1024, CancellationToken.None));
        Assert.Empty(router.Posts);
    }

    [Fact]
    public async Task ADeviceWhoseFixedIpDiffersFromItsCurrentIpIsAskedToReconnect()
    {
        var router = new FakeLimitRouter();
        router.Static.Add(("192.168.1.200", "F4:1A:9C:39:3A:00"));
        var client = new TdW8961Client(router, RouterEndpoint.Parse("http://192.168.1.1"));

        var error = await Assert.ThrowsAsync<RouterException>(() => client.LimitAsync("F4:1A:9C:39:3A:00", "192.168.1.111", 256, 1024, CancellationToken.None));
        Assert.Contains("192.168.1.200", error.Message, StringComparison.Ordinal);
        Assert.Empty(router.Posts);
    }

    [Fact]
    public async Task ARouterThatIgnoresTheRuleIsReported()
    {
        var router = new FakeLimitRouter { IgnoreRules = true };
        var client = new TdW8961Client(router, RouterEndpoint.Parse("http://192.168.1.1"));

        await Assert.ThrowsAsync<RouterException>(() => client.LimitAsync("F4:1A:9C:39:3A:00", "192.168.1.111", 256, 1024, CancellationToken.None));
    }

    [Fact]
    public async Task TheUsageHistorySurvivesANewClient()
    {
        var usage = new WifiUsageTracker();
        var router = new FakeLimitRouter();
        var endpoint = RouterEndpoint.Parse("http://192.168.1.1");
        await new TdW8961Client(router, endpoint, usage).ReadAsync(CancellationToken.None);
        await Task.Delay(600);
        router.PacketBump = 5_000;

        // A second client (as after signing in again) with the same tracker still sees the change.
        var snapshot = await new TdW8961Client(router, endpoint, usage).ReadAsync(CancellationToken.None);
        Assert.True(snapshot.Devices.Single(d => d.Mac == "F4:1A:9C:39:3A:00").PacketsPerSecond > 0);
    }

    [Fact]
    public void GameModeSharesTheBudgetAndGuaranteesThePcTheRest()
    {
        var plan = GameModePlanner.Build(1033, 4146, "192.168.1.109",
            new[] { "192.168.1.111", "192.168.1.105", "192.168.1.109", "192.168.1.101", "192.168.1.104" }, Array.Empty<ShapingRule>(), GameModeProfile.Soft);

        Assert.Equal(4, plan.Others.Count); // the PC is never among the others
        Assert.All(plan.Others, rule => Assert.Equal(625, rule.DownCeilingKbps)); // 2500 / 4
        Assert.All(plan.Others, rule => Assert.Equal(96, rule.UpCeilingKbps));    // 384 / 4
        Assert.Equal(2500, plan.OthersDownKbps);
        // The PC keeps what the others cannot take, and never less than half the line.
        Assert.Equal(new GameModeRule("192.168.1.109", 1033 - 384, 1033, 4146 / 2, 4146), plan.Pc);
        Assert.Equal("192.168.1.101", plan.Others[0].Ip);
    }

    [Fact]
    public void AggressiveAndExtremeSqueezeAFourMegabitLineHard()
    {
        var (up, down) = GameModePlanner.ShapingTotals(new LineSpeed(1148, 4607));
        Assert.Equal((918, 3915), (up, down)); // 80% up, 85% down of the sync speed

        var others = new[] { "192.168.1.101", "192.168.1.103", "192.168.1.104", "192.168.1.105", "192.168.1.106", "192.168.1.107" };
        var aggressive = GameModePlanner.Build(up, down, "192.168.1.109", others, Array.Empty<SavedLimit>());
        Assert.Equal(GameModeProfile.Aggressive, GameModeProfile.For(GameModeLevel.Aggressive));
        // Aggressive: 25% / 15% of the line shared by six devices -> 163 kbps down, 22 kbps up each.
        Assert.All(aggressive.Others, rule => Assert.Equal((22, 163), (rule.UpCeilingKbps, rule.DownCeilingKbps)));
        Assert.True(aggressive.OthersDownKbps <= 978 && aggressive.OthersUpKbps <= 137); // 25% / 15% of the line
        Assert.True(aggressive.Pc.DownFloorKbps >= down * 3 / 4);

        var extreme = GameModePlanner.Build(up, down, "192.168.1.109", others, Array.Empty<SavedLimit>(), GameModeProfile.Extreme);
        Assert.All(extreme.Others, rule => Assert.Equal((9, 64), (rule.UpCeilingKbps, rule.DownCeilingKbps)));
        Assert.True(extreme.Pc.UpFloorKbps >= up * 9 / 10);
        Assert.Equal(64_000, GameModeProfile.Extreme.PcOtherProgramsUploadBits);
    }

    [Fact]
    public void GameModeNeverStarvesADeviceAndKeepsALowerUserLimit()
    {
        var many = Enumerable.Range(100, 40).Select(i => $"192.168.1.{i}").ToList();
        var profile = GameModeProfile.Aggressive;
        var crowded = GameModePlanner.Build(1033, 4146, "192.168.1.109", many, Array.Empty<ShapingRule>());
        Assert.All(crowded.Others, rule => Assert.True(rule.DownCeilingKbps >= profile.MinDeviceDownKbps && rule.UpCeilingKbps >= profile.MinDeviceUpKbps));
        Assert.True(crowded.Pc.DownFloorKbps >= 4146 / 2); // the minimums add up past the budget, but the PC keeps half

        var user = new ShapingRule(0, "192.168.1.111", true, null, null, 16, 64);
        var plan = GameModePlanner.Build(1033, 4146, "192.168.1.109", new[] { "192.168.1.111" }, new[] { user });
        Assert.Equal((16, 64), (plan.Others[0].UpCeilingKbps, plan.Others[0].DownCeilingKbps));
        Assert.Throws<RouterException>(() => GameModePlanner.Build(0, 0, "192.168.1.109", many, Array.Empty<ShapingRule>()));
    }

    [Fact]
    public void FloorsGoInTheRuleForm()
    {
        Assert.Contains("uprateFloor=672&uprateCeiling=1033&downrateFloor=1866&downrateCeiling=4146",
            TdW8961LimitPages.AddRuleBody("192.168.1.109", 672, 1033, 1866, 4146), StringComparison.Ordinal);
        Assert.Throws<RouterException>(() => TdW8961LimitPages.AddRuleBody("192.168.1.109", 2000, 1033, null, 4146));
    }

    [Fact]
    public async Task GameModeAppliesOnlyWhatChangedAndRestoresEverything()
    {
        var router = new FakeLimitRouter();
        var client = new TdW8961Client(router, RouterEndpoint.Parse("http://192.168.1.1"));
        await client.LimitAsync("F4:1A:9C:39:3A:00", "192.168.1.111", 64, 256, CancellationToken.None);
        router.SetTotals(0, 0); // as if the user had cleared the totals by hand
        router.Posts.Clear();

        var shaping = await client.EnsureLineTotalsAsync(CancellationToken.None);
        var backup = new GameModeBackup { TotalUpKbps = 0, TotalDownKbps = 0, Limits = TdW8961Client.SaveLimits(shaping), PcIp = "192.168.1.109" };
        var plan = GameModePlanner.Build(shaping.TotalUpKbps, shaping.TotalDownKbps, "192.168.1.109", new[] { "192.168.1.111", "192.168.1.105" }, shaping.Rules);
        backup.TouchedIps.AddRange(plan.AllRules.Select(rule => rule.Ip));

        var on = await client.ApplyGameModeAsync(plan, CancellationToken.None);
        Assert.Equal(3, on.Rules.Count);
        Assert.Equal((64, 256), (on.LimitsFor("192.168.1.111")[0].UpCeilingKbps, on.LimitsFor("192.168.1.111")[0].DownCeilingKbps));
        var pc = Assert.Single(on.LimitsFor("192.168.1.109"));
        Assert.Equal(plan.Pc.DownFloorKbps, pc.DownFloorKbps);

        router.Posts.Clear();
        await client.ApplyGameModeAsync(plan, CancellationToken.None);
        Assert.Empty(router.Posts); // nothing changed, nothing posted

        var off = await client.RestoreGameModeAsync(backup, CancellationToken.None);
        var back = Assert.Single(off.Rules);
        Assert.Equal(("192.168.1.111", 64, 256), (back.SourceIp, back.UpCeilingKbps, back.DownCeilingKbps));
        Assert.Equal((0, 0), router.Totals);
    }

    [Fact]
    public async Task AFullRouterIsReportedInsteadOfHalfApplied()
    {
        var router = new FakeLimitRouter { MaxRules = 2 };
        var client = new TdW8961Client(router, RouterEndpoint.Parse("http://192.168.1.1"));
        var shaping = await client.EnsureLineTotalsAsync(CancellationToken.None);
        var plan = GameModePlanner.Build(shaping.TotalUpKbps, shaping.TotalDownKbps, "192.168.1.109",
            new[] { "192.168.1.111", "192.168.1.105", "192.168.1.104" }, shaping.Rules);

        var error = await Assert.ThrowsAsync<RouterException>(() => client.ApplyGameModeAsync(plan, CancellationToken.None));
        Assert.Contains("full", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void FindsDotaByNameOrPath()
    {
        var list = new[]
        {
            new RedFilter.Core.Processes.ProcessNetworkRow(1, "steam", @"C:\Steam\steam.exe", 3, 0, 0, 0),
            new RedFilter.Core.Processes.ProcessNetworkRow(2, "dota2", @"C:\Steam\steamapps\common\dota 2 beta\game\bin\win64\dota2.exe", 2, 4, 0, 0)
        };
        Assert.Equal(2, RedFilter.Core.Processes.GameDetector.FindDota(list)!.Pid);
        Assert.Null(RedFilter.Core.Processes.GameDetector.FindDota(list.Take(1)));
        Assert.True(RedFilter.Core.Processes.GameDetector.IsDota(new(3, "DOTA2.EXE", null, 0, 0, 0, 0)));
    }

    /// <summary>Serves the pages the limit flow reads and applies its form posts, like the real router does.</summary>
    private sealed class FakeLimitRouter : IRouterTransport
    {
        public List<string> Posts { get; } = new();
        public List<(string Ip, string Mac)> Static { get; } = new();
        public List<(string Ip, int Up, int Down)> Rules => Full.Select(rule => (rule.Ip, rule.Up, rule.Down)).ToList();
        public List<(string Ip, int Up, int Down, int UpFloor, int DownFloor)> Full { get; } = new();
        public (int Up, int Down) Totals { get; private set; }
        public bool IgnoreRules { get; init; }
        public int MaxRules { get; init; } = 32;
        public string Leases { get; set; } = "<tr><td>Redmi-10A</td><td>192.168.1.111</td><td>f4:1a:9c:39:3a:00</td></tr>" +
                                             "<tr><td>Shakyamuni</td><td>192.168.1.109</td><td>28:d0:43:8b:2b:a4</td></tr>";
        public void SetTotals(int up, int down) => Totals = (up, down);
        public long PacketBump { get; set; }
        public bool UsedUntrustedCertificate => false;

        public Task<RouterHttpResponse> SendAsync(RouterHttpRequest request, CancellationToken cancellationToken)
        {
            var page = request.Url.AbsolutePath.TrimStart('/');
            if (request.Method == HttpMethod.Post)
            {
                Posts.Add(page + "?" + request.Body);
                var form = HttpUtility.ParseQueryString(request.Body ?? "");
                if (page == TdW8961LimitPages.StaticDhcpForm && form["delete"] == null)
                    Static.Add((form["ipaddr"]!, MacAddress.RequireUnicast(form["macaddr"]!)));
                if (page == TdW8961LimitPages.ShapingForm)
                {
                    if (form["applyItflimit"] != null)
                        Totals = (int.Parse(form["total"]!), int.Parse(form["downtotal"]!));
                    if (form["addRule"] != null && !IgnoreRules && Full.Count < MaxRules)
                        Full.Add((form["srcip"]!, int.Parse(form["uprateCeiling"]!), int.Parse(form["downrateCeiling"]!),
                            int.TryParse(form["uprateFloor"], out var uf) ? uf : -1, int.TryParse(form["downrateFloor"], out var df) ? df : -1));
                    if (form["save"] != null && int.TryParse(form["removeRuleList"], out var remove))
                        Full.RemoveAt(remove);
                }

                return Ok("<html>ok</html>");
            }

            return page switch
            {
                TdW8961LimitPages.ShapingPage => Ok(ShapingPage(Totals.Up, Totals.Down,
                    string.Concat(Full.Select((rule, i) => ShapingRow(i, rule.Ip + "/32", rule.Up, rule.Down, upFloor: rule.UpFloor, downFloor: rule.DownFloor))))),
                TdW8961LimitPages.StaticDhcpPage => Ok(StaticPage(Static.Select(s => (s.Ip, s.Mac.ToLowerInvariant())).ToArray())),
                TdW8961LimitPages.StatusPage => Ok(Status),
                TdW8961Pages.StationsPage => Ok($"<tr><td>f4:1a:9c:39:3a:00</td><td>{1000 + PacketBump}</td><td>10</td><td>65</td><td>no</td></tr>" +
                                                "<tr><td>28:d0:43:8b:2b:a4</td><td>500</td><td>10</td><td>27</td><td>no</td></tr>"),
                TdW8961Pages.DhcpPage => Ok(Leases),
                TdW8961Pages.AccessControlPage => Ok("<script>document.formWlAcAdd.wlanAcEnabled.selectedIndex=0;</script>"),
                _ => Task.FromResult(new RouterHttpResponse { StatusCode = 404, Body = "missing" })
            };
        }

        public void Dispose()
        {
        }

        private static Task<RouterHttpResponse> Ok(string body) => Task.FromResult(new RouterHttpResponse { StatusCode = 200, Body = body });
    }
}
