using System.Globalization;
using System.Net;
using System.Text.RegularExpressions;

namespace RedFilter.Core.Router.TpLink;

/// <summary>One row of "IP QoS Traffic Shaping" (ipqostc.htm). Rates are kbps; null means "not set" (the router shows -1).</summary>
public sealed record ShapingRule(
    int RemoveIndex,
    string? SourceIp,
    bool OnlyMatchesSourceIp,
    int? UpFloorKbps,
    int? DownFloorKbps,
    int? UpCeilingKbps,
    int? DownCeilingKbps);

/// <summary>The whole traffic shaping page: the line totals (0 = unlimited) and the rules.</summary>
public sealed record ShapingState(int TotalUpKbps, int TotalDownKbps, IReadOnlyList<ShapingRule> Rules)
{
    /// <summary>The rules RedFilter treats as "the limit for this IP": source IP only, nothing else to match on.</summary>
    public IReadOnlyList<ShapingRule> LimitsFor(string ip) =>
        Rules.Where(rule => rule.OnlyMatchesSourceIp && string.Equals(rule.SourceIp, ip, StringComparison.Ordinal)).ToList();
}

/// <summary>One fixed IP/MAC pair from "DHCP Static IP Configuration" (dhcpip.htm).</summary>
public sealed record StaticLease(int SelectValue, string Ip, string Mac);

/// <summary>The static DHCP page: the pool the router accepts fixed IPs from, and the fixed pairs.</summary>
public sealed record StaticLeaseState(string LanPrefix, int PoolStart, int PoolEnd, string LeaseTime, IReadOnlyList<StaticLease> Leases)
{
    public bool InPool(string ip) =>
        ip.StartsWith(LanPrefix, StringComparison.Ordinal) &&
        int.TryParse(ip.AsSpan(LanPrefix.Length), NumberStyles.None, CultureInfo.InvariantCulture, out var last) &&
        last >= PoolStart && last <= PoolEnd;
}

/// <summary>The ADSL sync speed shown on the status page.</summary>
public sealed record LineSpeed(int UpKbps, int DownKbps);

/// <summary>
/// Parsers and form bodies for the speed-limit pages of the TD-W8961N v5: traffic shaping, static DHCP
/// and the line speed on the status page. Formats were captured from a real router (firmware
/// "Mar 7 2024") by adding a rule and a fixed IP, reading the pages, and removing both.
/// </summary>
public static class TdW8961LimitPages
{
    public const string ShapingPage = "ipqostc.htm";
    public const string ShapingForm = "form2IPQoSTc.cgi";
    public const string StaticDhcpPage = "dhcpip.htm";
    public const string StaticDhcpForm = "form2Dhcpip.cgi";
    public const string StatusPage = "status.htm";

    /// <summary>The only WAN interface this router offers in the rule form ("WAN0").</summary>
    public const string WanInterface = "2";

    private static readonly Regex RowSplit = new("<tr", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
    private static readonly Regex Cell = new("<td[^>]*>(.*?)(?=<td|</tr|$)", RegexOptions.IgnoreCase | RegexOptions.Singleline | RegexOptions.CultureInvariant);
    private static readonly Regex Tags = new("<[^>]*>", RegexOptions.CultureInvariant);
    private static readonly Regex RemoveBox = new(@"name=[""']?removeQ[""']?\s+value=[""']?(\d+)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
    private static readonly Regex Total = new(@"name=[""']?(total|downtotal)[""']?[^>]*?value=[""']?(\d+)", RegexOptions.IgnoreCase | RegexOptions.Singleline | RegexOptions.CultureInvariant);
    private static readonly Regex StaticRow = new(@"name=[""']?select[""']?\s+value=[""']?(\d+)[""']?[^>]*postDhcpIp\(\s*'([\d.]+)'\s*,\s*'([0-9A-Fa-f:]{17})'", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
    private static readonly Regex PoolNumber = new(@"\b(lanip1|lanip2|lanip3|startip|endip)\s*=\s*(\d+)", RegexOptions.CultureInvariant);
    private static readonly Regex LeaseTime = new(@"name=[""']?ltime[""']?\s+value=\s*[""']?(\d+)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
    private static readonly Regex Speed = new(@"(Upstream|Downstream) Speed\s*(\d+)\s*kbps", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

    public static ShapingState ParseShaping(string html)
    {
        int? up = null, down = null;
        foreach (Match match in Total.Matches(html))
        {
            var value = int.Parse(match.Groups[2].Value, CultureInfo.InvariantCulture);
            if (match.Groups[1].Value.Equals("total", StringComparison.OrdinalIgnoreCase))
                up ??= value;
            else
                down ??= value;
        }

        if (up == null || down == null)
            throw new RouterException("The router's traffic shaping page did not show the line bandwidth, so RedFilter did not change it.");

        var rules = new List<ShapingRule>();
        foreach (var chunk in RowSplit.Split(html).Skip(1))
        {
            var box = RemoveBox.Match(chunk);
            if (!box.Success)
                continue;
            var cells = Cell.Matches(chunk).Select(match => WebUtility.HtmlDecode(Tags.Replace(match.Groups[1].Value, "")).Trim()).ToList();
            // ID, Wan Itf, Protocol, Src Port, Dst Port, Src IP, Dst IP, Up Floor, Down Floor, Up Ceiling, Down Ceiling, Remove
            if (cells.Count < 11)
                continue;
            var source = SourceIp(cells[5]);
            var onlySource = source != null && cells[2].Length == 0 && cells[3].Length == 0 && cells[4].Length == 0 && cells[6].Length == 0;
            rules.Add(new ShapingRule(
                int.Parse(box.Groups[1].Value, CultureInfo.InvariantCulture),
                source,
                onlySource,
                Rate(cells[7]),
                Rate(cells[8]),
                Rate(cells[9]),
                Rate(cells[10])));
        }

        return new ShapingState(up.Value, down.Value, rules);
    }

    public static StaticLeaseState ParseStaticLeases(string html)
    {
        var numbers = new Dictionary<string, int>(StringComparer.Ordinal);
        foreach (Match match in PoolNumber.Matches(html))
            numbers.TryAdd(match.Groups[1].Value, int.Parse(match.Groups[2].Value, CultureInfo.InvariantCulture));
        if (!numbers.TryGetValue("lanip1", out var a) || !numbers.TryGetValue("lanip2", out var b) || !numbers.TryGetValue("lanip3", out var c) ||
            !numbers.TryGetValue("startip", out var start) || !numbers.TryGetValue("endip", out var end))
            throw new RouterException("The router's static DHCP page did not show its address pool, so RedFilter did not change it.");

        var leaseTime = LeaseTime.Match(html) is { Success: true } lt ? lt.Groups[1].Value : "1440";
        var leases = new List<StaticLease>();
        foreach (Match match in StaticRow.Matches(html))
        {
            if (MacAddress.TryNormalize(match.Groups[3].Value, out var mac))
                leases.Add(new StaticLease(int.Parse(match.Groups[1].Value, CultureInfo.InvariantCulture), match.Groups[2].Value, mac));
        }

        return new StaticLeaseState($"{a}.{b}.{c}.", start, end, leaseTime, leases);
    }

    /// <summary>The DSL sync speed, or null when the status page does not show it (for example while the line is down).</summary>
    public static LineSpeed? ParseLineSpeed(string html)
    {
        var text = Regex.Replace(WebUtility.HtmlDecode(Tags.Replace(html, " ")), @"\s+", " ");
        int? up = null, down = null;
        foreach (Match match in Speed.Matches(text))
        {
            var value = int.Parse(match.Groups[2].Value, CultureInfo.InvariantCulture);
            if (match.Groups[1].Value.StartsWith("Up", StringComparison.OrdinalIgnoreCase))
                up ??= value;
            else
                down ??= value;
        }

        return up is > 0 && down is > 0 ? new LineSpeed(up.Value, down.Value) : null;
    }

    public static string SetTotalsBody(int upKbps, int downKbps) =>
        Form(
            ("total", Kbps(upKbps)),
            ("downtotal", Kbps(downKbps)),
            ("applyItflimit", "Apply"),
            ("submit.htm?ipqostc.htm", "Send"));

    /// <summary>A rule that matches only the source IP (one host) and caps it in both directions.</summary>
    public static string AddLimitBody(string ip, int upCeilingKbps, int downCeilingKbps) =>
        AddRuleBody(ip, null, upCeilingKbps, null, downCeilingKbps);

    /// <summary>Like <see cref="AddLimitBody"/>, with optional guaranteed floors ("Garanted Bandwidth").</summary>
    public static string AddRuleBody(string ip, int? upFloorKbps, int upCeilingKbps, int? downFloorKbps, int downCeilingKbps)
    {
        if (upFloorKbps > upCeilingKbps || downFloorKbps > downCeilingKbps)
            throw new RouterException("A guaranteed speed cannot be above the maximum.");
        return Form(
            ("removeRuleList", ""),
            ("intf", WanInterface),
            ("proto", "0"),
            ("srcip", RequireIpv4(ip)),
            ("srcnetmask", "255.255.255.255"),
            ("dstip", ""),
            ("dstnetmask", ""),
            ("uprateFloor", upFloorKbps is { } upFloor ? Kbps(upFloor) : ""),
            ("uprateCeiling", Kbps(upCeilingKbps)),
            ("downrateFloor", downFloorKbps is { } downFloor ? Kbps(downFloor) : ""),
            ("downrateCeiling", Kbps(downCeilingKbps)),
            ("addRule", "Apply"),
            ("submit.htm?ipqostc.htm", "Send"));
    }

    /// <summary>Removes one rule by the value of its "Remove" checkbox (the indexes shift after every removal).</summary>
    public static string RemoveRuleBody(int removeIndex) =>
        Form(
            ("removeRuleList", removeIndex.ToString(CultureInfo.InvariantCulture)),
            ("save", "Save/Apply"),
            ("intf", "255"),
            ("proto", "0"),
            ("srcip", ""),
            ("srcnetmask", ""),
            ("dstip", ""),
            ("dstnetmask", ""),
            ("uprateFloor", ""),
            ("uprateCeiling", ""),
            ("downrateFloor", ""),
            ("downrateCeiling", ""),
            ("submit.htm?ipqostc.htm", "Send"));

    public static string AddStaticLeaseBody(string ip, string mac, string leaseTime) =>
        Form(
            ("ltime", leaseTime),
            ("ipaddr", RequireIpv4(ip)),
            ("macaddr", TdW8961Pages.Compact(mac)),
            ("submit.htm?dhcpip.htm", "Send"));

    public static string RemoveStaticLeaseBody(StaticLease lease, string leaseTime) =>
        Form(
            ("ltime", leaseTime),
            ("ipaddr", lease.Ip),
            ("macaddr", TdW8961Pages.Compact(lease.Mac)),
            ("delete", "Delete Selected"),
            ("select", lease.SelectValue.ToString(CultureInfo.InvariantCulture)),
            ("submit.htm?dhcpip.htm", "Send"));

    private static string? SourceIp(string cell)
    {
        var text = cell.Trim();
        if (text.EndsWith("/32", StringComparison.Ordinal))
            text = text[..^3];
        return IPAddress.TryParse(text, out var ip) && ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork && !text.Contains('/') ? text : null;
    }

    private static int? Rate(string cell) =>
        int.TryParse(cell, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out var value) && value > 0 ? value : null;

    private static string Kbps(int kbps)
    {
        if (kbps < 0 || kbps > 999_999)
            throw new RouterException("Speed limits must be between 0 and 999999 kbps.");
        return kbps.ToString(CultureInfo.InvariantCulture);
    }

    private static string RequireIpv4(string ip)
    {
        if (!IPAddress.TryParse(ip, out var parsed) || parsed.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork || parsed.ToString() != ip.Trim())
            throw new RouterException($"\"{ip}\" is not an IPv4 address.");
        return parsed.ToString();
    }

    private static string Form(params (string Name, string Value)[] fields) =>
        string.Join("&", fields.Select(field => Uri.EscapeDataString(field.Name) + "=" + Uri.EscapeDataString(field.Value)));
}
