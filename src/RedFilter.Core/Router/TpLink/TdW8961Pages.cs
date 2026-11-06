using System.Globalization;
using System.Net;
using System.Text.RegularExpressions;

namespace RedFilter.Core.Router.TpLink;

/// <summary>One wireless station from the router's "Active Wireless Client Table" (wlstatbl.htm).</summary>
public sealed record WifiStation(string Mac, long TxPackets, long RxPackets, double? TxRateMbps, bool? PowerSaving)
{
    public long TotalPackets => TxPackets + RxPackets;
}

/// <summary>One lease from the "Active DHCP Client Table" (dhcptbl.htm).</summary>
public sealed record DhcpLease(string? Name, string Ip, string Mac);

public enum AccessControlMode
{
    Disabled = 0,
    AllowListed = 1,
    DenyListed = 2
}

/// <summary>The wireless access control list (wlactrl.htm): the mode and the MAC addresses on the list.</summary>
public sealed record AccessControlState(AccessControlMode Mode, IReadOnlyList<string> Macs)
{
    public bool Contains(string mac) =>
        MacAddress.TryNormalize(mac, out var normalized) && Macs.Contains(normalized, StringComparer.OrdinalIgnoreCase);

    /// <summary>MACs that are on the list and would be blocked right now.</summary>
    public IReadOnlyList<string> Blocked => Mode == AccessControlMode.DenyListed ? Macs : Array.Empty<string>();
}

/// <summary>
/// Parsers and form bodies for the Realtek-based web interface of the TP-Link TD-W8961N v5.
/// The pages are classic server-rendered HTML; these functions only read and build text, so they
/// are tested against HTML captured from a real router.
/// </summary>
public static class TdW8961Pages
{
    public const string StationsPage = "wlstatbl.htm";
    public const string DhcpPage = "dhcptbl.htm";
    public const string AccessControlPage = "wlactrl.htm";
    public const string AccessControlForm = "form2WlAc.cgi";

    private static readonly Regex RowSplit = new("<tr", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
    private static readonly Regex Cell = new("<td[^>]*>(.*?)(?=<td|</tr|$)", RegexOptions.IgnoreCase | RegexOptions.Singleline | RegexOptions.CultureInvariant);
    private static readonly Regex Tags = new("<[^>]*>", RegexOptions.CultureInvariant);
    private static readonly Regex AcMode = new(@"wlanAcEnabled\.selectedIndex\s*=\s*(\d)", RegexOptions.CultureInvariant);
    private static readonly Regex AcEntry = new(@"name=[""']?select[""']?\s+value=[""']?([0-9A-Fa-f]{12})", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

    /// <summary>The router answers pages with its login form when the session is missing or expired.</summary>
    public static bool IsLoginPage(string html) =>
        html.Contains("Router Login", StringComparison.OrdinalIgnoreCase) ||
        // Admin pages answer an expired session with a script that sends the browser to the login page.
        html.Contains("location=\"/login.htm\"", StringComparison.OrdinalIgnoreCase) ||
        html.Contains("location='/login.htm'", StringComparison.OrdinalIgnoreCase) ||
        (html.Contains("hex_md5", StringComparison.Ordinal) && html.Contains("password", StringComparison.OrdinalIgnoreCase) && !html.Contains("Active ", StringComparison.Ordinal));

    public static IReadOnlyList<WifiStation> ParseStations(string html)
    {
        var stations = new Dictionary<string, WifiStation>(StringComparer.OrdinalIgnoreCase);
        foreach (var cells in Rows(html))
        {
            if (cells.Count < 3 || !MacAddress.TryNormalize(cells[0], out var mac) || !LooksLikeMac(cells[0]))
                continue;
            if (!long.TryParse(cells[1], NumberStyles.Integer, CultureInfo.InvariantCulture, out var tx) ||
                !long.TryParse(cells[2], NumberStyles.Integer, CultureInfo.InvariantCulture, out var rx))
                continue;
            double? rate = cells.Count > 3 && double.TryParse(cells[3], NumberStyles.Float, CultureInfo.InvariantCulture, out var r) ? r : null;
            bool? saving = cells.Count > 4 ? cells[4].Equals("yes", StringComparison.OrdinalIgnoreCase) : null;
            stations[mac] = new WifiStation(mac, tx, rx, rate, saving);
        }

        return stations.Values.ToList();
    }

    public static IReadOnlyList<DhcpLease> ParseDhcp(string html)
    {
        var leases = new Dictionary<string, DhcpLease>(StringComparer.OrdinalIgnoreCase);
        foreach (var cells in Rows(html))
        {
            if (cells.Count < 3 || !IPAddress.TryParse(cells[1], out _) || !LooksLikeMac(cells[2]) ||
                !MacAddress.TryNormalize(cells[2], out var mac))
                continue;
            var name = string.IsNullOrWhiteSpace(cells[0]) ? null : cells[0];
            leases[mac] = new DhcpLease(name, cells[1], mac);
        }

        return leases.Values.ToList();
    }

    public static AccessControlState ParseAccessControl(string html)
    {
        var modeMatch = AcMode.Match(html);
        var mode = modeMatch.Success && int.TryParse(modeMatch.Groups[1].Value, out var index) && Enum.IsDefined(typeof(AccessControlMode), index)
            ? (AccessControlMode)index
            : throw new RouterException("The router's access control page did not say which mode is active, so RedFilter did not change it.");
        var macs = new List<string>();
        foreach (Match match in AcEntry.Matches(html))
        {
            if (MacAddress.TryNormalize(match.Groups[1].Value, out var mac) && !macs.Contains(mac, StringComparer.OrdinalIgnoreCase))
                macs.Add(mac);
        }

        return new AccessControlState(mode, macs);
    }

    /// <summary>Adds one MAC to the list. The current mode is sent back unchanged.</summary>
    public static string AddToAccessListBody(string mac, AccessControlMode currentMode) =>
        Form(
            ("wlanAcEnabled", ((int)currentMode).ToString(CultureInfo.InvariantCulture)),
            ("checkWPS2", "1"),
            ("mac", Compact(mac)),
            ("addFilterMac", "Add"),
            ("submit.htm?wlactrl.htm", "Send"));

    public static string SetAccessModeBody(AccessControlMode mode) =>
        Form(
            ("wlanAcEnabled", ((int)mode).ToString(CultureInfo.InvariantCulture)),
            ("checkWPS2", "1"),
            ("setFilterMode", "Apply Changes"),
            ("mac", ""),
            ("submit.htm?wlactrl.htm", "Send"));

    public static string RemoveFromAccessListBody(string mac, int totalEntries) =>
        Form(
            ("select", Compact(mac).ToLowerInvariant()),
            ("totalNum", totalEntries.ToString(CultureInfo.InvariantCulture)),
            ("deleteSelFilterMac", "Delete Selected"),
            ("submit.htm?wlactrl.htm", "Send"));

    /// <summary>The 12-hex form the router's MAC fields expect, after refusing broadcast and group addresses.</summary>
    public static string Compact(string mac) => MacAddress.RequireUnicast(mac).Replace(":", "", StringComparison.Ordinal);

    private static string Form(params (string Name, string Value)[] fields) =>
        string.Join("&", fields.Select(field => Uri.EscapeDataString(field.Name) + "=" + Uri.EscapeDataString(field.Value)));

    private static bool LooksLikeMac(string text) => Regex.IsMatch(text.Trim(), "^[0-9A-Fa-f]{2}([:-]?[0-9A-Fa-f]{2}){5}$");

    private static IEnumerable<List<string>> Rows(string html)
    {
        foreach (var chunk in RowSplit.Split(html).Skip(1))
        {
            var cells = Cell.Matches(chunk)
                .Select(match => WebUtility.HtmlDecode(Tags.Replace(match.Groups[1].Value, "")).Trim())
                .ToList();
            if (cells.Count > 0)
                yield return cells;
        }
    }
}

/// <summary>
/// Turns the router's cumulative packet counters into "packets per second right now", so the
/// device using the Wi-Fi most at this moment comes first. Counters restart when a device
/// reconnects; a drop is treated as a fresh start rather than a negative rate.
/// </summary>
public sealed class WifiUsageTracker
{
    private readonly Dictionary<string, (long Packets, DateTime At)> _last = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, double> _smoothed = new(StringComparer.OrdinalIgnoreCase);

    public IReadOnlyDictionary<string, double> Update(IReadOnlyList<WifiStation> stations, DateTime nowUtc)
    {
        var rates = new Dictionary<string, double>(StringComparer.OrdinalIgnoreCase);
        foreach (var station in stations)
        {
            var rate = 0.0;
            if (_last.TryGetValue(station.Mac, out var previous))
            {
                var seconds = (nowUtc - previous.At).TotalSeconds;
                if (seconds >= 0.5 && station.TotalPackets >= previous.Packets)
                    rate = (station.TotalPackets - previous.Packets) / seconds;
            }

            // Light smoothing so one quiet poll does not make the busiest device drop to the bottom.
            var smoothed = _smoothed.TryGetValue(station.Mac, out var old) ? old * 0.4 + rate * 0.6 : rate;
            _smoothed[station.Mac] = smoothed;
            _last[station.Mac] = (station.TotalPackets, nowUtc);
            rates[station.Mac] = smoothed;
        }

        foreach (var gone in _last.Keys.Where(mac => !rates.ContainsKey(mac)).ToList())
        {
            _last.Remove(gone);
            _smoothed.Remove(gone);
        }

        return rates;
    }
}
