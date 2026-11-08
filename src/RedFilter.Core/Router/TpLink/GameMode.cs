using System.Globalization;
using System.Net;

namespace RedFilter.Core.Router.TpLink;

/// <summary>One speed rule the game mode wants on the router: a single source IP with optional guaranteed floors.</summary>
public sealed record GameModeRule(string Ip, int? UpFloorKbps, int UpCeilingKbps, int? DownFloorKbps, int DownCeilingKbps);

/// <summary>What the router should look like while the game mode is on.</summary>
public sealed record GameModePlan(
    int TotalUpKbps,
    int TotalDownKbps,
    GameModeRule Pc,
    IReadOnlyList<GameModeRule> Others,
    int OthersUpKbps,
    int OthersDownKbps)
{
    public IEnumerable<GameModeRule> AllRules => Others.Prepend(Pc);
}

/// <summary>A limit that existed before the game mode, so it can be put back afterwards.</summary>
public sealed record SavedLimit(string Ip, int? UpCeilingKbps, int? DownCeilingKbps);

/// <summary>
/// Everything needed to undo the game mode, saved to disk when it starts so a crash or a closed
/// window does not leave the house throttled with no way back.
/// </summary>
public sealed class GameModeBackup
{
    public int TotalUpKbps { get; set; }
    public int TotalDownKbps { get; set; }
    public List<SavedLimit> Limits { get; set; } = new();
    /// <summary>Every IP the game mode put a rule on. Only these rules are removed when it ends.</summary>
    public List<string> TouchedIps { get; set; } = new();
    public string? PcIp { get; set; }
    public DateTime StartedUtc { get; set; }
}

/// <summary>
/// Plans the "Dota 2" mode: this PC gets a guaranteed share of the line and every other device gets
/// its own rule, so that together they never take more than a fixed budget. Every rule matches one
/// IP and no two rules overlap, so the result does not depend on how the router orders its rules.
/// </summary>
public static class GameModePlanner
{
    /// <summary>What all other devices may use together, at most (kbps).</summary>
    public const int OthersDownBudgetKbps = 2500;
    public const int OthersUpBudgetKbps = 384;

    /// <summary>Below this, a phone cannot even load a chat; the budget is shared but never thinner than this.</summary>
    public const int MinDeviceDownKbps = 128;
    public const int MinDeviceUpKbps = 32;

    /// <param name="totalUpKbps">Line totals the router uses (90% of the DSL sync speed).</param>
    /// <param name="existing">Rules already on the router; a lower limit the user set on a device is kept.</param>
    public static GameModePlan Build(int totalUpKbps, int totalDownKbps, string pcIp, IEnumerable<string> otherIps, IReadOnlyList<ShapingRule> existing) =>
        Build(totalUpKbps, totalDownKbps, pcIp, otherIps, TdW8961Client.SaveLimits(new ShapingState(totalUpKbps, totalDownKbps, existing)));

    /// <param name="userLimits">Limits the user had before the game mode (from the backup); a lower one is kept.</param>
    public static GameModePlan Build(int totalUpKbps, int totalDownKbps, string pcIp, IEnumerable<string> otherIps, IReadOnlyList<SavedLimit> userLimits)
    {
        if (totalUpKbps <= 0 || totalDownKbps <= 0)
            throw new RouterException("The router does not know the speed of the line, so the game mode cannot share it.");
        RequireIpv4(pcIp);

        var others = otherIps
            .Where(ip => !string.Equals(ip, pcIp, StringComparison.Ordinal))
            .Select(RequireIpv4)
            .Distinct(StringComparer.Ordinal)
            .OrderBy(ip => IPAddress.Parse(ip).GetAddressBytes()[3])
            .ToList();

        // On a slow line the fixed budget would leave nothing for the game; keep at least a third for the PC.
        var othersDown = Math.Min(OthersDownBudgetKbps, totalDownKbps * 65 / 100);
        var othersUp = Math.Min(OthersUpBudgetKbps, totalUpKbps * 40 / 100);

        var count = Math.Max(1, others.Count);
        var eachDown = Math.Max(MinDeviceDownKbps, othersDown / count);
        var eachUp = Math.Max(MinDeviceUpKbps, othersUp / count);

        var rules = new List<GameModeRule>();
        foreach (var ip in others)
        {
            var user = userLimits.FirstOrDefault(limit => limit.Ip == ip);
            var down = Math.Min(eachDown, user?.DownCeilingKbps ?? int.MaxValue);
            var up = Math.Min(eachUp, user?.UpCeilingKbps ?? int.MaxValue);
            rules.Add(new GameModeRule(ip, null, up, null, down));
        }

        // The PC is guaranteed what the others cannot take, and may use the whole line when it is free.
        var pc = new GameModeRule(pcIp, totalUpKbps - othersUp, totalUpKbps, totalDownKbps - othersDown, totalDownKbps);
        return new GameModePlan(totalUpKbps, totalDownKbps, pc, rules, othersUp, othersDown);
    }

    /// <summary>True when the router already has exactly this rule for the IP (and nothing else for it).</summary>
    public static bool IsInPlace(ShapingState state, GameModeRule rule)
    {
        var current = state.LimitsFor(rule.Ip);
        return current.Count == 1 &&
               current[0].UpCeilingKbps == rule.UpCeilingKbps &&
               current[0].DownCeilingKbps == rule.DownCeilingKbps &&
               current[0].UpFloorKbps == rule.UpFloorKbps &&
               current[0].DownFloorKbps == rule.DownFloorKbps;
    }

    private static string RequireIpv4(string ip)
    {
        if (!IPAddress.TryParse(ip, out var parsed) || parsed.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
            throw new RouterException($"\"{ip}\" is not an IPv4 address.");
        return parsed.ToString();
    }

    public static string Describe(int kbps) =>
        kbps >= 1000 && kbps % 100 == 0
            ? (kbps / 1000.0).ToString("0.#", CultureInfo.GetCultureInfo("es-ES")) + " Mbps"
            : kbps.ToString(CultureInfo.InvariantCulture) + " kbps";
}
