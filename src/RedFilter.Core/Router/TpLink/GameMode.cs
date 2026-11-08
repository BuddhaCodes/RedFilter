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
public enum GameModeLevel
{
    /// <summary>The others keep most of the line: videos still play in decent quality.</summary>
    Soft = 0,
    /// <summary>The others get about a quarter of the line: chat, browsing and low-quality video.</summary>
    Aggressive = 1,
    /// <summary>The others get a trickle: messages and notifications only.</summary>
    Extreme = 2
}

/// <summary>How hard a level squeezes the other devices, and this PC's other programs.</summary>
public sealed record GameModeProfile(
    GameModeLevel Level,
    string Name,
    int OthersDownBudgetKbps,
    int OthersUpBudgetKbps,
    int OthersDownPercent,
    int OthersUpPercent,
    int MinDeviceDownKbps,
    int MinDeviceUpKbps,
    long PcOtherProgramsUploadBits)
{
    public static readonly GameModeProfile Soft = new(GameModeLevel.Soft, "Suave", 2500, 384, 65, 40, 128, 32, 256_000);
    public static readonly GameModeProfile Aggressive = new(GameModeLevel.Aggressive, "Agresivo", 1000, 160, 25, 15, 64, 16, 128_000);
    public static readonly GameModeProfile Extreme = new(GameModeLevel.Extreme, "Extremo", 384, 64, 10, 6, 32, 8, 64_000);

    public static GameModeProfile For(GameModeLevel level) => level switch
    {
        GameModeLevel.Soft => Soft,
        GameModeLevel.Extreme => Extreme,
        _ => Aggressive
    };
}

/// <summary>
/// Plans the "Dota 2" mode: this PC gets a guaranteed share of the line and every other device gets
/// its own rule, so that together they never take more than the level's budget. Every rule matches one
/// IP and no two rules overlap, so the result does not depend on how the router orders its rules.
/// </summary>
public static class GameModePlanner
{
    /// <summary>
    /// The line totals the router should shape to. An ADSL line carries less than its sync speed (ATM
    /// overhead), and shaping must sit below what really gets through, or the modem's own queue fills
    /// up and the ping climbs anyway. Upload is cut harder because it is where the lag comes from.
    /// </summary>
    public static (int UpKbps, int DownKbps) ShapingTotals(LineSpeed line) => (line.UpKbps * 80 / 100, line.DownKbps * 85 / 100);

    public static GameModePlan Build(int totalUpKbps, int totalDownKbps, string pcIp, IEnumerable<string> otherIps, IReadOnlyList<ShapingRule> existing, GameModeProfile? profile = null) =>
        Build(totalUpKbps, totalDownKbps, pcIp, otherIps, TdW8961Client.SaveLimits(new ShapingState(totalUpKbps, totalDownKbps, existing)), profile);

    /// <param name="userLimits">Limits the user had before the game mode (from the backup); a lower one is kept.</param>
    public static GameModePlan Build(int totalUpKbps, int totalDownKbps, string pcIp, IEnumerable<string> otherIps, IReadOnlyList<SavedLimit> userLimits, GameModeProfile? profile = null)
    {
        profile ??= GameModeProfile.Aggressive;
        if (totalUpKbps <= 0 || totalDownKbps <= 0)
            throw new RouterException("The router does not know the speed of the line, so the game mode cannot share it.");
        RequireIpv4(pcIp);

        var others = otherIps
            .Where(ip => !string.Equals(ip, pcIp, StringComparison.Ordinal))
            .Select(RequireIpv4)
            .Distinct(StringComparer.Ordinal)
            .OrderBy(ip => IPAddress.Parse(ip).GetAddressBytes()[3])
            .ToList();

        // The budget is the smaller of a fixed amount and a share of the line, so a slow line is squeezed too.
        var othersDown = Math.Min(profile.OthersDownBudgetKbps, totalDownKbps * profile.OthersDownPercent / 100);
        var othersUp = Math.Min(profile.OthersUpBudgetKbps, totalUpKbps * profile.OthersUpPercent / 100);

        var count = Math.Max(1, others.Count);
        var eachDown = Math.Max(profile.MinDeviceDownKbps, othersDown / count);
        var eachUp = Math.Max(profile.MinDeviceUpKbps, othersUp / count);

        var rules = new List<GameModeRule>();
        foreach (var ip in others)
        {
            var user = userLimits.FirstOrDefault(limit => limit.Ip == ip);
            var down = Math.Min(eachDown, user?.DownCeilingKbps ?? int.MaxValue);
            var up = Math.Min(eachUp, user?.UpCeilingKbps ?? int.MaxValue);
            rules.Add(new GameModeRule(ip, null, up, null, down));
        }

        // With many devices the per-device minimum can add up to more than the budget; count what was really given.
        var givenDown = rules.Count == 0 ? othersDown : rules.Sum(rule => rule.DownCeilingKbps);
        var givenUp = rules.Count == 0 ? othersUp : rules.Sum(rule => rule.UpCeilingKbps);

        // The PC is guaranteed what the others cannot take (never less than half the line), and may use all of it when free.
        var pc = new GameModeRule(pcIp,
            Math.Clamp(totalUpKbps - givenUp, totalUpKbps / 2, totalUpKbps), totalUpKbps,
            Math.Clamp(totalDownKbps - givenDown, totalDownKbps / 2, totalDownKbps), totalDownKbps);
        return new GameModePlan(totalUpKbps, totalDownKbps, pc, rules, givenUp, givenDown);
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
