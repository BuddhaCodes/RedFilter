using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using RedFilter.Core.Processes;

namespace RedFilter.Core.Qos;

/// <summary>One outbound "block" rule in Windows Firewall for one program.</summary>
public sealed record FirewallBlockSpec(string Name, string AppPath);

/// <summary>What the "only Dota has internet" part of the game mode keeps working.</summary>
public sealed record SoloGameOptions(string GamePath, bool AllowDiscord);

public interface IFirewallBlockStore
{
    Task<IReadOnlyList<FirewallBlockSpec>> ReadAsync(CancellationToken cancellationToken);
    Task ApplyAsync(IReadOnlyList<FirewallBlockSpec> desired, CancellationToken cancellationToken);
    Task RemoveAllAsync(CancellationToken cancellationToken);
}

/// <summary>
/// Plans which programs on this PC lose internet while only the game should have it. Never blocks
/// Windows itself (DNS, updates, the desktop all live in protected processes), RedFilter, the game and
/// everything installed with it, or Steam (Dota needs it to log in and find matches). Discord is optional.
/// </summary>
public static class FirewallBlockPlanner
{
    public const string RulePrefix = "RedFilter-Block-";
    public const string Group = "RedFilter";

    // Steam's client, its browser helper and the in-game overlay: without them Dota cannot log in.
    private static readonly HashSet<string> SteamStems = new(StringComparer.OrdinalIgnoreCase)
    {
        "steam", "steamservice", "steamwebhelper", "steamerrorreporter", "steamerrorreporter64",
        "gameoverlayui", "gameoverlayui64", "GameOverlayUI"
    };

    /// <param name="processes">The running processes; only those using the network (or already blocked) are blocked.</param>
    /// <param name="alreadyBlocked">Programs blocked earlier: they stay blocked even when their connections are gone.</param>
    public static IReadOnlyList<FirewallBlockSpec> Build(IEnumerable<ProcessNetworkRow> processes, SoloGameOptions options, IEnumerable<string> alreadyBlocked)
    {
        var gameRoot = GameRoot(options.GamePath);
        var paths = new SortedSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var process in processes)
        {
            if (string.IsNullOrWhiteSpace(process.ExecutablePath) || process.TcpConnections + process.UdpEndpoints == 0)
                continue;
            if (QosPolicyPlanner.IsProtected(process))
                continue;
            paths.Add(process.ExecutablePath.Trim());
        }

        foreach (var path in alreadyBlocked)
        {
            if (!string.IsNullOrWhiteSpace(path))
                paths.Add(path.Trim());
        }

        return paths
            .Where(path => !Keeps(path, options, gameRoot))
            .Select(path => new FirewallBlockSpec(RuleName(path), path))
            .ToList();
    }

    /// <summary>True for a program that must keep its internet while only the game has it.</summary>
    public static bool Keeps(string path, SoloGameOptions options, string? gameRoot = null)
    {
        gameRoot ??= GameRoot(options.GamePath);
        var stem = FileStem(path);
        if (path.Equals(options.GamePath, StringComparison.OrdinalIgnoreCase))
            return true;
        if (gameRoot != null && path.StartsWith(gameRoot, StringComparison.OrdinalIgnoreCase))
            return true;
        if (SteamStems.Contains(stem) || Contains(path, @"\Steam\bin\cef\"))
            return true;
        if (options.AllowDiscord && (Contains(path, @"\Discord\") || Contains(path, @"\DiscordPTB\") || Contains(path, @"\DiscordCanary\")))
            return true;
        // Same list as the QoS planner: Windows' own processes and RedFilter itself.
        return QosPolicyPlanner.IsProtected(new ProcessNetworkRow(0, stem, path, 0, 0, 0, 0));
    }

    public static string RuleName(string appPath)
    {
        var key = appPath.Trim().ToUpperInvariant();
        var hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(key)));
        return RulePrefix + hash[..12];
    }

    public static string Fingerprint(IReadOnlyList<FirewallBlockSpec> blocks) =>
        string.Join("\n", blocks.Select(block => block.Name).Order(StringComparer.Ordinal));

    /// <summary>
    /// The game's install folder ("...\steamapps\common\dota 2 beta\"), so its helpers keep the
    /// network too. Falls back to the folder of the executable.
    /// </summary>
    public static string? GameRoot(string gamePath)
    {
        if (string.IsNullOrWhiteSpace(gamePath))
            return null;
        var marker = gamePath.IndexOf(@"\steamapps\common\", StringComparison.OrdinalIgnoreCase);
        if (marker >= 0)
        {
            var start = marker + @"\steamapps\common\".Length;
            var end = gamePath.IndexOf('\\', start);
            return end > start ? gamePath[..(end + 1)] : null;
        }

        var slash = gamePath.LastIndexOf('\\');
        return slash > 0 ? gamePath[..(slash + 1)] : null;
    }

    private static bool Contains(string path, string part) => path.Contains(part, StringComparison.OrdinalIgnoreCase);

    private static string FileStem(string path)
    {
        var file = path[(path.LastIndexOfAny(['\\', '/']) + 1)..];
        var dot = file.LastIndexOf('.');
        return dot > 0 ? file[..dot] : file;
    }
}

public static class FirewallBlockReconciler
{
    public static (IReadOnlyList<string> Remove, IReadOnlyList<FirewallBlockSpec> Add) Diff(
        IReadOnlyList<FirewallBlockSpec> current,
        IReadOnlyList<FirewallBlockSpec> desired)
    {
        var want = desired.ToDictionary(block => block.Name, StringComparer.OrdinalIgnoreCase);
        var have = new Dictionary<string, FirewallBlockSpec>(StringComparer.OrdinalIgnoreCase);
        foreach (var block in current)
            have[block.Name] = block;

        var remove = have.Values
            .Where(block => !want.TryGetValue(block.Name, out var w) || !string.Equals(w.AppPath, block.AppPath, StringComparison.OrdinalIgnoreCase))
            .Select(block => block.Name)
            .ToList();
        var add = desired
            .Where(block => !have.TryGetValue(block.Name, out var h) || !string.Equals(h.AppPath, block.AppPath, StringComparison.OrdinalIgnoreCase))
            .ToList();
        return (remove, add);
    }
}

/// <summary>
/// The fixed PowerShell script behind the firewall blocks. Like the QoS script, it never contains a
/// path or a rule name: those arrive as ASCII JSON on stdin and are only ever passed as parameters.
/// Every rule lives in the "RedFilter" group, so turning the mode off removes exactly what it added.
/// </summary>
public static class NetFirewallScript
{
    private static readonly Regex SafeName = new(@"^RedFilter-Block-[A-F0-9]{12}$", RegexOptions.CultureInvariant);

    private static readonly JsonSerializerOptions PayloadOptions = new()
    {
        Encoder = System.Text.Encodings.Web.JavaScriptEncoder.Default
    };

    public const string Script =
        """
        $ErrorActionPreference = 'Stop'
        try {
          Import-Module NetSecurity -ErrorAction Stop
          $request = [Console]::In.ReadToEnd() | ConvertFrom-Json
          function Get-RedFilterRule {
            @(Get-NetFirewallRule -Group 'RedFilter' -ErrorAction SilentlyContinue | Where-Object { $_.Name -like 'RedFilter-Block-*' })
          }
          function Write-AsciiJson($value) {
            $json = ConvertTo-Json -InputObject $value -Compress -Depth 4
            [regex]::Replace($json, '[^\u0000-\u007F]', { param($m) '\u{0:x4}' -f [int][char]$m.Value })
          }
          switch ([string]$request.op) {
            'query' {
              $rows = @(Get-RedFilterRule | ForEach-Object {
                [PSCustomObject]@{
                  Name = [string]$_.Name
                  Program = [string](($_ | Get-NetFirewallApplicationFilter).Program)
                }
              })
              Write-AsciiJson -value $rows
            }
            'clear' {
              $rows = Get-RedFilterRule
              foreach ($row in $rows) { Remove-NetFirewallRule -Name $row.Name -Confirm:$false }
              Write-Output ('OK removed=' + $rows.Count)
            }
            'apply' {
              $removed = 0
              $applied = 0
              $removeNames = @($request.remove | Where-Object { $_ } | ForEach-Object { [string]$_ })
              foreach ($row in (Get-RedFilterRule | Where-Object { $removeNames -contains $_.Name })) {
                Remove-NetFirewallRule -Name $row.Name -Confirm:$false
                $removed++
              }
              foreach ($block in @($request.add)) {
                if ($null -eq $block) { continue }
                $name = [string]$block.name
                $program = [string]$block.path
                if ($name -cnotmatch '^RedFilter-Block-[A-F0-9]{12}$') { throw 'Refusing an unexpected firewall rule name.' }
                if ([string]::IsNullOrWhiteSpace($program)) { throw 'A firewall block needs a program path.' }
                $leaf = [System.IO.Path]::GetFileNameWithoutExtension($program)
                if (@('svchost', 'lsass', 'services', 'System', 'RedFilter', 'powershell', 'pwsh') -contains $leaf) { throw 'Refusing to block a Windows or RedFilter process.' }
                New-NetFirewallRule -Name $name -DisplayName ('RedFilter: modo Dota 2 (' + $leaf + ')') -Group 'RedFilter' `
                  -Direction Outbound -Action Block -Program $program -Profile Any -Enabled True | Out-Null
                $applied++
              }
              Write-Output ('OK removed=' + $removed + ' applied=' + $applied)
            }
            default { throw 'Unknown RedFilter firewall request.' }
          }
        } catch {
          [Console]::Error.WriteLine($_.Exception.Message)
          exit 1
        }
        """;

    public static string EncodedScript { get; } = Convert.ToBase64String(Encoding.Unicode.GetBytes(Script));

    public static string QueryPayload() => JsonSerializer.Serialize(new { op = "query" }, PayloadOptions);

    public static string ClearPayload() => JsonSerializer.Serialize(new { op = "clear" }, PayloadOptions);

    public static string ApplyPayload(IReadOnlyList<string> remove, IReadOnlyList<FirewallBlockSpec> add)
    {
        var removeNames = remove.Select(RequireName).ToArray();
        var blocks = add.Select(block => new { name = RequireName(block.Name), path = NetQosScript.RequirePath(block.AppPath) }).ToArray();
        return JsonSerializer.Serialize(new { op = "apply", remove = removeNames, add = blocks }, PayloadOptions);
    }

    public static string RequireName(string name) =>
        SafeName.IsMatch(name) ? name : throw new InvalidOperationException("Refusing to build a firewall request for an unexpected rule name.");

    public static IReadOnlyList<FirewallBlockSpec> ParseQuery(string output)
    {
        var start = output.IndexOfAny(['[', '{']);
        if (start < 0)
            return Array.Empty<FirewallBlockSpec>();
        using var document = JsonDocument.Parse(output[start..].Trim());
        var items = document.RootElement.ValueKind == JsonValueKind.Array
            ? document.RootElement.EnumerateArray().ToList()
            : new List<JsonElement> { document.RootElement };
        return items
            .Where(item => item.ValueKind == JsonValueKind.Object)
            .Select(item => new FirewallBlockSpec(
                item.TryGetProperty("Name", out var name) ? name.GetString() ?? "" : "",
                item.TryGetProperty("Program", out var program) ? program.GetString() ?? "" : ""))
            .Where(block => block.Name.StartsWith(FirewallBlockPlanner.RulePrefix, StringComparison.Ordinal))
            .ToList();
    }
}
