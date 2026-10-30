using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using RedFilter.Core.Processes;
using RedFilter.Core.Text;

namespace RedFilter.Core.Qos;

public sealed record QosPolicySpec(
    string Name,
    string AppPath,
    bool IsOwner,
    int Dscp,
    long? ThrottleBitsPerSecond);

public sealed record ActiveQosPolicy(
    string Name,
    string? AppPath,
    long? ThrottleBitsPerSecond,
    int? Dscp);

public sealed record QosPlan(
    string OwnerName,
    int OwnerPid,
    string OwnerPath,
    long ThrottleBitsPerSecond,
    IReadOnlyList<QosPolicySpec> Policies,
    IReadOnlyList<string> Notes);

public interface IQosPolicyStore
{
    Task<IReadOnlyList<ActiveQosPolicy>> ReadAsync(CancellationToken cancellationToken);
    Task ApplyAsync(IReadOnlyList<QosPolicySpec> desired, CancellationToken cancellationToken);
    Task RemoveAllAsync(CancellationToken cancellationToken);
}

public static class QosPolicyPlanner
{
    public const string OwnerPolicyName = "RedFilter-Owner";
    public const string LimitPrefix = "RedFilter-Limit-";
    public const int OwnerDscp = 46;
    public const int BackgroundDscp = 8;
    public const long MinimumThrottleBits = 64_000;
    public const long MaximumThrottleBits = 100_000_000;

    // These processes keep the PC working. Throttling them can break logon, DNS, and the desktop.
    private static readonly HashSet<string> NeverThrottle = new(StringComparer.OrdinalIgnoreCase)
    {
        "System", "Idle", "Registry", "Secure System", "MemCompression",
        "smss", "csrss", "wininit", "winlogon", "services", "lsass", "LsaIso",
        "svchost", "fontdrvhost", "dwm", "sihost", "taskhostw", "RuntimeBroker",
        "dllhost", "conhost", "WmiPrvSE", "spoolsv", "SearchIndexer", "MsMpEng",
        "SecurityHealthService", "SecurityHealthSystray", "SgrmBroker", "NisSrv",
        "dasHost", "RedFilter", "powershell", "pwsh", "smartscreen", "csrss"
    };

    public static long NormalizeThrottle(long bitsPerSecond)
    {
        if (bitsPerSecond < MinimumThrottleBits)
            return MinimumThrottleBits;
        if (bitsPerSecond > MaximumThrottleBits)
            return MaximumThrottleBits;
        return bitsPerSecond;
    }

    public static QosPlan Build(
        ProcessNetworkRow owner,
        IReadOnlyList<ProcessNetworkRow> processes,
        long throttleBitsPerSecond,
        string? thisProgramPath)
    {
        if (string.IsNullOrWhiteSpace(owner.ExecutablePath))
        {
            throw new InvalidOperationException(
                $"RedFilter cannot read the program path for {owner.Name} (PID {owner.Pid}). " +
                "Windows QoS matches a program path, so this process cannot take the network. " +
                "Run RedFilter as administrator and choose a program whose path is visible.");
        }

        var throttle = NormalizeThrottle(throttleBitsPerSecond);
        var ownerPath = owner.ExecutablePath.Trim();
        var policies = new List<QosPolicySpec>
        {
            new(OwnerPolicyName, ownerPath, true, OwnerDscp, null)
        };

        var seenPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { ownerPath };
        if (!string.IsNullOrWhiteSpace(thisProgramPath))
            seenPaths.Add(thisProgramPath.Trim());

        var skippedSystem = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var missingPath = 0;

        foreach (var process in processes)
        {
            if (process.Pid == owner.Pid)
                continue;
            if (IsProtected(process))
            {
                if (process.TcpConnections + process.UdpEndpoints > 0)
                    skippedSystem.Add(process.Name);
                continue;
            }

            if (string.IsNullOrWhiteSpace(process.ExecutablePath))
            {
                if (process.TcpConnections + process.UdpEndpoints > 0)
                    missingPath++;
                continue;
            }

            var path = process.ExecutablePath.Trim();
            if (!seenPaths.Add(path))
                continue;

            policies.Add(new QosPolicySpec(
                LimitName(path),
                path,
                false,
                BackgroundDscp,
                throttle));
        }

        var notes = new List<string>
        {
            $"Windows QoS matches the program path, so every process running {Path.GetFileName(ownerPath)} is included.",
            $"Outbound traffic from other ordinary programs is limited to {RateText.BitsPerSecond(throttle)}. " +
            "This limit does not cap downloads. Windows cannot shape inbound bytes with this policy.",
            "The policies live in the active QoS store. They stay in effect after you close RedFilter, and Windows drops them on reboot. Turn the filter off to restore sharing sooner."
        };

        if (IsProtected(owner))
        {
            notes.Add(
                $"{owner.Name} is a Windows component. Prioritizing it marks that program path, " +
                "and RedFilter still will not throttle the rest of the system list.");
        }

        if (skippedSystem.Count > 0)
        {
            var names = string.Join(", ", skippedSystem.OrderBy(n => n, StringComparer.OrdinalIgnoreCase));
            notes.Add("Left unthrottled so Windows keeps working: " + names + ".");
        }

        if (missingPath > 0)
        {
            notes.Add(
                $"{missingPath} process{(missingPath == 1 ? "" : "es")} had network activity but no readable program path, so they were left unchanged.");
        }

        var limited = policies.Count - 1;
        notes.Insert(1, limited == 0
            ? "No other ordinary program had a usable path, so only the priority mark was applied."
            : $"{limited} other program path{(limited == 1 ? "" : "s")} will be limited.");

        return new QosPlan(owner.Name, owner.Pid, ownerPath, throttle, policies, notes);
    }

    public static bool IsProtected(ProcessNetworkRow process)
    {
        if (NeverThrottle.Contains(process.Name))
            return true;
        if (string.IsNullOrWhiteSpace(process.ExecutablePath))
            return false;
        var file = Path.GetFileNameWithoutExtension(process.ExecutablePath);
        return NeverThrottle.Contains(file);
    }

    public static string LimitName(string appPath)
    {
        var key = appPath.Trim().ToUpperInvariant();
        var hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(key)));
        return LimitPrefix + hash[..12];
    }
}

public static class QosPolicyReconciler
{
    public static (IReadOnlyList<string> Remove, IReadOnlyList<QosPolicySpec> Add) Diff(
        IReadOnlyList<ActiveQosPolicy> current,
        IReadOnlyList<QosPolicySpec> desired)
    {
        var desiredByName = desired.ToDictionary(d => d.Name, StringComparer.OrdinalIgnoreCase);
        var currentByName = new Dictionary<string, ActiveQosPolicy>(StringComparer.OrdinalIgnoreCase);
        foreach (var policy in current)
            currentByName[policy.Name] = policy;

        var remove = new List<string>();
        foreach (var policy in currentByName.Values)
        {
            if (!desiredByName.TryGetValue(policy.Name, out var want) || !Same(policy, want))
                remove.Add(policy.Name);
        }

        var add = new List<QosPolicySpec>();
        foreach (var want in desired)
        {
            if (!currentByName.TryGetValue(want.Name, out var have) || !Same(have, want))
                add.Add(want);
        }

        return (remove, add);
    }

    private static bool Same(ActiveQosPolicy have, QosPolicySpec want)
    {
        if (!string.Equals(have.AppPath?.Trim(), want.AppPath.Trim(), StringComparison.OrdinalIgnoreCase))
            return false;
        if ((have.Dscp ?? -1) != want.Dscp)
            return false;
        return (have.ThrottleBitsPerSecond ?? 0) == (want.ThrottleBitsPerSecond ?? 0);
    }
}

public static class NetQosScript
{
    private static readonly Regex SafeName = new(@"^RedFilter-[A-Za-z0-9-]+$", RegexOptions.CultureInvariant);

    public static string Query() =>
        """
        $ErrorActionPreference = 'Stop'
        Import-Module NetQos -ErrorAction Stop
        $rows = @(Get-NetQosPolicy -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Where-Object { $_.Name -like 'RedFilter-*' })
        if ($rows.Count -eq 0) { Write-Output '[]'; return }
        $rows | ForEach-Object {
          [PSCustomObject]@{
            Name = [string]$_.Name
            AppPathNameMatchCondition = [string]$_.AppPathNameMatchCondition
            ThrottleRateActionBitsPerSecond = $_.ThrottleRateActionBitsPerSecond
            DSCPAction = $_.DSCPAction
          }
        } | ConvertTo-Json -Compress
        """;

    public static string RemoveAll() =>
        """
        $ErrorActionPreference = 'Stop'
        Import-Module NetQos -ErrorAction Stop
        $rows = @(Get-NetQosPolicy -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Where-Object { $_.Name -like 'RedFilter-*' })
        foreach ($row in $rows) {
          Remove-NetQosPolicy -Name $row.Name -PolicyStore ActiveStore -Confirm:$false
        }
        Write-Output ('OK removed=' + $rows.Count)
        """;

    public static string Apply(IReadOnlyList<string> remove, IReadOnlyList<QosPolicySpec> add)
    {
        var builder = new StringBuilder();
        builder.AppendLine("$ErrorActionPreference = 'Stop'");
        builder.AppendLine("Import-Module NetQos -ErrorAction Stop");
        builder.AppendLine("$removed = 0");
        builder.AppendLine("$applied = 0");
        if (remove.Count > 0)
        {
            builder.AppendLine("$removeNames = @(");
            foreach (var name in remove)
                builder.AppendLine($"  '{RequireName(name)}'");
            builder.AppendLine(")");
            builder.AppendLine("Get-NetQosPolicy -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Where-Object { $removeNames -contains $_.Name } | ForEach-Object {");
            builder.AppendLine("  Remove-NetQosPolicy -Name $_.Name -PolicyStore ActiveStore -Confirm:$false");
            builder.AppendLine("  $removed++");
            builder.AppendLine("}");
        }

        foreach (var policy in add)
        {
            var name = RequireName(policy.Name);
            var path = EscapeLiteral(policy.AppPath);
            if (policy.IsOwner)
            {
                builder.AppendLine(
                    $"New-NetQosPolicy -Name '{name}' -AppPathNameMatchCondition '{path}' -DSCPAction {policy.Dscp} -Precedence 10 -NetworkProfile All -PolicyStore ActiveStore -Confirm:$false | Out-Null");
            }
            else
            {
                var rate = policy.ThrottleBitsPerSecond ?? throw new InvalidOperationException("A limit policy needs a throttle rate.");
                if (rate < QosPolicyPlanner.MinimumThrottleBits)
                    throw new InvalidOperationException("Refusing to build a QoS policy that would block outbound traffic completely.");
                builder.AppendLine(
                    $"New-NetQosPolicy -Name '{name}' -AppPathNameMatchCondition '{path}' -ThrottleRateActionBitsPerSecond {rate} -DSCPAction {policy.Dscp} -Precedence 40 -NetworkProfile All -PolicyStore ActiveStore -Confirm:$false | Out-Null");
            }

            builder.AppendLine("$applied++");
        }

        builder.AppendLine("Write-Output ('OK removed=' + $removed + ' applied=' + $applied)");
        return builder.ToString();
    }

    public static string RequireName(string name)
    {
        if (!SafeName.IsMatch(name))
            throw new InvalidOperationException("Refusing to build a QoS script for an unexpected policy name.");
        return name;
    }

    public static string EscapeLiteral(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
            throw new InvalidOperationException("A QoS policy needs a program path.");
        foreach (var ch in value)
        {
            if (ch < ' ' || ch == '`')
                throw new InvalidOperationException("The program path contains characters that cannot be placed in a QoS policy.");
        }

        return value.Replace("'", "''", StringComparison.Ordinal);
    }
}

public static class NetQosPolicyParser
{
    public static IReadOnlyList<ActiveQosPolicy> Parse(string output)
    {
        var json = ExtractJson(output);
        if (json == "[]")
            return Array.Empty<ActiveQosPolicy>();

        using var document = System.Text.Json.JsonDocument.Parse(json);
        var root = document.RootElement;
        if (root.ValueKind == System.Text.Json.JsonValueKind.Array)
        {
            var list = new List<ActiveQosPolicy>();
            foreach (var item in root.EnumerateArray())
                list.Add(Read(item));
            return list;
        }

        if (root.ValueKind == System.Text.Json.JsonValueKind.Object)
            return new[] { Read(root) };

        throw new InvalidOperationException("Windows QoS returned an unexpected policy list.");
    }

    private static ActiveQosPolicy Read(System.Text.Json.JsonElement item)
    {
        var name = item.TryGetProperty("Name", out var nameElement) ? nameElement.GetString() : null;
        if (string.IsNullOrWhiteSpace(name))
            throw new InvalidOperationException("Windows QoS returned a policy without a name.");
        return new ActiveQosPolicy(
            name,
            item.TryGetProperty("AppPathNameMatchCondition", out var path) ? path.GetString() : null,
            ReadInt64(item, "ThrottleRateActionBitsPerSecond"),
            ReadInt32(item, "DSCPAction"));
    }

    private static long? ReadInt64(System.Text.Json.JsonElement item, string name)
    {
        if (!item.TryGetProperty(name, out var value) || value.ValueKind == System.Text.Json.JsonValueKind.Null)
            return null;
        if (value.ValueKind == System.Text.Json.JsonValueKind.Number && value.TryGetInt64(out var number))
            return number;
        if (value.ValueKind == System.Text.Json.JsonValueKind.String && long.TryParse(value.GetString(), out var parsed))
            return parsed;
        return null;
    }

    private static int? ReadInt32(System.Text.Json.JsonElement item, string name)
    {
        var wide = ReadInt64(item, name);
        if (wide is null || wide > int.MaxValue || wide < int.MinValue)
            return wide is null ? null : (int)wide.Value;
        return (int)wide.Value;
    }

    private static string ExtractJson(string output)
    {
        if (string.IsNullOrWhiteSpace(output))
            throw new InvalidOperationException("Windows QoS did not return a policy list.");
        var lines = output.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        for (var i = lines.Length - 1; i >= 0; i--)
        {
            if (lines[i].StartsWith('[') || lines[i].StartsWith('{'))
                return lines[i];
        }

        var excerpt = output.Trim();
        if (excerpt.Length > 400)
            excerpt = excerpt[..400];
        throw new InvalidOperationException("Windows QoS returned an unexpected response. " + excerpt);
    }
}
