using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
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
        "dasHost", "RedFilter", "powershell", "pwsh", "smartscreen"
    };

    public static long NormalizeThrottle(long bitsPerSecond)
    {
        if (bitsPerSecond < MinimumThrottleBits)
            return MinimumThrottleBits;
        if (bitsPerSecond > MaximumThrottleBits)
            return MaximumThrottleBits;
        return bitsPerSecond;
    }

    /// <param name="keepLimited">Program paths already limited in this filter session. They stay limited
    /// even when they are idle or not running, so the policy set only grows and Windows QoS is not
    /// rewritten every time a short-lived program exits.</param>
    /// <param name="requireActivity">When connection counts are available, only programs with TCP connections
    /// or UDP endpoints get a new limit. Without counts every program with a path is limited.</param>
    public static QosPlan Build(
        ProcessNetworkRow owner,
        IReadOnlyList<ProcessNetworkRow> processes,
        long throttleBitsPerSecond,
        string? thisProgramPath,
        IReadOnlyCollection<string>? keepLimited = null,
        bool requireActivity = false)
    {
        if (string.IsNullOrWhiteSpace(owner.ExecutablePath))
        {
            throw new InvalidOperationException(
                $"Windows no deja ver la ruta de {owner.Name} (PID {owner.Pid}), y la prioridad se aplica por ruta. " +
                "Elige otro programa, o abre RedFilter como administrador.");
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
        var sticky = new HashSet<string>(
            (keepLimited ?? Array.Empty<string>()).Where(path => !string.IsNullOrWhiteSpace(path)).Select(path => path.Trim()),
            StringComparer.OrdinalIgnoreCase);

        var skippedSystem = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var missingPath = 0;
        var serviceHostActive = false;

        foreach (var process in processes.OrderBy(p => p.ExecutablePath, StringComparer.OrdinalIgnoreCase))
        {
            if (process.Pid == owner.Pid)
                continue;
            var active = process.TcpConnections + process.UdpEndpoints > 0;
            if (IsProtected(process))
            {
                if (active)
                {
                    skippedSystem.Add(process.Name);
                    if (process.Name.Equals("svchost", StringComparison.OrdinalIgnoreCase))
                        serviceHostActive = true;
                }

                continue;
            }

            if (string.IsNullOrWhiteSpace(process.ExecutablePath))
            {
                if (active)
                    missingPath++;
                continue;
            }

            var path = process.ExecutablePath.Trim();
            if (requireActivity && !active && !sticky.Contains(path))
                continue;
            if (!seenPaths.Add(path))
                continue;

            policies.Add(new QosPolicySpec(LimitName(path), path, false, BackgroundDscp, throttle));
        }

        // Keep earlier limits for programs that went idle or exited.
        foreach (var path in sticky.OrderBy(p => p, StringComparer.OrdinalIgnoreCase))
        {
            if (!seenPaths.Add(path))
                continue;
            if (NeverThrottle.Contains(FileStem(path)))
                continue;
            policies.Add(new QosPolicySpec(LimitName(path), path, false, BackgroundDscp, throttle));
        }

        var notes = new List<string>
        {
            $"Prioridad para {Path.GetFileName(ownerPath)} (todas sus ventanas y procesos).",
            $"Los demás programas quedan limitados a {RateText.BitsPerSecond(throttle)} de subida. Las descargas no se limitan.",
            "La marca de prioridad (DSCP " + OwnerDscp + ") solo ayuda si el router la respeta.",
            "Sigue activo aunque cierres RedFilter; se borra al reiniciar Windows o con \"Quitar prioridad\".",
            "Con RedFilter abierto, los programas que empiecen a usar la red también se limitan solos; con RedFilter cerrado, no."
        };

        if (IsProtected(owner))
            notes.Add($"{owner.Name} es un componente de Windows; se le da prioridad, pero el resto del sistema no se limita.");

        if (skippedSystem.Count > 0)
        {
            var names = string.Join(", ", skippedSystem.OrderBy(n => n, StringComparer.OrdinalIgnoreCase));
            notes.Add("No se limitan, para que Windows siga funcionando: " + names + ".");
        }

        if (serviceHostActive)
        {
            notes.Add(
                "Windows Update y la Optimización de distribución (Delivery Optimization) van dentro de svchost y no se pueden limitar desde aquí. " +
                "Para frenarlas: Configuración > Windows Update > Opciones avanzadas > Optimización de distribución.");
        }

        if (missingPath > 0)
            notes.Add($"{missingPath} proceso{(missingPath == 1 ? "" : "s")} con red sin ruta legible se dejaron igual.");

        var limited = policies.Count - 1;
        notes.Insert(1, limited == 0
            ? "Ningún otro programa usa la red ahora; solo se aplicó la prioridad."
            : $"{limited} programa{(limited == 1 ? "" : "s")} más quedan limitados.");

        return new QosPlan(owner.Name, owner.Pid, ownerPath, throttle, policies, notes);
    }

    /// <summary>A stable fingerprint of the policies, so callers can skip PowerShell when nothing changed.</summary>
    public static string Fingerprint(IReadOnlyList<QosPolicySpec> policies) =>
        string.Join("\n", policies
            .OrderBy(policy => policy.Name, StringComparer.Ordinal)
            .Select(policy => $"{policy.Name}|{policy.AppPath.ToUpperInvariant()}|{policy.Dscp}|{policy.ThrottleBitsPerSecond}"));

    public static bool IsProtected(ProcessNetworkRow process)
    {
        if (NeverThrottle.Contains(process.Name))
            return true;
        if (string.IsNullOrWhiteSpace(process.ExecutablePath))
            return false;
        return NeverThrottle.Contains(FileStem(process.ExecutablePath));
    }

    // Windows paths are parsed the same way on every OS, so planning does not depend on where it runs.
    private static string FileStem(string path)
    {
        var file = path[(path.LastIndexOfAny(['\\', '/']) + 1)..];
        var dot = file.LastIndexOf('.');
        return dot > 0 ? file[..dot] : file;
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

    private static readonly JsonSerializerOptions PayloadOptions = new()
    {
        // The default encoder escapes every non-ASCII character (including the typographic quotes
        // PowerShell treats as string delimiters), so the payload is plain ASCII on stdin.
        Encoder = System.Text.Encodings.Web.JavaScriptEncoder.Default
    };

    // The script text never contains a program path or a policy name. Those arrive as JSON on stdin,
    // so a crafted path cannot change what the elevated PowerShell runs.
    public const string Script =
        """
        $ErrorActionPreference = 'Stop'
        try {
          Import-Module NetQos -ErrorAction Stop
          $request = [Console]::In.ReadToEnd() | ConvertFrom-Json
          function Get-RedFilterPolicy {
            @(Get-NetQosPolicy -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Where-Object { $_.Name -like 'RedFilter-*' })
          }
          function Write-AsciiJson($value) {
            $json = ConvertTo-Json -InputObject $value -Compress -Depth 4
            [regex]::Replace($json, '[^\u0000-\u007F]', { param($m) '\u{0:x4}' -f [int][char]$m.Value })
          }
          switch ([string]$request.op) {
            'query' {
              $rows = @(Get-RedFilterPolicy | ForEach-Object {
                [PSCustomObject]@{
                  Name = [string]$_.Name
                  AppPathNameMatchCondition = [string]$_.AppPathNameMatchCondition
                  ThrottleRateActionBitsPerSecond = $_.ThrottleRateActionBitsPerSecond
                  DSCPAction = $_.DSCPAction
                }
              })
              Write-AsciiJson -value $rows
            }
            'clear' {
              $rows = Get-RedFilterPolicy
              foreach ($row in $rows) {
                Remove-NetQosPolicy -Name $row.Name -PolicyStore ActiveStore -Confirm:$false
              }
              Write-Output ('OK removed=' + $rows.Count)
            }
            'apply' {
              $removed = 0
              $applied = 0
              $removeNames = @($request.remove | Where-Object { $_ } | ForEach-Object { [string]$_ })
              if ($removeNames.Count -gt 0) {
                foreach ($row in (Get-RedFilterPolicy | Where-Object { $removeNames -contains $_.Name })) {
                  Remove-NetQosPolicy -Name $row.Name -PolicyStore ActiveStore -Confirm:$false
                  $removed++
                }
              }
              foreach ($policy in @($request.add)) {
                if ($null -eq $policy) { continue }
                $name = [string]$policy.name
                if ($name -cnotmatch '^RedFilter-[A-Za-z0-9-]+$') { throw 'Refusing an unexpected QoS policy name.' }
                $settings = @{
                  Name = $name
                  AppPathNameMatchCondition = [string]$policy.path
                  DSCPAction = [sbyte]$policy.dscp
                  NetworkProfile = 'All'
                  PolicyStore = 'ActiveStore'
                  Confirm = $false
                }
                if ($policy.owner) {
                  $settings.Precedence = [byte]10
                } else {
                  $rate = [uint64]$policy.rate
                  if ($rate -lt 64000) { throw 'Refusing a QoS limit that would block outbound traffic.' }
                  $settings.Precedence = [byte]40
                  $settings.ThrottleRateActionBitsPerSecond = $rate
                }
                New-NetQosPolicy @settings | Out-Null
                $applied++
              }
              Write-Output ('OK removed=' + $removed + ' applied=' + $applied)
            }
            default { throw 'Unknown RedFilter QoS request.' }
          }
        } catch {
          # Plain text on stderr; -EncodedCommand would otherwise serialize the error as CLIXML.
          [Console]::Error.WriteLine($_.Exception.Message)
          exit 1
        }
        """;

    public static string EncodedScript { get; } = Convert.ToBase64String(Encoding.Unicode.GetBytes(Script));

    public static string QueryPayload() => JsonSerializer.Serialize(new { op = "query" }, PayloadOptions);

    public static string ClearPayload() => JsonSerializer.Serialize(new { op = "clear" }, PayloadOptions);

    public static string ApplyPayload(IReadOnlyList<string> remove, IReadOnlyList<QosPolicySpec> add)
    {
        var removeNames = remove.Select(RequireName).ToArray();
        var policies = add.Select(policy =>
        {
            var name = RequireName(policy.Name);
            var path = RequirePath(policy.AppPath);
            if (policy.Dscp is < 0 or > 63)
                throw new InvalidOperationException("A DSCP value must be between 0 and 63.");
            long? rate = null;
            if (!policy.IsOwner)
            {
                rate = policy.ThrottleBitsPerSecond ?? throw new InvalidOperationException("A limit policy needs a throttle rate.");
                if (rate < QosPolicyPlanner.MinimumThrottleBits)
                    throw new InvalidOperationException("Refusing to build a QoS policy that would block outbound traffic completely.");
            }

            return new { name, path, owner = policy.IsOwner, dscp = policy.Dscp, rate };
        }).ToArray();
        return JsonSerializer.Serialize(new { op = "apply", remove = removeNames, add = policies }, PayloadOptions);
    }

    public static string RequireName(string name)
    {
        if (!SafeName.IsMatch(name))
            throw new InvalidOperationException("Refusing to build a QoS request for an unexpected policy name.");
        return name;
    }

    public static string RequirePath(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
            throw new InvalidOperationException("A QoS policy needs a program path.");
        if (value.Length > 32_767 || value.Any(char.IsControl))
            throw new InvalidOperationException("The program path contains characters that cannot be placed in a QoS policy.");
        return value;
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
            return null;
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
