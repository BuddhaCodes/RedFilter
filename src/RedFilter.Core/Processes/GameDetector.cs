namespace RedFilter.Core.Processes;

/// <summary>Finds Dota 2 among the running processes (dota2.exe under "dota 2 beta\game\bin\win64").</summary>
public static class GameDetector
{
    public const string DotaName = "dota2";

    public static ProcessNetworkRow? FindDota(IEnumerable<ProcessNetworkRow> processes) =>
        processes
            .Where(IsDota)
            .OrderByDescending(process => !string.IsNullOrWhiteSpace(process.ExecutablePath))
            .ThenByDescending(process => process.TcpConnections + process.UdpEndpoints)
            .FirstOrDefault();

    public static bool IsDota(ProcessNetworkRow process)
    {
        var name = process.Name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ? process.Name[..^4] : process.Name;
        if (name.Equals(DotaName, StringComparison.OrdinalIgnoreCase))
            return true;
        var file = string.IsNullOrWhiteSpace(process.ExecutablePath) ? null : Path.GetFileNameWithoutExtension(process.ExecutablePath);
        return file != null && file.Equals(DotaName, StringComparison.OrdinalIgnoreCase);
    }
}
