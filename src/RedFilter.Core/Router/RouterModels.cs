namespace RedFilter.Core.Router;

public enum RouterUsageKind
{
    None,
    TransferredBytes,
    ReportedRate,
    LinkSpeed
}

public sealed record RouterCapabilities(
    bool ListClients,
    bool Disconnect,
    bool Block,
    bool Unblock,
    bool AllowReconnect,
    bool SetPriority,
    bool Wake,
    string Limitations)
{
    public static RouterCapabilities None { get; } = new(false, false, false, false, false, false, false, "");
}

public sealed record RouterClient(
    string Mac,
    string? Name,
    string? IpAddress,
    bool IsWireless,
    bool IsBanned,
    string ConnectionLabel,
    long? RxBytes,
    long? TxBytes,
    string? ReportedRate,
    int? LinkSpeedMbps,
    bool? HasPriority);

public sealed record RouterClientList(
    IReadOnlyList<RouterClient> Clients,
    RouterUsageKind UsageKind,
    string Note);

public sealed record RouterActionResult(bool Success, string Message);

public interface IRouterSession
{
    string Brand { get; }
    string? Model { get; }
    string? Firmware { get; }
    RouterCapabilities Capabilities { get; }
    Task<RouterClientList> GetClientsAsync(CancellationToken cancellationToken);
    Task<RouterActionResult> DisconnectAsync(string mac, CancellationToken cancellationToken);
    Task<RouterActionResult> BlockAsync(string mac, CancellationToken cancellationToken);
    Task<RouterActionResult> UnblockAsync(string mac, CancellationToken cancellationToken);
    Task<RouterActionResult> SetPriorityAsync(RouterClient client, bool priority, CancellationToken cancellationToken);
    Task<RouterActionResult> WakeAsync(string mac, CancellationToken cancellationToken);
}

public sealed class RouterInspection
{
    public bool Success { get; init; }
    public string Status { get; init; } = "";
    public string? Brand { get; init; }
    public string? Model { get; init; }
    public string? Firmware { get; init; }
    public RouterCapabilities Capabilities { get; init; } = RouterCapabilities.None;
    public IReadOnlyList<RouterClient> Clients { get; init; } = Array.Empty<RouterClient>();
    public RouterUsageKind UsageKind { get; init; }
    public bool UsedUntrustedCertificate { get; init; }

    public static RouterInspection Failed(string status) => new() { Success = false, Status = status };
}

public sealed class RouterException : Exception
{
    public RouterException(string message) : base(message)
    {
    }

    public RouterException(string message, Exception inner) : base(message, inner)
    {
    }
}

public static class SecretText
{
    public static string Scrub(string? text, string? secret)
    {
        if (string.IsNullOrEmpty(text))
            return "";
        var cleaned = text;
        if (!string.IsNullOrEmpty(secret) && secret.Length >= 3)
            cleaned = cleaned.Replace(secret, "(hidden)", StringComparison.Ordinal);
        cleaned = System.Text.RegularExpressions.Regex.Replace(
            cleaned,
            "(?i)(token|password|sid|response|login_authorization)=[^&\\s\"']+",
            "$1=(hidden)");
        return cleaned;
    }

    public static string Excerpt(string? text, string? secret)
    {
        var cleaned = Scrub(text, secret).Replace('\r', ' ').Replace('\n', ' ').Trim();
        if (cleaned.Length > 180)
            cleaned = cleaned[..180] + "...";
        return cleaned;
    }
}
