namespace RedFilter.Core.Processes;

public sealed record ProcessNetworkRow(
    int Pid,
    string Name,
    string? ExecutablePath,
    int TcpConnections,
    int UdpEndpoints,
    double DownloadBytesPerSecond,
    double UploadBytesPerSecond);

public sealed record ProcessNetworkSnapshot(
    IReadOnlyList<ProcessNetworkRow> Processes,
    bool ThroughputAvailable,
    string? Warning,
    bool ConnectionsAvailable = false);

public interface IProcessNetworkSource
{
    ProcessNetworkSnapshot Sample();
}
