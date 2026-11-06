using RedFilter.Core.Processes;
using RedFilter.Core.Router;
using RedFilter.Core.Text;

namespace RedFilter.ViewModels;

public sealed class ThrottleChoice
{
    public required string Label { get; init; }
    public long BitsPerSecond { get; init; }
}

public sealed class BrandChoice
{
    public required string Id { get; init; }
    public required string Label { get; init; }
}

public sealed class ProcessRowViewModel : ObservableObject
{
    private string _name = "";
    private string _path = "";
    private string _download = "—";
    private string _upload = "—";
    private int _connections;
    private double _downloadBps;
    private double _uploadBps;
    private bool _isOwner;
    private ProcessNetworkRow _source = new(0, "", null, 0, 0, 0, 0);

    public ProcessRowViewModel(ProcessNetworkRow source, bool isOwner)
    {
        Pid = source.Pid;
        Update(source, isOwner);
    }

    public int Pid { get; }
    public string Name { get => _name; private set => Set(ref _name, value); }
    public string Path { get => _path; private set => Set(ref _path, value); }
    public string Download { get => _download; private set => Set(ref _download, value); }
    public string Upload { get => _upload; private set => Set(ref _upload, value); }
    public int Connections { get => _connections; private set => Set(ref _connections, value); }
    public double DownloadBps { get => _downloadBps; private set => Set(ref _downloadBps, value); }
    public double UploadBps { get => _uploadBps; private set => Set(ref _uploadBps, value); }
    public bool IsOwner
    {
        get => _isOwner;
        private set
        {
            if (Set(ref _isOwner, value))
                Raise(nameof(OwnerLabel));
        }
    }

    public string OwnerLabel => IsOwner ? "Yes" : "";
    public ProcessNetworkRow Source => _source;

    public void Update(ProcessNetworkRow source, bool isOwner)
    {
        _source = source;
        Name = source.Name;
        Path = source.ExecutablePath ?? "";
        DownloadBps = source.DownloadBytesPerSecond;
        UploadBps = source.UploadBytesPerSecond;
        Download = RateText.BytesPerSecond(source.DownloadBytesPerSecond);
        Upload = RateText.BytesPerSecond(source.UploadBytesPerSecond);
        Connections = source.TcpConnections + source.UdpEndpoints;
        IsOwner = isOwner;
    }
}

public sealed class ProgramRow
{
    public int Pid { get; init; }
    public required string Name { get; init; }
    public required string Path { get; init; }
    public double BytesPerSecond { get; init; }
    public int Connections { get; init; }
    public bool IsOwner { get; init; }
    public bool Protected { get; init; }

    public string Rate => BytesPerSecond > 0 ? RateText.BytesPerSecond(BytesPerSecond) : $"{Connections} conexi{(Connections == 1 ? "ón" : "ones")}";
    public bool CanPrioritize => !IsOwner;
}

public sealed class ClientRowViewModel
{
    public required string Name { get; init; }
    public required string Mac { get; init; }
    public required string Ip { get; init; }
    public required string Connection { get; init; }
    public required string Usage { get; init; }
    public required string Rank { get; init; }
    public required long Score { get; init; }
    public required RouterClient Source { get; init; }
}
