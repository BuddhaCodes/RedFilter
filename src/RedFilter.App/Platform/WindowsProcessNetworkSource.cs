using System.Diagnostics;
using System.IO;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;
using RedFilter.Core.Processes;

namespace RedFilter.Platform;

public sealed class WindowsProcessNetworkSource : IProcessNetworkSource
{
    private const int AfInet = 2;
    private const int AfInet6 = 23;
    private const int TcpTableOwnerPidAll = 5;
    private const int UdpTableOwnerPid = 1;
    private const int ErrorInsufficientBuffer = 122;
    private const int TcpEstablished = 5;
    private const int EstatsData = 1;
    private const uint ProcessQueryLimitedInformation = 0x1000;

    private const uint ErrorAccessDenied = 5;

    private readonly object _gate = new();
    private readonly object _pathGate = new();
    private readonly bool _canEnableEstats;
    private readonly Dictionary<int, string?> _paths = new();
    // Counters and the "statistics already enabled" set are rebuilt from the live connection table on
    // every sample, so closed connections drop out instead of piling up for the life of the app.
    private Dictionary<string, ulong> _lastIn = new(StringComparer.Ordinal);
    private Dictionary<string, ulong> _lastOut = new(StringComparer.Ordinal);
    private HashSet<string> _estatsEnabled = new(StringComparer.Ordinal);
    private Dictionary<string, ulong> _nextIn = new(StringComparer.Ordinal);
    private Dictionary<string, ulong> _nextOut = new(StringComparer.Ordinal);
    private HashSet<string> _nextEnabled = new(StringComparer.Ordinal);
    private DateTime _lastSampleUtc = DateTime.MinValue;
    private bool _estatsWorked;
    private bool _estatsDenied;
    private Task<TransportRead>? _transportTask;
    private TransportRead? _completedTransport;

    /// <param name="isElevated">Per-connection TCP statistics can only be switched on by an administrator.
    /// Without elevation RedFilter skips them and lists connection counts only.</param>
    public WindowsProcessNetworkSource(bool isElevated)
    {
        _canEnableEstats = isElevated;
    }

    public ProcessNetworkSnapshot Sample()
    {
        // Programs are listed even when Windows connection statistics are slow.
        // The counter read used to run first and could stall the table forever.
        var rows = CaptureProcesses(out var processWarning);
        var task = StartTransportRead();
        TransportRead? transport = _completedTransport;
        string? warning = processWarning;
        try
        {
            if (task.IsCompleted || task.Wait(TimeSpan.FromSeconds(2)))
                transport = task.Result;
        }
        catch (AggregateException ex)
        {
            warning = Join(warning, "Network counters could not be read: " + ex.GetBaseException().Message);
        }

        if (transport == null)
            warning = Join(warning, "Network counters are taking too long. Programs are listed without live rates.");
        else
        {
            Merge(rows, transport);
            warning = Join(warning, transport.Warning);
        }

        return new ProcessNetworkSnapshot(
            rows.Values.OrderBy(row => row.Name, StringComparer.OrdinalIgnoreCase).ToList(),
            transport?.ThroughputAvailable ?? false,
            warning,
            transport?.CountsAvailable ?? false);
    }

    private Task<TransportRead> StartTransportRead()
    {
        lock (_gate)
        {
            if (_transportTask == null || _transportTask.IsCompleted)
                _transportTask = Task.Run(ReadTransport);
            return _transportTask;
        }
    }

    private TransportRead ReadTransport()
    {
        lock (_gate)
        {
            var now = DateTime.UtcNow;
            var elapsed = (now - _lastSampleUtc).TotalSeconds;
            var first = _lastSampleUtc == DateTime.MinValue;
            _lastSampleUtc = now;
            var tcp = new Dictionary<int, (int count, double down, double up)>();
            var udp = new Dictionary<int, int>();
            string? warning = null;
            var countsAvailable = true;
            _nextIn.Clear();
            _nextOut.Clear();
            _nextEnabled.Clear();
            try
            {
                ReadTcp(AfInet, false, tcp, elapsed, first);
                ReadTcp(AfInet6, true, tcp, elapsed, first);
                ReadUdp(AfInet, false, udp);
                ReadUdp(AfInet6, true, udp);
                if (!_canEnableEstats || _estatsDenied)
                    warning = "Live TCP rates need administrator approval. Connection counts are shown.";
                else if (!_estatsWorked && tcp.Values.Any(item => item.count > 0))
                    warning = "TCP throughput is not available from Windows connection statistics yet. Connection counts are shown.";
            }
            catch (Exception ex)
            {
                warning = "Network counters could not be read: " + ex.Message;
                countsAvailable = false;
            }

            // Swap in the counters for connections that exist right now; the old maps become next round's scratch space.
            (_lastIn, _nextIn) = (_nextIn, _lastIn);
            (_lastOut, _nextOut) = (_nextOut, _lastOut);
            (_estatsEnabled, _nextEnabled) = (_nextEnabled, _estatsEnabled);

            var result = new TransportRead(tcp, udp, warning, _estatsWorked && _canEnableEstats && !_estatsDenied, countsAvailable);
            _completedTransport = result;
            return result;
        }
    }

    private Dictionary<int, ProcessNetworkRow> CaptureProcesses(out string? warning)
    {
        warning = null;
        var rows = new Dictionary<int, ProcessNetworkRow>();
        Process[] processes;
        try
        {
            processes = Process.GetProcesses();
        }
        catch (Exception ex)
        {
            warning = "Running programs could not be listed: " + ex.Message;
            return rows;
        }

        foreach (var process in processes)
        {
            try
            {
                var pid = process.Id;
                var path = PathFor(pid);
                var name = string.IsNullOrWhiteSpace(process.ProcessName)
                    ? (path == null ? "pid " + pid : Path.GetFileNameWithoutExtension(path))
                    : process.ProcessName;
                rows[pid] = new ProcessNetworkRow(pid, name, path, 0, 0, 0, 0);
            }
            catch (Exception)
            {
                // A process can exit between enumeration and the name lookup.
            }
            finally
            {
                process.Dispose();
            }
        }

        lock (_pathGate)
        {
            var stale = _paths.Keys.Where(pid => !rows.ContainsKey(pid)).ToList();
            foreach (var pid in stale)
                _paths.Remove(pid);
        }

        return rows;
    }

    private void Merge(Dictionary<int, ProcessNetworkRow> rows, TransportRead transport)
    {
        foreach (var pair in transport.Tcp)
        {
            transport.Udp.TryGetValue(pair.Key, out var udpCount);
            if (rows.TryGetValue(pair.Key, out var row))
            {
                rows[pair.Key] = row with
                {
                    TcpConnections = pair.Value.count,
                    UdpEndpoints = udpCount,
                    DownloadBytesPerSecond = pair.Value.down,
                    UploadBytesPerSecond = pair.Value.up
                };
            }
            else
            {
                var path = PathFor(pair.Key);
                var name = path == null ? "pid " + pair.Key : Path.GetFileNameWithoutExtension(path);
                rows[pair.Key] = new ProcessNetworkRow(pair.Key, name ?? "pid " + pair.Key, path, pair.Value.count, udpCount, pair.Value.down, pair.Value.up);
            }
        }

        foreach (var pair in transport.Udp)
        {
            if (transport.Tcp.ContainsKey(pair.Key))
                continue;
            if (rows.TryGetValue(pair.Key, out var row))
                rows[pair.Key] = row with { UdpEndpoints = pair.Value };
            else
            {
                var path = PathFor(pair.Key);
                var name = path == null ? "pid " + pair.Key : Path.GetFileNameWithoutExtension(path);
                rows[pair.Key] = new ProcessNetworkRow(pair.Key, name ?? "pid " + pair.Key, path, 0, pair.Value, 0, 0);
            }
        }
    }

    private static string? Join(string? first, string? second)
    {
        if (string.IsNullOrWhiteSpace(first))
            return string.IsNullOrWhiteSpace(second) ? null : second;
        if (string.IsNullOrWhiteSpace(second))
            return first;
        return first + " " + second;
    }

    private sealed record TransportRead(
        Dictionary<int, (int count, double down, double up)> Tcp,
        Dictionary<int, int> Udp,
        string? Warning,
        bool ThroughputAvailable,
        bool CountsAvailable);

    private void ReadTcp(int family, bool ipv6, Dictionary<int, (int count, double down, double up)> totals, double elapsed, bool first)
    {
        var buffer = AllocTable(() =>
        {
            var size = 0;
            return GetExtendedTcpTable(IntPtr.Zero, ref size, false, family, TcpTableOwnerPidAll, 0) == ErrorInsufficientBuffer ? size : 0;
        }, (pointer, size) => GetExtendedTcpTable(pointer, ref size, true, family, TcpTableOwnerPidAll, 0));
        if (buffer == IntPtr.Zero)
            return;

        try
        {
            var count = Marshal.ReadInt32(buffer);
            var rowSize = ipv6 ? Marshal.SizeOf<MibTcp6RowOwnerPid>() : Marshal.SizeOf<MibTcpRowOwnerPid>();
            var offset = 4;
            for (var i = 0; i < count; i++)
            {
                var pointer = buffer + offset;
                offset += rowSize;
                int pid;
                int state;
                ulong bytesIn = 0;
                ulong bytesOut = 0;
                string key;
                if (!ipv6)
                {
                    var row = Marshal.PtrToStructure<MibTcpRowOwnerPid>(pointer);
                    pid = (int)row.OwningPid;
                    state = (int)row.State;
                    key = "4:" + new IPAddress(row.LocalAddr) + ":" + Port(row.LocalPort) + "-" + new IPAddress(row.RemoteAddr) + ":" + Port(row.RemotePort);
                    if (state == TcpEstablished && CanReadStats)
                        ReadV4Stats(key, row, ref bytesIn, ref bytesOut);
                }
                else
                {
                    var row = Marshal.PtrToStructure<MibTcp6RowOwnerPid>(pointer);
                    pid = (int)row.OwningPid;
                    state = (int)row.State;
                    key = "6:" + new IPAddress(row.LocalAddr) + ":" + Port(row.LocalPort) + "-" + new IPAddress(row.RemoteAddr) + ":" + Port(row.RemotePort);
                    if (state == TcpEstablished && CanReadStats)
                        ReadV6Stats(key, row, ref bytesIn, ref bytesOut);
                }

                if (state != TcpEstablished)
                    continue;

                var down = Rate(key, bytesIn, _lastIn, _nextIn, elapsed, first);
                var up = Rate(key, bytesOut, _lastOut, _nextOut, elapsed, first);
                totals.TryGetValue(pid, out var current);
                totals[pid] = (current.count + 1, current.down + down, current.up + up);
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private void ReadUdp(int family, bool ipv6, Dictionary<int, int> totals)
    {
        var buffer = AllocTable(() =>
        {
            var size = 0;
            return GetExtendedUdpTable(IntPtr.Zero, ref size, false, family, UdpTableOwnerPid, 0) == ErrorInsufficientBuffer ? size : 0;
        }, (pointer, size) => GetExtendedUdpTable(pointer, ref size, true, family, UdpTableOwnerPid, 0));
        if (buffer == IntPtr.Zero)
            return;

        try
        {
            var count = Marshal.ReadInt32(buffer);
            var rowSize = ipv6 ? Marshal.SizeOf<MibUdp6RowOwnerPid>() : Marshal.SizeOf<MibUdpRowOwnerPid>();
            var offset = 4;
            for (var i = 0; i < count; i++)
            {
                var pid = ipv6
                    ? (int)Marshal.PtrToStructure<MibUdp6RowOwnerPid>(buffer + offset).OwningPid
                    : (int)Marshal.PtrToStructure<MibUdpRowOwnerPid>(buffer + offset).OwningPid;
                offset += rowSize;
                totals.TryGetValue(pid, out var current);
                totals[pid] = current + 1;
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private bool CanReadStats => _canEnableEstats && !_estatsDenied;

    private void ReadV4Stats(string key, MibTcpRowOwnerPid row, ref ulong bytesIn, ref ulong bytesOut)
    {
        var tcpRow = new MibTcpRow
        {
            State = row.State,
            LocalAddr = row.LocalAddr,
            LocalPort = row.LocalPort,
            RemoteAddr = row.RemoteAddr,
            RemotePort = row.RemotePort
        };
        if (!EnsureEnabled(key, () => EnableStats(ref tcpRow)))
            return;
        if (!TryReadRod(tcpRow, out var rod))
            return;
        bytesIn = rod.DataBytesIn;
        bytesOut = rod.DataBytesOut;
        _estatsWorked = true;
    }

    private void ReadV6Stats(string key, MibTcp6RowOwnerPid row, ref ulong bytesIn, ref ulong bytesOut)
    {
        var tcpRow = new MibTcp6Row
        {
            State = row.State,
            LocalAddr = row.LocalAddr,
            LocalScopeId = row.LocalScopeId,
            LocalPort = row.LocalPort,
            RemoteAddr = row.RemoteAddr,
            RemoteScopeId = row.RemoteScopeId,
            RemotePort = row.RemotePort
        };
        if (!EnsureEnabled(key, () => EnableStats6(ref tcpRow)))
            return;
        if (!TryReadRod6(tcpRow, out var rod))
            return;
        bytesIn = rod.DataBytesIn;
        bytesOut = rod.DataBytesOut;
        _estatsWorked = true;
    }

    // Statistics collection is switched on once per connection, not on every sample.
    private bool EnsureEnabled(string key, Func<uint> enable)
    {
        if (_estatsEnabled.Contains(key))
        {
            _nextEnabled.Add(key);
            return true;
        }

        var result = enable();
        if (result == ErrorAccessDenied)
        {
            _estatsDenied = true;
            return false;
        }

        if (result != 0)
            return false;
        _nextEnabled.Add(key);
        return true;
    }

    private static uint EnableStats(ref MibTcpRow row)
    {
        var enable = new byte[] { 1 };
        var pin = GCHandle.Alloc(enable, GCHandleType.Pinned);
        try
        {
            return SetPerTcpConnectionEStats(ref row, EstatsData, pin.AddrOfPinnedObject(), 0, 1, 0);
        }
        finally
        {
            pin.Free();
        }
    }

    private static uint EnableStats6(ref MibTcp6Row row)
    {
        var enable = new byte[] { 1 };
        var pin = GCHandle.Alloc(enable, GCHandleType.Pinned);
        try
        {
            return SetPerTcp6ConnectionEStats(ref row, EstatsData, pin.AddrOfPinnedObject(), 0, 1, 0);
        }
        finally
        {
            pin.Free();
        }
    }

    private static bool TryReadRod(MibTcpRow row, out TcpEstatsDataRod rod)
    {
        rod = default;
        var size = Marshal.SizeOf<TcpEstatsDataRod>();
        var memory = Marshal.AllocHGlobal(size);
        try
        {
            var result = GetPerTcpConnectionEStats(ref row, EstatsData, IntPtr.Zero, 0, 0, IntPtr.Zero, 0, 0, memory, 0, (uint)size);
            if (result != 0)
                return false;
            rod = Marshal.PtrToStructure<TcpEstatsDataRod>(memory);
            return true;
        }
        finally
        {
            Marshal.FreeHGlobal(memory);
        }
    }

    private static bool TryReadRod6(MibTcp6Row row, out TcpEstatsDataRod rod)
    {
        rod = default;
        var size = Marshal.SizeOf<TcpEstatsDataRod>();
        var memory = Marshal.AllocHGlobal(size);
        try
        {
            var result = GetPerTcp6ConnectionEStats(ref row, EstatsData, IntPtr.Zero, 0, 0, IntPtr.Zero, 0, 0, memory, 0, (uint)size);
            if (result != 0)
                return false;
            rod = Marshal.PtrToStructure<TcpEstatsDataRod>(memory);
            return true;
        }
        finally
        {
            Marshal.FreeHGlobal(memory);
        }
    }

    private static double Rate(string key, ulong current, Dictionary<string, ulong> previous, Dictionary<string, ulong> next, double elapsed, bool first)
    {
        next[key] = current;
        if (!previous.TryGetValue(key, out var last))
            return 0;
        if (first || elapsed < 0.2 || current < last)
            return 0;
        return (current - last) / elapsed;
    }

    private string? PathFor(int pid)
    {
        lock (_pathGate)
        {
            if (pid <= 4)
                return null;
            if (_paths.TryGetValue(pid, out var cached))
                return cached;

            string? path = null;
            var handle = OpenProcess(ProcessQueryLimitedInformation, false, (uint)pid);
            if (handle != IntPtr.Zero)
            {
                try
                {
                    var capacity = 1024;
                    var builder = new StringBuilder(capacity);
                    if (QueryFullProcessImageName(handle, 0, builder, ref capacity))
                        path = builder.ToString();
                }
                finally
                {
                    CloseHandle(handle);
                }
            }

            _paths[pid] = path;
            return path;
        }
    }

    private static IntPtr AllocTable(Func<int> probe, Func<IntPtr, int, uint> fill)
    {
        var size = probe();
        if (size <= 0)
            return IntPtr.Zero;
        var buffer = Marshal.AllocHGlobal(size);
        var result = fill(buffer, size);
        if (result == 0)
            return buffer;
        Marshal.FreeHGlobal(buffer);
        return IntPtr.Zero;
    }

    private static int Port(uint raw) => ((int)(raw & 0xFF) << 8) + (int)((raw >> 8) & 0xFF);

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(IntPtr table, ref int size, bool order, int family, int tableClass, uint reserved);

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedUdpTable(IntPtr table, ref int size, bool order, int family, int tableClass, uint reserved);

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint SetPerTcpConnectionEStats(ref MibTcpRow row, int estatsType, IntPtr rw, uint rwVersion, uint rwSize, uint offset);

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetPerTcpConnectionEStats(ref MibTcpRow row, int estatsType, IntPtr rw, uint rwVersion, uint rwSize, IntPtr ros, uint rosVersion, uint rosSize, IntPtr rod, uint rodVersion, uint rodSize);

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint SetPerTcp6ConnectionEStats(ref MibTcp6Row row, int estatsType, IntPtr rw, uint rwVersion, uint rwSize, uint offset);

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetPerTcp6ConnectionEStats(ref MibTcp6Row row, int estatsType, IntPtr rw, uint rwVersion, uint rwSize, IntPtr ros, uint rosVersion, uint rosSize, IntPtr rod, uint rodVersion, uint rodSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint access, bool inherit, uint pid);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool QueryFullProcessImageName(IntPtr process, int flags, StringBuilder name, ref int size);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);

    [StructLayout(LayoutKind.Sequential)]
    private struct MibTcpRowOwnerPid
    {
        public uint State;
        public uint LocalAddr;
        public uint LocalPort;
        public uint RemoteAddr;
        public uint RemotePort;
        public uint OwningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MibTcpRow
    {
        public uint State;
        public uint LocalAddr;
        public uint LocalPort;
        public uint RemoteAddr;
        public uint RemotePort;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MibTcp6RowOwnerPid
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] LocalAddr;
        public uint LocalScopeId;
        public uint LocalPort;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] RemoteAddr;
        public uint RemoteScopeId;
        public uint RemotePort;
        public uint State;
        public uint OwningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MibTcp6Row
    {
        public uint State;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] LocalAddr;
        public uint LocalScopeId;
        public uint LocalPort;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] RemoteAddr;
        public uint RemoteScopeId;
        public uint RemotePort;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MibUdpRowOwnerPid
    {
        public uint LocalAddr;
        public uint LocalPort;
        public uint OwningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MibUdp6RowOwnerPid
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] LocalAddr;
        public uint LocalScopeId;
        public uint LocalPort;
        public uint OwningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct TcpEstatsDataRod
    {
        public ulong DataBytesOut;
        public ulong DataSegsOut;
        public ulong DataBytesIn;
        public ulong DataSegsIn;
        public ulong SegsOut;
        public ulong SegsIn;
        public uint SoftErrors;
        public uint SoftErrorReason;
        public uint SndUna;
        public uint SndNxt;
        public uint SndMax;
        public ulong ThruBytesAcked;
        public uint RcvNxt;
        public ulong ThruBytesReceived;
    }
}
