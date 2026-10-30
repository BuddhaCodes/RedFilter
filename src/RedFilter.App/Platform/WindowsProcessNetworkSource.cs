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

    private readonly object _gate = new();
    private readonly Dictionary<string, ulong> _lastIn = new(StringComparer.Ordinal);
    private readonly Dictionary<string, ulong> _lastOut = new(StringComparer.Ordinal);
    private readonly Dictionary<int, string?> _paths = new();
    private DateTime _lastSampleUtc = DateTime.MinValue;
    private bool _estatsWorked;

    public ProcessNetworkSnapshot Sample()
    {
        lock (_gate)
            return SampleCore();
    }

    private ProcessNetworkSnapshot SampleCore()
    {
        var now = DateTime.UtcNow;
        var elapsed = (now - _lastSampleUtc).TotalSeconds;
        var first = _lastSampleUtc == DateTime.MinValue;
        _lastSampleUtc = now;

        var tcp = new Dictionary<int, (int count, double down, double up)>();
        var udp = new Dictionary<int, int>();
        var warning = (string?)null;

        try
        {
            ReadTcp(AfInet, false, tcp, elapsed, first);
            ReadTcp(AfInet6, true, tcp, elapsed, first);
            ReadUdp(AfInet, false, udp);
            ReadUdp(AfInet6, true, udp);
        }
        catch (Exception ex)
        {
            warning = "Network counters could not be read: " + ex.Message;
        }

        var rows = new Dictionary<int, ProcessNetworkRow>();
        foreach (var process in Process.GetProcesses())
        {
            try
            {
                var pid = process.Id;
                var path = PathFor(pid);
                var name = string.IsNullOrWhiteSpace(process.ProcessName)
                    ? (path == null ? "pid " + pid : Path.GetFileNameWithoutExtension(path))
                    : process.ProcessName;
                tcp.TryGetValue(pid, out var network);
                udp.TryGetValue(pid, out var udpCount);
                rows[pid] = new ProcessNetworkRow(pid, name, path, network.count, udpCount, network.down, network.up);
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

        foreach (var pair in tcp)
        {
            if (rows.ContainsKey(pair.Key))
                continue;
            udp.TryGetValue(pair.Key, out var udpCount);
            var path = PathFor(pair.Key);
            var name = path == null ? "pid " + pair.Key : Path.GetFileNameWithoutExtension(path);
            rows[pair.Key] = new ProcessNetworkRow(pair.Key, name, path, pair.Value.count, udpCount, pair.Value.down, pair.Value.up);
        }

        if (!_estatsWorked && tcp.Values.Any(item => item.count > 0))
            warning ??= "TCP throughput is not available from Windows connection statistics yet. Connection counts are shown.";

        var stale = _paths.Keys.Where(pid => !rows.ContainsKey(pid)).ToList();
        foreach (var pid in stale)
            _paths.Remove(pid);

        return new ProcessNetworkSnapshot(rows.Values.OrderBy(row => row.Name, StringComparer.OrdinalIgnoreCase).ToList(), _estatsWorked, warning);
    }

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
                    if (state == TcpEstablished)
                        ReadV4Stats(row, ref bytesIn, ref bytesOut);
                }
                else
                {
                    var row = Marshal.PtrToStructure<MibTcp6RowOwnerPid>(pointer);
                    pid = (int)row.OwningPid;
                    state = (int)row.State;
                    key = "6:" + new IPAddress(row.LocalAddr) + ":" + Port(row.LocalPort) + "-" + new IPAddress(row.RemoteAddr) + ":" + Port(row.RemotePort);
                    if (state == TcpEstablished)
                        ReadV6Stats(row, ref bytesIn, ref bytesOut);
                }

                if (state != TcpEstablished)
                    continue;

                var down = Rate(key, bytesIn, _lastIn, elapsed, first);
                var up = Rate(key, bytesOut, _lastOut, elapsed, first);
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

    private void ReadV4Stats(MibTcpRowOwnerPid row, ref ulong bytesIn, ref ulong bytesOut)
    {
        var tcpRow = new MibTcpRow
        {
            State = row.State,
            LocalAddr = row.LocalAddr,
            LocalPort = row.LocalPort,
            RemoteAddr = row.RemoteAddr,
            RemotePort = row.RemotePort
        };
        if (!TryReadRod(tcpRow, out var rod))
            return;
        bytesIn = rod.DataBytesIn;
        bytesOut = rod.DataBytesOut;
        _estatsWorked = true;
    }

    private void ReadV6Stats(MibTcp6RowOwnerPid row, ref ulong bytesIn, ref ulong bytesOut)
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
        if (!TryReadRod6(tcpRow, out var rod))
            return;
        bytesIn = rod.DataBytesIn;
        bytesOut = rod.DataBytesOut;
        _estatsWorked = true;
    }

    private static bool TryReadRod(MibTcpRow row, out TcpEstatsDataRod rod)
    {
        rod = default;
        var enable = new byte[] { 1 };
        var pin = GCHandle.Alloc(enable, GCHandleType.Pinned);
        try
        {
            SetPerTcpConnectionEStats(ref row, EstatsData, pin.AddrOfPinnedObject(), 0, 1, 0);
        }
        finally
        {
            pin.Free();
        }

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
        var enable = new byte[] { 1 };
        var pin = GCHandle.Alloc(enable, GCHandleType.Pinned);
        try
        {
            SetPerTcp6ConnectionEStats(ref row, EstatsData, pin.AddrOfPinnedObject(), 0, 1, 0);
        }
        finally
        {
            pin.Free();
        }

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

    private static double Rate(string key, ulong current, Dictionary<string, ulong> previous, double elapsed, bool first)
    {
        previous.TryGetValue(key, out var last);
        previous[key] = current;
        if (first || elapsed < 0.2 || current < last)
            return 0;
        return (current - last) / elapsed;
    }

    private string? PathFor(int pid)
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
