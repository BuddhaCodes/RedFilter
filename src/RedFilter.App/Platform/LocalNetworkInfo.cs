using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using RedFilter.Core.Router;

namespace RedFilter.Platform;

/// <summary>What this PC looks like on the home network: its LAN address, its own MACs, and any VPN.</summary>
public sealed record LocalNetworkInfo(
    string? Gateway,
    string? LanIp,
    IReadOnlySet<string> OwnMacs,
    string? VpnName)
{
    public bool VpnActive => VpnName != null;

    public bool IsOwnMac(string mac) =>
        MacAddress.TryNormalize(mac, out var normalized) && OwnMacs.Contains(normalized);

    public static LocalNetworkInfo Read()
    {
        string? gateway = null;
        string? lanIp = null;
        string? vpn = null;
        var macs = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
        {
            try
            {
                var bytes = nic.GetPhysicalAddress().GetAddressBytes();
                if (bytes.Length == 6 && MacAddress.TryNormalize(Convert.ToHexString(bytes), out var mac))
                    macs.Add(mac);
                if (nic.OperationalStatus != OperationalStatus.Up || nic.NetworkInterfaceType == NetworkInterfaceType.Loopback)
                    continue;

                if (vpn == null && LooksLikeVpn(nic))
                    vpn = nic.Description.Contains("WireGuard", StringComparison.OrdinalIgnoreCase) ? "WireGuard" : nic.Name;

                var properties = nic.GetIPProperties();
                var lanGateway = properties.GatewayAddresses
                    .Select(item => item.Address)
                    .FirstOrDefault(address => address.AddressFamily == AddressFamily.InterNetwork &&
                                               RouterEndpoint.IsLanAddress(address) && !IPAddress.IsLoopback(address));
                if (gateway == null && lanGateway != null)
                {
                    gateway = lanGateway.ToString();
                    lanIp = properties.UnicastAddresses
                        .Select(item => item.Address)
                        .FirstOrDefault(address => address.AddressFamily == AddressFamily.InterNetwork)?
                        .ToString();
                }
            }
            catch (NetworkInformationException)
            {
                // An adapter can disappear while it is being read.
            }
        }

        return new LocalNetworkInfo(gateway, lanIp, macs, vpn);
    }

    private static bool LooksLikeVpn(NetworkInterface nic)
    {
        var text = nic.Name + " " + nic.Description;
        return nic.NetworkInterfaceType == NetworkInterfaceType.Ppp ||
               text.Contains("WireGuard", StringComparison.OrdinalIgnoreCase) ||
               text.Contains("Wintun", StringComparison.OrdinalIgnoreCase) ||
               text.Contains("TAP-Windows", StringComparison.OrdinalIgnoreCase) ||
               text.Contains("OpenVPN", StringComparison.OrdinalIgnoreCase) ||
               text.Contains("VPN", StringComparison.OrdinalIgnoreCase);
    }
}
