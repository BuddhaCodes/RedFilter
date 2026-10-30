using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace RedFilter.Platform;

public static class WindowsGatewayLookup
{
    public static string? TryGetDefaultGateway()
    {
        foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (nic.OperationalStatus != OperationalStatus.Up)
                continue;
            if (nic.NetworkInterfaceType == NetworkInterfaceType.Loopback)
                continue;
            foreach (var gateway in nic.GetIPProperties().GatewayAddresses)
            {
                if (gateway.Address.AddressFamily == AddressFamily.InterNetwork && !System.Net.IPAddress.IsLoopback(gateway.Address))
                    return gateway.Address.ToString();
            }
        }

        return null;
    }
}

public static class AdminCheck
{
    public static bool IsElevated()
    {
        using var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
        var principal = new System.Security.Principal.WindowsPrincipal(identity);
        return principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
    }
}
