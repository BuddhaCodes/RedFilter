using System.Net;
using System.Net.Sockets;
using System.Text.RegularExpressions;

namespace RedFilter.Core.Router;

public sealed record RouterEndpoint(Uri Origin, string Host, bool HostIsPublicIp)
{
    public Uri Append(string relative) => new(Origin, relative);

    public static RouterEndpoint Parse(string? text)
    {
        if (!TryParse(text, out var endpoint, out var error))
            throw new RouterException(error);
        return endpoint!;
    }

    public static bool TryParse(string? text, out RouterEndpoint? endpoint, out string error)
    {
        endpoint = null;
        error = "";
        if (string.IsNullOrWhiteSpace(text))
        {
            error = "Router address is missing.";
            return false;
        }

        var trimmed = text.Trim();
        if (trimmed.Contains(',') || trimmed.Contains(' ') || trimmed.Contains('*'))
        {
            error = "Enter one router address. RedFilter does not accept a list or a wildcard.";
            return false;
        }

        if (!trimmed.Contains("://", StringComparison.Ordinal) &&
            Regex.IsMatch(trimmed, @"/\d{1,2}$"))
        {
            error = "Enter the router address, not a subnet such as 192.168.1.0/24.";
            return false;
        }

        var withScheme = trimmed.Contains("://", StringComparison.Ordinal) ? trimmed : "http://" + trimmed;
        if (!Uri.TryCreate(withScheme, UriKind.Absolute, out var uri))
        {
            error = "Router address is not a valid http or https URL.";
            return false;
        }

        if (uri.Scheme is not ("http" or "https"))
        {
            error = "Router address must start with http:// or https://.";
            return false;
        }

        if (!string.IsNullOrEmpty(uri.UserInfo))
        {
            error = "Put the username and password in the fields below, not inside the address.";
            return false;
        }

        if (string.IsNullOrWhiteSpace(uri.IdnHost))
        {
            error = "Router address is missing a host.";
            return false;
        }

        var builder = new UriBuilder(uri.Scheme, uri.Host, uri.IsDefaultPort ? -1 : uri.Port);
        var publicIp = IPAddress.TryParse(uri.IdnHost, out var ip) && !IsLanAddress(ip);
        endpoint = new RouterEndpoint(builder.Uri, uri.IdnHost, publicIp);
        return true;
    }

    public static bool IsLanAddress(IPAddress ip)
    {
        if (IPAddress.IsLoopback(ip))
            return true;
        if (ip.AddressFamily == AddressFamily.InterNetwork)
        {
            var bytes = ip.GetAddressBytes();
            return bytes[0] == 10
                || (bytes[0] == 172 && bytes[1] is >= 16 and <= 31)
                || (bytes[0] == 192 && bytes[1] == 168)
                || (bytes[0] == 169 && bytes[1] == 254)
                || (bytes[0] == 100 && bytes[1] is >= 64 and <= 127);
        }

        if (ip.IsIPv6LinkLocal)
            return true;
        var v6 = ip.GetAddressBytes();
        return v6.Length > 0 && (v6[0] & 0xFE) == 0xFC;
    }
}
