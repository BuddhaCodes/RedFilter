using System.Net;
using System.Text.RegularExpressions;

namespace RedFilter.Core.Router;

public sealed record RouterProbe(
    bool Reachable,
    string? DetectedBrand,
    string? PageTitle,
    int? HttpStatus,
    string Summary)
{
    public static RouterProbe Unreachable(string summary) => new(false, null, null, null, summary);
}

public static class RouterDetector
{
    public static async Task<RouterProbe> ProbeAsync(
        IRouterTransport transport,
        RouterEndpoint endpoint,
        CancellationToken cancellationToken)
    {
        var home = await GetAsync(transport, endpoint.Append("/"), cancellationToken);
        if (home.Error != null && home.Response == null)
            return RouterProbe.Unreachable(home.Error);

        var homeBody = home.Response?.Body ?? "";
        var title = HtmlTitle(homeBody);
        var identified = Identify(homeBody, title);
        if (identified != null)
            return Found(home.Response, title, identified);

        var login = await GetAsync(transport, endpoint.Append("/login_sid.lua?version=2"), cancellationToken);
        identified = Identify(login.Response?.Body ?? "", HtmlTitle(login.Response?.Body ?? ""));
        if (identified != null)
            return Found(login.Response ?? home.Response, title ?? HtmlTitle(login.Response?.Body ?? ""), identified);

        var asus = await GetAsync(transport, endpoint.Append("/Main_Login.asp"), cancellationToken);
        identified = Identify((asus.Response?.Body ?? "") + homeBody, title);
        if (identified != null)
            return Found(asus.Response ?? home.Response, title, identified);

        var ubus = await PostAsync(
            transport,
            endpoint.Append("/ubus"),
            """{"jsonrpc":"2.0","id":1,"method":"list","params":["00000000000000000000000000000000","session"]}""",
            cancellationToken);
        if (ubus.Response != null && ubus.Response.Body.Contains("jsonrpc", StringComparison.OrdinalIgnoreCase))
            return new RouterProbe(true, "openwrt", title, ubus.Response.StatusCode,
                Describe("openwrt", title, ubus.Response.StatusCode));

        var status = home.Response?.StatusCode ?? login.Response?.StatusCode;
        var hint = VendorHint(homeBody + (login.Response?.Body ?? "") + (asus.Response?.Body ?? ""));
        var details = new List<string>();
        if (status != null)
            details.Add("HTTP " + status);
        if (title != null)
            details.Add("page title \"" + title + "\"");
        var detail = details.Count == 0 ? "" : " (" + string.Join(", ", details) + ")";
        var summary = hint ??
            $"The admin API at {endpoint.Origin} was not recognized{detail}. " +
            "Supported APIs: OpenWrt (ubus), ASUSWRT, and FRITZ!Box (TR-064). " +
            "Choose a brand if you know it. RedFilter did not send a password.";
        return new RouterProbe(home.Response != null, null, title, status, summary);
    }

    private static RouterProbe Found(RouterHttpResponse? response, string? title, string brand) =>
        new(true, brand, title, response?.StatusCode, Describe(brand, title, response?.StatusCode));

    private static string Describe(string brand, string? title, int? status)
    {
        var name = brand switch
        {
            "openwrt" => "OpenWrt",
            "asuswrt" => "ASUSWRT",
            "fritz" => "FRITZ!Box",
            _ => brand
        };
        var extra = title == null ? "" : $" Page title: \"{title}\".";
        var code = status is null ? "" : $" HTTP {status}.";
        return $"Detected {name}.{code}{extra}";
    }

    private static string? Identify(string body, string? title)
    {
        var haystack = body + " " + title;
        if (haystack.Contains("SessionInfo", StringComparison.Ordinal) &&
            haystack.Contains("<Challenge>", StringComparison.OrdinalIgnoreCase))
            return "fritz";
        if (ContainsAny(haystack, "FRITZ!Box", "Fritz!Box", "login_sid.lua"))
            return "fritz";
        if (ContainsAny(haystack, "OpenWrt", "LuCI", "cgi-bin/luci"))
            return "openwrt";
        if (ContainsAny(haystack, "ASUSWRT", "asus_token", "ASUS Wireless", "router.asus.com", "Main_Login.asp"))
            return "asuswrt";
        return null;
    }

    private static string? VendorHint(string body)
    {
        if (ContainsAny(body, "TP-LINK", "tp-link", "tplinkwifi", "Archer"))
            return "The page looks like TP-Link. RedFilter has no TP-Link admin adapter, because those local APIs differ by model and many of them are encrypted. The client list stays empty. Supported APIs: OpenWrt (ubus), ASUSWRT, and FRITZ!Box (TR-064).";
        if (ContainsAny(body, "NETGEAR", "Netgear"))
            return "The page looks like NETGEAR. RedFilter has no NETGEAR admin adapter. The client list stays empty. Supported APIs: OpenWrt (ubus), ASUSWRT, and FRITZ!Box (TR-064).";
        if (ContainsAny(body, "UniFi", "Ubiquiti"))
            return "The page looks like Ubiquiti UniFi. RedFilter has no UniFi controller adapter. The client list stays empty. Supported APIs: OpenWrt (ubus), ASUSWRT, and FRITZ!Box (TR-064).";
        return null;
    }

    private static bool ContainsAny(string haystack, params string[] needles) =>
        needles.Any(needle => haystack.Contains(needle, StringComparison.OrdinalIgnoreCase));

    public static string? HtmlTitle(string html)
    {
        var match = Regex.Match(html, "<title[^>]*>(.*?)</title>", RegexOptions.IgnoreCase | RegexOptions.Singleline);
        if (!match.Success)
            return null;
        var title = WebUtility.HtmlDecode(match.Groups[1].Value).Replace('\r', ' ').Replace('\n', ' ').Trim();
        if (title.Length > 120)
            title = title[..120];
        return title.Length == 0 ? null : title;
    }

    private static async Task<(RouterHttpResponse? Response, string? Error)> GetAsync(
        IRouterTransport transport,
        Uri url,
        CancellationToken cancellationToken)
    {
        try
        {
            return (await transport.SendAsync(new RouterHttpRequest { Url = url }, cancellationToken), null);
        }
        catch (RouterException ex)
        {
            return (null, ex.Message);
        }
    }

    private static async Task<(RouterHttpResponse? Response, string? Error)> PostAsync(
        IRouterTransport transport,
        Uri url,
        string body,
        CancellationToken cancellationToken)
    {
        try
        {
            return (await transport.SendAsync(new RouterHttpRequest
            {
                Method = HttpMethod.Post,
                Url = url,
                Body = body,
                ContentType = "application/json"
            }, cancellationToken), null);
        }
        catch (RouterException ex)
        {
            return (null, ex.Message);
        }
    }
}
