using System.Security.Cryptography;
using System.Text;

namespace RedFilter.Core.Router.TpLink;

/// <summary>
/// Sign-in for the TD-W8961N v5 web interface. The router's own login page disables the plain
/// fields and posts only hex MD5 digests of the username and password to login.cgi; the router then
/// keeps the session in a SessionID cookie, which the transport's cookie container carries.
/// </summary>
public static class TdW8961Login
{
    public static string Body(string username, string password) =>
        "usernameEncrypt=" + Md5Hex(username) +
        "&passwordEncrypt=" + Md5Hex(password) +
        "&" + Uri.EscapeDataString("submit.htm?login.htm") + "=Send";

    public static async Task LoginAsync(IRouterTransport transport, RouterEndpoint endpoint, string username, string password, CancellationToken cancellationToken)
    {
        if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password))
            throw new RouterException("Falta el usuario o la contraseña del router.");

        var response = await transport.SendAsync(new RouterHttpRequest
        {
            Method = HttpMethod.Post,
            Url = endpoint.Append("/login.cgi"),
            Body = Body(username, password),
            ContentType = "application/x-www-form-urlencoded"
        }, cancellationToken);

        if (response.StatusCode is < 200 or >= 400)
            throw new RouterException($"El router respondió HTTP {response.StatusCode} al iniciar sesión.");

        // A rejected login comes back to the login page; a good one opens the admin pages.
        var check = await transport.SendAsync(new RouterHttpRequest { Url = endpoint.Append("/" + TdW8961Pages.AccessControlPage) }, cancellationToken);
        if (check.StatusCode is 401 or 403 || TdW8961Pages.IsLoginPage(check.Body) || !check.Body.Contains("wlanAcEnabled", StringComparison.Ordinal))
            throw new RouterException("El router rechazó el usuario o la contraseña. Si te equivocaste varias veces, puede que tengas que esperar un rato.");
    }

    private static string Md5Hex(string value) =>
        Convert.ToHexString(MD5.HashData(Encoding.UTF8.GetBytes(value))).ToLowerInvariant();
}
