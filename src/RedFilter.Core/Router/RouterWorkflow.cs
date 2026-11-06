namespace RedFilter.Core.Router;

public sealed class RouterWorkflow : IDisposable
{
    private readonly Func<RouterEndpoint, IRouterTransport> _transportFactory;
    private IRouterTransport? _transport;
    private IRouterSession? _session;
    private LoginDetails? _login;

    public RouterWorkflow(Func<RouterEndpoint, IRouterTransport> transportFactory)
    {
        _transportFactory = transportFactory;
    }

    public IRouterSession? Session => _session;

    public async Task<RouterInspection> TestAsync(
        string? address,
        string? username,
        string? password,
        string? brandId,
        CancellationToken cancellationToken)
    {
        ReplaceTransport(null);
        if (!RouterEndpoint.TryParse(address, out var endpoint, out var error))
            return RouterInspection.Failed(error);
        if (string.IsNullOrEmpty(password))
            return RouterInspection.Failed("Admin password is missing. RedFilter does not guess credentials.");

        var selected = string.IsNullOrWhiteSpace(brandId) ? "auto" : brandId.Trim().ToLowerInvariant();
        if (selected is not ("auto" or "openwrt" or "asuswrt" or "fritz"))
            return RouterInspection.Failed($"\"{brandId}\" is not a supported brand. Choose Detect automatically, OpenWrt, ASUSWRT, or FRITZ!Box.");
        if (selected != "fritz" && string.IsNullOrWhiteSpace(username))
            return RouterInspection.Failed("Admin username is missing.");

        var transport = _transportFactory(endpoint!);
        ReplaceTransport(transport);
        var probe = await RouterDetector.ProbeAsync(transport, endpoint!, cancellationToken);
        if (!probe.Reachable && selected == "auto")
            return WithCertificate(RouterInspection.Failed(probe.Summary), transport);

        var brand = selected == "auto" ? probe.DetectedBrand : selected;
        if (brand == null)
            return WithCertificate(RouterInspection.Failed(probe.Summary), transport);

        var publicNote = endpoint!.HostIsPublicIp
            ? " This address is a public IP. The password is sent only to this host. Use it only when it is your router."
            : "";

        try
        {
            var login = new LoginDetails(brand, endpoint, username?.Trim() ?? "", password);
            _session = await LoginAsync(transport, login, cancellationToken);
            _login = login;
            var list = await _session.GetClientsAsync(cancellationToken);
            var model = _session.Model;
            var status = $"{_session.Brand} answered." +
                         (string.IsNullOrWhiteSpace(model) ? "" : $" Model: {model}.") +
                         (string.IsNullOrWhiteSpace(_session.Firmware) ? "" : $" Firmware: {_session.Firmware}.") +
                         " " + list.Note + publicNote;
            if (transport.UsedUntrustedCertificate)
                status += " The router certificate is not trusted. RedFilter accepted it only for this host.";
            return new RouterInspection
            {
                Success = true,
                Status = status.Trim(),
                Brand = brand,
                Model = model,
                Firmware = _session.Firmware,
                Capabilities = _session.Capabilities,
                Clients = list.Clients,
                UsageKind = list.UsageKind,
                UsedUntrustedCertificate = transport.UsedUntrustedCertificate,
                CertificateSha256 = transport.CertificateSha256
            };
        }
        catch (RouterException ex)
        {
            _session = null;
            _login = null;
            return WithCertificate(RouterInspection.Failed(SecretText.Scrub(ex.Message, password) + publicNote), transport);
        }
    }

    public async Task<RouterClientList?> RefreshAsync(CancellationToken cancellationToken)
    {
        if (_session == null)
            return null;
        return await RunAsync(session => session.GetClientsAsync(cancellationToken), cancellationToken);
    }

    /// <summary>
    /// Runs a call on the current session. When the router says the session expired (OpenWrt sessions
    /// last five minutes by default, ASUSWRT tokens also time out), RedFilter signs in once more with the
    /// same credentials and repeats the call. The first call was refused, so nothing is sent twice.
    /// </summary>
    public async Task<T> RunAsync<T>(Func<IRouterSession, Task<T>> action, CancellationToken cancellationToken)
    {
        var session = _session ?? throw new RouterException("There is no router session. Choose Test connection first.");
        try
        {
            return await action(session);
        }
        catch (RouterException ex) when (ex.SessionExpired && _login != null && _transport != null)
        {
            try
            {
                _session = await LoginAsync(_transport, _login, cancellationToken);
            }
            catch (RouterException relogin)
            {
                var password = _login.Password;
                _session = null;
                _login = null;
                throw new RouterException(
                    "The router session expired and signing in again failed. " + SecretText.Scrub(relogin.Message, password), relogin);
            }

            return await action(_session);
        }
    }

    private static async Task<IRouterSession> LoginAsync(IRouterTransport transport, LoginDetails login, CancellationToken cancellationToken) =>
        login.Brand switch
        {
            "openwrt" => await OpenWrtClient.LoginAsync(transport, login.Endpoint, login.Username, login.Password, cancellationToken),
            "asuswrt" => await AsusWrtClient.LoginAsync(transport, login.Endpoint, login.Username, login.Password, cancellationToken),
            "fritz" => await FritzBoxClient.LoginAsync(transport, login.Endpoint, login.Username, login.Password, cancellationToken),
            _ => throw new RouterException("That brand is not supported.")
        };

    private sealed record LoginDetails(string Brand, RouterEndpoint Endpoint, string Username, string Password);

    public void Dispose() => ReplaceTransport(null);

    private static RouterInspection WithCertificate(RouterInspection inspection, IRouterTransport transport) =>
        inspection.UsedUntrustedCertificate == transport.UsedUntrustedCertificate
            ? inspection
            : new RouterInspection
            {
                Success = inspection.Success,
                Status = inspection.Status,
                Brand = inspection.Brand,
                Model = inspection.Model,
                Firmware = inspection.Firmware,
                Capabilities = inspection.Capabilities,
                Clients = inspection.Clients,
                UsageKind = inspection.UsageKind,
                UsedUntrustedCertificate = transport.UsedUntrustedCertificate,
                CertificateSha256 = transport.CertificateSha256
            };

    private void ReplaceTransport(IRouterTransport? transport)
    {
        _session = null;
        _login = null;
        _transport?.Dispose();
        _transport = transport;
    }
}
