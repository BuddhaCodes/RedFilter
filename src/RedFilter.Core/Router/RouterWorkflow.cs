namespace RedFilter.Core.Router;

public sealed class RouterWorkflow : IDisposable
{
    private readonly Func<RouterEndpoint, IRouterTransport> _transportFactory;
    private IRouterTransport? _transport;
    private IRouterSession? _session;

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
            var user = username?.Trim() ?? "";
            _session = brand switch
            {
                "openwrt" => await OpenWrtClient.LoginAsync(transport, endpoint, user, password, cancellationToken),
                "asuswrt" => await AsusWrtClient.LoginAsync(transport, endpoint, user, password, cancellationToken),
                "fritz" => await FritzBoxClient.LoginAsync(transport, endpoint, user, password, cancellationToken),
                _ => throw new RouterException("That brand is not supported.")
            };
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
                UsedUntrustedCertificate = transport.UsedUntrustedCertificate
            };
        }
        catch (RouterException ex)
        {
            _session = null;
            return WithCertificate(RouterInspection.Failed(SecretText.Scrub(ex.Message, password) + publicNote), transport);
        }
    }

    public async Task<RouterClientList?> RefreshAsync(CancellationToken cancellationToken)
    {
        if (_session == null)
            return null;
        return await _session.GetClientsAsync(cancellationToken);
    }

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
                UsedUntrustedCertificate = transport.UsedUntrustedCertificate
            };

    private void ReplaceTransport(IRouterTransport? transport)
    {
        _session = null;
        _transport?.Dispose();
        _transport = transport;
    }
}
