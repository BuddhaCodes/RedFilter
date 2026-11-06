using System.Net;
using System.Net.Http;
using System.Net.Security;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Xml.Linq;

namespace RedFilter.Core.Router;

public sealed record RouterHttpRequest
{
    public HttpMethod Method { get; init; } = HttpMethod.Get;
    public required Uri Url { get; init; }
    public string? Body { get; init; }
    public string? ContentType { get; init; }
    public IReadOnlyDictionary<string, string>? Headers { get; init; }

    public RouterHttpRequest WithHeader(string name, string value)
    {
        var copy = Headers == null
            ? new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            : new Dictionary<string, string>(Headers, StringComparer.OrdinalIgnoreCase);
        copy[name] = value;
        return this with { Headers = copy };
    }
}

public sealed class RouterHttpResponse
{
    public int StatusCode { get; init; }
    public string Body { get; init; } = "";
    public IReadOnlyList<string> Authenticate { get; init; } = Array.Empty<string>();
    public bool Truncated { get; init; }
}

public interface IRouterTransport : IDisposable
{
    bool UsedUntrustedCertificate { get; }

    /// <summary>SHA-256 of the certificate the router presented over HTTPS, if any.</summary>
    string? CertificateSha256 => null;

    Task<RouterHttpResponse> SendAsync(RouterHttpRequest request, CancellationToken cancellationToken);
}

public sealed class HttpRouterTransport : IRouterTransport
{
    private const int MaxBodyChars = 1_000_000;
    private readonly HttpClient _client;
    private readonly string _host;
    private readonly string? _pinnedSha256;
    private bool _usedUntrustedCertificate;
    private bool _pinMismatch;
    private string? _certificateSha256;

    /// <param name="pinnedSha256">The certificate fingerprint saved after the last successful sign-in to this host.
    /// An untrusted certificate is accepted only when it matches, or when nothing is saved yet.</param>
    public HttpRouterTransport(string host, string? pinnedSha256 = null)
    {
        _host = host;
        _pinnedSha256 = string.IsNullOrWhiteSpace(pinnedSha256) ? null : pinnedSha256.Trim();
        var handler = new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            AutomaticDecompression = DecompressionMethods.All,
            ConnectTimeout = TimeSpan.FromSeconds(5),
            SslOptions = new SslClientAuthenticationOptions
            {
                RemoteCertificateValidationCallback = ValidateCertificate
            }
        };
        _client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(12) };
    }

    public bool UsedUntrustedCertificate => _usedUntrustedCertificate;
    public string? CertificateSha256 => _certificateSha256;

    public async Task<RouterHttpResponse> SendAsync(RouterHttpRequest request, CancellationToken cancellationToken)
    {
        var current = request;
        for (var hop = 0; hop < 4; hop++)
        {
            EnsureHost(current.Url);
            using var message = new HttpRequestMessage(current.Method, current.Url);
            message.Headers.TryAddWithoutValidation("User-Agent", "RedFilter/1.0");
            if (current.Headers != null)
            {
                foreach (var header in current.Headers)
                    message.Headers.TryAddWithoutValidation(header.Key, header.Value);
            }

            if (current.Body != null)
            {
                message.Content = new StringContent(
                    current.Body,
                    Encoding.UTF8,
                    current.ContentType ?? "application/octet-stream");
            }

            HttpResponseMessage response;
            try
            {
                response = await _client.SendAsync(message, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
            }
            catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException)
            {
                if (_pinMismatch)
                {
                    throw new RouterException(
                        $"The HTTPS certificate of {current.Url.Host} is not the one saved at the last successful sign-in, so RedFilter did not send anything. " +
                        "If you replaced or reset the router, choose Forget certificate and test again. Otherwise someone on the network may be intercepting the connection.",
                        ex);
                }

                throw new RouterException($"Cannot reach {current.Url.Host}. {ex.Message}", ex);
            }

            using (response)
            {
                if (response.StatusCode is HttpStatusCode.Moved or HttpStatusCode.Redirect
                        or HttpStatusCode.RedirectMethod or HttpStatusCode.TemporaryRedirect
                        or HttpStatusCode.PermanentRedirect
                    && response.Headers.Location != null)
                {
                    var next = response.Headers.Location.IsAbsoluteUri
                        ? response.Headers.Location
                        : new Uri(current.Url, response.Headers.Location);
                    if (!next.Host.Equals(_host, StringComparison.OrdinalIgnoreCase))
                    {
                        throw new RouterException(
                            $"The router redirected to {next.Host}, which is a different host. RedFilter will not follow that redirect.");
                    }

                    if (current.Url.Scheme == Uri.UriSchemeHttps && next.Scheme == Uri.UriSchemeHttp)
                    {
                        throw new RouterException(
                            "The router redirected from HTTPS to plain HTTP. RedFilter will not downgrade the connection.");
                    }

                    current = new RouterHttpRequest
                    {
                        Method = response.StatusCode == HttpStatusCode.RedirectMethod ? HttpMethod.Get : current.Method,
                        Url = next,
                        Body = response.StatusCode == HttpStatusCode.RedirectMethod ? null : current.Body,
                        ContentType = current.ContentType,
                        Headers = current.Headers
                    };
                    continue;
                }

                var body = await ReadBodyAsync(response, cancellationToken);
                var authenticate = response.Headers.WwwAuthenticate
                    .Select(item => item.ToString())
                    .ToArray();
                return new RouterHttpResponse
                {
                    StatusCode = (int)response.StatusCode,
                    Body = body.Text,
                    Truncated = body.Truncated,
                    Authenticate = authenticate
                };
            }
        }

        throw new RouterException("The router redirected too many times.");
    }

    public void Dispose() => _client.Dispose();

    private void EnsureHost(Uri url)
    {
        if (url.Scheme is not ("http" or "https"))
            throw new RouterException("Only http and https can be used to reach the router.");
        if (!url.Host.Equals(_host, StringComparison.OrdinalIgnoreCase))
            throw new RouterException($"Refusing to contact {url.Host}. RedFilter only talks to {_host}.");
    }

    private bool ValidateCertificate(object sender, System.Security.Cryptography.X509Certificates.X509Certificate? certificate, System.Security.Cryptography.X509Certificates.X509Chain? chain, SslPolicyErrors errors)
    {
        var fingerprint = certificate == null ? null : CertificateFingerprint(certificate.GetRawCertData());
        _certificateSha256 = fingerprint;
        if (errors == SslPolicyErrors.None)
            return true;

        // This handler only dials the configured router. Home routers usually present a self-signed
        // certificate, so it is trusted on first use and pinned after a successful sign-in.
        if (sender is not SslStream stream ||
            !(stream.TargetHostName.Length == 0 || stream.TargetHostName.Equals(_host, StringComparison.OrdinalIgnoreCase)))
            return false;

        if (_pinnedSha256 != null && !string.Equals(_pinnedSha256, fingerprint, StringComparison.OrdinalIgnoreCase))
        {
            _pinMismatch = true;
            return false;
        }

        _usedUntrustedCertificate = true;
        return true;
    }

    public static string CertificateFingerprint(byte[] rawCertificate) =>
        Convert.ToHexString(SHA256.HashData(rawCertificate));

    private static async Task<(string Text, bool Truncated)> ReadBodyAsync(HttpResponseMessage response, CancellationToken cancellationToken)
    {
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
        using var reader = new StreamReader(stream, Encoding.UTF8, detectEncodingFromByteOrderMarks: true);
        var buffer = new char[8192];
        var builder = new StringBuilder();
        while (builder.Length < MaxBodyChars)
        {
            var read = await reader.ReadAsync(buffer.AsMemory(0, Math.Min(buffer.Length, MaxBodyChars - builder.Length)), cancellationToken);
            if (read == 0)
                return (builder.ToString(), false);
            builder.Append(buffer, 0, read);
        }

        return (builder.ToString(), true);
    }
}

internal static class DigestAuth
{
    public static async Task<RouterHttpResponse> SendAsync(
        IRouterTransport transport,
        RouterHttpRequest request,
        string username,
        string password,
        CancellationToken cancellationToken)
    {
        var first = await transport.SendAsync(request, cancellationToken);
        if (first.StatusCode != 401)
            return first;

        var challenge = first.Authenticate.FirstOrDefault(value =>
            value.StartsWith("Digest", StringComparison.OrdinalIgnoreCase));
        if (challenge == null)
        {
            throw new RouterException(
                $"The router refused access (HTTP 401) and did not offer digest authentication. {SecretText.Excerpt(first.Body, password)}");
        }

        var header = BuildHeader(challenge, username, password, request.Method.Method, request.Url.PathAndQuery);
        return await transport.SendAsync(request.WithHeader("Authorization", header), cancellationToken);
    }

    public static string BuildHeader(string wwwAuthenticate, string username, string password, string method, string uri, int count = 1)
    {
        var fields = Parse(wwwAuthenticate);
        if (!fields.TryGetValue("realm", out var realm) || !fields.TryGetValue("nonce", out var nonce))
            throw new RouterException("The router sent a digest challenge without a realm and nonce.");

        var cnonce = Convert.ToHexString(RandomNumberGenerator.GetBytes(8)).ToLowerInvariant();
        var nc = count.ToString("x8", System.Globalization.CultureInfo.InvariantCulture);
        var qop = fields.TryGetValue("qop", out var qopValue)
            ? qopValue.Split(',')[0].Trim()
            : "";
        var ha1 = Hash($"{username}:{realm}:{password}");
        var ha2 = Hash($"{method}:{uri}");
        var response = string.IsNullOrEmpty(qop)
            ? Hash($"{ha1}:{nonce}:{ha2}")
            : Hash($"{ha1}:{nonce}:{nc}:{cnonce}:{qop}:{ha2}");

        var header = new StringBuilder();
        header.Append("Digest ");
        header.Append("username=").Append(Quote(username));
        header.Append(", realm=").Append(Quote(realm));
        header.Append(", nonce=").Append(Quote(nonce));
        header.Append(", uri=").Append(Quote(uri));
        header.Append(", response=").Append(Quote(response));
        header.Append(", algorithm=MD5");
        if (!string.IsNullOrEmpty(qop))
        {
            header.Append(", qop=").Append(qop);
            header.Append(", nc=").Append(nc);
            header.Append(", cnonce=").Append(Quote(cnonce));
        }

        if (fields.TryGetValue("opaque", out var opaque))
            header.Append(", opaque=").Append(Quote(opaque));
        return header.ToString();
    }

    private static Dictionary<string, string> Parse(string header)
    {
        var fields = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var match = Regex.Match(header, @"^Digest\s+", RegexOptions.IgnoreCase);
        var rest = match.Success ? header[match.Length..] : header;
        foreach (Match part in Regex.Matches(rest, @"(\w+)\s*=\s*(""([^""]*)""|[^,]+)"))
        {
            var key = part.Groups[1].Value;
            var value = part.Groups[3].Success ? part.Groups[3].Value : part.Groups[2].Value.Trim();
            fields[key] = value;
        }

        return fields;
    }

    private static string Hash(string value) =>
        Convert.ToHexString(MD5.HashData(Encoding.UTF8.GetBytes(value))).ToLowerInvariant();

    private static string Quote(string value) =>
        "\"" + value.Replace("\\", "\\\\", StringComparison.Ordinal).Replace("\"", "\\\"", StringComparison.Ordinal) + "\"";
}

/// <summary>
/// Digest authentication that reuses the last challenge, so each request after the first costs one
/// round trip instead of two. A stale or rejected nonce falls back to a fresh challenge once.
/// </summary>
internal sealed class DigestClient
{
    private readonly IRouterTransport _transport;
    private readonly string _username;
    private readonly string _password;
    private string? _challenge;
    private int _count;

    public DigestClient(IRouterTransport transport, string username, string password)
    {
        _transport = transport;
        _username = username;
        _password = password;
    }

    public async Task<RouterHttpResponse> SendAsync(RouterHttpRequest request, CancellationToken cancellationToken)
    {
        RouterHttpResponse first;
        if (_challenge != null)
        {
            _count++;
            first = await _transport.SendAsync(Authorize(request, _challenge, _count), cancellationToken);
        }
        else
        {
            first = await _transport.SendAsync(request, cancellationToken);
        }

        if (first.StatusCode != 401)
            return first;

        var challenge = first.Authenticate.FirstOrDefault(value =>
            value.StartsWith("Digest", StringComparison.OrdinalIgnoreCase));
        if (challenge == null)
        {
            _challenge = null;
            throw new RouterException(
                $"The router refused access (HTTP 401) and did not offer digest authentication. {SecretText.Excerpt(first.Body, _password)}");
        }

        _challenge = challenge;
        _count = 1;
        var second = await _transport.SendAsync(Authorize(request, challenge, _count), cancellationToken);
        if (second.StatusCode == 401)
        {
            _challenge = null;
            throw new RouterException("The router rejected the username or password (HTTP 401).");
        }

        return second;
    }

    private RouterHttpRequest Authorize(RouterHttpRequest request, string challenge, int count) =>
        request.WithHeader("Authorization",
            DigestAuth.BuildHeader(challenge, _username, _password, request.Method.Method, request.Url.PathAndQuery, count));
}

internal static class XmlValues
{
    public static XDocument Parse(string xml)
    {
        try
        {
            return XDocument.Parse(xml);
        }
        catch (System.Xml.XmlException ex)
        {
            throw new RouterException("The router returned XML that could not be read. " + ex.Message);
        }
    }

    public static string? Text(XContainer container, string localName) =>
        container.Descendants().FirstOrDefault(element => element.Name.LocalName == localName)?.Value?.Trim();

    public static IEnumerable<XElement> Items(XContainer container) =>
        container.Descendants().Where(element =>
            element.Name.LocalName is "Item" or "Host" &&
            element.Elements().Any(child => child.Name.LocalName == "MACAddress"));
}
