namespace RedFilter.Core.Router.TpLink;

/// <summary>
/// A signed-in connection to a TD-W8961N. Holds the credentials in memory for the life of the app so
/// an expired session (the router logs idle sessions out) is renewed once, transparently.
/// </summary>
public sealed class TdW8961Session : IDisposable
{
    private readonly Func<RouterEndpoint, IRouterTransport> _transportFactory;
    private readonly RouterEndpoint _endpoint;
    private readonly string _username;
    private readonly string _password;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private IRouterTransport? _transport;
    private TdW8961Client? _client;

    public TdW8961Session(Func<RouterEndpoint, IRouterTransport> transportFactory, RouterEndpoint endpoint, string username, string password)
    {
        _transportFactory = transportFactory;
        _endpoint = endpoint;
        _username = username;
        _password = password;
    }

    public RouterEndpoint Endpoint => _endpoint;

    /// <summary>Checks that the address is a TD-W8961N-style web interface before any password is sent.</summary>
    public static async Task<bool> LooksLikeThisRouterAsync(IRouterTransport transport, RouterEndpoint endpoint, CancellationToken cancellationToken)
    {
        try
        {
            var page = await transport.SendAsync(new RouterHttpRequest { Url = endpoint.Append("/login.htm") }, cancellationToken);
            return page.StatusCode == 200 && TdW8961Pages.IsLoginPage(page.Body);
        }
        catch (RouterException)
        {
            return false;
        }
    }

    public async Task ConnectAsync(CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken);
        try
        {
            await SignInAsync(cancellationToken);
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <summary>Runs one router operation. Calls are serialized, because the router handles one form at a time.</summary>
    public async Task<T> RunAsync<T>(Func<TdW8961Client, Task<T>> action, CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken);
        try
        {
            if (_client == null)
                await SignInAsync(cancellationToken);
            try
            {
                return await action(_client!);
            }
            catch (RouterException ex) when (ex.SessionExpired)
            {
                await SignInAsync(cancellationToken);
                return await action(_client!);
            }
        }
        finally
        {
            _gate.Release();
        }
    }

    public void Dispose()
    {
        _transport?.Dispose();
        _gate.Dispose();
    }

    private async Task SignInAsync(CancellationToken cancellationToken)
    {
        _transport?.Dispose();
        _client = null;
        _transport = _transportFactory(_endpoint);
        await TdW8961Login.LoginAsync(_transport, _endpoint, _username, _password, cancellationToken);
        _client = new TdW8961Client(_transport, _endpoint);
    }
}
