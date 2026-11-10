using RedFilter.Core.Qos;

namespace RedFilter.Platform;

/// <summary>
/// Windows Firewall blocks for the "only Dota has internet" part of the game mode. Runs the same way as
/// the QoS store: one fixed script, the request as ASCII JSON on stdin, administrator rights required.
/// </summary>
public sealed class PowerShellFirewallStore : IFirewallBlockStore
{
    public async Task<IReadOnlyList<FirewallBlockSpec>> ReadAsync(CancellationToken cancellationToken) =>
        NetFirewallScript.ParseQuery(await PowerShellQosPolicyStore.RunAsync(NetFirewallScript.EncodedScript, NetFirewallScript.QueryPayload(), cancellationToken));

    public async Task ApplyAsync(IReadOnlyList<FirewallBlockSpec> desired, CancellationToken cancellationToken)
    {
        var current = await ReadAsync(cancellationToken);
        var (remove, add) = FirewallBlockReconciler.Diff(current, desired);
        if (remove.Count == 0 && add.Count == 0)
            return;
        var output = await PowerShellQosPolicyStore.RunAsync(NetFirewallScript.EncodedScript, NetFirewallScript.ApplyPayload(remove, add), cancellationToken);
        if (!output.Contains("OK", StringComparison.Ordinal))
            throw new InvalidOperationException("Windows Firewall did not confirm the change. " + PowerShellQosPolicyStore.Excerpt(output));
    }

    public async Task RemoveAllAsync(CancellationToken cancellationToken)
    {
        var output = await PowerShellQosPolicyStore.RunAsync(NetFirewallScript.EncodedScript, NetFirewallScript.ClearPayload(), cancellationToken);
        if (!output.Contains("OK", StringComparison.Ordinal))
            throw new InvalidOperationException("Windows Firewall did not confirm that RedFilter's blocks were removed. " + PowerShellQosPolicyStore.Excerpt(output));
    }
}
