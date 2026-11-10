using System.Diagnostics;
using System.Text;
using RedFilter.Core.Qos;

namespace RedFilter.Platform;

public sealed class PowerShellQosPolicyStore : IQosPolicyStore
{
    public async Task<IReadOnlyList<ActiveQosPolicy>> ReadAsync(CancellationToken cancellationToken)
    {
        var output = await RunAsync(NetQosScript.EncodedScript, NetQosScript.QueryPayload(), cancellationToken);
        return NetQosPolicyParser.Parse(output);
    }

    public async Task ApplyAsync(IReadOnlyList<QosPolicySpec> desired, CancellationToken cancellationToken)
    {
        var current = await ReadAsync(cancellationToken);
        var (remove, add) = QosPolicyReconciler.Diff(current, desired);
        if (remove.Count == 0 && add.Count == 0)
            return;
        var output = await RunAsync(NetQosScript.EncodedScript, NetQosScript.ApplyPayload(remove, add), cancellationToken);
        if (!output.Contains("OK", StringComparison.Ordinal))
            throw new InvalidOperationException("Windows QoS did not confirm the policy change. " + Excerpt(output));
    }

    public async Task RemoveAllAsync(CancellationToken cancellationToken)
    {
        var output = await RunAsync(NetQosScript.EncodedScript, NetQosScript.ClearPayload(), cancellationToken);
        if (!output.Contains("OK", StringComparison.Ordinal))
            throw new InvalidOperationException("Windows QoS did not confirm that the policies were removed. " + Excerpt(output));
    }

    // The script is a fixed string passed with -EncodedCommand, so nothing is written to %TEMP%
    // where another process could swap it before the elevated PowerShell runs it. The request
    // (paths, names, rates) goes in as ASCII JSON on stdin and is never parsed as PowerShell code.
    internal static async Task<string> RunAsync(string encodedScript, string payload, CancellationToken cancellationToken)
    {
        using var process = new Process();
        process.StartInfo = new ProcessStartInfo
        {
            FileName = Path.Combine(Environment.SystemDirectory, "WindowsPowerShell", "v1.0", "powershell.exe"),
            UseShellExecute = false,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            StandardInputEncoding = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false),
            CreateNoWindow = true
        };
        process.StartInfo.ArgumentList.Add("-NoProfile");
        process.StartInfo.ArgumentList.Add("-NonInteractive");
        process.StartInfo.ArgumentList.Add("-ExecutionPolicy");
        process.StartInfo.ArgumentList.Add("Bypass");
        process.StartInfo.ArgumentList.Add("-EncodedCommand");
        process.StartInfo.ArgumentList.Add(encodedScript);

        try
        {
            if (!process.Start())
                throw new InvalidOperationException("Windows PowerShell did not start. RedFilter uses the built-in NetQos module and needs powershell.exe.");
        }
        catch (Exception ex) when (ex is not InvalidOperationException)
        {
            throw new InvalidOperationException(
                "Windows PowerShell was not found. RedFilter uses the built-in NetQos module (New-NetQosPolicy) and needs powershell.exe.",
                ex);
        }

        var stdoutTask = process.StandardOutput.ReadToEndAsync(cancellationToken);
        var stderrTask = process.StandardError.ReadToEndAsync(cancellationToken);
        await process.StandardInput.WriteAsync(payload.AsMemory(), cancellationToken);
        process.StandardInput.Close();

        try
        {
            await process.WaitForExitAsync(cancellationToken);
        }
        catch (OperationCanceledException)
        {
            try
            {
                process.Kill(entireProcessTree: true);
            }
            catch (InvalidOperationException)
            {
                // It already exited.
            }

            throw;
        }

        var stdout = await stdoutTask;
        var stderr = await stderrTask;
        if (process.ExitCode != 0)
        {
            var detail = string.IsNullOrWhiteSpace(stderr) ? stdout : stderr;
            throw new InvalidOperationException("Windows did not apply the change. " + Excerpt(detail));
        }

        return stdout;
    }

    internal static string Excerpt(string text)
    {
        var trimmed = text.Trim();
        if (trimmed.Length > 800)
            trimmed = trimmed[..800];
        return string.IsNullOrWhiteSpace(trimmed) ? "PowerShell exited without a message." : trimmed;
    }
}
