using System.Diagnostics;
using System.IO;
using System.Text;
using RedFilter.Core.Qos;

namespace RedFilter.Platform;

public sealed class PowerShellQosPolicyStore : IQosPolicyStore
{
    public async Task<IReadOnlyList<ActiveQosPolicy>> ReadAsync(CancellationToken cancellationToken)
    {
        var output = await RunAsync(NetQosScript.Query(), cancellationToken);
        return NetQosPolicyParser.Parse(output);
    }

    public async Task ApplyAsync(IReadOnlyList<QosPolicySpec> desired, CancellationToken cancellationToken)
    {
        var current = await ReadAsync(cancellationToken);
        var (remove, add) = QosPolicyReconciler.Diff(current, desired);
        if (remove.Count == 0 && add.Count == 0)
            return;
        var output = await RunAsync(NetQosScript.Apply(remove, add), cancellationToken);
        if (!output.Contains("OK", StringComparison.Ordinal))
            throw new InvalidOperationException("Windows QoS did not confirm the policy change. " + Excerpt(output));
    }

    public async Task RemoveAllAsync(CancellationToken cancellationToken)
    {
        var output = await RunAsync(NetQosScript.RemoveAll(), cancellationToken);
        if (!output.Contains("OK", StringComparison.Ordinal))
            throw new InvalidOperationException("Windows QoS did not confirm that the policies were removed. " + Excerpt(output));
    }

    private static async Task<string> RunAsync(string script, CancellationToken cancellationToken)
    {
        var path = Path.Combine(Path.GetTempPath(), "RedFilter-" + Guid.NewGuid().ToString("N") + ".ps1");
        await File.WriteAllTextAsync(path, script, new UTF8Encoding(encoderShouldEmitUTF8Identifier: true), cancellationToken);
        try
        {
            using var process = new Process();
            process.StartInfo = new ProcessStartInfo
            {
                FileName = "powershell.exe",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };
            process.StartInfo.ArgumentList.Add("-NoProfile");
            process.StartInfo.ArgumentList.Add("-NonInteractive");
            process.StartInfo.ArgumentList.Add("-ExecutionPolicy");
            process.StartInfo.ArgumentList.Add("Bypass");
            process.StartInfo.ArgumentList.Add("-File");
            process.StartInfo.ArgumentList.Add(path);

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
            await process.WaitForExitAsync(cancellationToken);
            var stdout = await stdoutTask;
            var stderr = await stderrTask;
            if (process.ExitCode != 0)
            {
                var detail = string.IsNullOrWhiteSpace(stderr) ? stdout : stderr;
                throw new InvalidOperationException("Windows QoS did not change. " + Excerpt(detail));
            }

            return stdout;
        }
        finally
        {
            try
            {
                File.Delete(path);
            }
            catch (IOException)
            {
                // The script has no secrets. Leaving it in temp is harmless if deletion races.
            }
        }
    }

    private static string Excerpt(string text)
    {
        var trimmed = text.Trim();
        if (trimmed.Length > 800)
            trimmed = trimmed[..800];
        return string.IsNullOrWhiteSpace(trimmed) ? "PowerShell exited without a message." : trimmed;
    }
}
