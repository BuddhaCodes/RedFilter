using System.ComponentModel;
using System.Diagnostics;
using RedFilter.Core.Qos;

namespace RedFilter.Platform;

public interface IQosElevation
{
    bool TryRelaunch(QosLaunchRequest request, out string failure);
}

public sealed class WindowsQosElevation : IQosElevation
{
    public bool TryRelaunch(QosLaunchRequest request, out string failure)
    {
        var path = Environment.ProcessPath;
        if (string.IsNullOrWhiteSpace(path))
        {
            failure = "RedFilter cannot find its own program file, so it cannot ask Windows for elevation. QoS stays blocked.";
            return false;
        }

        try
        {
            var started = Process.Start(new ProcessStartInfo
            {
                FileName = path,
                Arguments = QosLaunch.FormatArguments(request),
                UseShellExecute = true,
                Verb = "runas"
            });
            if (started == null)
            {
                failure = "Windows did not start the elevated RedFilter. QoS stays blocked.";
                return false;
            }

            failure = "";
            return true;
        }
        catch (Win32Exception ex) when (ex.NativeErrorCode == 1223)
        {
            failure = "Elevation was cancelled. QoS stays blocked.";
            return false;
        }
        catch (Exception ex)
        {
            failure = "Windows did not elevate RedFilter. QoS stays blocked. " + ex.Message;
            return false;
        }
    }
}
