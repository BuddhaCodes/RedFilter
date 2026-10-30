using System.Globalization;
using System.Text;

namespace RedFilter.Core.Qos;

public sealed record QosLaunchRequest(
    bool Clear,
    int? Pid,
    string? Path,
    string? Name,
    long? ThrottleBitsPerSecond);

public static class QosLaunch
{
    public static string FormatArguments(QosLaunchRequest request)
    {
        if (request.Clear)
            return "--qos clear";

        var parts = new List<string> { "--qos", "apply" };
        if (request.Pid is int pid)
        {
            parts.Add("--pid");
            parts.Add(pid.ToString(CultureInfo.InvariantCulture));
        }

        if (request.ThrottleBitsPerSecond is long throttle)
        {
            parts.Add("--throttle");
            parts.Add(throttle.ToString(CultureInfo.InvariantCulture));
        }

        if (!string.IsNullOrWhiteSpace(request.Name))
        {
            parts.Add("--name");
            parts.Add(request.Name);
        }

        if (!string.IsNullOrWhiteSpace(request.Path))
        {
            parts.Add("--path");
            parts.Add(request.Path);
        }

        return string.Join(' ', parts.Select(Quote));
    }

    public static bool TryParse(IReadOnlyList<string> args, out QosLaunchRequest? request)
    {
        request = null;
        if (args.Count == 0)
            return false;

        bool? clear = null;
        int? pid = null;
        long? throttle = null;
        string? path = null;
        string? name = null;

        for (var i = 0; i < args.Count; i++)
        {
            var token = args[i];
            if (token.Equals("--qos", StringComparison.OrdinalIgnoreCase))
            {
                if (!Take(args, ref i, out var verb))
                    return false;
                if (verb.Equals("apply", StringComparison.OrdinalIgnoreCase))
                    clear = false;
                else if (verb.Equals("clear", StringComparison.OrdinalIgnoreCase))
                    clear = true;
                else
                    return false;
                continue;
            }

            if (token.Equals("--pid", StringComparison.OrdinalIgnoreCase))
            {
                if (!Take(args, ref i, out var raw) || !int.TryParse(raw, NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsed) || parsed < 0)
                    return false;
                pid = parsed;
                continue;
            }

            if (token.Equals("--throttle", StringComparison.OrdinalIgnoreCase))
            {
                if (!Take(args, ref i, out var raw) || !long.TryParse(raw, NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsed) || parsed < 0)
                    return false;
                throttle = parsed;
                continue;
            }

            if (token.Equals("--name", StringComparison.OrdinalIgnoreCase))
            {
                if (!Take(args, ref i, out name))
                    return false;
                continue;
            }

            if (token.Equals("--path", StringComparison.OrdinalIgnoreCase))
            {
                if (!Take(args, ref i, out path))
                    return false;
                continue;
            }

            return false;
        }

        if (clear == null)
            return false;

        request = new QosLaunchRequest(clear.Value, pid, path, name, throttle);
        return true;
    }

    private static bool Take(IReadOnlyList<string> args, ref int index, out string value)
    {
        if (index + 1 >= args.Count)
        {
            value = "";
            return false;
        }

        index++;
        value = args[index];
        return true;
    }

    private static string Quote(string value)
    {
        if (value.Length > 0 && value.IndexOfAny([' ', '\t', '\n', '\v', '"']) < 0)
            return value;

        var quoted = new StringBuilder();
        quoted.Append('"');
        for (var i = 0; i < value.Length; i++)
        {
            var slashes = 0;
            while (i < value.Length && value[i] == '\\')
            {
                slashes++;
                i++;
            }

            if (i == value.Length)
            {
                quoted.Append('\\', slashes * 2);
                break;
            }

            if (value[i] == '"')
            {
                quoted.Append('\\', slashes * 2 + 1);
                quoted.Append('"');
            }
            else
            {
                quoted.Append('\\', slashes);
                quoted.Append(value[i]);
            }
        }

        quoted.Append('"');
        return quoted.ToString();
    }
}
