namespace RedFilter.Core.Text;

public static class RateText
{
    public static string BitsPerSecond(long bits)
    {
        if (bits % 1_000_000 == 0 && bits >= 1_000_000)
            return $"{bits / 1_000_000} Mbps";
        if (bits % 1_000 == 0 && bits >= 1_000)
            return $"{bits / 1_000} Kbps";
        return $"{bits} bps";
    }

    public static string BytesPerSecond(double bytesPerSecond)
    {
        if (double.IsNaN(bytesPerSecond) || double.IsInfinity(bytesPerSecond) || bytesPerSecond < 0)
            return "—";
        if (bytesPerSecond < 1024)
            return $"{bytesPerSecond:0} B/s";
        if (bytesPerSecond < 1024 * 1024)
            return $"{bytesPerSecond / 1024:0.0} KB/s";
        return $"{bytesPerSecond / (1024 * 1024):0.00} MB/s";
    }

    public static string ByteCount(long bytes)
    {
        if (bytes < 0)
            bytes = 0;
        if (bytes < 1024)
            return $"{bytes} B";
        if (bytes < 1024 * 1024)
            return $"{bytes / 1024.0:0.0} KB";
        if (bytes < 1024L * 1024 * 1024)
            return $"{bytes / (1024.0 * 1024):0.0} MB";
        return $"{bytes / (1024.0 * 1024 * 1024):0.00} GB";
    }
}
