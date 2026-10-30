using System.Globalization;

namespace RedFilter.Core.Router;

public static class MacAddress
{
    public static bool TryNormalize(string? text, out string normalized)
    {
        normalized = "";
        if (string.IsNullOrWhiteSpace(text))
            return false;

        var hex = new string(text.Where(Uri.IsHexDigit).ToArray());
        if (hex.Length != 12)
            return false;

        var bytes = Convert.FromHexString(hex);
        var chars = new char[17];
        for (var i = 0; i < 6; i++)
        {
            if (i > 0)
                chars[i * 3 - 1] = ':';
            var pair = bytes[i].ToString("X2", CultureInfo.InvariantCulture);
            chars[i * 3] = pair[0];
            chars[i * 3 + 1] = pair[1];
        }

        normalized = new string(chars);
        return true;
    }

    public static string RequireUnicast(string? text)
    {
        if (!TryNormalize(text, out var mac))
            throw new RouterException("That is not a client MAC address. Use six hexadecimal bytes, such as AA:BB:CC:DD:EE:FF.");

        var first = byte.Parse(mac[..2], NumberStyles.HexNumber, CultureInfo.InvariantCulture);
        if (mac == "FF:FF:FF:FF:FF:FF")
            throw new RouterException("The broadcast address is not a client. RedFilter will not address every station.");
        if ((first & 0x01) != 0)
            throw new RouterException("That MAC is a group address, not a single client. RedFilter will not use it.");
        return mac;
    }
}
