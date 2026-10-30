using System.Security.Cryptography;
using System.Text;
using System.Xml.Linq;

namespace RedFilter.Core.Router;

public static class FritzChallenge
{
    public static string Calculate(string challenge, string password)
    {
        if (challenge.StartsWith("2$", StringComparison.Ordinal))
            return CalculatePbkdf2(challenge, password);

        var bytes = Encoding.Unicode.GetBytes(challenge + "-" + password);
        return challenge + "-" + Convert.ToHexString(MD5.HashData(bytes)).ToLowerInvariant();
    }

    public static string CalculatePbkdf2(string challenge, string password)
    {
        var parts = challenge.Split('$');
        if (parts.Length < 5)
            throw new RouterException("The FRITZ!Box challenge is not in the documented PBKDF2 form (2$iterations$salt$iterations$salt).");

        var iterations1 = int.Parse(parts[1], System.Globalization.CultureInfo.InvariantCulture);
        var iterations2 = int.Parse(parts[3], System.Globalization.CultureInfo.InvariantCulture);
        if (iterations1 is < 1 or > 5_000_000 || iterations2 is < 1 or > 5_000_000)
            throw new RouterException("The FRITZ!Box challenge asked for an unexpected number of PBKDF2 iterations.");

        var salt1 = Convert.FromHexString(parts[2]);
        var salt2 = Convert.FromHexString(parts[4]);
        var first = Rfc2898DeriveBytes.Pbkdf2(
            Encoding.UTF8.GetBytes(password),
            salt1,
            iterations1,
            HashAlgorithmName.SHA256,
            32);
        var second = Rfc2898DeriveBytes.Pbkdf2(first, salt2, iterations2, HashAlgorithmName.SHA256, 32);
        return parts[4] + "$" + Convert.ToHexString(second).ToLowerInvariant();
    }

    public static (string Challenge, int BlockTime) ReadLoginPage(string xml)
    {
        var document = XmlValues.Parse(xml);
        var challenge = XmlValues.Text(document, "Challenge");
        if (string.IsNullOrWhiteSpace(challenge))
            throw new RouterException("The FRITZ!Box login page did not include a challenge.");
        var blockText = XmlValues.Text(document, "BlockTime");
        var blockTime = int.TryParse(blockText, out var seconds) ? seconds : 0;
        return (challenge, blockTime);
    }

    public static string? ReadSid(string xml)
    {
        var document = XmlValues.Parse(xml);
        return XmlValues.Text(document, "SID");
    }
}
