using System.Text.Json;
using System.Text.Json.Serialization;

namespace RedFilter.Core.Settings;

public sealed class AppSettings
{
    public string? RouterAddress { get; set; }
    public string? RouterUsername { get; set; }
    public string Brand { get; set; } = "auto";
    public string? RouterModel { get; set; }
    public string? NetworkOwnerPath { get; set; }
    public string? NetworkOwnerName { get; set; }
    public int? NetworkOwnerPid { get; set; }
    public long ThrottleBitsPerSecond { get; set; } = 1_000_000;
    public string? RouterCertificateHost { get; set; }
    public string? RouterCertificateSha256 { get; set; }

    /// <summary>Set while the Dota 2 mode is on: how to put the router back the way it was.</summary>
    public RedFilter.Core.Router.TpLink.GameModeBackup? GameMode { get; set; }

    /// <summary>Offer the Dota 2 mode when dota2.exe starts, and end it when the game closes.</summary>
    public bool GameModeAuto { get; set; } = true;

    /// <summary>How hard the Dota 2 mode squeezes everyone else.</summary>
    public RedFilter.Core.Router.TpLink.GameModeLevel GameModeLevel { get; set; } = RedFilter.Core.Router.TpLink.GameModeLevel.Aggressive;
}

public interface ISecretProtector
{
    byte[] Protect(byte[] plaintext);
    byte[] Unprotect(byte[] ciphertext);
}

public sealed class SettingsStore
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    private readonly string _directory;
    private readonly ISecretProtector _protector;

    public SettingsStore(string directory, ISecretProtector protector)
    {
        _directory = directory;
        _protector = protector;
    }

    public string SettingsPath => Path.Combine(_directory, "settings.json");
    public string SecretPath => Path.Combine(_directory, "router-secret.bin");

    public AppSettings Load()
    {
        if (!File.Exists(SettingsPath))
            return new AppSettings();
        try
        {
            var json = File.ReadAllText(SettingsPath);
            return JsonSerializer.Deserialize<AppSettings>(json, JsonOptions) ?? new AppSettings();
        }
        catch (Exception ex) when (ex is JsonException or IOException or UnauthorizedAccessException)
        {
            return new AppSettings();
        }
    }

    public void Save(AppSettings settings)
    {
        Directory.CreateDirectory(_directory);
        var copy = new AppSettings
        {
            RouterAddress = settings.RouterAddress,
            RouterUsername = settings.RouterUsername,
            Brand = string.IsNullOrWhiteSpace(settings.Brand) ? "auto" : settings.Brand,
            RouterModel = settings.RouterModel,
            NetworkOwnerPath = settings.NetworkOwnerPath,
            NetworkOwnerName = settings.NetworkOwnerName,
            NetworkOwnerPid = settings.NetworkOwnerPid,
            ThrottleBitsPerSecond = settings.ThrottleBitsPerSecond,
            RouterCertificateHost = settings.RouterCertificateHost,
            RouterCertificateSha256 = settings.RouterCertificateSha256,
            GameMode = settings.GameMode,
            GameModeAuto = settings.GameModeAuto,
            GameModeLevel = settings.GameModeLevel
        };
        WriteAtomically(SettingsPath, System.Text.Encoding.UTF8.GetBytes(JsonSerializer.Serialize(copy, JsonOptions)));
    }

    public string? LoadPassword()
    {
        if (!File.Exists(SecretPath))
            return null;
        try
        {
            var protectedBytes = File.ReadAllBytes(SecretPath);
            if (protectedBytes.Length == 0)
                return null;
            var plain = _protector.Unprotect(protectedBytes);
            var text = System.Text.Encoding.UTF8.GetString(plain);
            return text.Length == 0 ? null : text;
        }
        catch (Exception)
        {
            return null;
        }
    }

    public void SavePassword(string? password)
    {
        Directory.CreateDirectory(_directory);
        if (string.IsNullOrEmpty(password))
        {
            if (File.Exists(SecretPath))
                File.Delete(SecretPath);
            return;
        }

        var plain = System.Text.Encoding.UTF8.GetBytes(password);
        WriteAtomically(SecretPath, _protector.Protect(plain));
    }

    // Write to a sibling temp file and move it over the target, so a crash or full disk
    // never leaves a half-written settings.json or secret behind.
    private static void WriteAtomically(string path, byte[] contents)
    {
        var temp = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            File.WriteAllBytes(temp, contents);
            File.Move(temp, path, overwrite: true);
        }
        finally
        {
            if (File.Exists(temp))
                File.Delete(temp);
        }
    }
}
