using System.Text.Json;
using RedFilter.Core.Processes;
using RedFilter.Core.Qos;

namespace RedFilter.Core.Tests;

public sealed class FirewallBlockTests
{
    private const string Dota = @"C:\Program Files (x86)\Steam\steamapps\common\dota 2 beta\game\bin\win64\dota2.exe";

    private static ProcessNetworkRow P(string path, int connections = 2, string? name = null) =>
        new(1, name ?? Path.GetFileNameWithoutExtension(path.Replace('\\', '/')), path, connections, 0, 0, 0);

    [Fact]
    public void BlocksEveryProgramUsingTheNetworkExceptWindowsTheGameAndSteam()
    {
        var processes = new[]
        {
            P(Dota),
            P(@"C:\Program Files (x86)\Steam\steamapps\common\dota 2 beta\game\bin\win64\vconsole2.exe"),
            P(@"C:\Program Files (x86)\Steam\steam.exe"),
            P(@"C:\Program Files (x86)\Steam\bin\cef\cef.win7x64\steamwebhelper.exe"),
            P(@"C:\Windows\System32\svchost.exe"),
            P(@"C:\Tools\RedFilter.exe"),
            P(@"C:\Program Files\Google\Chrome\Application\chrome.exe"),
            P(@"C:\Users\x\AppData\Local\Discord\app-1.0.9\Discord.exe"),
            P(@"C:\Program Files\qBittorrent\qbittorrent.exe"),
            P(@"C:\Program Files\Notepad\notepad.exe", connections: 0),
        };

        var blocks = FirewallBlockPlanner.Build(processes, new SoloGameOptions(Dota, AllowDiscord: false), Array.Empty<string>());

        Assert.Equal(
            new[] { @"C:\Program Files\Google\Chrome\Application\chrome.exe", @"C:\Program Files\qBittorrent\qbittorrent.exe", @"C:\Users\x\AppData\Local\Discord\app-1.0.9\Discord.exe" },
            blocks.Select(block => block.AppPath).Order(StringComparer.OrdinalIgnoreCase).ToArray());
        Assert.All(blocks, block => Assert.Matches("^RedFilter-Block-[A-F0-9]{12}$", block.Name));
    }

    [Fact]
    public void DiscordCanKeepItsInternetAndBlockedProgramsStayBlocked()
    {
        var discord = @"C:\Users\x\AppData\Local\Discord\app-1.0.9\Discord.exe";
        var chrome = @"C:\Program Files\Google\Chrome\Application\chrome.exe";

        var blocks = FirewallBlockPlanner.Build(new[] { P(discord) }, new SoloGameOptions(Dota, AllowDiscord: true), new[] { chrome });

        // Chrome has no connections any more (it was blocked), but it must not get its internet back.
        Assert.Equal(new[] { chrome }, blocks.Select(block => block.AppPath).ToArray());
    }

    [Fact]
    public void FindsTheGameInstallFolder()
    {
        Assert.Equal(@"C:\Program Files (x86)\Steam\steamapps\common\dota 2 beta\", FirewallBlockPlanner.GameRoot(Dota));
        Assert.Equal(@"D:\Games\", FirewallBlockPlanner.GameRoot(@"D:\Games\dota2.exe"));
    }

    [Fact]
    public void DiffAddsAndRemovesOnlyWhatChanged()
    {
        var a = new FirewallBlockSpec(FirewallBlockPlanner.RuleName(@"C:\a.exe"), @"C:\a.exe");
        var b = new FirewallBlockSpec(FirewallBlockPlanner.RuleName(@"C:\b.exe"), @"C:\b.exe");
        var c = new FirewallBlockSpec(FirewallBlockPlanner.RuleName(@"C:\c.exe"), @"C:\c.exe");

        var (remove, add) = FirewallBlockReconciler.Diff(new[] { a, b }, new[] { b, c });

        Assert.Equal(new[] { a.Name }, remove);
        Assert.Equal(new[] { c }, add);
        Assert.Equal(FirewallBlockPlanner.RuleName(@"c:\A.EXE"), a.Name); // paths are case-insensitive on Windows
    }

    [Fact]
    public void PayloadIsAsciiJsonAndRefusesForeignNames()
    {
        var path = @"C:\Juegos\Fútbol\“raro”.exe";
        var payload = NetFirewallScript.ApplyPayload(Array.Empty<string>(), new[] { new FirewallBlockSpec(FirewallBlockPlanner.RuleName(path), path) });

        Assert.All(payload, ch => Assert.True(ch < 128));
        using var doc = JsonDocument.Parse(payload);
        Assert.Equal(path, doc.RootElement.GetProperty("add")[0].GetProperty("path").GetString());
        Assert.Throws<InvalidOperationException>(() => NetFirewallScript.ApplyPayload(new[] { "Windows-Defender" }, Array.Empty<FirewallBlockSpec>()));
        Assert.DoesNotContain("Fútbol", NetFirewallScript.Script, StringComparison.Ordinal);
        Assert.Contains("-Group 'RedFilter'", NetFirewallScript.Script, StringComparison.Ordinal);
    }

    [Fact]
    public void ParsesTheQueryOutput()
    {
        var one = NetFirewallScript.ParseQuery("""{"Name":"RedFilter-Block-0123456789AB","Program":"C:\\a.exe"}""");
        Assert.Equal(new FirewallBlockSpec("RedFilter-Block-0123456789AB", @"C:\a.exe"), Assert.Single(one));
        Assert.Empty(NetFirewallScript.ParseQuery("[]"));
        Assert.Empty(NetFirewallScript.ParseQuery("""[{"Name":"Other","Program":"x"}]"""));
    }
}
