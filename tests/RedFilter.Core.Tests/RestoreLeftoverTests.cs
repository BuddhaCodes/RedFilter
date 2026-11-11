using System.Web;
using RedFilter.Core.Router;
using RedFilter.Core.Router.TpLink;

namespace RedFilter.Core.Tests;

/// <summary>Turning the game mode off must leave nothing squeezing the line.</summary>
public sealed class RestoreLeftoverTests
{
    [Fact]
    public async Task WithNoRuleLeftTheLineGoesBackToUnlimitedEvenIfTotalsWereSetBefore()
    {
        var router = new MiniRouter { Totals = (1033, 4146) }; // totals left over from an older session
        var client = new TdW8961Client(router, RouterEndpoint.Parse("http://192.168.1.1"));
        var backup = new GameModeBackup { TotalUpKbps = 1033, TotalDownKbps = 4146, TouchedIps = { "192.168.1.109", "192.168.1.111" } };
        router.Rules.Add(("192.168.1.109", 918, 3915));
        router.Rules.Add(("192.168.1.111", 22, 163));

        var after = await client.RestoreGameModeAsync(backup, CancellationToken.None);

        Assert.Empty(after.Rules);
        Assert.Equal((0, 0), router.Totals);
    }

    [Fact]
    public async Task UserLimitsComeBackWithTheirTotals()
    {
        var router = new MiniRouter { Totals = (918, 3915) };
        var client = new TdW8961Client(router, RouterEndpoint.Parse("http://192.168.1.1"));
        var backup = new GameModeBackup { TotalUpKbps = 1033, TotalDownKbps = 4146, TouchedIps = { "192.168.1.105" }, Limits = { new SavedLimit("192.168.1.105", 64, 256) } };
        router.Rules.Add(("192.168.1.105", 22, 163));

        var after = await client.RestoreGameModeAsync(backup, CancellationToken.None);

        Assert.Equal(("192.168.1.105", 64, 256), Assert.Single(router.Rules));
        Assert.Equal((1033, 4146), router.Totals);
        Assert.Single(after.Rules);
    }

    [Fact]
    public async Task IdleTotalsAreClearedButHandMadeLimitsAreKept()
    {
        var idle = new MiniRouter { Totals = (918, 3915) };
        var cleared = await new TdW8961Client(idle, RouterEndpoint.Parse("http://192.168.1.1")).ClearIdleTotalsAsync(CancellationToken.None);
        Assert.Equal((0, 0), idle.Totals);
        Assert.Empty(cleared.Rules);

        var busy = new MiniRouter { Totals = (918, 3915) };
        busy.Rules.Add(("192.168.1.105", 64, 256));
        var kept = await new TdW8961Client(busy, RouterEndpoint.Parse("http://192.168.1.1")).ClearIdleTotalsAsync(CancellationToken.None);
        Assert.Equal((918, 3915), busy.Totals);
        Assert.Single(kept.Rules);
        Assert.Empty(busy.Posts);
    }

    private sealed class MiniRouter : IRouterTransport
    {
        public (int Up, int Down) Totals { get; set; }
        public List<(string Ip, int Up, int Down)> Rules { get; } = new();
        public List<string> Posts { get; } = new();
        public bool UsedUntrustedCertificate => false;

        public Task<RouterHttpResponse> SendAsync(RouterHttpRequest request, CancellationToken cancellationToken)
        {
            if (request.Method == HttpMethod.Post)
            {
                Posts.Add(request.Body ?? "");
                var form = HttpUtility.ParseQueryString(request.Body ?? "");
                if (form["applyItflimit"] != null)
                    Totals = (int.Parse(form["total"]!), int.Parse(form["downtotal"]!));
                if (form["addRule"] != null)
                    Rules.Add((form["srcip"]!, int.Parse(form["uprateCeiling"]!), int.Parse(form["downrateCeiling"]!)));
                if (form["save"] != null && int.TryParse(form["removeRuleList"], out var remove))
                    Rules.RemoveAt(remove);
                return Ok("ok");
            }

            var rows = string.Concat(Rules.Select((rule, i) =>
                $"<TR><TD>{i + 1}</TD><TD>WAN0</TD><TD> </TD><TD> </TD><TD> </TD><TD>{rule.Ip}/32</TD><TD> </TD><TD>-1</TD><TD>-1</TD><TD>{rule.Up}</TD><TD>{rule.Down}</TD><TD><input type=\"checkbox\" name=\"removeQ\" value=\"{i}\"></TD></TR>"));
            return Ok($"<input type=\"text\" name=total value=\"{Totals.Up}\"><input type=\"text\" name=downtotal value=\"{Totals.Down}\"><table>{rows}</table>");
        }

        public void Dispose()
        {
        }

        private static Task<RouterHttpResponse> Ok(string body) => Task.FromResult(new RouterHttpResponse { StatusCode = 200, Body = body });
    }
}
