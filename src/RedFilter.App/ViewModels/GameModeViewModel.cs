using Avalonia.Threading;
using RedFilter.Core.Processes;
using RedFilter.Core.Qos;
using RedFilter.Core.Router;
using RedFilter.Core.Router.TpLink;
using RedFilter.Core.Text;
using RedFilter.Core.Settings;

namespace RedFilter.ViewModels;

/// <summary>
/// "Modo Dota 2": on the router, this PC gets a guaranteed share of the line and every other device is
/// capped; on this PC, dota2.exe gets priority and other programs' uploads are throttled. It can be
/// switched on by hand, is offered when Dota 2 starts, and ends by itself when the game closes.
/// </summary>
public sealed class GameModeViewModel : ObservableObject, IDisposable
{
    private static readonly TimeSpan CheckInterval = TimeSpan.FromSeconds(3);
    private static readonly TimeSpan GoneGrace = TimeSpan.FromSeconds(20);

    private readonly NetworkViewModel _network;
    private readonly WifiViewModel _wifi;
    private readonly SettingsStore _store;
    private readonly IUserPrompt _prompt;
    private readonly DispatcherTimer _timer;
    private bool _active;
    private bool _busy;
    private bool _dotaRunning;
    private bool _auto;
    private string _detail = "";
    private string _dotaText = "Dota 2 no está abierto.";
    private int? _offeredPid;
    private int? _prioritizedPid;
    private string? _gamePath;
    private bool _sawGameWhileActive;
    private DateTime? _goneSinceUtc;
    private LevelChoice _level;

    public IReadOnlyList<LevelChoice> Levels { get; } = new[]
    {
        new LevelChoice { Profile = GameModeProfile.Soft },
        new LevelChoice { Profile = GameModeProfile.Aggressive },
        new LevelChoice { Profile = GameModeProfile.Extreme }
    };

    /// <summary>How hard the mode squeezes everyone else. Changing it while the mode is on re-applies it.</summary>
    public LevelChoice Level
    {
        get => _level;
        set
        {
            if (value == null || !Set(ref _level, value))
                return;
            Raise(nameof(LevelDescription));
            var settings = _store.Load();
            settings.GameModeLevel = value.Profile.Level;
            _store.Save(settings);
            if (Active)
                _ = ReapplyAsync();
        }
    }

    public string LevelDescription => Level.Description;
    private GameModeProfile Profile => Level.Profile;

    public GameModeViewModel(NetworkViewModel network, WifiViewModel wifi, SettingsStore store, IUserPrompt prompt)
    {
        _network = network;
        _wifi = wifi;
        _store = store;
        _prompt = prompt;
        var settings = store.Load();
        _auto = settings.GameModeAuto;
        _soloGame = settings.GameModeSoloGame;
        _allowDiscord = settings.GameModeAllowDiscord;
        _level = Levels.First(choice => choice.Profile.Level == GameModeProfile.For(settings.GameModeLevel).Level);
        _active = settings.GameMode != null;
        _detail = _active
            ? "El modo Dota 2 sigue activo desde la última vez. Apágalo cuando termines para devolver la red a los demás."
            : IdleDetail;
        _timer = new DispatcherTimer { Interval = CheckInterval };
        _timer.Tick += async (_, _) => await CheckAsync();
        _timer.Start();
    }

    private const string IdleDetail =
        "Reserva la línea para este PC, limita a todos los demás dispositivos de la casa y da prioridad a Dota 2 frente a los otros programas.";

    public bool Active { get => _active; private set { if (Set(ref _active, value)) { Raise(nameof(Title)); Raise(nameof(ToggleLabel)); Raise(nameof(StateLabel)); Raise(nameof(ToggleTip)); } } }
    public bool Busy { get => _busy; private set { if (Set(ref _busy, value)) { Raise(nameof(CanToggle)); Raise(nameof(ToggleLabel)); Raise(nameof(StateLabel)); } } }
    public bool DotaRunning { get => _dotaRunning; private set => Set(ref _dotaRunning, value); }
    public string Detail { get => _detail; private set => Set(ref _detail, value); }
    public string DotaText { get => _dotaText; private set => Set(ref _dotaText, value); }
    public string Title => Active ? "MODO DOTA 2 ACTIVO" : "MODO DOTA 2";
    public string ToggleLabel => Busy ? "…" : Active ? "APAGAR" : "ACTIVAR";
    public string StateLabel => Busy ? "APLICANDO" : Active ? "ACTIVO" : "APAGADO";
    public string ToggleTip => Active ? "Apagar el modo y devolver la red a como estaba" : "Activar el modo Dota 2";
    public bool CanToggle => !Busy;

    private bool _soloGame;
    private bool _allowDiscord;

    /// <summary>While the mode is on and Dota is running, only Dota (and Steam) has internet on this PC.</summary>
    public bool SoloGame
    {
        get => _soloGame;
        set
        {
            if (!Set(ref _soloGame, value))
                return;
            var settings = _store.Load();
            settings.GameModeSoloGame = value;
            _store.Save(settings);
            _ = ApplySoloAsync();
        }
    }

    /// <summary>Keep Discord online (voice chat) while only Dota has internet.</summary>
    public bool AllowDiscord
    {
        get => _allowDiscord;
        set
        {
            if (!Set(ref _allowDiscord, value))
                return;
            var settings = _store.Load();
            settings.GameModeAllowDiscord = value;
            _store.Save(settings);
            if (_network.SoloGameOn)
                _ = RestartSoloAsync();
        }
    }

    // Changes only the exceptions: programs already blocked stay blocked (except Discord, if now allowed).
    private async Task RestartSoloAsync()
    {
        if (_network.FindDota()?.ExecutablePath is { } path)
            await _network.StartSoloGameAsync(new SoloGameOptions(path, AllowDiscord));
        Detail = SoloText();
    }

    /// <summary>Blocks or unblocks the other programs to match the switch, the mode and whether Dota is running.</summary>
    private async Task ApplySoloAsync()
    {
        var game = _network.FindDota();
        var want = Active && SoloGame && game?.ExecutablePath != null;
        if (want && !_network.SoloGameOn)
        {
            if (!_network.IsAdmin)
            {
                Detail = "Para dejar internet solo a Dota hace falta RedFilter como administrador. Se pedirá al dar prioridad a Dota.";
                return;
            }

            if (await _network.StartSoloGameAsync(new SoloGameOptions(game!.ExecutablePath!, AllowDiscord)))
                Detail = SoloText();
        }
        else if (!want && _network.SoloGameOn)
        {
            await _network.StopSoloGameAsync();
            if (Active)
                Detail = "Los demás programas de este PC vuelven a tener internet (con la subida limitada).";
        }
    }

    private string SoloText() =>
        "Este PC: solo Dota 2 y Steam" + (AllowDiscord ? ", y Discord," : "") + " tienen internet. Los programas que se abran ahora también quedan sin red hasta que apagues el modo o cierres Dota.";

    public bool Auto
    {
        get => _auto;
        set
        {
            if (!Set(ref _auto, value))
                return;
            var settings = _store.Load();
            settings.GameModeAuto = value;
            _store.Save(settings);
        }
    }

    public async Task ToggleAsync()
    {
        if (Active)
            await StopAsync(automatic: false);
        else
            await StartAsync(_network.FindDota(), askFirst: true);
    }

    public void Dispose() => _timer.Stop();

    private async Task StartAsync(ProcessNetworkRow? game, bool askFirst)
    {
        if (Busy)
            return;
        if (!_wifi.Connected)
        {
            Detail = "Conecta primero con tu router en la sección Mi Wi-Fi: el modo Dota 2 reparte la línea desde el router.";
            return;
        }

        if (askFirst && !await _prompt.ConfirmAsync(
                "¿Activar el modo Dota 2?\n\n" +
                "•  Este PC tendrá reservada la mayor parte de la línea.\n" +
                $"•  Nivel {Profile.Name}: los demás dispositivos de la casa compartirán como mucho {GameModePlanner.Describe(Profile.OthersDownBudgetKbps)} de bajada y {GameModePlanner.Describe(Profile.OthersUpBudgetKbps)} de subida.\n" +
                $"   {Level.Description}\n" +
                (SoloGame
                    ? "•  En este PC, solo Dota 2 y Steam" + (AllowDiscord ? " (y Discord)" : "") + " tendrán internet: los demás programas se quedan sin red mientras juegas.\n\n"
                    : $"•  En este PC, Dota 2 tendrá prioridad y la subida de los otros programas se limita a {RateText.BitsPerSecond(Profile.PcOtherProgramsUploadBits)}.\n\n") +
                "Al aplicar los cambios, el router puede tardar unos segundos. Todo vuelve a como estaba al apagar el modo o al cerrar Dota 2." +
                (_network.IsAdmin || game == null ? "" : "\n\nPara la prioridad en este PC, Windows pedirá permiso de administrador y RedFilter se reiniciará.")))
            return;

        Busy = true;
        try
        {
            Detail = "Configurando el router…";
            var routerText = await _wifi.StartGameModeAsync(Profile);
            Active = true;
            _sawGameWhileActive = game != null;
            _goneSinceUtc = null;
            Detail = routerText + (game == null ? " Cuando abras Dota 2, se le dará prioridad en este PC." : "");
            if (game != null)
                await PrioritizeAsync(game, routerText);
        }
        catch (RouterException ex)
        {
            Detail = "No se pudo activar el modo: " + ex.Message + (_wifi.GameModeActive ? " Pulsa Apagar para deshacer lo que se llegó a aplicar." : "");
            Active = _wifi.GameModeActive;
        }
        finally
        {
            Busy = false;
        }
    }

    private async Task PrioritizeAsync(ProcessNetworkRow game, string routerText)
    {
        _prioritizedPid = game.Pid;
        _gamePath = game.ExecutablePath;
        if (!await _network.PrioritizeGameAsync(game, Profile.PcOtherProgramsUploadBits))
            return;
        Detail = routerText + $" Este PC: Dota 2 tiene prioridad y los demás programas suben a {RateText.BitsPerSecond(Profile.PcOtherProgramsUploadBits)} como mucho.";
        if (SoloGame)
        {
            await ApplySoloAsync();
            if (_network.SoloGameOn)
                Detail = routerText + " " + SoloText();
        }
    }

    private async Task ReapplyAsync()
    {
        if (Busy)
            return;
        Busy = true;
        try
        {
            Detail = $"Cambiando a nivel {Profile.Name}…";
            var routerText = await _wifi.StartGameModeAsync(Profile);
            Detail = routerText;
            if (_network.FindDota() is { } game && _network.IsAdmin)
                await PrioritizeAsync(game, routerText);
        }
        catch (RouterException ex)
        {
            Detail = "No se pudo cambiar el nivel: " + ex.Message;
        }
        finally
        {
            Busy = false;
        }
    }

    private async Task StopAsync(bool automatic)
    {
        if (Busy)
            return;
        Busy = true;
        try
        {
            Detail = "Devolviendo el router a como estaba…";
            var routerText = await _wifi.StopGameModeAsync();
            await _network.StopSoloGameAsync();
            await _network.EndGamePriorityAsync(_gamePath);
            Active = false;
            _prioritizedPid = null;
            _sawGameWhileActive = false;
            _goneSinceUtc = null;
            Detail = (automatic ? "Dota 2 se cerró, así que el modo se apagó solo. " : "Modo Dota 2 apagado. ") + routerText;
        }
        catch (RouterException ex)
        {
            Detail = "No se pudo apagar del todo: " + ex.Message + " Vuelve a pulsar Apagar cuando el router responda.";
        }
        finally
        {
            Busy = false;
        }
    }

    private async Task CheckAsync()
    {
        var game = _network.FindDota();
        DotaRunning = game != null;
        DotaText = game == null
            ? "Dota 2 no está abierto."
            : _network.HasPriority(game.ExecutablePath) ? "Dota 2 abierto · con prioridad en este PC" : "Dota 2 abierto";
        if (Busy)
            return;

        if (!Active)
        {
            if (game != null && Auto && _offeredPid != game.Pid && _wifi.Connected)
            {
                _offeredPid = game.Pid;
                await StartAsync(game, askFirst: true);
            }

            return;
        }

        if (game != null)
        {
            _sawGameWhileActive = true;
            _goneSinceUtc = null;
            // The mode was switched on before the game, or the game restarted: give the new process priority.
            if (_prioritizedPid != game.Pid && _network.IsAdmin && !_network.HasPriority(game.ExecutablePath))
                await PrioritizeAsync(game, "Modo Dota 2 activo.");
            else if (SoloGame && _network.IsAdmin && !_network.SoloGameOn)
                await ApplySoloAsync();
            await _wifi.RebalanceGameModeAsync();
            return;
        }

        // Dota closed: give the other programs their internet back right away, even before the mode ends.
        if (_network.SoloGameOn)
            await ApplySoloAsync();

        if (_sawGameWhileActive && Auto)
        {
            _goneSinceUtc ??= DateTime.UtcNow;
            if (DateTime.UtcNow - _goneSinceUtc >= GoneGrace)
                await StopAsync(automatic: true);
            return;
        }

        await _wifi.RebalanceGameModeAsync();
    }
}

/// <summary>One entry of the level picker.</summary>
public sealed class LevelChoice
{
    public required GameModeProfile Profile { get; init; }
    public string Label => Profile.Name;
    public string Description => Profile.Level switch
    {
        GameModeLevel.Soft => "Los demás: hasta ~2,5 Mbps / 384 kbps entre todos. Vídeo en calidad media.",
        GameModeLevel.Extreme => "Los demás: ~384 kbps / 64 kbps entre todos. Solo mensajes y notificaciones.",
        _ => "Los demás: ~1 Mbps / 160 kbps entre todos. Chat, web y vídeo en baja calidad."
    };
}
