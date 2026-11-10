using System.IO;
using Avalonia;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Markup.Xaml;
using Avalonia.Threading;
using RedFilter.Core.Qos;
using RedFilter.Core.Router;
using RedFilter.Core.Settings;
using RedFilter.Platform;
using RedFilter.ViewModels;
using RedFilter.Views;

namespace RedFilter;

public partial class App : Application
{
    public override void Initialize()
    {
        AvaloniaXamlLoader.Load(this);
    }

    public override void OnFrameworkInitializationCompleted()
    {
        Dispatcher.UIThread.UnhandledException += (_, args) =>
        {
            args.Handled = true;
            var owner = (ApplicationLifetime as IClassicDesktopStyleApplicationLifetime)?.MainWindow;
            var dialog = new ConfirmWindow(args.Exception.Message, okOnly: true);
            if (owner == null)
                dialog.Show();
            else
                _ = dialog.ShowDialog(owner);
        };

        if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
        {
            var folder = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "RedFilter");
            var store = new SettingsStore(folder, new DpapiSecretProtector());
            var prompt = new AvaloniaUserPrompt();
            QosLaunch.TryParse(desktop.Args ?? [], out var pendingLaunch);
            var elevated = AdminCheck.IsElevated();
            var network = new NetworkViewModel(
                new WindowsProcessNetworkSource(elevated),
                new PowerShellQosPolicyStore(),
                store,
                elevated,
                pendingLaunch,
                new WindowsQosElevation(),
                Shutdown,
                prompt,
                new PowerShellFirewallStore());
            var local = LocalNetworkInfo.Read();
            network.VpnActive = local.VpnActive;
            network.VpnName = local.VpnName ?? "";
            var wifi = new WifiViewModel(
                store,
                endpoint => new HttpRouterTransport(endpoint.Host, PinnedCertificate(store, endpoint.Host)),
                prompt,
                local);
            var game = new GameModeViewModel(network, wifi, store, prompt);
            desktop.MainWindow = new MainWindow(network, wifi, game);
            network.Start();
        }

        base.OnFrameworkInitializationCompleted();
    }

    private static string? PinnedCertificate(SettingsStore store, string host)
    {
        var settings = store.Load();
        return string.Equals(settings.RouterCertificateHost, host, StringComparison.OrdinalIgnoreCase)
            ? settings.RouterCertificateSha256
            : null;
    }

    private static void Shutdown()
    {
        if (Current?.ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
            desktop.Shutdown();
    }
}
