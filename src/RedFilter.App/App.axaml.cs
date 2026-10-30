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
            var network = new NetworkViewModel(
                new WindowsProcessNetworkSource(),
                new PowerShellQosPolicyStore(),
                store,
                AdminCheck.IsElevated(),
                pendingLaunch,
                new WindowsQosElevation(),
                Shutdown,
                prompt);
            var router = new RouterViewModel(
                store,
                endpoint => new HttpRouterTransport(endpoint.Host),
                WindowsGatewayLookup.TryGetDefaultGateway,
                prompt);
            desktop.MainWindow = new MainWindow(network, router);
        }

        base.OnFrameworkInitializationCompleted();
    }

    private static void Shutdown()
    {
        if (Current?.ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
            desktop.Shutdown();
    }
}
