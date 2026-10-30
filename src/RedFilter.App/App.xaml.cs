using System.IO;
using System.Windows;
using RedFilter.Core.Qos;
using RedFilter.Core.Router;
using RedFilter.Core.Settings;
using RedFilter.Platform;
using RedFilter.ViewModels;

namespace RedFilter;

public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        DispatcherUnhandledException += (_, args) =>
        {
            MessageBox.Show(args.Exception.Message, "RedFilter");
            args.Handled = true;
        };

        var folder = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "RedFilter");
        var store = new SettingsStore(folder, new DpapiSecretProtector());
        QosLaunch.TryParse(e.Args, out var pendingLaunch);
        var network = new NetworkViewModel(
            new WindowsProcessNetworkSource(),
            new PowerShellQosPolicyStore(),
            store,
            AdminCheck.IsElevated(),
            pendingLaunch,
            new WindowsQosElevation(),
            Shutdown);
        var router = new RouterViewModel(store, endpoint => new HttpRouterTransport(endpoint.Host), WindowsGatewayLookup.TryGetDefaultGateway);
        var window = new MainWindow(network, router);
        MainWindow = window;
        window.Show();
    }
}
