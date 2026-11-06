using Avalonia.Controls;
using RedFilter.ViewModels;

namespace RedFilter;

public partial class MainWindow : Window
{
    public MainWindow()
    {
        InitializeComponent();
    }

    public MainWindow(NetworkViewModel network, WifiViewModel wifi) : this()
    {
        PcPage.DataContext = network;
        WifiPage.DataContext = wifi;
        Opened += async (_, _) => await wifi.StartAsync();
        Closed += (_, _) =>
        {
            network.Dispose();
            wifi.Dispose();
        };
    }
}
