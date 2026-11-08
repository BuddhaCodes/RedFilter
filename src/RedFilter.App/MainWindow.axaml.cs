using Avalonia.Controls;
using RedFilter.ViewModels;

namespace RedFilter;

public partial class MainWindow : Window
{
    public MainWindow()
    {
        InitializeComponent();
    }

    public MainWindow(NetworkViewModel network, WifiViewModel wifi, GameModeViewModel game) : this()
    {
        PcPage.DataContext = network;
        WifiPage.DataContext = wifi;
        GamePage.DataContext = game;
        Opened += async (_, _) => await wifi.StartAsync();
        Closed += (_, _) =>
        {
            game.Dispose();
            network.Dispose();
            wifi.Dispose();
        };
    }
}
