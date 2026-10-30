using Avalonia.Controls;
using Avalonia.Interactivity;
using RedFilter.ViewModels;

namespace RedFilter;

public partial class MainWindow : Window
{
    private NetworkViewModel? _network;

    public MainWindow()
    {
        InitializeComponent();
    }

    public MainWindow(NetworkViewModel network, RouterViewModel router) : this()
    {
        _network = network;
        NetworkPage.DataContext = network;
        RouterPage.DataContext = router;
        Loaded += (_, _) => network.Start();
        Closed += (_, _) => _network?.Dispose();
    }

    private void ShowNetwork(object? sender, RoutedEventArgs e)
    {
        NetworkPage.IsVisible = true;
        RouterPage.IsVisible = false;
        NetworkButton.Classes.Add("active");
        RouterButton.Classes.Remove("active");
    }

    private void ShowRouter(object? sender, RoutedEventArgs e)
    {
        NetworkPage.IsVisible = false;
        RouterPage.IsVisible = true;
        RouterButton.Classes.Add("active");
        NetworkButton.Classes.Remove("active");
    }
}
