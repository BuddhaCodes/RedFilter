using System.Windows;
using RedFilter.ViewModels;

namespace RedFilter;

public partial class MainWindow : Window
{
    private readonly NetworkViewModel _network;

    public MainWindow(NetworkViewModel network, RouterViewModel router)
    {
        InitializeComponent();
        _network = network;
        NetworkPage.DataContext = network;
        RouterPage.DataContext = router;
        Loaded += (_, _) => network.Start();
        Closed += (_, _) => network.Dispose();
    }

    private void ShowNetwork(object sender, RoutedEventArgs e)
    {
        if (NetworkPage == null || RouterPage == null)
            return;
        NetworkPage.Visibility = Visibility.Visible;
        RouterPage.Visibility = Visibility.Collapsed;
    }

    private void ShowRouter(object sender, RoutedEventArgs e)
    {
        NetworkPage.Visibility = Visibility.Collapsed;
        RouterPage.Visibility = Visibility.Visible;
    }
}
