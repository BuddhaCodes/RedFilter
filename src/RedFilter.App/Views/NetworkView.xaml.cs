using System.Windows;
using System.Windows.Controls;
using RedFilter.ViewModels;

namespace RedFilter.Views;

public partial class NetworkView : UserControl
{
    public NetworkView()
    {
        InitializeComponent();
    }

    private NetworkViewModel Vm => (NetworkViewModel)DataContext;

    private async void GiveNetwork_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            await Vm.GiveNetworkAsync();
        }
        catch (Exception ex)
        {
            Vm.Status = ex.Message;
        }
    }

    private async void TurnOff_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            await Vm.TurnOffAsync();
        }
        catch (Exception ex)
        {
            Vm.Status = ex.Message;
        }
    }
}
