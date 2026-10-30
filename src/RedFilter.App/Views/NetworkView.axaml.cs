using Avalonia.Controls;
using Avalonia.Interactivity;
using RedFilter.ViewModels;

namespace RedFilter.Views;

public partial class NetworkView : UserControl
{
    public NetworkView()
    {
        InitializeComponent();
        DataContextChanged += (_, _) => BindProcesses();
    }

    private NetworkViewModel Vm => (NetworkViewModel)DataContext!;

    private void BindProcesses()
    {
        if (DataContext is NetworkViewModel vm)
            ProcessGrid.ItemsSource = vm.Processes;
    }

    private void ProcessGrid_SelectionChanged(object? sender, SelectionChangedEventArgs e)
    {
        if (DataContext is not NetworkViewModel vm)
            return;
        vm.Selected = ProcessGrid.SelectedItem as ProcessRowViewModel;
    }

    private async void GiveNetwork_Click(object? sender, RoutedEventArgs e)
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

    private async void TurnOff_Click(object? sender, RoutedEventArgs e)
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
