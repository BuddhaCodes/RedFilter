using Avalonia.Controls;
using Avalonia.Interactivity;
using RedFilter.ViewModels;

namespace RedFilter.Views;

public partial class PcView : UserControl
{
    public PcView()
    {
        InitializeComponent();
    }

    private NetworkViewModel? Vm => DataContext as NetworkViewModel;

    private async void Prioritize_Click(object? sender, RoutedEventArgs e)
    {
        if (Vm == null || (sender as Control)?.Tag is not ProgramRow program)
            return;
        try
        {
            await Vm.PrioritizeAsync(program);
        }
        catch (Exception ex)
        {
            Vm.Status = ex.Message;
        }
    }

    private async void TurnOff_Click(object? sender, RoutedEventArgs e)
    {
        if (Vm == null)
            return;
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
