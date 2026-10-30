using Avalonia.Controls;
using Avalonia.Interactivity;
using RedFilter.ViewModels;

namespace RedFilter.Views;

public partial class RouterView : UserControl
{
    public RouterView()
    {
        InitializeComponent();
    }

    private RouterViewModel Vm => (RouterViewModel)DataContext!;

    private void Save_Click(object? sender, RoutedEventArgs e)
    {
        Vm.Save(PasswordBox.Text);
        PasswordBox.Text = "";
    }

    private async void Test_Click(object? sender, RoutedEventArgs e)
    {
        try
        {
            Vm.UsePassword(PasswordBox.Text);
            await Vm.TestAsync();
            PasswordBox.Text = "";
        }
        catch (Exception ex)
        {
            Vm.Status = ex.Message;
        }
    }

    private async void Refresh_Click(object? sender, RoutedEventArgs e)
    {
        try
        {
            await Vm.RefreshAsync();
        }
        catch (Exception ex)
        {
            Vm.Status = ex.Message;
        }
    }

    private void Gateway_Click(object? sender, RoutedEventArgs e) => Vm.UseGateway();

    private void ClearPassword_Click(object? sender, RoutedEventArgs e)
    {
        PasswordBox.Text = "";
        Vm.ClearPassword();
    }

    private async void Disconnect_Click(object? sender, RoutedEventArgs e) => await Run(Vm.DisconnectAsync);
    private async void Block_Click(object? sender, RoutedEventArgs e) => await Run(Vm.BlockAsync);
    private async void Unblock_Click(object? sender, RoutedEventArgs e) => await Run(Vm.UnblockAsync);
    private async void Reconnect_Click(object? sender, RoutedEventArgs e) => await Run(Vm.AllowReconnectAsync);
    private async void Prioritize_Click(object? sender, RoutedEventArgs e) => await Run(Vm.PrioritizeAsync);
    private async void ClearPriority_Click(object? sender, RoutedEventArgs e) => await Run(Vm.ClearPriorityAsync);
    private async void Wake_Click(object? sender, RoutedEventArgs e) => await Run(Vm.WakeAsync);

    private async Task Run(Func<Task> action)
    {
        try
        {
            await action();
        }
        catch (Exception ex)
        {
            Vm.Status = ex.Message;
        }
    }
}
