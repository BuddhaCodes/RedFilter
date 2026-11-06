using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Interactivity;
using RedFilter.ViewModels;

namespace RedFilter.Views;

public partial class WifiView : UserControl
{
    public WifiView()
    {
        InitializeComponent();
    }

    private WifiViewModel? Vm => DataContext as WifiViewModel;

    private async void Connect_Click(object? sender, RoutedEventArgs e) => await ConnectAsync();

    private async void Password_KeyDown(object? sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter)
            await ConnectAsync();
    }

    private async Task ConnectAsync()
    {
        if (Vm == null)
            return;
        var password = PasswordBox.Text ?? "";
        await Vm.ConnectAsync(password, RememberBox.IsChecked == true);
        if (Vm.Connected)
            PasswordBox.Text = "";
    }

    private async void Refresh_Click(object? sender, RoutedEventArgs e)
    {
        if (Vm != null)
            await Vm.RefreshAsync();
    }

    private void Forget_Click(object? sender, RoutedEventArgs e) => Vm?.ForgetPassword();

    private async void Block_Click(object? sender, RoutedEventArgs e)
    {
        if (Vm != null && (sender as Control)?.Tag is WifiDeviceRow row)
            await Vm.BlockAsync(row);
    }

    private async void Unblock_Click(object? sender, RoutedEventArgs e)
    {
        if (Vm != null && (sender as Control)?.Tag is WifiDeviceRow row)
            await Vm.UnblockAsync(row);
    }
}
