using Avalonia.Controls;
using Avalonia.Controls.Primitives.PopupPositioning;
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


    private async void ClearList_Click(object? sender, RoutedEventArgs e)
    {
        if (Vm != null)
            await Vm.ClearSavedListAsync();
    }

    /// <summary>The undo button on the row: unblock, or remove the speed limit.</summary>
    private async void Primary_Click(object? sender, RoutedEventArgs e)
    {
        if (Vm == null || (sender as Control)?.Tag is not WifiDeviceRow row)
            return;
        if (row.CanUnblock)
            await Vm.UnblockAsync(row);
        else if (row.CanRemoveLimit)
            await Vm.RemoveLimitAsync(row);
    }

    /// <summary>
    /// The "⋯" menu, built for the row that was clicked so it only offers what makes sense for that
    /// device (no "Bloquear" on this PC, no "Limitar" while the Dota 2 mode manages the limits).
    /// </summary>
    private void Menu_Click(object? sender, RoutedEventArgs e)
    {
        if (Vm == null || sender is not Control button || button.Tag is not WifiDeviceRow row)
            return;
        var vm = Vm;
        var menu = new MenuFlyout { Placement = PlacementMode.BottomEdgeAlignedRight };
        void Add(string header, bool show, Func<Task> action)
        {
            if (!show)
                return;
            var item = new MenuItem { Header = header };
            item.Click += async (_, _) => await action();
            menu.Items.Add(item);
        }

        Add("Limitar velocidad…", row.CanLimit, () => vm.LimitAsync(row));
        Add("Bloquear del Wi-Fi…", row.CanBlock, () => vm.BlockAsync(row));
        Add("Quitar de la lista de bloqueo", row.CanForget, () => vm.UnblockAsync(row));
        if (menu.Items.Count > 0)
            menu.ShowAt(button);
    }



    private async void Unblock_Click(object? sender, RoutedEventArgs e)
    {
        if (Vm != null && (sender as Control)?.Tag is WifiDeviceRow row)
            await Vm.UnblockAsync(row);
    }
}
