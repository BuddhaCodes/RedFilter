using Avalonia.Controls;
using Avalonia.Interactivity;
using RedFilter.ViewModels;

namespace RedFilter.Views;

public partial class GameModeView : UserControl
{
    public GameModeView()
    {
        InitializeComponent();
    }

    private async void Toggle_Click(object? sender, RoutedEventArgs e)
    {
        if (DataContext is GameModeViewModel vm)
            await vm.ToggleAsync();
    }
}
