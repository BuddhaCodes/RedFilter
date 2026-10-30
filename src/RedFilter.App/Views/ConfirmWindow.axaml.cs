using Avalonia.Controls;
using Avalonia.Interactivity;

namespace RedFilter.Views;

public partial class ConfirmWindow : Window
{
    public ConfirmWindow()
    {
        InitializeComponent();
    }

    public ConfirmWindow(string message, bool okOnly = false) : this()
    {
        MessageText.Text = message;
        CancelButton.IsVisible = !okOnly;
    }

    private void Ok_Click(object? sender, RoutedEventArgs e) => Close(true);

    private void Cancel_Click(object? sender, RoutedEventArgs e) => Close(false);
}
