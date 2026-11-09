using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.Shapes;
using Avalonia.Input;
using Avalonia.Interactivity;
using Avalonia.Media;
using RedFilter.ViewModels;

namespace RedFilter;

public partial class MainWindow : Window
{
    private const string MaximizeGeometry = "M0.5,0.5 L9.5,0.5 L9.5,9.5 L0.5,9.5 Z";
    private const string RestoreGeometry = "M2.5,0.5 L9.5,0.5 L9.5,7.5 M0.5,2.5 L7.5,2.5 L7.5,9.5 L0.5,9.5 Z";

    public MainWindow()
    {
        InitializeComponent();
        PropertyChanged += (_, e) =>
        {
            if (e.Property == WindowStateProperty)
                UpdateMaximizeButton();
        };
    }

    public MainWindow(NetworkViewModel network, WifiViewModel wifi, GameModeViewModel game) : this()
    {
        PcPage.DataContext = network;
        WifiPage.DataContext = wifi;
        GamePage.DataContext = game;
        ModeBadge.DataContext = game;
        Opened += async (_, _) => await wifi.StartAsync();
        Closed += (_, _) =>
        {
            game.Dispose();
            network.Dispose();
            wifi.Dispose();
        };
    }

    // The title bar is marked with the TitleBar role, so Windows drags and maximizes it natively.
    // These handlers are the fallback for platforms that pass the clicks to the app instead.
    private void TitleBar_PointerPressed(object? sender, PointerPressedEventArgs e)
    {
        if (e.ClickCount == 1 && e.GetCurrentPoint(this).Properties.IsLeftButtonPressed)
            BeginMoveDrag(e);
    }

    private void TitleBar_DoubleTapped(object? sender, TappedEventArgs e) => ToggleMaximize();

    private void Minimize_Click(object? sender, RoutedEventArgs e) => WindowState = WindowState.Minimized;

    private void Maximize_Click(object? sender, RoutedEventArgs e) => ToggleMaximize();

    private void Close_Click(object? sender, RoutedEventArgs e) => Close();

    private void ToggleMaximize() =>
        WindowState = WindowState == WindowState.Maximized ? WindowState.Normal : WindowState.Maximized;

    private void UpdateMaximizeButton()
    {
        var maximized = WindowState == WindowState.Maximized;
        MaximizeIcon.Data = Geometry.Parse(maximized ? RestoreGeometry : MaximizeGeometry);
        ToolTip.SetTip(MaximizeButton, maximized ? "Restaurar" : "Maximizar");
    }
}
