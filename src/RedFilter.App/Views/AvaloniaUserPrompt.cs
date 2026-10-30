using Avalonia;
using Avalonia.Controls.ApplicationLifetimes;
using RedFilter.ViewModels;

namespace RedFilter.Views;

public sealed class AvaloniaUserPrompt : IUserPrompt
{
    public async Task<bool> ConfirmAsync(string message)
    {
        var owner = (Application.Current?.ApplicationLifetime as IClassicDesktopStyleApplicationLifetime)?.MainWindow;
        if (owner == null)
            return false;
        return await new ConfirmWindow(message).ShowDialog<bool>(owner);
    }
}
