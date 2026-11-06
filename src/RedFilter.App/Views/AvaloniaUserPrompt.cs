using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.ApplicationLifetimes;
using RedFilter.ViewModels;

namespace RedFilter.Views;

public sealed class AvaloniaUserPrompt : IUserPrompt
{
    public async Task<bool> ConfirmAsync(string message) =>
        await ChooseAsync(message, new[] { "Cancelar", "Aceptar" }) == 1;

    public async Task<int> ChooseAsync(string message, IReadOnlyList<string> options)
    {
        var owner = Owner();
        if (owner == null)
            return -1;
        return await new ConfirmWindow(message, options).ShowDialog<int?>(owner) ?? -1;
    }

    public async Task<string?> AskTextAsync(string message, bool secret)
    {
        var owner = Owner();
        if (owner == null)
            return null;
        var window = new ConfirmWindow(message, new[] { "Cancelar", "Aceptar" }, askText: true, secret: secret);
        var choice = await window.ShowDialog<int?>(owner);
        return choice == 1 ? window.Text : null;
    }

    private static Window? Owner() =>
        (Application.Current?.ApplicationLifetime as IClassicDesktopStyleApplicationLifetime)?.MainWindow;
}
