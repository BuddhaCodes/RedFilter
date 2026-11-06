using Avalonia.Controls;
using Avalonia.Input;

namespace RedFilter.Views;

public partial class ConfirmWindow : Window
{
    public ConfirmWindow()
    {
        InitializeComponent();
    }

    /// <param name="options">Button labels from left to right. The last one is the default (Enter); closing the window returns -1.</param>
    public ConfirmWindow(string message, IReadOnlyList<string> options, bool askText = false, bool secret = false) : this()
    {
        MessageText.Text = message;
        InputBox.IsVisible = askText;
        if (secret)
            InputBox.PasswordChar = '●';
        for (var i = 0; i < options.Count; i++)
        {
            var index = i;
            var button = new Button { Content = options[i], MinWidth = 104, Margin = new Avalonia.Thickness(8, 0, 0, 0) };
            if (i == options.Count - 1)
            {
                button.Classes.Add("accent");
                button.IsDefault = true;
            }

            button.Click += (_, _) => Close(index);
            Buttons.Children.Add(button);
        }

        Opened += (_, _) =>
        {
            if (askText)
                InputBox.Focus();
        };
        KeyDown += (_, e) =>
        {
            if (e.Key == Key.Escape)
                Close(-1);
        };
    }

    public string Text => InputBox.Text ?? "";

    // Used by the unhandled-exception handler: one OK button.
    public ConfirmWindow(string message, bool okOnly) : this(message, okOnly ? new[] { "Aceptar" } : new[] { "Cancelar", "Aceptar" })
    {
    }
}
