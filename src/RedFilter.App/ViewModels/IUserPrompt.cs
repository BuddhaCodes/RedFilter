namespace RedFilter.ViewModels;

public interface IUserPrompt
{
    Task<bool> ConfirmAsync(string message);

    /// <summary>Shows a message with one button per option and returns the chosen index, or -1 when closed.</summary>
    Task<int> ChooseAsync(string message, IReadOnlyList<string> options);

    /// <summary>Asks for one line of text, such as a password. Returns null when cancelled.</summary>
    Task<string?> AskTextAsync(string message, bool secret);
}
