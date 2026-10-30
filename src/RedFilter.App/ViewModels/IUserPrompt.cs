namespace RedFilter.ViewModels;

public interface IUserPrompt
{
    Task<bool> ConfirmAsync(string message);
}
