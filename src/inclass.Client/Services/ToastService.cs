using System.Runtime.Serialization;

namespace inclass.Client.Services;

public class ToastNotification
{
    public Guid Id { get; } = Guid.NewGuid();
    public string Message { get; init; } = "";
    public string? Title { get; init; }
    public ToastType Type { get; init; }
    public int DurationMs { get; init; } = 4000;
}

public enum ToastType{Success,Error,Warning,Info}

public class ToastService
{
    public event Action<ToastNotification>? OnToast;
    public void Success(string message, string? title = null) =>
        Emit(message, title, ToastType.Success);

    public void Error(string message, string? title = null) =>
        Emit(message, title, ToastType.Error);

    public void Warning(string message, string? title = null) =>
        Emit(message, title, ToastType.Warning);

    private void Emit(string message, string? title, ToastType type) =>
        OnToast?.Invoke(new ToastNotification { Message = message, Title = title, Type = type });
}