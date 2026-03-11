using Contract.InClass.ApiContract;

namespace inclass.Client.Services;

public class ApiResultHandler
{
    private readonly ToastService _toast;

    public ApiResultHandler(ToastService toast)
    {
        _toast = toast;
    }

    public T? Handle<T>(ApiResponse<T> response, string? successMessage = null)
    {
        if (response.IsSuccess)
        {
            if(successMessage != null)
                _toast.Success(successMessage);
            return response.Data;
        }

        if (response.Errors is { Length: > 0 })
        {
            foreach (var error in response.Errors)
            {
                _toast.Error(error.Message);
            }
        }
        else
        {
            _toast.Error("An unexpected error occured");
        }

        return default;

    }
}