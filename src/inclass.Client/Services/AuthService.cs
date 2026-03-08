using System.Net.Http.Json;
using Contract.InClass.Request.Auth;

namespace inclass.Client.Services;

public class AuthService
{
    private readonly HttpClient _http;

    public AuthService(IHttpClientFactory factory)
    {
        _http = factory.CreateClient("BffClient");
    }

    public async Task<ErrorOr<CurrentUser?>> GetCurrentUserAsync()
    {
        try
        {
            return await _http.GetFromJsonAsync<CurrentUser>("/api/auth-test/me");
        }
        catch (Exception e)
        {
            return Error.Failure("GetCurrentUserAsync", e.Message);
        }
        
    }
    
}

