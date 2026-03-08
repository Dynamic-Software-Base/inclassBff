using System.Net.Http.Json;
using System.Security.Claims;
using InClass.Client.Auth;
using Microsoft.AspNetCore.Components.Authorization;

namespace inclass.Client.Auth;

public class BffAuthStateProvider : AuthenticationStateProvider
{
    private readonly HttpClient _http;
    private static readonly AuthenticationState _anonymous =
        new(new ClaimsPrincipal(new ClaimsIdentity()));

    public BffAuthStateProvider(IHttpClientFactory factory)
    {
        _http = factory.CreateClient("BffClient");
    }

    public override async Task<AuthenticationState> GetAuthenticationStateAsync()
    {
        try
        {
            var me = await _http.GetFromJsonAsync<MeResponse>("auth/me"); // no leading /
            if (me?.IsAuthenticated == true)
            {
                var claims = new List<Claim>
                {
                    new(ClaimTypes.NameIdentifier, me.Id ?? ""),
                    new(ClaimTypes.Name, me.FullName ?? ""),
                    new(ClaimTypes.Email, me.Email ?? ""),
                };

                foreach (var role in me.Roles)
                    claims.Add(new(ClaimTypes.Role, role));

                return new AuthenticationState(new ClaimsPrincipal(new ClaimsIdentity(claims, "BffCookie")));
            }
        }
        catch { }

        return _anonymous;
    }
}