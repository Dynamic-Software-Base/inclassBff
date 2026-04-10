using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using System.Net.Http.Headers;

namespace InClassBff.Api.Auth;

public class TokenRefreshService
{
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly IOptionsSnapshot<OpenIdConnectOptions> _oidcOptions;
    private readonly ILogger<TokenRefreshService> _logger;

    // Refresh when less than this time remains on the access token
    private static readonly TimeSpan RefreshBuffer = TimeSpan.FromMinutes(1);

    public TokenRefreshService(
        IHttpClientFactory httpClientFactory,
        IOptionsSnapshot<OpenIdConnectOptions> oidcOptions,
        ILogger<TokenRefreshService> logger)
    {
        _httpClientFactory = httpClientFactory;
        _oidcOptions = oidcOptions;
        _logger = logger;
    }

    /// <summary>
    /// Checks if the access token is about to expire and refreshes it if needed.
    /// Returns true if the session was updated and needs to be re-signed in.
    /// </summary>
    public async Task<bool> TryRefreshTokensAsync(HttpContext httpContext)
    {
        var authenticateResult = await httpContext.AuthenticateAsync(
            CookieAuthenticationDefaults.AuthenticationScheme);

        if (!authenticateResult.Succeeded || authenticateResult.Properties == null)
            return false;

        var properties = authenticateResult.Properties;

        // Check access token expiry
        var expiresAt = properties.GetTokenValue("expires_at");
        if (!DateTimeOffset.TryParse(expiresAt, out var expiresAtOffset))
            return false;

        // Still fresh — no refresh needed
        if (expiresAtOffset > DateTimeOffset.UtcNow.Add(RefreshBuffer))
            return false;

        var refreshToken = properties.GetTokenValue("refresh_token");
        if (string.IsNullOrEmpty(refreshToken))
        {
            _logger.LogWarning("Access token expired but no refresh token available.");
            return false;
        }

        _logger.LogInformation("Access token expiring at {ExpiresAt}, refreshing...", expiresAt);

        try
        {
            var oidcOptions = _oidcOptions.Get(OpenIdConnectDefaults.AuthenticationScheme);

            // Discover the token endpoint
            var configManager = oidcOptions.ConfigurationManager
                ?? throw new InvalidOperationException("OIDC ConfigurationManager is null.");
            var oidcConfig = await configManager
                .GetConfigurationAsync(httpContext.RequestAborted);

            var tokenEndpoint = oidcConfig.TokenEndpoint;

            using var client = _httpClientFactory.CreateClient();

            // Set basic auth for client credentials
            var credentials = Convert.ToBase64String(
                System.Text.Encoding.UTF8.GetBytes(
                    $"{oidcOptions.ClientId}:{oidcOptions.ClientSecret}"));
            client.DefaultRequestHeaders.Authorization =
                new AuthenticationHeaderValue("Basic", credentials);

            var tokenResponse = await client.PostAsync(tokenEndpoint,
                new FormUrlEncodedContent(new Dictionary<string, string>
                {
                    ["grant_type"] = "refresh_token",
                    ["refresh_token"] = refreshToken,
                    ["client_id"] = oidcOptions.ClientId!,
                }));

            if (!tokenResponse.IsSuccessStatusCode)
            {
                var error = await tokenResponse.Content.ReadAsStringAsync();
                _logger.LogWarning("Token refresh failed ({Status}): {Error}",
                    tokenResponse.StatusCode, error);
                return false;
            }

            var tokenJson = await tokenResponse.Content.ReadFromJsonAsync<TokenRefreshResponse>();
            if (tokenJson is null) return false;

            // Update the stored tokens in the auth properties
            properties.UpdateTokenValue("access_token", tokenJson.AccessToken);
            properties.UpdateTokenValue("expires_at",
                DateTimeOffset.UtcNow
                    .AddSeconds(tokenJson.ExpiresIn)
                    .ToString("o")); // ISO 8601

            if (!string.IsNullOrEmpty(tokenJson.RefreshToken))
                properties.UpdateTokenValue("refresh_token", tokenJson.RefreshToken);

            if (!string.IsNullOrEmpty(tokenJson.IdToken))
                properties.UpdateTokenValue("id_token", tokenJson.IdToken);

            // Persist the updated ticket back to the session store
            await httpContext.SignInAsync(
                CookieAuthenticationDefaults.AuthenticationScheme,
                authenticateResult.Principal!,
                properties);

            _logger.LogInformation("Token refreshed successfully.");
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Exception during token refresh.");
            return false;
        }
    }

    private sealed record TokenRefreshResponse(
        [property: System.Text.Json.Serialization.JsonPropertyName("access_token")]
        string AccessToken,
        [property: System.Text.Json.Serialization.JsonPropertyName("expires_in")]
        int ExpiresIn,
        [property: System.Text.Json.Serialization.JsonPropertyName("refresh_token")]
        string? RefreshToken,
        [property: System.Text.Json.Serialization.JsonPropertyName("id_token")]
        string? IdToken
    );
}