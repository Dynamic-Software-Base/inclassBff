using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace InClassBff.Api.Auth;

[ApiController]
[Route("auth")]
public class AuthController : ControllerBase
{
    private readonly string[] _allowedOrigins;

    public AuthController(IConfiguration configuration)
    {
        _allowedOrigins = ParseOrigins(configuration["AllowedCorsOrigins"]);
    }

    [HttpGet("login")]
    public IActionResult Login(string? returnUrl = null)
    {
        var angularReturnUrl = returnUrl ?? _allowedOrigins[0];

        return Challenge(new AuthenticationProperties
        {
            RedirectUri = $"/auth/post-login?returnUrl={Uri.EscapeDataString(angularReturnUrl)}"
        }, OpenIdConnectDefaults.AuthenticationScheme);
    }

    [HttpGet("post-login")]
    [Authorize]
    public IActionResult PostLogin(string? returnUrl = null)
    {
        if (!string.IsNullOrEmpty(returnUrl) &&
            _allowedOrigins.Any(o => returnUrl.StartsWith(o, StringComparison.OrdinalIgnoreCase)))
        {
            return Redirect(returnUrl);
        }

        return Redirect(_allowedOrigins[0]);
    }

    [HttpPost("logout")]
    [Authorize]
    public IActionResult Logout()
    {
        return SignOut(
            new AuthenticationProperties
            {
                RedirectUri = _allowedOrigins[0]
            },
            CookieAuthenticationDefaults.AuthenticationScheme,
            OpenIdConnectDefaults.AuthenticationScheme
        );
    }

    [HttpGet("me")]
    public IActionResult Me()
    {
        if (!(User.Identity?.IsAuthenticated ?? false))
            return Unauthorized();

        var roles = User.FindAll(ClaimTypes.Role).Select(r => r.Value).ToList();

        return Ok(new
        {
            id = User.FindFirstValue(ClaimTypes.NameIdentifier),
            email = User.FindFirstValue(ClaimTypes.Email),
            fullName = User.FindFirstValue("name")
                       ?? $"{User.FindFirstValue("given_name")} {User.FindFirstValue("family_name")}".Trim(),
            roles,
            isAuthenticated = true
        });
    }

    [HttpGet("claims")]
    public IActionResult ClaimsDump()
    {
        return Ok(User.Claims.Select(c => new { c.Type, c.Value }));
    }

    private static string[] ParseOrigins(string? configuredOrigins)
    {
        var origins = (configuredOrigins ?? string.Empty)
            .Split([',', ';'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(origin => origin.TrimEnd('/'))
            .Where(origin => Uri.TryCreate(origin, UriKind.Absolute, out _))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

        return origins.Length == 0 ? ["http://localhost:4200"] : origins;
    }
}
