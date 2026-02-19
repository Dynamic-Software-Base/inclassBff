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
    // ── LOGIN ────────────────────────────────────────────────────────────────
    // Angular calls this to initiate login
    // BFF redirects browser to Keycloak login page
    [HttpGet("login")]
    public IActionResult Login(string? returnUrl = null)
    {
        // After Keycloak → BFF callback completes, redirect to Angular
        var angularReturnUrl = returnUrl ?? "http://localhost:4200";
    
        return Challenge(new AuthenticationProperties
        {
            RedirectUri = $"/auth/post-login?returnUrl={Uri.EscapeDataString(angularReturnUrl)}"
        }, OpenIdConnectDefaults.AuthenticationScheme);
    }

    [HttpGet("post-login")]
    [Authorize]
    public IActionResult PostLogin(string? returnUrl = null)
    {
        // Validate returnUrl to only allow your Angular origin
        var allowedOrigins = new[] { "http://localhost:4200" };
    
        if (!string.IsNullOrEmpty(returnUrl) && 
            allowedOrigins.Any(o => returnUrl.StartsWith(o, StringComparison.OrdinalIgnoreCase)))
        {
            return Redirect(returnUrl);
        }

        return Redirect("http://localhost:4200");
    }

    // ── LOGOUT ───────────────────────────────────────────────────────────────
    // Clears local session AND logs out of Keycloak (SSO logout)
    [HttpPost("logout")]
    [Authorize]
    public IActionResult Logout()
    {
        return SignOut(
            new AuthenticationProperties
            {
                RedirectUri = "/"
            },
            CookieAuthenticationDefaults.AuthenticationScheme,
            OpenIdConnectDefaults.AuthenticationScheme
        );
    }

    // ── ME ───────────────────────────────────────────────────────────────────
    // Angular calls this on startup to check if user is authenticated
    // Returns user info + roles without exposing the token
    [HttpGet("me")]
    public IActionResult Me()
    {
        if (!(User.Identity?.IsAuthenticated ?? false))
            return Unauthorized();

        var roles = User.FindAll(ClaimTypes.Role).Select(r => r.Value).ToList();

        return Ok(new
        {
            id = User.FindFirstValue(ClaimTypes.NameIdentifier), // sub
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

}