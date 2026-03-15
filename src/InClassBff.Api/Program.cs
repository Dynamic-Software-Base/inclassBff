using System.Net.Http.Headers;
using System.Security.Claims;
using InClassBff.Api.Proxy;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Yarp.ReverseProxy.Transforms;

var builder = WebApplication.CreateBuilder(args);
var allowedCorsOrigins = ParseOrigins(builder.Configuration["AllowedCorsOrigins"]);

// ── Memory Cache + Ticket Store ────────────────────────────────────────────────
// IMPORTANT: Register IMemoryCache before InMemoryTicketStore
builder.Services.AddMemoryCache();
builder.Services.AddSingleton<InMemoryTicketStore>();

// ── Authentication ─────────────────────────────────────────────────────────────
builder.Services.AddAuthentication(options =>
{
    options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
})
.AddCookie(options =>
{
    options.Cookie.Name = "inclass.session";
    options.Cookie.HttpOnly = true;
    options.Cookie.SecurePolicy = builder.Environment.IsDevelopment()
        ? CookieSecurePolicy.SameAsRequest
        : CookieSecurePolicy.Always;
    options.Cookie.SameSite = SameSiteMode.Lax; 
    options.Cookie.Path = "/";
    options.ExpireTimeSpan = TimeSpan.FromHours(8);
    options.SlidingExpiration = true;

    options.Events.OnRedirectToLogin = context =>
    {
        context.Response.StatusCode = StatusCodes.Status401Unauthorized;
        return Task.CompletedTask;
    };
    options.Events.OnRedirectToAccessDenied = context =>
    {
        context.Response.StatusCode = StatusCodes.Status403Forbidden;
        return Task.CompletedTask;
    };
})
.AddOpenIdConnect(options =>
{
    var keycloakConfig = builder.Configuration.GetSection("Keycloak");

    options.Authority = keycloakConfig["Authority"];
    options.ClientId = keycloakConfig["ClientId"];
    options.ClientSecret = keycloakConfig["ClientSecret"];
    options.ResponseType = OpenIdConnectResponseType.Code;
    options.SaveTokens = true; // Must be true so GetTokenAsync works in YARP transform
    options.GetClaimsFromUserInfoEndpoint = true;
    options.RequireHttpsMetadata = !builder.Environment.IsDevelopment();

    options.Scope.Clear();
    options.Scope.Add("openid");
    options.Scope.Add("profile");
    options.Scope.Add("email");
    options.Scope.Add("inclass-roles");
    options.Scope.Add("inclass-profile");

    options.CallbackPath = "/auth/callback";
    options.SignedOutCallbackPath = "/auth/signout-callback";
    options.SignedOutRedirectUri = allowedCorsOrigins[0];

    options.TokenValidationParameters.NameClaimType = "preferred_username";
    options.TokenValidationParameters.RoleClaimType = "roles";

    options.Events = new OpenIdConnectEvents
    {
        OnTokenValidated = context =>
        {
            // Trim unnecessary claims to keep ticket small
            var identity = context.Principal?.Identity as ClaimsIdentity;
            if (identity != null)
            {
                var claimsToRemove = identity.Claims
                    .Where(c =>
                        c.Type == "at_hash" ||
                        c.Type == "sid" ||
                        c.Type == "nonce" ||
                        c.Type == "s_hash" ||
                        c.Type == "aio" ||
                        c.Type == "uti")
                    .ToList();

                foreach (var claim in claimsToRemove)
                    identity.RemoveClaim(claim);
            }
            return Task.CompletedTask;
        }
    };
});

// ── Wire up SessionStore via PostConfigure ─────────────────────────────────────
// Cannot use `app` variable here (not built yet), so PostConfigure is the correct approach
builder.Services
    .AddOptions<CookieAuthenticationOptions>(CookieAuthenticationDefaults.AuthenticationScheme)
    .PostConfigure<InMemoryTicketStore>((options, ticketStore) =>
    {
        options.SessionStore = ticketStore;
    });

// ── Authorization ──────────────────────────────────────────────────────────────
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("ApiAuth", policy => policy.RequireAuthenticatedUser());
});

// ── YARP Reverse Proxy ─────────────────────────────────────────────────────────
builder.Services.AddReverseProxy()
    .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"))
    .AddTransforms(transformBuilder =>
    {
        transformBuilder.AddRequestTransform(async context =>
        {
            // Skip token injection for anonymous public routes
            if (context.HttpContext.Request.Path.StartsWithSegments("/public"))
                return;

            var accessToken = await context.HttpContext.GetTokenAsync("access_token");
            if (!string.IsNullOrEmpty(accessToken))
            {
                context.ProxyRequest.Headers.Authorization =
                    new AuthenticationHeaderValue("Bearer", accessToken);
            }
        });
    });
builder.Services.AddControllers();

var app = builder.Build();

app.UseHttpsRedirection();
app.UseBlazorFrameworkFiles();   // serves _framework/, _content/ etc.
app.UseStaticFiles();            // serves everything else in wwwroot

app.UseRouting();  
// ── Middleware pipeline ────────────────────────────────────────────────────────

app.UseAuthentication();
app.UseAuthorization();
app.UseWebSockets();
app.MapGet("/health", () => Results.Ok(new { status = "healthy" })).AllowAnonymous();
app.MapGet("/debug/config", (IConfiguration config) => new
{
    AllowedCorsOrigins = config["AllowedCorsOrigins"],
    Environment = Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT")
}).AllowAnonymous();
app.MapControllers();
app.MapReverseProxy();

app.MapFallbackToFile("index.html");
app.Run();

// ── Helpers ────────────────────────────────────────────────────────────────────
static string[] ParseOrigins(string? configuredOrigins)
{
    var origins = (configuredOrigins ?? string.Empty)
        .Split([',', ';'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
        .Select(origin => origin.TrimEnd('/'))
        .Where(origin => Uri.TryCreate(origin, UriKind.Absolute, out _))
        .Distinct(StringComparer.OrdinalIgnoreCase)
        .ToArray();

    if (origins.Length == 0)
        throw new InvalidOperationException(
            "AllowedCorsOrigins must contain at least one absolute origin URL.");

    return origins;
}
