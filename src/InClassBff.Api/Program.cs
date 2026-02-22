using System.Net.Http.Headers;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Yarp.ReverseProxy.Transforms;

var builder = WebApplication.CreateBuilder(args);
var allowedCorsOrigins = ParseOrigins(builder.Configuration["AllowedCorsOrigins"]);
builder.Services.AddDataProtection()
    .PersistKeysToFileSystem(new DirectoryInfo("/home/DataProtectionKeys"))
    .SetApplicationName("inclass-bff");
builder.WebHost.ConfigureKestrel(options =>
{
    options.Limits.MaxRequestHeadersTotalSize = 65536; // 64KB
});
builder.Services.AddCors(options =>
{
    options.AddPolicy("Angular", policy =>
    {
        policy
            .WithOrigins(allowedCorsOrigins)
            .AllowAnyHeader()
            .AllowAnyMethod()
            .AllowCredentials();
    });
});

builder.Services.AddAuthentication(options =>
{
    options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
})
.AddCookie(options =>
{
    options.Cookie.Name = "inclass.session";
    options.Cookie.HttpOnly = true;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    options.Cookie.SameSite = SameSiteMode.None;
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
    options.SaveTokens = false;
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
});

builder.Services.AddAuthorization();

builder.Services.AddReverseProxy()
    .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"))
    .AddTransforms(transformBuilder =>
    {
        transformBuilder.AddRequestTransform(async context =>
        {
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

app.UseCors("Angular");
app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/", () => Results.Ok(new { status = "ok" })).AllowAnonymous();
app.MapGet("/health", () => Results.Ok(new { status = "healthy" })).AllowAnonymous();
app.MapGet("/debug/config", (IConfiguration config) => new {
    AllowedCorsOrigins = config["AllowedCorsOrigins"],
    Environment = Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT")
});
app.MapReverseProxy().RequireAuthorization();
app.MapControllers();

app.Run();

static string[] ParseOrigins(string? configuredOrigins)
{
    var origins = (configuredOrigins ?? string.Empty)
        .Split([',', ';'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
        .Select(origin => origin.TrimEnd('/'))
        .Where(origin => Uri.TryCreate(origin, UriKind.Absolute, out _))
        .Distinct(StringComparer.OrdinalIgnoreCase)
        .ToArray();

    if (origins.Length == 0)
    {
        throw new InvalidOperationException(
            "AllowedCorsOrigins must contain at least one absolute origin URL.");
    }

    return origins;
}
