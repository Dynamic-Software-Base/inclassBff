using System.Net.Http.Headers;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Yarp.ReverseProxy.Transforms;

var builder = WebApplication.CreateBuilder(args);

// ── CORS ────────────────────────────────────────────────────────────────────
builder.Services.AddCors(options =>
{
    options.AddPolicy("Angular", policy =>
    {
        policy
            .WithOrigins(builder.Configuration["AllowedCorsOrigins"]!)
            .AllowAnyHeader()
            .AllowAnyMethod()
            .AllowCredentials(); // Required for cookies
    });
});

// ── AUTHENTICATION ───────────────────────────────────────────────────────────
builder.Services.AddAuthentication(options =>
{
    options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
})
.AddCookie(options =>
{
    options.Cookie.Name = "inclass.session";
    options.Cookie.HttpOnly = true;       // JS cannot read this cookie
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    options.Cookie.SameSite = SameSiteMode.Lax;
    options.ExpireTimeSpan = TimeSpan.FromHours(8);
    options.SlidingExpiration = true;

    // Return 401 instead of redirecting to login for API calls
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
    options.SaveTokens = true;
    options.GetClaimsFromUserInfoEndpoint = true;
    options.RequireHttpsMetadata = !builder.Environment.IsDevelopment();

    // Scopes we configured in Keycloak
    options.Scope.Clear();
    options.Scope.Add("openid");
    options.Scope.Add("profile");
    options.Scope.Add("email");
    options.Scope.Add("inclass-roles");
    options.Scope.Add("inclass-profile");

    // Where Keycloak redirects after login
    options.CallbackPath = "/auth/callback";

    // Where Keycloak redirects after logout
    options.SignedOutCallbackPath = "/auth/signout-callback";

    // After logout, redirect user to Angular
    options.SignedOutRedirectUri = builder.Configuration["AllowedCorsOrigins"];

    options.TokenValidationParameters.NameClaimType = "preferred_username";
    options.TokenValidationParameters.RoleClaimType = "roles";
});

// ── AUTHORIZATION ─────────────────────────────────────────────────────────
builder.Services.AddAuthorization();

// ── REVERSE PROXY ────────────────────────────────────────────────────────────
builder.Services.AddReverseProxy()
    .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"))
    .AddTransforms(transformBuilder =>
    {
        // For every proxied request, attach the user's access token as Bearer
        transformBuilder.AddRequestTransform(async context =>
        {
            var accessToken = await context.HttpContext
                .GetTokenAsync("access_token");

            if (!string.IsNullOrEmpty(accessToken))
            {
                context.ProxyRequest.Headers.Authorization =
                    new AuthenticationHeaderValue("Bearer", accessToken);
            }
        });
    });

builder.Services.AddControllers();

var app = builder.Build();

// ── MIDDLEWARE PIPELINE ───────────────────────────────────────────────────────
app.UseCors("Angular");
app.UseAuthentication();
app.UseAuthorization();

// Protect all /api/* routes — user must be authenticated
app.MapReverseProxy().RequireAuthorization();

app.MapControllers();

app.Run();