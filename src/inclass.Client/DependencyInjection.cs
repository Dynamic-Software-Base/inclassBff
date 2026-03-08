using inclass.Client.Auth;
using inclass.Client.Services;
using inclass.Client.Services.Api;
using Microsoft.AspNetCore.Components.Authorization;

namespace inclass.Client;

public static class DependencyInjection
{
    public static IServiceCollection AddSchoolService(this IServiceCollection services, IConfiguration configuration) =>
        services.AddServices();
            


    private static IServiceCollection AddServices(this IServiceCollection services)
    {
        services.AddScoped<ApiClient>();
        services.AddScoped<SchoolService>();
        services.AddScoped<FileService>();
        services.AddScoped<AuthenticationStateProvider, BffAuthStateProvider>();
        services.AddScoped<AuthService>();
        return services;
    }
}