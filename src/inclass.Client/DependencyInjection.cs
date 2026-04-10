using inclass.Client.Auth;
using inclass.Client.Services;
using inclass.Client.Services.Api;
using inclass.Client.Services.Registration;
using inclass.Client.Services.Schema;
using inclass.Client.Services.Schools;
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
        services.AddSingleton<SchoolContextService>();
        services.AddScoped<SchemaService>();
        services.AddScoped<EnrollmentService>();
        services.AddScoped<AuthenticationStateProvider, BffAuthStateProvider>();
        services.AddScoped<AuthService>();
        services.AddScoped<SchoolClassService>();
        services.AddScoped<RegistrationSessionService>();
        services.AddScoped<EducationalSystemService>();
        services.AddSingleton<ToastService>();
        services.AddScoped<ApiResultHandler>();
        return services;
    }
}