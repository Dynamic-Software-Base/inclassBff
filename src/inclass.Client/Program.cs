using Microsoft.AspNetCore.Components.Web;
using Microsoft.AspNetCore.Components.WebAssembly.Hosting;
using inclass.Client;
using inclass.Client.Auth;
using InClass.Client.Auth;
using inclass.Client.Services;
using Microsoft.AspNetCore.Components.Authorization;

var builder = WebAssemblyHostBuilder.CreateDefault(args);
builder.RootComponents.Add<App>("#app");
builder.RootComponents.Add<HeadOutlet>("head::after");

var bffBaseUrl = builder.Configuration["BffBaseUrl"] 
                 ?? builder.HostEnvironment.BaseAddress;

builder.Services.AddHttpClient("BffClient", client =>
{
    client.BaseAddress = new Uri(bffBaseUrl);
});

builder.Services.AddSchoolService(builder.Configuration);
builder.Services.AddAuthorizationCore();

await builder.Build().RunAsync();