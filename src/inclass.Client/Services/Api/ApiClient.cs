using System.Net.Http.Json;
using System.Text.Json;
using Contract.InClass.ApiContract;

namespace inclass.Client.Services.Api;

public class ApiClient
{
    private readonly HttpClient _httpClient;

    public ApiClient(IHttpClientFactory factory)
    {
        _httpClient = factory.CreateClient("BffClient");
    }
    public Task<ApiResponse<T>> GetAsync<T>(string url) =>
        SendAsync<T>(HttpMethod.Get, url);
    public Task<ApiResponse<T>> GetAsync<T>(string url,object body)=>
        SendAsync<T>(HttpMethod.Get, url, body);
    public Task<ApiResponse<T>> PostAsync<T>(string url, object body) =>
        SendAsync<T>(HttpMethod.Post, url, body);

    public Task<ApiResponse<T>> PutAsync<T>(string url, object body) =>
        SendAsync<T>(HttpMethod.Put, url, body);

    public Task<ApiResponse<T>> DeleteAsync<T>(string url) =>
        SendAsync<T>(HttpMethod.Delete, url);
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true
    };

    private async Task<ApiResponse<T>> SendAsync<T>(HttpMethod method, string url, object? body = null)
    {
        try
        {
            var finalUrl = url;

            if (body != null && (method == HttpMethod.Get || method == HttpMethod.Delete))
            {
                var queryString = ToQueryString(body);
                if (!string.IsNullOrEmpty(queryString))
                    finalUrl = $"{url}?{queryString}";
            }

            var request = new HttpRequestMessage(method, finalUrl);

            if (body != null && method != HttpMethod.Get && method != HttpMethod.Delete)
                request.Content = JsonContent.Create(body);

            var response = await _httpClient.SendAsync(request);
            var content  = await response.Content.ReadFromJsonAsync<ApiResponse<T>>(JsonOptions); // ← here
        
            return content ?? ApiResponse<T>.Failure([new ApiError
            {
                Code    = "Deserialization.Failed",
                Message = "Could not parse server response.",
                Type    = ApiErrorType.System
            }]);
        }
        catch (Exception e)
        {
            return ApiResponse<T>.Failure([new ApiError
            {
                Code    = "Network.Error",
                Message = e.Message,
                Type    = ApiErrorType.System
            }]);
        }
    }

private static string ToQueryString(object obj)
{
    var json       = JsonSerializer.Serialize(obj);
    var dictionary = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(json);
    if (dictionary is null) return string.Empty;

    var pairs = new List<string>();

    foreach (var (key, value) in dictionary)
    {
        if (value.ValueKind == JsonValueKind.Null) continue;

        if (value.ValueKind == JsonValueKind.Object)
        {
            // Flatten nested objects: GradeLevelOffering.HasPreSchool=true
            var nested = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(value.GetRawText());
            if (nested is null) continue;
            foreach (var (nestedKey, nestedValue) in nested)
            {
                if (nestedValue.ValueKind != JsonValueKind.Null)
                    pairs.Add($"{Uri.EscapeDataString(key)}.{Uri.EscapeDataString(nestedKey)}={Uri.EscapeDataString(nestedValue.ToString())}");
            }
        }
        else
        {
            pairs.Add($"{Uri.EscapeDataString(key)}={Uri.EscapeDataString(value.ToString())}");
        }
    }

    return string.Join("&", pairs);
}
}