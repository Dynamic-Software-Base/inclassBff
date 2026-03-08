using System.Net.Http.Json;
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

    public Task<ApiResponse<T>> PostAsync<T>(string url, object body) =>
        SendAsync<T>(HttpMethod.Post, url, body);

    public Task<ApiResponse<T>> PutAsync<T>(string url, object body) =>
        SendAsync<T>(HttpMethod.Put, url, body);

    public Task<ApiResponse<T>> DeleteAsync<T>(string url) =>
        SendAsync<T>(HttpMethod.Delete, url);
    private async Task<ApiResponse<T>> SendAsync<T>(HttpMethod method, string url, object? body = null)
    {
        try
        {
            var request = new HttpRequestMessage(method, url);
            if (body != null)
            {
                request.Content = JsonContent.Create(body);
            }
            
            var response = await _httpClient.SendAsync(request);
            var content = await response.Content.ReadFromJsonAsync<ApiResponse<T>>();
            return content ?? ApiResponse<T>.Failure([new ApiError
            {
                Code = "Deserialization.Failed",
                Message = "Could not parse server response.",
                Type = ApiErrorType.System
            }]);
        }
        catch (Exception e)
        {
            return ApiResponse<T>.Failure([
                new ApiError
                {
                    Code = "Network.Error",
                    Message = e.Message,
                    Type = ApiErrorType.System
                }
            ]);
        }
    }
}