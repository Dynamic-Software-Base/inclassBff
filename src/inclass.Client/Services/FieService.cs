using System.Net.Http.Json;
using Contract.InClass.ApiContract;
using Contract.InClass.Response.Files;
using inclass.Client.Services.Api;
using Microsoft.AspNetCore.Http;

namespace inclass.Client.Services;

public class FileService
{
    private readonly HttpClient _httpClient;

    public FileService(IHttpClientFactory factory)
    {
        _httpClient = factory.CreateClient("BffClient");
    }

    public async Task<ApiResponse<UploadFileResult>> UploadFile(IFormFile file, CancellationToken cancellationToken)
    {
        try
        {
            Console.WriteLine($"[FileService] Starting upload for: {file?.FileName ?? "NULL"}");
            
            if (file == null)
            {
                Console.WriteLine("[FileService] File is null!");
                return ApiResponse<UploadFileResult>.Failure([new ApiError
                {
                    Code = "File.Null",
                    Message = "File is null",
                    Type = ApiErrorType.Validation
                }]);
            }

            using var content = new MultipartFormDataContent();
            
            Console.WriteLine($"[FileService] Opening file stream...");
            var streamContent = new StreamContent(file.OpenReadStream());
            streamContent.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue(file.ContentType);
            
            Console.WriteLine($"[FileService] Adding file to form data...");
            content.Add(streamContent, "file", file.FileName);

            Console.WriteLine($"[FileService] Sending POST request to /api/File/upload...");
            var response = await _httpClient.PostAsync("/api/File/upload", content, cancellationToken);

            Console.WriteLine($"[FileService] Response status: {response.StatusCode}");
            
            if (response.IsSuccessStatusCode)
            {
                var result = await response.Content.ReadFromJsonAsync<ApiResponse<UploadFileResult>>(cancellationToken);
                Console.WriteLine($"[FileService] Upload successful: {result?.IsSuccess ?? false}");
                return result ?? ApiResponse<UploadFileResult>.Failure([new ApiError
                {
                    Code = "Deserialization.Failed",
                    Message = "Could not parse server response.",
                    Type = ApiErrorType.System
                }]);
            }
            else
            {
                var errorContent = await response.Content.ReadAsStringAsync(cancellationToken);
                Console.WriteLine($"[FileService] Upload failed: {errorContent}");
                
                return ApiResponse<UploadFileResult>.Failure([new ApiError
                {
                    Code = "Upload.Failed",
                    Message = $"Upload failed with status {response.StatusCode}: {errorContent}",
                    Type = ApiErrorType.System
                }]);
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[FileService] Exception: {ex.GetType().Name} - {ex.Message}");
            Console.WriteLine($"[FileService] StackTrace: {ex.StackTrace}");
            
            return ApiResponse<UploadFileResult>.Failure([new ApiError
            {
                Code = "Upload.Exception",
                Message = ex.Message,
                Type = ApiErrorType.System
            }]);
        }
    }

    public async Task<ApiResponse<List<UploadFileResult>>> GetAllSchoolsUploadedPictures()
    {
        try
        {
            var response = await _httpClient.GetAsync("/api/File/my-school-pictures");
            
            if (response.IsSuccessStatusCode)
            {
                var result = await response.Content.ReadFromJsonAsync<ApiResponse<List<UploadFileResult>>>();
                return result ?? ApiResponse<List<UploadFileResult>>.Failure([new ApiError
                {
                    Code = "Deserialization.Failed",
                    Message = "Could not parse server response.",
                    Type = ApiErrorType.System
                }]);
            }
            
            return ApiResponse<List<UploadFileResult>>.Failure([new ApiError
            {
                Code = "Fetch.Failed",
                Message = $"Failed to fetch pictures: {response.StatusCode}",
                Type = ApiErrorType.System
            }]);
        }
        catch (Exception ex)
        {
            return ApiResponse<List<UploadFileResult>>.Failure([new ApiError
            {
                Code = "Fetch.Exception",
                Message = ex.Message,
                Type = ApiErrorType.System
            }]);
        }
    }
}