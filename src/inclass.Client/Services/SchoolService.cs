using System.Net.Http.Json;
using Contract.InClass.ApiContract;
using Contract.InClass.Request.School;
using Contract.InClass.Response.School;
using inclass.Client.Services.Api;

namespace inclass.Client.Services;

public class SchoolService
{
    private readonly ApiClient _client;

    public SchoolService(ApiClient client)
    {
        _client = client;
    }

    
    

    public async Task<ApiResponse<CreateSchoolResponse>> CreateSchool(CreateSchoolRequestDto request)
    {
       return await _client.PostAsync<CreateSchoolResponse>("/api/schools", request);
    }

    public async Task<ApiResponse<List<SchoolSummaryDto>>> GetOwnerSchools(
        CancellationToken cancellationToken = default)
    {
        return await _client.GetAsync<List<SchoolSummaryDto>>("/api/schools/my-schools");
    }
}