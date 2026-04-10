using Contract.InClass.ApiContract;
using Contract.InClass.Request.Registration.Session;
using Contract.InClass.Response.Registration.Sessions;
using inclass.Client.Services.Api;

namespace inclass.Client.Services.Schools;

public class RegistrationSessionService
{
    private readonly ApiClient _client;

    public RegistrationSessionService(ApiClient client)
    {
        _client = client;
    }

    public Task<ApiResponse<List<RegistrationSessionResponse>>> GetSessions(Guid schoolId, string academicYear)
        => _client.GetAsync<List<RegistrationSessionResponse>>(
            $"/api/registrationsessions/{schoolId}", new { academicYear });

    public Task<ApiResponse<object>> OpenSession(Guid sessionId)
        => _client.PostAsync<object>($"/api/registrationsessions/{sessionId}/open", new { });

    public Task<ApiResponse<object>> CloseSession(Guid sessionId)
        => _client.PostAsync<object>($"/api/registrationsessions/{sessionId}/close", new { });

    public Task<ApiResponse<object>> CancelSession(Guid sessionId)
        => _client.PostAsync<object>($"/api/registrationsessions/{sessionId}/cancel", new { });

    public Task<ApiResponse<object>> UpdatePeriod(Guid sessionId, DateTime openDate, DateTime? closeDate)
        => _client.PatchAsync<object>($"/api/registrationsessions/{sessionId}/period",
            new UpdateRegistrationSessionPeriodRequest(sessionId, openDate, closeDate));

    public Task<ApiResponse<object>> UpdateQuota(Guid sessionId, int? dailyQuota, TimeOnly? cutoffTime)
        => _client.PatchAsync<object>($"/api/registrationsessions/{sessionId}/quota",
            new UpdateRegistrationSessionQuotaRequest(sessionId, dailyQuota, cutoffTime));

    public Task<ApiResponse<object>> UpdateStrategy(Guid sessionId, int assignmentStrategy)
        => _client.PatchAsync<object>($"/api/registrationsessions/{sessionId}/strategy",
            new UpdateRegistrationSessionStrategyRequest(sessionId, assignmentStrategy));

    public Task<ApiResponse<CreateBatchSessionsResult>> CreateBatch(CreateBatchRegistrationSessionsRequest request)
        => _client.PostAsync<CreateBatchSessionsResult>("/api/registrationsessions/batch", request);
}