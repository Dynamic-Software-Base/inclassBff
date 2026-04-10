using Contract.InClass.ApiContract;
using Contract.InClass.Request.Registration.Application;
using Contract.InClass.Response.Registration;
using inclass.Client.Services.Api;

namespace inclass.Client.Services.Registration;

public class EnrollmentService
{
    private readonly ApiClient _client;

    public EnrollmentService(ApiClient client)
    {
        _client = client;
    }

    public async Task<ApiResponse<EnrollmentSessionsResponse>> GetEnrollmentSessions(
        Guid schoolId,
        string academicYear)
    {
        return await _client.GetAsync<EnrollmentSessionsResponse>(
            $"/public/api/RegistrationSessions/{schoolId}/enrollment-sessions",
            new { academicYear });
    }

    public async Task<ApiResponse<FormSchemaResponse>> GetFormSchema(Guid sessionId)
    {
        return await _client.GetAsync<FormSchemaResponse>(
            $"/public/api/RegistrationSessions/sessions/{sessionId}/form-schema");
    }

    public async Task<ApiResponse<ApplicationPrefillResponse>> GetPrefill(
        string identityKey,
        Guid sessionId)
    {
        return await _client.GetAsync<ApplicationPrefillResponse>(
            "/public/api/RegistrationSessions/applications/prefill",
            new { identityKey, sessionId });
    }

    public async Task<ApiResponse<SubmitApplicationResponse>> SubmitApplication(
        SubmitApplicationRequest request)
    {
        return await _client.PostAsync<SubmitApplicationResponse>(
            "/public/api/RegistrationSessions/applications/submit",
            request);
    }
}