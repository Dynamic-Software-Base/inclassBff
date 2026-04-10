using Contract.InClass.ApiContract;
using Contract.InClass.Request.School.Classes;
using Contract.InClass.Response.School.Classes;
using inclass.Client.Services.Api;

namespace inclass.Client.Services.Schools;

public class SchoolClassService
{
    private readonly ApiClient _client;

    public SchoolClassService(ApiClient client)
    {
        _client = client;
    }

    public Task<ApiResponse<SchoolSupportedGradesResponse>> GetSupportedGrades(Guid schoolId)
        => _client.GetAsync<SchoolSupportedGradesResponse>($"/api/classrooms/{schoolId}/supported-grades");

    public Task<ApiResponse<List<string>>> GetAcademicYears(Guid schoolId)
        => _client.GetAsync<List<string>>($"/api/classrooms/{schoolId}/academic-years");

    public Task<ApiResponse<List<SchoolClassResponse>>> GetClasses(Guid schoolId, string academicYear)
        => _client.GetAsync<List<SchoolClassResponse>>($"/api/classrooms/{schoolId}/classes", new { academicYear });

    public Task<ApiResponse<Guid>> CreateClass(Guid schoolId, CreateSchoolClassRequest request)
        => _client.PostAsync<Guid>($"/api/classrooms/{schoolId}/classes", request);

    public Task<ApiResponse<List<Guid>>> CreateBatchClasses(Guid schoolId, CreateBatchSchoolClassesRequest request)
        => _client.PostAsync<List<Guid>>($"/api/classrooms/{schoolId}/classes/batch", request);

    public Task<ApiResponse<object>> UpdateClassName(UpdateSchoolClassNameRequest request)
        => _client.PatchAsync<object>($"/api/classrooms/classes/{request.SchoolClassId}/name", request);

    public Task<ApiResponse<object>> UpdateClassCapacity(UpdateSchoolClassCapacityRequest request)
        => _client.PatchAsync<object>($"/api/classrooms/classes/{request.SchoolClassId}/capacity", request);
}