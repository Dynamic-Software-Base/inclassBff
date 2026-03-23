using Contract.InClass.ApiContract;
using Contract.InClass.Response.School.EducationalSystem;
using inclass.Client.Services.Api;

namespace inclass.Client.Services;

public class EducationalSystemService
{
    private readonly ApiClient _client;

    public EducationalSystemService(ApiClient client)
    {
        _client = client;
    }

    /// <summary>
    /// Loads the default Moroccan MEN system with all cycles and grades.
    /// Called once when the school creation form initializes.
    /// </summary>
    public async Task<ApiResponse<EducationalSystemResponse>> GetDefaultAsync()
    {
        return await _client.GetAsync<EducationalSystemResponse>(
            "/api/educationalsystem/default");
    }
}