// inclass.Client/Services/SchemaService.cs

using Contract.InClass.ApiContract;
using Contract.InClass.Response.Registration.Schemas;
using inclass.Client.Services.Api;

namespace inclass.Client.Services.Schema;

public class SchemaService
{
    private readonly ApiClient _client;

    public SchemaService(ApiClient client)
    {
        _client = client;
    }

    public async Task<ApiResponse<FormSchemaResponse>> GetSchemaAsync(
        Guid schoolId, Guid gradeDefinitionId)
    {
        return await _client.GetAsync<FormSchemaResponse>(
            $"/api/schools/{schoolId}/grades/{gradeDefinitionId}/schema");
    }

    public async Task<ApiResponse<Guid>> SaveSchemaAsync(
        Guid schoolId, Guid gradeDefinitionId, string schemaJson)
    {
        return await _client.PutAsync<Guid>(
            $"/api/schools/{schoolId}/grades/{gradeDefinitionId}/schema",
            schemaJson);
    }
}