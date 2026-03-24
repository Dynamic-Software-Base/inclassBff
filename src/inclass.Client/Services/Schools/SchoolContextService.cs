using Contract.InClass.Response.School;
using Microsoft.JSInterop;

namespace inclass.Client.Services.Schools;

public class SchoolContextService
{
    private readonly IJSRuntime _js;
    private const string StorageKey = "inclass.selectedSchoolId";

    public Guid? SelectedSchoolId { get; private set; }
    public string? SelectedSchoolName { get; private set; }
    public string? SelectedSchoolCity { get; private set; }
    public List<SchoolSwitcherDto> Schools { get; private set; } = new();

    public event Action? OnChanged;

    public SchoolContextService(IJSRuntime js)
    {
        _js = js;
    }

    public async Task InitializeAsync(List<SchoolSwitcherDto> schools)
    {
        Schools = schools;
        if (!schools.Any()) return;

        // Try to restore persisted selection
        var persisted = await _js.InvokeAsync<string?>("localStorageInterop.get", StorageKey);

        SchoolSwitcherDto? match = null;

        if (!string.IsNullOrEmpty(persisted) && Guid.TryParse(persisted, out var persistedId))
            match = schools.FirstOrDefault(s => s.SchoolId == persistedId);

        // Fall back to first school if persisted one no longer exists
        var selected = match ?? schools.First();
        await SetSchoolAsync(selected, persist: match is null);
    }

    public async Task SelectSchoolAsync(SchoolSwitcherDto school)
    {
        await SetSchoolAsync(school, persist: true);
    }

    private async Task SetSchoolAsync(SchoolSwitcherDto school, bool persist)
    {
        SelectedSchoolId = school.SchoolId;
        SelectedSchoolName = school.Name;
        SelectedSchoolCity = school.City;

        if (persist)
            await _js.InvokeVoidAsync("localStorageInterop.set", StorageKey, school.SchoolId.ToString());

        OnChanged?.Invoke();
    }
}