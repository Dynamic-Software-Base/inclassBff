using Contract.InClass.Response.Registration;
using inclass.Client.Services;
using inclass.Client.Services.Enroll;
using inclass.Client.Services.Registration;
using Microsoft.AspNetCore.Components;

namespace inclass.Client.Pages.Schools.Enrtoll;

public partial class EnrollPage : ComponentBase
{
    [Parameter] public Guid SchoolId { get; set; }

    [Inject] private EnrollmentService EnrollmentService { get; set; } = default!;
    [Inject] private ApiResultHandler ResultHandler { get; set; } = default!;

    private EnrollmentSessionsResponse? _data;
    private bool _loading = true;
    private string? _error;

    private bool _modalOpen = false;
    private EnrollmentSessionDto? _selectedSession = null;
    private bool _preSelectedReturning = false;

    protected override async Task OnInitializedAsync()
    {
        await LoadSessions();
    }

    private async Task LoadSessions()
    {
        _loading = true;
        _error = null;

        var response = await EnrollmentService.GetEnrollmentSessions(SchoolId, "2026-2027");
        _data = ResultHandler.Handle(response);

        if (_data is null)
            _error = "Impossible de charger les sessions d'inscription.";

        _loading = false;
    }

    private void OpenModal(SessionSelectedArgs args)
    {
        _selectedSession = args.Session;
        _preSelectedReturning = args.PreSelectReturning;
        _modalOpen = true;
    }

    private void CloseModal()
    {
        _modalOpen = false;
        _selectedSession = null;
        _preSelectedReturning = false;
    }
}