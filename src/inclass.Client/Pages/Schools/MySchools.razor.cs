using Contract.InClass.ApiContract;
using Contract.InClass.Response.School;
using inclass.Client.Services;
using Microsoft.AspNetCore.Components;

namespace inclass.Client.Pages.Schools;

public partial class MySchools : ComponentBase
{
    [Inject] private SchoolService SchoolService { get; set; } = default!;
    [Inject] private NavigationManager NavigationManager { get; set; } = default!;

    private List<SchoolSummaryDto> _schools = [];
    private string? _error;
    private bool _loading = true;

    protected override async Task OnInitializedAsync()
    {
        var result = await SchoolService.GetOwnerSchools();

        if (result.IsSuccess)
        {
            _schools = result.Data!;
        }
        else
        {
            _error = result.Errors!
                .First(e => e.Type == ApiErrorType.Business || e.Type == ApiErrorType.System)
                .Message;
        }

        _loading = false;
    }
    
    private void NavigateToCreate()
    {
        NavigationManager.NavigateTo("/Create");
    }

}