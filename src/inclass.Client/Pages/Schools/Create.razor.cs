using Contract.InClass.Request.School;
using Contract.InClass.Response.Files;
using inclass.Client.Services;
using Microsoft.AspNetCore.Components;

namespace inclass.Client.Pages.Schools;

public partial class Create : ComponentBase
{
    private CreateSchoolRequestDto school = new();
    [Inject] private SchoolService SchoolService { get; set; }
    [Inject] private NavigationManager NavigationManager { get; set; }
    private List<UploadFileResult> uploadedPictures = new();
    private List<string>? errorMessage = null;
    private async Task CreateSchool()
    {
        var result = await SchoolService.CreateSchool(school);
        if (result.IsSuccess)
        {
            NavigationManager.NavigateTo("/schools");
            return;
        }

        errorMessage = result.Errors?.Select(e => e.Message).ToList() 
                       ?? ["An unexpected error occurred."];
    }

    protected override async Task OnInitializedAsync()
    {
        var result = await FileService.GetAllSchoolsUploadedPictures();

        if (result.IsSuccess)
        {
            uploadedPictures = result.Data!;
            return;
        }

        errorMessage = result.Errors?.Select(e => e.Message).ToList() 
                       ?? ["An unexpected error occurred."];
    }

}