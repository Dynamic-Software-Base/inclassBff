using Contract.InClass.Request.Registration.Application;
using Contract.InClass.Response.Registration;
using inclass.Client.Services;
using inclass.Client.Services.Registration;
using Microsoft.AspNetCore.Components;

namespace inclass.Client.Components.School.Enroll;

public partial class RegistrationModal : ComponentBase
{
    [Inject] private EnrollmentService EnrollmentService { get; set; } = default!;
    [Inject] private ApiResultHandler ResultHandler { get; set; } = default!;
    private string _submittedIdentityKey = "";
    
    [Parameter] public EnrollmentSessionDto Session { get; set; } = default!;
    [Parameter] public string SchoolName { get; set; } = "";
    [Parameter] public string AcademicYear { get; set; } = "";
    [Parameter] public Guid SchoolId { get; set; }
    [Parameter] public bool PreSelectedReturning { get; set; }
    [Parameter] public EventCallback OnClose { get; set; }

    private int _currentStep = 1;
    private bool _isReturning = false;
    private string _identityKey = "";
    private string _firstName = "";
    private string _lastName = "";
    private string _phone = "";
    private string _email = "";
    private Dictionary<string, string> _formValues = new();
    private ApplicationPrefillResponse? _prefillData = null;
    private string? _loadedSchemaJson = null;
    private bool _submitting = false;
    private string? _submitError = null;
    private Guid _submittedApplicationId;
    private Dictionary<string, string> _schemaRoleMap = new();

    protected override async Task OnInitializedAsync()
    {
        if (PreSelectedReturning)
        {
            _isReturning = true;
            _currentStep = 2;
        }
        await LoadSchema();
    }

    private async Task LoadSchema()
    {
        var response = await EnrollmentService.GetFormSchema(Session.SessionId);
        var result = ResultHandler.Handle(response);
        _loadedSchemaJson = result?.SchemaJson;

        // Build role map from schema
        _schemaRoleMap.Clear();
        if (_loadedSchemaJson != null)
        {
            try
            {
                using var doc = System.Text.Json.JsonDocument.Parse(_loadedSchemaJson);
                foreach (var section in doc.RootElement.GetProperty("sections").EnumerateArray())
                {
                    if (!section.TryGetProperty("fields", out var fields)) continue;
                    foreach (var field in fields.EnumerateArray())
                    {
                        if (field.TryGetProperty("role", out var roleEl) && roleEl.ValueKind == System.Text.Json.JsonValueKind.String)
                        {
                            var role = roleEl.GetString();
                            var key  = field.GetProperty("key").GetString();
                            if (role != null && key != null)
                                _schemaRoleMap[role] = key;
                        }
                    }
                }
            }
            catch { /* schema parse failure is non-fatal */ }
        }
    }

    private void GoToStep(int step) => _currentStep = step;

    private void HandleSelectNew()
    {
        _isReturning = false;
        GoToStep(3);
    }

    private void HandleSelectReturning()
    {
        _isReturning = true;
        GoToStep(2);
    }

    private void HandlePrefillSuccess(ApplicationPrefillResponse prefill)
    {
        _prefillData = prefill;
        foreach (var kvp in prefill.PreFilledFormValues)
            _formValues[kvp.Key] = kvp.Value?.ToString() ?? "";
        GoToStep(3);
    }
    private void HandleContinueAsNew()
    {
        _isReturning = false;
        _prefillData = null;
        GoToStep(3);
    }

    private void HandleFormNext(Dictionary<string, string> formValues)
    {
        _formValues = formValues;
        Console.WriteLine("holla");
        // Extract base fields from schema roles
        _firstName = ExtractByRole("studentFirstName") ?? "";
        _lastName  = ExtractByRole("studentLastName")  ?? "";
        _phone     = ExtractByRole("contactPhone")     ?? "";
        _email     = ExtractByRole("contactEmail");
        foreach (var formValue in formValues)
        {
            Console.WriteLine($"{formValue.Key}: {formValue.Value}");
        }
        Console.WriteLine(_firstName);
        Console.WriteLine(_lastName);
        Console.WriteLine(_phone);
        Console.WriteLine(_email);
        GoToStep(4);
    }
    private string? ExtractByRole(string role)
    {
        Console.WriteLine("wxtract ");
        Console.WriteLine(_schemaRoleMap.Count);
        // find the key in parsed schema that has this role, then get its value from _formValues
        foreach (var formValue in _schemaRoleMap)
        {
            Console.WriteLine($"{formValue.Key}: {formValue.Value}");
        }
        var key = _schemaRoleMap.GetValueOrDefault(role);
        return key != null && _formValues.TryGetValue(key, out var v) ? v : null;
    }
    private void HandleFormBack()
    {
        if (_isReturning)
            GoToStep(2);
        else
            GoToStep(1);
    }

    private async Task HandleSubmit()
    {
        _submitting = true;
        _submitError = null;

        var response = await EnrollmentService.SubmitApplication(new SubmitApplicationRequest(
            SessionId: Session.SessionId,
            StudentFirstName: _firstName,
            StudentLastName: _lastName,
            ContactPhone: _phone,
            ContactEmail: string.IsNullOrWhiteSpace(_email) ? null : _email,
            IsReturning: _isReturning,
            IdentityKey: _isReturning ? _identityKey : null,
            FormValuesJson: System.Text.Json.JsonSerializer.Serialize(_formValues)));

        var result = ResultHandler.Handle(response);

        if (result is not null)
        {
            _submittedApplicationId = result.ApplicationId;
            _submittedIdentityKey = result.IdentityKey;
            GoToStep(5);
        }
        else
        {
            _submitError = "Une erreur est survenue. Veuillez réessayer.";
        }

        _submitting = false;
    }

    private void HandleEnrollAnother()
    {
        ResetState();
        GoToStep(1);
    }

    private void ResetState()
    {
        _currentStep = 1;
        _isReturning = false;
        _identityKey = "";
        _firstName = "";
        _lastName = "";
        _phone = "";
        _email = "";
        _formValues = new();
        _prefillData = null;
        _submitError = null;
        _submittedIdentityKey = "";  // ← add
    }
    private async Task TryClose()
    {
        if (!_submitting)
        {
            ResetState();
            await OnClose.InvokeAsync();
        }
    }
}