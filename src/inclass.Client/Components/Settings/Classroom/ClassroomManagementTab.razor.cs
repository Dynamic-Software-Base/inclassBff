using Contract.InClass.Request.School.Classes;
using Contract.InClass.Response.School.Classes;
using inclass.Client.Services;
using inclass.Client.Services.Schools;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Web;

namespace inclass.Client.Components.Settings.Classroom;

public partial class ClassroomManagementTab : ComponentBase
{
     [Inject] private SchoolClassService ClassService { get; set; } = default!;
    [Inject] private SchoolContextService SchoolContext { get; set; } = default!;
    [Inject] private ApiResultHandler ResultHandler { get; set; } = default!;

    // ── Loading state ────────────────────────────────────────────────────────
    private bool _loadingGrades  = true;
    private bool _loadingClasses = true;
    private bool _loadingYears   = true;
    public  bool IsLoading => _loadingGrades || _loadingClasses || _loadingYears;
   private bool   AddingNewYear = false;
    private string NewYearValue  = string.Empty;
    private string NewYearError  = string.Empty;
    private Dictionary<string, List<SchoolClassModel>> DynamicYearClasses = new();
    private void CancelNewYear()
    {
        AddingNewYear = false;
        NewYearValue  = string.Empty;
        NewYearError  = string.Empty;
    }

    private void SubmitNewYear()
    {
        NewYearError = string.Empty;
        var val = NewYearValue.Trim();

        // Validate format YYYY-YYYY
        var parts = val.Split('-');
        if (parts.Length != 2
            || !int.TryParse(parts[0], out int start)
            || !int.TryParse(parts[1], out int end)
            || end != start + 1)
        {
            NewYearError = "Format invalide (ex: 2026-2027)";
            return;
        }

        if (AcademicYears.Contains(val))
        {
            NewYearError = "Cette année existe déjà.";
            return;
        }

        AcademicYears.Add(val);
        AcademicYears.Sort();
        DynamicYearClasses[val] = new List<SchoolClassModel>();

        SelectedYear = val;
        CancelNewYear();
        CancelAllEdits();
    }

    private void OnNewYearKeyDown(KeyboardEventArgs e)
    {
        if (e.Key == "Enter")  SubmitNewYear();
        if (e.Key == "Escape") CancelNewYear();
    }
    // ── School context ───────────────────────────────────────────────────────
    private Guid SchoolId => SchoolContext.SelectedSchoolId ?? Guid.Empty;

    // ── Academic year state ──────────────────────────────────────────────────
    private List<string> AcademicYears = new();
    private string SelectedYear = string.Empty;
    private string ActiveYear   = string.Empty;  // most recent year = active
    private bool IsReadOnly => !string.IsNullOrEmpty(SelectedYear)
                            && !string.IsNullOrEmpty(ActiveYear)
                            && AcademicYears.IndexOf(SelectedYear) < AcademicYears.IndexOf(ActiveYear);

    // ── Data ─────────────────────────────────────────────────────────────────
    private SchoolSupportedGradesResponse? SupportedGrades;
    private List<SchoolClassResponse> ActiveClasses = new();

    // ── Lifecycle ────────────────────────────────────────────────────────────
    protected override async Task OnInitializedAsync()
    {
        await LoadGrades();
        await LoadAcademicYears();
        // LoadClasses is triggered by LoadAcademicYears once SelectedYear is set
    }

    private async Task LoadGrades()
    {
        _loadingGrades = true;
        try
        {
            var response = await ClassService.GetSupportedGrades(SchoolId);
            SupportedGrades = ResultHandler.Handle(response);
        }
        finally
        {
            _loadingGrades = false; // always runs, even on exception
        }
    }

    private async Task LoadAcademicYears()
    {
        _loadingYears  = true;
        var response   = await ClassService.GetAcademicYears(SchoolId);
        var years      = ResultHandler.Handle(response);

        if (years is { Count: > 0 })
        {
            AcademicYears = years; // already sorted descending from API
            ActiveYear    = years.First(); // most recent = active
            SelectedYear  = ActiveYear;
        }

        _loadingYears = false;
        await LoadClasses();
    }

    private async Task LoadClasses()
    {
        if (string.IsNullOrEmpty(SelectedYear))
        {
            _loadingClasses = false; // ← add this
            return;
        }

        _loadingClasses = true;
        var response    = await ClassService.GetClasses(SchoolId, SelectedYear);
        ActiveClasses   = ResultHandler.Handle(response) ?? new();
        _loadingClasses = false;
    }
    // ── Cycles structure ─────────────────────────────────────────────────────
    private Dictionary<string, List<GradeModel>> Cycles =>
        SupportedGrades?.Cycles
            .OrderBy(c => c.SortOrder)
            .ToDictionary(
                c => c.NameFr,
                c => c.Grades
                    .OrderBy(g => g.SortOrder)
                    .Select(g => new GradeModel(g.Id.ToString(), g.Code, g.NameFr, c.NameFr, g.SortOrder))
                    .ToList())
        ?? new();
    
    private List<GradeModel> AllGrades =>
        SupportedGrades?.Cycles
            .SelectMany(c => c.Grades.Select(g => new GradeModel(g.Id.ToString(), g.Code, g.NameFr, c.NameFr, g.SortOrder)))
            .ToList()
        ?? new();
    private List<SchoolClassModel> GetClassesForCycle(string cycleName)
    {
        var ids = AllGrades.Where(g => g.Cycle == cycleName).Select(g => g.Id).ToHashSet();
        return ActiveClasses
            .Where(c => ids.Contains(c.GradeDefinitionId.ToString()))
            .Select(ToModel).ToList();
    }
    private List<SchoolClassModel> GetClassesForGrade(string gradeId)
        => ActiveClasses
            .Where(c => c.GradeDefinitionId.ToString() == gradeId)
            .Select(ToModel).ToList();

    private static SchoolClassModel ToModel(SchoolClassResponse dto) => new()
    {
        Id           = dto.Id.ToString(),
        GradeId      = dto.GradeDefinitionId.ToString(),
        Name         = dto.Name,
        MaxStudents  = dto.MaxStudents,
        EnrolledCount = dto.CurrentEnrollmentCount
    };

    // ── Summary stats ────────────────────────────────────────────────────────
    private int    StatsTotal    => ActiveClasses.Count;
    private int    StatsCapacity => ActiveClasses.Sum(c => c.MaxStudents);
    private int    StatsEnrolled => ActiveClasses.Sum(c => c.CurrentEnrollmentCount);
    private int    StatsFillRate => StatsCapacity > 0 ? (int)Math.Round((double)StatsEnrolled / StatsCapacity * 100) : 0;
    private string FillRateColor => StatsFillRate >= 100 ? "text-red-600" : StatsFillRate >= 80 ? "text-amber-600" : "text-emerald-600";

    // ── Collapse state ───────────────────────────────────────────────────────
    private HashSet<string> CollapsedCycles = new();

    private void ToggleCycle(string cycle)
    {
        if (!CollapsedCycles.Add(cycle)) CollapsedCycles.Remove(cycle);
    }

    // ── Year change ──────────────────────────────────────────────────────────
    private async Task OnYearChanged(ChangeEventArgs e)
    {
        SelectedYear = e.Value?.ToString() ?? ActiveYear;
        CancelAllEdits();
        await LoadClasses();
    }

    // ── Inline name edit ─────────────────────────────────────────────────────
    private string? EditingNameId;
    private string  EditingNameValue = string.Empty;

    private void StartNameEdit(SchoolClassModel cls)
    {
        CancelAllEdits();
        EditingNameId    = cls.Id;
        EditingNameValue = cls.Name;
    }

    private void CancelNameEdit()
    {
        EditingNameId    = null;
        EditingNameValue = string.Empty;
    }

    private async Task SubmitNameEdit(SchoolClassModel cls)
    {
        if (string.IsNullOrWhiteSpace(EditingNameValue)) return;

        var request  = new UpdateSchoolClassNameRequest(Guid.Parse(cls.Id), EditingNameValue.Trim());
        var response = await ClassService.UpdateClassName(request);
        var result   = ResultHandler.Handle(response, "Nom mis à jour");

        if (result is not null)
        {
            CancelNameEdit();
            await LoadClasses();
        }
    }

    private async Task OnNameKeyDown(KeyboardEventArgs e, SchoolClassModel cls)
    {
        if (e.Key == "Enter")  await SubmitNameEdit(cls);
        if (e.Key == "Escape") CancelNameEdit();
    }

    // ── Inline capacity edit ─────────────────────────────────────────────────
    private string? EditingCapacityId;
    private int     EditingCapacityValue;
    private string  CapacityEditError = string.Empty;

    private void StartCapacityEdit(SchoolClassModel cls)
    {
        CancelAllEdits();
        EditingCapacityId    = cls.Id;
        EditingCapacityValue = cls.MaxStudents;
        CapacityEditError    = string.Empty;
    }

    private void CancelCapacityEdit()
    {
        EditingCapacityId = null;
        CapacityEditError = string.Empty;
    }

    private async Task SubmitCapacityEdit(SchoolClassModel cls)
    {
        CapacityEditError = string.Empty;

        if (EditingCapacityValue < 1 || EditingCapacityValue > 60)
        {
            CapacityEditError = "La capacité doit être entre 1 et 60.";
            return;
        }
        if (EditingCapacityValue < cls.EnrolledCount)
        {
            CapacityEditError = $"Ne peut pas être inférieur aux {cls.EnrolledCount} inscrits.";
            return;
        }

        var request  = new UpdateSchoolClassCapacityRequest(Guid.Parse(cls.Id), EditingCapacityValue);
        var response = await ClassService.UpdateClassCapacity(request);
        var result   = ResultHandler.Handle(response, "Capacité mise à jour");

        if (result is not null)
        {
            CancelCapacityEdit();
            await LoadClasses();
        }
    }

    private async Task OnCapacityKeyDown(KeyboardEventArgs e, SchoolClassModel cls)
    {
        if (e.Key == "Enter")  await SubmitCapacityEdit(cls);
        if (e.Key == "Escape") CancelCapacityEdit();
    }

    // ── Add single class ─────────────────────────────────────────────────────
    private string? AddingClassGradeId;
    private string  NewClassName     = string.Empty;
    private int     NewClassCapacity = 28;
    private string  NewClassError    = string.Empty;

    private void OpenAddClass(string gradeId)
    {
        CancelAllEdits();
        AddingClassGradeId = gradeId;
        NewClassName       = string.Empty;
        NewClassCapacity   = 28;
        NewClassError      = string.Empty;
    }

    private void CancelAddClass()
    {
        AddingClassGradeId = null;
        NewClassError      = string.Empty;
    }

    private async Task SubmitAddClass(string gradeId)
    {
        NewClassError = string.Empty;

        if (string.IsNullOrWhiteSpace(NewClassName))
        {
            NewClassError = "Le nom de la classe est requis.";
            return;
        }
        if (NewClassCapacity < 1 || NewClassCapacity > 60)
        {
            NewClassError = "La capacité doit être entre 1 et 60.";
            return;
        }

        var request = new CreateSchoolClassRequest(
            SchoolId,
            Guid.Parse(gradeId),
            NewClassName.Trim(),
            SelectedYear,
            NewClassCapacity);

        var response = await ClassService.CreateClass(SchoolId, request);
        var result   = ResultHandler.Handle(response, "Classe créée avec succès");

        if (result != Guid.Empty)
        {
            CancelAddClass();
            await LoadClasses(); // refresh from server
        }
    }
    // ── Batch modal ──────────────────────────────────────────────────────────
    private bool   ShowBatchModal       = false;
    private int    BatchStep            = 1;
    private string BatchGradeId         = string.Empty;
    private int    BatchDefaultCapacity = 28;
    private string BatchStep1Error      = string.Empty;
    private string BatchStep2Error      = string.Empty;

    private class BatchRowModel
    {
        public string Name     { get; set; } = string.Empty;
        public int    Capacity { get; set; } = 28;
    }

    private List<BatchRowModel> BatchRows = new();

    private void OpenBatchModal()
    {
        BatchStep            = 1;
        BatchGradeId         = string.Empty;
        BatchDefaultCapacity = 28;
        BatchStep1Error      = string.Empty;
        BatchStep2Error      = string.Empty;
        BatchRows            = new List<BatchRowModel> { new() { Capacity = 28 } };
        ShowBatchModal       = true;
    }

    private void CloseBatchModal() => ShowBatchModal = false;

    private void BatchBack()
    {
        if (BatchStep > 1) BatchStep--;
        else CloseBatchModal();
    }

    private void BatchNextStep()
    {
        BatchStep1Error = string.Empty;

        if (string.IsNullOrEmpty(BatchGradeId))
        {
            BatchStep1Error = "Veuillez sélectionner un niveau.";
            return;
        }
        if (BatchDefaultCapacity < 1 || BatchDefaultCapacity > 60)
        {
            BatchStep1Error = "La capacité par défaut doit être entre 1 et 60.";
            return;
        }

        // Apply default capacity to all rows
        foreach (var r in BatchRows) r.Capacity = BatchDefaultCapacity;
        BatchStep = 2;
    }

    private void AddBatchRow()
        => BatchRows.Add(new BatchRowModel { Capacity = BatchDefaultCapacity });

    private void RemoveBatchRow(int idx)
    {
        if (BatchRows.Count > 1) BatchRows.RemoveAt(idx);
    }

    private async Task SubmitBatch()
    {
        BatchStep2Error = string.Empty;
        var valid = BatchRows.Where(r => !string.IsNullOrWhiteSpace(r.Name)).ToList();

        if (!valid.Any())
        {
            BatchStep2Error = "Veuillez saisir au moins un nom de classe.";
            return;
        }
        if (valid.Any(r => r.Capacity < 1 || r.Capacity > 60))
        {
            BatchStep2Error = "Chaque capacité doit être entre 1 et 60.";
            return;
        }

        var request = new CreateBatchSchoolClassesRequest(
            SchoolId,
            Guid.Parse(BatchGradeId),
            SelectedYear,
            valid.Select(r => new SchoolClassDefinition(r.Name.Trim(), r.Capacity)).ToList());

        var response = await ClassService.CreateBatchClasses(SchoolId, request);
        var result   = ResultHandler.Handle(response, $"{valid.Count} classe(s) créée(s) avec succès");

        if (result is { Count: > 0 })
        {
            CloseBatchModal();
            await LoadClasses();
        }
    }

    // ── Shared cancel helper ─────────────────────────────────────────────────
    private void CancelAllEdits()
    {
        CancelNameEdit();
        CancelCapacityEdit();
        CancelAddClass();
        
    }
    // Domain record Types
    private record GradeModel(string Id, string Code, string NameFr, string Cycle , int SortOrder);

    private class SchoolClassModel
    {
        public string Id { get; set; } = string.Empty;
        public string GradeId  { get; set; } =  string.Empty;
        public string Name { get; set; } = string.Empty;
        public int MaxStudents { get; set; }
        public int EnrolledCount { get; set; }

        public SchoolClassModel()
        { }
        public SchoolClassModel(string id, string gradeId, string name, int max, int enrolled)
        {
            Id = id; GradeId = gradeId; Name = name; MaxStudents = max; EnrolledCount = enrolled;
        }
    }
}
