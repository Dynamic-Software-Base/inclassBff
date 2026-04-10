using Contract.InClass.Request.Registration.Session;
using Contract.InClass.Response.Registration.Sessions;
using inclass.Client.Services.Schools;
using Microsoft.AspNetCore.Components;

namespace inclass.Client.Pages.Registration;

public partial class Registration : ComponentBase,IDisposable
{
    [Inject] private RegistrationSessionService SessionService { get; set; } = null!;
    [Inject] private SchoolClassService SchoolClassService { get; set; } = null!;
    [Inject] private SchoolContextService SchoolContext { get; set; } = null!;

    // ── Enums (kept local to match razor bindings) ────────────────────────
    public enum RegistrationSessionStatus 
    { 
        Scheduled = 1, 
        Open = 2, 
        Closed = 3, 
        Cancelled = 4 
    }
    public enum RegistrationPhaseType { ReRegistration = 0, Open = 1 }
    public enum AssignmentStrategy { BalanceLoad = 1, GenderSplit = 2, SiblingGrouping = 3, ManualOnly = 4 }
    public enum AllowedApplicantType { ReturningOnly = 0,  All = 1, Both = 2 }

    // ── Local DTOs (mapped from contract responses) ───────────────────────
    public class RegistrationPhaseDto
    {
        public DateOnly StartDate { get; set; }
        public DateOnly? EndDate { get; set; }
        public RegistrationPhaseType PhaseType { get; set; }
        public AllowedApplicantType AllowedApplicantType { get; set; }
    }

    public class RegistrationSessionDto
    {
        public string Id { get; set; } = "";
        public string GradeDefinitionId { get; set; } = "";
        public string GradeNameFr { get; set; } = "";
        public string CycleName { get; set; } = "";
        public string AcademicYear { get; set; } = "";
        public RegistrationSessionStatus Status { get; set; }
        public DateTime OpenDate { get; set; }
        public DateTime? CloseDate { get; set; }
        public int MaxSlots { get; set; }
        public int ReservedCount { get; set; }
        public int EnrolledCount { get; set; }
        public int WaitlistCount { get; set; }
        public int? DailyQuota { get; set; }
        public string DailyCutoffTime { get; set; } = "12:00";
        public AssignmentStrategy AssignmentStrategy { get; set; }
        public List<RegistrationPhaseDto> Phases { get; set; } = new();
    }

    public class GradeDefinition
    {
        public string Id { get; set; } = "";
        public string NameFr { get; set; } = "";
        public string CycleName { get; set; } = "";
        public int SortOrder { get; set; }
    }

    public class StrategyOption
    {
        public AssignmentStrategy Value { get; set; }
        public string Label { get; set; } = "";
        public string Description { get; set; } = "";
    }

    // ── State ─────────────────────────────────────────────────────────────
    private bool IsLoading = true;
    private string? ErrorMessage = null;

    private List<string> AcademicYears = new();
    private string ActiveYear = "";
    private string SelectedYear = "";

    private List<GradeDefinition> AllGrades = new();
    private Dictionary<string, int> GradeCapacities = new();
    private List<RegistrationSessionDto> AllSessions = new();

    private List<StrategyOption> StrategyOptions = new()
    {
        new() { Value=AssignmentStrategy.BalanceLoad,     Label="Équilibrer",  Description="Répartit équitablement entre les classes" },
        new() { Value=AssignmentStrategy.GenderSplit,     Label="Genre",       Description="Sépare les élèves par genre" },
        new() { Value=AssignmentStrategy.SiblingGrouping, Label="Fratrie",     Description="Regroupe les fratries ensemble" },
        new() { Value=AssignmentStrategy.ManualOnly,      Label="Manuel",      Description="Attribution manuelle uniquement" },
    };

    private bool IsReadOnly => SelectedYear != ActiveYear;
    private HashSet<string> ExpandedCycles = new();
    private AssignmentStrategy GlobalStrategy = AssignmentStrategy.BalanceLoad;
    private bool EditingGlobalStrategy = false;

    private List<RegistrationSessionDto> FilteredSessions =>
        AllSessions.Where(s => s.AcademicYear == SelectedYear).ToList();
    private List<string> CycleGroups =>
        FilteredSessions.Select(s => s.CycleName).Distinct().ToList();
    private Dictionary<string, List<GradeDefinition>> GradesGroupedByCycle =>
        AllGrades.GroupBy(g => g.CycleName)
                 .ToDictionary(g => g.Key, g => g.OrderBy(x => x.SortOrder).ToList());

    // Edit panel
    private RegistrationSessionDto? EditPanelSession = null;
    private string EditTab = "Période";
    private DateTime EditOpenDate;
    private DateTime? EditCloseDate;
    private int? EditDailyQuota;
    private TimeOnly? EditCutoffTime = new TimeOnly(12, 0);
    private AssignmentStrategy EditStrategy = AssignmentStrategy.BalanceLoad;

    // Wizard
    private bool ShowBatchWizard = false;
    private int WizardStep = 1;
    private HashSet<string> WizardSelectedGrades = new();
    private DateOnly WizardOpenDate = DateOnly.FromDateTime(DateTime.Today);
    private DateOnly WizardCloseDate = DateOnly.FromDateTime(DateTime.Today.AddDays(7));
    private bool WizardIncludeReRegistration = false;
    private DateOnly WizardPhase1Start = DateOnly.FromDateTime(DateTime.Today);
    private DateOnly WizardPhase1End = DateOnly.FromDateTime(DateTime.Today.AddDays(7));
    private DateOnly WizardPhase2Start = DateOnly.FromDateTime(DateTime.Today.AddDays(8));
    private DateOnly WizardPhase2End = DateOnly.FromDateTime(DateTime.Today.AddDays(15));
    private TimeOnly? WizardCutoffTime = new TimeOnly(12, 0);
    private int? WizardDailyQuota = null;
    private AssignmentStrategy WizardStrategy = AssignmentStrategy.BalanceLoad;
    private string WizardStep1Error = "";
    private string WizardStep2Error = "";

    // ── Lifecycle ─────────────────────────────────────────────────────────
    protected override async Task OnInitializedAsync()
    {
        if (SchoolContext.SelectedSchoolId.HasValue)
        {
            // Navigation case: context already ready
            await LoadInitialDataAsync();
        }
        else
        {
            // Refresh case: wait for InitializeAsync to finish
            SchoolContext.OnChanged += OnSchoolContextReady;
        }
    }
    private async void OnSchoolContextReady()
    {
        SchoolContext.OnChanged -= OnSchoolContextReady; // unsubscribe first
        try
        {
            await LoadInitialDataAsync();
        }
        catch (Exception ex)
        {
            ErrorMessage = "Erreur lors du chargement.";
        }
        await InvokeAsync(StateHasChanged); // must marshal back to render thread
    }
    public void Dispose()
    {
        SchoolContext.OnChanged -= OnSchoolContextReady; // guard against navigating away mid-load
    }
    private async Task LoadInitialDataAsync()
    {
        if (SchoolContext.SelectedSchoolId is not { } schoolId) return;

        IsLoading = true;
        ErrorMessage = null;

        // 1. Academic years
        var yearsResponse = await SchoolClassService.GetAcademicYears(schoolId);
        if (!yearsResponse.IsSuccess || yearsResponse.Data is null)
        {
            ErrorMessage = "Impossible de charger les années académiques.";
            IsLoading = false;
            return;
        }

        AcademicYears = yearsResponse.Data;
        ActiveYear = AcademicYears.FirstOrDefault() ?? "";
        SelectedYear = ActiveYear;

        // 2. Grades + capacities (supported grades gives us both)
        var gradesResponse = await SchoolClassService.GetSupportedGrades(schoolId);
        if (gradesResponse.IsSuccess && gradesResponse.Data is not null)
        {
            var allGrades = gradesResponse.Data.Cycles
                .SelectMany(c => c.Grades.Select(g => new { Cycle = c, Grade = g }))
                .ToList();

            AllGrades = allGrades.Select(x => new GradeDefinition
            {
                Id = x.Grade.Id.ToString(),
                NameFr = x.Grade.NameFr,
                CycleName = x.Cycle.NameFr,
                SortOrder = x.Grade.SortOrder
            }).ToList();
        }

// Capacities come from school classes (sum per grade)
        var classesResponse = await SchoolClassService.GetClasses(schoolId, ActiveYear);
        if (classesResponse.IsSuccess && classesResponse.Data is not null)
        {
            GradeCapacities = classesResponse.Data
                .GroupBy(c => c.GradeDefinitionId.ToString())
                .ToDictionary(
                    g => g.Key,
                    g => g.Sum(c => c.MaxStudents));
        }
        // 3. Sessions for active year
        await LoadSessionsAsync(schoolId, ActiveYear);

        ExpandedCycles = FilteredSessions.Select(s => s.CycleName).ToHashSet();
        IsLoading = false;
    }

    private async Task LoadSessionsAsync(Guid schoolId, string academicYear)
    {
        var response = await SessionService.GetSessions(schoolId, academicYear);
        if (!response.IsSuccess || response.Data is null) return;

        // Remove sessions for this year then re-add fresh data
        AllSessions.RemoveAll(s => s.AcademicYear == academicYear);
        AllSessions.AddRange(response.Data.Select(MapToDto));
    }

    private async Task OnYearChanged()
    {
        if (SchoolContext.SelectedSchoolId is not { } schoolId) return;
        await LoadSessionsAsync(schoolId, SelectedYear);
        ExpandedCycles = FilteredSessions.Select(s => s.CycleName).ToHashSet();
    }

    // ── Mapping ───────────────────────────────────────────────────────────
    private static RegistrationSessionDto MapToDto(RegistrationSessionResponse r) => new()
    {
        Id = r.Id.ToString(),
        GradeDefinitionId = r.GradeDefinitionId.ToString(),
        GradeNameFr = r.GradeNameFr,
        CycleName = r.CycleName,
        AcademicYear = r.AcademicYear,
        Status = (RegistrationSessionStatus)r.Status,
        OpenDate = r.OpenDate,
        CloseDate = r.CloseDate,
        MaxSlots = r.MaxSlots,
        ReservedCount = r.ReservedCount,
        EnrolledCount = r.EnrolledCount,
        WaitlistCount = r.WaitlistCount,
        DailyQuota = r.DailyQuota,
        DailyCutoffTime = r.DailyCutoffTime,
        AssignmentStrategy = (AssignmentStrategy)r.AssignmentStrategy,
        Phases = r.Phases.Select(p => new RegistrationPhaseDto
        {
            StartDate = p.StartDate,
            EndDate = p.EndDate,
            PhaseType = (RegistrationPhaseType)p.PhaseType,
            AllowedApplicantType = (AllowedApplicantType)p.AllowedApplicantType
        }).ToList()
    };

    // ── Actions ───────────────────────────────────────────────────────────
    private void SaveGlobalStrategy()
    {
        // UI-only: feeds wizard default
        WizardStrategy = GlobalStrategy;
        EditingGlobalStrategy = false;
    }

    private async Task OpenSession(RegistrationSessionDto s)
    {
        var result = await SessionService.OpenSession(Guid.Parse(s.Id));
        if (result.IsSuccess)
            s.Status = RegistrationSessionStatus.Open;
    }

    private async Task CloseSession(RegistrationSessionDto s)
    {
        var result = await SessionService.CloseSession(Guid.Parse(s.Id));
        if (result.IsSuccess)
            s.Status = RegistrationSessionStatus.Closed;
    }

    private async Task CancelSession(RegistrationSessionDto s)
    {
        var result = await SessionService.CancelSession(Guid.Parse(s.Id));
        if (result.IsSuccess)
            s.Status = RegistrationSessionStatus.Cancelled;
    }

    private void OpenEditPanel(RegistrationSessionDto s)
    {
        EditPanelSession = s;
        EditTab = "Période";
        EditOpenDate = s.OpenDate;
        EditCloseDate = s.CloseDate;
        EditDailyQuota = s.DailyQuota;
        EditCutoffTime = TimeOnly.TryParse(s.DailyCutoffTime, out var t) ? t : null;
        EditStrategy = s.AssignmentStrategy;
    }

    private void CloseEditPanel() => EditPanelSession = null;

    private async Task SaveEditPanel()
    {
        if (EditPanelSession is null) return;
        var sessionId = Guid.Parse(EditPanelSession.Id);

        if (EditTab == "Période")
        {
            var result = await SessionService.UpdatePeriod(sessionId, EditOpenDate, EditCloseDate);
            if (result.IsSuccess)
            {
                EditPanelSession.OpenDate = EditOpenDate;
                EditPanelSession.CloseDate = EditCloseDate;
            }
        }
        else if (EditTab == "Quota")
        {
            var result = await SessionService.UpdateQuota(sessionId, EditDailyQuota, EditCutoffTime);
            if (result.IsSuccess)
            {
                EditPanelSession.DailyQuota = EditDailyQuota;
                EditPanelSession.DailyCutoffTime = EditCutoffTime?.ToString("HH:mm");
            }
        }
        else if (EditTab == "Stratégie")
        {
            var result = await SessionService.UpdateStrategy(sessionId, (int)EditStrategy);
            if (result.IsSuccess)
                EditPanelSession.AssignmentStrategy = EditStrategy;
        }

        CloseEditPanel();
    }

    private void OpenBatchWizard()
    {
        WizardStep = 1;
        WizardSelectedGrades.Clear();
        WizardOpenDate = DateOnly.FromDateTime(DateTime.Today);
        WizardCloseDate = DateOnly.FromDateTime(DateTime.Today.AddDays(7));
        WizardIncludeReRegistration = false;
        WizardPhase1Start =DateOnly.FromDateTime(DateTime.Today);
        WizardPhase1End = DateOnly.FromDateTime(DateTime.Today.AddDays(7));
        WizardPhase2Start = DateOnly.FromDateTime(DateTime.Today.AddDays(8));
        WizardPhase2End = DateOnly.FromDateTime(DateTime.Today.AddDays(15));
        WizardCutoffTime = new TimeOnly(12, 0);
        WizardDailyQuota = null;
        WizardStrategy = GlobalStrategy; // ← feeds from global strategy card
        WizardStep1Error = "";
        WizardStep2Error = "";
        ShowBatchWizard = true;
    }

    private void CloseWizard() => ShowBatchWizard = false;

    private void ToggleGradeSelection(string id)
    {
        if (WizardSelectedGrades.Contains(id)) WizardSelectedGrades.Remove(id);
        else WizardSelectedGrades.Add(id);
    }

    private void ToggleAllCycleGrades(string cycle, bool select)
    {
        foreach (var g in AllGrades.Where(g => g.CycleName == cycle
                                            && GradeCapacities.GetValueOrDefault(g.Id, 0) > 0))
        {
            if (select) WizardSelectedGrades.Add(g.Id);
            else WizardSelectedGrades.Remove(g.Id);
        }
    }

    private void WizardNext()
    {
        if (WizardStep == 1)
        {
            if (!WizardSelectedGrades.Any()) { WizardStep1Error = "Sélectionnez au moins un niveau."; return; }
            WizardStep1Error = "";
        }
        else if (WizardStep == 2)
        {
            if (WizardOpenDate >= WizardCloseDate) { WizardStep2Error = "L'ouverture doit être antérieure à la clôture."; return; }
            if (WizardIncludeReRegistration && WizardPhase1End >= WizardPhase2Start) { WizardStep2Error = "Les phases ne doivent pas se chevaucher."; return; }
            WizardStep2Error = "";
        }
        WizardStep++;
    }

    private void WizardBack() { if (WizardStep > 1) WizardStep--; }

    private async Task SubmitBatchWizard()
    {
        if (SchoolContext.SelectedSchoolId is not { } schoolId) return;

        var phases = WizardIncludeReRegistration
            ? new List<RegistrationPhaseRequest>
            {
                new(WizardPhase1Start, WizardPhase1End, (int)RegistrationPhaseType.ReRegistration, (int)AllowedApplicantType.ReturningOnly),
                new(WizardPhase2Start, WizardPhase2End, (int)RegistrationPhaseType.Open,           (int)AllowedApplicantType.All)
            }
            : new List<RegistrationPhaseRequest>
            {
                new(WizardOpenDate, WizardCloseDate, (int)RegistrationPhaseType.Open, (int)AllowedApplicantType.All)
            };

        var request = new CreateBatchRegistrationSessionsRequest(
            SchoolId: schoolId,
            AcademicYear: SelectedYear,
            GradeDefinitionIds: WizardSelectedGrades.Select(Guid.Parse).ToList(),
            OpenDate: WizardOpenDate,
            CloseDate: WizardCloseDate,
            AssignmentStrategy: (int)WizardStrategy,
            Phases: phases,
            DailyQuota: WizardDailyQuota,
            DailyCutoffTime: WizardCutoffTime);

        var result = await SessionService.CreateBatch(request);
        if (result.IsSuccess)
        {
            CloseWizard();
            await LoadSessionsAsync(schoolId, SelectedYear);
            ExpandedCycles = FilteredSessions.Select(s => s.CycleName).ToHashSet();
        }
    }

    // ── Helpers (pure UI, unchanged) ──────────────────────────────────────
    private void ToggleCycle(string c)
    {
        if (ExpandedCycles.Contains(c)) ExpandedCycles.Remove(c);
        else ExpandedCycles.Add(c);
    }

    private string StatusLabel(RegistrationSessionStatus s) => s switch
    {
        RegistrationSessionStatus.Scheduled => "Planifiée",
        RegistrationSessionStatus.Open      => "Ouverte",
        RegistrationSessionStatus.Closed    => "Fermée",
        RegistrationSessionStatus.Cancelled => "Annulée",
        _ => s.ToString()
    };

    private string StatusClass(RegistrationSessionStatus s) => s switch
    {
        RegistrationSessionStatus.Open      => "text-[#4a9c3f]",
        RegistrationSessionStatus.Scheduled => "text-[#888]",
        RegistrationSessionStatus.Closed    => "text-[#aaa]",
        RegistrationSessionStatus.Cancelled => "text-[#ef4444]",
        _ => "text-[#888]"
    };

    private string StatusDot(RegistrationSessionStatus s) => s switch
    {
        RegistrationSessionStatus.Open      => "bg-[#7db800]",
        RegistrationSessionStatus.Scheduled => "bg-[#bbb]",
        RegistrationSessionStatus.Closed    => "bg-[#ccc]",
        RegistrationSessionStatus.Cancelled => "bg-[#ef4444]",
        _ => "bg-[#bbb]"
    };

    private string StrategyLabel(AssignmentStrategy s) => s switch
    {
        AssignmentStrategy.BalanceLoad     => "Équilibrage",
        AssignmentStrategy.GenderSplit     => "Genre",
        AssignmentStrategy.SiblingGrouping => "Fratrie",
        AssignmentStrategy.ManualOnly      => "Manuel",
        _ => s.ToString()
    };

    private string PhaseTypeLabel(RegistrationPhaseType t) => t switch
    {
        RegistrationPhaseType.ReRegistration => "Ré-inscription",
        RegistrationPhaseType.Open           => "Ouvertes",
        _ => t.ToString()
    };

    private RegistrationPhaseDto? ActivePhase(RegistrationSessionDto s)
    {
        var today = DateOnly.FromDateTime(DateTime.Today);
        return s.Phases.FirstOrDefault(p => p.StartDate <= today && p.EndDate >= today);
    }

    private string CycleBg(string c) => c switch
    {
        "Primaire"  => "bg-[#f0fbcc]",
        "Collégial" => "bg-[#f5f0fb]",
        "Lycée"     => "bg-[#f0f8fb]",
        _ => "bg-[#f5f5f5]"
    };

    private string CycleIcon(string c) => c switch
    {
        "Primaire"  => "text-[#7db800]",
        "Collégial" => "text-[#9b5de5]",
        "Lycée"     => "text-[#0ea5e9]",
        _ => "text-[#888]"
    };
}