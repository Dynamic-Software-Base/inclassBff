// SchemaModels.cs
namespace inclass.Client.Services.Settings;

public class SchemaSection
{
    public string Key { get; set; } = "";
    public string Title { get; set; } = "";
    public bool IsExpanded { get; set; } = true;
    public int SortOrder { get; set; } = 0;
    public List<SchemaField> Fields { get; set; } = new();
}

public class SchemaField
{
    public string Key { get; set; } = "";
    public string Label { get; set; } = "";
    public FieldType Type { get; set; } = FieldType.Text;
    public bool IsRequired { get; set; } = false;
    public string Placeholder { get; set; } = "";
    public string Hint { get; set; } = "";
    public int SortOrder { get; set; } = 0;
    public List<SelectOption> Options { get; set; } = new();
    public DisplayCondition? Condition { get; set; }
}

public class SelectOption
{
    public string Value { get; set; } = "";
    public string Label { get; set; } = "";
}

public class DisplayCondition
{
    public bool IsEnabled { get; set; } = false;
    public string FieldKey { get; set; } = "";
    public string Operator { get; set; } = "eq";
    public string Value { get; set; } = "";
}

public enum FieldType { Text, Textarea, Number, Date, Boolean, Select }

public static class FieldTypeExtensions
{
    public static string ToLabel(this FieldType t) => t switch
    {
        FieldType.Text     => "text",
        FieldType.Textarea => "textarea",
        FieldType.Number   => "number",
        FieldType.Date     => "date",
        FieldType.Boolean  => "boolean",
        FieldType.Select   => "select",
        _                  => "text"
    };

    /// Tailwind badge classes per type — color-coded
    public static string ToBadgeClass(this FieldType t) => t switch
    {
        FieldType.Text     => "bg-sky-50 text-sky-600 border-sky-200",
        FieldType.Textarea => "bg-violet-50 text-violet-600 border-violet-200",
        FieldType.Number   => "bg-amber-50 text-amber-600 border-amber-200",
        FieldType.Date     => "bg-orange-50 text-orange-600 border-orange-200",
        FieldType.Boolean  => "bg-emerald-50 text-emerald-600 border-emerald-200",
        FieldType.Select   => "bg-pink-50 text-pink-600 border-pink-200",
        _                  => "bg-zinc-100 text-zinc-500 border-zinc-200"
    };
}
