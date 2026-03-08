namespace InClass.Client.Auth;

public class MeResponse
{
    public string? Id { get; set; }
    public string? Email { get; set; }
    public string? FullName { get; set; }
    public List<string> Roles { get; set; } = [];
    public bool IsAuthenticated { get; set; }
}