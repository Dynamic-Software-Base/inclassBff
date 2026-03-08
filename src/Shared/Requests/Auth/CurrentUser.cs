namespace Shared.Requests.Auth;
public class CurrentUser
{
    public string value { get; set; }
    public string email { get; set; }
    public string fullName { get; set; }
    public int[] roles { get; set; }
    public bool isAuthenticated { get; set; }
    public bool isSchoolOwner { get; set; }
    public bool isTeacher { get; set; }
    public bool isStudent { get; set; }
    public bool isParent { get; set; }
    public bool isPlatformAdmin { get; set; }
}

