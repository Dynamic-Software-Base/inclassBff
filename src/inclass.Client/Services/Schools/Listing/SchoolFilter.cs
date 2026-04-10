namespace inclass.Client.Services.Schools.Listing;

public record SchoolFilter(
    string SearchText,
    string City,
    bool PreSchool,
    bool Primary,
    bool Middle,
    bool High);