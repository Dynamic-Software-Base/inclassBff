using System.ComponentModel.DataAnnotations;

namespace Shared.Requests.School;

public class CreateSchoolRequestDto
{
    [Required]
    [MinLength(5)]
    public string Name { get; set; } = "";
    public string? Ar_Name { get; set; }
    public string? Description { get; set; }

    public CreateSchoolAddressRequestDto Address { get; set; } = new();
    public CreateSchoolContactInfo ContactInfo { get; set; } = new();
    public CreateSchoolGradeLevelOffering GradeLevels { get; set; } = new();

    public List<CreateSchoolPicturesDto> Pictures { get; set; } = new();
}

public class CreateSchoolAddressRequestDto
{
    public string StreetAddress { get; set; } = "";
    public string? BuildingNumber { get; set; }
    public string? ApartmentNumber { get; set; }
    [Required]
    public string City { get; set; } = "";
    [Required]
    public string Region { get; set; } = "";
    [Required]
    [RegularExpression(@"^\d{5}$", ErrorMessage = "Postal code must be exactly 5 digits.")]
    public string PostalCode { get; set; } = "";
    [Required]
    public string Province { get; set; } = "";
}

public class CreateSchoolContactInfo
{
    [EmailAddress]
    public string Email { get; set; } = "";
    [Required]
    [RegularExpression(@"^\d{10}$", ErrorMessage = "Primary phone number must be exactly 10 digits.")]
    public string PrimaryPhoneNumber { get; set; } = "";
    [RegularExpression(@"^\d{10}$", ErrorMessage = "Primary phone number must be exactly 10 digits.")]
    public string? SecondaryPhoneNumber { get; set; }
}

public class CreateSchoolGradeLevelOffering
{
    public bool HasPreSchool { get; set; }
    public bool HasPrimarySchool { get; set; }
    public bool HasMiddleSchool { get; set; }
    public bool HasHighSchool { get; set; }
}

public class CreateSchoolPicturesDto
{
    public Guid PictureId { get; set; }
    public bool IsMain { get; set; }
}