using Contract.InClass.Response.Registration;

namespace inclass.Client.Services.Enroll;

public record SessionSelectedArgs(
    EnrollmentSessionDto Session,
    bool PreSelectReturning
);
