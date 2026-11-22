using SecureLab.Api.Data.Entities;
using SecureLab.Api.Presentation.Security;
namespace SecureLab.Api.Application.Incidents;

public enum IncidentOperation { ReadDetails, EditContent, Remove, Triage }

public static class IncidentAccessRules
{
    public static bool IsPermitted(IncidentOperation op, CallerContext who, Guid ownerId, IncidentStatus status) => op switch
    {
        IncidentOperation.ReadDetails => who.IsAnalyst || ownerId == who.UserId,
        IncidentOperation.EditContent or IncidentOperation.Remove => ownerId == who.UserId,
        IncidentOperation.Triage => who.IsAnalyst && status == IncidentStatus.New,
        _ => false
    };

    public static IQueryable<Incident> VisibleTo(this IQueryable<Incident> source, CallerContext who)
    {
        var uid = who.UserId;
        return who.IsAnalyst ? source : source.Where(i => i.OwnerUserId == uid);
    }
}

public static class IncidentProblems
{
    public static IResult NotFound() => Results.Problem(statusCode: 404, title: "Інцидент не знайдено");
}
