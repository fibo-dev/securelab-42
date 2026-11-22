using Microsoft.EntityFrameworkCore;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;
using SecureLab.Api.Presentation.Contracts;
using SecureLab.Api.Presentation.Security;

namespace SecureLab.Api.Application.Incidents;

public sealed class IncidentCommands(
    SecureLabDbContext dbContext,
    ILogger<IncidentCommands> logger)
{
    private const int TitleMaxLength = 160;
    private const int DescriptionMaxLength = 4000;
    private const int HighSeverityDescriptionMinLength = 40;
    private static readonly TimeSpan FutureTolerance = TimeSpan.FromMinutes(5);

    private static readonly IncidentStatus[] DuplicateBlockingStatuses =
    [
        IncidentStatus.New,
        IncidentStatus.Triaged,
        IncidentStatus.InProgress,
        IncidentStatus.Resolved
    ];

    public async Task<IResult> EditContentAsync(
        Guid id,
        UpdateIncidentRequest request,
        CallerContext who,
        CancellationToken ct)
    {
        var incident = await dbContext.Incidents.SingleOrDefaultAsync(i => i.Id == id, ct);
        if (incident is null ||
            !IncidentAccessRules.IsPermitted(IncidentOperation.EditContent, who, incident.OwnerUserId, incident.Status))
            return IncidentProblems.NotFound();

        var errors = new Dictionary<string, string[]>();
        if (request.Title is not null && (string.IsNullOrWhiteSpace(request.Title) || request.Title.Trim().Length > TitleMaxLength))
            errors["title"] = [$"Заголовок: 1-{TitleMaxLength} символів."];
        if (request.Description is not null && (string.IsNullOrWhiteSpace(request.Description) || request.Description.Trim().Length > DescriptionMaxLength))
            errors["description"] = [$"Опис: 1-{DescriptionMaxLength} символів."];

        IncidentSeverity? sev = null;
        if (request.Severity is not null)
        {
            if (Enum.TryParse<IncidentSeverity>(request.Severity, true, out var s) && Enum.IsDefined(s) && !request.Severity.Contains(','))
                sev = s;
            else
                errors["severity"] = ["Допустимі значення: Low, Medium, High, Critical."];
        }

        if (errors.Count > 0) return Results.ValidationProblem(errors);

        if (request.Title is not null) incident.Title = request.Title.Trim();
        if (request.Description is not null) incident.Description = request.Description.Trim();
        if (sev is not null) incident.Severity = sev.Value;
        incident.UpdatedAtUtc = DateTimeOffset.UtcNow;

        await dbContext.SaveChangesAsync(ct);
        return Results.NoContent();
    }

    public async Task<IResult> RemoveAsync(Guid id, CallerContext who, CancellationToken ct)
    {
        var incident = await dbContext.Incidents.SingleOrDefaultAsync(i => i.Id == id, ct);
        if (incident is null ||
            !IncidentAccessRules.IsPermitted(IncidentOperation.Remove, who, incident.OwnerUserId, incident.Status))
            return IncidentProblems.NotFound();

        dbContext.Incidents.Remove(incident);
        await dbContext.SaveChangesAsync(ct);
        return Results.NoContent();
    }

    public async Task<IResult> TriageAsync(Guid id, CallerContext who, string traceId, CancellationToken ct)
    {
        if (!who.IsAnalyst)
        {
            logger.LogWarning(
                "authorization.denied subject={SubjectId} action={Action} resource={ResourceId} result=denied time={OccurredAtUtc:o} trace={TraceId}",
                who.UserId, "incident.triage", id, DateTimeOffset.UtcNow, traceId);
            return Results.Problem(statusCode: StatusCodes.Status403Forbidden, title: "Forbidden");
        }

        var incident = await dbContext.Incidents.SingleOrDefaultAsync(i => i.Id == id, ct);
        if (incident is null) return IncidentProblems.NotFound();

        if (!IncidentAccessRules.IsPermitted(IncidentOperation.Triage, who, incident.OwnerUserId, incident.Status))
            return Results.Problem(statusCode: StatusCodes.Status409Conflict, title: "Перехід неможливий для поточного статусу");

        incident.Status = IncidentStatus.Triaged;
        incident.UpdatedAtUtc = DateTimeOffset.UtcNow;
        await dbContext.SaveChangesAsync(ct);
        return Results.NoContent();
    }

    public async Task<IResult> CreateAsync(
        CreateIncidentRequest request,
        Guid ownerUserId,
        CancellationToken cancellationToken)
    {
        var now = DateTimeOffset.UtcNow;
        var errors = new Dictionary<string, string[]>();

        if (string.IsNullOrWhiteSpace(request.Title))
            errors["title"] = ["Заголовок обов'язковий."];
        else if (request.Title.Length > TitleMaxLength)
            errors["title"] = [$"Заголовок не довший за {TitleMaxLength} символів."];

        if (string.IsNullOrWhiteSpace(request.Description))
            errors["description"] = ["Опис обов'язковий."];
        else if (request.Description.Length > DescriptionMaxLength)
            errors["description"] = [$"Опис не довший за {DescriptionMaxLength} символів."];

        var severityIsValid =
            Enum.TryParse<IncidentSeverity>(request.Severity, ignoreCase: true, out var severity)
            && Enum.IsDefined(severity)
            && !request.Severity!.Contains(',');

        if (!severityIsValid)
            errors["severity"] = ["Допустимі значення: Low, Medium, High, Critical."];

        if (request.OccurredAtUtc is null)
            errors["occurredAtUtc"] = ["Час події обов'язковий."];
        else if (request.OccurredAtUtc.Value > now.Add(FutureTolerance))
            errors["occurredAtUtc"] = ["Час події не може бути пізніше ніж на 5 хвилин у майбутньому."];

        var title = request.Title?.Trim() ?? "";
        var description = request.Description?.Trim() ?? "";

        if (severityIsValid
            && (severity == IncidentSeverity.High || severity == IncidentSeverity.Critical)
            && !errors.ContainsKey("description")
            && description.Length < HighSeverityDescriptionMinLength)
        {
            errors["description"] =
                [$"Для High і Critical опис має містити щонайменше {HighSeverityDescriptionMinLength} символів."];
        }

        if (errors.Count > 0)
            return Results.ValidationProblem(errors);

        var duplicateExists = await dbContext.Incidents.AnyAsync(
            item => item.Title == title && DuplicateBlockingStatuses.Contains(item.Status),
            cancellationToken);

        if (duplicateExists)
        {
            return Results.Problem(
                statusCode: StatusCodes.Status409Conflict,
                title: "Інцидент уже існує",
                detail: "Активний інцидент із таким заголовком уже зареєстровано.");
        }

        var incident = new Incident
        {
            Id = Guid.NewGuid(),
            OwnerUserId = ownerUserId,
            Title = title,
            Description = description,
            Severity = severity,
            Status = IncidentStatus.New,
            OccurredAtUtc = request.OccurredAtUtc!.Value.ToUniversalTime(),
            CreatedAtUtc = now,
            UpdatedAtUtc = now
        };

        dbContext.Incidents.Add(incident);
        await dbContext.SaveChangesAsync(cancellationToken);
        logger.LogInformation(
            "Incident {IncidentId} created with severity {Severity}", incident.Id, incident.Severity);

        return Results.Created(
            $"/api/incidents/{incident.Id}",
            new CreatedIncidentResponse(
                incident.Id,
                incident.Title,
                incident.Severity.ToString(),
                incident.Status.ToString(),
                incident.OccurredAtUtc,
                incident.CreatedAtUtc));
    }
}
