using Microsoft.EntityFrameworkCore;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;
using SecureLab.Api.Presentation.Contracts;
using SecureLab.Api.Presentation.Security;

namespace SecureLab.Api.Application.Incidents;

public sealed class IncidentQueries(SecureLabDbContext dbContext, ILogger<IncidentQueries> logger)
{
    public async Task<IReadOnlyList<IncidentListItemResponse>> GetListAsync(
        IncidentStatus? status,
        CallerContext who,
        CancellationToken cancellationToken)
    {
        logger.LogInformation("Loading incidents with status filter {Status} for user {UserId}", status, who.UserId);

        var query = dbContext.Incidents.AsNoTracking().VisibleTo(who);
        if (status is not null)
        {
            query = query.Where(incident => incident.Status == status);
        }

        return await query
            .OrderByDescending(incident => incident.CreatedAtUtc)
            .Select(incident => new IncidentListItemResponse(
                incident.Id,
                incident.Title,
                incident.Severity.ToString(),
                incident.Status.ToString(),
                incident.OccurredAtUtc,
                incident.CreatedAtUtc))
            .ToListAsync(cancellationToken);
    }

    public Task<IncidentDetailsResponse?> GetDetailsAsync(
        Guid id,
        CallerContext who,
        CancellationToken cancellationToken)
    {
        logger.LogInformation("Loading incident {IncidentId}", id);
        var showInternal = who.IsAnalyst;

        return dbContext.Incidents
            .AsNoTracking()
            .VisibleTo(who)
            .Where(incident => incident.Id == id)
            .Select(incident => new IncidentDetailsResponse(
                incident.Id,
                incident.Title,
                incident.Description,
                incident.Severity.ToString(),
                incident.Status.ToString(),
                incident.OccurredAtUtc,
                incident.CreatedAtUtc,
                incident.Owner.DisplayName,
                incident.Comments
                    .Where(comment => showInternal || !comment.IsInternal)
                    .OrderBy(comment => comment.CreatedAtUtc)
                    .Select(comment => new IncidentCommentResponse(
                        comment.Id,
                        comment.Author.DisplayName,
                        comment.Text,
                        comment.CreatedAtUtc))
                    .ToList()))
            .SingleOrDefaultAsync(cancellationToken);
    }

    public Task<IncidentCommentResponse?> GetCommentAsync(
        Guid commentId,
        CallerContext who,
        CancellationToken cancellationToken)
    {
        var uid = who.UserId;
        var analyst = who.IsAnalyst;
        return dbContext.IncidentComments.AsNoTracking()
            .Where(c => c.Id == commentId && (analyst || (!c.IsInternal && c.Incident.OwnerUserId == uid)))
            .Select(c => new IncidentCommentResponse(c.Id, c.Author.DisplayName, c.Text, c.CreatedAtUtc))
            .SingleOrDefaultAsync(cancellationToken);
    }

    public async Task<IReadOnlyList<IncidentSeveritySummaryResponse>> GetSeveritySummaryAsync(
        IncidentStatus? status,
        CancellationToken cancellationToken)
    {
        logger.LogInformation("Loading severity summary. FilterStatus: {Status}", status);

        var query = dbContext.Incidents.AsNoTracking();

        if (status.HasValue)
        {
            query = query.Where(incident => incident.Status == status.Value);
        }

        var summary = await query
            .GroupBy(incident => incident.Severity)
            .Select(group => new IncidentSeveritySummaryResponse(
                group.Key.ToString(),
                group.Count()))
            .ToListAsync(cancellationToken);

        var severityOrder = new Dictionary<IncidentSeverity, int>
        {
            { IncidentSeverity.Critical, 1 },
            { IncidentSeverity.High, 2 },
            { IncidentSeverity.Medium, 3 },
            { IncidentSeverity.Low, 4 }
        };

        return summary
            .OrderBy(item => severityOrder.TryGetValue(Enum.Parse<IncidentSeverity>(item.Severity), out var order) ? order : 99)
            .ToList();
    }
}
