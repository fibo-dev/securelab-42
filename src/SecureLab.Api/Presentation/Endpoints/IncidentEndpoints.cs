using System.Diagnostics;
using SecureLab.Api.Application.Incidents;
using SecureLab.Api.Data.Entities;
using SecureLab.Api.Presentation.Contracts;
using SecureLab.Api.Presentation.Security;

namespace SecureLab.Api.Presentation.Endpoints;

public static class IncidentEndpoints
{
    public static IEndpointRouteBuilder MapIncidentEndpoints(this IEndpointRouteBuilder endpoints)
    {
        var group = endpoints.MapGroup("/api/incidents")
            .WithTags("Incidents");

        group.RequireAuthorization();

        group.MapGet("/", GetListAsync)
            .WithName("GetIncidents")
            .Produces<IReadOnlyList<IncidentListItemResponse>>()
            .ProducesValidationProblem();

        group.MapGet("/{id:guid}", GetDetailsAsync)
            .WithName("GetIncidentDetails")
            .Produces<IncidentDetailsResponse>()
            .ProducesProblem(StatusCodes.Status404NotFound);

        group.MapPut("/{id:guid}", async (Guid id, UpdateIncidentRequest r, HttpContext h, IncidentCommands c, CancellationToken ct) =>
        {
            if (CallerContext.From(h.User) is not { } who) return Results.Challenge();
            return await c.EditContentAsync(id, r, who, ct);
        });

        group.MapDelete("/{id:guid}", async (Guid id, HttpContext h, IncidentCommands c, CancellationToken ct) =>
        {
            if (CallerContext.From(h.User) is not { } who) return Results.Challenge();
            return await c.RemoveAsync(id, who, ct);
        });

        group.MapPost("/{id:guid}/triage", async (Guid id, HttpContext h, IncidentCommands c, CancellationToken ct) =>
        {
            if (CallerContext.From(h.User) is not { } who) return Results.Challenge();
            return await c.TriageAsync(id, who, Activity.Current?.Id ?? h.TraceIdentifier, ct);
        });

        group.MapGet("/severity-summary", GetSeveritySummaryAsync)
            .WithName("GetIncidentSeveritySummary")
            .ProducesProblem(StatusCodes.Status501NotImplemented);

        endpoints.MapGet("/api/incident-comments/{id:guid}", GetCommentAsync)
            .WithName("GetIncidentComment")
            .Produces<IncidentCommentResponse>()
            .ProducesProblem(StatusCodes.Status404NotFound)
            .RequireAuthorization();

        return endpoints;
    }

    private static async Task<IResult> GetListAsync(
        string? status,
        HttpContext httpContext,
        IncidentQueries queries,
        CancellationToken cancellationToken)
    {
        if (CallerContext.From(httpContext.User) is not { } who) return Results.Challenge();

        IncidentStatus? parsedStatus = null;
        if (status is not null)
        {
            if (!Enum.TryParse<IncidentStatus>(status, ignoreCase: true, out var candidate)
                || !Enum.IsDefined(candidate))
            {
                return Results.ValidationProblem(new Dictionary<string, string[]>
                {
                    ["status"] = ["Допустимі значення: New, Triaged, InProgress, Resolved, Closed."]
                });
            }
            parsedStatus = candidate;
        }

        return Results.Ok(await queries.GetListAsync(parsedStatus, who, cancellationToken));
    }

    private static async Task<IResult> GetDetailsAsync(
        Guid id,
        HttpContext httpContext,
        IncidentQueries queries,
        CancellationToken cancellationToken)
    {
        if (CallerContext.From(httpContext.User) is not { } who) return Results.Challenge();

        var incident = await queries.GetDetailsAsync(id, who, cancellationToken);
        return incident is null ? IncidentProblems.NotFound() : Results.Ok(incident);
    }

    private static async Task<IResult> GetCommentAsync(
        Guid id,
        HttpContext httpContext,
        IncidentQueries queries,
        CancellationToken cancellationToken)
    {
        if (CallerContext.From(httpContext.User) is not { } who) return Results.Challenge();

        var note = await queries.GetCommentAsync(id, who, cancellationToken);
        return note is null ? IncidentProblems.NotFound() : Results.Ok(note);
    }

    private static async Task<IResult> GetSeveritySummaryAsync(
        string? status,
        IncidentQueries queries,
        CancellationToken cancellationToken)
    {
        IncidentStatus? parsedStatus = null;

        if (!string.IsNullOrWhiteSpace(status))
        {
            if (!Enum.TryParse<IncidentStatus>(status, ignoreCase: true, out var validStatus) ||
                !Enum.IsDefined(validStatus))
            {
                return Results.ValidationProblem(new Dictionary<string, string[]>
                {
                    { "status", new[] { "Допустимі значення: New, Triaged, InProgress, Resolved, Closed." } }
                });
            }
            parsedStatus = validStatus;
        }

        var summary = await queries.GetSeveritySummaryAsync(parsedStatus, cancellationToken);
        return Results.Ok(summary);
    }
}
