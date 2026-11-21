using SecureLab.Api.Application.Incidents;
using SecureLab.Api.Presentation.Contracts;

using Microsoft.EntityFrameworkCore;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;

namespace SecureLab.Api.Scaffolding;

// Навчальний старт ЛР 02. Запускати лише з локальними штучними даними.
public static class Lab02Endpoints
{
    public static void MapLab02Endpoints(this WebApplication app)
    {
        // ЛР 2: Безпечний пошук через LINQ та параметризацію
        app.MapGet("/api/incidents/search", async (string? q, string? sortBy, SecureLabDbContext db, CancellationToken ct) =>
        {
            // 1. Allowlist для sortBy
            if (!string.IsNullOrWhiteSpace(sortBy) && sortBy != "createdAtUtc" && sortBy != "severity" && sortBy != "status")
            {
                return Results.ValidationProblem(new Dictionary<string, string[]> { 
                    { "sortBy", new[] { "Допустимі значення: createdAtUtc, severity, status." } } 
                });
            }

            var query = db.Incidents.AsNoTracking();

            // 2. Безпечний пошук з екрануванням (параметризація + ILike)
            if (!string.IsNullOrWhiteSpace(q))
            {
                // Екрануємо символи ILIKE-патернів: \, %, _
                var escapedQ = q.Replace("\\", "\\\\").Replace("%", "\\%").Replace("_", "\\_");
                var pattern = $"%{escapedQ}%";
                
                query = query.Where(i => EF.Functions.ILike(i.Title, pattern, "\\") 
                                      || EF.Functions.ILike(i.Description, pattern, "\\"));
            }

            // 3. Явне ранжування для severity/status (бо вони зберігаються як текст)
            query = sortBy switch
            {
                "severity" => query.OrderBy(i => i.Severity == IncidentSeverity.Critical ? 1 :
                                                i.Severity == IncidentSeverity.High ? 2 :
                                                i.Severity == IncidentSeverity.Medium ? 3 : 4),
                "status" => query.OrderBy(i => i.Status == IncidentStatus.New ? 1 :
                                              i.Status == IncidentStatus.Triaged ? 2 :
                                              i.Status == IncidentStatus.InProgress ? 3 :
                                              i.Status == IncidentStatus.Resolved ? 4 : 5),
                _ => query.OrderByDescending(i => i.CreatedAtUtc) // За замовчуванням
            };

            var rows = await query.Take(50).ToListAsync(ct);

            return Results.Ok(rows.Select(row => new
            {
                row.Id, row.Title, row.Description,
                Severity = row.Severity.ToString(), Status = row.Status.ToString(), row.CreatedAtUtc
            }));
        });


        app.MapPost("/api/incidents", async (
            CreateIncidentRequest request,
            IncidentCommands commands,
            CancellationToken cancellationToken) =>
            await commands.CreateAsync(request, cancellationToken));
    }
}

