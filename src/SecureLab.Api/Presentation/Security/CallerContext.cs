using System.Security.Claims;
using SecureLab.Api.Data;
namespace SecureLab.Api.Presentation.Security;

public readonly record struct CallerContext(Guid UserId, bool IsAnalyst)
{
    public static CallerContext? From(ClaimsPrincipal user) =>
        Guid.TryParse(user.FindFirstValue(ClaimTypes.NameIdentifier), out var id)
            ? new CallerContext(id, user.IsInRole("Analyst"))
            : null;
}
