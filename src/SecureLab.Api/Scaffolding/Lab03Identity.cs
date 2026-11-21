using Microsoft.AspNetCore.Identity;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;
using SecureLab.Api.Presentation.Contracts;

using System.Security.Claims;

namespace SecureLab.Api.Scaffolding;

public static class Lab03Identity
{
    public static void AddLab03Identity(this WebApplicationBuilder builder)
    {
        builder.Services.AddIdentity<ApplicationUser, IdentityRole<Guid>>(options =>
        {
            options.User.RequireUniqueEmail = true;
            options.Password.RequiredLength = 10;
        }).AddEntityFrameworkStores<SecureLabDbContext>().AddDefaultTokenProviders();
        builder.Services.AddAuthorization();
        builder.Services.ConfigureApplicationCookie(options =>
        {
            options.Cookie.HttpOnly = true;
            options.Cookie.SameSite = SameSiteMode.Lax;
            options.Cookie.SecurePolicy = builder.Environment.IsDevelopment()
                ? CookieSecurePolicy.SameAsRequest : CookieSecurePolicy.Always;
            options.Events.OnRedirectToLogin = context =>
            {
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                return Task.CompletedTask;
            };
            options.Events.OnRedirectToAccessDenied = context =>
            {
                context.Response.StatusCode = StatusCodes.Status403Forbidden;
                return Task.CompletedTask;
            };
        });
    }

    public static void MapLab03Identity(this WebApplication app)
    {

        app.MapPost("/api/auth/register", async (RegistrationInput input, UserManager<ApplicationUser> users) =>
        {
            var errors = new Dictionary<string, string[]>();

            // 1. Нормалізація та перевірка довжини
            var userName = input.UserName?.Trim() ?? "";
            var email = input.Email?.Trim() ?? "";
            var displayName = input.DisplayName?.Trim() ?? "";

            if (string.IsNullOrWhiteSpace(userName) || userName.Length > 256)
                errors["userName"] = ["Ім'я користувача обов'язкове (до 256 символів)."];

            if (string.IsNullOrWhiteSpace(email) || email.Length > 256)
                errors["email"] = ["Email обов'язковий (до 256 символів)."];

            if (string.IsNullOrWhiteSpace(displayName) || displayName.Length > 120)
                errors["displayName"] = ["DisplayName обов'язковий (до 120 символів)."];

            if (string.IsNullOrWhiteSpace(input.Password))
                errors["password"] = ["Пароль обов'язковий."];

            if (errors.Count > 0)
                return Results.ValidationProblem(errors);

            // 2. Перевірка на дублікат (409 Conflict)
            var existingUser = await users.FindByNameAsync(userName) 
                            ?? await users.FindByEmailAsync(email);
            
            if (existingUser != null)
            {
                return Results.Conflict(new { message = "Користувач із такими даними вже існує." });
            }

            // 3. Створення користувача
            var user = new ApplicationUser 
            { 
                Id = Guid.NewGuid(), 
                UserName = userName, 
                Email = email, 
                DisplayName = displayName 
            };

            var result = await users.CreateAsync(user, input.Password!);

            // 4. Обробка помилок Identity (слабкий пароль тощо)
            if (!result.Succeeded)
            {
                var identityErrors = result.Errors
                    .GroupBy(e => e.Code.Contains("Password") ? "password" : "registration")
                    .ToDictionary(
                        g => g.Key,
                        g => g.Select(e => e.Description).ToArray()
                    );
                
                return Results.ValidationProblem(identityErrors);
            }

            // 5. Призначення ролі за замовчуванням
            var role = await users.AddToRoleAsync(user, DbSeeder.ReporterRole);
            if (!role.Succeeded) throw new InvalidOperationException("Default role assignment failed.");

            // 6. Успіх (201 Created)
            return Results.Created($"/api/users/{user.Id}", new RegisteredUserResponse(
                user.Id, 
                user.UserName!, 
                user.DisplayName!
            ));
        });        

        app.MapPost("/api/auth/login", async (LoginInput input, SignInManager<ApplicationUser> signIn) =>
        {
            if (string.IsNullOrWhiteSpace(input.UserName) || string.IsNullOrEmpty(input.Password))
                return Results.Unauthorized();
            var result = await signIn.PasswordSignInAsync(input.UserName, input.Password, false, false);
            return result.Succeeded ? Results.NoContent() : Results.Unauthorized();
        });
	app.MapPost("/api/auth/logout", async (SignInManager<ApplicationUser> signIn) =>
	{
	    await signIn.SignOutAsync();
	    return Results.NoContent();
	});
        // Виправлено: ID береться лише з claim principal, заголовок X-Demo-UserId ігнорується
        app.MapGet("/api/me", (HttpContext httpContext) =>
        {
            var userId = httpContext.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            if (!Guid.TryParse(userId, out var verifiedUserId))
                return Results.Problem(statusCode: StatusCodes.Status500InternalServerError);

            return Results.Ok(new CurrentUserResponse(
                verifiedUserId,
                httpContext.User.FindFirst(ClaimTypes.Name)?.Value ?? "",
                httpContext.User.FindFirst(ClaimTypes.Role)?.Value ?? ""
            ));
        }).RequireAuthorization();


        // Приклад лише mechanics: не повертає identity і не реалізує оцінювану operation.
        app.MapGet("/api/auth/session-check", () => Results.NoContent()).RequireAuthorization();
    }
}

public sealed record RegistrationInput(string? UserName, string? Email, string? DisplayName, string? Password);
public sealed record LoginInput(string? UserName, string? Password);
