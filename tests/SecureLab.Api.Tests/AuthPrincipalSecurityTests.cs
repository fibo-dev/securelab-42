using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Xunit;

namespace SecureLab.Api.Tests;

public class AuthPrincipalSecurityTests(SecureLabApiFactory factory)
    : IClassFixture<SecureLabApiFactory>
{
    private static string StudyPassword =>
        Environment.GetEnvironmentVariable("SeedUsers__Password")
        ?? throw new InvalidOperationException("Set local SeedUsers__Password outside Git.");

    // A-01: анонім → 401 без redirect
    [Fact]
    public async Task Anon_Me_Returns401_NotRedirectOrChallenge()
    {
        using var anon = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false
        });

        var resp = await anon.GetAsync("/api/me");

        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
        Assert.Null(resp.Headers.Location);
        Assert.Empty(resp.Headers.WwwAuthenticate);
        Assert.Equal("application/problem+json", resp.Content.Headers.ContentType?.MediaType);
    }

    // A-02: Alice → /api/me = 3 безпечні поля
    [Fact]
    public async Task Login_Me_ReturnsThreeSafeFields()
    {
        var alice = await factory.LoginAsync("alice", StudyPassword);
        var resp = await alice.GetAsync("/api/me");

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        var root = doc.RootElement;

	Assert.Equal("10000000-0000-0000-0000-000000000001", root.GetProperty("id").GetString());
        Assert.Equal("alice", root.GetProperty("userName").GetString());
        Assert.Equal("Reporter", root.GetProperty("role").GetString());
        Assert.Equal(3, root.EnumerateObject().Count());
    }

    // A-03: cookie Alice + заголовок Bob → залишається Alice
    [Fact]
    public async Task ForgedHeader_DoesNotOverrideCookie()
    {
        var alice = await factory.LoginAsync("alice", StudyPassword);
        var req = new HttpRequestMessage(HttpMethod.Get, "/api/me");
        req.Headers.Add("X-Demo-UserId", "10000000-0000-0000-0000-000000000002");

        var resp = await alice.SendAsync(req);
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        Assert.Equal("alice", doc.RootElement.GetProperty("userName").GetString());
    }

    // A-04: Bob створює інцидент → owner = Bob
    [Fact]
    public async Task Bob_CreatesIncident_OwnerIsBob()
    {
        var bob = await factory.LoginAsync("bob", StudyPassword);
        var unique = $"Bob - {Guid.NewGuid():N}";

        var resp = await bob.PostAsJsonAsync("/api/incidents", new
        {
            title = unique,
            description = "Тест власника з cookie",
            severity = "Low",
            occurredAtUtc = DateTimeOffset.UtcNow
        });

        Assert.Equal(HttpStatusCode.Created, resp.StatusCode);

        using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        var incidentId = doc.RootElement.GetProperty("id").GetGuid();

        // Перевіряємо через /api/incidents/{id} — там ownerDisplayName
        var details = await bob.GetAsync($"/api/incidents/{incidentId}");
        using var ddoc = JsonDocument.Parse(await details.Content.ReadAsStringAsync());
	Assert.Equal("Боб Мельник", ddoc.RootElement.GetProperty("ownerDisplayName").GetString());
    }

    // A-05: спроба підставити ownerUserId → ігнорується
    [Fact]
    public async Task ForgedOwnerUserId_IsIgnored()
    {
        var bob = await factory.LoginAsync("bob", StudyPassword);
        var unique = $"Bob fake - {Guid.NewGuid():N}";

        var resp = await bob.PostAsJsonAsync("/api/incidents", new
        {
            title = unique,
            description = "Спроба підставити Alice",
            severity = "Low",
            occurredAtUtc = DateTimeOffset.UtcNow,
            ownerUserId = "10000000-0000-0000-0000-000000000001",
            status = "Closed"
        });

        Assert.Equal(HttpStatusCode.Created, resp.StatusCode);
        using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        var id = doc.RootElement.GetProperty("id").GetGuid();

        var details = await bob.GetAsync($"/api/incidents/{id}");
        using var ddoc = JsonDocument.Parse(await details.Content.ReadAsStringAsync());
	Assert.Equal("Боб Мельник", ddoc.RootElement.GetProperty("ownerDisplayName").GetString());
    }

    // A-06: logout → наступний /api/me = 401
    [Fact]
    public async Task Logout_MakesMeUnauthorized()
    {
        var alice = await factory.LoginAsync("alice", StudyPassword);
        var meBefore = await alice.GetAsync("/api/me");
        Assert.Equal(HttpStatusCode.OK, meBefore.StatusCode);

        var logout = await alice.PostAsync("/api/auth/logout", null);
        Assert.Equal(HttpStatusCode.NoContent, logout.StatusCode);

        var meAfter = await alice.GetAsync("/api/me");
        Assert.Equal(HttpStatusCode.Unauthorized, meAfter.StatusCode);
    }

    // A-07: невідомий user і хибний пароль — однаковий зовнішній результат
    [Fact]
    public async Task UnknownUser_And_WrongPassword_ReturnSameExternalResult()
    {
        var client = factory.CreateClient();

        var r1 = await client.PostAsJsonAsync("/api/auth/login",
            new { userName = "does_not_exist", password = "anyPassword123!" });
        var r2 = await client.PostAsJsonAsync("/api/auth/login",
            new { userName = "alice", password = "wrongPassword123!" });

        Assert.Equal(r1.StatusCode, r2.StatusCode);
        Assert.Equal(r1.Content.Headers.ContentType?.MediaType,
                     r2.Content.Headers.ContentType?.MediaType);

        // Обидва — 401, тіла або нема, або однакової форми
        Assert.Equal(HttpStatusCode.Unauthorized, r1.StatusCode);
    }
}
