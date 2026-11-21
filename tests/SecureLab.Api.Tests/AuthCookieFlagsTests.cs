using System.Net.Http.Json;
using Xunit;

namespace SecureLab.Api.Tests;

public class AuthCookieFlagsTests(SecureLabApiFactory factory)
    : IClassFixture<SecureLabApiFactory>
{
    private static string StudyPassword =>
        Environment.GetEnvironmentVariable("SeedUsers__Password")
        ?? throw new InvalidOperationException("Set local SeedUsers__Password outside Git.");

    private async Task<string[]> LoginCookieAttributesAsync(string baseAddress)
    {
        using var client = factory.CreateClient(new Microsoft.AspNetCore.Mvc.Testing.WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri(baseAddress),
            AllowAutoRedirect = false
        });

        var resp = await client.PostAsJsonAsync("/api/auth/login",
            new { userName = "alice", password = StudyPassword });

        Assert.Equal(System.Net.HttpStatusCode.NoContent, resp.StatusCode);

        var setCookie = resp.Headers.GetValues("Set-Cookie")
            .FirstOrDefault(v => v.StartsWith(".AspNetCore.Identity.Application=", StringComparison.Ordinal));

        Assert.NotNull(setCookie);

        return setCookie!.Split(';', StringSplitOptions.RemoveEmptyEntries)
            .Skip(1)
            .Select(p => p.Trim().ToLowerInvariant())
            .ToArray();
    }

    [Fact]
    public async Task Cookie_OverHttps_Has_HttpOnly_Secure_SameSiteLax_PathRoot_Session()
    {
        var attrs = await LoginCookieAttributesAsync("https://localhost");

        Assert.Contains("httponly", attrs);
        Assert.Contains("secure", attrs);
        Assert.Contains("samesite=lax", attrs);
        Assert.Contains("path=/", attrs);
        Assert.DoesNotContain(attrs, a => a.StartsWith("expires"));
        Assert.DoesNotContain(attrs, a => a.StartsWith("max-age"));
    }

    [Fact]
    public async Task Cookie_OverHttp_Has_NoSecureAttribute()
    {
        var attrs = await LoginCookieAttributesAsync("http://localhost");
        Assert.DoesNotContain("secure", attrs);
    }
}
