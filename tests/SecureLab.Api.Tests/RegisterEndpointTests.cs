using System.Net;
using System.Net.Http.Json;
using Xunit;

namespace SecureLab.Api.Tests;

public class RegisterEndpointTests(SecureLabApiFactory factory) : IClassFixture<SecureLabApiFactory>
{
    [Fact]
    public async Task Register_ValidUser_Returns201WithThreeFields()
    {
        var client = factory.CreateClient();
        var response = await client.PostAsJsonAsync("/api/auth/register", new {
            userName = "reg_valid_1", email = "reg_valid_1@example.com",
            displayName = "Valid User", password = "ValidPass123!"
        });
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync();
        Assert.Contains("userName", body);
        Assert.Contains("displayName", body);
        Assert.DoesNotContain("password", body.ToLower());
    }

    [Fact]
    public async Task Register_Duplicate_Returns409()
    {
        var client = factory.CreateClient();
        var payload = new { userName = "reg_dup_1", email = "reg_dup_1@example.com",
            displayName = "Dup", password = "ValidPass123!" };
        await client.PostAsJsonAsync("/api/auth/register", payload);
        var second = await client.PostAsJsonAsync("/api/auth/register", payload);
        Assert.Equal(HttpStatusCode.Conflict, second.StatusCode);
    }

    [Fact]
    public async Task Register_WeakPassword_Returns400AndDoesNotCreateUser()
    {
        var client = factory.CreateClient();
        var response = await client.PostAsJsonAsync("/api/auth/register", new {
            userName = "reg_weak", email = "reg_weak@example.com",
            displayName = "Weak", password = "123"
        });
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task Register_ExtraFields_Ignored_ServerAssignsRole()
    {
        var client = factory.CreateClient();
        var response = await client.PostAsJsonAsync("/api/auth/register", new {
            userName = "reg_extra", email = "reg_extra@example.com",
            displayName = "Extra", password = "ValidPass123!",
            id = "11111111-1111-1111-1111-111111111111",
            role = "Admin"
        });
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync();
        Assert.DoesNotContain("11111111", body);
    }
}
