using System.Net;
using System.Net.Http.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Mvc.Testing;
using SecureLab.Api.Data;

namespace SecureLab.Api.Tests;

public class IncidentAccessControlTests(SecureLabApiFactory factory) : IClassFixture<SecureLabApiFactory>
{
    private static string Secret => Environment.GetEnvironmentVariable("SeedUsers__Password")
        ?? throw new InvalidOperationException("Set local SeedUsers__Password outside Git.");
    private static readonly Guid InternalNote = Guid.Parse("30000000-0000-0000-0000-000000000003");
    private static readonly Guid BobNote = Guid.Parse("30000000-0000-0000-0000-000000000002");

    private Task<HttpClient> As(string user) => factory.LoginAsync(user, Secret);
    private static Task<JsonObject?> Read(HttpClient c, Guid id) => c.GetFromJsonAsync<JsonObject>($"/api/incidents/{id}");

    private static async Task<Guid> CreateOwn(HttpClient c)
    {
        var r = await c.PostAsJsonAsync("/api/incidents", new {
            title = $"LR4 {Guid.NewGuid():N}", description = "Тестовий інцидент для перевірки доступу",
            severity = "Low", occurredAtUtc = DateTimeOffset.UtcNow });
        Assert.Equal(HttpStatusCode.Created, r.StatusCode);
        return Guid.Parse((await r.Content.ReadFromJsonAsync<JsonObject>())!["id"]!.GetValue<string>());
    }

    [Fact] // A-01
    public async Task Anonymous_Details_Returns401()
    {
        using var anon = factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
        var r = await anon.GetAsync($"/api/incidents/{DbSeeder.AliceIncidentId}");
        Assert.Equal(HttpStatusCode.Unauthorized, r.StatusCode);
        Assert.Null(r.Headers.Location);
    }

    [Fact] // A-02
    public async Task Owner_ReadsOwnDetails_Returns200()
    {
        var alice = await As("alice");
        Assert.Equal(HttpStatusCode.OK, (await alice.GetAsync($"/api/incidents/{DbSeeder.AliceIncidentId}")).StatusCode);
    }

    [Fact] // A-03
    public async Task OtherReporter_ReadsForeignDetails_Returns404_WithoutData()
    {
        var alice = await As("alice");
        var r = await alice.GetAsync($"/api/incidents/{DbSeeder.BobIncidentId}");
        Assert.Equal(HttpStatusCode.NotFound, r.StatusCode);
        Assert.DoesNotContain("ownerDisplayName", await r.Content.ReadAsStringAsync());
    }

    [Fact] // A-03R
    public async Task Analyst_ReadsForeignDetails_Returns200()
    {
        var morgan = await As("morgan");
        Assert.Equal(HttpStatusCode.OK, (await morgan.GetAsync($"/api/incidents/{DbSeeder.AliceIncidentId}")).StatusCode);
    }

    [Fact] // A-04
    public async Task NonOwner_UpdateAndDelete_Return404_AndKeepState()
    {
        var alice = await As("alice"); var bob = await As("bob");
        var before = (await Read(bob, DbSeeder.BobIncidentId))!["title"]!.GetValue<string>();
        var put = await alice.PutAsJsonAsync($"/api/incidents/{DbSeeder.BobIncidentId}",
            new { title = "hijack", description = "x", severity = "Low" });
        var del = await alice.DeleteAsync($"/api/incidents/{DbSeeder.BobIncidentId}");
        Assert.Equal(HttpStatusCode.NotFound, put.StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, del.StatusCode);
        Assert.Equal(before, (await Read(bob, DbSeeder.BobIncidentId))!["title"]!.GetValue<string>());
    }

    [Fact] // A-05
    public async Task List_AsReporter_DoesNotContainForeignIncidents()
    {
        var alice = await As("alice");
        var list = (await alice.GetFromJsonAsync<JsonArray>("/api/incidents"))!;
        Assert.DoesNotContain(list, n => n!["id"]!.GetValue<string>() == DbSeeder.BobIncidentId.ToString());
        Assert.Contains(list, n => n!["id"]!.GetValue<string>() == DbSeeder.AliceIncidentId.ToString());
    }

    [Fact] // A-06 + A-09 (відмова без зміни стану)
    public async Task Reporter_Triage_Returns403_AndStatusStaysNew()
    {
        var alice = await As("alice");
        var id = await CreateOwn(alice);
        try
        {
            var r = await alice.PostAsync($"/api/incidents/{id}/triage", null);
            Assert.Equal(HttpStatusCode.Forbidden, r.StatusCode);
            Assert.Equal("New", (await Read(alice, id))!["status"]!.GetValue<string>());
        }
        finally { await alice.DeleteAsync($"/api/incidents/{id}"); }
    }

    [Fact] // A-07
    public async Task Analyst_Triage_NewIncident_Returns204_AndStatusIsTriaged()
    {
        var alice = await As("alice"); var morgan = await As("morgan");
        var id = await CreateOwn(alice);
        try
        {
            var r = await morgan.PostAsync($"/api/incidents/{id}/triage", null);
            Assert.Equal(HttpStatusCode.NoContent, r.StatusCode);
            Assert.Equal("Triaged", (await Read(alice, id))!["status"]!.GetValue<string>());
            Assert.Equal(HttpStatusCode.Conflict, (await morgan.PostAsync($"/api/incidents/{id}/triage", null)).StatusCode);
        }
        finally { await alice.DeleteAsync($"/api/incidents/{id}"); }
    }

    [Fact] // A-08a
    public async Task Update_IgnoresForgedOwnerStatusRole()
    {
        var alice = await As("alice");
        var id = await CreateOwn(alice);
        try
        {
            var before = await Read(alice, id);
            var r = await alice.PutAsJsonAsync($"/api/incidents/{id}", new {
                title = "Оновлено власником", description = "нова", severity = "Low",
                ownerUserId = "10000000-0000-0000-0000-000000000002", status = "Closed", role = "Analyst" });
            Assert.Equal(HttpStatusCode.NoContent, r.StatusCode);
            var after = await Read(alice, id);
            Assert.Equal("Оновлено власником", after!["title"]!.GetValue<string>());
            Assert.Equal(before!["status"]!.GetValue<string>(), after["status"]!.GetValue<string>());
            Assert.Equal(before["ownerDisplayName"]!.GetValue<string>(), after["ownerDisplayName"]!.GetValue<string>());
        }
        finally { await alice.DeleteAsync($"/api/incidents/{id}"); }
    }

    [Fact] // A-10
    public async Task ForeignAndUnknownId_GiveSameResponse()
    {
        var alice = await As("alice");
        var foreign = await alice.GetAsync($"/api/incidents/{DbSeeder.BobIncidentId}");
        var unknown = await alice.GetAsync($"/api/incidents/{Guid.NewGuid()}");
        Assert.Equal(unknown.StatusCode, foreign.StatusCode);
        Assert.Equal(unknown.Content.Headers.ContentType?.ToString(), foreign.Content.Headers.ContentType?.ToString());
        var f = await foreign.Content.ReadFromJsonAsync<JsonObject>(); var u = await unknown.Content.ReadFromJsonAsync<JsonObject>();
        f!.Remove("traceId"); u!.Remove("traceId");
        Assert.True(JsonNode.DeepEquals(u, f));
    }

    [Fact] // A-12
    public async Task Comments_HiddenFromReporter_VisibleToAnalyst()
    {
        var alice = await As("alice"); var morgan = await As("morgan");
        Assert.Equal(HttpStatusCode.NotFound, (await alice.GetAsync($"/api/incident-comments/{InternalNote}")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await alice.GetAsync($"/api/incident-comments/{BobNote}")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await morgan.GetAsync($"/api/incident-comments/{InternalNote}")).StatusCode);
    }
}
