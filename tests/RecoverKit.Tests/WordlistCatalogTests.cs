using System.Net;
using System.Text.Json;
using RecoverKit.Core.Attacks;
using Xunit;

namespace RecoverKit.Tests;

public sealed class WordlistCatalogTests : IDisposable
{
    private readonly string dir = Path.Combine(Path.GetTempPath(), "rk-wordlists-" + Guid.NewGuid());
    internal static string Fixture(string name) => File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Fixtures", "Wordlists", name));
    public void Dispose() { if (Directory.Exists(dir)) Directory.Delete(dir, true); }

    [Fact]
    public async Task PagesAreSequentialAndFailedRefreshKeepsCache()
    {
        int calls = 0;
        using var http = new HttpClient(new Handler(request =>
        {
            calls++;
            Assert.Contains($"page={calls}", request.RequestUri!.Query);
            return calls == 1 ? Json(Fixture("page.json")) : Json("""{"data":[],"links":{"next":null}}""");
        }));
        var catalog = new WeakpassCatalog(dir, http);
        Assert.Null(await catalog.LoadAsync());
        var cache = await catalog.RefreshAsync();
        Assert.Equal(2, calls);
        Assert.Equal(4, cache.Items.Count);
        Assert.False(WeakpassCatalog.RefreshDue(cache, cache.FetchedAt.AddHours(23)));
        Assert.True(WeakpassCatalog.RefreshDue(cache, cache.FetchedAt.AddHours(24)));
        Assert.True(WeakpassCatalog.RefreshDue(cache, cache.FetchedAt.AddMinutes(-1)));
        using var failing = new HttpClient(new Handler(_ => new(HttpStatusCode.ServiceUnavailable)));
        await Assert.ThrowsAsync<HttpRequestException>(() => new WeakpassCatalog(dir, failing).RefreshAsync());
        Assert.Equal(cache.FetchedAt, (await catalog.LoadAsync())!.FetchedAt);
    }

    [Fact]
    public async Task DetailsAreParsedAndReusedUntilCatalogRefresh()
    {
        int calls = 0;
        using var http = new HttpClient(new Handler(_ => { calls++; return Json(Fixture("detail.json")); }));
        var catalog = new WeakpassCatalog(dir, http);
        var entry = WeakpassCatalog.ParsePage(Fixture("page.json")).Data.First(x => x.Id == 1934);
        var detail = await catalog.DetailAsync(entry, DateTimeOffset.MinValue);
        Assert.Equal(10000, detail.Count);
        Assert.Equal(80456, detail.Size);
        Assert.Equal("e2bfa126fd50e8d778a42c9eeeb804b4", detail.Checksum);
        Assert.NotEmpty(detail.Masks);
        Assert.NotEmpty(detail.LengthDistribution);
        await catalog.DetailAsync(entry, DateTimeOffset.MinValue);
        Assert.Equal(1, calls);
        await catalog.DetailAsync(entry, DateTimeOffset.UtcNow.AddMinutes(1));
        Assert.Equal(2, calls);
    }

    [Fact]
    public void FiltersSortsAndEstimatesUse64BitValues()
    {
        var items = new[] {
            new WeakpassWordlist { Id = 1, Name = "BIG", Rank = "S", Size = 150_000_000_000, Count = 20_000_000_000, Rate = 20 },
            new WeakpassWordlist { Id = 2, Name = "small.txt", Rank = "A", Size = 100, Count = 1000, Rate = 10 },
            new WeakpassWordlist { Id = 3, Name = "small2", Rank = null, Size = 200, Count = 2000, Rate = 5 }
        };
        Assert.Equal([2L], WordlistQuery.Apply(items, new() { Search = "SMALL", Ranks = ["A"], MaxSize = 1000, MinRate = 6 }).Select(x => x.Id));
        Assert.Equal([2L, 1L, 3L], WordlistQuery.Apply(items, new() { Sort = WordlistSort.Rank, Descending = true }).Select(x => x.Id));
        Assert.Equal([2L, 3L, 1L], WordlistQuery.Apply(items, new() { Sort = WordlistSort.Time, Speed = 100, RuleOutputs = 2 }).Select(x => x.Id));
        Assert.Equal(400_000_000, WordlistQuery.Seconds(items[0].Count, 2, 100));
        Assert.Null(WordlistQuery.Seconds(100, null, 100));
        Assert.Null(WordlistQuery.Seconds(100, 1, 0));
    }

    [Fact]
    public void DescriptionIsTextWithSafeLinksAndLengthsAreBucketed()
    {
        var description = WordlistText.Description("<b>From</b> <a href='https://example.org/list'>source</a><script>bad()</script> &amp; more");
        Assert.Equal("From source & more", description.Text);
        Assert.Contains("https://example.org/list", description.Links);
        Assert.Empty(WordlistText.Description("<a href='javascript:bad()'>bad</a>").Links);
        var buckets = WordlistText.LengthBuckets([new(4, 10), new(17, 20), new(50, 30)]);
        Assert.Equal(10, buckets[0]);
        Assert.Equal(50, buckets[^1]);
    }

    [Fact]
    public void CatalogDropsEntriesWithoutIdentity()
    {
        var page = WeakpassCatalog.ParsePage("""{"data":[{"id":1,"name":null},{"name":"missing id"},{"id":2,"name":"ok"}],"links":{"next":null}}""");
        Assert.Equal([2L], page.Data.Select(x => x.Id));
        Assert.Single(WordlistQuery.Apply(page.Data, new()));
    }

    [Theory]
    [InlineData("{}")]
    [InlineData("{\"data\":null,\"links\":{\"next\":null}}")]
    [InlineData("{\"links\":{\"next\":null}}")]
    public async Task MalformedPagesNeverReplaceCache(string json)
    {
        Directory.CreateDirectory(dir);
        string file = Path.Combine(dir, "catalog.json");
        const string previous = "{\"fetched_at\":\"2026-01-01T00:00:00Z\",\"items\":[{\"id\":2,\"name\":\"ok\"}]}";
        await File.WriteAllTextAsync(file, previous);
        using var http = new HttpClient(new Handler(_ => Json(json)));
        await Assert.ThrowsAsync<JsonException>(() => new WeakpassCatalog(dir, http).RefreshAsync());
        Assert.Equal(previous, await File.ReadAllTextAsync(file));
    }

    [Theory]
    [InlineData("{}")]
    [InlineData("{\"items\":null}")]
    [InlineData("{\"items\":[null]}")]
    public async Task BadCatalogCacheFallsBackToNoCache(string json)
    {
        Directory.CreateDirectory(dir);
        await File.WriteAllTextAsync(Path.Combine(dir, "catalog.json"), json);
        Assert.Null(await new WeakpassCatalog(dir).LoadAsync());
    }

    [Theory]
    [InlineData("{}")]
    [InlineData("{\"data\":null}")]
    [InlineData("{\"data\":{\"id\":1,\"name\":null}}")]
    public async Task MissingDetailIsAParseErrorAndIsNotCached(string json)
    {
        using var http = new HttpClient(new Handler(_ => Json(json)));
        await Assert.ThrowsAsync<JsonException>(() => new WeakpassCatalog(dir, http).DetailAsync(new() { Id = 1, Name = "x" }, DateTimeOffset.MinValue));
        Assert.False(File.Exists(Path.Combine(dir, "detail-1.json")));
    }

    [Fact]
    public async Task NullDetailArraysAreEmptyIncludingCachedDetails()
    {
        using var http = new HttpClient(new Handler(_ => Json("""{"data":{"id":1,"name":"x","examples":null,"masks":null,"top_masks":null,"length_distribution":null}}""")));
        var catalog = new WeakpassCatalog(dir, http);
        for (int i = 0; i < 2; i++)
        {
            var detail = await catalog.DetailAsync(new() { Id = 1, Name = "x" }, DateTimeOffset.MinValue);
            Assert.Empty(detail.Examples); Assert.Empty(detail.Masks);
            Assert.Empty(detail.TopMasks); Assert.Empty(detail.LengthDistribution);
        }
    }

    [Theory]
    [InlineData(false, 2)]
    [InlineData(true, 100)]
    public async Task EndlessCatalogFailsWithoutSaving(bool newIds, int expectedCalls)
    {
        int calls = 0;
        using var http = new HttpClient(new Handler(_ =>
        {
            calls++;
            return Json("""{"data":[{"id":ID,"name":"x"}],"links":{"next":"more"}}""".Replace("ID", (newIds ? calls : 1).ToString()));
        }));
        await Assert.ThrowsAsync<IOException>(() => new WeakpassCatalog(dir, http).RefreshAsync());
        Assert.Equal(expectedCalls, calls);
        Assert.False(File.Exists(Path.Combine(dir, "catalog.json")));
    }

    [Fact]
    public async Task PagePastLastPageFailsWithoutSaving()
    {
        using var http = new HttpClient(new Handler(_ => Json("""{"data":[{"id":1,"name":"x"}],"links":{"next":"more"},"meta":{"current_page":3,"last_page":2}}""")));
        await Assert.ThrowsAsync<IOException>(() => new WeakpassCatalog(dir, http).RefreshAsync());
        Assert.False(File.Exists(Path.Combine(dir, "catalog.json")));
    }

    [Fact]
    public async Task DuplicateFinalPageFailsWithoutSaving()
    {
        int calls = 0;
        using var http = new HttpClient(new Handler(_ => Json(++calls == 1
            ? """{"data":[{"id":1,"name":"x"}],"links":{"next":"more"}}"""
            : """{"data":[{"id":1,"name":"x"}],"links":{"next":null}}""")));
        await Assert.ThrowsAsync<IOException>(() => new WeakpassCatalog(dir, http).RefreshAsync());
        Assert.Equal(2, calls);
        Assert.False(File.Exists(Path.Combine(dir, "catalog.json")));
    }

    internal static HttpResponseMessage Json(string text) => new(HttpStatusCode.OK) { Content = new StringContent(text) };
    internal sealed class Handler(Func<HttpRequestMessage, HttpResponseMessage> reply) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) => Task.FromResult(reply(request));
    }
}
