using System.Net;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace RecoverKit.Core.Attacks;

public record WeakpassWordlist
{
    public long Id { get; init; }
    public string Name { get; init; } = "";
    public string? Slug { get; init; }
    public long Size { get; init; }
    public long SizeCompressed { get; init; }
    public long Count { get; init; }
    public string? Rank { get; init; }
    public double Rate { get; init; }
    public string? DownloadUrl { get; init; }
    public string? Url { get; init; }
}

public sealed record WeakpassDetail : WeakpassWordlist
{
    public string? Description { get; init; }
    public string? Checksum { get; init; }
    public string? ChecksumCompressed { get; init; }
    public long Downloaded { get; init; }
    public DateTimeOffset? CreatedAt { get; init; }
    public DateTimeOffset? UpdatedAt { get; init; }
    public string[] Examples { get; init; } = [];
    public WordlistMask[] Masks { get; init; } = [];
    public WordlistMask[] TopMasks { get; init; } = [];
    public WordlistLength[] LengthDistribution { get; init; } = [];
}

public sealed record WordlistMask(string Mask, long Count);
public sealed record WordlistLength(int Length, long Count);
public sealed record WordlistCatalogCache(DateTimeOffset FetchedAt, List<WeakpassWordlist> Items);
public sealed record WordlistPage(List<WeakpassWordlist> Data, WordlistPageLinks Links, WordlistPageMeta? Meta = null);
public sealed record WordlistPageMeta(int CurrentPage, int LastPage);
public sealed record WordlistPageLinks(string? Next);

/// <summary>All network work is explicit. Constructing or reading this cache never contacts weakpass.</summary>
public sealed class WeakpassCatalog
{
    public const string Api = "https://weakpass.com/api/v1";
    internal static readonly JsonSerializerOptions Json = new() { PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower, WriteIndented = true };
    private static readonly HttpClient SharedHttp = CreateHttp();
    private readonly HttpClient http;
    private readonly string directory;
    private readonly SemaphoreSlim refresh = new(1);
    private sealed record DetailCache(DateTimeOffset FetchedAt, WeakpassDetail Data);

    public WeakpassCatalog(string? cacheDirectory = null, HttpClient? client = null)
    {
        directory = cacheDirectory ?? Path.Combine(Settings.AppDataDir, "wordlists");
        http = client ?? SharedHttp;
    }

    internal static HttpClient Client => SharedHttp;
    private static HttpClient CreateHttp()
    {
        var client = new HttpClient { Timeout = TimeSpan.FromSeconds(60) };
        client.DefaultRequestHeaders.UserAgent.ParseAdd("RecoverKit/1.0");
        return client;
    }

    private static bool Valid(WeakpassWordlist? item) => item is { Id: > 0 } && !string.IsNullOrWhiteSpace(item.Name);

    public static WordlistPage ParsePage(string json)
    {
        var page = JsonSerializer.Deserialize<WordlistPage>(json, Json);
        if (page is not { Data: not null, Links: not null }) throw new JsonException("The wordlist catalog page is incomplete.");
        return page with { Data = page.Data.Where(Valid).ToList() };
    }

    public async Task<WordlistCatalogCache?> LoadAsync(CancellationToken ct = default)
    {
        var cache = await ReadAsync<WordlistCatalogCache>(Path.Combine(directory, "catalog.json"), ct);
        return cache is { Items: not null } && cache.FetchedAt != default && cache.Items.All(Valid) ? cache : null;
    }

    public static bool RefreshDue(WordlistCatalogCache? cache, DateTimeOffset now)
        => cache is null || now < cache.FetchedAt || now - cache.FetchedAt >= TimeSpan.FromHours(24);

    public async Task<WordlistCatalogCache> RefreshAsync(CancellationToken ct = default)
    {
        await refresh.WaitAsync(ct);
        try
        {
            var all = new List<WeakpassWordlist>();
            var ids = new HashSet<long>();
            for (int page = 1; page <= 100; page++)
            {
                var json = await http.GetStringAsync($"{Api}/wordlists?per_page=100&page={page}", ct);
                var result = ParsePage(json);
                if (result.Meta is { } meta && meta.CurrentPage > meta.LastPage)
                    throw new IOException("The wordlist catalog returned a page past its end. Retry the refresh.");
                var added = result.Data.Where(x => ids.Add(x.Id)).ToList();
                if (added.Count == 0 && (result.Data.Count > 0 || result.Links.Next is not null))
                    throw new IOException("The wordlist catalog stopped adding lists. Retry the refresh.");
                all.AddRange(added);
                if (result.Links.Next is null)
                {
                    var cache = new WordlistCatalogCache(DateTimeOffset.UtcNow, all);
                    await WriteAsync(Path.Combine(directory, "catalog.json"), cache, ct);
                    return cache;
                }
            }
            throw new IOException("The wordlist catalog has too many pages.");
        }
        finally { refresh.Release(); }
    }

    public async Task<WeakpassDetail> DetailAsync(WeakpassWordlist item, DateTimeOffset catalogTime, CancellationToken ct = default)
    {
        string file = Path.Combine(directory, $"detail-{item.Id}.json");
        var cache = await ReadAsync<DetailCache>(file, ct);
        if (cache is not null && Valid(cache.Data) && cache.Data.Id == item.Id && cache.FetchedAt >= catalogTime)
            return Normalize(cache.Data);
        var json = await http.GetStringAsync($"{Api}/wordlists/{Uri.EscapeDataString(item.Slug ?? item.Name)}", ct);
        using var doc = JsonDocument.Parse(json);
        if (doc.RootElement.ValueKind != JsonValueKind.Object || !doc.RootElement.TryGetProperty("data", out var data)
            || data.ValueKind != JsonValueKind.Object) throw new JsonException("The wordlist details are incomplete.");
        var parsed = data.Deserialize<WeakpassDetail>(Json);
        if (!Valid(parsed)) throw new JsonException("The wordlist details have no id or name.");
        var detail = Normalize(parsed!);
        if (detail.Id != item.Id) throw new IOException("The wordlist details do not match the selected list.");
        await WriteAsync(file, new DetailCache(DateTimeOffset.UtcNow, detail), ct);
        return detail;
    }

    private static WeakpassDetail Normalize(WeakpassDetail detail) => detail with
    {
        Examples = (detail.Examples ?? []).Where(x => x is not null).ToArray(),
        Masks = (detail.Masks ?? []).Where(x => x is not null && x.Mask is not null).ToArray(),
        TopMasks = (detail.TopMasks ?? []).Where(x => x is not null && x.Mask is not null).ToArray(),
        LengthDistribution = (detail.LengthDistribution ?? []).Where(x => x is not null).ToArray(),
    };

    internal static async Task<T?> ReadAsync<T>(string file, CancellationToken ct = default)
    {
        try
        {
            await using var stream = File.OpenRead(file);
            return await JsonSerializer.DeserializeAsync<T>(stream, Json, ct);
        }
        catch (Exception ex) when (ex is IOException or JsonException or UnauthorizedAccessException) { return default; }
    }

    internal static async Task WriteAsync<T>(string file, T value, CancellationToken ct = default)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(file)!);
        string temp = file + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            await using (var stream = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                await JsonSerializer.SerializeAsync(stream, value, Json, ct);
            File.Move(temp, file, true);
        }
        finally { if (File.Exists(temp)) File.Delete(temp); }
    }
}

public enum WordlistSort { Default, Name, Rank, Cracks, Words, Download, Time }

public sealed class WordlistQuery
{
    public string Search { get; init; } = "";
    public HashSet<string> Ranks { get; init; } = [];
    public long MaxSize { get; init; } = long.MaxValue;
    public double MinRate { get; init; }
    public WordlistSort Sort { get; init; }
    public bool Descending { get; init; }
    public double Speed { get; init; }
    public long? RuleOutputs { get; init; }

    public static double? Seconds(long words, long? outputs, double speed)
        => outputs is > 0 && double.IsFinite(speed) && speed > 0 ? words * (double)outputs.Value / speed : null;

    public static IEnumerable<WeakpassWordlist> Apply(IEnumerable<WeakpassWordlist> items, WordlistQuery query)
    {
        var matches = items.Where(x => x.Name.Contains(query.Search, StringComparison.OrdinalIgnoreCase)
            && (query.Ranks.Count == 0 || query.Ranks.Contains(x.Rank ?? "")) && x.Size <= query.MaxSize && x.Rate >= query.MinRate);
        if (query.Sort == WordlistSort.Default)
            return matches.OrderBy(x => Rank(x.Rank)).ThenByDescending(x => x.Rate).ThenByDescending(x => x.Count).ThenBy(x => x.Id);
        Func<WeakpassWordlist, IComparable?> key = query.Sort switch
        {
            WordlistSort.Name => x => x.Name.ToUpperInvariant(),
            WordlistSort.Rank => x => Rank(x.Rank),
            WordlistSort.Cracks => x => x.Rate,
            WordlistSort.Words => x => x.Count,
            WordlistSort.Download => x => x.SizeCompressed,
            _ => x => Seconds(x.Count, query.RuleOutputs, query.Speed),
        };
        // Unknown ranks always follow ranked lists, in either direction.
        var groups = matches.OrderBy(x => query.Sort == WordlistSort.Rank && x.Rank is null ? 1 : 0);
        return query.Descending ? groups.ThenByDescending(key).ThenBy(x => x.Id) : groups.ThenBy(key).ThenBy(x => x.Id);
    }

    private static int Rank(string? rank) => rank is { Length: 1 } ? "SABCDEF".IndexOf(rank[0]) is >= 0 and var r ? r : 7 : 7;
}

public static class WordlistText
{
    public static (string Text, string[] Links) Description(string? html)
    {
        html ??= "";
        var links = Regex.Matches(html, "https?://[^\\s<>\\\"']+", RegexOptions.IgnoreCase, TimeSpan.FromSeconds(1))
            .Select(x => WebUtility.HtmlDecode(x.Value)).Where(x => Uri.TryCreate(x, UriKind.Absolute, out var u) && u.Scheme is "http" or "https").Distinct().ToArray();
        string text = Regex.Replace(html, @"<(script|style)\b[^>]*>.*?</\1>", "", RegexOptions.IgnoreCase | RegexOptions.Singleline, TimeSpan.FromSeconds(1));
        text = Regex.Replace(text, "<[^>]*>", " ", RegexOptions.None, TimeSpan.FromSeconds(1));
        return (Regex.Replace(WebUtility.HtmlDecode(text), @"\s+", " ", RegexOptions.None, TimeSpan.FromSeconds(1)).Trim(), links);
    }

    public static long[] LengthBuckets(IEnumerable<WordlistLength> lengths)
    {
        var buckets = new long[14];
        foreach (var item in lengths.Where(x => x.Length >= 4)) buckets[Math.Min(item.Length, 17) - 4] += item.Count;
        return buckets;
    }

    public static string CharacterClasses(string mask) => string.Join(" + ", mask.Select(c => c switch
    { 'l' => "lowercase", 'u' => "uppercase", 'd' => "digits", 's' => "symbols", _ => c.ToString() }));
}
