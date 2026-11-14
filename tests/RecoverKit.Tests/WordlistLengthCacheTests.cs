using System.Text.Json.Nodes;
using RecoverKit.Core.Attacks;
using Xunit;

namespace RecoverKit.Tests;

public class WordlistLengthCacheTests
{
    [Fact]
    public void PlausibleHistogramCorruptionCannotLowerTheMaximum()
    {
        using var t = new TempDir();
        File.WriteAllText(t.Words, new string('a', 20) + "\n");
        Assert.Equal(20, WordlistLengthCache.Analyze(t.Words, cacheDirectory: t.Cache)!.Maximum);
        string file = Assert.Single(Directory.GetFiles(t.Cache));
        var json = JsonNode.Parse(File.ReadAllText(file))!;
        json["Lengths"] = new JsonObject { ["19"] = 1 };
        File.WriteAllText(file, json.ToJsonString());
        Assert.Equal(20, WordlistLengthCache.Analyze(t.Words, cacheDirectory: t.Cache)!.Maximum);
    }
    [Fact]
    public void CheapJobsCanUseThePersistentResultWithoutAllowingAColdScan()
    {
        using var t = new TempDir();
        File.WriteAllText(t.Words, "short\nlonger\n");
        Assert.Null(WordlistLengthCache.Analyze(t.Words, cacheDirectory: t.Cache, allowScan: false));
        Assert.NotNull(WordlistLengthCache.Analyze(t.Words, cacheDirectory: t.Cache));
        Assert.Equal(6, WordlistLengthCache.Analyze(t.Words, cacheDirectory: t.Cache, allowScan: false)!.Maximum);
        File.AppendAllText(t.Words, "changed\n");
        Assert.Null(WordlistLengthCache.Analyze(t.Words, cacheDirectory: t.Cache, allowScan: false));
    }
    [Fact]
    public void CountsUtf8BytesEmptyLinesAndFinalRecordsAcrossChunks()
    {
        using var t = new TempDir();
        File.WriteAllText(t.Words, new string('a', 65535) + "\r\n\n\u00e9\u00e9\r\nend\r");
        var progress = new List<(long Done, long Total)>();
        var info = WordlistLengthCache.Analyze(t.Words, (done, total) => progress.Add((done, total)), cacheDirectory: t.Cache)!;
        Assert.NotNull(info);
        Assert.Equal(65535, info.Maximum);
        Assert.Equal(4, info.Words);
        Assert.Equal(1, info.Lengths[0]);
        Assert.Equal(1, info.Lengths[3]);
        Assert.Equal(1, info.Lengths[4]);
        Assert.Equal(1, info.Lengths[65535]);
        Assert.Equal(2, info.LongerThan(3));
        Assert.Equal(1, info.LongerThan(4));
        Assert.Equal(0, info.LongerThan(65535));
        Assert.Equal((0L, new FileInfo(t.Words).Length), progress[0]);
        Assert.Equal((new FileInfo(t.Words).Length, new FileInfo(t.Words).Length), progress[^1]);
        Assert.Equal(2, progress.Count);
    }

    [Theory]
    [InlineData("", 0, 0)]
    [InlineData("\n", 1, 0)]
    [InlineData("\r\n\n", 2, 0)]
    [InlineData("word\n", 1, 4)]
    [InlineData("word\n\r", 2, 4)]
    [InlineData("a\rb\r\r\n", 1, 4)]
    public void DelimitsOnlyLfAndTrimsOneTrailingCr(string text, long words, int maximum)
    {
        using var t = new TempDir();
        File.WriteAllText(t.Words, text);
        var info = WordlistLengthCache.Analyze(t.Words, cacheDirectory: t.Cache)!;
        Assert.Equal(words, info.Words);
        Assert.Equal(maximum, info.Maximum);
    }

    [Fact]
    public async Task IndependentCallsReuseThePersistentCacheWithoutScanning()
    {
        using var t = new TempDir();
        File.WriteAllText(t.Words, "one\nlonger\n");
        Assert.Equal(6, WordlistLengthCache.Analyze(t.Words, cacheDirectory: t.Cache)!.Maximum);
        Assert.Single(Directory.GetFiles(t.Cache, "*.json"));
        var progress = new List<long>();
        var cached = await WordlistLengthCache.AnalyzeAsync(Path.Combine(t.Path, ".", "words.txt"),
            (done, _) => progress.Add(done), cacheDirectory: t.Cache);
        Assert.NotNull(cached);
        Assert.Equal(2, cached.Words);
        Assert.Equal(1, cached.LongerThan(3));
        Assert.Empty(progress);
    }

    [Fact]
    public void SizeAndModificationTimeInvalidateCachedHistogram()
    {
        using var t = new TempDir();
        File.WriteAllText(t.Words, "longone");
        var initial = WordlistLengthCache.Analyze(t.Words, cacheDirectory: t.Cache)!;
        Assert.True(initial.Source.Matches());
        Assert.Equal(Path.GetFullPath(t.Words), initial.Source.Path);
        File.WriteAllText(t.Words, "a\nb\nc\nd");
        File.SetLastWriteTimeUtc(t.Words, initial.Source.ModifiedUtc.AddMinutes(1));
        Assert.False(initial.Source.Matches());
        Assert.Equal(1, WordlistLengthCache.Analyze(t.Words, cacheDirectory: t.Cache)!.Maximum);
        File.WriteAllText(t.Words, "longer-word\n");
        File.SetLastWriteTimeUtc(t.Words, initial.Source.ModifiedUtc.AddMinutes(1));
        Assert.Equal(11, WordlistLengthCache.Analyze(t.Words, cacheDirectory: t.Cache)!.Maximum);
    }

    [Theory]
    [InlineData("not json")]
    [InlineData("{}")]
    [InlineData("null")]
    public void CorruptOrIncompleteCacheIsRescanned(string json)
    {
        using var t = new TempDir();
        File.WriteAllText(t.Words, "test\n");
        WordlistLengthCache.Analyze(t.Words, cacheDirectory: t.Cache);
        File.WriteAllText(Assert.Single(Directory.GetFiles(t.Cache, "*.json")), json);
        int progress = 0;
        Assert.Equal(4, WordlistLengthCache.Analyze(t.Words, (_, _) => progress++, cacheDirectory: t.Cache)!.Maximum);
        Assert.Equal(2, progress);
    }

    [Theory]
    [InlineData("Version")]
    [InlineData("Source")]
    [InlineData("Lengths")]
    public void MissingCacheFieldsForceRescan(string field)
    {
        using var t = new TempDir();
        File.WriteAllText(t.Words, "test\n");
        WordlistLengthCache.Analyze(t.Words, cacheDirectory: t.Cache);
        string cache = Assert.Single(Directory.GetFiles(t.Cache, "*.json"));
        var json = JsonNode.Parse(File.ReadAllText(cache))!.AsObject();
        json.Remove(field);
        File.WriteAllText(cache, json.ToJsonString());
        int progress = 0;
        Assert.Equal(4, WordlistLengthCache.Analyze(t.Words, (_, _) => progress++, cacheDirectory: t.Cache)!.Maximum);
        Assert.Equal(2, progress);
    }

    [Theory]
    [InlineData("version")]
    [InlineData("negative length")]
    [InlineData("zero count")]
    [InlineData("incomplete histogram")]
    [InlineData("overflow")]
    public void InvalidCacheValuesForceRescan(string corruption)
    {
        using var t = new TempDir();
        File.WriteAllText(t.Words, "test\nlonger\n");
        WordlistLengthCache.Analyze(t.Words, cacheDirectory: t.Cache);
        string cache = Assert.Single(Directory.GetFiles(t.Cache, "*.json"));
        var json = JsonNode.Parse(File.ReadAllText(cache))!.AsObject();
        if (corruption == "version") json["Version"] = 99;
        else json["Lengths"] = JsonNode.Parse(corruption switch
        {
            "negative length" => "{\"-1\":1}",
            "zero count" => "{\"4\":0}",
            "incomplete histogram" => "{\"4\":1}",
            _ => "{\"4\":9223372036854775807}",
        });
        File.WriteAllText(cache, json.ToJsonString());
        int progress = 0;
        var info = WordlistLengthCache.Analyze(t.Words, (_, _) => progress++, cacheDirectory: t.Cache)!;
        Assert.Equal(6, info.Maximum);
        Assert.Equal(2, info.Words);
        Assert.Equal(2, progress);
    }

    [Fact]
    public async Task CancellationIsHonoredBeforeCacheHitsAndDuringScanning()
    {
        using var t = new TempDir();
        File.WriteAllText(t.Words, "test\n");
        WordlistLengthCache.Analyze(t.Words, cacheDirectory: t.Cache);
        using var canceled = new CancellationTokenSource();
        canceled.Cancel();
        Assert.Throws<OperationCanceledException>(() => WordlistLengthCache.Analyze(t.Words, ct: canceled.Token, cacheDirectory: t.Cache));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => WordlistLengthCache.AnalyzeAsync(t.Words, ct: canceled.Token, cacheDirectory: t.Cache));
        Directory.Delete(t.Cache, true);
        using var during = new CancellationTokenSource();
        Assert.Throws<OperationCanceledException>(() => WordlistLengthCache.Analyze(t.Words,
            (_, _) => during.Cancel(), during.Token, t.Cache));
    }

    [Theory]
    [InlineData("1F8B")]
    [InlineData("504B0304")]
    [InlineData("425A68")]
    [InlineData("FD377A585A00")]
    [InlineData("28B52FFD")]
    public void CompressedFilesHaveUnknownLengths(string signature)
    {
        using var t = new TempDir();
        File.WriteAllBytes(t.Words, Convert.FromHexString(signature));
        Assert.Null(WordlistLengthCache.Analyze(t.Words, cacheDirectory: t.Cache));
    }

    [Fact]
    public void FilesChangedDuringScanAreNotCached()
    {
        using var t = new TempDir();
        File.WriteAllText(t.Words, "test\n");
        Assert.Null(WordlistLengthCache.Analyze(t.Words, (done, _) =>
        {
            if (done == 0) File.AppendAllText(t.Words, "changed\n");
        }, cacheDirectory: t.Cache));
        Assert.False(Directory.Exists(t.Cache));
    }

    [Fact]
    public void UnwritableCacheDoesNotLoseValidScanResult()
    {
        using var t = new TempDir();
        File.WriteAllText(t.Words, "test\n");
        File.WriteAllText(t.Cache, "a file blocks the cache directory");
        Assert.Equal(4, WordlistLengthCache.Analyze(t.Words, cacheDirectory: t.Cache)!.Maximum);
    }

    [Fact]
    public void MissingFilesHaveUnknownLengthsAndInvalidateStamps()
    {
        using var t = new TempDir();
        File.WriteAllText(t.Words, "test\n");
        var stamp = DictionaryFileStamp.Capture(t.Words);
        File.Delete(t.Words);
        Assert.False(stamp.Matches());
        Assert.Null(WordlistLengthCache.Analyze(t.Words, cacheDirectory: t.Cache));
    }

    [Fact]
    public async Task ConcurrentScansLeaveAReusableCacheEntry()
    {
        using var t = new TempDir();
        File.WriteAllText(t.Words, "test\nlonger\n");
        var results = await Task.WhenAll(Enumerable.Range(0, 8)
            .Select(_ => WordlistLengthCache.AnalyzeAsync(t.Words, cacheDirectory: t.Cache)));
        Assert.All(results, info => Assert.Equal(6, info!.Maximum));
        Assert.Single(Directory.GetFiles(t.Cache));
        int progress = 0;
        Assert.Equal(2, WordlistLengthCache.Analyze(t.Words, (_, _) => progress++, cacheDirectory: t.Cache)!.Words);
        Assert.Equal(0, progress);
    }

    private sealed class TempDir : IDisposable
    {
        public string Path { get; } = Directory.CreateTempSubdirectory("rk-wordlist-lengths").FullName;
        public string Words => System.IO.Path.Combine(Path, "words.txt");
        public string Cache => System.IO.Path.Combine(Path, "cache");
        public void Dispose() => Directory.Delete(Path, true);
    }
}
