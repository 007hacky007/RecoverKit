using RecoverKit.Core.Attacks;
using Xunit;
using Xunit.Abstractions;

namespace RecoverKit.Tests;

public sealed class WordlistLiveTests(ITestOutputHelper output)
{
    [Fact, Trait("Category", "Slow")]
    public async Task Ignis10KDownloadsAndUnpacksWithBothChecksums()
    {
        string root = Path.Combine(Path.GetTempPath(), "rk-wordlist-live-" + Guid.NewGuid());
        try
        {
            var catalog = new WeakpassCatalog(Path.Combine(root, "cache"));
            var cache = await catalog.RefreshAsync();
            Assert.NotEmpty(cache.Items);
            foreach (var list in cache.Items)
            {
                string name = WordlistLibrary.SafeName(list.Name);
                Assert.Contains(Path.GetExtension(name).ToLowerInvariant(), new[] { ".txt", ".dic", ".lst", ".wordlist", ".found", ".dict", ".udic", ".list", ".lex", ".utf", ".top", ".out", ".csv" });
                Assert.DoesNotContain('/', name); Assert.DoesNotContain('\\', name);
            }
            output.WriteLine($"Refreshed and checked safe names for {cache.Items.Count} catalog lists.");
            foreach (var group in cache.Items.GroupBy(x => Path.GetExtension(x.Name).ToLowerInvariant()).OrderByDescending(g => g.Count()).Take(20))
                output.WriteLine($"Extension '{group.Key}': {group.Count()}");
            var entry = Assert.Single(cache.Items, x => x.Name == "ignis-10K.txt");
            Assert.True(entry.SizeCompressed < 1_000_000);
            var detail = await catalog.DetailAsync(entry, cache.FetchedAt);
            var library = new WordlistLibrary(Path.Combine(root, "library"));
            var item = await new WordlistDownloads().Enqueue(library, detail).Completion;
            Assert.Equal(detail.Count, Wordlists.CountLines(library.FilePath(item)));
            Assert.Equal(detail.Size, new FileInfo(library.FilePath(item)).Length);
            Assert.Single(await library.LoadAsync());
            output.WriteLine($"Live download passed: {detail.Name}, {detail.SizeCompressed} compressed bytes, {detail.Size} unpacked bytes, {detail.Count} lines, both MD5 checksums.");
        }
        finally { if (Directory.Exists(root)) Directory.Delete(root, true); }
    }
}
