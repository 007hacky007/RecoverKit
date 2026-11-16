using System.IO.Compression;
using System.Net;
using System.Security.Cryptography;
using RecoverKit.Core.Attacks;
using RecoverKit.Core.Formats;
using Xunit;

namespace RecoverKit.Tests;

public sealed class WordlistDownloadTests : IDisposable
{
    private readonly string dir = Path.Combine(Path.GetTempPath(), "rk-library-" + Guid.NewGuid());
    public void Dispose() { if (Directory.Exists(dir)) Directory.Delete(dir, true); }
    private static readonly byte[] Words = "alpha\nbeta\ngamma\n"u8.ToArray();
    private static string Md5(byte[] bytes) => Convert.ToHexString(MD5.HashData(bytes));
    private static byte[] Gzip()
    {
        using var output = new MemoryStream();
        using (var gz = new GZipStream(output, CompressionMode.Compress, true)) gz.Write(Words);
        return output.ToArray();
    }
    private static WeakpassDetail Detail(byte[] compressed, string name = "test.txt") => new()
    {
        Id = 42, Name = name, Slug = "test", Count = 3, Size = Words.Length, SizeCompressed = compressed.Length,
        DownloadUrl = "https://weakpass.com/download/42/test.txt.gz", Checksum = Md5(Words), ChecksumCompressed = Md5(compressed),
    };

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task RedirectAndInterruptedDownloadResumeOrRestart(bool partialResponse)
    {
        var bytes = Gzip();
        var library = new WordlistLibrary(dir);
        var detail = Detail(bytes);
        string part = await library.PreparePartialAsync(detail);
        await File.WriteAllBytesAsync(part, bytes[..10]);
        int calls = 0;
        using var http = new HttpClient(new WordlistCatalogTests.Handler(request =>
        {
            calls++;
            Assert.Equal(10, request.Headers.Range!.Ranges.Single().From);
            if (calls == 1) return new(HttpStatusCode.Redirect) { Headers = { Location = new Uri("https://download.weakpass.com/wordlists/42/test.txt.gz") } };
            var response = new HttpResponseMessage(partialResponse ? HttpStatusCode.PartialContent : HttpStatusCode.OK)
            { Content = new ByteArrayContent(partialResponse ? bytes[10..] : bytes) };
            if (partialResponse) response.Content.Headers.ContentRange = new(10, bytes.Length - 1, bytes.Length);
            return response;
        }));
        var downloads = new WordlistDownloads(http, _ => long.MaxValue);
        var entry = await downloads.Enqueue(library, detail).Completion;
        Assert.Equal(partialResponse ? 2 : 4, calls);
        Assert.Equal(Words, await File.ReadAllBytesAsync(library.FilePath(entry)));
        Assert.False(File.Exists(part));
        Assert.Single(await library.LoadAsync());
        File.Delete(library.FilePath(entry));
        Assert.Empty(await library.LoadAsync());
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task EitherChecksumMismatchPublishesNothing(bool compressedMismatch)
    {
        var bytes = Gzip();
        var detail = Detail(bytes);
        detail = compressedMismatch ? detail with { ChecksumCompressed = new string('0', 32) } : detail with { Checksum = new string('0', 32) };
        using var http = new HttpClient(new WordlistCatalogTests.Handler(_ => new(HttpStatusCode.OK) { Content = new ByteArrayContent(bytes) }));
        var library = new WordlistLibrary(dir);
        var downloads = new WordlistDownloads(http, _ => long.MaxValue);
        var ex = await Assert.ThrowsAsync<IOException>(() => downloads.Enqueue(library, detail).Completion);
        Assert.Contains("checksum", ex.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Empty(await library.LoadAsync());
        Assert.Empty(Directory.GetFiles(dir, "*.part"));
        Assert.Empty(Directory.GetFiles(dir, "*.unpacking"));
    }

    [Theory]
    [InlineData(28, true)]                       // ENOSPC
    [InlineData(unchecked((int)0x80070070), true)] // ERROR_DISK_FULL
    [InlineData(unchecked((int)0x80070027), true)] // ERROR_HANDLE_DISK_FULL
    [InlineData(unchecked((int)0x80070005), false)] // access denied
    [InlineData(2, false)]                        // ENOENT
    public void RecognisesDiskFullErrors(int hresult, bool full)
        => Assert.Equal(full, WordlistDownloads.DiskFull(new IOException("x", hresult)));

    [Fact]
    public async Task RefusesDiskBudgetAndMissingChecksumsBeforeNetwork()
    {
        using var http = new HttpClient(new WordlistCatalogTests.Handler(_ => throw new Exception("Must not contact network")));
        var library = new WordlistLibrary(dir);
        var downloads = new WordlistDownloads(http, _ => 1);
        var ex = await Assert.ThrowsAsync<IOException>(() => downloads.Enqueue(library, Detail(Gzip())).Completion);
        Assert.Contains("free", ex.Message);
        downloads = new WordlistDownloads(http, _ => long.MaxValue);
        await Assert.ThrowsAsync<IOException>(() => downloads.Enqueue(library, Detail(Gzip()) with { Checksum = null }).Completion);
    }

    [Fact]
    public async Task CancelDeletesPartialAndQueueRunsOnlyOneAtATime()
    {
        var bytes = Gzip();
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        int active = 0, peak = 0;
        using var http = new HttpClient(new AsyncHandler(async ct =>
        {
            int current = Interlocked.Increment(ref active); peak = Math.Max(peak, current);
            entered.TrySetResult();
            try { await release.Task.WaitAsync(ct); }
            finally { Interlocked.Decrement(ref active); }
            return new(HttpStatusCode.OK) { Content = new ByteArrayContent(bytes) };
        }));
        var library = new WordlistLibrary(dir);
        var downloads = new WordlistDownloads(http, _ => long.MaxValue);
        var first = downloads.Enqueue(library, Detail(bytes));
        await entered.Task;
        var second = downloads.Enqueue(library, Detail(bytes) with { Id = 43 });
        first.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => first.Completion);
        release.SetResult();
        await second.Completion;
        Assert.Equal(1, peak);
        Assert.Empty(Directory.GetFiles(dir, "42-*.part"));
    }

    [Fact]
    public async Task NamesCollisionsAndDeleteNeverOverwriteUserFiles()
    {
        Assert.Equal("bad_name.txt", WordlistLibrary.SafeName("bad:name"));
        Assert.Equal("b0n3z.txt", WordlistLibrary.SafeName("b0n3z"));
        Assert.StartsWith("_", WordlistLibrary.SafeName("CON.txt"));
        Directory.CreateDirectory(dir);
        var original = Path.Combine(dir, "test.txt");
        await File.WriteAllTextAsync(original, "user file");
        var bytes = Gzip();
        using var http = new HttpClient(new WordlistCatalogTests.Handler(_ => new(HttpStatusCode.OK) { Content = new ByteArrayContent(bytes) }));
        var library = new WordlistLibrary(dir);
        var entry = await new WordlistDownloads(http, _ => long.MaxValue).Enqueue(library, Detail(bytes)).Completion;
        Assert.NotEqual("test.txt", entry.FileName);
        await library.DeleteAsync(entry.Id);
        Assert.Equal("user file", await File.ReadAllTextAsync(original));
        Assert.Empty(await library.LoadAsync());
        await File.WriteAllTextAsync(Path.Combine(dir, "library.json"), """{"version":1,"owner":"RecoverKit","wordlists":[{"id":1,"file_name":"../outside.txt"}]}""");
        Assert.Empty(await library.LoadAsync());
    }

    [Fact]
    public async Task UnpacksSingleFileLzma2WithoutExternalProgramAndRejectsOtherCoders()
    {
        string fixtures = Path.Combine(AppContext.BaseDirectory, "Fixtures", "Wordlists");
        foreach (string name in new[] { "single-lzma2.7z", "single-lzma.7z" })
        {
            using var source = File.OpenRead(Path.Combine(fixtures, name));
            using var output = new MemoryStream();
            RecoverKit.Core.Formats.SevenZipExtractor.UnpackSingleFile(source, output, Words.Length);
            Assert.Equal(Words, output.ToArray());
        }
        foreach (string name in new[] { "unsupported.7z", "multiple.7z", "encrypted.7z" })
        {
            using var source = File.OpenRead(Path.Combine(fixtures, name));
            using var output = new MemoryStream();
            var ex = Assert.ThrowsAny<Exception>(() => RecoverKit.Core.Formats.SevenZipExtractor.UnpackSingleFile(source, output, 100));
            Assert.True(ex is FormatException or RecoverKit.Core.Formats.UnsupportedFormatException, ex.ToString());
        }
        await Task.CompletedTask;
    }

    [Fact]
    public async Task StaleCleanupOnlyRemovesOwnedFilesAndCrashOutput()
    {
        var library = new WordlistLibrary(dir);
        var detail = Detail(Gzip());
        string part = await library.PreparePartialAsync(detail);
        await File.WriteAllTextAsync(part + ".unpacking", "interrupted output");
        string unowned = Path.Combine(dir, "99-user.txt.part");
        await File.WriteAllTextAsync(unowned, "keep");
        File.SetLastWriteTimeUtc(Path.Combine(dir, "download-42.json"), DateTime.UtcNow.AddDays(-8));
        File.SetLastWriteTimeUtc(part, DateTime.UtcNow.AddDays(-8));
        await library.CleanStalePartialsAsync();
        Assert.False(File.Exists(part));
        Assert.False(File.Exists(part + ".unpacking"));
        Assert.True(File.Exists(unowned));
        await File.WriteAllTextAsync(Path.Combine(dir, "download-1.json"), """{"id":1,"file_name":"x"}""");
        File.SetLastWriteTimeUtc(Path.Combine(dir, "download-1.json"), DateTime.UtcNow.AddDays(-8));
        await library.CleanStalePartialsAsync();
    }

    [Fact]
    public async Task ChangedFilesAreNotDeletedAndManifestWritesUseSharedFolderLock()
    {
        var bytes = Gzip();
        using var http = new HttpClient(new WordlistCatalogTests.Handler(_ => new(HttpStatusCode.OK) { Content = new ByteArrayContent(bytes) }));
        var library = new WordlistLibrary(dir);
        var entry = await new WordlistDownloads(http, _ => long.MaxValue).Enqueue(library, Detail(bytes)).Completion;
        await File.WriteAllTextAsync(library.FilePath(entry), "edited outside library");
        await Assert.ThrowsAsync<IOException>(() => new WordlistLibrary(dir).DeleteAsync(entry.Id));
        Assert.True(File.Exists(library.FilePath(entry)));
        Assert.Single(await library.LoadAsync());
    }

    [Fact]
    public async Task PartialResumeDiscardsInterruptedUnpackingButProtectsUnownedTempNames()
    {
        var detail = Detail(Gzip());
        var library = new WordlistLibrary(dir);
        string part = await library.PreparePartialAsync(detail);
        await File.WriteAllTextAsync(part + ".unpacking", "old output");
        await library.PreparePartialAsync(detail);
        Assert.False(File.Exists(part + ".unpacking"));
        string userOutput = Path.Combine(dir, "43-download.part.unpacking");
        await File.WriteAllTextAsync(userOutput, "user output");
        await Assert.ThrowsAsync<IOException>(() => library.PreparePartialAsync(detail with { Id = 43 }));
        Assert.Equal("user output", await File.ReadAllTextAsync(userOutput));
    }

    [Fact]
    public async Task InterruptedNetworkKeepsPartialAndCanResumeInNewService()
    {
        var bytes = Gzip();
        using var http = new HttpClient(new WordlistCatalogTests.Handler(_ => new(HttpStatusCode.OK) { Content = new ByteArrayContent(bytes[..10]) }));
        var library = new WordlistLibrary(dir);
        var detail = Detail(bytes);
        await Assert.ThrowsAsync<IOException>(() => new WordlistDownloads(http, _ => long.MaxValue).Enqueue(library, detail).Completion);
        string part = Assert.Single(Directory.GetFiles(dir, "*.part"));
        Assert.Equal(10, new FileInfo(part).Length);
        using var resumed = new HttpClient(new WordlistCatalogTests.Handler(request =>
        {
            Assert.Equal(10, request.Headers.Range!.Ranges.Single().From);
            return new(HttpStatusCode.PartialContent) { Content = new ByteArrayContent(bytes[10..]) { Headers = { ContentRange = new(10, bytes.Length - 1, bytes.Length) } } };
        }));
        await new WordlistDownloads(resumed, _ => long.MaxValue).Enqueue(library, detail).Completion;
        Assert.Single(await library.LoadAsync());
    }

    [Fact]
    public async Task ChangedRemoteChecksumRestartsOwnedPartialAndQueuedCancelRemovesIt()
    {
        var bytes = Gzip();
        var detail = Detail(bytes);
        var library = new WordlistLibrary(dir);
        string part = await library.PreparePartialAsync(detail);
        await File.WriteAllBytesAsync(part, bytes[..10]);
        await library.PreparePartialAsync(detail with { ChecksumCompressed = new string('1', 32) });
        Assert.Equal(0, new FileInfo(part).Length);
        // Restore the original identity, then cancel while another job occupies the worker.
        await library.PreparePartialAsync(detail);
        await File.WriteAllBytesAsync(part, bytes[..10]);
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        using var http = new HttpClient(new AsyncHandler(async ct =>
        {
            entered.TrySetResult(); await release.Task.WaitAsync(ct);
            return new(HttpStatusCode.OK) { Content = new ByteArrayContent(bytes) };
        }));
        var downloads = new WordlistDownloads(http, _ => long.MaxValue);
        var first = downloads.Enqueue(library, detail with { Id = 43 });
        await entered.Task;
        var queued = downloads.Enqueue(library, detail);
        queued.Cancel();
        try
        {
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => queued.Completion.WaitAsync(TimeSpan.FromSeconds(3)));
            Assert.False(File.Exists(part));
        }
        finally { release.TrySetResult(); }
        await first.Completion;
    }

    [Theory]
    [InlineData("user content")]
    [InlineData("[]")]
    public async Task ExistingForeignOrInvalidManifestIsNeverOverwritten(string content)
    {
        Directory.CreateDirectory(dir);
        string manifest = Path.Combine(dir, "library.json");
        await File.WriteAllTextAsync(manifest, content);
        var bytes = Gzip();
        using var http = new HttpClient(new WordlistCatalogTests.Handler(_ => new(HttpStatusCode.OK) { Content = new ByteArrayContent(bytes) }));
        var library = new WordlistLibrary(dir);
        await Assert.ThrowsAsync<IOException>(() => new WordlistDownloads(http, _ => long.MaxValue).Enqueue(library, Detail(bytes)).Completion);
        Assert.Equal(content, await File.ReadAllTextAsync(manifest));
        Assert.False(File.Exists(Path.Combine(dir, "test.txt")));
    }

    [Fact]
    public void LibraryDrivePathResolvesAncestorLinks()
    {
        if (OperatingSystem.IsWindows()) return; // Creating links needs a Windows privilege outside CI's test contract.
        string actual = Path.Combine(dir, "actual");
        Directory.CreateDirectory(Path.Combine(actual, "wordlists"));
        Directory.CreateSymbolicLink(Path.Combine(dir, "link"), actual);
        string path = Path.Combine(dir, "link", "wordlists");
        Assert.Equal(new DirectoryInfo(actual).FullName + Path.DirectorySeparatorChar + "wordlists", WordlistLibrary.ResolveDirectory(path));
    }

    [Theory]
    [InlineData("Hashes.org", "Hashes.org.txt")]
    [InlineData("[COMBO] NEW. - Porn Site - [25-01-15] SINIK", "[COMBO] NEW. - Porn Site - [25-01-15] SINIK.txt")]
    [InlineData("list.found", "list.found")]
    [InlineData("list.DICT", "list.DICT")]
    [InlineData("words.udic", "words.udic")]
    [InlineData("words.list", "words.list")]
    [InlineData("words.utf", "words.utf")]
    [InlineData("words.lex", "words.lex")]
    public void OnlyWordlistExtensionsAreKept(string name, string expected)
        => Assert.Equal(expected, WordlistLibrary.SafeName(name));

    [Fact]
    public async Task RenamedPartialResumesAndCanBeCancelledById()
    {
        var library = new WordlistLibrary(dir);
        var original = Detail(Gzip(), "old.txt");
        string part = await library.PreparePartialAsync(original);
        await File.WriteAllBytesAsync(part, [1, 2]);
        string renamed = await library.PreparePartialAsync(original with { Name = "new.txt" });
        Assert.Equal([1, 2], await File.ReadAllBytesAsync(renamed));
        await library.CancelPartialAsync(original with { Name = "another.txt" });
        Assert.False(File.Exists(renamed));
    }

    [Theory]
    [InlineData(36, false)]
    [InlineData(37, true)]
    [InlineData(40, true)]
    public void LibraryRefusesLzmaDictionariesAboveOneGiB(byte property, bool refuse)
    {
        var archive = File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, "Fixtures", "Wordlists", "single-lzma2.7z"));
        Assert.Equal(0, archive[0x45]);
        archive[0x45] = property;
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(archive.AsSpan(28), ZipCryptoSample.Crc32(archive.AsSpan(0x35)));
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(archive.AsSpan(8), ZipCryptoSample.Crc32(archive.AsSpan(12, 20)));
        using var input = new MemoryStream(archive);
        using var output = new MemoryStream();
        if (refuse)
        {
            var ex = Assert.Throws<RecoverKit.Core.Formats.UnsupportedFormatException>(() => RecoverKit.Core.Formats.SevenZipExtractor.UnpackSingleFile(input, output, Words.Length));
            Assert.Contains("1 GB", ex.Message);
            Assert.Equal(0, output.Length);
        }
        else
        {
            RecoverKit.Core.Formats.SevenZipExtractor.UnpackSingleFile(input, output, Words.Length);
            Assert.Equal(Words, output.ToArray());
        }
    }

    [Fact]
    public async Task LegacyNamedPartialIsAdoptedAfterRename()
    {
        Directory.CreateDirectory(dir);
        var detail = Detail(Gzip());
        string part = Path.Combine(dir, "42-old.txt.part");
        await File.WriteAllBytesAsync(part, [1, 2]);
        await File.WriteAllTextAsync(Path.Combine(dir, "download-42.json"), System.Text.Json.JsonSerializer.Serialize(
            new { Id = 42, FileName = "42-old.txt.part", Checksum = detail.ChecksumCompressed },
            new System.Text.Json.JsonSerializerOptions { PropertyNamingPolicy = System.Text.Json.JsonNamingPolicy.SnakeCaseLower }));
        var library = new WordlistLibrary(dir);
        Assert.Equal(part, await library.PreparePartialAsync(detail with { Name = "new.txt" }));
        Assert.Equal(2, await library.PartialSizeAsync(42));
        await library.CancelPartialAsync(detail);
        Assert.False(File.Exists(part));
    }

    private sealed class AsyncHandler(Func<CancellationToken, Task<HttpResponseMessage>> reply) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) => reply(cancellationToken);
    }
}
