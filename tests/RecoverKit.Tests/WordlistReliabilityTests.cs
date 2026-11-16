using System.Net;
using System.Net.Sockets;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using RecoverKit.Core.Attacks;
using Xunit;

namespace RecoverKit.Tests;

public sealed class WordlistReliabilityTests : IDisposable
{
    private readonly string dir = Path.Combine(Path.GetTempPath(), "rk-reliability-" + Guid.NewGuid());
    public void Dispose() { if (Directory.Exists(dir)) Directory.Delete(dir, true); }
    private static string Md5(byte[] bytes) => Convert.ToHexString(MD5.HashData(bytes));
    private static readonly byte[] Words = "alpha\nbeta\ngamma\n"u8.ToArray();
    private static byte[] Gzip()
    {
        using var output = new MemoryStream();
        using (var gzip = new GZipStream(output, CompressionMode.Compress, true)) gzip.Write(Words);
        return output.ToArray();
    }
    private static WeakpassDetail Detail(byte[] bytes) => new()
    {
        Id = 42, Name = "words.txt", Size = Words.Length, SizeCompressed = bytes.Length,
        Checksum = Md5(Words), ChecksumCompressed = Md5(bytes), DownloadUrl = "https://weakpass.com/words.txt.gz",
    };

    [Fact]
    public async Task StalledBodyTimesOutKeepsPartialAndResumes()
    {
        byte[] bytes = Gzip();
        using var server = new TcpListener(IPAddress.Loopback, 0);
        server.Start();
        int port = ((IPEndPoint)server.LocalEndpoint).Port;
        using var stop = new CancellationTokenSource();
        var serving = Task.Run(async () =>
        {
            using var client = await server.AcceptTcpClientAsync(stop.Token);
            using var stream = client.GetStream();
            using var reader = new StreamReader(stream, leaveOpen: true);
            while (await reader.ReadLineAsync(stop.Token) is { Length: > 0 }) { }
            await stream.WriteAsync(Encoding.ASCII.GetBytes($"HTTP/1.1 200 OK\r\nContent-Length: {bytes.Length}\r\n\r\n"), stop.Token);
            await stream.WriteAsync(bytes.AsMemory(0, 10), stop.Token);
            try { await Task.Delay(Timeout.Infinite, stop.Token); }
            catch (OperationCanceledException) { }
        });
        using var localHttp = WordlistDownloads.CreateHttp();
        using var http = new HttpClient(new LoopbackHandler(localHttp, port));
        var library = new WordlistLibrary(dir);
        try
        {
            var download = new WordlistDownloads(http, _ => long.MaxValue, TimeSpan.FromMilliseconds(200));
            var ex = await Assert.ThrowsAsync<IOException>(() => download.Enqueue(library, Detail(bytes)).Completion.WaitAsync(TimeSpan.FromSeconds(5)));
            Assert.Contains("stopped sending", ex.Message);
            string part = Assert.Single(Directory.GetFiles(dir, "*.part"));
            Assert.Equal(10, new FileInfo(part).Length);
            using var resumed = new HttpClient(new WordlistCatalogTests.Handler(request =>
            {
                Assert.Equal(10, request.Headers.Range!.Ranges.Single().From);
                return new(HttpStatusCode.PartialContent) { Content = new ByteArrayContent(bytes[10..]) { Headers = { ContentRange = new(10, bytes.Length - 1, bytes.Length) } } };
            }));
            var item = await new WordlistDownloads(resumed, _ => long.MaxValue).Enqueue(library, Detail(bytes)).Completion;
            Assert.Equal(Words, await File.ReadAllBytesAsync(library.FilePath(item)));
        }
        finally { stop.Cancel(); server.Stop(); await serving; }
    }

    [Fact]
    public async Task ProductionHandlerDoesNotFollowLocalRedirectAndDownloadRejectsItsHost()
    {
        using var server = new TcpListener(IPAddress.Loopback, 0);
        server.Start();
        int port = ((IPEndPoint)server.LocalEndpoint).Port;
        int calls = 0;
        using var stop = new CancellationTokenSource();
        var serving = Task.Run(async () =>
        {
            try
            {
                while (!stop.IsCancellationRequested)
                {
                    using var client = await server.AcceptTcpClientAsync(stop.Token);
                    using var stream = client.GetStream();
                    using var reader = new StreamReader(stream, leaveOpen: true);
                    while (await reader.ReadLineAsync(stop.Token) is { Length: > 0 }) { }
                    Interlocked.Increment(ref calls);
                    await stream.WriteAsync(Encoding.ASCII.GetBytes($"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:{port}/forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"), stop.Token);
                }
            }
            catch (OperationCanceledException) { }
        });
        try
        {
            using var local = WordlistDownloads.CreateHttp();
            using var http = new HttpClient(new LoopbackHandler(local, port));
            var ex = await Assert.ThrowsAsync<IOException>(() => new WordlistDownloads(http, _ => long.MaxValue).Enqueue(new(dir), Detail(Gzip())).Completion);
            Assert.Contains("URL", ex.Message);
            Assert.Equal(1, calls);
        }
        finally { stop.Cancel(); server.Stop(); await serving; }
    }

    [Fact]
    public async Task RangeIgnoredOnceRetriesBeforeDiscardingPartial()
    {
        var bytes = Gzip();
        var library = new WordlistLibrary(dir);
        var detail = Detail(bytes);
        string part = await library.PreparePartialAsync(detail);
        await File.WriteAllBytesAsync(part, bytes[..10]);
        int calls = 0;
        using var http = new HttpClient(new WordlistCatalogTests.Handler(request =>
        {
            Assert.Equal(10, request.Headers.Range!.Ranges.Single().From);
            calls++;
            return calls == 1 ? new(HttpStatusCode.OK) { Content = new ByteArrayContent(bytes) }
                : new(HttpStatusCode.PartialContent) { Content = new ByteArrayContent(bytes[10..]) { Headers = { ContentRange = new(10, bytes.Length - 1, bytes.Length) } } };
        }));
        var item = await new WordlistDownloads(http, _ => long.MaxValue).Enqueue(library, detail).Completion;
        Assert.Equal(2, calls);
        Assert.Equal(Words, await File.ReadAllBytesAsync(library.FilePath(item)));
    }

    [Fact]
    public async Task KeepCancelRetainsPartialAndUnpackReportsDeterminateProgress()
    {
        var bytes = Gzip();
        var library = new WordlistLibrary(dir);
        string part = await library.PreparePartialAsync(Detail(bytes));
        await File.WriteAllBytesAsync(part, bytes[..10]);
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        using var http = new HttpClient(new BlockingHandler(entered));
        var job = new WordlistDownloads(http, _ => long.MaxValue).Enqueue(library, Detail(bytes));
        await entered.Task;
        job.Cancel(keepPartial: true);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => job.Completion);
        Assert.Equal(10, new FileInfo(part).Length);
        using var resumed = new HttpClient(new WordlistCatalogTests.Handler(_ => new(HttpStatusCode.PartialContent) { Content = new ByteArrayContent(bytes[10..]) { Headers = { ContentRange = new(10, bytes.Length - 1, bytes.Length) } } }));
        var downloads = new WordlistDownloads(resumed, _ => long.MaxValue);
        var progress = new List<WordlistDownloadProgress>();
        downloads.Changed += changed => progress.Add(changed.Progress);
        await downloads.Enqueue(library, Detail(bytes)).Completion;
        Assert.Contains(progress, p => p.Stage == "Unpacking" && p.Bytes == Words.Length && p.Total == Words.Length && p.BytesPerSecond > 0);
        Assert.DoesNotContain(progress, p => p.Stage.StartsWith("Verifying"));
    }

    [Fact]
    public async Task RedirectLoopStopsBeforeASeventhRequest()
    {
        int calls = 0;
        using var http = new HttpClient(new WordlistCatalogTests.Handler(_ =>
        {
            calls++;
            return new(HttpStatusCode.Redirect) { Headers = { Location = new Uri("https://download.weakpass.com/words.txt.gz") } };
        }));
        var ex = await Assert.ThrowsAsync<IOException>(() => new WordlistDownloads(http, _ => long.MaxValue).Enqueue(new(dir), Detail(Gzip())).Completion);
        Assert.Contains("too many", ex.Message);
        Assert.Equal(6, calls);
    }

    [Fact]
    public async Task IgnoredRangesEventuallyRestartWithStatusAndResetHash()
    {
        var bytes = Gzip();
        var detail = Detail(bytes);
        var library = new WordlistLibrary(dir);
        string part = await library.PreparePartialAsync(detail);
        await File.WriteAllBytesAsync(part, bytes[..10]);
        int calls = 0;
        using var http = new HttpClient(new WordlistCatalogTests.Handler(request =>
        {
            calls++;
            Assert.Equal(10, request.Headers.Range!.Ranges.Single().From);
            return new(HttpStatusCode.OK) { Content = new ByteArrayContent(bytes) };
        }));
        var downloads = new WordlistDownloads(http, _ => long.MaxValue);
        bool restarted = false;
        downloads.Changed += job => { if (job.Progress.Stage.Contains("restarted from zero")) restarted = true; };
        var item = await downloads.Enqueue(library, detail).Completion;
        Assert.Equal(3, calls);
        Assert.True(restarted);
        Assert.Equal(Words, await File.ReadAllBytesAsync(library.FilePath(item)));
    }

    private sealed class LoopbackHandler(HttpClient http, int port) : HttpMessageHandler
    {
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            using var mapped = new HttpRequestMessage(request.Method, $"http://127.0.0.1:{port}/start");
            foreach (var header in request.Headers) mapped.Headers.TryAddWithoutValidation(header.Key, header.Value);
            return await http.SendAsync(mapped, HttpCompletionOption.ResponseHeadersRead, ct);
        }
    }
    private sealed class BlockingHandler(TaskCompletionSource entered) : HttpMessageHandler
    {
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            entered.TrySetResult(); await Task.Delay(Timeout.Infinite, ct);
            throw new InvalidOperationException();
        }
    }
}
