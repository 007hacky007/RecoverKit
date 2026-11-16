using System.Diagnostics;
using System.IO.Compression;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using RecoverKit.Core.Formats;

namespace RecoverKit.Core.Attacks;

public sealed record WordlistDownloadProgress(string Stage, long Bytes, long Total, double BytesPerSecond = 0)
{
    public double Fraction => Total > 0 ? Math.Clamp((double)Bytes / Total, 0, 1) : 0;
    public double? SecondsLeft => BytesPerSecond > 0 ? Math.Max(0, Total - Bytes) / BytesPerSecond : null;
}

public sealed class WordlistDownload
{
    internal readonly CancellationTokenSource Cancellation = new();
    internal Func<Task>? CancelPending;
    internal readonly TaskCompletionSource<LibraryWordlist> Result = new(TaskCreationOptions.RunContinuationsAsynchronously);
    public WeakpassDetail Detail { get; }
    public WordlistLibrary Library { get; }
    public WordlistDownloadProgress Progress { get; internal set; } = new("Queued", 0, 0);
    public Task<LibraryWordlist> Completion => Result.Task;
    public long DownloadedBytes { get; internal set; }
    public bool Finished => Completion.IsCompleted;
    public string? Error { get; internal set; }
    internal WordlistDownload(WordlistLibrary library, WeakpassDetail detail) { Library = library; Detail = detail; }
    internal bool KeepPartial;
    public void Cancel(bool keepPartial = false)
    {
        if (Finished) return;
        KeepPartial = keepPartial;
        Cancellation.Cancel();
        if (Progress.Stage == "Queued" && CancelPending is { } cancel) _ = cancel();
    }
}

/// <summary>One app-wide FIFO, independent of the dialog's lifetime.</summary>
public sealed class WordlistDownloads
{
    private readonly HttpClient http;
    private readonly Func<WordlistLibrary, long> freeSpace;
    private readonly TimeSpan readTimeout;
    private readonly object sync = new();
    private readonly List<WordlistDownload> jobs = [];
    private Task tail = Task.CompletedTask;
    public event Action<WordlistDownload>? Changed;
    public IReadOnlyList<WordlistDownload> Jobs { get { lock (sync) return jobs.ToArray(); } }

    private static readonly HttpClient DownloadHttp = CreateHttp();
    public static WordlistDownloads Shared { get; } = new();
    internal static HttpClient CreateHttp()
    {
        var client = new HttpClient(new HttpClientHandler { AllowAutoRedirect = false }) { Timeout = TimeSpan.FromSeconds(60) };
        client.DefaultRequestHeaders.UserAgent.ParseAdd("RecoverKit/1.0");
        return client;
    }

    public WordlistDownloads(HttpClient? client = null, Func<WordlistLibrary, long>? availableSpace = null, TimeSpan? inactivityTimeout = null)
    {
        http = client ?? DownloadHttp;
        freeSpace = availableSpace ?? (library => library.FreeSpace());
        readTimeout = inactivityTimeout ?? TimeSpan.FromSeconds(60);
    }

    public WordlistDownload Enqueue(WordlistLibrary library, WeakpassDetail detail)
    {
        lock (sync)
        {
            var existing = jobs.FirstOrDefault(x => !x.Finished && x.Detail.Id == detail.Id && x.Library.DirectoryPath == library.DirectoryPath);
            if (existing is not null) return existing;
            var job = new WordlistDownload(library, detail);
            job.CancelPending = async () =>
            {
                try
                {
                    if (!job.KeepPartial) await library.CancelPartialAsync(detail);
                    job.Progress = new("Cancelled", 0, 0);
                    job.Result.TrySetCanceled(job.Cancellation.Token);
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                {
                    job.Error = "Could not remove the partial download: " + ex.Message;
                    job.Result.TrySetException(new IOException(job.Error, ex));
                }
                Changed?.Invoke(job);
            };
            jobs.Add(job);
            // Observe failures even when the dialog which requested a download has closed.
            _ = job.Completion.ContinueWith(t => _ = t.Exception, TaskContinuationOptions.OnlyOnFaulted);
            var previous = tail;
            tail = Task.Run(async () => { await previous; await RunAsync(job); });
            return job;
        }
    }

    private void Report(WordlistDownload job, WordlistDownloadProgress progress)
    { job.Progress = progress; Changed?.Invoke(job); }

    private async Task RunAsync(WordlistDownload job)
    {
        if (job.Finished) return;
        job.Progress = new("Preparing", 0, 0);
        string? part = null, unpacked = null;
        // Completing the job lets waiters look at the folder, so it happens only after the cleanup below.
        Action? complete = null;
        var detail = job.Detail;
        var library = job.Library;
        var ct = job.Cancellation.Token;
        try
        {
            if (ct.IsCancellationRequested) { if (!job.KeepPartial) await library.CancelPartialAsync(detail); ct.ThrowIfCancellationRequested(); }
            if (!Checksum(detail.Checksum) || !Checksum(detail.ChecksumCompressed))
                throw new IOException($"{detail.Name}: both MD5 checksums are required before downloading.");
            Uri url = DownloadUri(detail.DownloadUrl);
            string extension = Path.GetExtension(url.AbsolutePath).ToLowerInvariant();
            if (extension is not ".gz" and not ".7z") throw new IOException($"{detail.Name}: unsupported download format {extension}.");
            long required = WordlistLibrary.RequiredSpace(detail), free = freeSpace(library);
            if (free < required) throw new IOException($"{detail.Name}: needs {required:N0} bytes free for download and unpacking; {free:N0} bytes are free.");
            part = await library.PreparePartialAsync(detail, ct);
            long offset = new FileInfo(part).Length;
            if (offset > detail.SizeCompressed) { File.Delete(part); offset = 0; }
            job.DownloadedBytes = offset;
            using var compressedHash = IncrementalHash.CreateHash(HashAlgorithmName.MD5);
            if (offset > 0) await HashPartialAsync(job, part, compressedHash, ct);
            if (offset != detail.SizeCompressed || offset == 0)
                await DownloadAsync(job, url, part, offset, compressedHash, ct);
            if (!Matches(compressedHash.GetHashAndReset(), detail.ChecksumCompressed!))
            {
                library.RemovePartial(detail, part);
                throw new IOException($"{detail.Name}: downloaded file failed its MD5 checksum. Download it again.");
            }
            Report(job, new("Unpacking", 0, detail.Size));
            unpacked = part + ".unpacking";
            string checksum = await Task.Run(() => Unpack(job, part, unpacked, extension, ct), ct);
            if (!checksum.Equals(detail.Checksum, StringComparison.OrdinalIgnoreCase))
            {
                library.RemovePartial(detail, part);
                throw new IOException($"{detail.Name}: unpacked file failed its MD5 checksum. Download it again.");
            }
            ct.ThrowIfCancellationRequested();
            var item = await library.PublishAsync(detail, unpacked, ct);
            library.RemovePartial(detail, part);
            Report(job, new("Ready", detail.Size, detail.Size));
            complete = () => job.Result.TrySetResult(item);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            try
            {
                if (part is not null && !job.KeepPartial) library.RemovePartial(detail, part);
                job.Progress = new("Cancelled", 0, 0);
                complete = () => job.Result.TrySetCanceled(ct);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                job.Error = "Could not remove the partial download: " + ex.Message;
                job.Progress = new("Failed", 0, 0);
                complete = () => job.Result.TrySetException(new IOException(job.Error, ex));
            }
        }
        catch (Exception ex)
        {
            job.Error = $"{detail.Name}: {ex.Message}";
            job.Progress = new("Failed", 0, 0);
            complete = () => job.Result.TrySetException(ex is IOException ? ex : new IOException(job.Error, ex));
        }
        finally
        {
            try { if (unpacked is not null && File.Exists(unpacked)) File.Delete(unpacked); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { job.Error = "Could not remove the temporary wordlist: " + ex.Message; }
            // Changed handlers check Finished, so complete first.
            try { complete?.Invoke(); }
            finally { Changed?.Invoke(job); }
        }
    }

    private static bool Checksum(string? value) => value is { Length: 32 } && value.All(Uri.IsHexDigit);
    private static Uri DownloadUri(string? value)
    {
        if (!Uri.TryCreate(value, UriKind.Absolute, out var uri) || uri.Scheme != "https"
            || uri.Host is not "weakpass.com" and not "download.weakpass.com" || !uri.IsDefaultPort || uri.UserInfo.Length != 0)
            throw new IOException("No supported weakpass download URL is available.");
        return uri;
    }

    private async Task DownloadAsync(WordlistDownload job, Uri url, string part, long offset, IncrementalHash hash, CancellationToken ct)
    {
        int redirects = 0, rangeRetries = 0;
        bool restarted = false;
        while (true)
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, url);
            if (offset > 0) request.Headers.Range = new RangeHeaderValue(offset, null);
            using var response = await http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct);
            if (response.StatusCode is HttpStatusCode.Redirect or HttpStatusCode.MovedPermanently or HttpStatusCode.TemporaryRedirect or HttpStatusCode.PermanentRedirect or HttpStatusCode.SeeOther)
            {
                if (++redirects > 5) throw new IOException("The download redirected too many times.");
                url = DownloadUri(new Uri(url, response.Headers.Location ?? throw new IOException("Download redirect has no location.")).AbsoluteUri);
                continue;
            }
            response.EnsureSuccessStatusCode();
            if (response.StatusCode == HttpStatusCode.PartialContent)
            {
                var range = response.Content.Headers.ContentRange;
                if (range?.From != offset || range.Length != job.Detail.SizeCompressed)
                    throw new IOException("The server returned a different download range. Retry the download.");
            }
            else if (response.StatusCode == HttpStatusCode.OK)
            {
                if (offset > 0 && rangeRetries++ < 2)
                {
                    Report(job, new("Retrying resume", offset, job.Detail.SizeCompressed));
                    response.Dispose();
                    await Task.Delay(500, ct);
                    continue;
                }
                if (offset > 0)
                {
                    restarted = true;
                    hash.GetHashAndReset();
                    offset = 0;
                }
            }
            else throw new IOException("The download server returned an unsupported response.");
            await using var source = await response.Content.ReadAsStreamAsync(ct);
            await using var destination = new FileStream(part, offset > 0 ? FileMode.Append : FileMode.Create, FileAccess.Write, FileShare.None, 81920, true);
            var buffer = new byte[81920];
            long done = offset;
            var watch = Stopwatch.StartNew();
            var samples = new Queue<(double Time, long Bytes)>();
            samples.Enqueue((0, done));
            double lastReport = -1;
            string stage = restarted ? "Downloading (restarted from zero)" : "Downloading";
            Report(job, new(stage, done, job.Detail.SizeCompressed));
            while (true)
            {
                using var readCancellation = CancellationTokenSource.CreateLinkedTokenSource(ct);
                readCancellation.CancelAfter(readTimeout);
                int n;
                try { n = await source.ReadAsync(buffer, readCancellation.Token); }
                catch (OperationCanceledException) when (!ct.IsCancellationRequested)
                { throw new IOException("The server stopped sending data. Download again to resume the partial download."); }
                if (n == 0) break;
                if (done > job.Detail.SizeCompressed - n) throw new IOException("The download is larger than its published size.");
                await destination.WriteAsync(buffer.AsMemory(0, n), ct);
                hash.AppendData(buffer, 0, n);
                done += n;
                job.DownloadedBytes = done;
                double now = watch.Elapsed.TotalSeconds;
                samples.Enqueue((now, done));
                while (samples.Count > 2 && now - samples.Peek().Time > 3) samples.Dequeue();
                var first = samples.Peek();
                double speed = (done - first.Bytes) / Math.Max(0.001, now - first.Time);
                if (now - lastReport >= 0.25)
                { Report(job, new(stage, done, job.Detail.SizeCompressed, speed)); lastReport = now; }
            }
            Report(job, new(stage, done, job.Detail.SizeCompressed, job.Progress.BytesPerSecond));
            if (done != job.Detail.SizeCompressed) throw new IOException("The download stopped early. Download again to resume it.");
            return;
        }
    }

    private static bool Matches(byte[] hash, string checksum) => Convert.ToHexString(hash).Equals(checksum, StringComparison.OrdinalIgnoreCase);

    private async Task HashPartialAsync(WordlistDownload job, string path, IncrementalHash hash, CancellationToken ct)
    {
        await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 1 << 20, true);
        var buffer = new byte[1 << 20];
        var watch = Stopwatch.StartNew();
        long done = 0;
        double last = -1;
        for (int n; (n = await stream.ReadAsync(buffer, ct)) > 0;)
        {
            hash.AppendData(buffer, 0, n); done += n;
            if (watch.Elapsed.TotalSeconds - last >= 0.25 || done == stream.Length)
            {
                last = watch.Elapsed.TotalSeconds;
                Report(job, new("Checking partial download", done, stream.Length, done / Math.Max(0.001, last)));
            }
        }
    }

    private string Unpack(WordlistDownload job, string compressed, string output, string extension, CancellationToken ct)
    {
        using var input = new FileStream(compressed, FileMode.Open, FileAccess.Read, FileShare.Read, 1 << 20, FileOptions.SequentialScan);
        using var file = new FileStream(output, FileMode.CreateNew, FileAccess.Write, FileShare.None, 1 << 20);
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.MD5);
        var watch = Stopwatch.StartNew();
        double last = -1;
        long size = job.Detail.Size;
        using var destination = new WordlistOutput(file, hash, size, ct, written =>
        {
            double now = watch.Elapsed.TotalSeconds;
            if (now - last < 0.25 && written != size) return;
            last = now;
            Report(job, new("Unpacking", written, size, written / Math.Max(0.001, now)));
        });
        if (extension == ".7z") SevenZipExtractor.UnpackSingleFile(input, destination, size, ct);
        else
        {
            using var gzip = new GZipStream(input, CompressionMode.Decompress);
            gzip.CopyTo(destination, 1 << 20);
        }
        if (destination.Written != size) throw new IOException("The unpacked wordlist has a different size than published.");
        return Convert.ToHexString(hash.GetHashAndReset());
    }

    private sealed class WordlistOutput(Stream file, IncrementalHash hash, long size, CancellationToken ct, Action<long> progress) : Stream
    {
        public long Written { get; private set; }
        public override void Write(ReadOnlySpan<byte> buffer)
        {
            ct.ThrowIfCancellationRequested();
            if (Written > size - buffer.Length) throw new IOException("The unpacked wordlist is larger than its published size.");
            file.Write(buffer); hash.AppendData(buffer); Written += buffer.Length; progress(Written);
        }
        public override void Write(byte[] buffer, int offset, int count) => Write(buffer.AsSpan(offset, count));
        public override bool CanRead => false;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => Written;
        public override long Position { get => Written; set => throw new NotSupportedException(); }
        public override void Flush() => file.Flush();
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
    }
}
