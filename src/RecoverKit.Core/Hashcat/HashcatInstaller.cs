using System.Diagnostics;
using System.Security.Cryptography;

namespace RecoverKit.Core.Hashcat;

/// <summary>Progress of a hashcat download/install, reported per stage.</summary>
public sealed class InstallProgress
{
    public string Stage { get; init; } = "";     // get-extractor | download | verify | extract | done
    public string Message { get; init; } = "";
    public long BytesDone { get; init; }
    public long BytesTotal { get; init; }         // 0 when unknown
    public double Fraction => BytesTotal > 0 ? Math.Clamp((double)BytesDone / BytesTotal, 0, 1) : 0;
}

public sealed class HashcatInstallResult
{
    public required string Directory { get; init; }      // the extracted hashcat-<ver> folder
    public string? ExecutablePath { get; init; }         // hashcat.exe / hashcat.bin for this OS, if present
}

public sealed class InstallException : Exception
{
    public InstallException(string message, Exception? inner = null) : base(message, inner) { }
}

/// <summary>
/// Downloads the official hashcat release and unpacks it next to the application, so the GPU
/// engine can be installed from inside RecoverKit without a manual download.
///
/// The binary release is a BCJ2-filtered 7-Zip archive, which no pure-managed unpacker handles,
/// so extraction is delegated to a 7-Zip command-line tool. On Windows the tiny official
/// <c>7zr.exe</c> is fetched automatically when no 7-Zip is already present; on other systems a
/// system 7-Zip (7zz/7z/7za) is used.
/// </summary>
public sealed class HashcatInstaller
{
    // Pinned, validated release. hashcat keeps every historical file at this stable URL.
    public const string Version = "7.1.2";
    public const string ArchiveUrl = "https://hashcat.net/files/hashcat-7.1.2.7z";
    public const string ArchiveSha256 = "80db0316387794ce9d14ed376da75b8a7742972485b45db790f5f8260307ff98";
    private const long ArchiveSize = 19682772;

    // Official standalone 7-Zip extractor (handles the BCJ2/LZMA2 archive). HTTPS from the vendor.
    private const string SevenZrUrl = "https://www.7-zip.org/a/7zr.exe";
    private const string SevenZrSha256 = "256feca8e274e5da655e2a284fabafd9f554365eb164862089dacd4e8276d282";

    private static readonly HttpClient Http = CreateHttp();

    private static HttpClient CreateHttp()
    {
        var c = new HttpClient { Timeout = TimeSpan.FromMinutes(30) };
        // Generic client identifier only; never anything that identifies the user.
        c.DefaultRequestHeaders.UserAgent.ParseAdd("RecoverKit/1.0");
        return c;
    }

    /// <summary>Folder that will receive the <c>hashcat-&lt;ver&gt;</c> directory.</summary>
    public string InstallRoot { get; }

    /// <summary>Optional explicit path to a 7-Zip executable to use for extraction.</summary>
    public string? SevenZipOverride { get; init; }

    public HashcatInstaller(string? installRoot = null)
        => InstallRoot = installRoot ?? Path.Combine(Settings.AppDataDir, "engines");

    public string ExpectedDirectory => Path.Combine(InstallRoot, "hashcat-" + Version);

    private static string[] BinaryNames =>
        OperatingSystem.IsWindows() ? ["hashcat.exe"]
        : OperatingSystem.IsMacOS() ? []            // the generic release ships no macOS binary (use Homebrew)
        : ["hashcat.bin", "hashcat"];

    /// <summary>Downloads and unpacks hashcat. Returns the install directory and the executable for this OS.</summary>
    public async Task<HashcatInstallResult> InstallAsync(IProgress<InstallProgress>? progress = null, CancellationToken ct = default)
    {
        Directory.CreateDirectory(InstallRoot);
        var seven = await EnsureSevenZipAsync(progress, ct);

        var tmpDir = Directory.CreateDirectory(Path.Combine(InstallRoot, ".tmp")).FullName;
        var archive = Path.Combine(tmpDir, "hashcat-" + Version + ".7z");
        try
        {
            progress?.Report(new InstallProgress { Stage = "download", Message = $"Downloading hashcat {Version} ..." });
            await DownloadAsync(ArchiveUrl, archive, ArchiveSha256, ArchiveSize, "download", progress, ct);

            // Remove any previous copy so extraction cannot leave stale files behind.
            if (Directory.Exists(ExpectedDirectory))
                try { Directory.Delete(ExpectedDirectory, true); } catch (IOException) { }

            progress?.Report(new InstallProgress { Stage = "extract", Message = "Extracting ..." });
            await ExtractAsync(seven, archive, InstallRoot, ct);
        }
        finally
        {
            try { Directory.Delete(tmpDir, true); } catch (IOException) { }
        }

        if (!Directory.Exists(ExpectedDirectory))
            throw new InstallException("Extraction did not produce the expected hashcat-" + Version + " folder.");

        var exe = BinaryNames.Select(n => Path.Combine(ExpectedDirectory, n)).FirstOrDefault(File.Exists);
        if (exe is not null && !OperatingSystem.IsWindows())
            try { File.SetUnixFileMode(exe, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute | UnixFileMode.GroupRead | UnixFileMode.GroupExecute | UnixFileMode.OtherRead | UnixFileMode.OtherExecute); }
            catch (IOException) { }

        progress?.Report(new InstallProgress { Stage = "done", Message = "Done." });
        return new HashcatInstallResult { Directory = ExpectedDirectory, ExecutablePath = exe };
    }

    // ---------------------------------------------------------------- 7-Zip

    /// <summary>Returns a usable 7-Zip executable, downloading the official 7zr.exe on Windows if needed.</summary>
    public async Task<string> EnsureSevenZipAsync(IProgress<InstallProgress>? progress, CancellationToken ct)
    {
        if (FindSevenZip() is { } found) return found;

        if (!OperatingSystem.IsWindows())
            throw new InstallException(
                "A 7-Zip tool is required to unpack hashcat but none was found. Install 7-Zip (p7zip) and retry, " +
                "for example: brew install sevenzip, or apt install p7zip-full.");

        var dest = Path.Combine(Directory.CreateDirectory(Path.Combine(InstallRoot, "tools")).FullName, "7zr.exe");
        progress?.Report(new InstallProgress { Stage = "get-extractor", Message = "Downloading 7-Zip extractor ..." });
        await DownloadAsync(SevenZrUrl, dest, SevenZrSha256, 0, "get-extractor", progress, ct);
        return dest;
    }

    /// <summary>Looks for a 7-Zip front-end: override, bundled tools dir, then PATH.</summary>
    public string? FindSevenZip()
    {
        string[] names = OperatingSystem.IsWindows()
            ? ["7zr.exe", "7za.exe", "7z.exe", "7zz.exe"]
            : ["7zz", "7z", "7za", "7zr"];

        var dirs = new List<string>
        {
            Path.Combine(InstallRoot, "tools"),
            Path.Combine(AppContext.BaseDirectory, "tools"),
            AppContext.BaseDirectory,
        };
        dirs.AddRange((Environment.GetEnvironmentVariable("PATH") ?? "")
            .Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries));

        if (!string.IsNullOrWhiteSpace(SevenZipOverride) && File.Exists(SevenZipOverride)) return SevenZipOverride;
        foreach (var d in dirs)
            foreach (var n in names)
            {
                var p = Path.Combine(d, n);
                if (File.Exists(p)) return p;
            }
        return null;
    }

    private static async Task ExtractAsync(string sevenZip, string archive, string outDir, CancellationToken ct)
    {
        var psi = new ProcessStartInfo(sevenZip)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        foreach (var a in new[] { "x", archive, "-o" + outDir, "-y", "-bso0", "-bsp0" }) psi.ArgumentList.Add(a);

        int logId = DebugLog.ProcessStart(psi, "extract hashcat archive");
        using var p = new Process { StartInfo = psi };
        try { p.Start(); }
        catch (System.ComponentModel.Win32Exception ex) { throw new InstallException($"Could not run the 7-Zip tool ({sevenZip}): {ex.Message}", ex); }
        var err = await p.StandardError.ReadToEndAsync(ct);
        await p.StandardOutput.ReadToEndAsync(ct);
        await p.WaitForExitAsync(ct);
        DebugLog.ProcessText(logId, "stderr", err);
        DebugLog.ProcessExit(logId, p.ExitCode, TimeSpan.Zero);
        if (p.ExitCode != 0)
            throw new InstallException($"7-Zip extraction failed (exit {p.ExitCode}). {err.Trim()}");
    }

    // ---------------------------------------------------------------- download + verify

    internal static async Task DownloadAsync(string url, string dest, string? expectedSha, long expectedSize,
        string stage, IProgress<InstallProgress>? progress, CancellationToken ct)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(dest)!);
        DebugLog.Info($"Download {url} -> {dest} (expected {expectedSize:N0} bytes, sha256 {expectedSha ?? "not pinned"})");
        using var resp = await Http.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, ct);
        DebugLog.Info($"HTTP {(int)resp.StatusCode} {resp.ReasonPhrase}, length {resp.Content.Headers.ContentLength?.ToString("N0") ?? "unknown"}");
        if (!resp.IsSuccessStatusCode)
            throw new InstallException($"Download failed: {(int)resp.StatusCode} {resp.ReasonPhrase} ({url})");

        long total = resp.Content.Headers.ContentLength ?? expectedSize;
        using var sha = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        await using (var src = await resp.Content.ReadAsStreamAsync(ct))
        await using (var dst = new FileStream(dest, FileMode.Create, FileAccess.Write, FileShare.None))
        {
            var buf = new byte[81920];
            long done = 0;
            int n;
            var lastReport = DateTime.MinValue;
            while ((n = await src.ReadAsync(buf, ct)) > 0)
            {
                await dst.WriteAsync(buf.AsMemory(0, n), ct);
                sha.AppendData(buf, 0, n);
                done += n;
                if ((DateTime.UtcNow - lastReport).TotalMilliseconds >= 100)
                {
                    progress?.Report(new InstallProgress { Stage = stage, BytesDone = done, BytesTotal = total });
                    lastReport = DateTime.UtcNow;
                }
            }
            progress?.Report(new InstallProgress { Stage = stage, BytesDone = done, BytesTotal = total });
        }

        var actual = Convert.ToHexString(sha.GetHashAndReset()).ToLowerInvariant();
        DebugLog.Info($"Downloaded {new FileInfo(dest).Length:N0} bytes, sha256 {actual}");
        if (expectedSha is not null && !actual.Equals(expectedSha, StringComparison.OrdinalIgnoreCase))
        {
            try { File.Delete(dest); } catch (IOException) { }
            throw new InstallException($"Downloaded file failed integrity check (SHA-256 {actual}, expected {expectedSha}).");
        }
    }
}
