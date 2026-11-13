using System.Diagnostics;
using System.Security.Cryptography;

namespace RecoverKit.Core.Hashcat;

/// <summary>Progress of a hashcat download/install, reported per stage.</summary>
public sealed class InstallProgress
{
    public string Stage { get; init; } = "";     // get-extractor | download | verify | extract | copy (macOS bundle) | done
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
    // The same file is published on GitHub (releases/download/v8.0.0/hashcat-8.0.0.7z) with the same hash.
    public const string Version = "8.0.0";
    public const string ArchiveUrl = "https://hashcat.net/files/hashcat-8.0.0.7z";
    public const string ArchiveSha256 = "9fa86e1bfd5dd898d3c83aa38a67b08db1ba5d2f5252dffa2af44a8c62585f49";
    private const long ArchiveSize = 20350217;

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

    // The generic release has no macOS binary; the Mac app bundles its own build (macos/build-hashcat.sh).
    private static string[] BinaryNames =>
        OperatingSystem.IsWindows() ? ["hashcat.exe"]
        : OperatingSystem.IsMacOS() ? ["hashcat"]
        : ["hashcat.bin", "hashcat"];

    /// <summary>
    /// Downloads and unpacks hashcat (Windows, Linux), or on macOS copies the hashcat bundled with
    /// the app into the engines folder. Returns the install directory and the executable for this OS.
    /// </summary>
    public async Task<HashcatInstallResult> InstallAsync(IProgress<InstallProgress>? progress = null, CancellationToken ct = default)
    {
        if (OperatingSystem.IsMacOS())
        {
            var bundle = BundledDirectory ?? throw new InstallException(
                "hashcat.net publishes no macOS build of hashcat, and this copy of RecoverKit does not include one. " +
                "Use the RecoverKit macOS app (which bundles hashcat), or install hashcat with Homebrew " +
                "(brew install hashcat) and select it in Preferences.");
            return await Task.Run(() => CopyBundle(bundle, progress, ct), ct);
        }

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

    // ---------------------------------------------------------------- macOS: hashcat bundled with the app

    /// <summary>Stamp file written by macos/build-hashcat.sh: "&lt;hashcat version&gt;-&lt;bundle revision&gt;".</summary>
    public const string BundleStampFile = "RECOVERKIT_BUNDLE";

    private static string ExeName => OperatingSystem.IsWindows() ? "hashcat.exe" : "hashcat";

    /// <summary>
    /// The hashcat folder shipped inside the macOS app bundle (RecoverKit.app/Contents/Resources/hashcat,
    /// next to Contents/MacOS where the apphost runs), or null when there is none or not on macOS.
    /// It is only a source to copy from: hashcat writes kernel caches and logs into its own folder,
    /// and the signed, possibly read-only app bundle must not change.
    /// </summary>
    public static string? BundledDirectory => OperatingSystem.IsMacOS() ? FindBundle(AppContext.BaseDirectory) : null;

    /// <summary>The bundled build's stamp, or null when there is no bundle (or no stamp in it).</summary>
    public static string? BundledStamp => BundledDirectory is { } d ? ReadStamp(d) : null;

    internal static string? FindBundle(string baseDir)
    {
        foreach (var d in new[] { Path.Combine(baseDir, "..", "Resources", "hashcat"), Path.Combine(baseDir, "hashcat") })
        {
            var full = Path.GetFullPath(d);
            if (File.Exists(Path.Combine(full, "hashcat")) && File.Exists(Path.Combine(full, BundleStampFile))) return full;
        }
        return null;
    }

    internal static string? ReadStamp(string dir)
    {
        try { return File.ReadAllText(Path.Combine(dir, BundleStampFile)).Trim(); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return null; }
    }

    /// <summary>
    /// True when a bundled hashcat exists and the engines folder lacks a copy of exactly that build
    /// (missing, or another stamp: an older or newer app was installed over this one).
    /// </summary>
    public bool BundleNeedsInstall(string? bundleDir = null)
    {
        bundleDir ??= BundledDirectory;
        if (bundleDir is null) return false;
        return !File.Exists(Path.Combine(ExpectedDirectory, ExeName)) || ReadStamp(ExpectedDirectory) != ReadStamp(bundleDir);
    }

    /// <summary>
    /// macOS: makes sure the engines folder holds a current copy of the bundled hashcat, copying it
    /// when missing or outdated. Meant to be called on startup (off the UI thread: the first copy is
    /// about 200 MB). Returns true when an up-to-date copy is in place afterwards, false when there is
    /// no bundle (or not on macOS) or the copy failed (logged). Never throws for I/O problems.
    /// </summary>
    public static bool TryInstallBundled(IProgress<InstallProgress>? progress = null, CancellationToken ct = default)
        => new HashcatInstaller().TryInstallBundledHere(BundledDirectory, progress, ct);

    internal bool TryInstallBundledHere(string? bundleDir, IProgress<InstallProgress>? progress, CancellationToken ct)
    {
        if (bundleDir is null) return false;
        if (!BundleNeedsInstall(bundleDir)) return true;
        try
        {
            CopyBundle(bundleDir, progress, ct);
            return true;
        }
        catch (Exception ex) when (ex is InstallException or IOException or UnauthorizedAccessException)
        {
            DebugLog.Error("Copying the bundled hashcat", ex);
            return false;
        }
    }

    /// <summary>
    /// Copies a portable hashcat folder (as built by macos/build-hashcat.sh) into the engines folder,
    /// the same way the bundled copy is installed.
    /// </summary>
    public Task<HashcatInstallResult> InstallFromFolderAsync(string folder, IProgress<InstallProgress>? progress = null, CancellationToken ct = default)
    {
        var full = Path.GetFullPath(folder);
        if (!File.Exists(Path.Combine(full, ExeName)))
            throw new InstallException("No hashcat executable in " + full);
        return Task.Run(() => CopyBundle(full, progress, ct), ct);
    }

    /// <summary>Copies a bundled hashcat folder to <see cref="ExpectedDirectory"/>, keeping file modes.</summary>
    internal HashcatInstallResult CopyBundle(string bundleDir, IProgress<InstallProgress>? progress, CancellationToken ct)
    {
        var stamp = ReadStamp(bundleDir);
        DebugLog.Info($"Installing bundled hashcat {stamp} from {bundleDir} to {ExpectedDirectory}");
        Directory.CreateDirectory(InstallRoot);
        var staging = ExpectedDirectory + ".partial";
        try
        {
            if (Directory.Exists(staging)) Directory.Delete(staging, true);
            var src = new DirectoryInfo(bundleDir);
            // Runtime output of an earlier use (should never be in a bundle) is not copied: kernel caches
            // (kernels/ in hashcat 7, cache/ in hashcat 8), logs, dictstat and pid files.
            static bool Skip(string rel) => rel is "kernels" or "cache" or "hashcat.log" or "hashcat.dictstat2" or "hashcat.pid"
                                            || rel.StartsWith("kernels" + Path.DirectorySeparatorChar, StringComparison.Ordinal)
                                            || rel.StartsWith("cache" + Path.DirectorySeparatorChar, StringComparison.Ordinal);
            var files = src.EnumerateFiles("*", SearchOption.AllDirectories)
                .Select(f => (File: f, Rel: Path.GetRelativePath(src.FullName, f.FullName)))
                .Where(x => !Skip(x.Rel)).ToList();
            long total = files.Sum(x => x.File.Length), done = 0;
            var lastReport = DateTime.MinValue;
            progress?.Report(new InstallProgress { Stage = "copy", Message = $"Installing hashcat {Version} ...", BytesTotal = total });

            foreach (var (file, rel) in files)
            {
                ct.ThrowIfCancellationRequested();
                var dest = Path.Combine(staging, rel);
                Directory.CreateDirectory(Path.GetDirectoryName(dest)!);
                File.Copy(file.FullName, dest);
                if (!OperatingSystem.IsWindows())
                {
                    // Keep the executable bits and drop the download quarantine the bundle may carry.
                    File.SetUnixFileMode(dest, File.GetUnixFileMode(file.FullName) | UnixFileMode.UserRead | UnixFileMode.UserWrite);
                    RemoveQuarantine(dest);
                }
                done += file.Length;
                if ((DateTime.UtcNow - lastReport).TotalMilliseconds >= 100)
                {
                    progress?.Report(new InstallProgress { Stage = "copy", BytesDone = done, BytesTotal = total });
                    lastReport = DateTime.UtcNow;
                }
            }
            progress?.Report(new InstallProgress { Stage = "copy", BytesDone = done, BytesTotal = total });

            var exe = Path.Combine(staging, ExeName);
            if (!File.Exists(exe)) throw new InstallException("The bundled hashcat folder has no hashcat executable: " + bundleDir);

            if (Directory.Exists(ExpectedDirectory)) Directory.Delete(ExpectedDirectory, true);
            Directory.Move(staging, ExpectedDirectory);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            throw new InstallException("Could not install the bundled hashcat: " + ex.Message, ex);
        }
        finally
        {
            try { if (Directory.Exists(staging)) Directory.Delete(staging, true); } catch (IOException) { }
        }

        DebugLog.Info($"Bundled hashcat {stamp} installed to {ExpectedDirectory}");
        progress?.Report(new InstallProgress { Stage = "done", Message = "Done." });
        return new HashcatInstallResult { Directory = ExpectedDirectory, ExecutablePath = Path.Combine(ExpectedDirectory, ExeName) };
    }

    private static void RemoveQuarantine(string path)
    {
        if (!OperatingSystem.IsMacOS()) return;
        try { _ = removexattr(path, "com.apple.quarantine", 0); }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException) { }
    }

    [System.Runtime.InteropServices.DllImport("libc", SetLastError = true)]
    private static extern int removexattr([System.Runtime.InteropServices.MarshalAs(System.Runtime.InteropServices.UnmanagedType.LPUTF8Str)] string path,
        [System.Runtime.InteropServices.MarshalAs(System.Runtime.InteropServices.UnmanagedType.LPUTF8Str)] string name, int options);

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
