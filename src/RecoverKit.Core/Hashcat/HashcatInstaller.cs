using System.Security.Cryptography;

namespace RecoverKit.Core.Hashcat;

/// <summary>Progress of a hashcat download/install, reported per stage.</summary>
public sealed class InstallProgress
{
    public string Stage { get; init; } = "";     // download | verify | copy | done
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
/// Installs the hashcat that every RecoverKit release ships (a <c>hashcat/</c> folder beside the
/// executable, or Contents/Resources/hashcat in the macOS app) by copying it into the engines folder.
/// Nothing is downloaded: <see cref="DownloadAsync"/> is only used for the NVRTC and CPU runtimes.
/// </summary>
public sealed class HashcatInstaller
{
    // The hashcat release that is bundled (see the bundle stamp for the bundle revision).
    public const string Version = "8.0.0";

    public const string NoBundleMessage = "This copy of RecoverKit does not include hashcat. Install hashcat 8 with your package manager, set its location in Preferences > Files and Paths, or run 'recoverkit-cli install-hashcat --from <folder>'.";

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

    public HashcatInstaller(string? installRoot = null)
        => InstallRoot = installRoot ?? Path.Combine(Settings.AppDataDir, "engines");

    public string ExpectedDirectory => Path.Combine(InstallRoot, "hashcat-" + Version);

    /// <summary>
    /// Copies the hashcat bundled with the app into the engines folder. Returns the install directory
    /// and the executable. Throws <see cref="InstallException"/> when this copy has no bundled hashcat.
    /// </summary>
    public async Task<HashcatInstallResult> InstallAsync(IProgress<InstallProgress>? progress = null, CancellationToken ct = default)
    {
        var bundle = BundledDirectory ?? throw new InstallException(NoBundleMessage);
        return await Task.Run(() => CopyBundle(bundle, progress, ct), ct);
    }

    // ---------------------------------------------------------------- macOS: hashcat bundled with the app

    /// <summary>Stamp file written by macos/build-hashcat.sh: "&lt;hashcat version&gt;-&lt;bundle revision&gt;".</summary>
    public const string BundleStampFile = "RECOVERKIT_BUNDLE";

    internal static string ExeName => OperatingSystem.IsWindows() ? "hashcat.exe" : "hashcat";

    /// <summary>
    /// The hashcat folder shipped with the app (macOS: RecoverKit.app/Contents/Resources/hashcat, next to
    /// Contents/MacOS where the apphost runs; Windows: hashcat/ beside the executable), or null when there is none.
    /// It is only a source to copy from: hashcat writes kernel caches and logs into its own folder,
    /// and the signed, possibly read-only app bundle must not change.
    /// </summary>
    public static string? BundledDirectory => FindBundle(AppContext.BaseDirectory);

    /// <summary>The bundled build's stamp, or null when there is no bundle (or no stamp in it).</summary>
    public static string? BundledStamp => BundledDirectory is { } d ? ReadStamp(d) : null;

    internal static string? FindBundle(string baseDir)
    {
        foreach (var d in new[] { Path.Combine(baseDir, "..", "Resources", "hashcat"), Path.Combine(baseDir, "hashcat") })
        {
            var full = Path.GetFullPath(d);
            if (File.Exists(Path.Combine(full, ExeName)) && File.Exists(Path.Combine(full, BundleStampFile))) return full;
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
