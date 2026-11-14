using System.Diagnostics;
using System.IO.Compression;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text.Json;
using RecoverKit.Core.Hashcat;

namespace RecoverKit.Core;

/// <summary>One file of a GitHub release; <see cref="Sha256"/> is GitHub's digest when it publishes one.</summary>
public sealed record ReleaseAsset(string Name, string Url, long Size, string? Sha256);

/// <summary>A published RecoverKit release.</summary>
public sealed record ReleaseInfo(Version Version, string Tag, string PageUrl, IReadOnlyList<ReleaseAsset> Assets);

/// <summary>How this copy of RecoverKit was installed, which decides the release file and how it is applied.</summary>
public enum InstallKind { WindowsMsi, WindowsPortable, MacBundle, Unknown }

/// <summary>A downloaded and verified update: the release file and, when unpacked, the staged copy.</summary>
public sealed record PreparedUpdate(InstallKind Kind, string Tag, string File, string? Staged);

/// <summary>
/// Updates RecoverKit from its GitHub releases. The release file for this installation is downloaded,
/// checked against the SHA-256 GitHub publishes for it (or the .sha256 file of the release) and then
/// applied by a small script that waits for this process to end, installs, and starts RecoverKit
/// again: the MSI on Windows (Windows Installer upgrades in place), a folder swap for the portable
/// archive, and an app-bundle swap on macOS.
/// </summary>
public static class AppUpdater
{
    public const string LatestReleaseApi = "https://api.github.com/repos/007hacky007/RecoverKit/releases/latest";

    private static readonly HttpClient Http = CreateHttp();

    private static HttpClient CreateHttp()
    {
        var c = new HttpClient { Timeout = TimeSpan.FromSeconds(30) };
        // Generic client identifier only; never anything that identifies the user.
        c.DefaultRequestHeaders.UserAgent.ParseAdd("RecoverKit/1.0");
        c.DefaultRequestHeaders.Accept.ParseAdd("application/vnd.github+json");
        return c;
    }

    /// <summary>Folder for downloaded release files and staged copies; cleared before each download.</summary>
    public static string UpdatesDir => Path.Combine(Settings.AppDataDir, "updates");

    /// <summary>The latest release, or null when none is published yet (HTTP 404).</summary>
    public static async Task<ReleaseInfo?> FetchLatestAsync(CancellationToken ct = default)
    {
        using var resp = await Http.GetAsync(LatestReleaseApi, ct);
        DebugLog.Info($"Update check: HTTP {(int)resp.StatusCode}");
        if (resp.StatusCode == System.Net.HttpStatusCode.NotFound) return null;
        resp.EnsureSuccessStatusCode();
        return ParseRelease(await resp.Content.ReadAsStringAsync(ct));
    }

    /// <summary>Reads a GitHub release object; null when it has no parsable version tag.</summary>
    public static ReleaseInfo? ParseRelease(string json)
    {
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;
        string tag = root.TryGetProperty("tag_name", out var t) ? t.GetString() ?? "" : "";
        if (!Version.TryParse(tag.TrimStart('v', 'V'), out var version)) return null;
        string url = root.TryGetProperty("html_url", out var u) ? u.GetString() ?? "" : "";
        var assets = new List<ReleaseAsset>();
        if (root.TryGetProperty("assets", out var list) && list.ValueKind == JsonValueKind.Array)
            foreach (var a in list.EnumerateArray())
            {
                string name = a.TryGetProperty("name", out var n) ? n.GetString() ?? "" : "";
                string download = a.TryGetProperty("browser_download_url", out var d) ? d.GetString() ?? "" : "";
                long size = a.TryGetProperty("size", out var s) && s.ValueKind == JsonValueKind.Number ? s.GetInt64() : 0;
                string? digest = a.TryGetProperty("digest", out var g) && g.ValueKind == JsonValueKind.String ? g.GetString() : null;
                string? sha = digest is not null && digest.StartsWith("sha256:", StringComparison.OrdinalIgnoreCase) && digest.Length == 7 + 64
                    ? digest[7..].ToLowerInvariant() : null;
                if (name.Length > 0 && download.StartsWith("https://", StringComparison.Ordinal)) assets.Add(new ReleaseAsset(name, download, size, sha));
            }
        return new ReleaseInfo(version, tag, url, assets);
    }

    /// <summary>True when <paramref name="release"/> is newer than the running <paramref name="currentVersion"/>.</summary>
    public static bool IsNewer(ReleaseInfo release, string currentVersion)
        => Version.TryParse(currentVersion, out var mine) && release.Version > mine;

    /// <summary>How the running copy was installed (see <see cref="DetectInstallKind(string, bool)"/>).</summary>
    public static InstallKind DetectInstallKind()
        => DetectInstallKind(AppContext.BaseDirectory, OperatingSystem.IsWindows() && IsMsiRegistered(AppContext.BaseDirectory));

    /// <summary>
    /// Windows: the MSI registers an App Paths entry for its folder; anything else is the portable
    /// archive. macOS: the app bundle. Other layouts (a development build) are not updated in place.
    /// </summary>
    internal static InstallKind DetectInstallKind(string appDir, bool msiRegistered)
    {
        if (OperatingSystem.IsWindows()) return msiRegistered ? InstallKind.WindowsMsi : InstallKind.WindowsPortable;
        if (OperatingSystem.IsMacOS()) return BundleOf(appDir) is not null ? InstallKind.MacBundle : InstallKind.Unknown;
        return InstallKind.Unknown;
    }

    /// <summary>The .app bundle that contains <paramref name="appDir"/> (its Contents/MacOS folder), or null.</summary>
    internal static string? BundleOf(string appDir)
    {
        var dir = Path.TrimEndingDirectorySeparator(Path.GetFullPath(appDir));
        if (!string.Equals(Path.GetFileName(dir), "MacOS", StringComparison.Ordinal)) return null;
        var contents = Path.GetDirectoryName(dir);
        if (contents is null || !string.Equals(Path.GetFileName(contents), "Contents", StringComparison.Ordinal)) return null;
        var bundle = Path.GetDirectoryName(contents);
        return bundle is not null && bundle.EndsWith(".app", StringComparison.OrdinalIgnoreCase) ? bundle : null;
    }

    [SupportedOSPlatform("windows")]
    private static bool IsMsiRegistered(string appDir)
    {
        try
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\App Paths\RecoverKit.exe");
            return key?.GetValue("Path") is string p && SameDirectory(p, appDir);
        }
        catch (Exception ex) when (ex is System.Security.SecurityException or IOException or UnauthorizedAccessException) { return false; }
    }

    internal static bool SameDirectory(string a, string b)
        => string.Equals(Path.TrimEndingDirectorySeparator(Path.GetFullPath(a)), Path.TrimEndingDirectorySeparator(Path.GetFullPath(b)),
            OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal);

    /// <summary>The release file for this installation (names as .github/workflows/build.yml publishes them), or null.</summary>
    public static ReleaseAsset? ChooseAsset(ReleaseInfo release, InstallKind kind, Architecture? architecture = null)
    {
        var arch = architecture ?? RuntimeInformation.ProcessArchitecture;
        string? suffix = kind switch
        {
            InstallKind.WindowsMsi when arch == Architecture.X64 => "-x64.msi",
            InstallKind.WindowsPortable when arch == Architecture.X64 => "-x64-portable.zip",
            InstallKind.MacBundle when arch == Architecture.Arm64 => "-macos-arm64.dmg",
            InstallKind.MacBundle when arch == Architecture.X64 => "-macos-x64.dmg",
            _ => null,
        };
        if (suffix is null) return null;
        return release.Assets.FirstOrDefault(a => a.Name.StartsWith("RecoverKit-", StringComparison.Ordinal) && a.Name.EndsWith(suffix, StringComparison.Ordinal));
    }

    /// <summary>The SHA-256 for <paramref name="fileName"/> in a shasum-style listing ("hash  name" per line), or null.</summary>
    internal static string? ChecksumFromListing(string listing, string fileName)
    {
        foreach (var raw in listing.Split('\n'))
        {
            var line = raw.Trim();
            var parts = line.Split([' ', '\t'], 2, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length != 2 || parts[0].Length != 64) continue;
            var name = parts[1].TrimStart('*').Trim();
            if (string.Equals(Path.GetFileName(name), fileName, StringComparison.Ordinal)) return parts[0].ToLowerInvariant();
        }
        return null;
    }

    /// <summary>
    /// Downloads and verifies the release file for <paramref name="kind"/>, and unpacks it where the
    /// update is applied by copying. Throws <see cref="InstallException"/> when the release has no
    /// checksum to verify the file with, or the file is not what it should be.
    /// </summary>
    public static async Task<PreparedUpdate> PrepareAsync(ReleaseInfo release, InstallKind kind, IProgress<InstallProgress>? progress = null, CancellationToken ct = default)
    {
        var asset = ChooseAsset(release, kind) ?? throw new InstallException($"Release {release.Tag} has no file for this installation.");
        string? sha = asset.Sha256;
        if (sha is null && release.Assets.FirstOrDefault(a => a.Name == asset.Name + ".sha256") is { } listing)
        {
            progress?.Report(new InstallProgress { Stage = "verify", Message = "Reading the checksum ..." });
            using var resp = await Http.GetAsync(listing.Url, ct);
            resp.EnsureSuccessStatusCode();
            sha = ChecksumFromListing(await resp.Content.ReadAsStringAsync(ct), asset.Name);
        }
        if (sha is null)
            throw new InstallException($"Release {release.Tag} publishes no checksum for {asset.Name}, so it cannot be verified. Download it from the release page instead.");

        string dir = UpdatesDir;
        try { if (Directory.Exists(dir)) Directory.Delete(dir, true); } catch (IOException) { }
        Directory.CreateDirectory(dir);
        string file = Path.Combine(dir, asset.Name);
        progress?.Report(new InstallProgress { Stage = "download", Message = $"Downloading {asset.Name} ..." });
        await HashcatInstaller.DownloadAsync(asset.Url, file, sha, asset.Size, "download", progress, ct);

        string? staged = null;
        switch (kind)
        {
            case InstallKind.WindowsPortable:
                progress?.Report(new InstallProgress { Stage = "extract", Message = "Unpacking ..." });
                staged = Path.Combine(dir, "portable");
                await Task.Run(() => ZipFile.ExtractToDirectory(file, staged), ct);
                if (!File.Exists(Path.Combine(staged, "RecoverKit.exe")))
                    throw new InstallException("The portable archive does not contain RecoverKit.exe.");
                break;
            case InstallKind.MacBundle:
                progress?.Report(new InstallProgress { Stage = "extract", Message = "Unpacking ..." });
                staged = Path.Combine(dir, "RecoverKit.app");
                await Task.Run(() => CopyFromDiskImage(file, staged), ct);
                break;
        }
        progress?.Report(new InstallProgress { Stage = "done", Message = "Ready to install." });
        return new PreparedUpdate(kind, release.Tag, file, staged);
    }

    private static void CopyFromDiskImage(string dmg, string staged)
    {
        string mount = Path.Combine(Path.GetDirectoryName(dmg)!, "mount");
        Run("hdiutil", ["attach", "-nobrowse", "-readonly", "-noautoopen", "-mountpoint", mount, dmg], TimeSpan.FromMinutes(2));
        try
        {
            string app = Directory.EnumerateDirectories(mount, "*.app").FirstOrDefault()
                ?? throw new InstallException("The disk image contains no application.");
            Run("ditto", [app, staged], TimeSpan.FromMinutes(5));
        }
        finally
        {
            try { Run("hdiutil", ["detach", mount, "-quiet"], TimeSpan.FromMinutes(1)); } catch (InstallException) { }
        }
    }

    private static void Run(string exe, string[] args, TimeSpan timeout)
    {
        var psi = new ProcessStartInfo(exe) { UseShellExecute = false, RedirectStandardError = true, RedirectStandardOutput = true, CreateNoWindow = true };
        foreach (var a in args) psi.ArgumentList.Add(a);
        using var p = Process.Start(psi) ?? throw new InstallException($"{exe} could not be started.");
        var err = p.StandardError.ReadToEndAsync();
        var outp = p.StandardOutput.ReadToEndAsync();
        if (!p.WaitForExit((int)timeout.TotalMilliseconds)) { p.Kill(true); throw new InstallException($"{exe} did not finish."); }
        if (p.ExitCode != 0) throw new InstallException($"{exe} failed: {err.Result.Trim()}");
        _ = outp.Result;
    }

    /// <summary>
    /// Starts the script that applies <paramref name="update"/> once this process has ended, and
    /// starts RecoverKit again. The caller exits right after. The script is left in the updates
    /// folder for the next update to clear.
    /// </summary>
    public static void Apply(PreparedUpdate update)
    {
        string exe = Environment.ProcessPath ?? throw new InvalidOperationException("The running program's path is unknown.");
        string appDir = Path.TrimEndingDirectorySeparator(AppContext.BaseDirectory);
        string script = ApplyScript(update, Environment.ProcessId, appDir, exe);
        string path = Path.Combine(UpdatesDir, OperatingSystem.IsWindows() ? "apply.cmd" : "apply.sh");
        File.WriteAllText(path, script);
        DebugLog.Info($"Update {update.Tag}: applying with {path}");
        ProcessStartInfo psi = OperatingSystem.IsWindows()
            ? new ProcessStartInfo("cmd.exe") { ArgumentList = { "/c", path }, UseShellExecute = false, CreateNoWindow = true }
            : new ProcessStartInfo("/bin/sh") { ArgumentList = { path }, UseShellExecute = false };
        psi.WorkingDirectory = UpdatesDir;
        Process.Start(psi)?.Dispose();
    }

    /// <summary>The apply script: wait for process <paramref name="pid"/>, install, start <paramref name="exe"/> again.</summary>
    internal static string ApplyScript(PreparedUpdate update, int pid, string appDir, string exe)
    {
        switch (update.Kind)
        {
            case InstallKind.WindowsMsi:
                return Cmd(pid, $"msiexec /i \"{update.File}\" /passive /norestart", $"start \"\" \"{exe}\"");
            case InstallKind.WindowsPortable:
                // robocopy: /E all folders, /IS /IT overwrite same files, retries while a handle lingers.
                return Cmd(pid, $"robocopy \"{update.Staged!.TrimEnd('\\', '/')}\" \"{appDir.TrimEnd('\\', '/')}\" /E /IS /IT /R:20 /W:1 >nul",
                    $"start \"\" \"{exe}\"");
            case InstallKind.MacBundle:
            {
                string app = BundleOf(appDir) ?? throw new InvalidOperationException("RecoverKit does not run from an app bundle.");
                string q(string s) => "'" + s.Replace("'", "'\\''") + "'";
                return "#!/bin/sh\n" +
                       $"while kill -0 {pid} 2>/dev/null; do sleep 1; done\n" +
                       $"rm -rf {q(app + ".old")}\n" +
                       $"if mv {q(app)} {q(app + ".old")} && mv {q(update.Staged!)} {q(app)}; then rm -rf {q(app + ".old")}; else mv {q(app + ".old")} {q(app)} 2>/dev/null; fi\n" +
                       $"open {q(app)}\n";
            }
            default:
                throw new InvalidOperationException("This installation is not updated in place.");
        }

        static string Cmd(int pid, string install, string restart) =>
            "@echo off\r\n" +
            ":wait\r\n" +
            $"tasklist /FI \"PID eq {pid}\" | find \"{pid}\" >nul\r\n" +
            // ping as the one-second sleep: timeout refuses to run without a console (a GUI parent).
            "if not errorlevel 1 (ping -n 2 127.0.0.1 >nul & goto wait)\r\n" +
            install + "\r\n" +
            restart + "\r\n";
    }
}
