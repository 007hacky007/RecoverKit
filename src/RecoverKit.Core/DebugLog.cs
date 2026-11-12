using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace RecoverKit.Core;

/// <summary>
/// One plain-text diagnostic log per application run, in &lt;AppData&gt;\RecoverKit\logs
/// (~/Library/Logs/RecoverKit on macOS). It is meant
/// to be sent back by a tester together with screenshots, so it records everything needed to
/// reproduce a session: environment, settings, every hashcat command line with its full output and
/// exit code, file detection, wizard choices, the text shown in the information pane, and crashes.
///
/// Privacy: recovered passwords are never written (only their length), and the user's profile
/// path and account name are replaced by %USERPROFILE% / %USERNAME%.
/// </summary>
public static class DebugLog
{
    private const int KeepFiles = 30;
    private static readonly object Gate = new();
    private static StreamWriter? _w;
    private static readonly Stopwatch Clock = Stopwatch.StartNew();
    private static int _cmdSeq;

    /// <summary>
    /// The log folder: &lt;data dir&gt;/logs, except on macOS where logs go to ~/Library/Logs/RecoverKit
    /// (where Console.app finds them) unless the data folder was relocated.
    /// </summary>
    public static string Directory =>
        OperatingSystem.IsMacOS() && !Settings.IsRelocated
            ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Library", "Logs", "RecoverKit")
            : Path.Combine(Settings.AppDataDir, "logs");

    /// <summary>
    /// Whether extracted hashes may appear in the log. Off by default: they are only needed to debug
    /// file parsing, and every registered hash (including hashcat's echo of it in status lines) is
    /// replaced by a placeholder.
    /// </summary>
    public static bool IncludeHashes { get; set; }

    private static readonly List<string> Hashes = new();

    /// <summary>Registers the hash lines of the current target so they can be masked.</summary>
    public static void RegisterHashes(string? hashLines)
    {
        if (string.IsNullOrEmpty(hashLines)) return;
        lock (Gate)
            foreach (var h in hashLines.Replace("\r", "").Split('\n'))
                if (h.Trim().Length >= 16 && !Hashes.Contains(h.Trim())) Hashes.Add(h.Trim());
    }
    public static string? CurrentFile { get; private set; }

    /// <summary>Opens a new log file for this run and writes the environment header.</summary>
    public static void Start(string appName, string version, string[] args)
    {
        lock (Gate)
        {
            if (_w is not null) return;
            try
            {
                System.IO.Directory.CreateDirectory(Directory);
                Prune();
                CurrentFile = Path.Combine(Directory, $"{appName}-{DateTime.Now:yyyyMMdd-HHmmss}-{Environment.ProcessId}.log");
                _w = new StreamWriter(new FileStream(CurrentFile, FileMode.Create, FileAccess.Write, FileShare.ReadWrite), new UTF8Encoding(true)) { AutoFlush = true };
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { _w = null; return; }
        }
        Write("START", $"{appName} {version} debug log");
        Write("ENV", $"Started: {DateTimeOffset.Now:yyyy-MM-dd HH:mm:ss zzz}");
        Write("ENV", $"Command line args: {string.Join(' ', args)}");
        Write("ENV", $"OS: {RuntimeInformation.OSDescription} ({RuntimeInformation.OSArchitecture}), Version {Environment.OSVersion.Version}");
        Write("ENV", $".NET: {RuntimeInformation.FrameworkDescription}, process {RuntimeInformation.ProcessArchitecture}, 64-bit={Environment.Is64BitProcess}");
        Write("ENV", $"Logical processors: {Environment.ProcessorCount}, CPU: {CpuName()}");
        Write("ENV", $"Memory: {GC.GetGCMemoryInfo().TotalAvailableMemoryBytes / 1_048_576:N0} MB available to the process");
        Write("ENV", $"Culture: {System.Globalization.CultureInfo.CurrentCulture.Name}, UI culture {System.Globalization.CultureInfo.CurrentUICulture.Name}");
        if (OperatingSystem.IsWindows()) Write("ENV", $"Elevated (administrator): {Hashcat.CpuRuntime.IsElevatedProcess}");
        Write("ENV", $"App directory: {AppContext.BaseDirectory}");
        Write("ENV", $"Data directory: {Settings.AppDataDir}");
        if (Hashcat.CpuRuntime.IsSupportedPlatform)
            Write("ENV", $"CPU OpenCL runtime: {Hashcat.CpuRuntime.Locate() ?? "(not installed)"}");
        if (Hashcat.HashcatInstaller.BundledDirectory is { } bundled)
            Write("ENV", $"Bundled hashcat: {bundled} ({Hashcat.HashcatInstaller.BundledStamp ?? "no stamp"})");
        foreach (var v in new[] { "OCL_ICD_FILENAMES", "CUDA_VISIBLE_DEVICES", "HIP_VISIBLE_DEVICES", "GPU_DEVICE_ORDINAL" })
            if (Environment.GetEnvironmentVariable(v) is { } val) Write("ENV", $"{v}={val}");
    }

    public static void Info(string message) => Write("INFO", message);
    public static void Ui(string message) => Write("UI", message.TrimEnd('\r', '\n'));
    public static void Warn(string message) => Write("WARN", message);

    public static void Error(string context, Exception ex) => Write("ERROR", $"{context}: {ex}");

    /// <summary>Records the user's settings (as stored), so the configuration of the session is known.</summary>
    public static void LogSettings(Settings s)
    {
        try { Write("SETTINGS", System.Text.Json.JsonSerializer.Serialize(s, new System.Text.Json.JsonSerializerOptions { WriteIndented = true, Converters = { new System.Text.Json.Serialization.JsonStringEnumConverter() } })); }
        catch (Exception ex) when (ex is NotSupportedException or InvalidOperationException) { Write("SETTINGS", "(could not serialize: " + ex.Message + ")"); }
    }

    /// <summary>Logs the start of an external process and returns an id used to pair its output lines.</summary>
    public static int ProcessStart(ProcessStartInfo psi, string? note = null)
    {
        int id = Interlocked.Increment(ref _cmdSeq);
        var sb = new StringBuilder();
        sb.Append($"#{id} {psi.FileName} {string.Join(' ', psi.ArgumentList.Select(Quote))}");
        sb.Append($"\n    cwd: {psi.WorkingDirectory}");
        foreach (var k in new[] { "OCL_ICD_FILENAMES", "CL_CONFIG_CPU_TBB_NUM_WORKERS" })
            if (psi.Environment.TryGetValue(k, out var v) && v is not null) sb.Append($"\n    env {k}={v}");
        if (note is not null) sb.Append($"\n    note: {note}");
        Write("CMD", sb.ToString());
        return id;
    }

    public static void ProcessOutput(int id, string stream, string line) => Write("OUT", $"#{id} {stream}: {line}");

    public static void ProcessExit(int id, int code, TimeSpan elapsed) => Write("EXIT", $"#{id} exit code {code} after {elapsed.TotalSeconds:F1} s");

    public static void ProcessText(int id, string stream, string text, bool redact = false)
    {
        if (string.IsNullOrEmpty(text)) return;
        foreach (var l in text.Replace("\r", "").Split('\n'))
            if (l.Length > 0) ProcessOutput(id, stream, redact ? "(redacted, " + l.Length + " chars)" : l);
    }

    private static void Write(string tag, string message)
    {
        lock (Gate)
        {
            if (_w is null) return;
            try
            {
                var text = Scrub(message).Replace("\n", "\n" + new string(' ', 24));
                _w.WriteLine($"{DateTime.Now:HH:mm:ss.fff} +{Clock.Elapsed.TotalSeconds,8:F1}s {tag,-8} {text}");
            }
            catch (Exception ex) when (ex is IOException or ObjectDisposedException) { }
        }
    }

    public static void Stop()
    {
        Write("STOP", "Application exit");
        lock (Gate) { _w?.Dispose(); _w = null; }
    }

    // ---------------------------------------------------------------- helpers

    private static readonly string Profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
    private static readonly string User = Environment.UserName;

    internal static string Scrub(string s)
    {
        if (!IncludeHashes)
            foreach (var h in Hashes)
                if (s.Contains(h, StringComparison.Ordinal)) s = s.Replace(h, $"<hash, {h.Length} chars>", StringComparison.Ordinal);
        if (Profile.Length > 3) s = s.Replace(Profile, "%USERPROFILE%", StringComparison.OrdinalIgnoreCase);
        if (User.Length > 2) s = System.Text.RegularExpressions.Regex.Replace(s, $@"\b{System.Text.RegularExpressions.Regex.Escape(User)}\b", "%USERNAME%",
            System.Text.RegularExpressions.RegexOptions.IgnoreCase);
        return s;
    }

    private static string Quote(string a) => a.Contains(' ') || a.Length == 0 ? $"\"{a}\"" : a;

    private static void Prune()
    {
        try
        {
            foreach (var f in new DirectoryInfo(Directory).GetFiles("*.log").OrderByDescending(f => f.CreationTimeUtc).Skip(KeepFiles - 1))
                f.Delete();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
    }

    private static string? MacCpuName()
    {
        try
        {
            using var p = Process.Start(new ProcessStartInfo("/usr/sbin/sysctl", ["-n", "machdep.cpu.brand_string"])
                { RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true });
            if (p is null) return null;
            var name = p.StandardOutput.ReadToEnd().Trim();
            p.WaitForExit(2000);
            return name.Length > 0 ? name : null;
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or IOException or InvalidOperationException) { return null; }
    }

    private static string CpuName()
    {
        if (OperatingSystem.IsMacOS()) return MacCpuName() ?? RuntimeInformation.ProcessArchitecture.ToString();
        if (!OperatingSystem.IsWindows()) return RuntimeInformation.ProcessArchitecture.ToString();
        try
        {
            using var k = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"HARDWARE\DESCRIPTION\System\CentralProcessor\0");
            return (k?.GetValue("ProcessorNameString") as string)?.Trim() ?? "unknown";
        }
        catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException or IOException) { return "unknown"; }
    }
}
