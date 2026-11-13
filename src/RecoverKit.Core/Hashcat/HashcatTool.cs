using System.Diagnostics;
using RecoverKit.Core.Formats;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace RecoverKit.Core.Hashcat;

public sealed class BackendDevice
{
    public int Id { get; init; }
    public int? AliasOf { get; init; }
    public string Backend { get; init; } = "";
    public string BackendVersion { get; init; } = "";
    public string Type { get; init; } = "";
    public string Vendor { get; init; } = "";
    public string Name { get; init; } = "";
    public int Processors { get; init; }
    public int ClockMhz { get; init; }
    public long MemoryMb { get; init; }

    private bool? _skipped;

    /// <summary>
    /// Whether hashcat skips this device unless it is selected with -d: an alias of a lower-numbered
    /// device that is itself used, or (macOS) a Metal device while OpenCL devices exist, because
    /// hashcat prefers Apple's OpenCL runtime and disables Metal then.
    /// </summary>
    public bool IsSkippedAlias
    {
        get => _skipped ?? (AliasOf is int a && a < Id);
        internal set => _skipped = value;
    }

    public bool IsMetal => Backend == "Metal";
}

public sealed class HashModeInfo
{
    public int Mode { get; init; }
    public string Name { get; init; } = "";
    public bool SlowHash { get; init; }
    public bool HasOptimizedKernel { get; init; }
    public int PasswordLenMax { get; init; }
    public string? ExampleHash { get; init; }
}

/// <summary>Locates hashcat and runs its short informational commands.</summary>
public sealed partial class HashcatTool
{
    public string Exe { get; }
    public string Directory { get; }

    /// <summary>CPU worker threads for the OpenCL CPU runtime (0 = one per logical processor).</summary>
    public int MaxCpuThreads { get; set; }

    private readonly Dictionary<int, HashModeInfo?> _modeInfo = new();

    private HashcatTool(string exe)
    {
        Exe = exe;
        Directory = Path.GetDirectoryName(Path.GetFullPath(exe)) ?? ".";
    }

    /// <summary>
    /// Finds hashcat: configured path, ./hashcat/ next to the application, the per-user engines
    /// folder, then PATH. On macOS the engines copy of the bundled hashcat comes first and the copy
    /// inside the app bundle is never used directly (see <see cref="HashcatInstaller.TryInstallBundled"/>).
    /// </summary>
    public static HashcatTool? Locate(string? configured)
        => Locate(configured, AppContext.BaseDirectory, Path.Combine(Settings.AppDataDir, "engines"));

    internal static HashcatTool? Locate(string? configured, string baseDir, string enginesDir)
    {
        string exeName = OperatingSystem.IsWindows() ? "hashcat.exe" : "hashcat";
        var candidates = new List<string>();
        // A configured path to an older copy that RecoverKit itself installed (engines/hashcat-7.1.2)
        // gives way to the pinned version once that is installed too.
        string pinned = Path.Combine(enginesDir, "hashcat-" + HashcatInstaller.Version, exeName);
        if (!string.IsNullOrWhiteSpace(configured) && !(IsOlderManagedCopy(configured, enginesDir) && File.Exists(pinned)))
            candidates.Add(configured);
        if (OperatingSystem.IsMacOS() || File.Exists(pinned))
            candidates.Add(pinned);
        // hashcat writes into its own folder, so the read-only copy inside the app bundle is skipped.
        string? bundle = OperatingSystem.IsMacOS() ? HashcatInstaller.FindBundle(baseDir) : null;
        // Next to the application, and in the per-user engines folder a download installs into.
        foreach (var root in new[] { baseDir, enginesDir })
        {
            candidates.Add(Path.Combine(root, "hashcat", exeName));
            try
            {
                foreach (var d in System.IO.Directory.EnumerateDirectories(root, "hashcat*"))
                    if (!d.EndsWith(".partial", StringComparison.Ordinal)) candidates.Add(Path.Combine(d, exeName));
            }
            catch (IOException) { }
        }
        foreach (var p in (Environment.GetEnvironmentVariable("PATH") ?? "").Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries))
            candidates.Add(Path.Combine(p, exeName));

        var hit = candidates.FirstOrDefault(c => File.Exists(c) &&
            (bundle is null || !Path.GetFullPath(c).StartsWith(bundle + Path.DirectorySeparatorChar, StringComparison.Ordinal)));
        if (hit is null) return null;
        // Homebrew and similar installs use a symlink; resolve it so the data directory is found.
        try
        {
            var fi = new FileInfo(hit);
            if (fi.LinkTarget is not null) hit = fi.ResolveLinkTarget(true)?.FullName ?? hit;
        }
        catch (IOException) { }
        return new HashcatTool(hit);
    }

    /// <summary>
    /// True when <paramref name="exe"/> lies in a hashcat-&lt;version&gt; folder of the engines folder (a copy
    /// RecoverKit downloaded or copied) whose version is not the pinned <see cref="HashcatInstaller.Version"/>.
    /// </summary>
    internal static bool IsOlderManagedCopy(string exe, string enginesDir)
    {
        try
        {
            var dir = Path.GetDirectoryName(Path.GetFullPath(exe));
            if (dir is null || !string.Equals(Path.GetDirectoryName(dir), Path.GetFullPath(enginesDir).TrimEnd(Path.DirectorySeparatorChar), StringComparison.OrdinalIgnoreCase))
                return false;
            var name = Path.GetFileName(dir);
            return name.StartsWith("hashcat-", StringComparison.Ordinal) && name != "hashcat-" + HashcatInstaller.Version;
        }
        catch (Exception ex) when (ex is ArgumentException or PathTooLongException or NotSupportedException) { return false; }
    }

    /// <summary>True when this is an older copy in the engines folder: offer the download of the pinned version.</summary>
    public bool IsOutdatedManagedCopy => IsOlderManagedCopy(Exe, Path.Combine(Settings.AppDataDir, "engines"));

    private int? _major;

    /// <summary>
    /// hashcat's major version from <c>--version</c> (v8.0.0 -> 8), cached; 0 when it cannot be read.
    /// hashcat 8 no longer runs the command stored in a restore file (see <see cref="HashcatRunner.BuildArguments"/>).
    /// </summary>
    public int MajorVersion
    {
        get
        {
            if (_major is int m) return m;
            int v = 0;
            try
            {
                var psi = StartInfo(["--version"]);
                using var p = Process.Start(psi);
                if (p is not null)
                {
                    var o = p.StandardOutput.ReadToEnd();
                    p.WaitForExit(20_000);
                    v = ParseMajorVersion(o);
                }
            }
            catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException or IOException) { }
            _major = v;
            return v;
        }
        set => _major = value;
    }

    internal static int ParseMajorVersion(string versionOutput)
    {
        var m = Regex.Match(versionOutput, @"v?(\d+)\.\d+");
        return m.Success && int.TryParse(m.Groups[1].Value, out var v) ? v : 0;
    }

    public ProcessStartInfo StartInfo(IEnumerable<string> args, bool redirectStdin = false)
    {
        var psi = new ProcessStartInfo(Exe)
        {
            WorkingDirectory = Directory,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            RedirectStandardInput = redirectStdin,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8,
        };
        foreach (var a in args) psi.ArgumentList.Add(a);
        CpuRuntime.ApplyTo(psi, MaxCpuThreads);
        NvrtcRuntime.ApplyTo(psi);
        return psi;
    }

    /// <summary>Runs hashcat to completion and returns (exit code, stdout, stderr).</summary>
    public async Task<(int Code, string Out, string Err)> RunAsync(IEnumerable<string> args, TimeSpan timeout, string? stdin = null, CancellationToken ct = default)
    {
        var psi = StartInfo(args, stdin is not null);
        // --show prints recovered plaintexts: keep them out of the debug log.
        bool redact = psi.ArgumentList.Contains("--show");
        int logId = DebugLog.ProcessStart(psi);
        var sw = Stopwatch.StartNew();
        using var p = new Process { StartInfo = psi };
        p.Start();
        var outTask = p.StandardOutput.ReadToEndAsync(ct);
        var errTask = p.StandardError.ReadToEndAsync(ct);
        if (stdin is not null)
        {
            await p.StandardInput.WriteAsync(stdin);
            p.StandardInput.Close();
        }
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(timeout);
        try { await p.WaitForExitAsync(cts.Token); }
        catch (OperationCanceledException)
        {
            try { p.Kill(true); } catch (InvalidOperationException) { }
            DebugLog.Warn($"#{logId} timed out after {timeout.TotalSeconds:F0} s and was killed");
            throw new TimeoutException("hashcat did not finish in time.");
        }
        var (o, e) = (await outTask, await errTask);
        DebugLog.ProcessText(logId, "stdout", o, redact);
        DebugLog.ProcessText(logId, "stderr", e);
        DebugLog.ProcessExit(logId, p.ExitCode, sw.Elapsed);
        return (p.ExitCode, o, e);
    }

    public async Task<string> VersionAsync()
    {
        var (_, o, _) = await RunAsync(["--version"], TimeSpan.FromSeconds(20));
        return o.Trim();
    }

    // ---------------------------------------------------------------- devices

    public async Task<List<BackendDevice>> DevicesAsync(CancellationToken ct = default)
    {
        var (_, o, e) = await RunAsync(["-I", "--quiet"], TimeSpan.FromSeconds(90), ct: ct);
        return ParseDevices(o + "\n" + e);
    }

    public static List<BackendDevice> ParseDevices(string text)
    {
        var list = new List<BackendDevice>();
        string backend = "", backendVersion = "";
        var lines = text.Replace("\r", "").Split('\n');
        for (int i = 0; i < lines.Length; i++)
        {
            var l = lines[i].Trim();
            var api = ApiHeader().Match(l);
            if (api.Success) { backend = api.Groups[1].Value; backendVersion = ""; continue; }
            var ver = Field().Match(l);
            if (ver.Success && ver.Groups[1].Value is "CUDA.Version" or "HIP.Version" or "Metal.Version" or "Metal.Runtime.Version" or "Version" && !lines[Math.Max(0, i - 1)].Contains("Backend Device"))
            {
                if (backendVersion == "") backendVersion = ver.Groups[2].Value.Trim();
            }
            var dev = DeviceHeader().Match(l);
            if (!dev.Success) continue;

            var f = new Dictionary<string, string>();
            for (int j = i + 1; j < lines.Length; j++)
            {
                var t = lines[j].Trim();
                if (t.Length == 0 || DeviceHeader().IsMatch(t) || ApiHeader().IsMatch(t)) break;
                var m = Field().Match(t);
                if (m.Success) f.TryAdd(m.Groups[1].Value, m.Groups[2].Value.Trim());
            }
            int Num(string k) => f.TryGetValue(k, out var v) && int.TryParse(Regex.Match(v, @"\d+").Value, out var n) ? n : 0;
            list.Add(new BackendDevice
            {
                Id = int.Parse(dev.Groups[1].Value),
                AliasOf = dev.Groups[2].Success ? int.Parse(dev.Groups[2].Value) : null,
                Backend = backend,
                BackendVersion = f.GetValueOrDefault("Version") ?? backendVersion,
                Type = f.GetValueOrDefault("Type") ?? "",
                Vendor = f.GetValueOrDefault("Vendor") ?? "",
                Name = f.GetValueOrDefault("Name") ?? "",
                Processors = Num("Processor(s)"),
                ClockMhz = Num("Clock"),
                MemoryMb = Num("Memory.Total"),
            });
        }
        ResolveSkipped(list);
        return list;
    }

    /// <summary>
    /// Mirrors hashcat's default device selection. On macOS hashcat disables every Metal device when
    /// an OpenCL device exists (it cannot map one to the other and its OpenCL support is better), so
    /// the OpenCL alias of a Metal GPU is the one that runs. Other aliases: the lower-numbered device
    /// of a pair survives, unless it is itself skipped.
    /// </summary>
    private static void ResolveSkipped(List<BackendDevice> list)
    {
        bool anyOpenCl = list.Any(d => d.Backend == "OpenCL");
        var skipped = new HashSet<int>();
        foreach (var d in list.OrderBy(d => d.Id))
        {
            bool skip = d.IsMetal ? anyOpenCl
                : d.AliasOf is int a && a < d.Id && !skipped.Contains(a);
            if (skip) skipped.Add(d.Id);
            d.IsSkippedAlias = skip;
        }
    }

    [GeneratedRegex(@"^(CUDA|HIP|Metal|OpenCL) Info:")] private static partial Regex ApiHeader();
    [GeneratedRegex(@"^Backend Device ID #0*(\d+)(?:\s*\(Alias: #0*(\d+)\))?")] private static partial Regex DeviceHeader();
    [GeneratedRegex(@"^([A-Za-z.()]+?)\.*:\s*(.*)$")] private static partial Regex Field();

    // ---------------------------------------------------------------- mode info

    public async Task<HashModeInfo?> ModeInfoAsync(int mode)
    {
        lock (_modeInfo) if (_modeInfo.TryGetValue(mode, out var c)) return c;
        HashModeInfo? info = null;
        try
        {
            var (_, o, _) = await RunAsync(["--hash-info", "-m", mode.ToString(), "--machine-readable", "--quiet"], TimeSpan.FromSeconds(30));
            using var doc = JsonDocument.Parse(o);
            var e = doc.RootElement.GetProperty(mode.ToString());
            info = new HashModeInfo
            {
                Mode = mode,
                Name = e.GetProperty("name").GetString() ?? "",
                SlowHash = e.TryGetProperty("slow_hash", out var sh) && sh.GetBoolean(),
                HasOptimizedKernel = e.TryGetProperty("kernel_type", out var kt) && kt.EnumerateArray().Any(x => x.GetString() == "optimized"),
                PasswordLenMax = e.TryGetProperty("password_len_max", out var pl) ? pl.GetInt32() : 256,
                ExampleHash = e.TryGetProperty("example_hash", out var ex) ? ex.GetString() : null,
            };
        }
        catch (Exception ex) when (ex is JsonException or KeyNotFoundException or InvalidOperationException or TimeoutException) { }
        lock (_modeInfo) _modeInfo[mode] = info;
        return info;
    }

    // ---------------------------------------------------------------- benchmark

    /// <summary>Benchmarks one mode; returns total H/s over all devices.</summary>
    public async Task<double> BenchmarkAsync(int mode, IEnumerable<string> deviceArgs, CancellationToken ct)
    {
        HashcatKernels.EnsureFor(this, mode);
        var args = new List<string> { "-b", "-m", mode.ToString(), "--machine-readable", "--quiet" };
        args.AddRange(deviceArgs);
        var (_, o, _) = await RunAsync(args, TimeSpan.FromMinutes(10), ct: ct);
        double total = 0;
        foreach (var line in o.Split('\n'))
        {
            var f = line.Trim().Split(':');
            if (f.Length >= 6 && f[1] == mode.ToString() && double.TryParse(f[^1], System.Globalization.CultureInfo.InvariantCulture, out var s))
                total += s;
        }
        return total;
    }

    // ---------------------------------------------------------------- rules preview / potfile

    /// <summary>Applies rules to words with hashcat --stdout (exact hashcat rule semantics).</summary>
    public async Task<List<string>> ApplyRulesAsync(IEnumerable<string> words, string rules, CancellationToken ct)
    {
        var dir = System.IO.Directory.CreateTempSubdirectory("rk-rules").FullName;
        try
        {
            var wf = Path.Combine(dir, "words.txt");
            var rf = Path.Combine(dir, "test.rule");
            await File.WriteAllTextAsync(wf, string.Join('\n', words) + "\n", new UTF8Encoding(false), ct);
            await File.WriteAllTextAsync(rf, rules.Replace("\r\n", "\n"), new UTF8Encoding(false), ct);
            var (_, o, _) = await RunAsync(["--stdout", wf, "-r", rf, "--quiet"], TimeSpan.FromSeconds(20), ct: ct);
            return o.Replace("\r", "").Split('\n', StringSplitOptions.RemoveEmptyEntries).ToList();
        }
        finally
        {
            try { System.IO.Directory.Delete(dir, true); } catch (IOException) { }
        }
    }

    /// <summary>Returns passwords already recovered for these hashes (hashcat --show against the potfile).</summary>
    public async Task<List<string>> ShowAsync(int mode, string hashFile, string potfile, VolumeCredentials? credentials = null)
    {
        var args = new List<string> { "-m", mode.ToString(), hashFile, "--show", "--potfile-path", potfile, "--outfile-format", "2", "--quiet" };
        // PIM options change salt_iter, so hashcat cannot match its own potfile when --show uses them.
        var (code, o, _) = await RunAsync(args, TimeSpan.FromSeconds(60));
        var passwords = new List<string>();
        // A failed --show prints its error to stdout (for example a missing hash-mode module).
        if (code != 0) return passwords;
        using var reader = new StringReader(o);
        while (reader.ReadLine() is { } line)
            if (!line.StartsWith("Hash '") && !line.Contains("Token length exception") && !line.StartsWith("No hashes loaded"))
                passwords.Add(DecodePlain(line, credentials));
        return passwords;
    }

    public static string DecodePlain(string s, VolumeCredentials? credentials)
    {
        s = DecodePlain(s);
        if (credentials is { Pim: > 0 })
        {
            string suffix = "   (PIM=" + credentials.Pim.ToString(System.Globalization.CultureInfo.InvariantCulture) + ")";
            if (s.EndsWith(suffix, StringComparison.Ordinal)) s = s[..^suffix.Length];
        }
        return s;
    }

    public static string DecodePlain(string s)
    {
        if (s.StartsWith("$HEX[") && s.EndsWith(']'))
        {
            try
            {
                var bytes = Convert.FromHexString(s[5..^1]);
                try { return new UTF8Encoding(false, true).GetString(bytes); }
                catch (DecoderFallbackException) { return Encoding.Latin1.GetString(bytes); }
            }
            catch (FormatException) { }
        }
        return s;
    }
}
