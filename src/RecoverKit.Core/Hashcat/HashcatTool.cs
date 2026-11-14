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
    public string DriverVersion { get; init; } = "";
    public string Type { get; init; } = "";
    public string Vendor { get; init; } = "";
    public string Name { get; init; } = "";
    public int Processors { get; init; }
    public int ClockMhz { get; init; }
    public long MemoryMb { get; init; }
    /// <summary>hashcat's "Memory.Unified" flag: the device shares the system memory (integrated GPUs, Apple silicon).</summary>
    public bool Unified { get; init; }

    /// <summary>A GPU built into the processor package (shares memory and power with the CPU cores).</summary>
    public bool IsIntegratedGpu => Unified && IsGpu;

    public bool IsGpu => Type.Contains("GPU", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Identifies the device across runs even when hashcat numbers devices differently (a backend
    /// added or removed by a driver update shifts every id): backend, name and the position among
    /// devices with the same backend and name.
    /// </summary>
    public string Key { get; internal set; } = "";

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
    public int? OptimizedPasswordLenMax { get; init; }
    public string? BenchmarkMask { get; init; }
    public string? BenchmarkCharset1 { get; init; }
    public string? ExampleHash { get; init; }
    public int PureBenchmarkLength { get; init; }
    public int BenchmarkLength => Native.MaskSpace.FromHashcatArgs(["-a", "3", "-1", BenchmarkCharset1 ?? "", BenchmarkMask ?? ""])?.MaxLength ?? 0;
}

/// <summary>Locates hashcat and runs its short informational commands.</summary>
public sealed partial class HashcatTool
{
    public string Exe { get; }
    public string Directory { get; }

    /// <summary>CPU worker threads for the OpenCL CPU runtime (0 = one per logical processor).</summary>
    public int MaxCpuThreads { get; set; }

    private readonly Dictionary<(string Version, int Mode, int AttackMode), HashModeInfo?> _modeInfo = new();

    internal static HashcatTool ForExe(string exe) => new(exe);

    private HashcatTool(string exe)
    {
        Exe = exe;
        Directory = Path.GetDirectoryName(Path.GetFullPath(exe)) ?? ".";
    }

    /// <summary>
    /// Finds hashcat: the configured path, the engines copy of the pinned hashcat (when the app has a
    /// bundle, on macOS, or when that copy exists), ./hashcat/ next to the application, the per-user engines
    /// folder, then PATH. The installed versions never run the bundled hashcat itself
    /// (Contents/Resources/hashcat on macOS, hashcat/ beside the executable on Windows; see
    /// <see cref="HashcatInstaller.TryInstallBundled"/>); the portable version runs it in place.
    /// </summary>
    public static HashcatTool? Locate(string? configured)
        => Locate(configured, AppContext.BaseDirectory, Path.Combine(Settings.AppDataDir, "engines"), Settings.IsPortable);

    internal static HashcatTool? Locate(string? configured, string baseDir, string enginesDir, bool portable = false)
    {
        string exeName = HashcatInstaller.ExeName;
        var candidates = new List<string>();
        string? bundle = HashcatInstaller.FindBundle(baseDir);
        bool inPlace = portable && bundle is not null;
        // A configured path to a copy that RecoverKit installed for another release (engines/hashcat-7.1.2)
        // gives way to the pinned version once that is installed too. The portable version's pinned
        // hashcat is the bundled one, run where it is.
        string pinned = inPlace ? Path.Combine(bundle!, exeName) : Path.Combine(enginesDir, "hashcat-" + HashcatInstaller.Version, exeName);
        if (!string.IsNullOrWhiteSpace(configured) && !(IsUnpinnedManagedCopy(configured, enginesDir) && File.Exists(pinned)))
            candidates.Add(configured);
        if (bundle is not null || OperatingSystem.IsMacOS() || File.Exists(pinned))
            candidates.Add(pinned);
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

        // hashcat writes into its own folder, so the installed versions never run the copy shipped with the app.
        var hit = candidates.FirstOrDefault(c => File.Exists(c) && (bundle is null || inPlace ||
            !Path.GetFullPath(c).StartsWith(bundle + Path.DirectorySeparatorChar, StringComparison.Ordinal)));
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

    /// <summary>The hashcat-&lt;version&gt; folder of the engines folder that holds <paramref name="exe"/> (a copy RecoverKit installed), or null.</summary>
    private static string? ManagedFolder(string exe, string enginesDir)
    {
        try
        {
            var dir = Path.GetDirectoryName(Path.GetFullPath(exe));
            if (dir is null || !string.Equals(Path.GetDirectoryName(dir), Path.GetFullPath(enginesDir).TrimEnd(Path.DirectorySeparatorChar), StringComparison.OrdinalIgnoreCase))
                return null;
            var name = Path.GetFileName(dir);
            return name.StartsWith("hashcat-", StringComparison.Ordinal) ? name : null;
        }
        catch (Exception ex) when (ex is ArgumentException or PathTooLongException or NotSupportedException) { return null; }
    }

    /// <summary>True when <paramref name="exe"/> is a copy RecoverKit installed into the engines folder.</summary>
    internal static bool IsManagedCopy(string exe, string enginesDir) => ManagedFolder(exe, enginesDir) is not null;

    /// <summary>
    /// True when <paramref name="exe"/> is a copy RecoverKit installed for another release (any version but
    /// the pinned <see cref="HashcatInstaller.Version"/>, whose kernel files RecoverKit's ZIP kernels need).
    /// </summary>
    internal static bool IsUnpinnedManagedCopy(string exe, string enginesDir)
        => ManagedFolder(exe, enginesDir) is { } name && name != "hashcat-" + HashcatInstaller.Version;

    /// <summary>True when this hashcat was installed by RecoverKit (the engines folder), not by the user.</summary>
    public bool IsManaged => IsManagedCopy(Exe, Path.Combine(Settings.AppDataDir, "engines")) || IsInPlaceBundle;

    /// <summary>True when this is the portable version's bundled hashcat, run where it is.</summary>
    public bool IsInPlaceBundle => IsInside(Exe, HashcatInstaller.InPlaceBundle);

    internal static bool IsInside(string exe, string? folder)
    {
        if (folder is null) return false;
        try { return Path.GetFullPath(exe).StartsWith(Path.GetFullPath(folder).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase); }
        catch (Exception ex) when (ex is ArgumentException or PathTooLongException or NotSupportedException) { return false; }
    }

    /// <summary>
    /// The version in hashcat's <c>--version</c> output ("v7.1.2", "v6.2.6-851-g6716447df" -> 6.2.6), or
    /// null when it cannot be read.
    /// </summary>
    public static Version? ParseVersion(string versionOutput)
    {
        var m = Regex.Match(versionOutput.Trim(), @"^v?(\d+)\.(\d+)(?:\.(\d+))?");
        if (!m.Success) return null;
        int Part(int i) => m.Groups[i].Success && int.TryParse(m.Groups[i].Value, out var v) ? v : 0;
        return new Version(Part(1), Part(2), Part(3));
    }

    /// <summary>
    /// True when <paramref name="versionOutput"/> names a hashcat older than the pinned
    /// <see cref="HashcatInstaller.Version"/>, wherever it is installed. Unknown versions are not older.
    /// </summary>
    public static bool IsOlderThanPinned(string versionOutput)
        => ParseVersion(versionOutput) is { } v && v < Version.Parse(HashcatInstaller.Version);

    private int? _major;

    /// <summary>
    /// hashcat's major version from <c>--version</c> (v8.0.0 -> 8), cached; 0 when it cannot be read.
    /// hashcat 8 no longer runs the command stored in a restore file (see <see cref="HashcatRunner.BuildArguments"/>).
    /// </summary>
    private string? _fullVersion;

    /// <summary>The complete hashcat version for performance-profile invalidation, cached after the first read.</summary>
    public string FullVersion
    {
        get
        {
            if (_fullVersion is not null) return _fullVersion;
            try
            {
                using var process = Process.Start(StartInfo(["--version"]));
                if (process is null) return _fullVersion = "unknown";
                var stdout = process.StandardOutput.ReadToEndAsync();
                var stderr = process.StandardError.ReadToEndAsync();
                if (!process.WaitForExit(20_000)) { process.Kill(true); return _fullVersion = "unknown"; }
                _ = stderr.GetAwaiter().GetResult();
                return _fullVersion = stdout.GetAwaiter().GetResult().Trim();
            }
            catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException or IOException)
            { return _fullVersion = "unknown"; }
        }
    }

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
                    _fullVersion = o.Trim();
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
    public async Task<(int Code, string Out, string Err)> RunAsync(IEnumerable<string> args, TimeSpan timeout, string? stdin = null, CancellationToken ct = default, ProcessPriority? priority = null, bool redactOutput = false, bool preserveOutputBom = false)
    {
        var psi = StartInfo(args, stdin is not null);
        // --show prints recovered plaintexts: keep them out of the debug log.
        bool redact = redactOutput || psi.ArgumentList.Contains("--show") || psi.ArgumentList.Contains("--hash-info");
        int logId = DebugLog.ProcessStart(psi);
        var sw = Stopwatch.StartNew();
        using var p = new Process { StartInfo = psi };
        p.Start();
        if (priority is { } selectedPriority && Native.NativeRunner.LowersProcessPriority)
            try { p.PriorityClass = Native.NativeRunner.ProcessClassFor(selectedPriority); }
            catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception or PlatformNotSupportedException) { }
        using var output = preserveOutputBom ? new StreamReader(p.StandardOutput.BaseStream, new UTF8Encoding(false), detectEncodingFromByteOrderMarks: false) : null;
        var outTask = (output ?? p.StandardOutput).ReadToEndAsync(ct);
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
            await p.WaitForExitAsync(CancellationToken.None);
            try { await Task.WhenAll(outTask, errTask); } catch (OperationCanceledException) { }
            ct.ThrowIfCancellationRequested();
            DebugLog.Warn($"#{logId} timed out after {timeout.TotalSeconds:F0} s and was killed");
            throw new TimeoutException($"hashcat did not finish within {timeout.TotalSeconds:F0} s.");
        }
        var (o, e) = (await outTask, await errTask);
        DebugLog.ProcessText(logId, "stdout", o, redact);
        DebugLog.ProcessText(logId, "stderr", e, redact);
        DebugLog.ProcessExit(logId, p.ExitCode, sw.Elapsed);
        return (p.ExitCode, o, e);
    }

    public async Task<string> VersionAsync(CancellationToken ct = default)
    {
        try
        {
            var (_, o, _) = await RunAsync(["--version"], VersionTimeout, ct: ct);
            return _fullVersion = o.Trim();
        }
        catch (TimeoutException) { throw new HashcatStartTimeoutException(StartTimeoutMessage(Directory, VersionTimeout)); }
    }

    // ---------------------------------------------------------------- devices

    public async Task<List<BackendDevice>> DevicesAsync(CancellationToken ct = default)
    {
        try
        {
            var (_, o, e) = await RunAsync(["-I", "--quiet"], DevicesTimeout, ct: ct);
            return ParseDevices(o + "\n" + e);
        }
        catch (TimeoutException) { throw new TimeoutException(DevicesTimeoutMessage(DevicesTimeout)); }
    }

    internal static readonly TimeSpan VersionTimeout = TimeSpan.FromSeconds(20);
    internal static readonly TimeSpan DevicesTimeout = TimeSpan.FromSeconds(90);

    /// <summary>
    /// hashcat --version prints one line without touching any device, so a timeout means the program
    /// did not start: usually antivirus software holding or blocking it (hashcat is often classed as a
    /// "hacking tool").
    /// </summary>
    internal static string StartTimeoutMessage(string folder, TimeSpan timeout)
        => $"hashcat did not start within {timeout.TotalSeconds:F0} s. Antivirus software may be scanning or blocking it: " +
           $"allow the folder {folder} in your antivirus (and restore hashcat from its quarantine if it is there), then click Check again.";

    internal static string DevicesTimeoutMessage(TimeSpan timeout)
        => $"hashcat started but did not list the graphics cards and processors within {timeout.TotalSeconds:F0} s (hashcat -I). " +
           "A graphics card driver or an OpenCL runtime is probably hanging: update or reinstall the graphics driver, restart the computer, then click Check again.";

    public static List<BackendDevice> ParseDevices(string text)
    {
        var list = new List<BackendDevice>();
        string backend = "", backendVersion = "", driverVersion = "";
        var lines = text.Replace("\r", "").Split('\n');
        for (int i = 0; i < lines.Length; i++)
        {
            var l = lines[i].Trim();
            var api = ApiHeader().Match(l);
            if (api.Success) { backend = api.Groups[1].Value; backendVersion = ""; driverVersion = ""; continue; }
            var ver = Field().Match(l);
            if (ver.Success && ver.Groups[1].Value == "Driver.Version") driverVersion = ver.Groups[2].Value.Trim();
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
                DriverVersion = f.GetValueOrDefault("Driver.Version") ?? driverVersion,
                // hashcat -I prints no "Type" for CUDA and HIP devices; those backends only expose GPUs.
                Type = f.GetValueOrDefault("Type") ?? (backend is "CUDA" or "HIP" ? "GPU" : ""),
                Vendor = f.GetValueOrDefault("Vendor") ?? "",
                Name = f.GetValueOrDefault("Name") ?? "",
                Processors = Num("Processor(s)"),
                ClockMhz = Num("Clock"),
                MemoryMb = Num("Memory.Total"),
                Unified = f.TryGetValue("Memory.Unified", out var uni) && uni.Trim() == "1",
            });
        }
        ResolveSkipped(list);
        foreach (var g in list.GroupBy(d => (d.Backend, d.Name)))
        {
            int n = 0;
            foreach (var d in g.OrderBy(d => d.Id)) d.Key = $"{d.Backend}|{d.Name}|{n++}";
        }
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

    public async Task<HashModeInfo?> ModeInfoAsync(int mode, int attackMode = 0, CancellationToken ct = default)
    {
        HashModeInfo? info = null;
        try
        {
            string version = await VersionAsync(ct);
            if (string.IsNullOrWhiteSpace(version)) return null;
            var key = (version, mode, attackMode);
            lock (_modeInfo) if (_modeInfo.TryGetValue(key, out var c)) return c;
            var args = new List<string> { "--hash-info", "-m", mode.ToString(), "-a", attackMode.ToString(), "--machine-readable", "--quiet" };
            var (code, pure, _) = await RunAsync(args, TimeSpan.FromSeconds(30), ct: ct);
            if (code == 0)
            {
                info = ParseModeInfo(mode, pure, null);
                if (info.HasOptimizedKernel)
                {
                    // One --hash-info ignores -O. The detailed query selects the kernel and attack mode.
                    args.Insert(0, "--hash-info");
                    args.Add("-O");
                    try
                    {
                        var (optCode, opt, _) = await RunAsync(args, TimeSpan.FromSeconds(30), ct: ct);
                        if (optCode == 0) info = ParseModeInfo(mode, pure, opt);
                    }
                    catch (Exception ex) when (ex is TimeoutException or IOException or System.ComponentModel.Win32Exception) { }
                }
            }
            lock (_modeInfo) _modeInfo[key] = info;
        }
        catch (Exception ex) when (ex is JsonException or KeyNotFoundException or InvalidOperationException
                                   or TimeoutException or IOException or System.ComponentModel.Win32Exception) { }
        return info;
    }

    internal static HashModeInfo ParseModeInfo(int mode, string pure, string? optimized)
    {
        using var doc = JsonDocument.Parse(pure);
        var e = doc.RootElement.GetProperty(mode.ToString());
        int? limit = null;
        string? mask = null, charset = null;
        if (optimized is not null)
        {
            try
            {
                using var optDoc = JsonDocument.Parse(optimized);
                var opt = optDoc.RootElement.GetProperty(mode.ToString());
                if (opt.TryGetProperty("kernel_type_filter", out var filter)
                    && filter.EnumerateArray().Any(x => x.GetString() == "optimized")
                    && opt.TryGetProperty("password_len_max", out var pl) && pl.TryGetInt32(out int max) && max > 0)
                {
                    limit = max;
                    mask = opt.TryGetProperty("benchmark_mask", out var bm) ? bm.GetString() : null;
                    charset = opt.TryGetProperty("benchmark_charset1", out var cs) ? cs.GetString() : null;
                }
            }
            catch (Exception ex) when (ex is JsonException or KeyNotFoundException or InvalidOperationException or FormatException) { }
        }
        return new HashModeInfo
        {
            PureBenchmarkLength = Native.MaskSpace.FromHashcatArgs(["-a", "3", "-1", e.TryGetProperty("benchmark_charset1", out var pcs) ? pcs.GetString() ?? "" : "", e.TryGetProperty("benchmark_mask", out var pm) ? pm.GetString() ?? "" : ""])?.MaxLength ?? 0,
            Mode = mode,
            Name = e.GetProperty("name").GetString() ?? "",
            SlowHash = e.TryGetProperty("slow_hash", out var sh) && sh.GetBoolean(),
            HasOptimizedKernel = e.TryGetProperty("kernel_type", out var kt) && kt.EnumerateArray().Any(x => x.GetString() == "optimized"),
            PasswordLenMax = e.TryGetProperty("password_len_max", out var pureMax) ? pureMax.GetInt32() : 256,
            OptimizedPasswordLenMax = limit,
            BenchmarkMask = mask ?? (e.TryGetProperty("benchmark_mask", out var pureMask) ? pureMask.GetString() : null),
            BenchmarkCharset1 = charset ?? (e.TryGetProperty("benchmark_charset1", out var bc) ? bc.GetString() : null),
            ExampleHash = e.TryGetProperty("example_hash", out var example) ? example.GetString() : null,
        };
    }

    // ---------------------------------------------------------------- benchmark

    /// <summary>Benchmarks one mode; returns total H/s over all devices.</summary>
    /// <summary>
    /// hashcat's --keyspace for an attack: for masks, the number of base words that --skip/--limit and
    /// restore points count (not candidates). Null when hashcat rejects the arguments.
    /// </summary>
    public async Task<long?> KeyspaceAsync(int mode, IEnumerable<string> attackArgs, CancellationToken ct = default, bool useOptimizedKernel = false)
    {
        var args = new List<string> { "-m", mode.ToString(), "--keyspace", "--quiet" };
        args.AddRange(attackArgs);
        if (useOptimizedKernel) args.Add("-O");
        var (code, o, _) = await RunAsync(args, TimeSpan.FromSeconds(60), ct: ct);
        var last = o.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).LastOrDefault();
        return code == 0 && long.TryParse(last, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var k) && k > 0 ? k : null;
    }

    public async Task<double> BenchmarkAsync(int mode, IEnumerable<string> deviceArgs, CancellationToken ct, bool optimizedKernels = true)
    {
        HashcatKernels.EnsureFor(this, mode);
        // hashcat 8: -b benchmarks the optimized kernel where a mode has one, -B the pure one, and it
        // refuses -B together with -O. The shared decision picks the kernel, not the caller's arguments.
        bool optimized = await RecoverySession.SelectOptimizedKernelAsync(this, mode, null, optimizedKernels);
        var args = new List<string> { MajorVersion >= 8 && !optimized ? "-B" : "-b", "-m", mode.ToString(), "--machine-readable", "--quiet" };
        if (optimized) args.Add("-O");
        args.AddRange(deviceArgs.Where(a => a is not ("-O" or "--optimized-kernel-enable")));
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
        => (await ShowRawAsync(mode, hashFile, potfile)).Select(l => DecodePlain(l, credentials)).ToList();

    /// <summary>Plaintexts from --show ($HEX[...] kept); preserveBom retains BOM bytes belonging to the first password.</summary>
    public async Task<List<string>> ShowRawAsync(int mode, string hashFile, string potfile, bool preserveBom = false)
    {
        var args = new List<string> { "-m", mode.ToString(), hashFile, "--show", "--potfile-path", potfile, "--outfile-format", "2", "--quiet" };
        // PIM options change salt_iter, so hashcat cannot match its own potfile when --show uses them.
        var (code, o, _) = await RunAsync(args, TimeSpan.FromSeconds(60), preserveOutputBom: preserveBom);
        var passwords = new List<string>();
        // A failed --show prints its error to stdout (for example a missing hash-mode module).
        if (code != 0) return passwords;
        using var reader = new StringReader(o);
        while (reader.ReadLine() is { } line)
            if (!line.StartsWith("Hash '") && !line.Contains("Token length exception") && !line.StartsWith("No hashes loaded"))
                passwords.Add(line);
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

/// <summary>hashcat did not answer <c>--version</c> in time: the program itself did not start.</summary>
public sealed class HashcatStartTimeoutException(string message) : TimeoutException(message);
