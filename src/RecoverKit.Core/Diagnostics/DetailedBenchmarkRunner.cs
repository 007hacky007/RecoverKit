using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using RecoverKit.Core.Hashcat;
using RecoverKit.Core.Native;

namespace RecoverKit.Core.Diagnostics;

/// <summary>Runs synthetic diagnostics in an isolated hashcat installation, without saving settings.</summary>
public sealed class DetailedBenchmarkRunner(HashcatTool? tool, Settings settings, IReadOnlyList<BackendDevice> devices)
{
    public static IReadOnlyList<DiagnosticSection> Sections { get; } =
    [
        new("system", "System and devices", 0.5),
        new("cpu", "Built-in CPU engine and correctness", 5),
        new("gpu", "GPU formats, each device and backend", 20),
        new("zip", "ZIP GPU kernels and entry sizes", 25),
        new("hybrid", "Finite CPU, GPU and hybrid jobs", 20),
    ];

    /// <summary>Dwell time for live ZIP samples. Startup and compilation take additional time.</summary>
    public int Seconds { get; init; } = 6;
    private static readonly int[] Modes = [9400, 9600, 12500, 13000, 13600, 22000, 10500, 17200, 17210, 29321, 29331];

    internal static string[] SelectSections(IEnumerable<string>? sections)
    {
        var selected = sections?.ToHashSet(StringComparer.OrdinalIgnoreCase) ?? Sections.Select(s => s.Id).ToHashSet();
        if (selected.Any(s => !Sections.Any(x => x.Id.Equals(s, StringComparison.OrdinalIgnoreCase))))
            throw new ArgumentException("Unknown diagnostics section. Choose system,cpu,gpu,zip,hybrid.");
        return Sections.Where(s => selected.Contains(s.Id)).Select(s => s.Id).ToArray();
    }

    public async Task<DiagnosticReport> RunAsync(IEnumerable<string>? sections = null, IProgress<DiagnosticProgress>? progress = null, CancellationToken ct = default)
    {
        var selected = SelectSections(sections);
        var report = new DiagnosticReport { CpuPolicy = PerformanceProfiles.PolicyFingerprint(settings, "cpu"), GpuPolicy = PerformanceProfiles.PolicyFingerprint(settings, "gpu") };
        var clock = Stopwatch.StartNew();
        string current = "", step = "Preparing";
        double estimatedMinutes = Sections.Where(s => selected.Contains(s.Id)).Sum(s => s.EstimatedMinutes);
        void Update(string text)
        {
            step = text;
            progress?.Report(new(current, step, clock.Elapsed, TimeSpan.FromSeconds(Math.Max(0, estimatedMinutes * 60 - clock.Elapsed.TotalSeconds))));
        }
        using var pulse = new Timer(_ => Update(step), null, 1000, 1000);
        string? isolated = null;
        HashcatTool? local = null;
        async Task PrepareGpuAsync()
        {
            if (local is not null || tool is null) return;
            Update("Preparing isolated GPU engine");
            isolated = Directory.CreateTempSubdirectory("rk-diagnostics-").FullName;
            await Task.Run(() => CopyEngine(tool.Directory, isolated, ct), ct);
            local = HashcatTool.Locate(Path.Combine(isolated, Path.GetFileName(tool.Exe)))
                ?? throw new InvalidOperationException("Cannot open the isolated GPU engine.");
            local.MaxCpuThreads = settings.MaxCpuThreads;
            devices = await local.DevicesAsync(ct);
            if (devices.Count == 0)
            {
                // A fresh portable copy can initialize a backend on its first invocation.
                var (_, output, error) = await local.RunAsync(["-I"], TimeSpan.FromSeconds(90), ct: ct);
                devices = HashcatTool.ParseDevices(output + "\n" + error);
            }
        }
        try
        {
            foreach (string section in selected)
            {
                ct.ThrowIfCancellationRequested();
                current = section;
                Update("Starting section");
                var sectionClock = Stopwatch.StartNew();
                try
                {
                    if (section == "system") { await PrepareGpuAsync(); await SystemAsync(local, report, ct); }
                    else if (section == "cpu") await CpuDiagnostics.RunAsync(report.Measurements.Add, Update, ct, settings);
                    else
                    {
                        if (tool is null) throw new InvalidOperationException("hashcat is unavailable.");
                        await PrepareGpuAsync();
                        if (devices.All(d => !d.IsGpu)) throw new InvalidOperationException("No GPU devices were detected.");
                        if (HashcatRunner.ActiveGpus(settings, devices).Count == 0) throw new InvalidOperationException("GPU tests skipped: every physical GPU is disabled.");
                        if (!await PowerLimitSatisfiedAsync()) throw new InvalidOperationException("GPU tests skipped: the configured power limit is not already active. Set it before measuring; diagnostics never raises power limits.");
                        if (section is "gpu" or "zip" && (settings.GpuTempGuard || settings.GpuDutyPercent < 100))
                            throw new InvalidOperationException("GPU benchmark skipped: hashcat benchmark output cannot enforce the pause/duty guard. Finite hybrid jobs retain the configured guard.");
                        if (section == "gpu") await GpuAsync(local!, report, Update, ct);
                        if (section == "zip") await ZipAsync(local!, report, Update, ct);
                        if (section == "hybrid") await HybridAsync(local!, report, Update, ct);
                    }
                }
                catch (Exception ex) when (ex is not OperationCanceledException && !ct.IsCancellationRequested)
                {
                    report.Measurements.Add(new() { Section = section, Step = step, Error = SafeError(ex) });
                }
                finally { report.System[$"Elapsed.{section}.seconds"] = sectionClock.Elapsed.TotalSeconds.ToString("F2", CultureInfo.InvariantCulture); }
            }
        }
        catch (Exception) when (ct.IsCancellationRequested) { report.Cancelled = true; }
        finally
        {
            report.Cancelled |= ct.IsCancellationRequested;
            pulse.Change(Timeout.Infinite, Timeout.Infinite);
            report.System["NVIDIA telemetry after"] = Telemetry();
            if (isolated is not null)
                try { Directory.Delete(isolated, true); }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                { report.Summary.Add("Temporary GPU files could not be removed; they contain synthetic targets only."); }
            report.Finished = DateTimeOffset.UtcNow;
        }
        // A failed correctness check must quarantine an old choice even if no timing completed.
        if (report.Measurements.Any(m => m.Correct && m.Speed > 0 || m.Section == "cpu" && !m.Correct && m.Variant.Length > 0))
        {
            try { PerformanceProfiles.Record(report, tool, devices, "detailed"); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            { report.Summary.Add("The report is available, but this computer's performance profile could not be saved."); }
        }
        return report;
    }

    private async Task SystemAsync(HashcatTool? systemTool, DiagnosticReport report, CancellationToken ct)
    {
        report.System["RecoverKit version"] = typeof(DetailedBenchmarkRunner).Assembly.GetName().Version?.ToString() ?? "unknown";
        report.System["Build configuration"] = PerformanceProfiles.BuildConfiguration;
        report.System[".NET runtime"] = Environment.Version.ToString();
        report.System["Native library API"] = NativeKernels.NativeApiVersion.ToString();
        report.System["OS"] = RuntimeInformation.OSDescription;
        report.System["Architecture"] = RuntimeInformation.ProcessArchitecture.ToString();
        report.System["CPU"] = SystemFacts.CpuName();
        report.System["CPU features"] = NativeKernels.CpuFeatures();
        report.System["Physical cores"] = SystemFacts.PhysicalCores().ToString();
        report.System["Logical threads"] = Environment.ProcessorCount.ToString();
        report.System["RAM bytes"] = SystemFacts.RamBytes().ToString();
        report.System["GPU temperature guard"] = settings.GpuTempGuard ? $"active, {settings.GpuTempLimit} C" : "off";
        report.System["GPU duty percent"] = settings.GpuDutyPercent.ToString();
        report.System["GPU power limit"] = settings.GpuPowerLimit ? "requested; tests run only if already active" : "off; current hardware limits retained";
        report.System["Strategy preference"] = settings.Strategy.ToString();
        report.System["Built-in CPU engine enabled"] = settings.UseNativeCpuEngine.ToString();
        report.System["Hybrid enabled"] = settings.HybridCpuGpu.ToString();
        report.System["CPU thread budget"] = settings.MaxCpuThreads > 0 ? settings.MaxCpuThreads.ToString() : "all logical threads";
        report.System["Optimized kernels enabled"] = settings.OptimizedKernels.ToString();
        report.System["GPU workload"] = settings.Workload.ToString();
        report.System["Priority preference"] = settings.Priority.ToString();
        report.System["Diagnostics process priority"] = Process.GetCurrentProcess().PriorityClass.ToString();
        report.System["CPU worker priority"] = NativeRunner.ThreadPriorityFor(settings.Priority).ToString();
        report.System["NVRTC"] = NvrtcRuntime.Locate() is not null ? "private installation present" : devices.Any(d => d.Backend == "CUDA") ? "CUDA backend available" : "private installation absent; CUDA not detected";
        report.System["NVIDIA telemetry before"] = Telemetry();
        report.System["Power plan"] = OperatingSystem.IsWindows() ? await ReadCommandAsync("powercfg", ["/getactivescheme"], ct) : "not applicable";
        foreach (var device in devices)
            report.System[$"Device {device.Id}"] = $"{device.Name}; {device.Backend} {device.BackendVersion}; {device.Type}; alias {device.AliasOf?.ToString() ?? "none"}; skipped {device.IsSkippedAlias}; user disabled {HashcatRunner.IsDisabled(settings, device)}; memory {device.MemoryMb} MB";
        if (systemTool is null) { report.System["hashcat version"] = "unavailable"; return; }
        report.System["hashcat version"] = await systemTool.VersionAsync();
        var (_, o, e) = await systemTool.RunAsync(["-I"], TimeSpan.FromSeconds(90), ct: ct);
        var versions = (o + "\n" + e).Split('\n').Where(l => Regex.IsMatch(l, @"^\s*(Driver\.Version|Version|CUDA\.Version|HIP\.Version|Metal\.Version)\.{2,}\s*:")).Select(l => l.Trim());
        report.System["GPU drivers"] = string.Join("; ", versions);
    }

    private IEnumerable<BackendDevice> AllowedGpuDevices()
    {
        var active = HashcatRunner.ActiveGpus(settings, devices).Select(d => GpuProfileSelection.FamilyKey(d.Key, devices)).ToHashSet();
        return devices.Where(d => d.IsGpu && !HashcatRunner.IsDisabled(settings, d) && active.Contains(GpuProfileSelection.FamilyKey(d.Key, devices)));
    }

    private async Task GpuAsync(HashcatTool local, DiagnosticReport report, Action<string> progress, CancellationToken ct)
    {
        foreach (var dev in AllowedGpuDevices())
        foreach (int mode in Modes)
        foreach (bool pure in mode == 12500 && settings.OptimizedKernels ? new[] { false, true } : new[] { !settings.OptimizedKernels })
        for (int repeat = 1; repeat <= 2; repeat++)
        {
            ct.ThrowIfCancellationRequested();
            string label = $"Device {dev.Id} {dev.Backend}, mode {mode}, {(pure ? "pure" : "default")}, repeat {repeat}/2";
            progress(label);
            var clock = Stopwatch.StartNew();
            var row = new DiagnosticMeasurement { Section = "gpu", Step = label, Mode = mode, Target = $"hashcat built-in example mode {mode}", Length = 0, Engine = "gpu", Variant = pure ? "pure" : "default", DeviceKey = dev.Key, Backend = dev.Backend, Repeat = repeat };
            try
            {
                if (mode is 17200 or 17210)
                {
                    HashcatKernels.EnsureFor(local, mode);
                    row.Details["ZIP GPU kernel"] = HashcatKernels.Inspect(local.Directory) == HashcatKernels.State.Installed ? "replacement" : "hashcat original";
                }
                var args = new List<string> { pure ? "-B" : "-b", "-m", mode.ToString(), "-d", dev.Id.ToString(), "-w", settings.Workload.ToString(), "--potfile-disable", "--restore-disable", "--logfile-disable", "--session", "rk-diagnostic-bench" };
                var (code, output, error) = await local.RunAsync(args, TimeSpan.FromMinutes(4), ct: ct, priority: settings.Priority, redactOutput: true);
                var parsed = ParseBenchmark(output + "\n" + error);
                row.Speed = parsed.Speed;
                foreach (var detail in parsed.Details) row.Details[detail.Key] = detail.Value;
                // hashcat's benchmark uses its own self-test and optimized/pure example workload.
                row.Correct = code == 0 && row.Speed > 0 && !Regex.IsMatch(output + error, "self-test.*(failed|error)", RegexOptions.IgnoreCase);
                if (!row.Correct) row.Error = DiagnosticGpuError.Classify(output, error, code);
                row.Details["Default"] = (!dev.IsSkippedAlias && pure == !settings.OptimizedKernels).ToString();
                row.Details["Length source"] = "hashcat module benchmark metadata; not compared with CPU fixture rates";
                var info = await local.ModeInfoAsync(mode);
                row.Length = info?.BenchmarkLength ?? 0;
                bool optimized = !pure && info?.HasOptimizedKernel == true;
                row.Details["Optimized"] = optimized.ToString();
                if (!row.Details.ContainsKey("Kernel"))
                {
                    row.Details["Kernel"] = optimized ? "optimized" : "pure";
                    row.Details["Kernel type source"] = "module capabilities and requested benchmark option";
                }
                row.Details["Comparability"] = "Benchmark rate only; never added to CPU fixture rates or used to choose CPU versus GPU.";
            }
            catch (Exception ex) when (ex is not OperationCanceledException && !ct.IsCancellationRequested) { row.Error = SafeError(ex); }
            row.ElapsedSeconds = clock.Elapsed.TotalSeconds;
            report.Measurements.Add(row);
        }
    }

    internal static DiagnosticMeasurement ParseBenchmark(string output)
    {
        var row = new DiagnosticMeasurement();
        var speed = Regex.Match(output, @"Speed\.#\d+[^:]*:\s*([\d.]+)\s*([kMGT]?)H/s", RegexOptions.IgnoreCase);
        if (speed.Success && double.TryParse(speed.Groups[1].Value, NumberStyles.Float, CultureInfo.InvariantCulture, out double value))
            row.Speed = value * (speed.Groups[2].Value.ToUpperInvariant() switch { "K" => 1e3, "M" => 1e6, "G" => 1e9, "T" => 1e12, _ => 1 });
        foreach (string key in new[] { "Accel", "Loops", "Thr", "Vec" })
        {
            var match = Regex.Match(output, $@"\b{key}:\s*(\d+)");
            if (match.Success) row.Details[key] = match.Groups[1].Value;
        }
        var kernel = Regex.Match(output, @"Kernel\.Feature[^:]*:\s*([^\r\n]+)");
        if (kernel.Success) row.Details["Kernel"] = kernel.Groups[1].Value.Trim();
        return row;
    }

    private async Task ZipAsync(HashcatTool local, DiagnosticReport report, Action<string> progress, CancellationToken ct)
    {
        var samples = ZipKernelBenchmark.DefaultSamples();
        var checkedPaths = new Dictionary<string, bool>();
        foreach (var device in AllowedGpuDevices())
        foreach (var sample in samples)
        for (int repeat = 1; repeat <= 2; repeat++)
        {
            ct.ThrowIfCancellationRequested();
            var clock = Stopwatch.StartNew();
            var bench = new ZipKernelBenchmark(local) { Seconds = Math.Clamp(Seconds, 3, 60), Priority = settings.Priority };
            bench.Progress += message =>
            {
                if (!message.StartsWith("Device #", StringComparison.Ordinal)) return;
                string variant = message.Contains("amplifier cache", StringComparison.Ordinal) ? "amplifier cache" : message.Contains("RecoverKit", StringComparison.Ordinal) ? "replacement" : "hashcat original";
                progress($"Device {device.Id} {device.Backend}, {sample.Label}, {variant}, repeat {repeat}/2");
            };
            try
            {
                foreach (string variant in new[] { "hashcat", "replacement", "amplifier-cache" })
                {
                    string key = $"{device.Key}|{sample.Label}|{variant}";
                    if (!checkedPaths.TryGetValue(key, out bool correct))
                    {
                        progress($"Device {device.Id} {sample.Label}, checking {variant} correctness");
                        correct = await GpuZipCorrectness.CheckAsync(local, device, sample, variant, ct);
                        checkedPaths[key] = correct;
                        report.Measurements.Add(new() { Section = "zip", Step = "Correctness", Mode = sample.Mode, Target = "synthetic ZIP " + sample.Label, Length = 8, Engine = "gpu", Variant = variant, DeviceKey = device.Key, Backend = device.Backend, Correct = correct, Error = correct ? null : "FAIL: GPU results differ from scalar verification; this sample will not be timed.", Details = new() { ["Check"] = correct ? "PASS" : "FAIL", ["Candidates"] = "16 positive and negative candidates, exact match set" } });
                    }
                    if (!correct) throw new InvalidOperationException("ZIP correctness failed; timing skipped for this sample.");
                }
                var rows = await bench.RunAsync([device], [sample], ct);
                if (rows.Count == 0) throw new InvalidOperationException("Replacement ZIP kernels do not support this hashcat installation.");
                foreach (var row in rows)
                foreach (var (variant, speed) in new[] { ("hashcat", row.Original), ("replacement", row.Replacement), ("amplifier-cache", row.AmpCache) })
                    report.Measurements.Add(new() { Section = "zip", Step = sample.Label, Mode = sample.Mode, Target = "synthetic ZIP " + sample.Label, Length = 8, Engine = "gpu", Variant = variant, DeviceKey = device.Key, Backend = device.Backend, Repeat = repeat, Speed = speed, ElapsedSeconds = clock.Elapsed.TotalSeconds / 3, Correct = speed > 0, Error = speed > 0 ? null : "No benchmark rate reported.", Details = new() { ["Correctness"] = "PASS: exact recovered candidate set equals scalar verification on a matched synthetic entry.", ["Mask"] = "eight printable ASCII characters" } });
            }
            catch (Exception ex) when (ex is not OperationCanceledException && !ct.IsCancellationRequested)
            { report.Measurements.Add(new() { Section = "zip", Step = sample.Label, Mode = sample.Mode, DeviceKey = device.Key, Error = SafeError(ex), ElapsedSeconds = clock.Elapsed.TotalSeconds }); }
        }
    }

    private async Task HybridAsync(HashcatTool local, DiagnosticReport report, Action<string> progress, CancellationToken ct)
    {
        var physical = devices.Where(d => d.IsGpu && !d.IsSkippedAlias && !HashcatRunner.IsDisabled(settings, d)).ToList();
        if (physical.Count == 0)
        {
            report.Measurements.Add(new() { Section = "hybrid", Step = "Device selection", Error = "Finite GPU and hybrid jobs skipped: every physical GPU is disabled." });
            return;
        }
        var previous = PerformanceProfiles.Load();
        PerformanceProfiles.Invalidate(previous, PerformanceProfiles.CpuFingerprint, PerformanceProfiles.GpuFingerprint(local, devices));
        int limit = settings.MaxCpuThreads > 0 ? settings.MaxCpuThreads : Environment.ProcessorCount;
        var workers = new[] { Math.Max(1, SystemFacts.PhysicalCores() - 1), SystemFacts.PhysicalCores(), Math.Max(1, Environment.ProcessorCount - 1) }.Select(n => Math.Min(n, limit)).Distinct().ToArray();
        foreach (int mode in new[] { 13000, 17210 })
        {
            var groups = HybridBenchmarkDevices.Groups(settings, devices, mode, report.Measurements, previous);
            var hash = NativeKernels.BenchmarkHashes[mode];
            var kernel = NativeKernels.TryCreate(mode, hash);
            if (kernel is null) { report.Measurements.Add(new() { Section = "hybrid", Mode = mode, Step = "CPU kernel", Error = "Built-in kernel unavailable." }); continue; }
            var correctness = await CpuDiagnosticWorker.CheckAsync(mode, mode == 17210 ? PerformanceProfiles.DefaultZipVariant() : "default", ct);
            if (!correctness.Passed)
            {
                report.Measurements.Add(new() { Section = "hybrid", Mode = mode, Step = "CPU correctness FAIL", Engine = "cpu", Correct = false, Error = correctness.Error });
                continue;
            }
            // ZIP must outlast the scheduler's CPU-only shortcut to measure concurrent engines.
            int length = mode == 13000 ? 5 : 9;
            foreach (var group in groups)
            foreach (int count in new[] { 0, -1 }.Concat(workers).Append(HybridRunner.CpuThreads(settings, group, true)).Distinct())
            for (int repeat = 1; repeat <= 2; repeat++)
            {
                ct.ThrowIfCancellationRequested();
                if (count < 0 && !group.Select(d => d.Key).SequenceEqual(physical.Select(d => d.Key))) continue;
                string engine = count == 0 ? "gpu" : count < 0 ? "cpu" : "hybrid";
                string label = $"Mode {mode}, {engine}, {(count < 0 ? limit : count)} workers, {(count < 0 ? 0 : group.Count)} GPU(s), repeat {repeat}/2";
                progress(label);
                var row = new DiagnosticMeasurement { Section = "hybrid", Step = label, Mode = mode, Target = "native synthetic fixture mode " + mode, Length = length, Engine = engine, Variant = count == 0 ? "gpu-default" : engine, Threads = count < 0 ? limit : count, DeviceKey = count < 0 ? "" : string.Join(";", group.Select(d => d.Key)), Backend = count < 0 ? "" : string.Join(";", group.Select(d => d.Backend)), Repeat = repeat, Details = new() { ["Mask"] = $"A-N, {length} characters", ["Metric"] = "complete candidates / whole-job elapsed", ["Finite"] = "true" } };
                var clock = Stopwatch.StartNew();
                try
                {
                    row.Details["Default"] = (group.Select(d => d.Key).SequenceEqual(physical.Select(d => d.Key)) && (settings.HybridCpuGpu ? count == HybridRunner.CpuThreads(settings, physical, true) : count == 0)).ToString();
                    var result = await FiniteDiagnosticWorker.ExecuteAsync(local, settings, group, mode, count, length, limit, ct);
                    row.Correct = result.Correct;
                    row.Speed = result.Speed;
                    row.ElapsedSeconds = result.ElapsedSeconds;
                    row.Error = result.Error;
                    foreach (var detail in result.Details) row.Details[detail.Key] = detail.Value;
                }
                catch (Exception ex) when (ex is not OperationCanceledException && !ct.IsCancellationRequested) { row.Error = SafeError(ex); }
                finally { if (row.ElapsedSeconds <= 0) row.ElapsedSeconds = clock.Elapsed.TotalSeconds; report.Measurements.Add(row); }
            }
        }
    }

    private async Task<bool> PowerLimitSatisfiedAsync()
    {
        if (!settings.GpuPowerLimit) return true;
        var power = await NvidiaPower.QueryAsync();
        return power.Count > 0 && settings.GpuPowerWatts.All(pair => power.Any(p => p.Index == pair.Key && p.CurrentWatts <= pair.Value + 0.5));
    }

    private static string SafeError(Exception ex) => ex is InvalidOperationException ? ex.Message : $"Step failed ({ex.GetType().Name}); private process output omitted.";

    private static string Telemetry()
    {
        try
        {
            if (NvidiaSmi.Locate() is not { } exe) return "nvidia-smi unavailable";
            var (code, output) = new NvidiaSmi(exe).Run(["--query-gpu=name,driver_version,pstate,clocks.current.sm,power.draw,power.limit,temperature.gpu,utilization.gpu", "--format=csv"]);
            return code == 0 ? output.Trim() : "nvidia-smi query unavailable";
        }
        catch (Exception ex) when (ex is IOException or InvalidOperationException or System.ComponentModel.Win32Exception) { return "nvidia-smi query unavailable"; }
    }

    private static async Task<string> ReadCommandAsync(string exe, string[] args, CancellationToken ct)
    {
        try
        {
            var start = new ProcessStartInfo(exe) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
            foreach (string arg in args) start.ArgumentList.Add(arg);
            using var process = Process.Start(start)!;
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(TimeSpan.FromSeconds(3));
            var stdout = process.StandardOutput.ReadToEndAsync(timeout.Token);
            var stderr = process.StandardError.ReadToEndAsync(timeout.Token);
            try { await process.WaitForExitAsync(timeout.Token); }
            catch (OperationCanceledException) { try { process.Kill(true); } catch (InvalidOperationException) { } return "unavailable"; }
            _ = await stderr;
            // The GUID identifies a plan, while a custom plan name can contain personal data.
            var guid = Regex.Match(await stdout, @"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}");
            return guid.Success ? guid.Value : "unavailable";
        }
        catch (Exception ex) when (ex is IOException or InvalidOperationException or System.ComponentModel.Win32Exception) { return "unavailable"; }
    }

    internal static void CopyEngine(string source, string destination, CancellationToken ct) => CopyEngineTree(source, destination, true, ct);

    private static void CopyEngineTree(string source, string destination, bool root, CancellationToken ct)
    {
        foreach (string entry in Directory.EnumerateFileSystemEntries(source))
        {
            ct.ThrowIfCancellationRequested();
            string name = Path.GetFileName(entry);
            if ((File.GetAttributes(entry) & FileAttributes.ReparsePoint) != 0) continue;
            if (Directory.Exists(entry))
            {
                if (root && name is not ("OpenCL" or "modules" or "bridges" or "feeds" or "charsets" or "tables" or "masks" or "rules" or "tunings" or "pcfg")) continue;
                var dir = Directory.CreateDirectory(Path.Combine(destination, name));
                CopyEngineTree(entry, dir.FullName, false, ct);
            }
            else
            {
                if (root && !(name is "hashcat" or "hashcat.hcstat2" or "RECOVERKIT_BUNDLE" || name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) || name.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) || name.EndsWith(".bin", StringComparison.OrdinalIgnoreCase) || name.EndsWith(".so", StringComparison.OrdinalIgnoreCase) || name.EndsWith(".dylib", StringComparison.OrdinalIgnoreCase))) continue;
                if (name.EndsWith(".potfile", StringComparison.OrdinalIgnoreCase) || name.EndsWith(".restore", StringComparison.OrdinalIgnoreCase) || name.EndsWith(".log", StringComparison.OrdinalIgnoreCase) || name.EndsWith(".pid", StringComparison.OrdinalIgnoreCase)) continue;
                string dest = Path.Combine(destination, name);
                // Reuse macOS's validation of immutable native binaries. New copies of hundreds of
                // modules otherwise pay code-signature validation on every diagnostics run.
                bool immutableBinary = name is "hashcat" || name.EndsWith(".so", StringComparison.OrdinalIgnoreCase) || name.EndsWith(".dylib", StringComparison.OrdinalIgnoreCase);
                if (OperatingSystem.IsMacOS() && immutableBinary)
                {
                    if (name != "hashcat") { File.CreateSymbolicLink(dest, entry); continue; }
                    if (Link(entry, dest) == 0) continue;
                }
                File.Copy(entry, dest, true);
                if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(dest, File.GetUnixFileMode(entry));
            }
        }
    }
    [DllImport("libc", EntryPoint = "link", SetLastError = true)]
    private static extern int Link(string existingPath, string newPath);
}
