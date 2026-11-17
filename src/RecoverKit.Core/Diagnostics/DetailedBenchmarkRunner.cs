using RecoverKit.Core.Native.Kernels;
using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using RecoverKit.Core.Hashcat;
using RecoverKit.Core.Native;

namespace RecoverKit.Core.Diagnostics;

/// <summary>Runs synthetic diagnostics in an isolated hashcat installation, without saving settings.</summary>
public sealed partial class DetailedBenchmarkRunner(HashcatTool? tool, Settings settings, IReadOnlyList<BackendDevice> devices)
{
    public static IReadOnlyList<DiagnosticSection> Sections { get; } =
    [
        new("system", "System and devices", 0.5),
        new("cpu", "Built-in CPU engine and correctness", CpuDiagnostics.HasWidePaths ? 8 : 3),
        new("gpu", "GPU backends and main formats", 20),
        new("zip", "ZIP GPU kernels and entry sizes", 16),
        new("hybrid", "Finite CPU, GPU and hybrid jobs", 20),
    ];

    /// <summary>Dwell time for live ZIP samples. Startup and compilation take additional time.</summary>
    public int Seconds { get; init; } = 3;
    public bool Thorough { get; init; }
    private static readonly int[] Modes = [9400, 9600, 12500, 13000, 13600, 22000, 10500, 17200, 17210, 29321, 29322, 29323, 29421, 29422, 29423, 29331];

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
        if (!Thorough) return await RunShortAsync(selected, progress, ct);
        var report = new DiagnosticReport { CpuPolicy = PerformanceProfiles.PolicyFingerprint(settings, "cpu"), GpuPolicy = PerformanceProfiles.PolicyFingerprint(settings, "gpu") };
        var clock = Stopwatch.StartNew();
        var plan = new DiagnosticPlan();
        report.Plan = plan.Steps;
        void Update() => progress?.Report(plan.Progress(clock.Elapsed));
        using var pulse = new Timer(_ => Update(), null, Timeout.Infinite, 1000);
        string? isolated = null;
        HashcatTool? local = null;
        try
        {
            // Device discovery precedes the timed plan so every backend gets explicit slots.
            if (tool is not null && selected.Any(s => s != "cpu"))
            {
                progress?.Report(new("system", "Preparing isolated GPU engine and detecting devices", clock.Elapsed, TimeSpan.FromMinutes(Thorough ? 70 : 10)));
                isolated = Directory.CreateTempSubdirectory("rk-diagnostics-").FullName;
                await Task.Run(() => CopyEngine(tool.Directory, isolated, ct), ct);
                local = HashcatTool.Locate(Path.Combine(isolated, Path.GetFileName(tool.Exe)))
                    ?? throw new InvalidOperationException("Cannot open the isolated GPU engine.");
                local.MaxCpuThreads = settings.MaxCpuThreads;
                devices = await local.DevicesAsync(ct);
                if (devices.Count == 0)
                {
                    var (_, output, error) = await local.RunAsync(["-I"], TimeSpan.FromSeconds(30), ct: ct);
                    devices = HashcatTool.ParseDevices(output + "\n" + error);
                }
            }
            report.System["Test plan"] = Thorough ? "Thorough" : "Default (short windows and adaptive repeats)";
            CompleteSetup(report);
            report.System["Elapsed.preparation.seconds"] = clock.Elapsed.TotalSeconds.ToString("F2", CultureInfo.InvariantCulture);
            if (selected.Contains("system")) plan.Add("system", "System and devices", 5, () => SystemAsync(local, report, ct));
            if (selected.Contains("cpu")) CpuDiagnostics.AddSteps(plan, report, settings, Thorough, ct);
            bool gpuAllowed = local is not null && HashcatRunner.NvidiaBackendError(settings, devices) is null
                && HashcatRunner.ActiveGpus(settings, devices).Count > 0 && await PowerLimitSatisfiedAsync();
            foreach (string section in selected.Where(s => s is "gpu" or "zip" or "hybrid"))
            {
                if (!gpuAllowed || section is "gpu" or "zip" && (settings.GpuTempGuard || settings.GpuDutyPercent < 100))
                {
                    report.Measurements.Add(new() { Section = section, Step = "GPU availability and limits", Error = HashcatRunner.NvidiaBackendError(settings, devices)
                        ?? "GPU tests skipped: engine/devices unavailable, all GPUs disabled, or configured power/pause/duty limits prevent this benchmark." });
                    continue;
                }
                if (section == "gpu") { AddGpuSteps(plan, local!, report, ct); AddComparisonSteps(plan, local!, report, ct); }
                if (section == "zip") AddZipSteps(plan, local!, report, ct);
                if (section == "hybrid") AddHybridSteps(plan, local!, report, ct);
            }
            pulse.Change(1000, 1000);
            await plan.RunAsync(report, Update, ct);
        }
        catch (Exception) when (ct.IsCancellationRequested) { report.Cancelled = true; }
        finally
        {
            report.Cancelled |= ct.IsCancellationRequested;
            CompleteSetup(report);
            pulse.Change(Timeout.Infinite, Timeout.Infinite);
            foreach (var section in plan.Steps.GroupBy(s => s.Section))
                report.System[$"Elapsed.{section.Key}.seconds"] = section.Sum(s => s.ElapsedSeconds).ToString("F2", CultureInfo.InvariantCulture);
            report.System["NVIDIA telemetry after"] = Telemetry();
            if (isolated is not null)
                try { Directory.Delete(isolated, true); }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                { report.Summary.Add("Temporary GPU files could not be removed; they contain synthetic targets only."); }
            report.Finished = DateTimeOffset.UtcNow;
            report.System["Elapsed.total.seconds"] = clock.Elapsed.TotalSeconds.ToString("F2", CultureInfo.InvariantCulture);
            report.Summary.Add($"Total elapsed: {clock.Elapsed:mm\\:ss}. " + string.Join(", ", plan.Steps.GroupBy(s => s.Section).Select(g => $"{g.Key}: {g.Sum(s => s.ElapsedSeconds):F0} s")));
        }
        if (report.Measurements.Any(m => m.Correct && m.Speed > 0 || m.Section == "cpu" && !m.Correct && m.Variant.Length > 0))
        {
            try { PerformanceProfiles.Record(report, tool, devices, "detailed"); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            { report.Summary.Add("The report is available, but this computer's performance profile could not be saved."); }
        }
        return report;
    }

    private void CompleteSetup(DiagnosticReport report)
    {
        report.Setup = BenchmarkSetup.Lines(tool, settings, devices);
        report.Setup.Add("Detailed measurements exercise individual engines, variants and thread counts; each row records its actual execution settings. CPU correctness and path sweeps run independently of the recovery engine preference.");
        foreach (var row in report.Measurements.Where(r => r.Engine == "cpu" && !r.Details.ContainsKey("Engine")))
        {
            row.Details["Engine"] = $"built-in CPU engine, {row.Threads} threads, {row.Details.GetValueOrDefault("actual path", row.Variant)}";
            row.Details["hashcat arguments"] = "none";
            row.Details["CPU worker priority"] = NativeRunner.ThreadPriorityFor(settings.Priority).ToString();
            row.Details["Diagnostic override"] = "CPU variant and worker count measured independently of recovery engine preferences and extra arguments.";
        }
    }

    private async Task SystemAsync(HashcatTool? systemTool, DiagnosticReport report, CancellationToken ct, bool shortPlan = false)
    {
        report.System["RecoverKit version"] = PerformanceProfiles.AppVersion;
        report.System["Build configuration"] = PerformanceProfiles.BuildConfiguration;
        report.System[".NET runtime"] = Environment.Version.ToString();
        report.System["Native library API"] = NativeKernels.NativeApiVersion.ToString();
        report.System["OS"] = RuntimeInformation.OSDescription;
        report.System["Architecture"] = RuntimeInformation.ProcessArchitecture.ToString();
        report.System["CPU"] = SystemFacts.CpuName();
        CpuDiagnostics.AddSystemFacts(report, settings);
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
        report.System["NVIDIA telemetry before"] = shortPlan ? "Not measured, run the thorough test" : Telemetry();
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
        return devices.Where(d => d.IsGpu && !HashcatRunner.IsDisabled(settings, d) && active.Contains(GpuProfileSelection.FamilyKey(d.Key, devices))
            && HashcatRunner.ResolveGpu(settings, d, devices).Id == d.Id);
    }

    private void AddGpuSteps(DiagnosticPlan plan, HashcatTool local, DiagnosticReport report, CancellationToken ct)
    {
        var repeats = new List<(string Label, Func<Task> Run, Func<bool> Needed)>();
        foreach (int mode in Modes)
        {
            foreach (var dev in AllowedGpuDevices())
            foreach (bool pure in mode == 12500 && settings.OptimizedKernels ? new[] { false, true } : new[] { !settings.OptimizedKernels })
            {
                string label = $"Device {dev.Id} {dev.Backend}, mode {mode}, {(pure ? "pure" : "default")}";
                async Task Measure(int repeat)
                {
                    var clock = Stopwatch.StartNew();
                    var row = new DiagnosticMeasurement { Section = "gpu", Step = label, Mode = mode, Target = $"hashcat built-in example mode {mode}", Length = 0, Engine = "gpu", Variant = pure ? "pure" : "default", DeviceKey = dev.Key, Backend = dev.Backend, Repeat = repeat };
                    try
                    {
                        using var invocation = new BenchmarkSetup.Invocation(local);
                        if (mode is 17200 or 17210)
                        {
                            HashcatKernels.EnsureFor(local, mode);
                            row.Details["ZIP GPU kernel"] = HashcatKernels.Inspect(local.Directory) == HashcatKernels.State.Installed ? "replacement" : "hashcat original";
                        }
                        var args = new List<string> { pure ? "-B" : "-b", "-m", mode.ToString(), "-d", dev.Id.ToString(), "-w", settings.Workload.ToString(), "--potfile-disable", "--restore-disable", "--logfile-disable", "--session", "rk-diagnostic-bench" };
                        if (!Thorough) args.AddRange(["--runtime", "3"]);
                        args.AddRange(settings.ExtraArguments.Split(' ', StringSplitOptions.RemoveEmptyEntries).Where(a => a is not ("-O" or "--optimized-kernel-enable")));
                        using var tuning = Thorough ? null : DiagnosticGpuTuning.Apply(local, [dev]);
                        var (code, output, error) = await local.RunAsync(args, TimeSpan.FromSeconds(Thorough ? 240 : 45), ct: ct, priority: settings.Priority, redactOutput: true);
                        var parsed = ParseBenchmark(output + "\n" + error);
                        row.Speed = parsed.Speed;
                        foreach (var detail in parsed.Details) row.Details[detail.Key] = detail.Value;
                        // hashcat's benchmark uses its own self-test and optimized/pure example workload.
                        row.Correct = code == 0 && row.Speed > 0 && !Regex.IsMatch(output + error, "self-test.*(failed|error)", RegexOptions.IgnoreCase);
                        if (!row.Correct) row.Error = DiagnosticGpuError.Classify(output, error, code);
                        row.Details["Default"] = (!dev.IsSkippedAlias && pure == !settings.OptimizedKernels).ToString();
                        row.Details["Length source"] = "hashcat module benchmark metadata; not compared with CPU fixture rates";
                        var info = await local.ModeInfoAsync(mode, 3);
                        row.Length = pure ? info?.PureBenchmarkLength ?? 0 : info?.BenchmarkLength ?? 0;
                        bool optimized = !pure && info?.HasOptimizedKernel == true;
                        row.Details["Optimized"] = optimized.ToString();
                        if (!row.Details.ContainsKey("Kernel"))
                        {
                            row.Details["Kernel"] = optimized ? "optimized" : "pure";
                            row.Details["Kernel type source"] = "module capabilities and requested benchmark option";
                        }
                        row.Details["Comparability"] = "Benchmark rate only; never added to CPU fixture rates or used to choose CPU versus GPU.";
                        BenchmarkSetup.AddExecution(row.Details, settings, devices, invocation);
                    }
                    catch (Exception ex) when (ex is not OperationCanceledException && !ct.IsCancellationRequested) { row.Error = SafeError(ex); }
                    row.ElapsedSeconds = clock.Elapsed.TotalSeconds;
                    row.Details["Adaptive sampling"] = (!Thorough).ToString();
                    row.Details["Internally averaged benchmark"] = "True";
                    row.Details["Launch search"] = Thorough ? "Unrestricted" : "Compute-unit-scaled launch size; bounded loop blocks where the module allows them; automatic thread selection and self-test";
                    report.Measurements.Add(row);
                }
                plan.Add("gpu", label, 10, () => Measure(1));
                repeats.Add((label, () => Measure(2), () => Thorough || report.Measurements.Any(r => r.Section == "gpu" && r.Mode == mode && r.DeviceKey == dev.Key
                    && r.Variant == (pure ? "pure" : "default") && r.Details.GetValueOrDefault("Noisy") == "True")));
            }
            foreach (var repeat in repeats) plan.Add("gpu", repeat.Label + ", confirmation if noisy", 10, repeat.Run, repeat.Needed, conditional: !Thorough);
            repeats.Clear();
        }
    }

    internal static DiagnosticMeasurement ParseBenchmark(string output)
    {
        var row = new DiagnosticMeasurement();
        var speed = Regex.Match(output, @"Speed\.#\d+[^:]*:\s*([\d.]+)\s*([kMGT]?)H/s", RegexOptions.IgnoreCase);
        if (speed.Success && double.TryParse(speed.Groups[1].Value, NumberStyles.Float, CultureInfo.InvariantCulture, out double value))
            row.Speed = value * (speed.Groups[2].Value.ToUpperInvariant() switch { "K" => 1e3, "M" => 1e6, "G" => 1e9, "T" => 1e12, _ => 1 });
        var observed = Regex.Matches(output, @"Speed\.#\d+[^:]*:\s*([\d.]+)\s*([kMGT]?)H/s", RegexOptions.IgnoreCase)
            .Select(m => double.Parse(m.Groups[1].Value, CultureInfo.InvariantCulture) * (m.Groups[2].Value.ToUpperInvariant() switch { "K" => 1e3, "M" => 1e6, "G" => 1e9, "T" => 1e12, _ => 1 })).Where(v => v > 0).ToList();
        row.Details["Noisy"] = (observed.Count > 1 && observed.Max() / observed.Min() > 1.10).ToString();
        foreach (string key in new[] { "Accel", "Loops", "Thr", "Vec" })
        {
            var match = Regex.Match(output, $@"\b{key}:\s*(\d+)");
            if (match.Success) row.Details[key] = match.Groups[1].Value;
        }
        var kernel = Regex.Match(output, @"Kernel\.Feature[^:]*:\s*([^\r\n]+)");
        if (kernel.Success) row.Details["Kernel"] = kernel.Groups[1].Value.Trim();
        return row;
    }

    private void AddZipSteps(DiagnosticPlan plan, HashcatTool local, DiagnosticReport report, CancellationToken ct)
    {
        var samples = ComparisonZipSamples();
        var slots = Thorough ? AllowedGpuDevices() : HashcatRunner.ActiveGpus(settings, devices);
        foreach (var slot in slots)
        {
            BackendDevice Device(int mode)
            {
                if (Thorough) return slot;
                string family = GpuProfileSelection.FamilyKey(slot.Key, devices);
                var rows = report.Measurements.Where(r => r.Section == "gpu" && r.Mode == mode && GpuProfileSelection.FamilyKey(r.DeviceKey, devices) == family).ToList();
                var baseline = rows.FirstOrDefault(r => r.DeviceKey == slot.Key);
                var choice = baseline is null ? null : PerformanceProfiles.Choose(rows, baseline.Variant);
                return choice is { DeviceKeys.Count: 1 } ? devices.First(d => d.Key == choice.DeviceKeys[0]) : slot;
            }
            var checks = new Dictionary<(int Mode, string Variant), bool>();
            foreach (var mode in samples.GroupBy(s => s.Mode))
            foreach (string variant in mode.Key == 17230 ? new[] { "replacement" } : new[] { "hashcat", "replacement", "amplifier-cache" })
                plan.Add("zip", $"GPU family {slot.Id}, mode {mode.Key}, checking {variant}", 3, async () =>
                {
                    var device = Device(mode.Key);
                    bool correct = await GpuZipCorrectness.CheckAsync(local, device, mode.ToList(), variant, ct);
                    checks[(mode.Key, variant)] = correct;
                    foreach (var sample in mode)
                        report.Measurements.Add(new() { Section = "zip", Step = "Correctness", Mode = sample.Mode, Target = "synthetic ZIP " + sample.Label,
                            Length = 7, Engine = "gpu", Variant = variant, DeviceKey = device.Key, Backend = device.Backend, Correct = correct,
                            Error = correct ? null : "FAIL: GPU matches differ from scalar verification; timing skipped.", Details = new() { ["Check"] = correct ? "PASS" : "FAIL", ["Candidates"] = "Positive and negative candidates for each entry size in a batched GPU run" } });
                });
            foreach (var sample in samples)
            {
                var rows = new List<DiagnosticMeasurement>();
                async Task Measure(string variant, int repeat)
                {
                    var device = Device(sample.Mode);
                    var timer = Stopwatch.StartNew();
                    using var invocation = new BenchmarkSetup.Invocation(local);
                    double speed = await new ZipKernelBenchmark(local) { Seconds = Thorough ? Math.Max(6, Seconds) : Seconds, Mask = BenchmarkTestFiles.Mask, Charset1 = BenchmarkTestFiles.Charset, Priority = settings.Priority, Workload = settings.Workload, ExtraArguments = settings.ExtraArguments, BoundedTuning = !Thorough }.MeasureAsync(sample, device, variant, ct);
                    var row = new DiagnosticMeasurement { Section = "zip", Step = sample.Label, Mode = sample.Mode, Target = "synthetic ZIP " + sample.Label,
                        Length = 7, Engine = "gpu", Variant = variant, DeviceKey = device.Key, Backend = device.Backend, Repeat = repeat,
                        Speed = speed, ElapsedSeconds = timer.Elapsed.TotalSeconds, Correct = speed > 0, Error = speed > 0 ? null : "No benchmark rate reported.",
                        Details = ComparisonDetails(sample) };
                    BenchmarkSetup.AddExecution(row.Details, settings, devices, invocation);
                    rows.Add(row);
                    report.Measurements.Add(row);
                }
                foreach (int repeat in new[] { 1, 2 })
                foreach (string variant in sample.Mode == 17230 ? new[] { "replacement" } : new[] { "hashcat", "replacement", "amplifier-cache" })
                    plan.Add("zip", $"GPU family {slot.Id}, {sample.Label}, {variant}, sample {repeat}", Thorough ? 10 : 5,
                        () => Measure(variant, repeat), () => checks.GetValueOrDefault((sample.Mode, variant)) && (repeat == 1 || Thorough
                            || DiagnosticPlan.Contender(rows.FirstOrDefault(r => r.Variant == variant)?.Speed ?? 0, rows.Select(r => r.Speed))), conditional: !Thorough && repeat == 2);
            }
        }
    }

    internal static int[] HybridWorkers(IEnumerable<DiagnosticMeasurement> measurements, int mode, int limit)
    {
        var rows = measurements.Where(r => r.Section == "cpu" && r.Mode == mode && r.Correct && r.Speed > 0 && r.Error is null).ToList();
        int best = rows.OrderByDescending(r => r.Speed).FirstOrDefault()?.Threads ?? Math.Min(SystemFacts.PhysicalCores(), limit);
        int reserve = Math.Max(1, best - 1);
        return new[] { reserve, Math.Min(best, limit) }.Distinct().Take(2).ToArray();
    }

    internal static readonly int[] HybridModes = [9400, 13000, 17210, 12500, 13600, 22000, 29321, 29322, 29323, 29421, 29422, 29423];

    private void AddHybridSteps(DiagnosticPlan plan, HashcatTool local, DiagnosticReport report, CancellationToken ct)
    {
        int limit = settings.MaxCpuThreads > 0 ? settings.MaxCpuThreads : Environment.ProcessorCount;
        var physical = HashcatRunner.ActiveGpus(settings, devices);
        var allGroups = HybridBenchmarkDevices.Groups(settings, devices, 0, []);
        // Reserve current and preferred backends, each with/without integrated GPUs. Choices resolve after GPU timings.
        int groupSlots = allGroups.Count * 2;
        // RAR 3 shows how the GPU and the processor share its work (the GPU alone, the CPU alone, both).
        foreach (int mode in HybridModes)
        {
            List<List<BackendDevice>>? groups = null;
            string[]? mask = null;
            int[] workers = [];
            bool correct = false;
            plan.Add("hybrid", $"Mode {mode}, size jobs from measured rates", 1, async () =>
            {
                groups = HybridBenchmarkDevices.Groups(settings, devices, mode, report.Measurements);
                correct = (await CpuDiagnosticWorker.CheckAsync(mode, mode == 17210 ? PerformanceProfiles.DefaultZipVariant() : "default", ct)).Passed;
                workers = Thorough
                    ? new[] { Math.Max(1, SystemFacts.PhysicalCores() - 1), SystemFacts.PhysicalCores(), Math.Max(1, limit - 1), HybridRunner.CpuThreads(settings, physical, true) }.Select(n => Math.Min(n, limit)).Distinct().ToArray()
                    : HybridWorkers(report.Measurements, mode, limit);
                double cpu = report.Measurements.Where(r => r.Section == "cpu" && r.Mode == mode && r.Correct).Select(r => r.Speed).DefaultIfEmpty(0).Max();
                double gpu = report.Measurements.Where(r => r.Section == "gpu" && r.Mode == mode && r.Correct).Select(r => r.Speed).DefaultIfEmpty(0).Max();
                if (mode == 17210) gpu = report.Measurements.Where(r => r.Section == "zip" && r.Mode == mode && r.Target.Contains("17 bytes") && r.Correct).Select(r => r.Speed).DefaultIfEmpty(gpu).Max();
                if (cpu <= 0) cpu = NativeKernels.TryCreate(mode, NativeKernels.BenchmarkHashes[mode])?.SpeedHint * limit ?? 1000;
                if (gpu <= 0) gpu = cpu * 2;
                mask = Thorough && (mode is not (9400 or 13600 or 22000) && !TrueCryptSha512Kernel.SupportsMode(mode))
                    ? ["-a", "3", "-1", "ABCDEFGHIJKLMN", string.Concat(Enumerable.Repeat("?1", mode is 13000 or 12500 ? 5 : 9))]
                    : FiniteDiagnosticWorker.SizedMask(cpu + gpu, 12, mode == 22000 ? 8 : 1);
            });
            int workerSlots = Thorough ? 4 : 2;
            for (int groupIndex = 0; groupIndex < groupSlots; groupIndex++)
            {
                int gi = groupIndex;
                var rows = new List<DiagnosticMeasurement>();
                for (int repeat = 1; repeat <= 2; repeat++)
                for (int workerIndex = 0; workerIndex < workerSlots + 2; workerIndex++)
                {
                    if (workerIndex == 1 && !Thorough) continue;
                    int wi = workerIndex, rep = repeat;
                    int Count() => wi == 0 ? 0 : wi == 1 ? -1 : workers[wi - 2];
                    bool Available() => correct && groups is not null && gi < groups.Count && (wi < 2 || wi - 2 < workers.Length) && (wi != 1 || Thorough && gi == 0);
                    plan.Add("hybrid", $"Mode {mode}, GPU group {gi + 1}, option {wi + 1}, sample {rep}", Thorough ? 30 : 15, async () =>
                    {
                        var group = groups![gi];
                        int count = Count();
                        string engine = count == 0 ? "gpu" : count < 0 ? "cpu" : "hybrid";
                        var space = MaskSpace.FromHashcatArgs(mask!)!;
                        var result = await FiniteDiagnosticWorker.ExecuteAsync(local, settings, group, mode, count, space.MaxLength, limit, ct, mask, !Thorough, devices);
                        var row = new DiagnosticMeasurement { Section = "hybrid", Step = $"{engine}, {count} workers, group {gi + 1}", Mode = mode,
                            Target = "native synthetic fixture mode " + mode, Length = space.MaxLength, Engine = engine, Variant = count == 0 ? "gpu-default" : engine,
                            Threads = count < 0 ? limit : count, DeviceKey = count < 0 ? "" : string.Join(";", group.Select(d => d.Key)), Backend = count < 0 ? "" : string.Join(";", group.Select(d => d.Backend)),
                            Repeat = rep, Speed = result.Speed, Correct = result.Correct, Error = result.Error, ElapsedSeconds = result.ElapsedSeconds, Details = result.Details };
                        row.Details["Mask"] = string.Join(" ", mask!);
                        row.Details["Metric"] = "complete candidates / whole-job elapsed";
                        row.Details["Finite"] = "true";
                        row.Details["Adaptive sampling"] = (!Thorough).ToString();
                        bool hybridDefault = settings.HybridCpuGpu && ((mode is not (9400 or 13600 or 22000) && !TrueCryptSha512Kernel.SupportsMode(mode)) || settings.PerformanceStrategyExplicit
                            || physical.Any(d => !d.IsIntegratedGpu));
                        row.Details["Default"] = (gi == 0 && (hybridDefault ? count == HybridRunner.CpuThreads(settings, physical, true) : count == 0)).ToString();
                        rows.Add(row);
                        report.Measurements.Add(row);
                    }, () => Available() && (rep == 1 || Thorough || DiagnosticPlan.Contender(rows.FirstOrDefault(r => r.Engine == (Count() == 0 ? "gpu" : Count() < 0 ? "cpu" : "hybrid") && r.Threads == (Count() < 0 ? limit : Count()))?.Speed ?? 0, rows.Select(r => r.Speed))), conditional: !Thorough && (rep == 2 || gi > 0));
                }
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
