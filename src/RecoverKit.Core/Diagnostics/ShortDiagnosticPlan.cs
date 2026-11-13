using System.Diagnostics;
using System.Globalization;
using RecoverKit.Core.Hashcat;
using RecoverKit.Core.Native;

namespace RecoverKit.Core.Diagnostics;

public sealed partial class DetailedBenchmarkRunner
{
    public static double DefaultSectionSeconds(string section) => ShortBudgets.GetValueOrDefault(section);

    internal static Dictionary<string, double> ShortBudgets => new() { ["system"] = 8, ["cpu"] = 38, ["gpu"] = 39, ["zip"] = 20, ["hybrid"] = 10 };

    private async Task<DiagnosticReport> RunShortAsync(string[] selected, IProgress<DiagnosticProgress>? progress, CancellationToken ct)
    {
        var clock = Stopwatch.StartNew();
        var report = new DiagnosticReport { CpuPolicy = PerformanceProfiles.PolicyFingerprint(settings, "cpu"), GpuPolicy = PerformanceProfiles.PolicyFingerprint(settings, "gpu") };
        if (selected.Length == 0) { report.Finished = DateTimeOffset.UtcNow; return report; }
        var plan = new DiagnosticPlan { TotalBudget = TimeSpan.FromSeconds(115), SectionBudgets = ShortBudgets };
        report.Plan = plan.Steps;
        report.System["Test plan"] = "Default: 115 seconds for work, 5 seconds reserved for cleanup and profile storage";
        report.System["Section budgets (seconds)"] = string.Join(", ", ShortBudgets.Select(p => $"{p.Key}: {p.Value}"));
        HashcatTool? local = null;
        string? isolated = null;
        bool gpuAllowed = false;
        bool versionRead = false;
        var checks = new Dictionary<(int Mode, string Variant), bool>();
        List<IGrouping<string, BackendDevice>> Families() => AllowedGpuDevices().GroupBy(d => GpuProfileSelection.FamilyKey(d.Key, devices)).ToList();
        BackendDevice? Slot(int family, int backend) => Families().ElementAtOrDefault(family)?.OrderBy(d => d.IsSkippedAlias).ThenBy(d => d.Id).ElementAtOrDefault(backend);
        BackendDevice? Chosen(int family)
        {
            var first = Slot(family, 0);
            if (first is null) return null;
            return ShortBackendWinner(report.Measurements, Families()[family].ToList()) ?? first;
        }
        void Add(string section, string label, double seconds, Func<CancellationToken, Task> run, Func<bool>? needed = null)
        {
            if (selected.Contains(section)) plan.AddBounded(section, label, seconds, run, needed);
        }
        // The entire list, including conditional backend slots, exists before the first measurement.
        plan.AddBounded("system", "System facts and isolated engine preparation", 8, async token =>
        {
            if (tool is not null) { await tool.VersionAsync(token); versionRead = true; }
            await SystemAsync(null, report, token, shortPlan: true);
            if (tool is null || !selected.Any(s => s is "gpu" or "zip" or "hybrid")) return;
            isolated = Directory.CreateTempSubdirectory("rk-diagnostics-").FullName;
            await Task.Run(() => CopyEngine(tool.Directory, isolated, token), token);
            local = HashcatTool.Locate(Path.Combine(isolated, Path.GetFileName(tool.Exe)))!;
            local.MaxCpuThreads = settings.MaxCpuThreads;
            if (devices.Count == 0) devices = await local.DevicesAsync(token);
            if (devices.Count == 0)
            {
                var (code, output, error) = await local.RunAsync(["-I"], TimeSpan.FromSeconds(5), ct: token);
                devices = HashcatTool.ParseDevices(output + "\n" + error);
                if (devices.Count == 0) report.System["GPU availability"] = DiagnosticGpuError.Classify(output, error, code);
            }
            report.System["hashcat version"] = tool.FullVersion;
            foreach (var d in devices) report.System[$"Device {d.Id}"] = $"{d.Name}; {d.Backend}; driver {d.DriverVersion}; alias {d.AliasOf}; skipped {d.IsSkippedAlias}";
            gpuAllowed = HashcatRunner.ActiveGpus(settings, devices).Count > 0 && !settings.GpuTempGuard && settings.GpuDutyPercent == 100 && await PowerLimitSatisfiedAsync();
        });
        int threads = settings.MaxCpuThreads > 0 ? settings.MaxCpuThreads : Environment.ProcessorCount;
        var cpuModes = NativeKernels.BenchmarkHashes.Keys.Where(m => m > 0).ToList();
        foreach (int mode in cpuModes)
        foreach (var variant in KernelVariants.ForMode(mode).Where(v => v.Supported))
        {
            if (mode == 17200) continue; // A ZIP path check covers both stored and deflated vectors.
            Add("cpu", $"Correctness mode {mode}, {variant.Name}", 1, async token =>
            {
                var check = await CpuDiagnosticWorker.CheckAsync(mode, variant.Name, token);
                foreach (int checkedMode in mode == 17210 ? new[] { 17210, 17200 } : new[] { mode })
                {
                    checks[(checkedMode, variant.Name)] = check.Passed;
                    report.Measurements.Add(new() { Section = "cpu", Step = "Correctness", Mode = checkedMode, Engine = "cpu", Variant = variant.Name,
                        Correct = check.Passed, Error = check.Error, Details = new() { ["Cases"] = check.Cases.ToString(), ["Check"] = check.Passed ? "PASS" : "FAIL" } });
                }
            });
        }
        var confirmations = new List<(int Mode, string Variant, string Label, Func<CancellationToken, Task> Run)>();
        foreach (int mode in cpuModes.OrderByDescending(m => m is 17210 or 17200))
        {
            var variants = KernelVariants.ForMode(mode).Where(v => v.Supported).ToList();
            if (variants.Count < 2 && mode != 13000) continue;
            foreach (var variant in variants.OrderByDescending(v => v.Name == (mode is 17200 or 17210 ? PerformanceProfiles.DefaultZipVariant() : "default")))
            {
                async Task Measure(int repeat, CancellationToken token)
                {
                    var result = await CpuDiagnosticWorker.MeasureAsync(mode, variant.Name, threads, settings.Priority, repeat, token, 1);
                    report.Measurements.Add(new() { Section = "cpu", Step = "Short CPU window", Mode = mode, Target = $"native synthetic fixture mode {mode}", Length = 7,
                        Engine = "cpu", Variant = variant.Name, Threads = threads, Repeat = repeat, Correct = result.Check.Passed, Speed = result.Speed, Error = result.Error,
                        ElapsedSeconds = result.ElapsedSeconds, Details = new() { ["Short plan"] = "True", ["Selection"] = "Unconfirmed choices use automatic calibration" } });
                }
                string label = $"Mode {mode}, {variant.Name}, {threads} workers, 1-second window";
                Add("cpu", label, 2, token => Measure(1, token), () => checks.GetValueOrDefault((mode, variant.Name)));
                confirmations.Add((mode, variant.Name, label, token => Measure(2, token)));
            }
        }
        foreach (var confirmation in confirmations)
            Add("cpu", confirmation.Label + ", confirmation if useful", 2, confirmation.Run,
                () => NeedsConfirmation(report.Measurements, "cpu", confirmation.Mode, confirmation.Variant));
        for (int family = 0; family < 2; family++)
        foreach (int mode in new[] { 10500, 13000 })
        for (int backend = 0; backend < 3; backend++)
        {
            int f = family, b = backend;
            Add("gpu", $"GPU family {f + 1}, backend {b + 1}, representative mode {mode}", 5,
                async token => report.Measurements.Add(await ShortGpuAsync(local!, Slot(f, b)!, mode, "backend probe", token)),
                () => gpuAllowed && Slot(f, b) is not null && Slot(f, 1) is not null);
        }
        foreach (int mode in new[] { 17210, 12500, 13000, 10500, 9400 })
        for (int family = 0; family < 2; family++)
        {
            int f = family;
            Add("gpu", $"GPU family {f + 1}, chosen backend, main format {mode}", 5,
                async token => report.Measurements.Add(await ShortGpuAsync(local!, Chosen(f)!, mode, "chosen backend", token)),
                () => gpuAllowed && Chosen(f) is not null && !report.Measurements.Any(r => r.Section == "gpu" && r.Mode == mode && r.DeviceKey == Chosen(f)!.Key && r.Correct));
        }
        foreach (int repeat in new[] { 1, 2 })
        foreach (var sample in ZipKernelBenchmark.DefaultSamples().Where(s => s.Label.Contains("453") || s.Label.StartsWith("deflated, 1 KB")))
        foreach (string variant in new[] { "replacement", "hashcat" })
            Add("zip", $"{sample.Label}, {variant}, chosen backend", 4, async token =>
            {
                var dev = Chosen(0)!;
                bool correct = await GpuZipCorrectness.CheckAsync(local!, dev, sample, variant, token);
                double speed = correct ? await new ZipKernelBenchmark(local!) { Seconds = 1, Priority = settings.Priority, BoundedTuning = true }.MeasureAsync(sample, dev, variant, token) : 0;
                report.Measurements.Add(new() { Section = "zip", Step = sample.Label, Target = "synthetic ZIP " + sample.Label, Mode = sample.Mode, Length = 8,
                    Variant = variant, Engine = "gpu", DeviceKey = dev.Key, Backend = dev.Backend, Speed = speed, Correct = correct, Repeat = repeat,
                    Error = correct ? null : "GPU correctness failed", Details = new() { ["Selection"] = "Single short window; keep default unless confirmed by the thorough test" } });
            }, () => gpuAllowed && Chosen(0) is not null && (repeat == 1 || NeedsConfirmation(report.Measurements, "zip", sample.Mode, variant)));
        if (!selected.Contains("cpu"))
            foreach (int mode in new[] { 13000, 17210 })
                Add("hybrid", $"Correctness prerequisite mode {mode}", 1, async token =>
                {
                    string variant = mode == 17210 ? PerformanceProfiles.DefaultZipVariant() : "default";
                    checks[(mode, variant)] = (await CpuDiagnosticWorker.CheckAsync(mode, variant, token)).Passed;
                });
        foreach (int mode in new[] { 13000, 17210 })
        foreach (int option in new[] { -1, 0, 1 })
            Add("hybrid", $"Mode {mode}, {(option < 0 ? "CPU" : option == 0 ? "GPU" : "hybrid split")}, short finite check", 3, async token =>
            {
                var group = Enumerable.Range(0, 2).Select(Chosen).OfType<BackendDevice>().Select(d => CloneActive(d)).ToList();
                int workers = HybridWorkers(report.Measurements, mode, threads)[0];
                double cpu = report.Measurements.Where(r => r.Section == "cpu" && r.Mode == mode).Select(r => r.Speed).DefaultIfEmpty(1000).Max();
                double gpu = report.Measurements.Where(r => r.Section == "gpu" && r.Mode == mode).Select(r => r.Speed).DefaultIfEmpty(cpu * 2).Max();
                var mask = FiniteDiagnosticWorker.SizedMask(cpu + gpu, .5);
                var space = MaskSpace.FromHashcatArgs(mask)!;
                var result = await FiniteDiagnosticWorker.ExecuteAsync(local!, settings, group, mode, option < 1 ? option : workers, space.MaxLength, threads, token, mask, true, devices);
                report.Measurements.Add(new() { Section = "hybrid", Step = $"Short finite check, option {option}", Mode = mode, Target = "native synthetic fixture mode " + mode,
                    Length = space.MaxLength, Engine = option < 0 ? "cpu" : option == 0 ? "gpu" : "hybrid", Threads = option < 0 ? threads : option == 0 ? 0 : workers,
                    Speed = result.Speed, Correct = result.Correct, Error = result.Error, ElapsedSeconds = result.ElapsedSeconds, Repeat = 1, Details = result.Details });
            }, () => gpuAllowed && Chosen(0) is not null && checks.GetValueOrDefault((mode, mode == 17210 ? PerformanceProfiles.DefaultZipVariant() : "default")));
        void Update() => progress?.Report(plan.Progress(clock.Elapsed));
        using var pulse = new Timer(_ => Update(), null, 1000, 1000);
        try { await plan.RunAsync(report, Update, ct); }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { report.Cancelled = true; }
        finally
        {
            pulse.Change(Timeout.Infinite, Timeout.Infinite);
            if (isolated is not null) try { Directory.Delete(isolated, true); } catch (IOException) { }
        }
        report.Summary.Add("Default test: short windows within a two-minute limit. Unconfirmed choices use the existing automatic calibration before an attack (at most six seconds).");
        report.Summary.Add("Full backend/mode sweeps, pure kernels, repeats, worker sweeps and integrated-GPU whole-job comparisons: not measured, run the thorough test.");
        if (!gpuAllowed && selected.Any(s => s is "gpu" or "zip" or "hybrid"))
            report.Summary.Add("GPU work was not measured: no eligible GPU was detected or configured guard/power/duty limits prevented it.");
        if (versionRead && report.Measurements.Any(m => m.Correct && m.Speed > 0 || m.Section == "cpu" && !m.Correct && m.Variant.Length > 0))
        {
            try { PerformanceProfiles.Record(report, tool, devices, "detailed"); RecordShortBackends(report); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            { report.Summary.Add("The report is available, but this computer's performance profile could not be saved."); }
        }
        foreach (var section in plan.Steps.GroupBy(s => s.Section)) report.System[$"Elapsed.{section.Key}.seconds"] = section.Sum(s => s.ElapsedSeconds).ToString("F2", CultureInfo.InvariantCulture);
        report.System["Elapsed.total.seconds"] = clock.Elapsed.TotalSeconds.ToString("F2", CultureInfo.InvariantCulture);
        report.Finished = DateTimeOffset.UtcNow;
        report.Summary.Add($"Total elapsed: {clock.Elapsed:mm\\:ss}. " + string.Join(", ", plan.Steps.GroupBy(s => s.Section).Select(g => $"{g.Key}: {g.Sum(s => s.ElapsedSeconds):F1} s")));
        return report;
    }

    private static bool NeedsConfirmation(IEnumerable<DiagnosticMeasurement> measurements, string section, int mode, string variant)
    {
        var rows = measurements.Where(r => r.Section == section && r.Mode == mode && r.Correct && r.Speed > 0 && r.Error is null && r.Repeat == 1).ToList();
        string baseline = section == "zip" ? "replacement" : mode is 17200 or 17210 ? PerformanceProfiles.DefaultZipVariant() : "default";
        var current = rows.FirstOrDefault(r => r.Variant == baseline);
        var best = rows.OrderByDescending(r => r.Speed).FirstOrDefault();
        return current is not null && best is not null && best.Variant != baseline && best.Speed >= current.Speed * 1.10
            && (variant == best.Variant || variant == baseline);
    }

    private static BackendDevice CloneActive(BackendDevice d) => new() { Id = d.Id, Key = d.Key, Name = d.Name, Backend = d.Backend, Type = d.Type,
        Processors = d.Processors, AliasOf = d.AliasOf, DriverVersion = d.DriverVersion, BackendVersion = d.BackendVersion, Unified = d.Unified, IsSkippedAlias = false };

    internal static BackendDevice? ShortBackendWinner(IEnumerable<DiagnosticMeasurement> measurements, IReadOnlyList<BackendDevice> family)
    {
        var rows = measurements.Where(r => r.Step == "backend probe" && r.Correct && r.Speed > 0 && r.Error is null).ToList();
        var baseline = family.OrderBy(d => d.IsSkippedAlias).ThenBy(d => d.Id).First();
        foreach (var dev in family.Where(d => d.Key != baseline.Key))
            if (new[] { 10500, 13000 }.All(mode => rows.Any(r => r.Mode == mode && r.DeviceKey == baseline.Key)
                && rows.Any(r => r.Mode == mode && r.DeviceKey == dev.Key && r.Speed >= rows.Where(b => b.Mode == mode && b.DeviceKey == baseline.Key).Max(b => b.Speed) * 1.10))) return dev;
        return null;
    }

    private void RecordShortBackends(DiagnosticReport report)
    {
        var profile = PerformanceProfiles.Load();
        foreach (var family in AllowedGpuDevices().GroupBy(d => GpuProfileSelection.FamilyKey(d.Key, devices)))
        {
            var winner = ShortBackendWinner(report.Measurements, family.ToList());
            if (winner is null) continue;
            var decision = new PerformanceDecision { Domain = "gpu", Mode = 0, Scope = family.Key, Engine = "gpu", Variant = "representative backends",
                DeviceKeys = [winner.Key], Policy = report.GpuPolicy, Reason = "Backend won both representative modes by at least 10%; applied to other modes until measured separately" };
            profile.Decisions.RemoveAll(d => d.Domain == "gpu" && d.Mode == 0 && d.Scope == family.Key);
            profile.Decisions.Add(decision);
            report.Decisions.Add(decision);
            report.Summary.Add($"{winner.Name}: {winner.Backend}; {decision.Reason}.");
        }
        if (report.Decisions.Any(d => d.Mode == 0)) PerformanceProfiles.Save(profile);
    }

    private async Task<DiagnosticMeasurement> ShortGpuAsync(HashcatTool local, BackendDevice dev, int mode, string step, CancellationToken ct)
    {
        var timer = Stopwatch.StartNew();
        string hash = NativeKernels.BenchmarkHashes.GetValueOrDefault(mode) ?? (await local.ModeInfoAsync(mode, 3, ct))?.ExampleHash
            ?? throw new InvalidOperationException("No synthetic target available.");
        bool optimized = settings.OptimizedKernels && (await local.ModeInfoAsync(mode, 3, ct))?.HasOptimizedKernel == true;
        var sample = new ZipKernelBenchmark.Sample("native synthetic fixture mode " + mode, mode, hash);
        double speed = await new ZipKernelBenchmark(local) { Seconds = 1, Optimized = optimized, Mask = "?u?u?u?u?u?u?u", Priority = settings.Priority, BoundedTuning = true }.MeasureAsync(sample, dev, "replacement", ct);
        return new() { Section = "gpu", Step = step, Mode = mode, Target = sample.Label, Length = 7, Engine = "gpu", Variant = "default", DeviceKey = dev.Key, Backend = dev.Backend,
            Speed = speed, Correct = speed > 0, Repeat = 1, ElapsedSeconds = timer.Elapsed.TotalSeconds,
            Error = speed > 0 ? null : "No valid live rate within this window", Details = new() { ["Mask"] = "brute force, uppercase letters, length 7", ["Short plan"] = "True" } };
    }
}
