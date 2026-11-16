using System.Text.Json;
using RecoverKit.Core.Hashcat;
using RecoverKit.Core.Native;

namespace RecoverKit.Core.Diagnostics;

public static class ProfileSettings
{
    public static Settings ForAttack(Settings preferences, PerformanceProfile profile, IReadOnlyList<BackendDevice> devices, int mode, int length, string hashLine, double candidates = double.PositiveInfinity, bool maskAttack = true)
    {
        var execution = maskAttack ? PerformanceProfiles.Apply(PerformanceProfiles.ForMode(profile, mode, length, "execution"), preferences, devices) : null;
        // Retain the scheduler's CPU path for tiny jobs, except Office 2007 and PBKDF2 SHA-1 GPU-only choices.
        if (execution?.Engine is "gpu" or "hybrid" && NativeKernels.BenchmarkHashes.TryGetValue(mode, out var fixture)
            && (mode is not (9400 or 13600 or 22000) || execution.Engine != "gpu")
            && NativeKernels.TryCreate(mode, fixture) is { } kernel
            && candidates / Math.Max(1, kernel.SpeedHint * Environment.ProcessorCount) < preferences.GpuStartupByMode.GetValueOrDefault(mode, 15)) execution = null;
        var cpu = maskAttack ? PerformanceProfiles.Apply(PerformanceProfiles.ForMode(profile, mode, length, "cpu"), preferences, devices) : null;
        var gpu = GpuProfileSelection.ForAttack(profile, preferences, devices, mode, length);
        if (execution?.DeviceKeys is { Count: > 0 } executionKeys && gpu is not null
            && (!executionKeys.Order().SequenceEqual(gpu.DeviceKeys.Order()) || execution.Optimized is bool optimized && gpu.Optimized is bool gpuOptimized && optimized != gpuOptimized)) gpu = null;
        var zip = maskAttack && mode is 17200 or 17210 ? ZipDecision(profile, preferences, devices, mode, length, hashLine, execution ?? gpu) : null;
        bool failed = maskAttack && PerformanceProfiles.IsCpuVariantFailed(profile, mode, cpu?.Variant ?? (mode is 17200 or 17210 ? PerformanceProfiles.DefaultZipVariant() : "default"));
        if (failed)
        {
            execution = execution?.Engine is "cpu" or "hybrid" ? null : execution;
            cpu = null;
            if (mode is 17200 or 17210 && !PerformanceProfiles.IsCpuVariantFailed(profile, mode, "managed-scalar") && CpuDiagnostics.CheckZipVariant("managed-scalar").Passed)
                cpu = new PerformanceDecision { Domain = "cpu", Mode = mode, Length = length, Engine = "cpu", Variant = "managed-scalar", Threads = Environment.ProcessorCount, Reason = "failed CPU variant quarantined; checked managed scalar fallback" };
        }
        if (execution is null && cpu is null && gpu is null && zip is null && !failed) return preferences;
        var copy = Copy(preferences);
        if (failed && cpu is null) copy.UseNativeCpuEngine = false;
        copy.PerformanceChoice = execution;
        copy.CpuPerformanceChoice = cpu;
        copy.GpuPerformanceChoice = gpu;
        copy.ZipGpuPerformanceChoice = zip;
        return copy;
    }

    private static Settings Copy(Settings preferences)
    {
        var copy = JsonSerializer.Deserialize<Settings>(JsonSerializer.Serialize(preferences))!;
        copy.SessionsDir = preferences.SessionsDir;
        copy.KeyCachePath = preferences.KeyCachePath;
        copy.SpeedByMode = preferences.SpeedByMode;
        copy.GpuSpeedByMode = preferences.GpuSpeedByMode;
        copy.CpuSpeedByMode = preferences.CpuSpeedByMode;
        copy.GpuStartupByMode = preferences.GpuStartupByMode;
        copy.PerformanceChoice = preferences.PerformanceChoice;
        copy.CpuPerformanceChoice = preferences.CpuPerformanceChoice;
        copy.GpuPerformanceChoice = preferences.GpuPerformanceChoice;
        copy.ZipGpuPerformanceChoice = preferences.ZipGpuPerformanceChoice;
        return copy;
    }

    public static Settings PreserveResumeEngine(Settings settings, int mode, string directory, string session)
    {
        if (settings.PerformanceStrategyExplicit || settings.Strategy != DeviceStrategy.GpuOnly) return settings;
        string? engine = File.Exists(NativeRunner.RestoreFile(directory, session)) ? "cpu"
            : File.Exists(HybridRunner.RestoreFile(directory, session)) ? "hybrid"
            : File.Exists(HashcatRunner.RestoreFile(directory, session)) ? "gpu" : null;
        if (engine is null) return settings;
        var copy = Copy(settings);
        copy.PerformanceChoice = new PerformanceDecision { Domain = "execution", Mode = mode, Engine = engine,
            Threads = engine == "cpu" ? settings.MaxCpuThreads : engine == "hybrid" ? HybridRunner.CpuThreads(settings, null, true) : 0,
            Reason = "resuming the saved engine checkpoint" };
        return copy;
    }

    private static PerformanceDecision? ZipDecision(PerformanceProfile profile, Settings settings, IReadOnlyList<BackendDevice> devices, int mode, int length, string hashLine, PerformanceDecision? gpuChoice)
    {
        var fields = hashLine.Split('*');
        if (fields.Length < 6 || !int.TryParse(fields[4], System.Globalization.NumberStyles.HexNumber, System.Globalization.CultureInfo.InvariantCulture, out int encryptedSize)) return null;
        int size = Math.Max(0, encryptedSize - 12);
        string label = mode == 17210 ? size <= 64 ? "17 bytes" : size <= 1024 ? "453 bytes" : "4 KB" : size <= 4096 ? "1 KB" : "16 KB";
        var active = gpuChoice?.DeviceKeys is { Count: > 0 } keys ? devices.Where(d => keys.Contains(d.Key) && !HashcatRunner.IsDisabled(settings, d)).ToList() : HashcatRunner.ActiveGpus(settings, devices);
        if (active.Count != 1) return null;
        var choice = profile.Decisions.Where(d => d.Domain == "zip" && d.Mode == mode && d.Target.Contains(label, StringComparison.Ordinal)
                && ZipChecksMatch(d.Target, fields) && d.DeviceKeys.SequenceEqual(active.Select(device => device.Key)))
            .OrderByDescending(d => d.Length == length).ThenByDescending(d => d.Margin).FirstOrDefault();
        return PerformanceProfiles.Apply(choice, settings, devices);
    }

    private static bool ZipChecksMatch(string target, string[] fields)
    {
        if (target.Contains(", check2", StringComparison.Ordinal)) return fields[1] == "2";
        if (target.Contains(", check1", StringComparison.Ordinal)) return fields[1] == "1";
        if (fields.Length < 13) return !target.Contains(", crc", StringComparison.Ordinal);
        if (target.EndsWith(", crc-time", StringComparison.Ordinal)) return fields[11] != fields[12];
        if (target.EndsWith(", crc", StringComparison.Ordinal)) return fields[11] == fields[12];
        return true;
    }

    public static string Explain(Settings settings, IReadOnlyList<BackendDevice> devices, bool cpuOnly, bool hybrid)
    {
        string engine = cpuOnly ? "Built-in CPU" : hybrid ? "Hybrid CPU + GPU" : "hashcat GPU";
        int workers = cpuOnly ? settings.MaxCpuThreads > 0 ? settings.MaxCpuThreads : settings.PerformanceChoice?.Threads is > 0 ? settings.PerformanceChoice.Threads : settings.CpuPerformanceChoice?.Threads is > 0 ? settings.CpuPerformanceChoice.Threads : Environment.ProcessorCount
            : hybrid ? HybridRunner.CpuThreads(settings, devices, true) : 0;
        var detail = new List<string>();
        if (workers > 0) detail.Add($"{workers} CPU workers");
        if ((cpuOnly || hybrid) && settings.CpuPerformanceChoice is { } cpu && cpu.Mode != 29331) detail.Add($"CPU path {cpu.Variant} ({cpu.Reason})");
        if (settings.PerformanceChoice is { } choice) detail.Add(choice.Reason);
        if (!cpuOnly && settings.GpuPerformanceChoice is { } gpu) detail.Add(gpu.Reason);
        if (!cpuOnly && settings.ZipGpuPerformanceChoice is { } zip) detail.Add($"ZIP GPU kernel {zip.Variant} ({zip.Reason})");
        return $"Performance profile: {engine}" + (detail.Count > 0 ? ", " + string.Join("; ", detail) : "") + ".";
    }

    public static double EstimatedSpeed(Settings preferences, IReadOnlyList<BackendDevice> devices, int mode, int length = 7)
    {
        var profile = PerformanceProfiles.Load();
        var tool = HashcatTool.Locate(preferences.HashcatPath);
        PerformanceProfiles.Invalidate(profile, PerformanceProfiles.CpuFingerprint, PerformanceProfiles.GpuFingerprint(tool, devices));
        var execution = PerformanceProfiles.Apply(PerformanceProfiles.ForMode(profile, mode, length, "execution"), preferences, devices);
        if (execution is { Speed: > 0 }) return execution.Speed;
        if (HashcatRunner.ActiveGpus(preferences, devices).Count == 0 || preferences.Strategy == DeviceStrategy.CpuOnly)
        {
            var cpu = PerformanceProfiles.Apply(PerformanceProfiles.ForMode(profile, mode, length, "cpu"), preferences, devices);
            if (cpu is { Speed: > 0 }) return cpu.Speed;
        }
        return preferences.SpeedFor(mode);
    }

    public static IDisposable? CpuSelection(Settings s, int mode)
    {
        if (Math.Abs(mode) == 29331)
        {
            NativeKernels.ConfigureWhirlpool(s);
            return null; // Measured variants must not turn the experimental path on for recovery.
        }
        if (s.CpuPerformanceChoice is not { Variant: var variant } || !KernelVariants.Supported(mode, variant)) return null;
        if (mode is 17200 or 17210 && !string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("RECOVERKIT_ZIP_PATH"))) return null;
        if (mode == 9400 && !string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("RECOVERKIT_OFFICE2007_PATH"))) return null;
        if (mode is 13600 or 22000 && !string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("RECOVERKIT_PBKDF2_SHA1_PATH"))) return null;
        return KernelVariants.Select(mode, variant);
    }
}
