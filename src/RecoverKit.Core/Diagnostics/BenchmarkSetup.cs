using System.Globalization;
using RecoverKit.Core.Hashcat;
using RecoverKit.Core.Native;

namespace RecoverKit.Core.Diagnostics;

/// <summary>Shared benchmark metadata. Row arguments contain tuning and device flags only.</summary>
public static class BenchmarkSetup
{
    public const string ExtraPrefix = "Extra arguments: ";

    public sealed class Invocation : IDisposable
    {
        private readonly HashcatTool _tool;
        public IReadOnlyList<string> Arguments { get; private set; } = [];
        public Invocation(HashcatTool tool) { _tool = tool; tool.ArgumentsStarting += Capture; }
        private void Capture(IReadOnlyList<string> arguments)
        {
            if (arguments.Contains("-m") && !arguments.Contains("--hash-info") && !arguments.Contains("--keyspace")
                && (arguments.Contains("-b") || arguments.Contains("-B") || arguments.Contains("--session"))) Arguments = arguments.ToArray();
        }
        public void Dispose() => _tool.ArgumentsStarting -= Capture;
        public string Safe => SafeArguments(Arguments);
    }

    public static List<string> Lines(HashcatTool? tool, Settings settings, IReadOnlyList<BackendDevice> devices)
    {
        var lines = new List<string>
        {
            "RecoverKit version: " + PerformanceProfiles.AppVersion,
            "hashcat version: " + (tool?.FullVersion ?? "unavailable"),
            "CPU: " + SystemFacts.CpuName() + $"; {Environment.ProcessorCount} logical threads",
            "CPU features and native library: " + NativeKernels.CpuFeatures(),
            "NVIDIA backend preference: " + BackendName(settings.NvidiaBackend),
        };
        var active = HashcatRunner.ActiveGpus(settings, devices);
        foreach (var d in devices.Where(d => d.IsGpu))
        {
            var resolved = HashcatRunner.ResolveGpu(settings, d, devices);
            bool enabled = active.Any(a => a.Id == resolved.Id);
            if (OperatingSystem.IsMacOS() && devices.FirstOrDefault(m => m.IsMetal && (m.Id == resolved.Id || m.AliasOf == resolved.Id || resolved.AliasOf == m.Id)) is { } metal)
            {
                enabled = active.Any(a => a.Id == metal.Id || a.AliasOf == metal.Id || metal.AliasOf == a.Id);
                resolved = metal;
            }
            string state = HashcatRunner.IsDisabled(settings, d) ? "not used: unticked"
                : settings.Strategy == DeviceStrategy.CpuOnly ? "not used: CPU-only strategy"
                : HashcatRunner.IsAutomaticallyExcluded(settings, d, devices) ? "not used: automatically excluded integrated GPU beside a discrete GPU"
                : enabled ? $"selected: #{resolved.Id} {resolved.Backend}"
                : "not used: alias or performance-profile selection";
            if (resolved.Id != d.Id) state += $"; alias resolves to #{resolved.Id} {resolved.Backend}";
            lines.Add($"GPU #{d.Id} {d.Name}: {d.Backend}; {state}; driver {Known(d.DriverVersion)}; backend version {Known(d.BackendVersion)}");
        }
        if (!devices.Any(d => d.IsGpu)) lines.Add("GPU devices: none detected");
        if (OperatingSystem.IsMacOS()) lines.Add("macOS GPU runs use Metal; OpenDocument 1.1 (mode 18600) uses OpenCL. Each measurement records its actual format backend.");
        if (HashcatRunner.NvidiaBackendError(settings, devices) is { } backendError) lines.Add("Backend unavailable: " + backendError);
        if (settings.NvidiaBackend == NvidiaBackend.Automatic && CudaFallback.Reason(devices) is { } reason)
            lines.Add("Automatic CUDA fallback: " + reason);
        var nvidia = devices.Where(d => d.IsGpu && (d.Backend == "CUDA" || d.Vendor.Contains("NVIDIA", StringComparison.OrdinalIgnoreCase) || d.Name.Contains("NVIDIA", StringComparison.OrdinalIgnoreCase))).ToList();
        if (settings.NvidiaBackend == NvidiaBackend.Automatic)
            lines.Add("Automatic resolved to: " + (nvidia.Count == 0 ? "no NVIDIA GPU detected" : string.Join(", ", nvidia.Select(d => HashcatRunner.ResolveGpu(settings, d, devices).Backend).Distinct())));
        lines.Add("NVIDIA driver version: " + Known(string.Join(", ", nvidia.Select(d => d.DriverVersion).Where(v => v.Length > 0).Distinct())));
        lines.Add("CUDA version: " + Known(string.Join(", ", nvidia.Where(d => d.Backend == "CUDA").Select(d => d.BackendVersion).Where(v => v.Length > 0).Distinct())));
        lines.AddRange(ExecutionLines(settings));
        lines.Add($"Built-in CPU standalone threads: {(settings.MaxCpuThreads > 0 ? settings.MaxCpuThreads : settings.PerformanceChoice is { Engine: "cpu", Threads: > 0 } choice ? choice.Threads : settings.CpuPerformanceChoice?.Threads is > 0 ? settings.CpuPerformanceChoice.Threads : Environment.ProcessorCount)}; hybrid CPU threads: {HybridRunner.CpuThreads(settings, devices, hashcatRunning: true)}");
        lines.Add(ExtraPrefix + (string.IsNullOrWhiteSpace(settings.ExtraArguments) ? "none" : settings.ExtraArguments));
        if (!string.IsNullOrWhiteSpace(settings.ExtraArguments)) lines.Add("Extra arguments disable the built-in CPU engine and hybrid execution.");
        if (HashcatRunner.HasDeviceOverrides(settings.ExtraArguments)) lines.Add("Extra arguments override device selection; per-row hashcat arguments show the effective device flags.");
        return lines;
    }

    private static string BackendName(NvidiaBackend value) => value switch { NvidiaBackend.Cuda => "CUDA", NvidiaBackend.OpenCl => "OpenCL", _ => "Automatic" };

    private static string Known(string value) => value.Length == 0 ? "unknown" : value;

    public static List<string> ExecutionLines(Settings s)
    {
        var lines = new List<string>
        {
            $"Strategy: {s.Strategy}; hybrid: {s.HybridCpuGpu}; built-in CPU engine: {s.UseNativeCpuEngine}; hashcat CPU with GPU: {s.HashcatCpuWithGpu}",
            $"CPU threads: {(s.MaxCpuThreads > 0 ? s.MaxCpuThreads.ToString(CultureInfo.InvariantCulture) : $"automatic (up to {Environment.ProcessorCount})")}; workload: {s.Workload}; optimized kernels: {s.OptimizedKernels}; priority: {s.Priority}",
            $"GPU temperature guard: {(s.GpuTempGuard ? $"{s.GpuTempLimit} C, hysteresis {s.GpuTempHysteresis} C" : "off")}; duty: {s.GpuDutyPercent}%",
            "GPU power limit: " + (s.GpuPowerLimit ? s.GpuPowerWatts.Count == 0 ? "requested, no watt limits configured" : string.Join(", ", s.GpuPowerWatts.OrderBy(p => p.Key).Select(p => $"NVIDIA #{p.Key}: {p.Value} W")) : "off"),
        };
        if (OperatingSystem.IsMacOS()) lines.Add("macOS keeps the default process priority; built-in CPU worker priority: " + NativeRunner.ThreadPriorityFor(s.Priority));
        foreach (var (domain, choice) in new[] { ("execution", s.PerformanceChoice), ("CPU", s.CpuPerformanceChoice), ("GPU", s.GpuPerformanceChoice), ("ZIP GPU", s.ZipGpuPerformanceChoice) })
            if (choice is not null)
                lines.Add($"Performance profile {domain}: {choice.Engine}; variant {choice.Variant}; threads {choice.Threads}; devices {string.Join(", ", choice.DeviceKeys)}; optimized {choice.Optimized?.ToString() ?? "module default"}; {choice.Reason}");
        if (s.PerformanceChoice is null && s.CpuPerformanceChoice is null && s.GpuPerformanceChoice is null && s.ZipGpuPerformanceChoice is null)
            lines.Add("Performance profile: no measured override applied");
        return lines;
    }

    public static string Engine(Settings settings, IReadOnlyList<BackendDevice> devices, bool native, bool hybrid, int threads, string? path = null, IReadOnlyList<string>? arguments = null)
    {
        string cpu = $"built-in CPU engine, {threads} threads" + (string.IsNullOrEmpty(path) ? "" : ", " + path);
        if (native) return cpu;
        var selected = arguments is { Count: > 0 } ? SelectedDevices(arguments, devices) : HashcatRunner.ActiveGpus(settings, devices);
        var gpus = selected.Where(d => d.IsGpu).ToList();
        string gpu = string.Join(" + ", gpus.Select(d => $"#{d.Id} {d.Name} ({(arguments is { Count: > 0 } ? d.Backend : HashcatRunner.RunningBackend(settings, d, devices))})"));
        if (arguments is { Count: > 0 } && selected.Count == 0)
            return "hashcat, no matching device selected" + (hybrid ? " + " + cpu : "");
        bool hashcatCpu = selected.Any(d => d.Type.Contains("CPU", StringComparison.OrdinalIgnoreCase))
            || arguments is not { Count: > 0 } && !hybrid && (settings.Strategy == DeviceStrategy.CpuOnly || gpus.Count == 0 || settings.Strategy == DeviceStrategy.GpuAndCpu && settings.HashcatCpuWithGpu);
        string hashcat = "hashcat, " + (gpu.Length > 0 ? "GPU " + gpu + (hashcatCpu ? " + " : "") : "")
            + (hashcatCpu ? $"CPU (OpenCL), {(settings.MaxCpuThreads > 0 ? settings.MaxCpuThreads : Environment.ProcessorCount)} threads" : "");
        if (HashcatRunner.HasDeviceOverrides(settings.ExtraArguments)) hashcat += "; device selection overridden by extra arguments";
        return hybrid ? hashcat + " + " + cpu : hashcat;
    }

    public static void AddExecution(Dictionary<string, string> details, Settings settings, IReadOnlyList<BackendDevice> devices,
        Invocation? invocation, bool native = false, bool hybrid = false, int threads = 0, string? cpuPath = null)
    {
        details["Engine"] = Engine(settings, devices, native, hybrid, threads, cpuPath, invocation?.Arguments);
        details["Effective settings"] = string.Join("; ", ExecutionLines(settings));
        details["hashcat arguments"] = invocation?.Safe is { Length: > 0 } args ? args : "none";
        details["Argument scope"] = "Device and tuning flags only; targets, paths and unrecognized options omitted. Setup preserves configured extra arguments verbatim.";
        details["Extra arguments"] = string.IsNullOrWhiteSpace(settings.ExtraArguments) ? "none" : SafeArguments(settings.ExtraArguments.Split(' ', StringSplitOptions.RemoveEmptyEntries));
        if (invocation is { Arguments.Count: > 0 })
            details["Requested kernel"] = invocation.Arguments.Contains("-B") ? "pure"
                : invocation.Arguments.Contains("-O") ? "optimized"
                : invocation.Arguments.Contains("-b") ? "hashcat benchmark default (optimized where supported)" : "pure";
    }

    private static List<BackendDevice> SelectedDevices(IReadOnlyList<string> args, IReadOnlyList<BackendDevice> devices)
    {
        string? Last(string shortName, string longName)
        {
            string? value = null;
            for (int i = 0; i < args.Count; i++)
                if (args[i].StartsWith(longName + "=", StringComparison.Ordinal)) value = args[i][(longName.Length + 1)..];
                else if ((args[i] == shortName || args[i] == longName) && i + 1 < args.Count) value = args[++i];
                else if (args[i].StartsWith(shortName, StringComparison.Ordinal) && args[i].Length > shortName.Length
                    && args[i][shortName.Length..].All(c => char.IsAsciiDigit(c) || c == ',')) value = args[i][shortName.Length..];
            return value;
        }
        var available = devices.Where(d => !args.Contains("--backend-ignore-" + d.Backend.ToLowerInvariant())).OrderBy(d => d.Id).ToList();
        bool renumbered = available.Count != devices.Count;
        var ids = Last("-d", "--backend-devices")?.Split(',').Select(s => int.TryParse(s, out int id) ? id : -1).ToHashSet();
        var types = Last("-D", "--opencl-device-types")?.Split(',').ToHashSet();
        bool gpuDefault = available.Any(d => !d.IsSkippedAlias && d.IsGpu);
        return available.Where((d, i) => ids is not null ? ids.Contains(renumbered ? i + 1 : d.Id)
            : !d.IsSkippedAlias && (types is null ? !gpuDefault || d.IsGpu : types.Contains(d.IsGpu ? "2" : "1"))).ToList();
    }

    public static string SafeArguments(IEnumerable<string> arguments)
    {
        var args = arguments.ToList();
        var safe = new List<string>();
        var numeric = new HashSet<string> { "-m", "-a", "-w", "-d", "-D", "-n", "-u", "-T", "--backend-devices", "--opencl-device-types", "--opencl-platforms", "--workload-profile", "--kernel-accel", "--kernel-loops", "--kernel-threads", "--kernel-vector-width", "--backend-vector-width", "--scrypt-tmto", "--segment-size", "--bitmap-min", "--bitmap-max", "--runtime", "--status-timer", "--hwmon-temp-abort", "--spin-damp", "--nvidia-spin-damp" };
        var flags = new HashSet<string> { "-O", "-b", "-B", "--optimized-kernel-enable", "--machine-readable", "--quiet", "--force", "--backend-ignore-cuda", "--backend-ignore-opencl", "--backend-ignore-hip", "--backend-ignore-metal", "--backend-ignore-nvml", "--backend-ignore-adl", "--backend-ignore-adlx", "--backend-ignore-sysfs", "--self-test-disable", "--markov-disable", "--markov-classic", "--markov-inverse", "--slow-candidates", "--hwmon-disable", "--potfile-disable", "--restore-disable", "--logfile-disable", "--status", "--status-json", "--keep-guessing" };
        for (int i = 0; i < args.Count; i++)
        {
            string a = args[i];
            int equals = a.IndexOf('=');
            string name = equals >= 0 ? a[..equals] : a;
            if (flags.Contains(a)) safe.Add(a);
            else if (a.Length > 2 && numeric.Contains(a[..2]) && a[2..].All(c => char.IsAsciiDigit(c) || c is ',' or '.')) safe.Add(a);
            else if (numeric.Contains(name))
            {
                string? value = equals >= 0 ? a[(equals + 1)..] : i + 1 < args.Count ? args[++i] : null;
                if (value is { Length: > 0 } && value.All(c => char.IsAsciiDigit(c) || c is ',' or '.'))
                    safe.Add(equals >= 0 ? name + "=" + value : name + " " + value);
            }
        }
        return string.Join(" ", safe);
    }
}
