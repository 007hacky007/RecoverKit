using RecoverKit.Core.Hashcat;

namespace RecoverKit.Core.Dependencies;

/// <summary>Everything the decision needs to know about this machine, gathered elsewhere.</summary>
public sealed record MachineFacts
{
    public bool IsWindows { get; init; }
    public bool BundleAvailable { get; init; }
    public string? BundleCopyError { get; init; }
    public string? HashcatExe { get; init; }
    public bool HashcatIsManaged { get; init; }
    /// <summary>Raw output of <c>hashcat --version</c>.</summary>
    public string? HashcatVersion { get; init; }
    public string? HashcatError { get; init; }
    /// <summary>Null when hashcat could not run or was not found; empty when it ran and found no device.</summary>
    public IReadOnlyList<BackendDevice>? Devices { get; init; }
    public (int Major, int Minor)? NvidiaDriverCuda { get; init; }
    public bool NvidiaDriverPresent { get; init; }
    public bool NvrtcInstalled { get; init; }
    public bool CpuRuntimeInstalled { get; init; }
    public bool Elevated { get; init; }
    public DeviceStrategy Strategy { get; init; }
    public bool HashcatCpuWithGpu { get; init; }
}

/// <summary>Pure decision logic: which dependency lights are green, yellow or red.</summary>
public static class DependencyCheck
{
    public static IReadOnlyList<DependencyItem> Evaluate(MachineFacts f)
    {
        var items = new List<DependencyItem> { Hashcat(f) };
        if (f.IsWindows)
        {
            items.Add(Nvrtc(f));
            items.Add(Cpu(f));
        }
        return items;
    }

    public static bool ShouldShowAtStart(IReadOnlyList<DependencyItem> items, IReadOnlyCollection<string> skipped)
        => items.Any(i => i.Light == Light.Red
            || (i.Light == Light.Yellow && i.Installable && (i.SkipKey is null || !skipped.Contains(i.SkipKey))));

    private static DependencyItem Hashcat(MachineFacts f)
    {
        const string name = "hashcat";
        if (f.HashcatExe is null)
        {
            if (f.BundleAvailable)
                return new(DependencyId.Hashcat, name, Light.Red,
                    f.BundleCopyError ?? "hashcat is not installed; RecoverKit can copy its bundled hashcat.",
                    DependencyAction.CopyBundledHashcat);
            return new(DependencyId.Hashcat, name, Light.Red, HashcatInstaller.NoBundleMessage, DependencyAction.None);
        }
        if (!string.IsNullOrEmpty(f.HashcatError))
            return new(DependencyId.Hashcat, name, Light.Red, f.HashcatError, DependencyAction.None);

        var version = f.HashcatVersion ?? "";
        if (HashcatTool.IsOlderThanPinned(version) && !f.HashcatIsManaged)
        {
            var v = version.Trim();
            var reason = $"Your hashcat ({v}) is older than the {HashcatInstaller.Version} that comes with RecoverKit.";
            return f.BundleAvailable
                ? new(DependencyId.Hashcat, name, Light.Yellow, reason, DependencyAction.UseBundledHashcat,
                    SkipKey: $"hashcat|{f.HashcatExe}|{v}")
                : new(DependencyId.Hashcat, name, Light.Yellow, reason, DependencyAction.None);
        }
        return new(DependencyId.Hashcat, name, Light.Green, $"hashcat {version.Trim()} is ready.", DependencyAction.None);
    }

    private static bool IsNvidia(BackendDevice d)
        => d.Vendor.Contains("NVIDIA", StringComparison.OrdinalIgnoreCase)
           || d.Name.Contains("NVIDIA", StringComparison.OrdinalIgnoreCase);

    private static DependencyItem Pending(DependencyId id, string name)
        => new(id, name, Light.Yellow, "Waiting for hashcat to report its devices.", DependencyAction.None, Pending: true);

    private static DependencyItem Nvrtc(MachineFacts f)
    {
        const string name = "NVIDIA NVRTC";
        if (f.Devices is not { } devices) return Pending(DependencyId.Nvrtc, name);

        if (!devices.Any(IsNvidia) || devices.Any(d => d.Backend == "CUDA"))
            return new(DependencyId.Nvrtc, name, Light.Green, "Not needed.", DependencyAction.None);
        if (f.NvrtcInstalled)
            return new(DependencyId.Nvrtc, name, Light.Green, "The NVIDIA runtime is installed.", DependencyAction.None);
        if (f.Elevated)
            return new(DependencyId.Nvrtc, name, Light.Yellow,
                "NVIDIA GPUs would run faster with the CUDA runtime, but it cannot be installed while RecoverKit runs as administrator.",
                DependencyAction.None);
        var pkg = NvrtcRuntime.Choose(f.NvidiaDriverCuda);
        if (pkg is null)
            return new(DependencyId.Nvrtc, name, Light.Yellow,
                "NVIDIA GPUs would run faster with the CUDA runtime, but the installed driver is too old or unknown; update the NVIDIA driver.",
                DependencyAction.None);
        return new(DependencyId.Nvrtc, name, Light.Yellow,
            "NVIDIA GPUs run faster with the CUDA runtime, which RecoverKit can download.",
            DependencyAction.DownloadNvrtc, pkg.Size, NvrtcRuntime.LicenseName, NvrtcRuntime.LicenseUrl,
            $"nvrtc|{pkg.Version}", NvrtcPackage: pkg);
    }

    private static DependencyItem Cpu(MachineFacts f)
    {
        const string name = "Intel CPU runtime";
        if (f.Devices is not { } devices) return Pending(DependencyId.CpuRuntime, name);

        var usable = devices.Where(d => !d.IsSkippedAlias).ToList();
        bool hasCpu = usable.Any(d => d.Type.Contains("CPU", StringComparison.OrdinalIgnoreCase));
        var download = f.Elevated ? DependencyAction.None : DependencyAction.DownloadCpuRuntime;

        if (f.CpuRuntimeInstalled && !f.Elevated)
            return new(DependencyId.CpuRuntime, name, Light.Green, "The Intel CPU runtime is installed.", DependencyAction.None);
        if (usable.Count == 0)
            return new(DependencyId.CpuRuntime, name, Light.Red,
                "hashcat found no usable device; the Intel CPU runtime lets it run on the processor.",
                download, CpuRuntime.DownloadBytes, CpuRuntime.LicenseName, CpuRuntime.LicenseUrl);
        if (f.Strategy == DeviceStrategy.CpuOnly && !hasCpu)
            return new(DependencyId.CpuRuntime, name, Light.Red,
                "Your settings use only the CPU, but hashcat sees no CPU device; the Intel CPU runtime provides one.",
                download, CpuRuntime.DownloadBytes, CpuRuntime.LicenseName, CpuRuntime.LicenseUrl);
        if (f.HashcatCpuWithGpu && !hasCpu)
            return new(DependencyId.CpuRuntime, name, Light.Yellow,
                "hashcat is set to use the CPU alongside the GPU, but sees no CPU device; the Intel CPU runtime provides one.",
                download, CpuRuntime.DownloadBytes, CpuRuntime.LicenseName, CpuRuntime.LicenseUrl,
                $"cpu-runtime|{CpuRuntime.Version}");
        return new(DependencyId.CpuRuntime, name, Light.Green, "Not needed: a GPU driver is installed.", DependencyAction.None);
    }
}
