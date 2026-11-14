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
    /// <summary>The portable version's bundled hashcat, run where it is (always the pinned build).</summary>
    public bool HashcatRunsInPlace { get; init; }
    /// <summary>hashcat did not answer <c>--version</c> in time (it did not start at all).</summary>
    public bool HashcatStartTimedOut { get; init; }
    /// <summary>Raw output of <c>hashcat --version</c>.</summary>
    public string? HashcatVersion { get; init; }
    public string? HashcatError { get; init; }
    /// <summary>Null when hashcat could not run or was not found; empty when it ran and found no device.</summary>
    public IReadOnlyList<BackendDevice>? Devices { get; init; }
    public (int Major, int Minor)? NvidiaDriverCuda { get; init; }
    public bool NvidiaDriverPresent { get; init; }
    public bool NvrtcInstalled { get; init; }
    /// <summary>NVRTC copies on this PC (CUDA Toolkits) newer than the driver supports; hashcat does not see them.</summary>
    public IReadOnlyList<(string Directory, (int Major, int Minor) Version)> NvrtcTooNew { get; init; } = [];
    /// <summary>Why NVIDIA GPUs run through OpenCL after a CUDA kernel build failed, or null.</summary>
    public string? CudaFallbackReason { get; init; }
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
        const string pinnedName = "hashcat " + HashcatInstaller.Version;
        if (f.HashcatExe is null)
        {
            if (f.BundleAvailable)
                return new(DependencyId.Hashcat, pinnedName, Light.Red,
                    f.BundleCopyError ?? "hashcat is not installed; RecoverKit can copy its bundled hashcat.",
                    DependencyAction.CopyBundledHashcat);
            return new(DependencyId.Hashcat, pinnedName, Light.Red, HashcatInstaller.NoBundleMessage, DependencyAction.None);
        }
        if (!string.IsNullOrEmpty(f.HashcatError))
        {
            // RecoverKit's own copy did not start (antivirus, a stuck process, a damaged copy): repair it.
            if (f.HashcatStartTimedOut && f.BundleAvailable && f.HashcatIsManaged)
                return new(DependencyId.Hashcat, pinnedName, Light.Red,
                    f.HashcatError + " Repair stops stuck hashcat processes, copies hashcat again and, if it still does not start, moves it to another folder.",
                    DependencyAction.RepairHashcat);
            // A broken hashcat of the user's own (or an older managed copy) gives way to the bundled one.
            return f.BundleAvailable && !IsPinnedManagedCopy(f)
                ? new(DependencyId.Hashcat, pinnedName, Light.Red,
                    $"{f.HashcatError} RecoverKit can switch to the hashcat {HashcatInstaller.Version} it comes with.",
                    DependencyAction.UseBundledHashcat)
                : new(DependencyId.Hashcat, pinnedName, Light.Red, f.HashcatError, DependencyAction.None);
        }

        var version = f.HashcatVersion ?? "";
        var v = version.Trim();
        var name = HashcatTool.ParseVersion(v) is { } parsed ? $"hashcat {parsed.ToString(3)}" : pinnedName;
        bool older = HashcatTool.IsOlderThanPinned(version);
        // The bundle copy failed and only an older copy (an earlier RecoverKit's, or the user's) is left.
        if (older && f.BundleAvailable && f.BundleCopyError is { Length: > 0 } copyError)
            return new(DependencyId.Hashcat, pinnedName, Light.Red, copyError, DependencyAction.CopyBundledHashcat);
        if (older && !f.HashcatIsManaged)
        {
            var reason = $"Your hashcat ({v}) is older than the {HashcatInstaller.Version} that comes with RecoverKit.";
            return f.BundleAvailable
                ? new(DependencyId.Hashcat, name, Light.Yellow, reason, DependencyAction.UseBundledHashcat,
                    SkipKey: $"hashcat|{f.HashcatExe}|{v}")
                : new(DependencyId.Hashcat, name, Light.Yellow,
                    reason + $" Install hashcat {HashcatInstaller.Version}, or set its location in Preferences > Files and Paths.",
                    DependencyAction.None);
        }
        return new(DependencyId.Hashcat, name, Light.Green, $"hashcat {v} is ready.", DependencyAction.None);
    }

    /// <summary>The exe sits in the engines folder's hashcat-&lt;pinned version&gt; copy (either path separator).</summary>
    private static bool IsPinnedManagedCopy(MachineFacts f)
    {
        if (!f.HashcatIsManaged || f.HashcatExe is null) return false;
        if (f.HashcatRunsInPlace) return true;
        var parts = f.HashcatExe.Split('/', '\\');
        return parts.Length >= 2 && parts[^2] == "hashcat-" + HashcatInstaller.Version;
    }

    private static bool IsNvidia(BackendDevice d)
        => d.Vendor.Contains("NVIDIA", StringComparison.OrdinalIgnoreCase)
           || d.Name.Contains("NVIDIA", StringComparison.OrdinalIgnoreCase);

    private static DependencyItem Pending(DependencyId id, string name)
        => new(id, name, Light.Yellow, "Waiting for hashcat to report its devices.", DependencyAction.None, Pending: true);

    private static DependencyItem Nvrtc(MachineFacts f)
    {
        const string name = "NVIDIA CUDA compiler (NVRTC)";
        if (f.Devices is not { } devices) return Pending(DependencyId.Nvrtc, name);

        string switched = f.CudaFallbackReason is { Length: > 0 } why
            ? $"CUDA could not build hashcat's kernel ({why}), so NVIDIA GPUs run through OpenCL. "
            : "";
        if (switched.Length == 0 && (!devices.Any(IsNvidia) || devices.Any(d => d.Backend == "CUDA")))
            return new(DependencyId.Nvrtc, name, Light.Green, "Not needed.", DependencyAction.None);
        if (f.NvrtcInstalled && switched.Length > 0)
            return new(DependencyId.Nvrtc, name, Light.Yellow,
                switched + "RecoverKit's CUDA compiler is installed but did not help: update the NVIDIA driver. CUDA is tried again after a driver or RecoverKit update.",
                DependencyAction.None);
        if (f.NvrtcInstalled)
            return new(DependencyId.Nvrtc, name, Light.Green, "The NVIDIA runtime is installed.", DependencyAction.None);
        // A CUDA Toolkit newer than the driver: its compiler produces code the driver rejects, so RecoverKit
        // keeps it away from hashcat, which then runs the NVIDIA GPU through OpenCL.
        string tooNew = f.NvrtcTooNew is [var first, ..] && f.NvidiaDriverCuda is { } drv
            ? $"The CUDA compiler of the CUDA Toolkit {first.Version.Major}.{first.Version.Minor} on this PC ({first.Directory}) is newer than the NVIDIA driver supports " +
              $"(CUDA {drv.Major}.{drv.Minor}), so hashcat cannot use it and runs the NVIDIA GPU through OpenCL. Update the NVIDIA driver, or: "
            : "";
        var pkg = NvrtcRuntime.Choose(f.NvidiaDriverCuda);
        var versioned = pkg is null ? name : $"NVIDIA CUDA compiler (NVRTC {pkg.Version})";
        if (f.Elevated)
            return new(DependencyId.Nvrtc, versioned, Light.Yellow,
                switched + "NVIDIA GPUs would run faster with the CUDA runtime, but it cannot be installed while RecoverKit runs as administrator.",
                DependencyAction.None);
        if (pkg is null)
            return new(DependencyId.Nvrtc, name, Light.Yellow,
                switched + "NVIDIA GPUs would run faster with the CUDA runtime, but the installed driver is too old or unknown; update the NVIDIA driver.",
                DependencyAction.None);
        return new(DependencyId.Nvrtc, versioned, Light.Yellow,
            switched + tooNew + "NVIDIA GPUs run faster with the CUDA runtime, which RecoverKit can download.",
            DependencyAction.DownloadNvrtc, pkg.Size, NvrtcRuntime.LicenseName, NvrtcRuntime.LicenseUrl,
            $"nvrtc|{pkg.Version}", NvrtcPackage: pkg);
    }

    internal const string ElevatedCpuReason =
        "Start RecoverKit normally (not as administrator) to use the processor: Windows does not let an administrator process load the per-user CPU runtime.";

    private static DependencyItem Cpu(MachineFacts f)
    {
        const string name = "CPU runtime (OpenCL) " + CpuRuntime.Version;
        if (f.Devices is not { } devices) return Pending(DependencyId.CpuRuntime, name);

        var usable = devices.Where(d => !d.IsSkippedAlias).ToList();
        bool hasCpu = usable.Any(d => d.Type.Contains("CPU", StringComparison.OrdinalIgnoreCase));

        // An administrator process ignores the per-user runtime: say so instead of offering an install it would not use.
        DependencyItem Need(Light light, string reason, string? skipKey = null) => f.Elevated
            ? new(DependencyId.CpuRuntime, name, light, ElevatedCpuReason, DependencyAction.None)
            : new(DependencyId.CpuRuntime, name, light, reason, DependencyAction.DownloadCpuRuntime,
                CpuRuntime.DownloadBytes, CpuRuntime.LicenseName, CpuRuntime.LicenseUrl, skipKey);

        if (f.CpuRuntimeInstalled && !f.Elevated)
            return new(DependencyId.CpuRuntime, name, Light.Green, "The Intel CPU runtime is installed.", DependencyAction.None);
        if (usable.Count == 0)
            return Need(Light.Red, "hashcat found no usable device; the Intel CPU runtime lets it run on the processor.");
        if (f.Strategy == DeviceStrategy.CpuOnly && !hasCpu)
            return Need(Light.Red, "Your settings use only the CPU, but hashcat sees no CPU device; the Intel CPU runtime provides one.");
        if (f.HashcatCpuWithGpu && !hasCpu)
            return Need(Light.Yellow,
                "hashcat is set to use the CPU alongside the GPU, but sees no CPU device; the Intel CPU runtime provides one.",
                $"cpu-runtime|{CpuRuntime.Version}");
        return new(DependencyId.CpuRuntime, name, Light.Green, "Not needed: a GPU driver is installed.", DependencyAction.None);
    }
}
