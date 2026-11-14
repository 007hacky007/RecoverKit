using System.ComponentModel;
using System.Net.Http;
using RecoverKit.Core.Hashcat;

namespace RecoverKit.Core.Dependencies;

/// <summary>The machine facts, the located hashcat and the evaluated dependency rows.</summary>
public sealed record DependencyScan(
    MachineFacts Facts,
    HashcatTool? Tool,
    string HashcatVersion,
    List<BackendDevice> Devices,
    IReadOnlyList<DependencyItem> Items)
{
    /// <summary>
    /// Looks at this machine (runs hashcat --version and -I, and nvidia-smi when present) and evaluates
    /// the rows. Never throws for machine problems; cancellation still propagates.
    /// </summary>
    public static async Task<DependencyScan> RunAsync(Settings settings, string? bundleCopyError = null, CancellationToken ct = default)
    {
        var tool = Probe(() => HashcatTool.Locate(settings.HashcatPath), null);
        string version = "";
        string? error = null;
        bool startTimedOut = false;
        List<BackendDevice>? devices = null;

        if (tool is not null)
        {
            try
            {
                version = await tool.VersionAsync(ct);
                if (string.IsNullOrWhiteSpace(version))
                    error = "hashcat did not report a version.";
                else
                    devices = await tool.DevicesAsync(ct);
            }
            catch (Exception ex) when (ex is TimeoutException or Win32Exception or InvalidOperationException or IOException or UnauthorizedAccessException)
            {
                error = ex is TimeoutException ? ex.Message : "hashcat could not run: " + ex.Message;
                startTimedOut = ex is HashcatStartTimeoutException;
                devices = null;
            }
        }

        bool isWindows = OperatingSystem.IsWindows();
        bool nvidia = Probe(() => NvidiaSmi.Locate(), null) is not null;

        var facts = new MachineFacts
        {
            IsWindows = isWindows,
            BundleAvailable = HashcatInstaller.BundledDirectory is not null,
            BundleCopyError = bundleCopyError,
            HashcatExe = tool?.Exe,
            HashcatIsManaged = tool?.IsManaged ?? false,
            HashcatRunsInPlace = tool?.IsInPlaceBundle ?? false,
            HashcatStartTimedOut = startTimedOut,
            HashcatVersion = tool is null ? null : version,
            HashcatError = error,
            Devices = devices,
            NvidiaDriverPresent = nvidia,
            NvidiaDriverCuda = nvidia && isWindows ? Probe(() => NvrtcRuntime.DriverCudaVersion(), null) : null,
            CudaFallbackReason = CudaFallback.Reason(devices),
            NvrtcTooNew = Probe(() => NvrtcRuntime.TooNewForDriver(NvrtcRuntime.Driver.Value), (IReadOnlyList<(string, (int, int))>)[]),
            NvrtcInstalled = Probe(() => NvrtcRuntime.Locate(), null) is not null,
            CpuRuntimeInstalled = Probe(() => CpuRuntime.Locate(), null) is not null,
            Elevated = Probe(() => CpuRuntime.IsElevatedProcess, false),
            Strategy = settings.Strategy,
            HashcatCpuWithGpu = settings.HashcatCpuWithGpu,
        };

        var items = DependencyCheck.Evaluate(facts);
        foreach (var i in items)
            DebugLog.Info($"Dependency {i.Name}: {i.Light}, action {i.Action}, pending {i.Pending}, {i.Reason}");
        return new DependencyScan(facts, tool, version, devices ?? [], items);
    }

    // An unreadable probe counts as "not present".
    private static T Probe<T>(Func<T> f, T fallback)
    {
        try { return f(); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or Win32Exception or InvalidOperationException or TimeoutException)
        {
            DebugLog.Warn("Dependency probe failed: " + ex.Message);
            return fallback;
        }
    }
}
