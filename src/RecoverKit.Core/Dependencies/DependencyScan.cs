using System.ComponentModel;
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
        var tool = HashcatTool.Locate(settings.HashcatPath);
        string version = "";
        string? error = null;
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
            catch (Exception ex) when (ex is TimeoutException or Win32Exception or InvalidOperationException)
            {
                error = ex.Message;
                devices = null;
            }
        }

        bool isWindows = OperatingSystem.IsWindows();
        bool nvidia = NvidiaSmi.Locate() is not null;

        var facts = new MachineFacts
        {
            IsWindows = isWindows,
            BundleAvailable = HashcatInstaller.BundledDirectory is not null,
            BundleCopyError = bundleCopyError,
            HashcatExe = tool?.Exe,
            HashcatIsManaged = tool?.IsManaged ?? false,
            HashcatVersion = tool is null ? null : version,
            HashcatError = error,
            Devices = devices,
            NvidiaDriverPresent = nvidia,
            NvidiaDriverCuda = nvidia && isWindows ? NvrtcRuntime.DriverCudaVersion() : null,
            NvrtcInstalled = NvrtcRuntime.Locate() is not null,
            CpuRuntimeInstalled = CpuRuntime.Locate() is not null,
            Elevated = CpuRuntime.IsElevatedProcess,
            Strategy = settings.Strategy,
            HashcatCpuWithGpu = settings.HashcatCpuWithGpu,
        };

        var items = DependencyCheck.Evaluate(facts);
        foreach (var i in items)
            DebugLog.Info($"Dependency {i.Name}: {i.Light}, action {i.Action}, pending {i.Pending}, {i.Reason}");
        return new DependencyScan(facts, tool, version, devices ?? [], items);
    }
}
