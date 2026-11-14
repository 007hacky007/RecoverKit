using System.Net.Http;
using RecoverKit.Core.Hashcat;

namespace RecoverKit.Core.Dependencies;

/// <summary>
/// Installs the dependency rows the user selected, one after another in dependency order.
/// <paramref name="updateSettings"/> applies and saves a settings change; the app passes one that runs it on
/// the UI thread, because installs run on a worker thread. Without it the change is applied in place.
/// </summary>
public sealed class DependencyInstaller(
    Settings settings,
    Func<DependencyItem, IProgress<InstallProgress>?, CancellationToken, Task>? run = null,
    Func<Action<Settings>, Task>? updateSettings = null)
{
    private readonly Func<DependencyItem, IProgress<InstallProgress>?, CancellationToken, Task> _run =
        run ?? DefaultRun(updateSettings ?? (change => { change(settings); settings.Save(); return Task.CompletedTask; }));

    public async Task<IReadOnlyList<(DependencyItem Item, Exception? Error)>> InstallAllAsync(
        IEnumerable<DependencyItem> items,
        IProgress<(DependencyItem Item, InstallProgress Progress)>? progress,
        CancellationToken ct)
    {
        var results = new List<(DependencyItem, Exception?)>();
        foreach (var item in items.Where(i => i.Installable).OrderBy(i => i.Id))
        {
            ct.ThrowIfCancellationRequested();
            DebugLog.Info($"Installing {item.Name} ({item.Action})");
            IProgress<InstallProgress>? p = progress is null ? null : new SyncProgress(item, progress);
            try
            {
                await _run(item, p, ct);
                DebugLog.Info($"Installed {item.Name}");
                results.Add((item, null));
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested)
            {
                var ex = new InstallException("The download timed out.");
                DebugLog.Error($"Installing {item.Name} failed", ex);
                results.Add((item, ex));
            }
            catch (Exception ex) when (ex is InstallException or IOException or HttpRequestException or UnauthorizedAccessException)
            {
                DebugLog.Error($"Installing {item.Name} failed", ex);
                results.Add((item, ex));
            }
        }
        return results;
    }

    private sealed class SyncProgress(DependencyItem item, IProgress<(DependencyItem Item, InstallProgress Progress)> target) : IProgress<InstallProgress>
    {
        public void Report(InstallProgress value) => target.Report((item, value));
    }

    /// <summary>Points the settings at the copy in the engines folder (the data folder is fixed per user).</summary>
    internal static void PointAtEnginesCopy(Settings s, string enginesExe) => s.HashcatPath = enginesExe;

    private static Func<DependencyItem, IProgress<InstallProgress>?, CancellationToken, Task> DefaultRun(Func<Action<Settings>, Task> updateSettings)
        => async (item, progress, ct) =>
        {
            switch (item.Action)
            {
                // The portable version runs its bundled hashcat in place: switching to it only clears the path.
                case DependencyAction.CopyBundledHashcat or DependencyAction.UseBundledHashcat when HashcatInstaller.InPlaceBundle is not null:
                    await updateSettings(s => s.HashcatPath = null);
                    progress?.Report(new InstallProgress { Stage = "done", Message = "Done." });
                    break;
                case DependencyAction.CopyBundledHashcat:
                {
                    var installer = new HashcatInstaller();
                    await installer.InstallAsync(progress, ct);
                    var exe = Path.Combine(installer.ExpectedDirectory, HashcatInstaller.ExeName);
                    await updateSettings(s =>
                    {
                        if (!string.IsNullOrEmpty(s.HashcatPath) && !File.Exists(s.HashcatPath)) PointAtEnginesCopy(s, exe);
                    });
                    break;
                }
                case DependencyAction.UseBundledHashcat:
                {
                    var installer = new HashcatInstaller();
                    bool copy = installer.BundleNeedsInstall();
                    if (copy) await installer.InstallAsync(progress, ct);
                    var exe = Path.Combine(installer.ExpectedDirectory, HashcatInstaller.ExeName);
                    await updateSettings(s => PointAtEnginesCopy(s, exe));
                    // The copy reports "done" itself; switching to a copy already in place needs its own report.
                    if (!copy) progress?.Report(new InstallProgress { Stage = "done", Message = "Done." });
                    break;
                }
                case DependencyAction.DownloadNvrtc:
                    await NvrtcRuntime.InstallAsync(item.NvrtcPackage!, progress, ct);
                    break;
                case DependencyAction.DownloadCpuRuntime:
                    await CpuRuntime.InstallAsync(progress, ct);
                    break;
            }
        };
}
