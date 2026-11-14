using System.Diagnostics;

namespace RecoverKit.Core.Hashcat;

/// <summary>
/// Repairs a hashcat that RecoverKit placed itself and that does not start (<c>--version</c> does not
/// answer): stops leftover hashcat processes from its folder, copies the bundled hashcat again, and,
/// when the fresh copy still hangs while the bundled one starts, puts hashcat in another folder.
/// Antivirus software that holds programs in some folders (AppData, Downloads) is the usual cause.
/// </summary>
public static class HashcatRepair
{
    /// <summary>Returns the hashcat executable to use from now on, or throws <see cref="InstallException"/>.</summary>
    public static Task<string> RepairAsync(string? configured, IProgress<InstallProgress>? progress, CancellationToken ct)
        => RepairAsync(new Environment(configured), progress, ct);

    internal sealed record Environment(string? Configured)
    {
        public string? Bundle { get; init; } = HashcatInstaller.BundledDirectory;
        public bool InPlace { get; init; } = HashcatInstaller.InPlaceBundle is not null;
        public HashcatInstaller Engines { get; init; } = new();
        /// <summary>Further folders that receive a copy when the usual one is held, in order of preference.</summary>
        public IReadOnlyList<string> Alternatives { get; init; } = DefaultAlternatives();
        public Func<string, CancellationToken, Task<bool>> Starts { get; init; } = StartsAsync;
        public Action<string> StopProcesses { get; init; } = StopHashcatIn;
        public Func<string?, string?> Current { get; init; } = path => HashcatTool.Locate(path)?.Exe;
    }

    internal static async Task<string> RepairAsync(Environment env, IProgress<InstallProgress>? progress, CancellationToken ct)
    {
        void Say(string text) { DebugLog.Info("hashcat repair: " + text); progress?.Report(new InstallProgress { Stage = "repair", Message = text }); }
        var bundle = env.Bundle ?? throw new InstallException(HashcatInstaller.NoBundleMessage);
        string bundleExe = Path.Combine(bundle, HashcatInstaller.ExeName);

        if (env.Current(env.Configured) is { } current && Path.GetDirectoryName(current) is { } currentDir)
        {
            Say("Stopping hashcat processes left from earlier attempts...");
            env.StopProcesses(currentDir);
        }

        if (!env.InPlace)
        {
            Say($"Copying hashcat {HashcatInstaller.Version} again...");
            try
            {
                var result = await Task.Run(() => env.Engines.CopyBundle(bundle, progress, ct), ct);
                Say("Checking that hashcat starts...");
                if (await env.Starts(result.ExecutablePath!, ct)) return result.ExecutablePath!;
            }
            // A file of the old copy that cannot be replaced (still held by a scanner) leaves the other folders.
            catch (InstallException ex) { DebugLog.Warn("hashcat repair: copying again failed: " + ex.Message); }
        }

        Say("Checking whether hashcat starts from RecoverKit's own folder...");
        bool bundleStarts = await env.Starts(bundleExe, ct);
        if (bundleStarts && env.InPlace) return bundleExe;
        if (!bundleStarts)
            throw new InstallException(
                $"hashcat does not start even from RecoverKit's own folder ({bundle}), so antivirus software is probably blocking it. " +
                "In Windows Security open Virus & threat protection > Protection history (or your antivirus's quarantine), allow hashcat, then click Check again.");

        // The bundled hashcat starts but the copy does not: the folder of the copy is the problem.
        foreach (var root in env.Alternatives)
        {
            ct.ThrowIfCancellationRequested();
            HashcatInstallResult copy;
            try
            {
                Say($"Copying hashcat to {root}...");
                copy = await Task.Run(() => new HashcatInstaller(root).CopyBundle(bundle, progress, ct), ct);
            }
            catch (Exception ex) when (ex is InstallException or IOException or UnauthorizedAccessException)
            {
                DebugLog.Warn($"hashcat repair: cannot use {root}: {ex.Message}");
                continue;
            }
            Say("Checking that hashcat starts...");
            if (await env.Starts(copy.ExecutablePath!, ct)) return copy.ExecutablePath!;
        }
        throw new InstallException(
            "hashcat starts from RecoverKit's own folder but not from any folder it can be copied to. Antivirus software is probably holding it: " +
            "allow hashcat in your antivirus, or copy the hashcat folder to a folder of your choice and set it in Preferences > Files and Paths.");
    }

    internal static IReadOnlyList<string> DefaultAlternatives()
    {
        if (!OperatingSystem.IsWindows()) return [];
        var list = new List<string>();
        // Outside AppData and Downloads, where antivirus software holds unknown programs most often.
        if (Path.GetPathRoot(System.Environment.SystemDirectory) is { Length: > 0 } drive) list.Add(Path.Combine(drive, "RecoverKit"));
        var profile = System.Environment.GetFolderPath(System.Environment.SpecialFolder.UserProfile);
        if (profile.Length > 0) list.Add(Path.Combine(profile, "RecoverKit"));
        return list;
    }

    private static async Task<bool> StartsAsync(string exe, CancellationToken ct)
    {
        try { return (await HashcatTool.ForExe(exe).RunAsync(["--version"], HashcatTool.VersionTimeout, ct: ct)).Out.TrimStart().StartsWith('v'); }
        catch (Exception ex) when (ex is TimeoutException or System.ComponentModel.Win32Exception or InvalidOperationException or IOException or UnauthorizedAccessException)
        {
            DebugLog.Warn($"hashcat repair: {exe} did not start: {ex.Message}");
            return false;
        }
    }

    private static void StopHashcatIn(string folder)
    {
        foreach (var p in Process.GetProcessesByName("hashcat"))
        {
            using (p)
            {
                try
                {
                    if (p.MainModule?.FileName is { } file && HashcatTool.IsInside(file, folder))
                    {
                        DebugLog.Info($"hashcat repair: stopping hashcat process {p.Id}");
                        p.Kill(true);
                    }
                }
                catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception or NotSupportedException) { }
            }
        }
    }
}
