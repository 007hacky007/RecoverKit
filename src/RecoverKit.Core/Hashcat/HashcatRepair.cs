using System.Diagnostics;

namespace RecoverKit.Core.Hashcat;

/// <summary>A question Repair asks before a step that changes something on the computer.</summary>
public sealed record RepairQuestion(string Title, string Text, string Accept, string Decline);

/// <summary>
/// Repairs a hashcat that RecoverKit placed itself and that does not start (<c>--version</c> does not
/// answer): stops leftover hashcat processes from its folder, copies the bundled hashcat again, and,
/// when the fresh copy still hangs while the bundled one starts, offers to put hashcat in another folder
/// and to remove the old copy. Antivirus software that holds programs in some folders (AppData,
/// Downloads) is the usual cause. Every step that changes something is explained and asked first.
/// </summary>
public static class HashcatRepair
{
    /// <summary>
    /// Returns the hashcat executable to use from now on, or throws <see cref="InstallException"/>.
    /// <paramref name="ask"/> shows a question and returns true when the user agrees; without it Repair
    /// only does what the user already chose by clicking Repair and never moves or removes hashcat.
    /// </summary>
    public static Task<string> RepairAsync(string? configured, IProgress<InstallProgress>? progress, CancellationToken ct,
        Func<RepairQuestion, CancellationToken, Task<bool>>? ask = null)
        => RepairAsync(new Environment(configured) { Ask = ask }, progress, ct);

    internal sealed record Environment(string? Configured)
    {
        public string? Bundle { get; init; } = HashcatInstaller.BundledDirectory;
        public bool InPlace { get; init; } = HashcatInstaller.InPlaceBundle is not null;
        public HashcatInstaller Engines { get; init; } = new();
        /// <summary>Further folders that receive a copy when the usual one is held, in order of preference.</summary>
        public IReadOnlyList<string> Alternatives { get; init; } = DefaultAlternatives();
        public Func<string, CancellationToken, Task<bool>> Starts { get; init; } = StartsAsync;
        public Action<string> StopProcesses { get; init; } = StopHashcatIn;
        public Func<string, int> RunningIn { get; init; } = CountHashcatIn;
        public Func<string?, string?> Current { get; init; } = path => HashcatTool.Locate(path)?.Exe;
        public Func<RepairQuestion, CancellationToken, Task<bool>>? Ask { get; init; }
    }

    internal const string Title = "Repair hashcat";

    internal static async Task<string> RepairAsync(Environment env, IProgress<InstallProgress>? progress, CancellationToken ct)
    {
        void Say(string text) { DebugLog.Info("hashcat repair: " + text); progress?.Report(new InstallProgress { Stage = "repair", Message = text }); }
        var bundle = env.Bundle ?? throw new InstallException(HashcatInstaller.NoBundleMessage);
        string bundleExe = Path.Combine(bundle, HashcatInstaller.ExeName);
        string? currentDir = env.Current(env.Configured) is { } current ? Path.GetDirectoryName(current) : null;
        string target = env.Engines.ExpectedDirectory;

        if (env.Ask is { } ask && !await ask(new(Title, Plan(env, bundle, currentDir), "Repair", "Cancel"), ct))
            throw new InstallException("Repair was cancelled. Nothing was changed.");

        if (currentDir is not null)
        {
            Say("Stopping hashcat programs left from earlier attempts...");
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
        string allowInstead = "allow hashcat in your antivirus (in Windows Security: Virus & threat protection > Protection history), then click Check again";
        foreach (var root in env.Alternatives)
        {
            ct.ThrowIfCancellationRequested();
            string folder = new HashcatInstaller(root).ExpectedDirectory;
            if (env.Ask is not { } askMove || !await askMove(new(Title, MoveQuestion(target, bundle, folder), "Use this folder", "Cancel"), ct))
                throw new InstallException(
                    $"hashcat was copied again to {target} but still does not start there, and it was not moved. Nothing else was changed. " +
                    $"To fix it, {allowInstead}, or click Repair again and let RecoverKit use another folder.");
            HashcatInstallResult copy;
            try
            {
                Say($"Copying hashcat to {folder}...");
                copy = await Task.Run(() => new HashcatInstaller(root).CopyBundle(bundle, progress, ct), ct);
            }
            catch (Exception ex) when (ex is InstallException or IOException or UnauthorizedAccessException)
            {
                DebugLog.Warn($"hashcat repair: cannot use {root}: {ex.Message}");
                Say($"Could not copy hashcat to {folder}: {ex.Message}");
                continue;
            }
            Say("Checking that hashcat starts...");
            if (!await env.Starts(copy.ExecutablePath!, ct))
            {
                Say($"hashcat does not start from {folder} either.");
                continue;
            }
            await OfferCleanupAsync(env, target, folder, Say, ct);
            return copy.ExecutablePath!;
        }
        throw new InstallException(
            "hashcat starts from RecoverKit's own folder but not from any folder it can be copied to. Antivirus software is probably holding it: " +
            $"{allowInstead}, or copy the hashcat folder to a folder of your choice and set it in Preferences > Files and Paths.");
    }

    /// <summary>The first question: what Repair is about to do, with the folders involved.</summary>
    internal static string Plan(Environment env, string bundle, string? currentDir)
    {
        var steps = new List<string>();
        if (currentDir is not null)
        {
            int running = env.RunningIn(currentDir);
            steps.Add(running switch
            {
                0 => $"Stop any hashcat program still running from {currentDir} (none is running now).",
                1 => $"Stop the hashcat program still running from {currentDir}. It is left from an earlier attempt and does not answer.",
                _ => $"Stop the {running} hashcat programs still running from {currentDir}. They are left from earlier attempts and do not answer.",
            });
        }
        if (env.InPlace)
            steps.Add($"Check whether hashcat starts from RecoverKit's own folder ({bundle}).");
        else
        {
            steps.Add($"Copy hashcat {HashcatInstaller.Version} ({SizeOf(bundle)}) from RecoverKit's own folder to {env.Engines.ExpectedDirectory} again, replacing the files there.");
            steps.Add("Check that the new copy starts.");
        }
        var text = "hashcat does not start, so RecoverKit cannot check passwords. Repair will:\n\n"
            + string.Join("\n", steps.Select((s, i) => $"{i + 1}. {s}"));
        if (!env.InPlace && env.Alternatives.Count > 0)
            text += "\n\nIf hashcat still does not start, RecoverKit asks you before putting it in another folder.";
        return text + "\n\nYour settings, sessions and found passwords are not changed.";
    }

    internal static string MoveQuestion(string target, string bundle, string folder) =>
        $"hashcat was copied again to {target}, but it still does not start there. The same hashcat starts from RecoverKit's own folder ({bundle}), " +
        "so something on this computer is holding programs in that folder. This is usually antivirus software, which often treats new programs in AppData this way.\n\n" +
        $"RecoverKit can copy hashcat ({SizeOf(bundle)}) to {folder} and use it from there. That folder is inside your user folder, so other accounts on this computer cannot change it.\n\n" +
        "Instead, you can cancel, allow hashcat in your antivirus (in Windows Security: Virus & threat protection > Protection history), then click Check again.";

    /// <summary>After a move, the copy in the usual folder is unused: offer to remove it.</summary>
    private static async Task OfferCleanupAsync(Environment env, string old, string folder, Action<string> say, CancellationToken ct)
    {
        if (env.Ask is not { } ask || !Directory.Exists(old) || HashcatTool.IsInside(Path.Combine(folder, "x"), old)) return;
        var question = new RepairQuestion(Title,
            $"hashcat now runs from {folder}.\n\nThe old copy in {old} ({SizeOf(old)}) is no longer used. Remove it?\n\n" +
            "If antivirus software still holds some of its files, RecoverKit removes what it can and tells you what is left.",
            "Remove old copy", "Keep it");
        if (!await ask(question, ct)) { DebugLog.Info($"hashcat repair: old copy {old} kept"); return; }
        env.StopProcesses(old);
        int left = RemoveFolder(old);
        if (Directory.Exists(old + ".partial")) left += RemoveFolder(old + ".partial");
        say(left == 0
            ? $"Removed the old copy in {old}."
            : $"Removed the old copy in {old} except {left} file(s) that are still in use. You can delete that folder later.");
    }

    /// <summary>Deletes what it can and returns the number of files left behind.</summary>
    private static int RemoveFolder(string dir)
    {
        try { Directory.Delete(dir, true); return 0; }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            DebugLog.Warn($"hashcat repair: could not remove all of {dir}: {ex.Message}");
            int left = 0;
            foreach (var file in SafeFiles(dir))
            {
                try { File.Delete(file); }
                catch (Exception e) when (e is IOException or UnauthorizedAccessException) { left++; }
            }
            try { Directory.Delete(dir, true); } catch (Exception e) when (e is IOException or UnauthorizedAccessException) { }
            return Math.Max(left, Directory.Exists(dir) ? 1 : 0);
        }
    }

    private static IEnumerable<string> SafeFiles(string dir)
    {
        try { return Directory.GetFiles(dir, "*", SearchOption.AllDirectories); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return []; }
    }

    internal static string SizeOf(string dir)
    {
        long bytes = 0;
        foreach (var file in SafeFiles(dir))
            try { bytes += new FileInfo(file).Length; } catch (IOException) { }
        return bytes >= 1L << 20 ? $"about {bytes / (1L << 20):N0} MB" : $"about {Math.Max(1, bytes / 1024):N0} KB";
    }

    internal static IReadOnlyList<string> DefaultAlternatives()
    {
        if (!OperatingSystem.IsWindows()) return [];
        // Outside AppData and Downloads, where antivirus software holds unknown programs most often, and
        // inside the user's profile: a folder at the drive root (C:\RecoverKit) is writable by every user
        // of the PC, so another account could replace hashcat.exe there.
        var profile = System.Environment.GetFolderPath(System.Environment.SpecialFolder.UserProfile);
        return profile.Length > 0 ? [Path.Combine(profile, "RecoverKit")] : [];
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

    private static IEnumerable<Process> HashcatIn(string folder)
    {
        foreach (var p in Process.GetProcessesByName("hashcat"))
        {
            bool inside = false;
            try { inside = p.MainModule?.FileName is { } file && HashcatTool.IsInside(file, folder); }
            catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception or NotSupportedException) { }
            if (inside) yield return p;
            else p.Dispose();
        }
    }

    private static int CountHashcatIn(string folder)
    {
        int n = 0;
        foreach (var p in HashcatIn(folder)) using (p) n++;
        return n;
    }

    private static void StopHashcatIn(string folder)
    {
        foreach (var p in HashcatIn(folder))
        {
            using (p)
            {
                try
                {
                    DebugLog.Info($"hashcat repair: stopping hashcat process {p.Id}");
                    p.Kill(true);
                }
                catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception or NotSupportedException) { }
            }
        }
    }
}
