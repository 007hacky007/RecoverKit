using System.Reflection;
using System.Security.Cryptography;
using System.Text;

namespace RecoverKit.Core.Hashcat;

/// <summary>
/// RecoverKit's replacement GPU kernels for hashcat (ZipCrypto, modes 17200 and 17210), written
/// against hashcat 8.0.0. hashcat compiles kernels from the .cl sources in its OpenCL folder at run
/// time, for CUDA, HIP, OpenCL and Metal alike, so replacing the source files is enough: no own GPU
/// host code. hashcat 8 keys its kernel cache on the source text, so the replacement is compiled on
/// first use.
///
/// Only files whose content is exactly hashcat 8.0.0's original (line endings ignored, the Windows
/// release uses CRLF) or an earlier RecoverKit replacement are touched; the original is kept next to
/// it as <c>&lt;name&gt;.hashcat</c>, so any other hashcat version stays unmodified and
/// <see cref="Restore"/> can put the originals back.
/// </summary>
public static class HashcatKernels
{
    /// <summary>The shared helpers (key schedule, queue, RK_QUEUE and RK_AMP_CACHE settings).</summary>
    public const string IncludeFile = "inc_rk_zipcrypto.cl";

    /// <summary>
    /// Every include file (the helpers and the kernel bodies), installed whenever the kernels are. They are
    /// named inc_*: hashcat 8 hands only such files to NVRTC on Windows, and checksums every file of
    /// OpenCL/ that is not a mode kernel into its kernel cache key, so a changed include is recompiled.
    /// </summary>
    public static IEnumerable<string> IncludeFiles => Sources.Keys.Where(k => !k.StartsWith('m')).Order();

    /// <summary>Suffix of the saved hashcat original.</summary>
    public const string OriginalSuffix = ".hashcat";

    /// <summary>hashcat modes the replacement kernels serve.</summary>
    public static readonly int[] Modes = [17200, 17210];

    /// <summary>
    /// SHA-256 of hashcat 8.0.0's original kernel files (LF line endings), by file name. A kernel is
    /// replaced only when the file on disk is one of these (or already ours).
    /// </summary>
    internal static readonly IReadOnlyDictionary<string, string> Originals = new Dictionary<string, string>
    {
        ["m17200_a0-pure.cl"] = "8cc090809d856f102f7723148099e44efcbe6f371da93b9f02a577f2b24a1f44",
        ["m17200_a3-pure.cl"] = "868234fe68fb3d8b03c350f17a97031610e30f70d70e30533aeb1773511668af",
        ["m17210_a0-pure.cl"] = "d4b40226a68a5acb1ae19a0cf50dad2f40567f6cb093d130e6deaabedd8fea73",
        ["m17210_a3-pure.cl"] = "21304bd626e6415548b1efcfa5b80baca5713fee28fca02a4f2850cadb513f35",
    };

    /// <summary>Set RECOVERKIT_HASHCAT_ZIP_KERNELS=0 to leave hashcat's own kernels in place.</summary>
    public static bool Disabled => Environment.GetEnvironmentVariable("RECOVERKIT_HASHCAT_ZIP_KERNELS") == "0";

    private static readonly object Gate = new();
    private static readonly HashSet<string> Done = new(StringComparer.Ordinal);

    /// <summary>The replacement sources, by file name (the include and the kernels).</summary>
    public static IReadOnlyDictionary<string, string> Sources => _sources.Value;

    private static readonly Lazy<Dictionary<string, string>> _sources = new(() =>
    {
        var asm = typeof(HashcatKernels).Assembly;
        var d = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var name in asm.GetManifestResourceNames())
        {
            const string prefix = "RecoverKit.Kernels.";
            if (!name.StartsWith(prefix, StringComparison.Ordinal)) continue;
            using var s = asm.GetManifestResourceStream(name)!;
            using var r = new StreamReader(s, Encoding.UTF8);
            d[name[prefix.Length..]] = r.ReadToEnd().Replace("\r\n", "\n");
        }
        return d;
    });

    /// <summary>Kernel file names RecoverKit replaces (m17200_*, m17210_*).</summary>
    public static IEnumerable<string> KernelFiles => Sources.Keys.Where(k => k.StartsWith('m')).Order();

    internal static string Hash(string text)
        => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(text.Replace("\r\n", "\n")))).ToLowerInvariant();

    private static string? ReadNormalized(string path)
    {
        try { return File.Exists(path) ? File.ReadAllText(path, Encoding.UTF8).Replace("\r\n", "\n") : null; }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return null; }
    }

    /// <summary>
    /// State of the ZIP kernels in a hashcat folder: RecoverKit's current kernels, files that can be
    /// replaced (hashcat 8.0.0's originals, or an earlier RecoverKit version's kernels with hashcat's
    /// original kept beside them), or something else (another hashcat version).
    /// </summary>
    public enum State { Installed, Original, Unsupported }

    /// <summary>Text every RecoverKit kernel file carries in its header comment.</summary>
    internal const string Marker = "RecoverKit replacement kernel for hashcat";

    /// <summary>Whether <paramref name="hashcatDir"/> runs RecoverKit's kernels, hashcat's 8.0.0 originals, or neither.</summary>
    public static State Inspect(string hashcatDir) => Inspect(hashcatDir, Originals);

    internal static State Inspect(string hashcatDir, IReadOnlyDictionary<string, string> originals)
    {
        var dir = Path.Combine(hashcatDir, "OpenCL");
        bool allOurs = true;
        foreach (var f in KernelFiles)
        {
            var text = ReadNormalized(Path.Combine(dir, f));
            if (text is null) return State.Unsupported;
            bool ours = text == Sources[f];
            bool known = originals.TryGetValue(f, out var h);
            bool orig = known && Hash(text) == h;
            // An earlier RecoverKit version's kernel, over hashcat's original.
            bool older = !ours && !orig && known && text.Contains(Marker, StringComparison.Ordinal)
                         && ReadNormalized(Path.Combine(dir, f + OriginalSuffix)) is { } backup && Hash(backup) == h;
            if (!ours) allOurs = false;
            if (!ours && !orig && !older) return State.Unsupported;
        }
        if (allOurs && IncludeFiles.All(f => ReadNormalized(Path.Combine(dir, f)) == Sources[f])) return State.Installed;
        return State.Original;
    }

    /// <summary>
    /// Makes sure the hashcat in <paramref name="hashcatDir"/> runs RecoverKit's ZIP kernels, once per
    /// process and folder. Never throws: on any problem hashcat's own kernels stay in use (logged).
    /// Returns true when the replacement kernels are in place.
    /// </summary>
    public static bool EnsureInstalled(string hashcatDir)
    {
        if (Disabled) return false;
        lock (Gate)
        {
            var key = Path.GetFullPath(hashcatDir);
            if (Done.Contains(key)) return Inspect(hashcatDir) == State.Installed;
            Done.Add(key);
            try { return Install(hashcatDir); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                DebugLog.Error("Installing RecoverKit's ZIP kernels into " + hashcatDir, ex);
                return false;
            }
        }
    }

    /// <summary>Returns whether this mode and attack run the installed replacement kernels.</summary>
    public static bool EnsureFor(HashcatTool tool, int mode, int attackMode = 3)
        => Array.IndexOf(Modes, mode) >= 0 && attackMode is 0 or 3 && EnsureInstalled(tool.Directory);

    /// <summary>
    /// Why the replacement kernels cannot run with this hashcat, in plain words, or null when they can.
    /// The usual case: an earlier RecoverKit installed hashcat 7.1.2 and the upgrade kept using it.
    /// </summary>
    public static string? UnavailableReason(HashcatTool tool)
    {
        if (Disabled) return "RecoverKit's ZIP GPU kernels are turned off (RECOVERKIT_HASHCAT_ZIP_KERNELS=0).";
        if (Inspect(tool.Directory) == State.Unsupported)
        {
            // Only the user's own older hashcat has a switch on the dependencies page (a newer one, or a copy
            // RecoverKit installed, has none).
            bool canSwitch = HashcatInstaller.BundledDirectory is not null && !tool.IsManaged && HashcatTool.IsOlderThanPinned(tool.FullVersion);
            return $"RecoverKit's faster ZIP kernels need hashcat {HashcatInstaller.Version} exactly, and this computer runs hashcat {tool.FullVersion.TrimStart('v')}." +
                   (canSwitch ? $" Tools > Dependencies switches to hashcat {HashcatInstaller.Version}." : "");
        }
        if (!EnsureInstalled(tool.Directory))
            return "RecoverKit's ZIP GPU kernels could not be written into hashcat's OpenCL folder (details are in the debug log).";
        return null;
    }

    /// <summary>
    /// Installs the replacement kernels when every file to replace is hashcat 8.0.0's original or
    /// already ours. Returns true when they are in place afterwards.
    /// </summary>
    public static bool Install(string hashcatDir) => Install(hashcatDir, Originals);

    internal static bool Install(string hashcatDir, IReadOnlyDictionary<string, string> originals)
    {
        var dir = Path.Combine(hashcatDir, "OpenCL");
        var state = Inspect(hashcatDir, originals);
        if (state == State.Unsupported)
        {
            DebugLog.Info($"ZIP kernels: {dir} is not hashcat {HashcatInstaller.Version}'s, keeping its own kernels");
            return false;
        }
        foreach (var f in KernelFiles)
        {
            var path = Path.Combine(dir, f);
            var text = ReadNormalized(path)!;
            if (text == Sources[f]) continue;
            var backup = path + OriginalSuffix;
            if (!File.Exists(backup)) File.Copy(path, backup);
            WriteAtomic(path, Sources[f]);
        }
        foreach (var f in IncludeFiles)
            if (ReadNormalized(Path.Combine(dir, f)) != Sources[f]) WriteAtomic(Path.Combine(dir, f), Sources[f]);
        if (state != State.Installed) DebugLog.Info($"ZIP kernels: installed RecoverKit's kernels into {dir}");
        return Inspect(hashcatDir, originals) == State.Installed;
    }

    /// <summary>Puts hashcat's original kernels back (benchmarks compare both). Returns false when there is nothing to restore.</summary>
    public static bool Restore(string hashcatDir)
    {
        var dir = Path.Combine(hashcatDir, "OpenCL");
        bool any = false;
        lock (Gate)
        {
            foreach (var f in KernelFiles)
            {
                var path = Path.Combine(dir, f);
                var backup = path + OriginalSuffix;
                if (!File.Exists(backup)) continue;
                File.Copy(backup, path, overwrite: true);
                any = true;
            }
            Done.Remove(Path.GetFullPath(hashcatDir));
        }
        return any;
    }

    /// <summary>Applies a measured ZIP kernel for one run, then restores every source byte.</summary>
    public static IDisposable? ApplyProfile(HashcatTool tool, int mode, string? variant)
    {
        if (Disabled || !Modes.Contains(mode) || variant is not ("hashcat" or "amplifier-cache") || Inspect(tool.Directory) == State.Unsupported) return null;
        var paths = Sources.Keys.Select(name => Path.Combine(tool.Directory, "OpenCL", name)).ToList();
        var saved = paths.ToDictionary(path => path, path => File.Exists(path) ? File.ReadAllBytes(path) : null);
        var restore = new SourceRestore(saved);
        try
        {
            if (variant == "hashcat") Restore(tool.Directory);
            else
            {
                Install(tool.Directory);
                WriteAtomic(Path.Combine(tool.Directory, "OpenCL", IncludeFile), Sources[IncludeFile].Replace("#define RK_AMP_CACHE 0", "#define RK_AMP_CACHE 1"));
            }
            return restore;
        }
        catch { restore.Dispose(); throw; }
    }

    private sealed class SourceRestore(Dictionary<string, byte[]?> saved) : IDisposable
    {
        public void Dispose()
        {
            foreach (var (path, content) in saved)
                if (content is null) File.Delete(path); else File.WriteAllBytes(path, content);
        }
    }

    private static void WriteAtomic(string path, string text)
    {
        var tmp = path + ".rk-tmp";
        File.WriteAllText(tmp, text, new UTF8Encoding(false));
        File.Move(tmp, path, overwrite: true);
    }
}
