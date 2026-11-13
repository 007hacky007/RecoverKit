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
    /// <summary>The shared include, installed whenever a kernel is.</summary>
    public const string IncludeFile = "inc_rk_zipcrypto.cl";

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
        ["m17200_a3-pure.cl"] = "868234fe68fb3d8b03c350f17a97031610e30f70d70e30533aeb1773511668af",
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

    /// <summary>Kernel file names RecoverKit replaces (without the include).</summary>
    public static IEnumerable<string> KernelFiles => Sources.Keys.Where(k => k != IncludeFile).Order();

    internal static string Hash(string text)
        => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(text.Replace("\r\n", "\n")))).ToLowerInvariant();

    private static string? ReadNormalized(string path)
    {
        try { return File.Exists(path) ? File.ReadAllText(path, Encoding.UTF8).Replace("\r\n", "\n") : null; }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return null; }
    }

    /// <summary>State of the ZIP kernels in a hashcat folder.</summary>
    public enum State { Installed, Original, Unsupported }

    /// <summary>Whether <paramref name="hashcatDir"/> runs RecoverKit's kernels, hashcat's 8.0.0 originals, or neither.</summary>
    public static State Inspect(string hashcatDir) => Inspect(hashcatDir, Originals);

    internal static State Inspect(string hashcatDir, IReadOnlyDictionary<string, string> originals)
    {
        var dir = Path.Combine(hashcatDir, "OpenCL");
        bool allOurs = true, allOriginal = true;
        foreach (var f in KernelFiles)
        {
            var text = ReadNormalized(Path.Combine(dir, f));
            if (text is null) return State.Unsupported;
            bool ours = text == Sources[f];
            bool orig = originals.TryGetValue(f, out var h) && Hash(text) == h;
            if (!ours) allOurs = false;
            if (!orig) allOriginal = false;
            if (!ours && !orig) return State.Unsupported;
        }
        if (allOurs && ReadNormalized(Path.Combine(dir, IncludeFile)) == Sources[IncludeFile]) return State.Installed;
        return allOriginal ? State.Original : State.Installed;
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

    /// <summary>For a mode the replacement kernels serve, <see cref="EnsureInstalled"/>; otherwise nothing.</summary>
    public static void EnsureFor(HashcatTool tool, int mode)
    {
        if (Array.IndexOf(Modes, mode) >= 0) EnsureInstalled(tool.Directory);
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
        if (ReadNormalized(Path.Combine(dir, IncludeFile)) != Sources[IncludeFile])
            WriteAtomic(Path.Combine(dir, IncludeFile), Sources[IncludeFile]);
        if (state != State.Installed) DebugLog.Info($"ZIP kernels: installed RecoverKit's kernels into {dir}");
        return true;
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

    private static void WriteAtomic(string path, string text)
    {
        var tmp = path + ".rk-tmp";
        File.WriteAllText(tmp, text, new UTF8Encoding(false));
        File.Move(tmp, path, overwrite: true);
    }
}
