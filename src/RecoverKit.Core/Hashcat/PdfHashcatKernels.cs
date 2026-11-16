using System.Text;

namespace RecoverKit.Core.Hashcat;

/// <summary>Independently guarded replacements for hashcat 8's slow-hash PDF kernels.</summary>
public static class PdfHashcatKernels
{
    internal static readonly IReadOnlyDictionary<string, string> Originals = new Dictionary<string, string>
    {
        ["m10500-pure.cl"] = "6d5b36d204ba3a7f104f67d3b2f0f61554bb09de048c1ae58fcab5c305294644",
    };

    private static readonly object Gate = new();
    private static readonly Lazy<Dictionary<string, string>> Embedded = new(() =>
    {
        var assembly = typeof(PdfHashcatKernels).Assembly;
        const string prefix = "RecoverKit.PdfKernels.";
        return assembly.GetManifestResourceNames().Where(n => n.StartsWith(prefix, StringComparison.Ordinal))
            .ToDictionary(n => n[prefix.Length..], n =>
            {
                using var reader = new StreamReader(assembly.GetManifestResourceStream(n)!);
                return reader.ReadToEnd().Replace("\r\n", "\n");
            });
    });

    public static IReadOnlyDictionary<string, string> Sources => Embedded.Value;
    /// <summary>"0" or "1" from RECOVERKIT_HASHCAT_PDF_KERNELS, or null when unset.</summary>
    private static string? Switch => Environment.GetEnvironmentVariable("RECOVERKIT_HASHCAT_PDF_KERNELS");

    /// <summary>
    /// The replacement is measured faster only on Apple's Metal backend (+35% on an M1 Pro); OpenCL on the
    /// same Mac was unchanged and NVIDIA (CUDA/OpenCL) is unmeasured. Elsewhere hashcat's kernel stays the
    /// default until `bench-pdf` shows a gain there; RECOVERKIT_HASHCAT_PDF_KERNELS=1 opts in, =0 opts out.
    /// </summary>
    public static bool Disabled => Switch == "0" || Switch != "1" && !DefaultOn;

    internal static bool DefaultOn => OperatingSystem.IsMacOS();

    /// <summary>True only when the user turned the replacement off explicitly.</summary>
    public static bool ExplicitlyDisabled => Switch == "0";

    public static bool EnsureInstalled(string directory, int mode)
    {
        if (Disabled)
        {
            Restore(directory);
            string path = Path.Combine(directory, "OpenCL", $"m{mode}-pure.cl");
            if (Read(path)?.Contains(HashcatKernels.Marker, StringComparison.Ordinal) == true)
                throw new InvalidOperationException("The PDF kernel could not be restored. Repair hashcat's original kernel backup before running with RECOVERKIT_HASHCAT_PDF_KERNELS=0.");
            return false;
        }
        try
        {
            return Install(directory);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            DebugLog.Error("Installing RecoverKit's PDF kernels", ex);
            return false;
        }
    }

    private static string? Read(string path) => File.Exists(path) ? File.ReadAllText(path).Replace("\r\n", "\n") : null;

    public static bool Supported(string directory) => Supported(directory, Originals);

    private static bool Supported(string directory, IReadOnlyDictionary<string, string> originals)
    {
        if (Sources.Count == 0) return false;
        foreach (var (name, source) in Sources)
        {
            if (!originals.TryGetValue(name, out var hash)) return false;
            string path = Path.Combine(directory, "OpenCL", name);
            string? text = Read(path);
            if (text is null) return false;
            string? backup = Read(path + HashcatKernels.OriginalSuffix);
            if (backup is not null && HashcatKernels.Hash(backup) != hash) return false;
            if (HashcatKernels.Hash(text) == hash) continue;
            // A replacement needs a verified backup, even when its current bytes are ours.
            if (text != source && !text.Contains(HashcatKernels.Marker, StringComparison.Ordinal)) return false;
            if (backup is null) return false;
        }
        return true;
    }

    public static bool Install(string directory) => Install(directory, Originals);

    internal static bool Install(string directory, IReadOnlyDictionary<string, string> originals)
    {
        lock (Gate)
        {
            if (!Supported(directory, originals)) return false;
            foreach (var (name, source) in Sources)
            {
                string path = Path.Combine(directory, "OpenCL", name);
                if (Read(path) == source) continue;
                string backup = path + HashcatKernels.OriginalSuffix;
                if (!File.Exists(backup)) File.Copy(path, backup);
                string temp = path + ".rk-tmp";
                File.WriteAllText(temp, source, new UTF8Encoding(false));
                File.Move(temp, path, overwrite: true);
            }
            return true;
        }
    }

    public static bool Restore(string directory) => Restore(directory, Originals);

    internal static bool Restore(string directory, IReadOnlyDictionary<string, string> originals)
    {
        lock (Gate)
        {
            bool restored = false;
            foreach (var (name, source) in Sources)
            {
                string path = Path.Combine(directory, "OpenCL", name);
                string? current = Read(path);
                if (current is null || current != source && !current.Contains(HashcatKernels.Marker, StringComparison.Ordinal)) continue;
                string backup = path + HashcatKernels.OriginalSuffix;
                if (Read(backup) is not { } text || HashcatKernels.Hash(text) != originals[name]) continue;
                string temp = path + ".rk-tmp";
                File.Copy(backup, temp, overwrite: true);
                File.Move(temp, path, overwrite: true);
                restored = true;
            }
            return restored;
        }
    }
}
