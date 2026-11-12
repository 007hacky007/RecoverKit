using System.Diagnostics;
using System.IO.Compression;
using System.Runtime.Versioning;

namespace RecoverKit.Core.Hashcat;

/// <summary>
/// Lets hashcat recover passwords on the processor when no GPU driver is installed.
///
/// hashcat reaches every device, the CPU included, through an OpenCL/CUDA/HIP runtime, and a stock
/// Windows installation has none. This downloads Intel's CPU Runtime for OpenCL (the runtime hashcat
/// recommends for Intel and AMD processors) from its official PyPI packages, verifies their SHA-256,
/// and unpacks the DLLs into the per-user engines folder. Nothing is installed system-wide: each
/// hashcat process gets the runtime through PATH and the Khronos loader's OCL_ICD_FILENAMES list,
/// which adds the CPU device next to any GPU drivers already present.
///
/// The Khronos loader deliberately ignores these variables in elevated processes, so that code
/// running without admin rights cannot get a DLL loaded into an administrator's process. RecoverKit
/// respects that: when it runs elevated it does not use the per-user runtime at all (no PATH change,
/// and never a system-wide HKLM registration of a user-writable DLL) and tells the user to run it
/// normally instead.
/// </summary>
public static class CpuRuntime
{
    public const string Version = "2026.1.2";
    public const string LicenseName = "Intel End User License Agreement for Developer Tools";
    public const string LicenseUrl = "https://www.intel.com/content/www/us/en/developer/articles/license/end-user-license-agreement.html";
    public const string DriverDll = "intelocl64.dll";

    /// <summary>A pinned wheel and the folder inside it whose files make up the runtime.</summary>
    private sealed record Package(string Name, string Url, string Sha256, long Size, string BinPrefix, string? DocPrefix);

    private static readonly Package[] Packages =
    [
        new("Intel CPU Runtime for OpenCL",
            "https://files.pythonhosted.org/packages/94/4e/dea179a1beb493fcf5bfc5f4680f5a2660373b8f00be0ce3ec89eeeb3942/intel_opencl_rt-2026.1.2-py2.py3-none-win_amd64.whl",
            "9b4da9a4e12e56c5eda5c93c22a8eb0579f5811d27a5d8cc1171303208308320", 109497438,
            "intel_opencl_rt-2026.1.2.data/data/Library/bin/",
            "intel_opencl_rt-2026.1.2.data/data/share/doc/opencl/licensing/"),
        new("oneTBB",
            "https://files.pythonhosted.org/packages/ac/ff/168d3498762069b0cd2dff20ab34d53fa48a0a35ffd1965cf456c603f292/tbb-2023.1.0-py3-none-win_amd64.whl",
            "27df1315202defc67a73800c667ba4fbd03cf8924f73949373d4a34d1443fca2", 428501,
            "tbb-2023.1.0.data/data/Library/bin/",
            null),
    ];

    /// <summary>Approximate download size, for the UI.</summary>
    public static long DownloadBytes => Packages.Sum(p => p.Size);

    public static string InstallRoot => Path.Combine(Settings.AppDataDir, "engines");
    public static string ExpectedDirectory => Path.Combine(InstallRoot, "opencl-cpu-" + Version);

    public static bool IsSupportedPlatform => OperatingSystem.IsWindows();

    /// <summary>The installed runtime folder, or null when it has not been downloaded.</summary>
    public static string? Locate()
    {
        var d = ExpectedDirectory;
        return File.Exists(Path.Combine(d, DriverDll)) && File.Exists(Path.Combine(d, "VERSION")) ? d : null;
    }

    /// <summary>
    /// Prepares a hashcat process: exposes the CPU runtime when installed and applies the CPU thread
    /// limit (honoured by Intel's runtime; 0 keeps one thread per logical processor).
    /// </summary>
    public static void ApplyTo(ProcessStartInfo psi, int maxCpuThreads)
    {
        if (maxCpuThreads > 0) psi.Environment["CL_CONFIG_CPU_TBB_NUM_WORKERS"] = maxCpuThreads.ToString();

        var dir = Locate();
        if (dir is null || IsElevatedProcess) return;
        var env = psi.Environment;
        env.TryGetValue("PATH", out var path);
        env["PATH"] = dir + Path.PathSeparator + path;

        var icd = Path.Combine(dir, DriverDll);
        env.TryGetValue("OCL_ICD_FILENAMES", out var list);
        if (string.IsNullOrEmpty(list)) env["OCL_ICD_FILENAMES"] = icd;
        else if (!list.Contains(icd, StringComparison.OrdinalIgnoreCase)) env["OCL_ICD_FILENAMES"] = list + Path.PathSeparator + icd;
    }

    /// <summary>True when installed but unusable because this process runs as administrator.</summary>
    public static bool BlockedByElevation => IsElevatedProcess && Locate() is not null;

    // ---------------------------------------------------------------- install

    public static async Task<string> InstallAsync(IProgress<InstallProgress>? progress = null, CancellationToken ct = default)
    {
        if (!IsSupportedPlatform)
            throw new InstallException("The CPU runtime download is for Windows. On Linux install PoCL (for example " +
                                       "apt install pocl-opencl-icd). On macOS hashcat uses the GPU through Metal/OpenCL, " +
                                       "and the built-in CPU engine covers the processor.");

        Directory.CreateDirectory(InstallRoot);
        var tmp = Directory.CreateDirectory(Path.Combine(InstallRoot, ".tmp-opencl-cpu")).FullName;
        var staging = ExpectedDirectory + ".partial";
        try
        {
            if (Directory.Exists(staging)) Directory.Delete(staging, true);
            Directory.CreateDirectory(staging);

            foreach (var pkg in Packages)
            {
                ct.ThrowIfCancellationRequested();
                var wheel = Path.Combine(tmp, Path.GetFileName(new Uri(pkg.Url).LocalPath));
                progress?.Report(new InstallProgress { Stage = "download", Message = $"Downloading {pkg.Name} ..." });
                await HashcatInstaller.DownloadAsync(pkg.Url, wheel, pkg.Sha256, pkg.Size, "download", progress, ct);

                progress?.Report(new InstallProgress { Stage = "extract", Message = $"Unpacking {pkg.Name} ..." });
                await Task.Run(() => ExtractWheel(wheel, pkg, staging), ct);
                File.Delete(wheel);
            }

            if (!File.Exists(Path.Combine(staging, DriverDll)))
                throw new InstallException("The downloaded package does not contain " + DriverDll + ".");
            File.WriteAllText(Path.Combine(staging, "VERSION"), Version + Environment.NewLine);

            if (Directory.Exists(ExpectedDirectory)) Directory.Delete(ExpectedDirectory, true);
            Directory.Move(staging, ExpectedDirectory);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException)
        {
            DebugLog.Error("CPU runtime install", ex);
            throw new InstallException("Could not install the CPU runtime: " + ex.Message, ex);
        }
        finally
        {
            try { Directory.Delete(tmp, true); } catch (IOException) { }
            try { if (Directory.Exists(staging)) Directory.Delete(staging, true); } catch (IOException) { }
        }

        DebugLog.Info($"CPU runtime {Version} installed to {ExpectedDirectory}: " +
                      string.Join(", ", Directory.GetFiles(ExpectedDirectory).Select(Path.GetFileName)));
        progress?.Report(new InstallProgress { Stage = "done", Message = "Done." });
        return ExpectedDirectory;
    }

    /// <summary>Copies the runtime files (and the license texts) out of a wheel, flattened into one folder.</summary>
    private static void ExtractWheel(string wheel, Package pkg, string outDir)
    {
        using var zip = ZipFile.OpenRead(wheel);
        foreach (var e in zip.Entries)
        {
            if (e.Name.Length == 0) continue;
            bool bin = e.FullName.StartsWith(pkg.BinPrefix, StringComparison.Ordinal) && e.FullName.IndexOf('/', pkg.BinPrefix.Length) < 0;
            bool doc = pkg.DocPrefix is not null && e.FullName.StartsWith(pkg.DocPrefix, StringComparison.Ordinal);
            if (!bin && !doc) continue;
            var ext = Path.GetExtension(e.Name).ToLowerInvariant();
            if (bin && ext is ".lib" or ".py") continue;           // import libraries and debugger helpers are not needed
            var dest = Path.Combine(outDir, doc ? Path.Combine("licensing", e.Name) : e.Name);
            Directory.CreateDirectory(Path.GetDirectoryName(dest)!);
            e.ExtractToFile(dest, overwrite: true);
        }
    }

    // ---------------------------------------------------------------- elevated processes

    private static readonly Lazy<bool> Elevated = new(() => OperatingSystem.IsWindows() && CheckElevated());

    /// <summary>Whether RecoverKit itself runs with an elevated (administrator) token.</summary>
    public static bool IsElevatedProcess => Elevated.Value;

    [SupportedOSPlatform("windows")]
    private static bool CheckElevated()
    {
        try
        {
            using var id = System.Security.Principal.WindowsIdentity.GetCurrent();
            return new System.Security.Principal.WindowsPrincipal(id).IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
        }
        catch (System.Security.SecurityException) { return false; }
    }
}
