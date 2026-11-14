using System.Diagnostics;
using System.IO.Compression;
using System.Text.RegularExpressions;

namespace RecoverKit.Core.Hashcat;

/// <summary>
/// Lets hashcat use its CUDA backend on NVIDIA GPUs without the CUDA Toolkit (Windows).
///
/// hashcat compiles its kernels at run time. With CUDA it needs NVIDIA's run-time compiler NVRTC
/// (nvrtc64_*.dll and nvrtc-builtins64_*.dll), which is part of the CUDA Toolkit, not of the driver;
/// without it hashcat falls back to OpenCL. NVIDIA publishes NVRTC on its own as the official
/// nvidia-cuda-nvrtc-cu12 package on PyPI (NVIDIA's CUDA license, which lists these DLLs as
/// redistributable). This downloads the package, verifies its SHA-256, unpacks the two DLLs into the
/// per-user engines folder and puts that folder on each hashcat process's PATH, where hashcat 8
/// looks for the newest nvrtc64_*.dll. Nothing is installed system-wide.
///
/// hashcat hands the driver PTX produced by NVRTC, and a driver accepts PTX only from an NVRTC no
/// newer than itself, so the package is chosen by the CUDA version the driver reports (nvidia-smi).
/// hashcat 8 needs CUDA 12.0 at least.
/// </summary>
public static class NvrtcRuntime
{
    public const string LicenseName = "NVIDIA CUDA Toolkit End User License Agreement";
    public const string LicenseUrl = "https://docs.nvidia.com/cuda/eula/index.html";

    /// <summary>A pinned nvidia-cuda-nvrtc-cu12 wheel and the driver CUDA version it needs.</summary>
    public sealed record Package(string Version, int MinDriverMajor, int MinDriverMinor, string Url, string Sha256, long Size)
    {
        public string Directory => Path.Combine(InstallRoot, "nvrtc-" + Version);
    }

    // Newest first. 12.8 is the first NVRTC that knows the RTX 50 series (Blackwell, sm_120).
    public static readonly Package[] Packages =
    [
        new("12.8.93", 12, 8,
            "https://files.pythonhosted.org/packages/45/51/52a3d84baa2136cc8df15500ad731d74d3a1114d4c123e043cb608d4a32b/nvidia_cuda_nvrtc_cu12-12.8.93-py3-none-win_amd64.whl",
            "7a4b6b2904850fe78e0bd179c4b655c404d4bb799ef03ddc60804247099ae909", 73586838),
        new("12.4.127", 12, 4,
            "https://files.pythonhosted.org/packages/7c/30/8c844bfb770f045bcd8b2c83455c5afb45983e1a8abf0c4e5297b481b6a5/nvidia_cuda_nvrtc_cu12-12.4.127-py3-none-win_amd64.whl",
            "a961b2f1d5f17b14867c619ceb99ef6fcec12e46612711bcec78eb05068a60ec", 19751955),
    ];

    private const string BinPrefix = "nvidia/cuda_nvrtc/bin/";

    public static string InstallRoot => Path.Combine(Settings.AppDataDir, "engines");

    public static bool IsSupportedPlatform => OperatingSystem.IsWindows();

    /// <summary>The newest installed NVRTC folder, or null.</summary>
    public static string? Locate()
    {
        foreach (var p in Packages)
            if (File.Exists(Path.Combine(p.Directory, "VERSION")) && System.IO.Directory.GetFiles(p.Directory, "nvrtc64_*.dll").Length > 0)
                return p.Directory;
        return null;
    }

    /// <summary>
    /// Chooses the NVRTC a hashcat process sees. hashcat 8 loads the newest nvrtc64_*.dll from CUDA_PATH and
    /// every PATH folder, and the driver rejects code from an NVRTC newer than itself ("Unsupported .version
    /// 9.5; current version is '9.3'" with CUDA Toolkit 13.5 on a CUDA 13.3 driver), which fails every CUDA
    /// kernel build. So copies newer than the driver are hidden, and when RecoverKit's own NVRTC is
    /// installed (not in elevated processes, as with the CPU runtime) it is the only one hashcat sees.
    /// </summary>
    public static void ApplyTo(ProcessStartInfo psi)
    {
        if (IsSupportedPlatform) ApplyTo(psi.Environment, Driver.Value, CpuRuntime.IsElevatedProcess ? null : Locate());
    }

    internal static void ApplyTo(IDictionary<string, string?> env, (int Major, int Minor)? driver, string? own)
    {
        if (own is not null && driver is { } d && DirectoryVersion(own) is { } ownVersion && !Fits(ownVersion, d)) own = null;
        // Without a known driver nothing can be judged: leave the system's copies alone.
        bool Keep(string dir) => DirectoryVersion(dir) is not { } v || (own is null && (driver is not { } dv || Fits(v, dv)));
        env.TryGetValue("PATH", out var path);
        var kept = (path ?? "").Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries).Where(Keep);
        env["PATH"] = string.Join(Path.PathSeparator, (own is null ? kept : kept.Prepend(own)));
        if (env.TryGetValue("CUDA_PATH", out var cudaPath) && !string.IsNullOrEmpty(cudaPath)
            && !(Keep(Path.Combine(cudaPath, "bin", "x64")) && Keep(Path.Combine(cudaPath, "bin"))))
            env.Remove("CUDA_PATH");
    }

    /// <summary>The CUDA version of the NVIDIA driver, read once per run of RecoverKit.</summary>
    internal static readonly Lazy<(int Major, int Minor)?> Driver = new(() => IsSupportedPlatform ? DriverCudaVersion() : null);

    private static bool Fits((int Major, int Minor) nvrtc, (int Major, int Minor) driver)
        => nvrtc.Major < driver.Major || (nvrtc.Major == driver.Major && nvrtc.Minor <= driver.Minor);

    /// <summary>
    /// The CUDA version of the NVRTC in <paramref name="dir"/> from its builtins file
    /// (nvrtc-builtins64_135.dll is 13.5), or null when the folder holds no NVRTC.
    /// </summary>
    internal static (int Major, int Minor)? DirectoryVersion(string dir)
    {
        try
        {
            if (!System.IO.Directory.Exists(dir) || System.IO.Directory.GetFiles(dir, "nvrtc64_*.dll").Length == 0) return null;
            (int, int)? best = null;
            foreach (var f in System.IO.Directory.GetFiles(dir, "nvrtc-builtins64_*.dll"))
            {
                var m = Regex.Match(Path.GetFileName(f), @"^nvrtc-builtins64_(\d+)(\d)\.dll$", RegexOptions.IgnoreCase);
                if (!m.Success) continue;
                (int, int) v = (int.Parse(m.Groups[1].Value), int.Parse(m.Groups[2].Value));
                if (best is not { } b || v.CompareTo(b) > 0) best = v;
            }
            // nvrtc64_130_0.dll alone names only the major version: count it as x.9 so a newer major is still caught.
            if (best is null && System.IO.Directory.GetFiles(dir, "nvrtc64_*.dll").Select(f => Regex.Match(Path.GetFileName(f), @"^nvrtc64_(\d+)0_")).FirstOrDefault(m => m.Success) is { } name)
                best = (int.Parse(name.Groups[1].Value), 9);
            return best;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException) { return null; }
    }

    /// <summary>NVRTC copies on PATH or under CUDA_PATH that the driver cannot use, for the dependencies page.</summary>
    public static IReadOnlyList<(string Directory, (int Major, int Minor) Version)> TooNewForDriver((int Major, int Minor)? driver)
    {
        if (driver is not { } d) return [];
        var dirs = (Environment.GetEnvironmentVariable("PATH") ?? "").Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries).ToList();
        if (Environment.GetEnvironmentVariable("CUDA_PATH") is { Length: > 0 } cuda)
            dirs.AddRange([Path.Combine(cuda, "bin", "x64"), Path.Combine(cuda, "bin")]);
        return dirs.Distinct(StringComparer.OrdinalIgnoreCase)
            .Select(dir => (Directory: dir, Version: DirectoryVersion(dir)))
            .Where(x => x.Version is { } v && !Fits(v, d))
            .Select(x => (x.Directory, x.Version!.Value)).ToList();
    }

    /// <summary>The CUDA version of the NVIDIA driver from nvidia-smi's banner ("CUDA Version: 12.8"), or null.</summary>
    public static (int Major, int Minor)? DriverCudaVersion(Func<(int Code, string Output)>? runSmi = null)
    {
        try
        {
            string output;
            if (runSmi is not null) output = runSmi().Output;
            else if (NvidiaSmi.Locate() is { } exe) output = new NvidiaSmi(exe).Run([]).Output;
            else return null;
            return ParseCudaVersion(output);
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException or IOException) { return null; }
    }

    internal static (int, int)? ParseCudaVersion(string smiOutput)
    {
        var m = Regex.Match(smiOutput, @"CUDA Version\s*:\s*(\d+)\.(\d+)");
        return m.Success ? (int.Parse(m.Groups[1].Value), int.Parse(m.Groups[2].Value)) : null;
    }

    /// <summary>The newest package the driver can use, or null when the driver is older than CUDA 12.4 (or unknown).</summary>
    public static Package? Choose((int Major, int Minor)? driver)
        => driver is { } d ? Packages.FirstOrDefault(p => d.Major > p.MinDriverMajor || (d.Major == p.MinDriverMajor && d.Minor >= p.MinDriverMinor)) : null;

    public static async Task<string> InstallAsync(Package pkg, IProgress<InstallProgress>? progress = null, CancellationToken ct = default)
    {
        if (!IsSupportedPlatform)
            throw new InstallException("The NVRTC download is for Windows. On Linux install NVIDIA's CUDA runtime compiler package " +
                                       "(for example cuda-nvrtc-12-x); macOS has no NVIDIA GPUs.");
        System.IO.Directory.CreateDirectory(InstallRoot);
        var tmp = System.IO.Directory.CreateDirectory(Path.Combine(InstallRoot, ".tmp-nvrtc")).FullName;
        var staging = pkg.Directory + ".partial";
        try
        {
            if (System.IO.Directory.Exists(staging)) System.IO.Directory.Delete(staging, true);
            System.IO.Directory.CreateDirectory(staging);
            var wheel = Path.Combine(tmp, Path.GetFileName(new Uri(pkg.Url).LocalPath));
            progress?.Report(new InstallProgress { Stage = "download", Message = $"Downloading NVIDIA NVRTC {pkg.Version} ..." });
            await HashcatInstaller.DownloadAsync(pkg.Url, wheel, pkg.Sha256, pkg.Size, "download", progress, ct);
            progress?.Report(new InstallProgress { Stage = "extract", Message = "Unpacking ..." });
            await Task.Run(() => ExtractWheel(wheel, staging), ct);
            File.Delete(wheel);
            if (System.IO.Directory.GetFiles(staging, "nvrtc64_*.dll").Length == 0 || System.IO.Directory.GetFiles(staging, "nvrtc-builtins64_*.dll").Length == 0)
                throw new InstallException("The downloaded package does not contain the NVRTC DLLs.");
            File.WriteAllText(Path.Combine(staging, "VERSION"), pkg.Version + Environment.NewLine);
            if (System.IO.Directory.Exists(pkg.Directory)) System.IO.Directory.Delete(pkg.Directory, true);
            System.IO.Directory.Move(staging, pkg.Directory);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException)
        {
            DebugLog.Error("NVRTC install", ex);
            throw new InstallException("Could not install NVRTC: " + ex.Message, ex);
        }
        finally
        {
            try { System.IO.Directory.Delete(tmp, true); } catch (IOException) { }
            try { if (System.IO.Directory.Exists(staging)) System.IO.Directory.Delete(staging, true); } catch (IOException) { }
        }
        DebugLog.Info($"NVRTC {pkg.Version} installed to {pkg.Directory}: " +
                      string.Join(", ", System.IO.Directory.GetFiles(pkg.Directory).Select(Path.GetFileName)));
        progress?.Report(new InstallProgress { Stage = "done", Message = "Done." });
        return pkg.Directory;
    }

    /// <summary>
    /// The two DLLs hashcat loads, and NVIDIA's license text. The ".alt" variant of nvrtc64 is left out:
    /// hashcat picks the newest nvrtc64_*.dll by name and must not see two.
    /// </summary>
    internal static void ExtractWheel(string wheel, string outDir)
    {
        using var zip = ZipFile.OpenRead(wheel);
        foreach (var e in zip.Entries)
        {
            bool dll = e.FullName.StartsWith(BinPrefix, StringComparison.Ordinal) && e.FullName.IndexOf('/', BinPrefix.Length) < 0
                       && e.Name.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) && !e.Name.Contains(".alt.", StringComparison.OrdinalIgnoreCase);
            bool license = e.FullName.EndsWith(".dist-info/License.txt", StringComparison.OrdinalIgnoreCase);
            if (!dll && !license) continue;
            e.ExtractToFile(Path.Combine(outDir, dll ? e.Name : "NVIDIA-LICENSE.txt"), overwrite: true);
        }
    }
}
