using RecoverKit.Core;
using RecoverKit.Core.Formats;
using RecoverKit.Core.Hashcat;
using Xunit;

namespace RecoverKit.Tests;

/// <summary>hashcat on macOS: Metal device parsing and the app-bundled hashcat copy.</summary>
public class MacHashcatTests
{
    // hashcat 7.1.2 -I --quiet, built with macos/build-hashcat.sh, Apple M1 Pro, macOS 27.
    private const string AppleSiliconInfo = """
        Metal Info:
        ===========

        Metal.Version.: 382.5.3

        Backend Device ID #01 (Alias: #02)
          Type...........: GPU
          Vendor.ID......: 2
          Vendor.........: Apple
          Name...........: Apple M1 Pro
          Processor(s)...: 16
          Preferred.Thrd.: 32
          Clock..........: N/A
          Memory.Total...: 25559 MB (limited to 9584 MB allocatable in one block)
          Memory.Free....: 12779 MB
          Memory.Unified.: 1
          Local.Memory...: 32 KB
          Phys.Location..: built-in
          Registry.ID....: 2495
          Max.TX.Rate....: N/A
          GPU.Properties.: headless 0, low-power 0, removable 0

        OpenCL Info:
        ============

        OpenCL Platform ID #1
          Vendor..: Apple
          Name....: Apple
          Version.: OpenCL 1.2 (Aug  8 2026 15:27:26)

          Backend Device ID #02 (Alias: #01)
            Type...........: GPU
            Vendor.ID......: 2
            Vendor.........: Apple
            Name...........: Apple M1 Pro
            Version........: OpenCL 1.2
            Processor(s)...: 16
            Preferred.Thrd.: 32
            Clock..........: 1000
            Memory.Total...: 25559 MB (limited to 2396 MB allocatable in one block)
            Memory.Free....: 12779 MB
            Memory.Unified.: 1
            Local.Memory...: 32 KB
            OpenCL.Version.: OpenCL C 1.2
            Driver.Version.: 1.2 1.0
        """;

    [Fact]
    public void MetalDeviceIsParsedAndSkippedWhileOpenClExists()
    {
        var devs = HashcatTool.ParseDevices(AppleSiliconInfo);
        Assert.Equal(2, devs.Count);

        var metal = devs[0];
        Assert.Equal(1, metal.Id);
        Assert.Equal(2, metal.AliasOf);
        Assert.Equal("Metal", metal.Backend);
        Assert.True(metal.IsMetal);
        Assert.Equal("382.5.3", metal.BackendVersion);
        Assert.Equal("GPU", metal.Type);
        Assert.Equal("Apple M1 Pro", metal.Name);
        Assert.Equal(16, metal.Processors);
        Assert.Equal(0, metal.ClockMhz);          // "N/A"
        Assert.Equal(25559, metal.MemoryMb);
        // hashcat disables Metal when an OpenCL device exists ...
        Assert.True(metal.IsSkippedAlias);

        // ... so the OpenCL alias is the device that runs, although it is the higher-numbered one.
        var ocl = devs[1];
        Assert.Equal("OpenCL", ocl.Backend);
        Assert.Equal(1, ocl.AliasOf);
        Assert.Equal(1000, ocl.ClockMhz);
        Assert.False(ocl.IsSkippedAlias);
    }

    [Fact]
    public void MetalDeviceRunsWhenThereIsNoOpenCl()
    {
        var metalOnly = AppleSiliconInfo[..AppleSiliconInfo.IndexOf("OpenCL Info:", StringComparison.Ordinal)]
            .Replace(" (Alias: #02)", "");
        var d = Assert.Single(HashcatTool.ParseDevices(metalOnly));
        Assert.True(d.IsMetal);
        Assert.False(d.IsSkippedAlias);
    }

    [Fact]
    public void CudaKeepsWinningOverItsOpenClAlias()
    {
        const string text = """
            CUDA Info:
            ==========

            CUDA.Version.: 12.4

            Backend Device ID #01 (Alias: #02)
              Name...........: NVIDIA GeForce RTX 3080
              Processor(s)...: 68
              Clock..........: 1710
              Memory.Total...: 10239 MB

            OpenCL Info:
            ============

            OpenCL Platform ID #1
              Vendor..: NVIDIA Corporation
              Name....: NVIDIA CUDA
              Version.: OpenCL 3.0 CUDA 12.4.89

              Backend Device ID #02 (Alias: #01)
                Type...........: GPU
                Name...........: NVIDIA GeForce RTX 3080
            """;
        var devs = HashcatTool.ParseDevices(text);
        Assert.False(devs[0].IsSkippedAlias);
        Assert.True(devs[1].IsSkippedAlias);
    }

    [Fact]
    public void DeviceSelectionOnAppleSiliconUsesTheOpenClDevice()
    {
        var devs = HashcatTool.ParseDevices(AppleSiliconInfo);
        // Unchecking another device builds -d from the devices hashcat actually uses.
        var s = new Settings { DisabledDevices = [99] };
        Assert.Equal(["-d", "2", "--backend-ignore-cuda", "--backend-ignore-hip"], HashcatRunner.DeviceArguments(s, devs));
        // There is a GPU, so the GPU-first default adds nothing.
        Assert.Equal(["--backend-ignore-cuda", "--backend-ignore-hip"], HashcatRunner.DeviceArguments(new Settings(), devs));
    }

    [Fact]
    public void KeepGuessingRunsUseTheMetalDevice()
    {
        // Apple's OpenCL breaks hashcat's --keep-guessing after the first hit; Metal does not.
        var devs = HashcatTool.ParseDevices(AppleSiliconInfo);
        Assert.Equal(["-d", "1", "--backend-ignore-cuda", "--backend-ignore-hip"], HashcatRunner.DeviceArguments(new Settings(), devs, preferMetal: true));
        Assert.Equal(["-D", "2", "-d", "1", "--backend-ignore-cuda", "--backend-ignore-hip"], HashcatRunner.DeviceArguments(new Settings(), devs, gpuOnly: true, preferMetal: true));
    }

    [Theory]
    [InlineData(12500, true, true)]
    [InlineData(23700, true, true)]
    [InlineData(13000, true, true)]
    [InlineData(10700, true, true)]
    [InlineData(17230, true, true)]
    [InlineData(18600, true, false)]
    [InlineData(12500, false, false)]
    [InlineData(13000, false, false)]
    public void EveryFormatAvoidsOpenClOnlyOnMacOS(int mode, bool isMacOS, bool expected)
        => Assert.Equal(expected, HashcatRunner.MustAvoidAppleOpenCl(mode, isMacOS));

    [Fact]
    public void ZipHeaderFilterRunsOnMetalOnMacOS()
    {
        var devs = HashcatTool.ParseDevices(AppleSiliconInfo);
        var args = HashcatRunner.GpuArguments(new Settings(), devs, 17230);
        if (OperatingSystem.IsMacOS())
        {
            Assert.Equal(["-D", "2", "-d", "1", "--backend-ignore-cuda", "--backend-ignore-hip", "--backend-ignore-opencl"], args);
            Assert.Equal([devs.First(d => d.IsMetal).Key], ZipCheckBytesTarget.ActiveDevices(new Settings(), devs).Select(d => d.Key));
        }
        else Assert.DoesNotContain("--backend-ignore-opencl", args);
    }

    [Fact]
    public void MetalOnlyArgumentsReplaceEveryGpuAndCloseOpenCl()
    {
        var devs = HashcatTool.ParseDevices(AppleSiliconInfo);
        Assert.Equal(["-d", "1", "--backend-ignore-cuda", "--backend-ignore-hip", "--backend-ignore-opencl"],
            HashcatRunner.MetalOnlyArguments(new Settings(), devs));
        Assert.Equal(["-D", "2", "-d", "1", "--backend-ignore-cuda", "--backend-ignore-hip", "--backend-ignore-opencl"],
            HashcatRunner.MetalOnlyArguments(new Settings(), devs, gpuOnly: true));
        // A measured choice of the OpenCL device is mapped to its Metal device as well.
        var openCl = devs.First(d => d.IsGpu && !d.IsMetal);
        var measured = new Settings { GpuPerformanceChoice = new() { DeviceKeys = [openCl.Key] } };
        var args = HashcatRunner.MetalOnlyArguments(measured, devs);
        Assert.Equal("1", args[args.IndexOf("-d") + 1]);
        Assert.Contains("--backend-ignore-opencl", args);
        // Unknown devices: hashcat still cannot open OpenCL, so it fails instead of skipping candidates.
        Assert.Contains("--backend-ignore-opencl", HashcatRunner.MetalOnlyArguments(new Settings(), null));
        // hashcat reaches the processor only through OpenCL.
        Assert.DoesNotContain("--backend-ignore-opencl", HashcatRunner.MetalOnlyArguments(new Settings { Strategy = DeviceStrategy.CpuOnly }, devs));
    }

    [Fact]
    public void CpuOnlyIsFlaggedWhenHashcatHasNoCpuDevice()
    {
        var devs = HashcatTool.ParseDevices(AppleSiliconInfo);
        Assert.True(HashcatRunner.NoCpuDevice(new Settings { Strategy = DeviceStrategy.CpuOnly }, devs));
        Assert.False(HashcatRunner.NoCpuDevice(new Settings { Strategy = DeviceStrategy.GpuOnly }, devs));
        var withCpu = devs.Append(new BackendDevice { Id = 3, Type = "CPU", Backend = "OpenCL" }).ToList();
        Assert.False(HashcatRunner.NoCpuDevice(new Settings { Strategy = DeviceStrategy.CpuOnly }, withCpu));
    }

    // ---------------------------------------------------------------- bundled hashcat

    private sealed class TempDir : IDisposable
    {
        public string Path { get; } = Directory.CreateTempSubdirectory("rk-mac").FullName;
        public void Dispose()
        {
            try { Directory.Delete(Path, true); } catch (IOException) { }
        }
    }

    /// <summary>A fake RecoverKit.app with Contents/MacOS and Contents/Resources/hashcat.</summary>
    private static (string MacOs, string Bundle) MakeApp(string root, string stamp)
    {
        var macOs = Directory.CreateDirectory(System.IO.Path.Combine(root, "RecoverKit.app", "Contents", "MacOS")).FullName;
        var bundle = Directory.CreateDirectory(System.IO.Path.Combine(root, "RecoverKit.app", "Contents", "Resources", "hashcat")).FullName;
        File.WriteAllText(System.IO.Path.Combine(bundle, HashcatInstaller.ExeName), "#!/bin/sh\necho v7.1.2\n");
        Directory.CreateDirectory(System.IO.Path.Combine(bundle, "modules"));
        File.WriteAllText(System.IO.Path.Combine(bundle, "modules", "module_00000.so"), "x");
        Directory.CreateDirectory(System.IO.Path.Combine(bundle, "kernels"));
        File.WriteAllText(System.IO.Path.Combine(bundle, "kernels", "stale.kernel"), "x");
        File.WriteAllText(System.IO.Path.Combine(bundle, HashcatInstaller.BundleStampFile), stamp + "\n");
        if (!OperatingSystem.IsWindows())
            File.SetUnixFileMode(System.IO.Path.Combine(bundle, "hashcat"),
                UnixFileMode.UserRead | UnixFileMode.UserExecute | UnixFileMode.GroupRead | UnixFileMode.GroupExecute | UnixFileMode.OtherRead | UnixFileMode.OtherExecute);
        return (macOs, bundle);
    }

    [Fact]
    public void BundleIsFoundBesideContentsMacOs()
    {
        using var t = new TempDir();
        var (macOs, bundle) = MakeApp(t.Path, "7.1.2-1");
        Assert.Equal(System.IO.Path.GetFullPath(bundle), HashcatInstaller.FindBundle(macOs + System.IO.Path.DirectorySeparatorChar));

        // A plain hashcat folder without the stamp is not treated as the app bundle.
        File.Delete(System.IO.Path.Combine(bundle, HashcatInstaller.BundleStampFile));
        Assert.Null(HashcatInstaller.FindBundle(macOs));
    }

    [Fact]
    public void BundleIsCopiedWithExecutableBitsAndRecopiedWhenTheStampChanges()
    {
        using var t = new TempDir();
        var (_, bundle) = MakeApp(t.Path, "7.1.2-1");
        var inst = new HashcatInstaller(System.IO.Path.Combine(t.Path, "engines"));

        Assert.True(inst.BundleNeedsInstall(bundle));
        var stages = new List<string>();
        Assert.True(inst.TryInstallBundledHere(bundle, new SyncProgress(p => stages.Add(p.Stage)), default));
        Assert.Contains("copy", stages);
        Assert.Equal("done", stages[^1]);

        var exe = System.IO.Path.Combine(inst.ExpectedDirectory, OperatingSystem.IsWindows() ? "hashcat.exe" : "hashcat");
        Assert.True(File.Exists(exe));
        Assert.True(File.Exists(System.IO.Path.Combine(inst.ExpectedDirectory, "modules", "module_00000.so")));
        Assert.False(Directory.Exists(System.IO.Path.Combine(inst.ExpectedDirectory, "kernels")));
        Assert.False(Directory.Exists(inst.ExpectedDirectory + ".partial"));
        if (!OperatingSystem.IsWindows())
        {
            var mode = File.GetUnixFileMode(exe);
            Assert.True(mode.HasFlag(UnixFileMode.UserExecute));
            Assert.True(mode.HasFlag(UnixFileMode.OtherExecute));
            Assert.True(mode.HasFlag(UnixFileMode.UserWrite));   // so a later update can replace it
        }
        Assert.False(inst.BundleNeedsInstall(bundle));

        // hashcat's own output in the engines copy, then a newer app version.
        File.WriteAllText(System.IO.Path.Combine(inst.ExpectedDirectory, "hashcat.log"), "x");
        File.WriteAllText(System.IO.Path.Combine(bundle, HashcatInstaller.BundleStampFile), "7.1.2-2\n");
        Assert.True(inst.BundleNeedsInstall(bundle));
        Assert.True(inst.TryInstallBundledHere(bundle, null, default));
        Assert.Equal("7.1.2-2", HashcatInstaller.ReadStamp(inst.ExpectedDirectory));
        Assert.False(File.Exists(System.IO.Path.Combine(inst.ExpectedDirectory, "hashcat.log")));
    }

    [Fact]
    public void NoBundleMeansNothingToInstall()
    {
        using var t = new TempDir();
        var inst = new HashcatInstaller(System.IO.Path.Combine(t.Path, "engines"));
        Assert.False(inst.BundleNeedsInstall(null));
        Assert.False(inst.TryInstallBundledHere(null, null, default));
    }

    [Fact]
    public void LocatePrefersTheEnginesCopyAndNeverRunsInsideTheBundle()
    {
        if (!OperatingSystem.IsMacOS()) return;
        using var t = new TempDir();
        var (macOs, bundle) = MakeApp(t.Path, "7.1.2-1");
        var engines = System.IO.Path.Combine(t.Path, "engines");

        // Not installed yet: the bundle itself must not be returned (PATH may still offer another hashcat).
        var before = HashcatTool.Locate(null, macOs, engines);
        Assert.True(before is null || !before.Exe.StartsWith(bundle, StringComparison.Ordinal));
        // Even when configured explicitly.
        var configured = HashcatTool.Locate(System.IO.Path.Combine(bundle, "hashcat"), macOs, engines);
        Assert.True(configured is null || !configured.Exe.StartsWith(bundle, StringComparison.Ordinal));

        var inst = new HashcatInstaller(engines);
        Assert.True(inst.TryInstallBundledHere(bundle, null, default));
        var after = HashcatTool.Locate(null, macOs, engines);
        Assert.NotNull(after);
        Assert.Equal(System.IO.Path.Combine(inst.ExpectedDirectory, "hashcat"), after.Exe);
    }

    [Fact]
    public void MacOsDataAndLogFoldersFollowApplePlatformConventions()
    {
        if (!OperatingSystem.IsMacOS() || Settings.IsRelocated) return;
        var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        Assert.Equal(System.IO.Path.Combine(home, "Library", "Application Support", "RecoverKit"), Settings.AppDataDir);
        Assert.Equal(System.IO.Path.Combine(home, "Library", "Logs", "RecoverKit"), DebugLog.Directory);
    }

    /// <summary>IProgress that reports synchronously (Progress&lt;T&gt; posts to the thread pool).</summary>
    private sealed class SyncProgress(Action<InstallProgress> report) : IProgress<InstallProgress>
    {
        public void Report(InstallProgress value) => report(value);
    }
}
