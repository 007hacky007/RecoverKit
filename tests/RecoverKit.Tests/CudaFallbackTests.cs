using RecoverKit.Core;
using RecoverKit.Core.Attacks;
using RecoverKit.Core.Dependencies;
using RecoverKit.Core.Hashcat;
using Xunit;

namespace RecoverKit.Tests;

/// <summary>A CUDA Toolkit newer than the NVIDIA driver, as on a tester's RTX 4060 (driver CUDA 13.3, toolkit 13.5).</summary>
[Collection("CudaFallback")]
public class CudaFallbackTests : IDisposable
{
    // hashcat -I of that PC; the driver version is made unique so other tests never match the fallback key.
    private const string Info = """
        CUDA Info:
        ==========

        CUDA.Version.: 13.3

        Backend Device ID #01 (Alias: #02)
          Name...........: NVIDIA GeForce RTX 4060
          Processor(s)...: 24
          Preferred.Thrd.: 32
          Clock..........: 2460
          Memory.Total...: 8187 MB
          Memory.Free....: 7106 MB
          Memory.Unified.: 0
          Local.Memory...: 99 KB
          Cache.Size.....: 24 MB
          PCI.Addr.BDFe..: 0000:01:00.0

        OpenCL Info:
        ============

        OpenCL Platform ID #1
          Vendor..: NVIDIA Corporation
          Name....: NVIDIA CUDA
          Version.: OpenCL 3.0 CUDA 13.3.80

          Backend Device ID #02 (Alias: #01)
            Type...........: GPU
            Vendor.ID......: 32
            Vendor.........: NVIDIA Corporation
            Name...........: NVIDIA GeForce RTX 4060
            Version........: OpenCL 3.0 CUDA
            Processor(s)...: 24
            Preferred.Thrd.: 32
            Clock..........: 2460
            Memory.Total...: 8187 MB (limited to 2046 MB allocatable in one block)
            Memory.Free....: 7106 MB
            Memory.Unified.: 0
            Local.Memory...: 48 KB
            OpenCL.Version.: OpenCL C 1.2
            Driver.Version.: 999.17
            PCI.Addr.BDF...: 01:00.0

        OpenCL Platform ID #2
          Vendor..: Advanced Micro Devices, Inc.
          Name....: AMD Accelerated Parallel Processing
          Version.: OpenCL 2.1 AMD-APP (3652.0)

          Backend Device ID #03
            Type...........: GPU
            Vendor.ID......: 1
            Vendor.........: Advanced Micro Devices, Inc.
            Name...........: AMD Radeon(TM) Graphics
            Version........: OpenCL 2.0 AMD-APP (3652.0)
            Processor(s)...: 1
            Preferred.Thrd.: 32
            Clock..........: 2200
            Memory.Total...: 37109 MB (limited to 14901 MB allocatable in one block)
            Memory.Free....: 37012 MB
            Memory.Unified.: 1
            Local.Memory...: 64 KB
            OpenCL.Version.: OpenCL C 2.0
            Driver.Version.: 3652.0 (PAL,LC)
            PCI.Addr.BDF...: 75:00.0
        """;

    private const string LinkFailure = """
        hashcat could not compile the attack kernel. Check the compute driver and compiler installation.
        cuLinkAddData(): the provided PTX was compiled with an unsupported toolchain.
        • Device #1: Kernel C:\RecoverKit\hashcat/OpenCL/shared.cl link failed. Error Log:
        ptxas application ptx input, line 9; fatal   : Unsupported .version 9.5; current version is '9.3'
        • Device #1: Kernel C:\RecoverKit\hashcat/OpenCL/shared.cl build failed.
        """;

    private readonly string _dir = Directory.CreateTempSubdirectory("rk-cuda").FullName;
    private readonly List<BackendDevice> _devices = HashcatTool.ParseDevices(Info);

    public CudaFallbackTests() => CudaFallback.ResetForTests(Path.Combine(_dir, "cuda-fallback.json"));

    public void Dispose()
    {
        CudaFallback.ResetForTests(Path.Combine(Settings.AppDataDir, "cuda-fallback.json"));
        try { Directory.Delete(_dir, true); } catch (IOException) { }
    }

    private (HashcatRunner, RunRequest) Runner()
    {
        string exe = Path.Combine(_dir, HashcatInstaller.ExeName);
        File.WriteAllText(exe, "");
        return (new HashcatRunner(HashcatTool.Locate(exe)!) { KnownDevices = _devices, HashcatMajorVersion = 8 }, new RunRequest
        {
            Mode = 17200, HashFile = Path.Combine(_dir, "target.hash"), SessionName = "s", SessionDir = _dir,
            Attack = new PreparedAttack { Description = "mask", Args = { "-a", "3", "?l?l" } }, Settings = new Settings(),
        });
    }

    [Fact]
    public void ACudaLinkFailureSwitchesTheGpuToOpenCl()
    {
        var (runner, request) = Runner();
        Assert.DoesNotContain("--backend-ignore-cuda", HashcatRunner.DeviceArguments(new Settings(), _devices));
        var failed = runner.FailedCudaDevice(request, LinkFailure);
        Assert.Equal("CUDA", failed!.Backend);

        CudaFallback.Activate(_devices, "test");
        Assert.True(CudaFallback.IsActive(_devices));
        // Every GPU through OpenCL: the RTX 4060's OpenCL device and the Radeon.
        Assert.Contains("--backend-ignore-cuda", HashcatRunner.DeviceArguments(new Settings(), _devices));
        Assert.Null(runner.FailedCudaDevice(request, LinkFailure));

        // A measured choice of the CUDA device selects its OpenCL twin, renumbered without CUDA.
        var cuda = _devices.Single(d => d.Backend == "CUDA");
        var measured = new Settings { GpuPerformanceChoice = new() { DeviceKeys = [cuda.Key] } };
        var args = HashcatRunner.DeviceArguments(measured, _devices);
        Assert.Equal("1", args[args.IndexOf("-d") + 1]);
        Assert.Contains("--backend-ignore-cuda", args);

        // Another driver (or RecoverKit version) tries CUDA again.
        var other = HashcatTool.ParseDevices(Info.Replace("999.17", "999.18"));
        Assert.False(CudaFallback.IsActive(other));
    }

    [Fact]
    public void BenchmarksNameTheBackendTheGpuRunsOn()
    {
        var cuda = _devices.Single(d => d.Backend == "CUDA");
        var settings = new Settings { GpuPerformanceChoice = new() { DeviceKeys = [cuda.Key] } };
        Assert.Equal("CUDA", HashcatRunner.RunningBackend(cuda, _devices));
        Assert.Equal("CUDA", HashcatRunner.GpuBackends(settings, _devices));

        CudaFallback.Activate(_devices, "test");
        Assert.Equal("OpenCL", HashcatRunner.RunningBackend(cuda, _devices));
        Assert.Equal("OpenCL", HashcatRunner.GpuBackends(settings, _devices));
    }

    [Fact]
    public void OtherBuildFailuresDoNotSwitch()
    {
        var (runner, request) = Runner();
        Assert.Null(runner.FailedCudaDevice(request, LinkFailure.Replace("Device #1", "Device #3")));
        Assert.Null(runner.FailedCudaDevice(request, "hashcat could not complete the attack (exit code 255)."));
    }

    [Fact]
    public void TheMessageSaysWhatHappenedAndWhatToDo()
    {
        string said = HashcatOutputDetails(LinkFailure);
        Assert.Contains("Unsupported .version 9.5", said);
        string message = HashcatRunner.CudaSwitchMessage("NVIDIA GeForce RTX 4060", said);
        Assert.Contains("switched it to OpenCL", message);
        Assert.Contains("Tools > Dependencies", message);
        Assert.Contains("no password is skipped", message);
    }

    private static string HashcatOutputDetails(string failure)
        => (string)typeof(HashcatRunner).Assembly.GetType("RecoverKit.Core.Hashcat.HashcatOutput")!
            .GetMethod("Details", System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.NonPublic)!.Invoke(null, [failure])!;

    private string Toolkit(string name, string dll, string builtins)
    {
        var dir = Directory.CreateDirectory(Path.Combine(_dir, name)).FullName;
        File.WriteAllText(Path.Combine(dir, dll), "");
        File.WriteAllText(Path.Combine(dir, builtins), "");
        return dir;
    }

    [Fact]
    public void HashcatDoesNotSeeACompilerNewerThanTheDriver()
    {
        var root = Directory.CreateDirectory(Path.Combine(_dir, "cuda135")).FullName;
        var x64 = Directory.CreateDirectory(Path.Combine(root, "bin", "x64")).FullName;
        File.WriteAllText(Path.Combine(x64, "nvrtc64_130_0.dll"), "");
        File.WriteAllText(Path.Combine(x64, "nvrtc-builtins64_135.dll"), "");
        var old = Toolkit("cuda124", "nvrtc64_120_0.dll", "nvrtc-builtins64_124.dll");
        var own = Toolkit("nvrtc-12.8.93", "nvrtc64_120_0.dll", "nvrtc-builtins64_128.dll");
        var plain = Directory.CreateDirectory(Path.Combine(_dir, "tools")).FullName;
        char sep = Path.PathSeparator;
        Dictionary<string, string?> Env() => new() { ["PATH"] = string.Join(sep, x64, old, plain), ["CUDA_PATH"] = root };

        var env = Env();
        NvrtcRuntime.ApplyTo(env, (13, 3), null);
        Assert.Equal(string.Join(sep, old, plain), env["PATH"]);
        Assert.False(env.ContainsKey("CUDA_PATH"));

        // RecoverKit's own compiler is then the only one hashcat sees.
        env = Env();
        NvrtcRuntime.ApplyTo(env, (13, 3), own);
        Assert.Equal(string.Join(sep, own, plain), env["PATH"]);

        // A driver older than RecoverKit's compiler keeps a toolkit it can use instead.
        env = Env();
        NvrtcRuntime.ApplyTo(env, (12, 4), own);
        Assert.Equal(string.Join(sep, old, plain), env["PATH"]);

        // Unknown driver: nothing is judged.
        env = Env();
        NvrtcRuntime.ApplyTo(env, null, null);
        Assert.Equal(string.Join(sep, x64, old, plain), env["PATH"]);
        Assert.Equal(root, env["CUDA_PATH"]);
    }

    [Fact]
    public void TheDependenciesPageNamesTheToolkitAndOffersRecoverKitsCompiler()
    {
        var facts = new MachineFacts
        {
            IsWindows = true, HashcatExe = "hashcat.exe", HashcatIsManaged = true, HashcatVersion = "v8.0.0", BundleAvailable = true,
            Devices = _devices.Where(d => d.Backend != "CUDA").ToList(), NvidiaDriverPresent = true, NvidiaDriverCuda = (13, 3),
            NvrtcTooNew = [(@"C:\Program Files\NVIDIA GPU Computing Toolkit\CUDA\v13.5\bin\x64", (13, 5))],
        };
        var row = DependencyCheck.Evaluate(facts).Single(i => i.Id == DependencyId.Nvrtc);
        Assert.Equal(Light.Yellow, row.Light);
        Assert.Equal(DependencyAction.DownloadNvrtc, row.Action);
        Assert.Contains("CUDA Toolkit 13.5", row.Reason);
        Assert.Contains("CUDA 13.3", row.Reason);

        var switched = DependencyCheck.Evaluate(facts with { Devices = _devices, NvrtcTooNew = [], CudaFallbackReason = "Unsupported .version 9.5" })
            .Single(i => i.Id == DependencyId.Nvrtc);
        Assert.Equal(Light.Yellow, switched.Light);
        Assert.Contains("run through OpenCL", switched.Reason);
    }
}
