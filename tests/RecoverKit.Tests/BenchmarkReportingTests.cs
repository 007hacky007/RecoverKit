using RecoverKit.App.Ui;
using RecoverKit.Core;
using RecoverKit.Core.Diagnostics;
using RecoverKit.Core.Hashcat;
using Xunit;

namespace RecoverKit.Tests;

[Collection("CudaFallback")]
public sealed class BenchmarkReportingTests
{
    [Fact]
    public void SetupIncludesLimitsDisabledDevicesAndVerbatimExtras()
    {
        var gpu = new BackendDevice { Id = 1, Key = "OpenCL|GPU|0", Backend = "OpenCL", Type = "GPU", Name = "Test GPU", DriverVersion = "123.45" };
        var settings = new Settings { DisabledDeviceKeys = [gpu.Key], ExtraArguments = "--force  --kernel-loops 17", MaxCpuThreads = 3,
            Workload = 2, GpuDutyPercent = 50, GpuTempGuard = true, GpuTempLimit = 71, GpuTempHysteresis = 8,
            GpuPowerLimit = true, GpuPowerWatts = new() { [0] = 80 } };
        string setup = string.Join("\n", BenchmarkSetup.Lines(null, settings, [gpu]));
        Assert.Contains("RecoverKit version:", setup);
        Assert.Contains("hashcat version: unavailable", setup);
        Assert.Contains("Test GPU", setup);
        Assert.Contains("unticked", setup);
        Assert.Contains("123.45", setup);
        Assert.Contains("CPU threads: 3", setup);
        Assert.Contains("workload: 2", setup);
        Assert.Contains("71 C", setup);
        Assert.Contains("hysteresis 8 C", setup);
        Assert.Contains("50%", setup);
        Assert.Contains("80 W", setup);
        Assert.Contains("Extra arguments: --force  --kernel-loops 17", setup);
        Assert.Contains("Extra arguments disable the built-in CPU engine", setup);
    }

    [Fact]
    public void CudaDeviceShowsTheDriverVersionOfItsOpenClAlias()
    {
        // hashcat prints the NVIDIA driver version only on the OpenCL device.
        var cuda = new BackendDevice { Id = 1, Key = "CUDA|NVIDIA GeForce RTX 4060|0", Backend = "CUDA", Type = "GPU", Name = "NVIDIA GeForce RTX 4060", BackendVersion = "13.3" };
        var opencl = new BackendDevice { Id = 2, AliasOf = 1, Key = "OpenCL|NVIDIA GeForce RTX 4060|0", Backend = "OpenCL", Type = "GPU",
            Name = "NVIDIA GeForce RTX 4060", Vendor = "NVIDIA Corporation", DriverVersion = "610.88", IsSkippedAlias = true };
        var lines = BenchmarkSetup.Lines(null, new Settings(), [cuda, opencl]);
        string cudaLine = Assert.Single(lines, l => l.StartsWith("GPU #1 ", StringComparison.Ordinal));
        Assert.Contains("driver 610.88", cudaLine);
        Assert.DoesNotContain(lines, l => l.Contains("driver unknown", StringComparison.Ordinal));
    }

    [Fact]
    public void RowsRepeatOnlySettingsThatDifferFromTheSetup()
    {
        var settings = new Settings();
        var setup = BenchmarkSetup.Lines(null, settings, []);
        Assert.Contains(BenchmarkSetup.RowNote, setup);
        Assert.Empty(BenchmarkSetup.RowSettings(BenchmarkSetup.ExecutionLines(settings), setup));
        var changed = BenchmarkSetup.ExecutionLines(new Settings { Workload = 1 }).ToList();
        var shown = BenchmarkSetup.RowSettings(changed, setup).ToList();
        Assert.Contains(shown, l => l.Contains("workload: 1", StringComparison.Ordinal));
        Assert.True(shown.Count < changed.Count);
    }

    [Fact]
    public void RowArgumentsRetainTuningAndRemoveTargetsPathsAndUnknownValues()
    {
        string args = BenchmarkSetup.SafeArguments(["-m", "12500", "/private/target.hash", "-a", "3", "?u?u?u", "-d", "2", "-w", "4",
            "--session", "personal-name", "--potfile-path=/private/secrets", "--kernel-loops=19", "--force", "-O", "$RAR3$private"]);
        Assert.Equal("-m 12500 -a 3 -d 2 -w 4 --kernel-loops=19 --force -O", args);
        Assert.Equal("-d2 --self-test-disable --markov-disable --kernel-vector-width 4 --scrypt-tmto=2 --backend-ignore-nvml",
            BenchmarkSetup.SafeArguments(["-d2", "--self-test-disable", "--markov-disable", "--kernel-vector-width", "4", "--scrypt-tmto=2", "--backend-ignore-nvml"]));
    }

    [Fact]
    public void InvocationKeepsRetryArgumentsAfterLaterMetadataRequests()
    {
        var tool = HashcatTool.ForExe(Path.Combine(Path.GetTempPath(), "unused-hashcat"));
        using var invocation = new BenchmarkSetup.Invocation(tool);
        tool.StartInfo(["-m", "12500", "-d", "1", "-O", "--session", "private-session"]);
        tool.StartInfo(["-m", "12500", "-d", "1", "--backend-ignore-cuda", "--session", "private-session"]);
        tool.StartInfo(["-m", "12500", "--hash-info", "-O"]);
        Assert.Equal("-m 12500 -d 1 --backend-ignore-cuda", invocation.Safe);
    }

    [Fact]
    public async Task MissingExplicitBackendIsReportedAndGpuWorkIsSkipped()
    {
        var settings = new Settings { NvidiaBackend = NvidiaBackend.Cuda };
        var devices = new[] { new BackendDevice { Id = 1, Name = "NVIDIA Test GPU", Key = "OpenCL|Test|0", Type = "GPU", Backend = "OpenCL" } };
        var report = await new DetailedBenchmarkRunner(null, settings, devices) { Thorough = true }.RunAsync(["gpu"]);
        Assert.Contains(report.Setup, line => line.StartsWith("Backend unavailable:", StringComparison.Ordinal));
        Assert.Contains(report.Measurements, row => row.Error?.Contains("has no CUDA device", StringComparison.Ordinal) == true);
        Assert.DoesNotContain(report.Measurements, row => row.Correct);
    }

    [Fact]
    public void SetupIsVisibleInDetailedHtmlAndJsonWhileRowArgumentsRemainScrubbed()
    {
        const string extra = "Extra arguments: --custom-path /private/example <value>";
        var report = new DiagnosticReport { Setup = ["CPU threads: 3", extra], Measurements = [new() { Details = new() { ["hashcat arguments"] = "/private/secret.hash" } }] };
        string html = DiagnosticHtml.Render(report);
        Assert.Contains("<h2>Setup</h2>", html);
        Assert.Contains("CPU threads: 3", html);
        Assert.Contains("--custom-path /private/example &lt;value&gt;", html);
        Assert.DoesNotContain("/private/secret.hash", html);
    }

    [Fact]
    public void ExecutionMetadataNamesSelectedProfileWithoutShowingItsTarget()
    {
        var settings = new Settings { PerformanceChoice = new PerformanceDecision { Domain = "execution", Engine = "cpu", Variant = "avx2", Threads = 3,
            Reason = "confirmed CPU choice", Target = "$RAR3$private", Optimized = false } };
        string metadata = string.Join("\n", BenchmarkSetup.ExecutionLines(settings));
        Assert.Contains("execution", metadata);
        Assert.Contains("avx2", metadata);
        Assert.Contains("threads 3", metadata);
        Assert.Contains("confirmed CPU choice", metadata);
        Assert.DoesNotContain("$RAR3$", metadata);
    }

    [Fact]
    public void EngineFollowsActualDeviceFlagsAndIgnoredBackendRenumbering()
    {
        var devices = new List<BackendDevice>
        {
            new() { Id = 1, Name = "NVIDIA GPU", Backend = "CUDA", Type = "GPU" },
            new() { Id = 2, Name = "NVIDIA GPU", Backend = "OpenCL", Type = "GPU", AliasOf = 1 },
            new() { Id = 3, Name = "Processor", Backend = "OpenCL", Type = "CPU" },
        };
        string engine = BenchmarkSetup.Engine(new Settings(), devices, false, false, 0, arguments: ["-d", "1", "--backend-ignore-cuda"]);
        Assert.Contains("NVIDIA GPU (OpenCL)", engine);
        Assert.DoesNotContain("CPU (OpenCL)", engine);
        string defaultEngine = BenchmarkSetup.Engine(new Settings(), devices, false, false, 0, arguments: ["-m", "12500", "-b"]);
        Assert.DoesNotContain("CPU (OpenCL)", defaultEngine);
        Assert.Equal("hashcat, no matching device selected", BenchmarkSetup.Engine(new Settings(), devices, false, false, 0, arguments: ["-d", "99"]));
        Assert.Contains("CPU (OpenCL)", BenchmarkSetup.Engine(new Settings(), devices, false, false, 0, arguments: ["-D1"]));
    }

    [Fact]
    public void SetupShowsAutomaticIntegratedGpuExclusionAndResolution()
    {
        var devices = new List<BackendDevice>
        {
            new() { Id = 1, Name = "Discrete GPU", Backend = "OpenCL", Type = "GPU" },
            new() { Id = 2, Name = "Integrated GPU", Backend = "OpenCL", Type = "GPU", Unified = true },
        };
        string setup = string.Join("\n", BenchmarkSetup.Lines(null, new Settings(), devices));
        Assert.Contains("automatically excluded integrated GPU", setup);
        Assert.Contains("NVIDIA backend preference: Automatic", setup);
        Assert.Contains("Automatic resolved to: no NVIDIA GPU detected", setup);
    }

    [Fact]
    public void MacSetupNamesTheMetalFormatBackendWithoutExcludingItsAlias()
    {
        if (!OperatingSystem.IsMacOS()) return;
        var devices = new List<BackendDevice>
        {
            new() { Id = 1, AliasOf = 2, Name = "Apple Test GPU", Backend = "OpenCL", Type = "GPU", Unified = true },
            new() { Id = 2, AliasOf = 1, Name = "Apple Test GPU", Backend = "Metal", Type = "GPU", Unified = true },
        };
        var setup = BenchmarkSetup.Lines(null, new Settings(), devices);
        Assert.All(setup.Where(line => line.StartsWith("GPU #", StringComparison.Ordinal)), line => Assert.Contains("selected: #2 Metal", line));
        Assert.Contains(setup, line => line.Contains("mode 18600", StringComparison.Ordinal) && line.Contains("OpenCL", StringComparison.Ordinal));
    }

    [Fact]
    public void SetupShowsAutomaticFallbackReasonAndExplicitCudaResolution()
    {
        string directory = Directory.CreateTempSubdirectory("rk-setup-fallback-").FullName;
        try
        {
            CudaFallback.ResetForTests(Path.Combine(directory, "fallback.json"));
            var devices = new List<BackendDevice>
            {
                new() { Id = 1, AliasOf = 2, Name = "NVIDIA Test GPU", Key = "CUDA|Test|0", Type = "GPU", Backend = "CUDA", BackendVersion = "13.3", DriverVersion = "setup-test" },
                new() { Id = 2, AliasOf = 1, Name = "NVIDIA Test GPU", Key = "OpenCL|Test|0", Type = "GPU", Backend = "OpenCL", DriverVersion = "setup-test" },
            };
            CudaFallback.Activate(devices, "CUDA synthetic compile failure");
            string automatic = string.Join("\n", BenchmarkSetup.Lines(null, new Settings(), devices));
            Assert.Contains("Automatic resolved to: OpenCL", automatic);
            Assert.Contains("Automatic CUDA fallback: CUDA synthetic compile failure", automatic);
            Assert.Contains("selected: #2 OpenCL", automatic);
            Assert.Contains("CUDA version: 13.3", automatic);
            string explicitCuda = string.Join("\n", BenchmarkSetup.Lines(null, new Settings { NvidiaBackend = NvidiaBackend.Cuda }, devices));
            Assert.Contains("NVIDIA backend preference: CUDA", explicitCuda);
            Assert.Contains("selected: #1 CUDA", explicitCuda);
            Assert.DoesNotContain("Automatic CUDA fallback:", explicitCuda);
        }
        finally
        {
            CudaFallback.ResetForTests(Path.Combine(Settings.AppDataDir, "cuda-fallback.json"));
            Directory.Delete(directory, true);
        }
    }

    [Fact]
    public async Task QuickStandaloneBenchmarkPassesExtraArgumentsToHashcat()
    {
        if (OperatingSystem.IsWindows()) return;
        string directory = Directory.CreateTempSubdirectory("rk-benchmark-args-").FullName;
        try
        {
            string exe = Path.Combine(directory, "hashcat");
            await File.WriteAllTextAsync(exe, """
                #!/bin/sh
                case " $* " in
                  *" --version "*) echo v8.0.0; exit 0;;
                  *" --hash-info "*) echo '{}'; exit 0;;
                  *" -b "*|*" -B "*) printf '%s\n' "$@" > "$0.args"; echo '1:15700:1:1:1:123'; exit 0;;
                esac
                echo '{}'
                """);
            File.SetUnixFileMode(exe, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            var tool = HashcatTool.ForExe(exe);
            var settings = new Settings { UseNativeCpuEngine = false, OptimizedKernels = false,
                ExtraArguments = "--force --kernel-loops 17 -O --optimized-kernel-enable" };
            SpeedProbe.Details? details = null;
            var result = await SpeedProbe.MeasureAsync(tool, settings, [], 15700, TimeSpan.FromSeconds(1), default, measuredWith: d => details = d);
            var args = await File.ReadAllLinesAsync(exe + ".args");
            Assert.Equal(123, result.Speed);
            Assert.Contains("--force", args);
            Assert.Contains("17", args);
            Assert.DoesNotContain("-O", args);
            Assert.DoesNotContain("--optimized-kernel-enable", args);
            Assert.NotNull(details);
            Assert.Contains("--force --kernel-loops 17", details.Arguments);
            Assert.Contains("-B", details.Arguments);
            Assert.Equal("hashcat, no matching device selected", details.Engine);
        }
        finally { Directory.Delete(directory, true); }
    }
}
