using RecoverKit.Core;
using RecoverKit.Core.Attacks;
using RecoverKit.Core.Diagnostics;
using RecoverKit.Core.Hashcat;
using RecoverKit.Core.Native;
using Xunit;

namespace RecoverKit.Tests;

public class ProfileSettingsTests
{
    [Fact]
    public void MeasuredCpuChoiceReachesPlanWithoutChangingPreferences()
    {
        var settings = new Settings();
        var device = new BackendDevice { Id = 1, Name = "Synthetic GPU", Type = "GPU", Backend = "OpenCL", Key = "gpu" };
        var profile = new PerformanceProfile { Decisions = [new() { Domain = "execution", Mode = 17210, Length = 7, Engine = "cpu", Variant = "cpu", Threads = 3 }] };
        var applied = ProfileSettings.ForAttack(settings, profile, [device], 17210, 7, NativeKernels.BenchmarkHashes[17210]);
        var attack = new PreparedAttack { Description = "Synthetic" }; attack.Args.AddRange(["-a", "3", "?u?u?u?u?u?u?u"]);
        Assert.NotNull(NativeRunner.Plan(17210, NativeKernels.BenchmarkHashes[17210], attack, applied, [device]));
        Assert.Null(HybridRunner.Plan(17210, NativeKernels.BenchmarkHashes[17210], attack, applied, [device]));
        Assert.Null(settings.PerformanceChoice);
        Assert.Equal(DeviceStrategy.GpuOnly, settings.Strategy);
    }

    [Fact]
    public void MeasuredHybridWorkerCountReachesScheduler()
    {
        var settings = new Settings { PerformanceChoice = new() { Engine = "hybrid", Threads = 2 } };
        Assert.Equal(Math.Min(2, Environment.ProcessorCount), HybridRunner.CpuThreads(settings, [], true));
        settings.MaxCpuThreads = 1;
        Assert.Equal(1, HybridRunner.CpuThreads(settings, [], true));
    }

    [Fact]
    public void ProfileCanSelectAliasButDisabledDeviceWins()
    {
        var gpu = new BackendDevice { Id = 1, Type = "GPU", Key = "physical" };
        var alias = new BackendDevice { Id = 2, Type = "GPU", Key = "alias", AliasOf = 1, IsSkippedAlias = true };
        var settings = new Settings { GpuPerformanceChoice = new() { DeviceKeys = ["alias"] } };
        var args = HashcatRunner.DeviceArguments(settings, [gpu, alias]);
        Assert.Contains("2", args);
        settings.DisabledDeviceKeys.Add("alias");
        args = HashcatRunner.DeviceArguments(settings, [gpu, alias]);
        Assert.DoesNotContain("2", args);
    }

    [Fact]
    public void ProfileReusesClosestMeasuredLengthForTheFormat()
    {
        var settings = new Settings();
        var profile = new PerformanceProfile { Decisions = [new() { Domain = "execution", Mode = 17210, Length = 7, Engine = "cpu", Threads = 3 }] };
        Assert.Equal("cpu", ProfileSettings.ForAttack(settings, profile, [], 17210, 4, "synthetic").PerformanceChoice?.Engine);
    }
    [Fact]
    public void FailedDefaultUsesCheckedScalarFallback()
    {
        var preferences = new Settings();
        var profile = new PerformanceProfile { FailedCpuVariants = new() { [17210] = [PerformanceProfiles.DefaultZipVariant()] } };
        var applied = ProfileSettings.ForAttack(preferences, profile, [], 17210, 7, NativeKernels.BenchmarkHashes[17210]);
        if (PerformanceProfiles.DefaultZipVariant() == "managed-scalar") Assert.False(applied.UseNativeCpuEngine);
        else Assert.Equal("managed-scalar", applied.CpuPerformanceChoice?.Variant);
        Assert.True(preferences.UseNativeCpuEngine);
    }

    [Fact]
    public void TemporaryGpuKernelSelectionRestoresAllSources()
    {
        var dir = Directory.CreateTempSubdirectory("rk-profile-kernel-").FullName;
        try
        {
            string sources = Directory.CreateDirectory(Path.Combine(dir, "OpenCL")).FullName;
            foreach (var (name, content) in HashcatKernels.Sources)
            {
                File.WriteAllText(Path.Combine(sources, name), content);
                if (name.StartsWith('m')) File.WriteAllText(Path.Combine(sources, name + ".hashcat"), "synthetic original");
            }
            string exe = Path.Combine(dir, "hashcat"); File.WriteAllText(exe, "");
            var tool = HashcatTool.Locate(exe)!;
            using (HashcatKernels.ApplyProfile(tool, 17210, "hashcat"))
                Assert.All(HashcatKernels.KernelFiles, name => Assert.Equal("synthetic original", File.ReadAllText(Path.Combine(sources, name))));
            foreach (var (name, content) in HashcatKernels.Sources) Assert.Equal(content, File.ReadAllText(Path.Combine(sources, name)));
            using (HashcatKernels.ApplyProfile(tool, 17210, "amplifier-cache"))
                Assert.Contains("#define RK_AMP_CACHE 1", File.ReadAllText(Path.Combine(sources, HashcatKernels.IncludeFile)));
            foreach (var (name, content) in HashcatKernels.Sources) Assert.Equal(content, File.ReadAllText(Path.Combine(sources, name)));
        }
        finally { Directory.Delete(dir, true); }
    }

    [Fact]
    public void TinyJobsKeepTheSchedulersCpuPath()
    {
        var settings = new Settings();
        var gpu = new BackendDevice { Id = 1, Type = "GPU", Key = "gpu" };
        var profile = new PerformanceProfile { Decisions = [new() { Domain = "execution", Mode = 17210, Length = 8, Engine = "gpu", DeviceKeys = ["gpu"] }] };
        var applied = ProfileSettings.ForAttack(settings, profile, [gpu], 17210, 8, NativeKernels.BenchmarkHashes[17210], candidates: 1);
        Assert.Null(applied.PerformanceChoice);
    }

    [Fact]
    public void CpuOnlyStrategyStillUsesTheMeasuredCpuVariant()
    {
        var choice = new PerformanceDecision { Domain = "cpu", Mode = 17210, Engine = "cpu", Variant = "managed-scalar", Threads = Environment.ProcessorCount };
        var settings = new Settings { Strategy = DeviceStrategy.CpuOnly, PerformanceStrategyExplicit = true };
        Assert.Same(choice, PerformanceProfiles.Apply(choice, settings, []));
    }

    [Fact]
    public void PowerPolicyChangesDropGpuChoicesWithoutDroppingCpuChoices()
    {
        var measured = new Settings();
        var changed = new Settings { GpuDutyPercent = 50 };
        var gpu = new PerformanceDecision { Domain = "gpu", Engine = "gpu", Policy = PerformanceProfiles.PolicyFingerprint(measured, "gpu") };
        var cpu = new PerformanceDecision { Domain = "cpu", Engine = "cpu", Policy = PerformanceProfiles.PolicyFingerprint(measured, "cpu") };
        Assert.Null(PerformanceProfiles.Apply(gpu, changed, []));
        Assert.Same(cpu, PerformanceProfiles.Apply(cpu, changed, []));
    }

    [Theory]
    [InlineData("failed at /Users/Example Person/Documents/private file.txt", "Example Person")]
    [InlineData(@"failed C:\Users\Another Person\private data\secret.zip", "Another Person")]
    [InlineData(@"failed \\Private Server\share\personal notes.txt", "Private Server")]
    public void ReportsRemoveSpacedAndNetworkPaths(string error, string privateName)
    {
        var report = new DiagnosticReport { Measurements = [new() { Error = error }] };
        string html = DiagnosticHtml.Render(report);
        Assert.DoesNotContain(privateName, html);
        Assert.DoesNotContain("file.txt", html);
        Assert.DoesNotContain("notes.txt", html);
        Assert.DoesNotContain("secret.zip", html);
    }

    [Fact]
    public void ResumeKeepsTheSavedEngineWhenProfileChanges()
    {
        string directory = Directory.CreateTempSubdirectory("rk-resume-profile-").FullName;
        try
        {
            File.WriteAllText(NativeRunner.RestoreFile(directory, "resume"), "{}");
            var settings = new Settings { PerformanceChoice = new() { Domain = "execution", Engine = "gpu" } };
            var resumed = ProfileSettings.PreserveResumeEngine(settings, 17210, directory, "resume");
            Assert.Equal("cpu", resumed.PerformanceChoice?.Engine);
            Assert.Equal("gpu", settings.PerformanceChoice.Engine);
        }
        finally { Directory.Delete(directory, true); }
    }

    [Fact]
    public void DictionaryAttacksUseMeasuredBackendWithoutCpuEngineChoice()
    {
        var gpu = new BackendDevice { Id = 1, Key = "cuda", Type = "GPU", Backend = "CUDA" };
        var profile = new PerformanceProfile { Decisions = [new() { Domain = "gpu", Scope = "cuda", Mode = 13000, Engine = "gpu", DeviceKeys = ["cuda"], Optimized = true }, new() { Domain = "execution", Mode = 13000, Engine = "cpu" }] };
        var settings = ProfileSettings.ForAttack(new Settings(), profile, [gpu], 13000, 0, "synthetic", maskAttack: false);
        Assert.NotNull(settings.GpuPerformanceChoice);
        Assert.Null(settings.PerformanceChoice);
        Assert.Null(settings.CpuPerformanceChoice);
    }

    [Fact]
    public void ExecutionChoiceKeepsItsMeasuredBackendAndKernelFlag()
    {
        BackendDevice[] devices = [new() { Id = 1, Key = "cuda", Type = "GPU" }, new() { Id = 2, Key = "opencl", Type = "GPU", AliasOf = 1, IsSkippedAlias = true }];
        string family = GpuProfileSelection.FamilyKey("cuda", devices);
        var profile = new PerformanceProfile { Decisions = [new() { Domain = "execution", Mode = 13000, Engine = "hybrid", DeviceKeys = ["cuda"], Optimized = true }, new() { Domain = "gpu", Scope = family, Mode = 13000, Engine = "gpu", DeviceKeys = ["opencl"], Optimized = false }] };
        var settings = ProfileSettings.ForAttack(new Settings(), profile, devices, 13000, 5, NativeKernels.BenchmarkHashes[13000]);
        Assert.Equal(["cuda"], settings.PerformanceChoice!.DeviceKeys);
        Assert.True(settings.PerformanceChoice.Optimized);
        Assert.Null(settings.GpuPerformanceChoice);
    }

}
