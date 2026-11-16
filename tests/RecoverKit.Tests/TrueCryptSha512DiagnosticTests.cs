using RecoverKit.Core;
using RecoverKit.Core.Diagnostics;
using RecoverKit.Core.Native;
using Xunit;

namespace RecoverKit.Tests;

[Collection("NativeFeatures")]
public sealed class TrueCryptSha512DiagnosticTests
{
    [Theory]
    [InlineData(29321)]
    [InlineData(29322)]
    [InlineData(29323)]
    [InlineData(29421)]
    [InlineData(29422)]
    [InlineData(29423)]
    public void EveryModeExposesTheSameKdfPaths(int mode)
    {
        Assert.Equal(["default", "managed", "scalar", "avx2", "avx512", "neon", "arm-sha512"],
            KernelVariants.ForMode(mode).Select(v => v.Name));
        Assert.Contains(mode, DetailedBenchmarkRunner.HybridModes);
        Assert.Equal(7, MatchedSpeedProbe.LengthFor(mode));
        Assert.Equal(NativeKernels.BenchmarkHashes[mode], MatchedSpeedProbe.HashLine(mode));
    }

    [Fact]
    public void EachAvailableNativePathMatchesIndependentDigestAnswers()
    {
        if (!RkNative.Available) return;
        foreach (var variant in KernelVariants.ForMode(29321).Where(v => v.Supported && v.Name != "managed"))
        {
            using var selection = KernelVariants.Select(29321, variant.Name);
            NativeKernels.ResetCpuPath(29321);
            var check = CpuDiagnostics.CheckKernel(29321, variant.Name);
            Assert.True(check.Passed, $"{variant.Name}: {check.Error}");
            if (variant.Name == "default") continue;
            var result = CpuDiagnosticWorker.EnforcePath(new(check, 0, 0,
                NativeKernels.CpuPath(29321, actualOnly: true), SelfTestState: NativeKernels.WideSelfTestState(29321)), variant.Name);
            Assert.True(result.Check.Passed, result.Error);
        }
    }

    [Fact]
    public void VeraCryptProbeKeepsBatchesShortAndKeyspaceLarge()
    {
        var request = MatchedSpeedProbe.CreateRequest(29423, new Settings(), [], "probe", TimeSpan.FromSeconds(6), false);
        var args = request.Attack.Args.TakeWhile(arg => arg != "--runtime").ToArray();
        Assert.Equal(NativeKernels.BenchmarkMaskArguments(29423, 7), args);
        var space = MaskSpace.FromHashcatArgs(args)!;
        Assert.Equal("AB"u8.ToArray(), space.Positions[^1]);
        Assert.Equal(7, space.MaxLength);
        Assert.True(space.TotalKeyspace > long.MaxValue / 100000000);
    }

    [Theory]
    [InlineData("gpu", false)]
    [InlineData("hybrid", true)]
    public void TinyMasksKeepTheirMeasuredExecutionWinner(string engine, bool integrated)
    {
        RecoverKit.Core.Hashcat.BackendDevice[] devices = [new() { Id = 1, Key = "gpu", Type = "GPU", Unified = integrated }];
        var profile = new PerformanceProfile
        {
            Decisions = [new() { Domain = "execution", Mode = 29321, Length = 7, Engine = engine, DeviceKeys = ["gpu"] }],
        };
        var settings = ProfileSettings.ForAttack(new Settings(), profile, devices, 29321, 7,
            NativeKernels.BenchmarkHashes[29321], candidates: 1);
        Assert.Equal(engine, settings.PerformanceChoice?.Engine);
        var attack = new RecoverKit.Core.Attacks.PreparedAttack { Description = "tiny mask", Args = { "-a", "3", "ABCDEF?u" } };
        Assert.Equal(engine == "hybrid", HybridRunner.Plan(29321, NativeKernels.BenchmarkHashes[29321], attack, settings, devices) is not null);
    }

    [Fact]
    public void ExplicitEnvironmentPathOverridesProfileSelection()
    {
        string? saved = Environment.GetEnvironmentVariable("RECOVERKIT_PBKDF2_SHA512_PATH");
        try
        {
            Environment.SetEnvironmentVariable("RECOVERKIT_PBKDF2_SHA512_PATH", "scalar");
            Assert.Null(ProfileSettings.CpuSelection(new Settings { CpuPerformanceChoice = new() { Variant = "scalar" } }, 29321));
        }
        finally { Environment.SetEnvironmentVariable("RECOVERKIT_PBKDF2_SHA512_PATH", saved); }
    }

    [Theory]
    [InlineData("arm-sha512", "native NEON")]
    [InlineData("arm-sha512", "native scalar")]
    [InlineData("avx512", "native AVX2")]
    public void FallbackCannotKeepARequestedPathTiming(string variant, string path)
    {
        var result = CpuDiagnosticWorker.EnforcePath(new(new(true, 10), 1000, 1, path, SelfTestState: "passed"), variant);
        Assert.False(result.Check.Passed);
        Assert.Equal(0, result.Speed);
    }

    [Fact]
    public void WideReportRequiresActualAvx512AndPassingGuard()
    {
        var report = new DiagnosticReport { System = new() { ["AVX-512 available"] = "True", ["Logical threads"] = "1" } };
        report.Measurements = [new() { Section = "cpu", Mode = 29321, Variant = "avx512", Threads = 1,
            Correct = true, Speed = 100, Length = 7, Target = "known answer",
            Details = new() { ["actual path"] = "native AVX-512", ["self-test state"] = "passed" } }];
        Assert.Equal(100d, report.WideVectorPaths.Rows.Single(r => r.Mode == 29321).SingleThread.Avx512.Median);
        report.Measurements[0].Details["self-test state"] = "not run";
        Assert.Equal("FAIL", report.WideVectorPaths.Rows.Single(r => r.Mode == 29321).Correctness);
    }
}
