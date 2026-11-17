using RecoverKit.Core;
using RecoverKit.Core.Diagnostics;
using RecoverKit.Core.Native;
using Xunit;

namespace RecoverKit.Tests;

[Collection("NativeFeatures")]
public sealed class OfficeAgileDiagnosticTests
{
    [Theory]
    [InlineData(9500, "sha-ni", "arm-sha1")]
    [InlineData(9600, null, "arm-sha512")]
    public void DiagnosticsRegisterIndependentPaths(int mode, string? shaNi, string arm)
    {
        string[] expected = shaNi is null
            ? ["default", "scalar", "avx2", "avx512", "neon", arm]
            : ["default", "scalar", "avx2", "avx512", shaNi, "neon", arm];
        Assert.Equal(expected, KernelVariants.ForMode(mode).Select(v => v.Name));
        Assert.Contains(mode, DetailedBenchmarkRunner.HybridModes);
        Assert.Equal(7, MatchedSpeedProbe.LengthFor(mode));
    }

    [Theory]
    [InlineData(9500, "RECOVERKIT_OFFICE2010_PATH")]
    [InlineData(9600, "RECOVERKIT_OFFICE2013_PATH")]
    public void ExplicitOfficePathOverridesMeasuredSelection(int mode, string variable)
    {
        string? saved = Environment.GetEnvironmentVariable(variable);
        try
        {
            Environment.SetEnvironmentVariable(variable, "scalar");
            Assert.Null(ProfileSettings.CpuSelection(new Settings { CpuPerformanceChoice = new() { Variant = "avx2" } }, mode));
        }
        finally { Environment.SetEnvironmentVariable(variable, saved); }
    }

    [Theory]
    [InlineData(9500)]
    [InlineData(9600)]
    public void WideReportRequiresGuardAndExactPath(int mode)
    {
        var report = new DiagnosticReport { System = new() { ["AVX-512 available"] = "True", ["Logical threads"] = "1" } };
        report.Measurements = [new() { Section = "cpu", Mode = mode, Variant = "avx512", Threads = 1,
            Correct = true, Speed = 100, Length = 7, Target = "synthetic",
            Details = new() { ["actual path"] = "native AVX-512", ["self-test state"] = "passed" } }];
        Assert.Equal(100d, report.WideVectorPaths.Rows.Single(r => r.Mode == mode).SingleThread.Avx512.Median);
        report.Measurements[0].Details["self-test state"] = "not run";
        Assert.Equal("FAIL", report.WideVectorPaths.Rows.Single(r => r.Mode == mode).Correctness);
        report.Measurements[0].Details["self-test state"] = "passed";
        report.Measurements[0].Details["actual path"] = "native scalar";
        Assert.Equal("FAIL", report.WideVectorPaths.Rows.Single(r => r.Mode == mode).Correctness);
    }

    [Theory]
    [InlineData(9500)]
    [InlineData(9600)]
    public void EveryAvailableVariantMatchesTheIndependentReference(int mode)
    {
        if (!RkNative.Available) return;
        var saved = RkNative.Features;
        foreach (var variant in KernelVariants.ForMode(mode).Where(v => v.Supported))
        {
            using (KernelVariants.Select(mode, variant.Name))
            {
                NativeKernels.ResetCpuPath(mode);
                var check = CpuDiagnostics.CheckKernel(mode, variant.Name);
                Assert.True(check.Passed, $"{variant.Name}: {check.Error}");
                if (variant.Name != "default")
                {
                    var result = CpuDiagnosticWorker.EnforcePath(new(check, 0, 0, NativeKernels.CpuPath(mode, actualOnly: true),
                        SelfTestState: NativeKernels.WideSelfTestState(mode)), variant.Name);
                    Assert.True(result.Check.Passed, $"{variant.Name}: {result.Error}");
                }
            }
            Assert.Equal(saved, RkNative.Features);
        }
    }
}
