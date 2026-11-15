using RecoverKit.Core.Diagnostics;
using RecoverKit.Core.Native;
using Xunit;

namespace RecoverKit.Tests;

[Collection("NativeFeatures")]
public sealed class Pbkdf2Sha1DiagnosticTests
{
    [Theory]
    [InlineData(13600)]
    [InlineData(22000)]
    public void Sha1ModesRegisterEverySelectablePath(int mode)
    {
        Assert.Equal(["default", "scalar", "avx2", "avx512", "neon", "arm-sha1"],
            KernelVariants.ForMode(mode).Select(v => v.Name));
    }

    [Theory]
    [InlineData(13600, 7)]
    [InlineData(22000, 8)]
    public void DefaultCandidateLengthRespectsFormatBounds(int mode, int length)
        => Assert.Equal(length, CpuDiagnostics.CandidateLength(mode));

    [Theory]
    [InlineData(13600)]
    [InlineData(22000)]
    public void ExplicitSha1PathOverridesMeasuredFeatureSelection(int mode)
    {
        if (!RkNative.Available) return;
        string? saved = Environment.GetEnvironmentVariable("RECOVERKIT_PBKDF2_SHA1_PATH");
        try
        {
            Environment.SetEnvironmentVariable("RECOVERKIT_PBKDF2_SHA1_PATH", "arm-sha1");
            var settings = new RecoverKit.Core.Settings { CpuPerformanceChoice = new() { Variant = "scalar" } };
            using var selection = ProfileSettings.CpuSelection(settings, mode);
            Assert.Null(selection);
        }
        finally { Environment.SetEnvironmentVariable("RECOVERKIT_PBKDF2_SHA1_PATH", saved); }
    }

    [Theory]
    [InlineData(13600)]
    [InlineData(22000)]
    public void KnownPasswordAndNativeLanesMatchScalarReference(int mode)
    {
        if (!RkNative.Available) return;
        foreach (var variant in KernelVariants.ForMode(mode).Where(v => v.Supported))
        {
            using var selected = KernelVariants.Select(mode, variant.Name);
            NativeKernels.ResetCpuPath(mode);
            var check = CpuDiagnostics.CheckKernel(mode, variant.Name);
            Assert.True(check.Passed, $"{mode}, {variant.Name}: {check.Error}");
            if (variant.Name == "default") continue;
            var result = CpuDiagnosticWorker.EnforcePath(new(check, 0, 0, NativeKernels.CpuPath(mode, actualOnly: true),
                SelfTestState: NativeKernels.WideSelfTestState(mode)), variant.Name);
            if (variant.Name == "avx512" && Environment.GetEnvironmentVariable("RECOVERKIT_PBKDF2_SHA1_AVX512") == "0")
                Assert.False(result.Check.Passed);
            else Assert.True(result.Check.Passed, $"{mode}, {variant.Name}: {result.Error}");
        }
    }

    [Theory]
    [InlineData(13600)]
    [InlineData(22000)]
    public void ScalarSelectionRestoresFeaturesAfterFailure(int mode)
    {
        if (!RkNative.Available) return;
        var saved = RkNative.Features;
        void FailingStep()
        {
            using var selected = KernelVariants.Select(mode, "scalar");
            Assert.Equal((RkNative.Feature)0, RkNative.Features & (RkNative.Feature.Avx2 | RkNative.Feature.Avx512 | RkNative.Feature.Neon | RkNative.Feature.ArmSha1));
            throw new InvalidOperationException("simulated diagnostic failure");
        }
        try
        {
            Assert.Throws<InvalidOperationException>(FailingStep);
        }
        finally { Assert.Equal(saved, RkNative.Features); }
    }

    [Theory]
    [InlineData("neon", "native scalar")]
    [InlineData("arm-sha1", "native NEON")]
    [InlineData("arm-sha1", "native ARM SHA-1 + scalar fallback")]
    public void RequestedSha1FallbackCannotPassOrKeepARate(string variant, string path)
    {
        var result = CpuDiagnosticWorker.EnforcePath(new(new(true, 30), 500, 1, path), variant);
        Assert.False(result.Check.Passed);
        Assert.Equal(0, result.Speed);
    }

    [Theory]
    [InlineData("neon", "native NEON")]
    [InlineData("arm-sha1", "native ARM SHA-1")]
    public void MatchingSha1PathPasses(string variant, string path)
        => Assert.True(CpuDiagnosticWorker.EnforcePath(new(new(true, 30), 0, 0, path), variant).Check.Passed);

    [Theory]
    [InlineData(13600)]
    [InlineData(22000)]
    public void Sha1ModesAppearInWideReportAndRequireNativeGuard(int mode)
    {
        var report = new DiagnosticReport { System = new() { ["AVX-512 available"] = "True", ["Logical threads"] = "1" } };
        report.Measurements = [new() { Section = "cpu", Mode = mode, Variant = "avx512", Threads = 1,
            Correct = true, Speed = 100, Length = mode == 22000 ? 8 : 7, Target = "synthetic",
            Details = new() { ["actual path"] = "native AVX-512", ["self-test state"] = "passed" } }];
        var row = report.WideVectorPaths.Rows.Single(r => r.Mode == mode);
        Assert.Equal(100d, row.SingleThread.Avx512.Median);
        Assert.Equal(mode == 22000 ? 8 : 7, row.Length);
        report.Measurements[0].Details["self-test state"] = "not run";
        Assert.Equal("FAIL", report.WideVectorPaths.Rows.Single(r => r.Mode == mode).Correctness);
    }

    [Theory]
    [InlineData(13600)]
    [InlineData(22000)]
    public void Sha1WideReportRejectsScalarFallback(int mode)
    {
        var report = new DiagnosticReport { System = new() { ["AVX-512 available"] = "True", ["Logical threads"] = "1" } };
        report.Measurements = [new() { Section = "cpu", Mode = mode, Variant = "avx512", Threads = 1,
            Correct = true, Speed = 100, Length = CpuDiagnostics.CandidateLength(mode), Target = "synthetic",
            Details = new() { ["actual path"] = "native scalar", ["self-test state"] = "passed" } }];
        var row = report.WideVectorPaths.Rows.Single(r => r.Mode == mode);
        Assert.Equal("FAIL", row.Correctness);
        Assert.Null(row.SingleThread.Avx512.Median);
        Assert.Contains("scalar", row.SingleThread.Avx512.Reason);
    }
}
