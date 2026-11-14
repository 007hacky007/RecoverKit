using RecoverKit.Core.Diagnostics;
using RecoverKit.Core.Native;
using RecoverKit.Core.Native.Kernels;
using Xunit;

namespace RecoverKit.Tests;

[Collection("NativeFeatures")]
public class WideCpuDiagnosticTests
{
    [Theory]
    [InlineData("failed", "self-test failed")]
    [InlineData("switched off", "switched off")]
    [InlineData("not run", "feature missing")]
    public void RequestedWideFallbackFailsWithoutTiming(string state, string reason)
    {
        var result = CpuDiagnosticWorker.EnforcePath(new(new(true, 30), 500, 1, "native AVX2", SelfTestState: state), "avx512");
        Assert.False(result.Check.Passed);
        Assert.Equal(0, result.Speed);
        Assert.Contains("AVX2", result.Error);
        Assert.Contains(reason, result.Error);
    }

    [Fact]
    public void MixedExecutionCannotMasqueradeAsWide()
    {
        var result = CpuDiagnosticWorker.EnforcePath(new(new(true, 30), 500, 1, "native AVX-512 + scalar fallback", SelfTestState: "passed"), "avx512");
        Assert.False(result.Check.Passed);
        Assert.Equal(0, result.Speed);
    }

    [Fact]
    public void FallbackAtTheCorrectnessGateIsNotTimed()
    {
        bool timed = false;
        var result = CpuDiagnostics.CheckThenMeasure(
            () => CpuDiagnosticWorker.EnforcePath(new(new(true, 30), 0, 0, "scalar fallback", SelfTestState: "passed"), "avx512").Check,
            () => { timed = true; return 500; });
        Assert.False(timed);
        Assert.False(result.Check.Passed);
        Assert.Equal(0, result.Speed);
    }

    [Fact]
    public void MatchingWidePathRetainsItsRate()
    {
        var result = CpuDiagnosticWorker.EnforcePath(new(new(true, 30), 500, 1, "native AVX-512", SelfTestState: "passed"), "avx512");
        Assert.True(result.Check.Passed);
        Assert.Equal(500, result.Speed);
    }

    [Fact]
    public void WideExecutionWithoutItsGuardCannotPass()
    {
        var result = CpuDiagnosticWorker.EnforcePath(new(new(true, 30), 500, 1, "native AVX-512", SelfTestState: "not run"), "avx512");
        Assert.False(result.Check.Passed);
        Assert.Equal(0, result.Speed);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(7)]
    [InlineData(26)]
    public void ChunkedRar3ReferenceMatchesExistingReference(int length)
    {
        var k = Rar3Kernel.TryParse(NativeKernels.BenchmarkHashes[12500])!;
        var pw = Enumerable.Range(0, length).Select(i => (byte)(i * 17 + 33)).ToArray();
        var (digest, iv) = k.ReferenceHash(pw);
        Assert.Equal([.. digest, .. iv], WideCpuChecks.Rar3Reference(pw, Convert.FromHexString("45109af8ab5f297a")));
    }

    [Fact]
    public void WideSupportRequiresTheNativeFeature()
    {
        Assert.False(KernelVariants.WideSupported("avx512", false, RkNative.Feature.Avx512));
        Assert.False(KernelVariants.WideSupported("avx512", true, RkNative.Feature.Avx2));
        Assert.True(KernelVariants.WideSupported("avx512", true, RkNative.Feature.Avx512));
        Assert.True(KernelVariants.WideSupported("avx2", true, RkNative.Feature.Avx2));
    }

    [Fact]
    public void UnsupportedWideVariantsHaveNoDiagnosticSteps()
    {
        var saved = RkNative.Features;
        try
        {
            RkNative.LimitFeatures(saved & ~(RkNative.Feature.Avx2 | RkNative.Feature.Avx512));
            var plan = new DiagnosticPlan();
            CpuDiagnostics.AddSteps(plan, new(), new(), true, default);
            Assert.DoesNotContain(plan.Steps, s => s.Label.Contains(", avx2,") || s.Label.Contains(", avx512,"));
        }
        finally { RkNative.LimitFeatures(saved); }
    }

    [Fact]
    public void WideChecksExerciseTheNativeHostPath()
    {
        if (!RkNative.HasVectorPath) return;
        Assert.True(WideCpuChecks.Check(12500).Passed);
        Assert.True(WideCpuChecks.Check(13000).Passed);
    }
}
