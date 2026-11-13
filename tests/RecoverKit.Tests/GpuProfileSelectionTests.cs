using RecoverKit.Core;
using RecoverKit.Core.Diagnostics;
using RecoverKit.Core.Hashcat;
using Xunit;

namespace RecoverKit.Tests;

public class GpuProfileSelectionTests
{
    private static BackendDevice Device(int id, string key, int? alias = null, bool skipped = false) => new()
    {
        Id = id, Key = key, AliasOf = alias, IsSkippedAlias = skipped,
        Type = "GPU", Name = "Same model", Backend = alias is null ? "CUDA" : "OpenCL",
    };

    private static PerformanceDecision Choice(string family, string key, bool? optimized = true) => new()
    {
        Domain = "gpu", Scope = family, Mode = 13000, Length = 0,
        Engine = "gpu", Variant = "default", DeviceKeys = [key], Optimized = optimized,
    };

    [Fact]
    public void AliasCycleHasOneStableFamily()
    {
        BackendDevice[] devices = [Device(4, "z", 7), Device(7, "a", 4, true), Device(9, "other")];
        Assert.Equal("a", GpuProfileSelection.FamilyKey("z", devices));
        Assert.Equal("a", GpuProfileSelection.FamilyKey("a", devices.Reverse().ToArray()));
        Assert.Equal("other", GpuProfileSelection.FamilyKey("other", devices));
    }

    [Fact]
    public void MeasuredAliasKeepsTheOtherPhysicalGpu()
    {
        BackendDevice[] devices = [Device(1, "a-cuda"), Device(2, "a-opencl", 1, true), Device(3, "b-cuda")];
        var profile = new PerformanceProfile { Decisions = [Choice("a-cuda", "a-opencl")] };
        var selected = GpuProfileSelection.ForAttack(profile, new Settings(), devices, 13000, 7);
        Assert.Equal(["a-opencl", "b-cuda"], selected!.DeviceKeys);
        Assert.True(selected.Optimized);
    }

    [Fact]
    public void MissingMeasuredDeviceFallsBackWhileOtherChoiceStillApplies()
    {
        BackendDevice[] devices = [Device(1, "a-cuda"), Device(2, "a-opencl", 1, true), Device(3, "b-cuda")];
        var profile = new PerformanceProfile { Decisions = [Choice("a-cuda", "a-opencl"), Choice("b-cuda", "missing")] };
        Assert.Equal(["a-opencl", "b-cuda"], GpuProfileSelection.ForAttack(profile, new Settings(), devices, 13000, 7)!.DeviceKeys);
    }

    [Fact]
    public void SameModelDevicesWithoutAliasLinksStaySeparate()
    {
        BackendDevice[] devices = [Device(1, "cuda-first"), Device(2, "cuda-second")];
        Assert.Equal("cuda-first", GpuProfileSelection.FamilyKey("cuda-first", devices));
        Assert.Equal("cuda-second", GpuProfileSelection.FamilyKey("cuda-second", devices));
        var profile = new PerformanceProfile { Decisions = [Choice("cuda-first", "cuda-first")] };
        Assert.Equal(["cuda-first", "cuda-second"], GpuProfileSelection.ForAttack(profile, new Settings(), devices, 13000, 7)!.DeviceKeys);
    }

    [Fact]
    public void DisabledPhysicalGpuIsNotAddedBack()
    {
        BackendDevice[] devices = [Device(1, "a-cuda"), Device(2, "a-opencl", 1, true), Device(3, "b-cuda")];
        var profile = new PerformanceProfile { Decisions = [Choice("a-cuda", "a-opencl"), Choice("b-cuda", "b-cuda")] };
        var settings = new Settings { DisabledDeviceKeys = ["b-cuda"] };
        Assert.Equal(["a-opencl"], GpuProfileSelection.ForAttack(profile, settings, devices, 13000, 7)!.DeviceKeys);
    }

    [Fact]
    public void DisabledMeasuredAliasUsesCurrentBackend()
    {
        BackendDevice[] devices = [Device(1, "a-cuda"), Device(2, "a-opencl", 1, true), Device(3, "b-cuda")];
        var profile = new PerformanceProfile { Decisions = [Choice("a-cuda", "a-opencl"), Choice("b-cuda", "b-cuda")] };
        var settings = new Settings { DisabledDeviceKeys = ["a-opencl"] };
        Assert.Equal(["a-cuda", "b-cuda"], GpuProfileSelection.ForAttack(profile, settings, devices, 13000, 7)!.DeviceKeys);
    }

    [Fact]
    public void ExplicitStrategyKeepsUserChoice()
    {
        BackendDevice[] devices = [Device(1, "cuda")];
        var profile = new PerformanceProfile { Decisions = [Choice("cuda", "cuda")] };
        Assert.Null(GpuProfileSelection.ForAttack(profile, new Settings { PerformanceStrategyExplicit = true }, devices, 13000, 7));
    }

    [Fact]
    public void ConflictingKernelChoiceDoesNotChangeOtherGpu()
    {
        BackendDevice[] devices = [Device(1, "a"), Device(2, "b")];
        var profile = new PerformanceProfile { Decisions = [Choice("a", "a", false)] };
        Assert.Null(GpuProfileSelection.ForAttack(profile, new Settings(), devices, 13000, 7));
        profile.Decisions.Add(Choice("b", "b", false));
        Assert.False(GpuProfileSelection.ForAttack(profile, new Settings(), devices, 13000, 7)!.Optimized);
    }

    [Fact]
    public void WrongModeOrFamilyCannotSelectAnAlias()
    {
        BackendDevice[] devices = [Device(1, "a-cuda"), Device(2, "a-opencl", 1, true)];
        var wrongMode = Choice("a-cuda", "a-opencl"); wrongMode.Mode = 17210;
        var wrongFamily = Choice("another-gpu", "a-opencl");
        var profile = new PerformanceProfile { Decisions = [wrongMode, wrongFamily] };
        Assert.Null(GpuProfileSelection.ForAttack(profile, new Settings(), devices, 13000, 7));
    }
    [Fact]
    public void BackendChoiceAppliesToOtherMaskLengthsOfTheSameFormat()
    {
        BackendDevice[] devices = [Device(1, "a-cuda"), Device(2, "a-opencl", 1, true)];
        var measured = Choice("a-cuda", "a-opencl"); measured.Length = 5;
        var profile = new PerformanceProfile { Decisions = [measured] };
        Assert.Equal(["a-opencl"], GpuProfileSelection.ForAttack(profile, new Settings(), devices, 13000, 7)!.DeviceKeys);
    }

}
