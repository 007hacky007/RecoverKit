using RecoverKit.Core;
using RecoverKit.Core.Diagnostics;
using RecoverKit.Core.Hashcat;
using Xunit;

namespace RecoverKit.Tests;

public class HybridBenchmarkDevicesTests
{
    private static BackendDevice Device(int id, string key, int? alias = null, bool integrated = false) => new()
    {
        Id = id, Key = key, AliasOf = alias, IsSkippedAlias = alias is not null,
        Name = "Synthetic GPU", Type = "GPU", Backend = alias is null ? "HIP" : "OpenCL",
        BackendVersion = "backend-version", DriverVersion = "driver-version", Vendor = "vendor",
        Processors = 16, ClockMhz = 1000, MemoryMb = 2048, Unified = integrated,
    };

    private static DiagnosticMeasurement Row(string key, double speed, int repeat, bool baseline = false) => new()
    {
        Section = "gpu", Mode = 13000, Target = "synthetic matching fixture", Length = 0,
        Engine = "gpu", Variant = "default", DeviceKey = key, Repeat = repeat,
        Correct = true, Speed = speed, Details = new() { ["Default"] = baseline.ToString() },
    };

    private static string[][] Keys(List<List<BackendDevice>> groups) => groups.Select(g => g.Select(d => d.Key).ToArray()).ToArray();

    [Fact]
    public void ClearAlternateWinnerAddsForcedAliasWithoutChangingOriginal()
    {
        BackendDevice[] devices = [Device(1, "hip"), Device(2, "opencl", 1)];
        DiagnosticMeasurement[] rows = [Row("opencl", 140, 1), Row("opencl", 142, 2), Row("hip", 100, 1, true), Row("hip", 102, 2, true)];
        var groups = HybridBenchmarkDevices.Groups(new Settings(), devices, 13000, rows);
        Assert.Equal([["hip"], ["opencl"]], Keys(groups));
        var forced = groups[1][0];
        Assert.NotSame(devices[1], forced);
        Assert.False(forced.IsSkippedAlias);
        Assert.True(devices[1].IsSkippedAlias);
        Assert.Equal(devices[1].Id, forced.Id);
        Assert.Equal(devices[1].AliasOf, forced.AliasOf);
        Assert.Equal("Synthetic GPU", forced.Name);
        Assert.Equal("OpenCL", forced.Backend);
        Assert.Equal("backend-version", forced.BackendVersion);
        Assert.Equal("driver-version", forced.DriverVersion);
        Assert.Equal("vendor", forced.Vendor);
        Assert.Equal(16, forced.Processors);
        Assert.Equal(1000, forced.ClockMhz);
        Assert.Equal(2048, forced.MemoryMb);
        Assert.Equal("GPU", forced.Type);
        Assert.False(forced.Unified);
    }

    [Fact]
    public void NoisyPairRetainsDefaultWithoutDuplicatingGroup()
    {
        BackendDevice[] devices = [Device(1, "hip"), Device(2, "opencl", 1)];
        DiagnosticMeasurement[] rows = [Row("hip", 100, 1, true), Row("hip", 102, 2, true), Row("opencl", 110, 1), Row("opencl", 103, 2)];
        Assert.Equal([["hip"]], Keys(HybridBenchmarkDevices.Groups(new Settings(), devices, 13000, rows)));
    }

    [Fact]
    public void AliasesAreNeverAddedToTheSamePhysicalGroup()
    {
        BackendDevice[] devices = [Device(1, "hip"), Device(2, "opencl", 1), Device(3, "other-gpu")];
        DiagnosticMeasurement[] rows = [Row("hip", 100, 1, true), Row("hip", 100, 2, true), Row("opencl", 120, 1), Row("opencl", 120, 2)];
        Assert.Equal([["hip", "other-gpu"], ["opencl", "other-gpu"]], Keys(HybridBenchmarkDevices.Groups(new Settings(), devices, 13000, rows)));
    }

    [Fact]
    public void DisabledDeviceAndDisabledAliasStayOut()
    {
        BackendDevice[] devices = [Device(1, "hip"), Device(2, "opencl", 1), Device(3, "disabled-gpu")];
        var settings = new Settings { DisabledDeviceKeys = ["opencl", "disabled-gpu"] };
        DiagnosticMeasurement[] rows = [Row("hip", 100, 1, true), Row("hip", 100, 2, true), Row("opencl", 200, 1), Row("opencl", 200, 2), Row("disabled-gpu", 300, 1, true), Row("disabled-gpu", 300, 2, true)];
        Assert.Equal([["hip"]], Keys(HybridBenchmarkDevices.Groups(settings, devices, 13000, rows)));
    }

    [Fact]
    public void MixedGpusIncludeCurrentAndPreferredDiscreteSubsets()
    {
        BackendDevice[] devices = [Device(1, "discrete"), Device(2, "discrete-alias", 1), Device(3, "integrated", integrated: true)];
        DiagnosticMeasurement[] rows = [Row("discrete", 100, 1, true), Row("discrete", 100, 2, true), Row("discrete-alias", 130, 1), Row("discrete-alias", 130, 2)];
        Assert.Equal([["discrete", "integrated"], ["discrete"], ["discrete-alias", "integrated"], ["discrete-alias"]],
            Keys(HybridBenchmarkDevices.Groups(new Settings { DeviceSelectionExplicit = true }, devices, 13000, rows)));
    }

    [Fact]
    public void PreviousProfileSuppliesBackendWhenModeWasNotMeasured()
    {
        BackendDevice[] devices = [Device(1, "hip"), Device(2, "opencl", 1)];
        var previous = new PerformanceProfile { Decisions = [new() { Domain = "gpu", Mode = 13000, Scope = "hip", DeviceKeys = ["opencl"], Engine = "gpu", Margin = .2 }] };
        Assert.Equal([["hip"], ["opencl"]], Keys(HybridBenchmarkDevices.Groups(new Settings(), devices, 13000, [], previous)));
        var unrelated = Row("hip", 100, 1, true); unrelated.Mode = 17210;
        Assert.Equal([["hip"], ["opencl"]], Keys(HybridBenchmarkDevices.Groups(new Settings(), devices, 13000, [unrelated], previous)));
    }

    [Fact]
    public void IncompleteCurrentMeasurementsDoNotUseOldBackendWinner()
    {
        BackendDevice[] devices = [Device(1, "hip"), Device(2, "opencl", 1)];
        var previous = new PerformanceProfile { Decisions = [new() { Domain = "gpu", Mode = 13000, Scope = "hip", DeviceKeys = ["opencl"], Engine = "gpu", Margin = .2 }] };
        DiagnosticMeasurement[] rows = [Row("hip", 100, 1, true), Row("hip", 100, 2, true), Row("opencl", 200, 1)];
        Assert.Equal([["hip"]], Keys(HybridBenchmarkDevices.Groups(new Settings(), devices, 13000, rows, previous)));
    }

    [Fact]
    public void MissingDefaultMarkerCannotEstablishBackendAdvantage()
    {
        BackendDevice[] devices = [Device(1, "hip"), Device(2, "opencl", 1)];
        DiagnosticMeasurement[] rows = [Row("hip", 100, 1), Row("hip", 100, 2), Row("opencl", 200, 1), Row("opencl", 200, 2)];
        Assert.Equal([["hip"]], Keys(HybridBenchmarkDevices.Groups(new Settings(), devices, 13000, rows)));
    }
}
