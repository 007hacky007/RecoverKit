using System.Text.Json;
using RecoverKit.Core;
using RecoverKit.Core.Diagnostics;
using RecoverKit.Core.Hashcat;
using Xunit;

namespace RecoverKit.Tests;

public sealed class FiniteDiagnosticWorkerTests
{
    [Fact]
    public void RequestContainsOnlySyntheticWorkloadAndNumericPreferences()
    {
        var settings = new Settings { ExtraArguments = "PRIVATE-EXTRA", DefaultDictionary = "PRIVATE-DICTIONARY", DataPath = "PRIVATE-DATA", ExecuteOnSuccess = "PRIVATE-COMMAND",
            GpuTempGuard = true, GpuTempLimit = 81, GpuDutyPercent = 50, Workload = 2, Priority = ProcessPriority.BelowNormal, GpuPowerLimit = true, GpuPowerWatts = new() { [0] = 100 } };
        var request = FiniteDiagnosticWorker.BuildRequest("isolated-engine", settings, [], 13000, 7, 5, 8);
        string json = JsonSerializer.Serialize(request);
        Assert.DoesNotContain("PRIVATE", json);
        Assert.DoesNotContain("ExtraArguments", json);
        Assert.DoesNotContain("Dictionary", json);
        Assert.Equal(81, request.Limits.GpuTempLimit);
        Assert.Equal(50, request.Limits.GpuDutyPercent);
        Assert.Equal(100, request.Limits.GpuPowerWatts[0]);
        Assert.Equal(7, request.Count);
    }

    [Fact]
    public void DeviceMetadataRoundTripRetainsStableKeyAndAliasState()
    {
        var device = new BackendDevice { Id = 2, Key = "OpenCL|Example GPU|1", Name = "Example GPU", Type = "GPU", Backend = "OpenCL", AliasOf = 1, IsSkippedAlias = false, Unified = true };
        var request = FiniteDiagnosticWorker.BuildRequest("isolated-engine", new Settings(), [device], 17210, 0, 8, 8);
        var restored = JsonSerializer.Deserialize<FiniteDiagnosticWorker.WorkerRequest>(JsonSerializer.Serialize(request))!.Devices[0].ToDevice();
        Assert.Equal(device.Key, restored.Key);
        Assert.False(restored.IsSkippedAlias);
        Assert.True(restored.IsIntegratedGpu);
        Assert.Equal(1, restored.AliasOf);
    }

    [Fact]
    public void NativeFailureAndInvalidResultsCannotBecomeEligible()
    {
        Assert.False(FiniteDiagnosticWorker.ReadResult(139, "{}").Correct);
        Assert.False(FiniteDiagnosticWorker.ReadResult(0, "not JSON").Correct);
        Assert.False(FiniteDiagnosticWorker.ReadResult(0, "{}").Correct);
        Assert.False(FiniteDiagnosticWorker.ReadResult(0, "{\"Correct\":true,\"Speed\":-1,\"ElapsedSeconds\":1}").Correct);
    }

    [Fact]
    public void FilteredCompletedJobResultIsAccepted()
    {
        var value = new FiniteDiagnosticWorker.Result { Correct = true, Speed = 100, ElapsedSeconds = 2, Details = new() { ["Engine speed 0 CPU"] = "100" } };
        var result = FiniteDiagnosticWorker.ReadResult(0, JsonSerializer.Serialize(value));
        Assert.True(result.Correct);
        Assert.Equal("100", result.Details["Engine speed 0 CPU"]);
    }
}
