using System.Diagnostics;
using RecoverKit.Core.Diagnostics;
using RecoverKit.Core.Native;
using RecoverKit.Core.Native.Kernels;
using Xunit;

namespace RecoverKit.Tests;

[Collection("NativeFeatures")]
public sealed class CpuDiagnosticWorkerTests
{
    [Fact]
    public void InvalidJsonAndNativeProcessFailureAreFailedChecks()
    {
        Assert.False(CpuDiagnosticWorker.ReadResult(0, "{not valid json").Check.Passed);
        Assert.False(CpuDiagnosticWorker.ReadResult(139, "").Check.Passed);
        Assert.Contains("139", CpuDiagnosticWorker.ReadResult(139, "").Error);
    }

    [Fact]
    public async Task NonzeroChildProcessExitBecomesARecordedFailure()
    {
        var start = new ProcessStartInfo(OperatingSystem.IsWindows() ? "cmd.exe" : "/bin/sh");
        start.ArgumentList.Add(OperatingSystem.IsWindows() ? "/c" : "-c");
        start.ArgumentList.Add("exit 7");
        var directory = Directory.CreateTempSubdirectory("rk-worker-test-");
        try
        {
            var result = await CpuDiagnosticWorker.RunProcessAsync(start, Path.Combine(directory.FullName, "missing.json"), TimeSpan.FromSeconds(1), CancellationToken.None);
            Assert.False(result.Check.Passed);
            Assert.Contains("7", result.Error);
        }
        finally { directory.Delete(true); }
    }

    [Fact]
    public async Task CancellationKillsChildAndLeavesParentSelectorsAlone()
    {
        int zip = ZipCryptoNative.RequestedPath;
        bool native = RkNative.Disabled;
        var start = new ProcessStartInfo(OperatingSystem.IsWindows() ? "cmd.exe" : "/bin/sleep");
        if (OperatingSystem.IsWindows()) { start.ArgumentList.Add("/c"); start.ArgumentList.Add("ping -n 30 127.0.0.1 > nul"); }
        else start.ArgumentList.Add("30");
        var directory = Directory.CreateTempSubdirectory("rk-worker-test-");
        try
        {
            using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(100));
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => CpuDiagnosticWorker.RunProcessAsync(start, Path.Combine(directory.FullName, "missing.json"), TimeSpan.FromSeconds(1), cts.Token));
            Assert.Equal(zip, ZipCryptoNative.RequestedPath);
            Assert.Equal(native, RkNative.Disabled);
        }
        finally { directory.Delete(true); }
    }

    [Fact]
    public void MissingAndImpossibleWorkerResultsAreRejected()
    {
        Assert.False(CpuDiagnosticWorker.ReadResult(0, "null").Check.Passed);
        Assert.False(CpuDiagnosticWorker.ReadResult(0, "{}").Check.Passed);
        Assert.False(CpuDiagnosticWorker.ReadResult(0, "{\"Check\":{\"Passed\":true,\"Cases\":0},\"Speed\":1}").Check.Passed);
    }
}
