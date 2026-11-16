using RecoverKit.Core.Hashcat;
using RecoverKit.Core;
using Xunit;

namespace RecoverKit.Tests;

public class PdfKernelBenchmarkTests
{
    [Fact]
    public void UnselectedNvidiaGpuDoesNotBlockAnotherGpu()
    {
        BackendDevice[] devices = [new() { Id = 1, Type = "GPU", Backend = "CUDA" }, new() { Id = 2, Type = "GPU", Backend = "OpenCL", Vendor = "AMD" }];
        Assert.Equal([devices[1]], PdfKernelBenchmark.SelectDevices(devices, NvidiaBackend.OpenCl, new HashSet<int> { 2 }));
        Assert.Throws<InvalidOperationException>(() => PdfKernelBenchmark.SelectDevices(devices, NvidiaBackend.OpenCl, new HashSet<int> { 1 }));
        Assert.Equal(devices, PdfKernelBenchmark.SelectDevices(devices, NvidiaBackend.Automatic, null));
    }

    private const string Status = """
        Speed.#01........: 900.0 kH/s (50.0ms) @ Accel:64 Loops:70 Thr:32 Vec:1
        Speed.#01........: 1.1 MH/s (50.0ms) @ Accel:64 Loops:70 Thr:32 Vec:1
        Speed.#01........: 1.2 MH/s (50.0ms) @ Accel:64 Loops:70 Thr:32 Vec:1
        Speed.#01........: 1.4 MH/s (50.0ms) @ Accel:64 Loops:70 Thr:32 Vec:1
        Speed.#01........: 1.6 MH/s (50.0ms) @ Accel:64 Loops:70 Thr:32 Vec:1
        """;

    [Fact]
    public void LiveSpeedDiscardsWarmupAndUsesTheMedian()
        => Assert.Equal(1_400_000, PdfKernelBenchmark.ParseSpeed(4, Status, false));

    [Theory]
    [InlineData(-1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(254)]
    public void FailedOrInterruptedRunsCannotProduceASpeed(int exitCode)
        => Assert.Equal(0, PdfKernelBenchmark.ParseSpeed(exitCode, Status, false));

    [Fact]
    public void BenchmarkRequiresSuccessAndDoesNotDiscardItsSingleSample()
    {
        Assert.Equal(0, PdfKernelBenchmark.ParseSpeed(4, Status, true));
        Assert.Equal(900_000, PdfKernelBenchmark.ParseSpeed(0, Status.Split('\n')[0], true));
        Assert.Equal(0, PdfKernelBenchmark.ParseSpeed(0, "self-test failed", true));
    }
}
