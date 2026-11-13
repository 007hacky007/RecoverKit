using RecoverKit.Core.Diagnostics;
using Xunit;

namespace RecoverKit.Tests;

public class DiagnosticGpuErrorTests
{
    [Theory]
    [InlineData("Failed to load nvrtc64_120_0.dll", "NVRTC compiler unavailable")]
    [InlineData("Aborting session due to kernel self-test failure", "Kernel correctness self-test failed")]
    [InlineData("CL_BUILD_PROGRAM_FAILURE", "GPU kernel compilation failed")]
    [InlineData("Skipping (hash-mode 29331)", "Hash mode unsupported by this backend")]
    [InlineData("Not enough allocatable device memory for this attack", "Insufficient GPU memory or execution resources")]
    [InlineData("CL_OUT_OF_RESOURCES", "Insufficient GPU memory or execution resources")]
    [InlineData("CL_PLATFORM_NOT_FOUND_KHR", "OpenCL platform unavailable")]
    [InlineData("CUDA_ERROR_SYSTEM_DRIVER_MISMATCH", "GPU driver or backend initialization failed")]
    [InlineData("No devices found/left", "No usable GPU device")]
    public void ClassifiesKnownFailuresWithoutReturningProcessText(string output, string category)
    {
        Assert.Equal(category + " (exit -1).", DiagnosticGpuError.Classify(output, "", -1));
    }

    [Fact]
    public void UnknownFailureNeverEchoesPathsHashesOrSecrets()
    {
        string error = "Internal issue in C:\\Users\\Tester\\private.hash, password=secret, $rar5$private";
        Assert.Equal("No successful benchmark rate; process details omitted (exit 255).", DiagnosticGpuError.Classify("", error, 255));
    }
}
