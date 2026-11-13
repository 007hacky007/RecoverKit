namespace RecoverKit.Core.Hashcat;

/// <summary>hashcat prints optional runtime advice on stderr alongside actual attack failures.</summary>
internal static class HashcatOutput
{
    internal static bool IsStartupAdvice(string line) => Has(line,
        "Failed to initialize the AMD main driver HIP runtime library", "Failed to initialize AMD HIP RTC library",
        "Failed to initialize the NVIDIA main driver CUDA runtime library", "Failed to initialize NVIDIA RTC library",
        "Successfully initialized", "Please install the AMD HIP SDK", "Could not open libamdhip", "Could not open libhiprtc",
        "CUDA SDK Toolkit", "Falling back to OpenCL", "The NVIDIA RTC library", "Install the Windows build of it",
        "Windows and the version of it", "WSL2", "Linux CUDA Toolkit", "hashcat.net/faq/wrongdriver",
        "developer.nvidia.com/cuda-downloads", "docs.nvidia.com/cuda/wsl-user-guide", "Metal 4 setup failed");

    internal static bool IsCudaCompilerAdvice(string line) => Has(line,
        "NVIDIA main driver CUDA runtime library", "NVIDIA RTC library", "CUDA SDK Toolkit",
        "Falling back to OpenCL runtime", "Install the Windows build of it", "Windows and the version of it",
        "WSL2", "Linux CUDA Toolkit", "hashcat.net/faq/wrongdriver", "developer.nvidia.com/cuda-downloads",
        "docs.nvidia.com/cuda/wsl-user-guide");

    internal static bool NeedsCudaCompilerHint(string line)
        => Has(line, "CUDA SDK Toolkit not installed", "Failed to initialize NVIDIA RTC library");

    private static bool IsTargetFailure(string text)
        => Has(text, "No hashes loaded", "Token length exception", "Separator unmatched", "Signature unmatched", "could not read the hash");
    private static bool IsSelfTestFailure(string text) => Has(text, "self-test", "self test");
    private static bool IsBuildFailure(string text)
        => Has(text, "build failed", "build failure", "CL_BUILD_PROGRAM_FAILURE", "clBuildProgram()", "nvrtcCompileProgram()",
            "hiprtcCompileProgram()", "failed to create metal library", "kernel build", "kernel compile", "could not compile");
    private static bool IsMemoryFailure(string text)
        => Has(text, "Not enough allocatable", "out of memory", "OUT_OF_MEMORY", "MEM_OBJECT_ALLOCATION_FAILURE", "allocation failed", "could not allocate enough");
    private static bool IsDeviceFailure(string text)
        => Has(text, "No devices", "No OpenCL, HIP or CUDA compatible platform", "No OpenCL-compatible", "Skipping (hash-mode", "could not find a usable compute device");

    internal static bool IsTransientFailure(string? text)
    {
        if (text is null || IsTargetFailure(text) || IsSelfTestFailure(text) || IsBuildFailure(text) ||
            IsMemoryFailure(text) || IsDeviceFailure(text) || Has(text, "syntax error")) return false;
        // Retry runtime execution failures only; invalid arguments and kernel compilation need a fix.
        return Has(text, "Metal 4 command buffer failed", "Metal command buffer failed", "MTLCommandBufferErrorDomain",
            "MTL4CommandQueueErrorDomain", "CL_OUT_OF_RESOURCES", "CL_DEVICE_NOT_AVAILABLE", "CL_OUT_OF_HOST_MEMORY",
            "CUDA_ERROR_LAUNCH_FAILED", "CUDA_ERROR_LAUNCH_TIMEOUT", "CUDA_ERROR_ILLEGAL_ADDRESS", "CUDA_ERROR_UNKNOWN",
            "hipErrorLaunchFailure", "hipErrorLaunchTimeOut", "hipErrorIllegalAddress", "hipErrorUnknown");
    }

    internal static string FailureMessage(IEnumerable<string> output, int exitCode)
    {
        var lines = output.Where(l => !string.IsNullOrWhiteSpace(l) && !l.StartsWith('{') && !IsStartupAdvice(l)).ToList();
        var errors = lines.Where(l => Has(l, "error", "failed", "failure", "cannot", "no devices", "no hashes", "not enough", "not found",
            "Skipping (hash-mode", "CL_OUT_OF", "CL_DEVICE_NOT_AVAILABLE", "hipError", "exception", "unmatched")).ToList();
        string all = string.Join(Environment.NewLine, lines);
        string reason = IsTargetFailure(all) ? "hashcat could not read the hash for this file." :
            IsSelfTestFailure(all) ? "hashcat's kernel self-test failed. Check the GPU driver before trying again." :
            IsBuildFailure(all) ? "hashcat could not compile the attack kernel. Check the compute driver and compiler installation." :
            IsMemoryFailure(all) ? "hashcat could not allocate enough device memory for this attack." :
            IsDeviceFailure(all) ? "hashcat could not find a usable compute device. Check the GPU driver and device selection in Preferences." :
            IsTransientFailure(all) ? "The GPU stopped processing the attack because its compute runtime failed." :
            $"hashcat could not complete the attack (exit code {exitCode}).";
        var detailsLines = (errors.Count > 0 ? errors : lines).TakeLast(12).ToList();
        string? primary = lines.FirstOrDefault(l => IsTargetFailure(all) ? IsTargetFailure(l) :
            IsSelfTestFailure(all) ? IsSelfTestFailure(l) : IsBuildFailure(all) ? IsBuildFailure(l) :
            IsMemoryFailure(all) ? IsMemoryFailure(l) : IsDeviceFailure(all) && IsDeviceFailure(l));
        if (primary is not null && !detailsLines.Contains(primary)) detailsLines.Insert(0, primary);
        string details = string.Join(Environment.NewLine, detailsLines);
        return details.Length > 0 ? reason + Environment.NewLine + details : reason;
    }

    private static bool Has(string text, params string[] parts)
        => parts.Any(p => text.Contains(p, StringComparison.OrdinalIgnoreCase));
}
