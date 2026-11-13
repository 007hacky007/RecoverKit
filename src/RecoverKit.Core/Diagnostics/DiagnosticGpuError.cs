namespace RecoverKit.Core.Diagnostics;

/// <summary>Reports useful GPU failure categories without copying private process output.</summary>
internal static class DiagnosticGpuError
{
    internal static string Classify(string output, string error, int exitCode)
    {
        string text = output + "\n" + error;
        bool Has(params string[] words) => words.Any(w => text.Contains(w, StringComparison.OrdinalIgnoreCase));
        string category;
        if (Has("self-test", "self test") && Has("failed", "failure", "error"))
            category = "Kernel correctness self-test failed";
        else if (Has("nvrtc") && Has("not found", "not installed", "not available", "unavailable", "missing", "failed to load", "cannot locate", "could not find"))
            category = "NVRTC compiler unavailable";
        else if (Has("CL_OUT_OF_RESOURCES", "CL_MEM_OBJECT_ALLOCATION_FAILURE", "out of memory", "not enough allocatable", "insufficient memory", "CUDA_ERROR_OUT_OF_MEMORY"))
            category = "Insufficient GPU memory or execution resources";
        else if (Has("CL_PLATFORM_NOT_FOUND", "no OpenCL platform", "OpenCL platform not found"))
            category = "OpenCL platform unavailable";
        else if (Has("DRIVER_MISMATCH", "driver version is insufficient", "failed to initialize", "driver initialization", "CUDA_ERROR_SYSTEM_NOT_READY", "CUDA_ERROR_UNKNOWN"))
            category = "GPU driver or backend initialization failed";
        else if (Has("CL_BUILD_PROGRAM_FAILURE", "kernel build failed", "compilation failed", "compiler error", "compiler runtime", "build program failed", "kernel compilation error"))
            category = "GPU kernel compilation failed";
        else if (Has("Skipping (hash-mode", "unsupported hash mode", "hash mode not supported", "not supported by this backend"))
            category = "Hash mode unsupported by this backend";
        else if (Has("No devices found", "No usable devices", "No devices left", "DEVICE_NOT_FOUND", "INVALID_DEVICE"))
            category = "No usable GPU device";
        else category = "No successful benchmark rate; process details omitted";
        return $"{category} (exit {exitCode}).";
    }
}
