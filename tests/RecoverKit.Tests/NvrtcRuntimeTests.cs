using System.IO.Compression;
using RecoverKit.Core.Hashcat;
using Xunit;

namespace RecoverKit.Tests;

public class NvrtcRuntimeTests
{
    private const string SmiBanner = """
        +-----------------------------------------------------------------------------------------+
        | NVIDIA-SMI 572.83                 Driver Version: 572.83         CUDA Version: 12.8     |
        |-----------------------------------------+------------------------+----------------------+
        """;

    [Fact]
    public void DriverCudaVersionIsReadFromTheBanner()
    {
        Assert.Equal((12, 8), NvrtcRuntime.ParseCudaVersion(SmiBanner));
        Assert.Equal((13, 0), NvrtcRuntime.DriverCudaVersion(() => (0, "| CUDA Version: 13.0 |")));
        Assert.Null(NvrtcRuntime.ParseCudaVersion("NVIDIA-SMI has failed"));
    }

    [Fact]
    public void TheNewestNvrtcTheDriverAcceptsIsChosen()
    {
        Assert.Equal("12.8.93", NvrtcRuntime.Choose((13, 0))!.Version);
        Assert.Equal("12.8.93", NvrtcRuntime.Choose((12, 8))!.Version);
        Assert.Equal("12.4.127", NvrtcRuntime.Choose((12, 7))!.Version);
        Assert.Equal("12.4.127", NvrtcRuntime.Choose((12, 4))!.Version);
        Assert.Null(NvrtcRuntime.Choose((12, 2)));
        Assert.Null(NvrtcRuntime.Choose((11, 8)));
        Assert.Null(NvrtcRuntime.Choose(null));
        foreach (var p in NvrtcRuntime.Packages)
        {
            Assert.StartsWith("https://files.pythonhosted.org/", p.Url);
            Assert.Equal(64, p.Sha256.Length);
        }
    }

    [Fact]
    public void OnlyTheTwoDllsAndTheLicenseAreUnpacked()
    {
        var dir = Directory.CreateTempSubdirectory("rk-nvrtc").FullName;
        try
        {
            var wheel = Path.Combine(dir, "w.whl");
            using (var z = ZipFile.Open(wheel, ZipArchiveMode.Create))
            {
                foreach (var name in new[]
                {
                    "nvidia/cuda_nvrtc/bin/__init__.py", "nvidia/cuda_nvrtc/bin/nvrtc-builtins64_128.dll",
                    "nvidia/cuda_nvrtc/bin/nvrtc64_120_0.alt.dll", "nvidia/cuda_nvrtc/bin/nvrtc64_120_0.dll",
                    "nvidia/cuda_nvrtc/include/nvrtc.h", "nvidia_cuda_nvrtc_cu12-12.8.93.dist-info/License.txt",
                })
                {
                    using var w = new StreamWriter(z.CreateEntry(name).Open());
                    w.Write(name);
                }
            }
            var outDir = Directory.CreateDirectory(Path.Combine(dir, "out")).FullName;
            NvrtcRuntime.ExtractWheel(wheel, outDir);
            Assert.Equal(["NVIDIA-LICENSE.txt", "nvrtc-builtins64_128.dll", "nvrtc64_120_0.dll"],
                Directory.GetFiles(outDir).Select(f => Path.GetFileName(f)!).Order(StringComparer.Ordinal).ToArray());
        }
        finally
        {
            try { Directory.Delete(dir, true); } catch (IOException) { }
        }
    }
}
