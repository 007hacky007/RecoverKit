using RecoverKit.Core.Attacks;
using RecoverKit.Core.Hashcat;
using Xunit;

namespace RecoverKit.Tests;

public sealed class CandidateExportTests
{
    [Fact]
    public async Task GeneratorFailsWhenHashcatCannotListCandidates()
    {
        if (OperatingSystem.IsWindows()) return;
        string dir = Directory.CreateTempSubdirectory("rk-export").FullName;
        try
        {
            var tool = FakeHashcat(dir, """
                echo 'clGetPlatformIDs(): CL_PLATFORM_NOT_FOUND_KHR' >&2
                echo 'ATTENTION! No OpenCL, HIP or CUDA compatible platform found.' >&2
                echo '* Intel and AMD CPUs require this runtime:' >&2
                exit 255
                """);
            string output = Path.Combine(dir, "out.txt");
            var ex = await Assert.ThrowsAsync<IOException>(() =>
                CandidateExport.WriteDictionaryAsync([Step(dir)], tool, output, CandidateExport.EncodingFor("UTF8"), null, CancellationToken.None));
            Assert.Contains("No OpenCL, HIP or CUDA compatible platform found.", ex.Message);
            Assert.Contains("Tools > Dependencies", ex.Message);
            Assert.Contains("exit code 255", ex.Message);
        }
        finally { Directory.Delete(dir, true); }
    }

    [Fact]
    public async Task GeneratorWritesEveryCandidateWhenHashcatSucceeds()
    {
        if (OperatingSystem.IsWindows()) return;
        string dir = Directory.CreateTempSubdirectory("rk-export").FullName;
        try
        {
            var tool = FakeHashcat(dir, "printf 'alpha\\nbeta\\n'\nexit 0");
            string output = Path.Combine(dir, "out.txt");
            long n = await CandidateExport.WriteDictionaryAsync([Step(dir)], tool, output, CandidateExport.EncodingFor("UTF8"), null, CancellationToken.None);
            Assert.Equal(2, n);
            Assert.Equal(["alpha", "beta"], await File.ReadAllLinesAsync(output));
        }
        finally { Directory.Delete(dir, true); }
    }

    [Fact]
    public void FailureMessageUsesTheFirstMeaningfulLine()
    {
        Assert.Equal("hashcat could not produce the candidates (exit code 254): /missing.txt: No such file or directory",
            CandidateExport.FailureMessage(254, "/missing.txt: No such file or directory\n\n"));
        Assert.Equal("hashcat could not produce the candidates (exit code 1).", CandidateExport.FailureMessage(1, ""));
    }

    private static PreparedAttack Step(string dir)
    {
        var step = new PreparedAttack { Description = "test" };
        step.Args.AddRange(["-a", "0", Path.Combine(dir, "words.txt")]);
        return step;
    }

    private static HashcatTool FakeHashcat(string dir, string body)
    {
        string exe = Path.Combine(dir, "hashcat");
        File.WriteAllText(exe, "#!/bin/sh\ncase \" $* \" in *\" --version \"*) echo v8.0.0; exit 0;; esac\n" + body + "\n");
        File.SetUnixFileMode(exe, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        return HashcatTool.Locate(exe, dir, dir)!;
    }
}
