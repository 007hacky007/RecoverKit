using RecoverKit.Core.Attacks;
using RecoverKit.Core.Hashcat;
using System.Text;
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

    [Fact]
    public async Task SupportedExportsNeverStartHashcatAndKeepProgressAndEncoding()
    {
        string dir = Directory.CreateTempSubdirectory("rk-local-export").FullName;
        try
        {
            string words = Path.Combine(dir, "words.txt"), output = Path.Combine(dir, "out.txt");
            File.WriteAllText(words, "alpha\n\n$HEX[ff]\n");
            var step = ExportCandidatesTests.Step("-a", "0", words);
            var tool = HashcatTool.ForExe(Path.Combine(dir, "does-not-exist"));
            var progress = new Counts();
            long n = await CandidateExport.WriteDictionaryAsync([step], tool, output, CandidateExport.EncodingFor("UTF16"), progress, default);
            Assert.Equal(3, n);
            Assert.Equal([3L], progress.Values);
            Assert.Equal(Encoding.Unicode.GetPreamble().Concat(Encoding.Unicode.GetBytes("alpha\r\n\r\nÿ\r\n")), File.ReadAllBytes(output));

            File.WriteAllText(words, "password\n");
            Assert.Equal(1, await CandidateExport.WritePmkTableAsync([step], tool, output, "IEEE", 1, null, default));
            Assert.Equal("f42c6fc52df0ebef9ebb4b90b38a5f902e83fe1b135a70e23aed762e9710a12e:password", File.ReadAllLines(output)[1]);
            using var cancelled = new CancellationTokenSource();
            cancelled.Cancel();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => CandidateExport.WriteDictionaryAsync([step], tool, output,
                CandidateExport.EncodingFor("UTF8"), null, cancelled.Token));
        }
        finally { Directory.Delete(dir, true); }
    }

    private sealed class Counts : IProgress<long>
    {
        public List<long> Values { get; } = [];
        public void Report(long value) => Values.Add(value);
    }

    private static PreparedAttack Step(string dir)
    {
        var step = new PreparedAttack { Description = "test" };
        step.Args.AddRange(["-a", "0", Path.Combine(dir, "words.txt"), "-r", Path.Combine(dir, "rules.rule")]);
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
