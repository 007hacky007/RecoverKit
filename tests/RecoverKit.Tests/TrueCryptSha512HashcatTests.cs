using System.Security.Cryptography;
using System.Text;
using RecoverKit.Core;
using RecoverKit.Core.Attacks;
using RecoverKit.Core.Hashcat;
using RecoverKit.Core.Native;
using RecoverKit.Core.Native.Kernels;
using Xunit;
using Xunit.Abstractions;

namespace RecoverKit.Tests;

[Trait("Category", "Slow")]
[Collection("NativeFeatures")]
public sealed class TrueCryptSha512HashcatTests(ITestOutputHelper output)
{
    public static IEnumerable<object[]> Modes => TrueCryptSha512IntegrationTests.Modes;

    public static IEnumerable<object[]> GeneratedHeaders
    {
        get
        {
            foreach (var (mode, ciphers) in new (int, string[])[]
            {
                (29321, ["AES", "Serpent", "Twofish"]),
                (29322, ["AES-Twofish", "Serpent-AES", "Twofish-Serpent"]),
                (29323, ["AES-Twofish-Serpent", "Serpent-Twofish-AES"]),
                (29421, ["AES", "Serpent", "Twofish", "Camellia", "Kuznyechik"]),
                (29422, ["AES-Twofish", "Serpent-AES", "Twofish-Serpent", "Camellia-Kuznyechik", "Camellia-Serpent", "Kuznyechik-AES", "Kuznyechik-Twofish"]),
                (29423, ["AES-Twofish-Serpent", "Serpent-Twofish-AES", "Kuznyechik-Serpent-Camellia"]),
            })
            foreach (string cipher in ciphers) yield return [mode, cipher];
        }
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task PublishedExampleIsAcceptedByBothEngines(int mode)
    {
        string hash = NativeKernels.BenchmarkHashes[mode];
        Assert.True(TrueCryptSha512Kernel.TryParse(mode, hash)!.Verify("hashcat"u8));
        await HashcatAsync(mode, hash, "hashcat");
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task EveryGeneratedCipherAndCascadeIsAcceptedByHashcat(int mode)
    {
        int pim = mode >= 29400 ? 1 : 0;
        var fixtures = new List<string>();
        foreach (var row in GeneratedHeaders.Where(row => (int)row[0] == mode))
        {
            string cipher = (string)row[1];
            // Separate salts keep hashcat's single-esalt kernels from merging distinct headers.
            byte[] salt = SHA512.HashData(Encoding.ASCII.GetBytes($"RecoverKit SHA512 fixture {mode} {cipher}"));
            string hash = TrueCryptSha512Tests.MakeHeader(mode, cipher, "test7"u8.ToArray(), pim, salt: salt);
            Assert.True(TrueCryptSha512Kernel.TryParse(mode, hash, pim)!.Verify("test7"u8));
            fixtures.Add(hash);
        }
        Assert.Equal(fixtures.Count, fixtures.Select(hash => hash.Split('$')[2]).Distinct().Count());
        // Every generated digest must crack as test7 and reject wrong candidates. The six published
        // tests retain hashcat's self-test; native path guards remain on for every test.
        await HashcatAsync(mode, string.Join('\n', fixtures), "test7", pim, skipSelfTest: true);
    }

    [Fact]
    public async Task CustomPimGeneratedHeaderAgreesWithHashcat()
    {
        const int mode = 29421, pim = 7;
        string hash = TrueCryptSha512Tests.MakeHeader(mode, "AES", "test7"u8.ToArray(), pim);
        Assert.True(TrueCryptSha512Kernel.TryParse(mode, hash, pim)!.Verify("test7"u8));
        await HashcatAsync(mode, hash, "test7", pim, skipSelfTest: true);
    }

    [Theory]
    [InlineData(29321, false)]
    [InlineData(29321, true)]
    [InlineData(29421, false)]
    [InlineData(29421, true)]
    public async Task MaskAndRuleDictionaryHybridAgreeWithHashcat(int mode, bool dictionary)
    {
        var tool = Tool();
        Assert.True(RkNative.Available, "Build native/build.sh before integration tests.");
        string dir = Directory.CreateTempSubdirectory("rk-sha512-hashcat-hybrid-").FullName;
        try
        {
            string hash = NativeKernels.BenchmarkHashes[mode], file = Path.Combine(dir, "target.hash");
            await File.WriteAllTextAsync(file, hash + "\n");
            var attack = new PreparedAttack { Description = "SHA512 hybrid" };
            if (dictionary)
            {
                string words = Path.Combine(dir, "words"), rules = Path.Combine(dir, "rules");
                await File.WriteAllLinesAsync(words, ["wrong00", "hashcax", "wrong01"]);
                await File.WriteAllTextAsync(rules, "sxt\n");
                attack.Args.AddRange(["-a", "0", words, "-r", rules]);
            }
            else attack.Args.AddRange(["-a", "3", "-1", "st", "hashca?1"]);
            var settings = new Settings { DontUsePasswordCache = true, SessionsDir = dir, Priority = ProcessPriority.Normal };
            var request = new RunRequest
            {
                Mode = mode, HashFile = file, Attack = attack, SessionName = "sha512_gpu", SessionDir = dir,
                Settings = settings, UseOptimizedKernel = false,
            };
            using var stop = new CancellationTokenSource(TimeSpan.FromMinutes(5));
            var gpu = new HashcatRunner(tool);
            gpu.OutputLine += output.WriteLine;
            var gpuResult = await gpu.RunAsync(request, stop.Token);
            Assert.True(gpuResult.Outcome == RunOutcome.Cracked, gpuResult.Error ?? $"hashcat returned {gpuResult.Outcome}");
            Assert.Equal(["hashcat"], gpuResult.Passwords.Distinct());
            var kernel = NativeKernels.TryCreate(mode, hash)!;
            var plan = dictionary ? new HybridPlan(kernel, null) { Dictionary = DictionaryAttack.Parse(attack.Args) }
                : new HybridPlan(kernel, MaskSpace.FromHashcatArgs(attack.Args));
            var hybrid = new HybridRunner
            {
                ForceGpu = true, ThreadsOverride = 1, HashcatStartupSeconds = .001,
                InitialGpuSpeed = 100000, InitialCpuSpeed = 1000, BatchSeconds = .01,
            };
            hybrid.OutputLine += output.WriteLine;
            var result = await hybrid.RunAsync(plan, hash, request with { SessionName = "sha512_hybrid" }, tool, stop.Token);
            Assert.True(result.Outcome == RunOutcome.Cracked, result.Error ?? $"hybrid returned {result.Outcome}");
            Assert.Equal(["hashcat"], result.Passwords.Distinct());
        }
        finally { Directory.Delete(dir, true); }
    }

    private static HashcatTool Tool()
    {
        string? executable = Environment.GetEnvironmentVariable("RECOVERKIT_TEST_HASHCAT");
        Assert.False(string.IsNullOrWhiteSpace(executable), "Set RECOVERKIT_TEST_HASHCAT to a private hashcat 8 copy.");
        return HashcatTool.Locate(executable)!;
    }

    private async Task<RunResult> HashcatAsync(int mode, string hash, string password, int pim = 0, bool skipSelfTest = false)
    {
        var tool = Tool();
        string dir = Directory.CreateTempSubdirectory("rk-sha512-hashcat-known-").FullName;
        try
        {
            string file = Path.Combine(dir, "target.hash"), words = Path.Combine(dir, "words");
            await File.WriteAllTextAsync(file, hash + "\n");
            await File.WriteAllLinesAsync(words, ["wrong00", "test7", "hashcat", "wrong01"]);
            using var stop = new CancellationTokenSource(TimeSpan.FromMinutes(8));
            var runner = new HashcatRunner(tool);
            runner.OutputLine += output.WriteLine;
            var result = await runner.RunAsync(new RunRequest
            {
                Mode = mode, HashFile = file, SessionName = "known", SessionDir = dir,
                Settings = new() { DontUsePasswordCache = true, Priority = ProcessPriority.Normal,
                    ExtraArguments = skipSelfTest ? "--self-test-disable" : "" }, UseOptimizedKernel = false,
                VolumeCredentials = pim > 0 ? new(new RecoverKit.Core.Formats.VolumeOptions { Pim = pim }) : null,
                Attack = new() { Description = "SHA512 known answer", Args = { "-a", "0", words } },
            }, stop.Token);
            Assert.True(result.Outcome == RunOutcome.Cracked, result.Error ?? $"hashcat returned {result.Outcome}");
            Assert.Equal([password], result.Passwords.Distinct());
            // Outfile format 2 emits one plaintext per recovered digest, even when passwords repeat.
            Assert.Equal(hash.Split('\n', StringSplitOptions.RemoveEmptyEntries).Length,
                File.ReadAllLines(HashcatRunner.OutFile(dir, "known")).Length);
            return result;
        }
        finally { Directory.Delete(dir, true); }
    }
}
