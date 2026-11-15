using System.Diagnostics;
using RecoverKit.Core;
using RecoverKit.Core.Attacks;
using RecoverKit.Core.Hashcat;
using RecoverKit.Core.Native;
using Xunit;
using Xunit.Abstractions;

namespace RecoverKit.Tests;

[Trait("Category", "Slow")]
[Collection("NativeFeatures")]
public sealed class Pbkdf2Sha1HashcatTests(ITestOutputHelper output)
{
    public static IEnumerable<object[]> IndependentFixtures => WpaCpuTests.KnownAnswers.Select(row =>
        new object[] { 22000, row[0], ((string)row[0]).Contains("686173686361742d6573736964") ? "hashcat!" : "password" })
        .Concat(WinZipAesCpuTests.KnownAnswers.Select(row => new object[] { 13600, row[0], "winzip-test" }));

    [Theory]
    [MemberData(nameof(IndependentFixtures))]
    public async Task IndependentNativeFixturesAgreeWithHashcat(int mode, string hash, string password)
    {
        string? executable = Environment.GetEnvironmentVariable("RECOVERKIT_TEST_HASHCAT");
        Assert.False(string.IsNullOrWhiteSpace(executable));
        var tool = HashcatTool.Locate(executable)!;
        string dir = Directory.CreateTempSubdirectory("rk-sha1-known-").FullName;
        try
        {
            string file = Path.Combine(dir, "target.hash"), words = Path.Combine(dir, "words");
            await File.WriteAllTextAsync(file, hash);
            await File.WriteAllLinesAsync(words, ["wrong-passphrase", password, "another-wrong-password"]);
            var kernel = NativeKernels.TryCreate(mode, hash);
            Assert.NotNull(kernel);
            Assert.True(kernel.Verify(System.Text.Encoding.UTF8.GetBytes(password)));
            using var stop = new CancellationTokenSource(TimeSpan.FromMinutes(2));
            var runner = new HashcatRunner(tool);
            runner.OutputLine += output.WriteLine;
            var result = await runner.RunAsync(new RunRequest
            {
                Mode = mode, HashFile = file, SessionName = "known", SessionDir = dir,
                Settings = new Settings { DontUsePasswordCache = true }, UseOptimizedKernel = false,
                Attack = new PreparedAttack { Description = "known answer", Args = { "-a", "0", words } },
            }, stop.Token);
            Assert.True(result.Outcome == RunOutcome.Cracked, result.Error ?? $"hashcat returned {result.Outcome}");
            Assert.Contains(password, result.Passwords);
        }
        finally { Directory.Delete(dir, true); }
    }

    [Fact]
    public async Task CpuWpaCacheCanBeReadByHashcat()
    {
        string? executable = Environment.GetEnvironmentVariable("RECOVERKIT_TEST_HASHCAT");
        Assert.False(string.IsNullOrWhiteSpace(executable));
        var tool = HashcatTool.Locate(executable)!;
        string dir = Directory.CreateTempSubdirectory("rk-wpa-cache-").FullName;
        try
        {
            string line = NativeKernels.BenchmarkHashes[22000], file = Path.Combine(dir, "network.hash");
            await File.WriteAllTextAsync(file, line);
            var settings = new Settings();
            string cache = Path.Combine(dir, "potfile");
            var kernel = RecoverKit.Core.Native.Kernels.WpaKernel.TryParse(line)!;
            await NativeRunner.RecordFoundAsync(settings, NativeRunner.MatchedHashLine(kernel, line, "hashcat!"u8.ToArray()), "hashcat!"u8.ToArray(), cache);
            Assert.Contains("hashcat!", await tool.ShowAsync(22000, file, cache));
        }
        finally { Directory.Delete(dir, true); }
    }

    [Theory]
    [InlineData(13600, false)]
    [InlineData(13600, true)]
    [InlineData(22000, false)]
    [InlineData(22000, true)]
    public async Task HashcatAndHybridRecoverTheSamePassword(int mode, bool dictionary)
    {
        string? executable = Environment.GetEnvironmentVariable("RECOVERKIT_TEST_HASHCAT");
        Assert.False(string.IsNullOrWhiteSpace(executable), "Set RECOVERKIT_TEST_HASHCAT to a private hashcat 8 copy.");
        var tool = HashcatTool.Locate(executable)!;
        Assert.True(RkNative.Available, "Rebuild native/build.sh before native/GPU integration tests.");
        var kernel = NativeKernels.TryCreate(mode, NativeKernels.BenchmarkHashes[mode]);
        Assert.NotNull(kernel);
        string dir = Directory.CreateTempSubdirectory("rk-sha1-hashcat-").FullName;
        try
        {
            string hash = NativeKernels.BenchmarkHashes[mode], file = Path.Combine(dir, "target.hash");
            await File.WriteAllTextAsync(file, hash);
            var attack = new PreparedAttack { Description = "SHA1 integration" };
            if (dictionary)
            {
                string words = Path.Combine(dir, "words"), rules = Path.Combine(dir, "rules");
                await File.WriteAllLinesAsync(words, Enumerable.Range(0, 1000).Select(i => $"wrong{i:0000}")
                    .Append(mode == 22000 ? "hashcatx" : "hashca"));
                await File.WriteAllTextAsync(rules, mode == 22000 ? "sx!\n" : "$t\n");
                attack.Args.AddRange(["-a", "0", words, "-r", rules]);
            }
            else attack.Args.AddRange(["-a", "3", "-1", "abcht!", mode == 22000 ? "hash?1?1?1?1" : "hash?1?1?1"]);
            var settings = new Settings { DontUsePasswordCache = true, Priority = ProcessPriority.Normal, SessionsDir = dir };
            var request = new RunRequest
            {
                Mode = mode, HashFile = file, Attack = attack, SessionName = "sha1_gpu", SessionDir = dir,
                Settings = settings, UseOptimizedKernel = false,
            };
            using var stop = new CancellationTokenSource(TimeSpan.FromMinutes(5));
            var gpuRunner = new HashcatRunner(tool);
            gpuRunner.OutputLine += output.WriteLine;
            var gpu = await gpuRunner.RunAsync(request, stop.Token);
            Assert.True(gpu.Outcome == RunOutcome.Cracked, gpu.Error ?? $"hashcat returned {gpu.Outcome}");
            string expected = mode == 22000 ? "hashcat!" : "hashcat";
            Assert.Contains(expected, gpu.Passwords);
            var runner = new HybridRunner
            {
                ForceGpu = true, ThreadsOverride = 1, HashcatStartupSeconds = .001,
                InitialGpuSpeed = 100000, InitialCpuSpeed = 1000, BatchSeconds = .01,
            };
            runner.OutputLine += output.WriteLine;
            var plan = dictionary ? new HybridPlan(kernel!, null) { Dictionary = DictionaryAttack.Parse(attack.Args) }
                : new HybridPlan(kernel!, MaskSpace.FromHashcatArgs(attack.Args));
            var result = await runner.RunAsync(plan, hash, request with { SessionName = "sha1_hybrid" }, tool, stop.Token);
            Assert.True(result.Outcome == RunOutcome.Cracked, result.Error ?? $"hybrid returned {result.Outcome}");
            Assert.Contains(expected, result.Passwords);
            output.WriteLine($"mode {mode}, dictionary={dictionary}: API {NativeKernels.NativeApiVersion}, {NativeKernels.CpuPath(mode, actualOnly: true)}, {result.Outcome}");
        }
        finally { Directory.Delete(dir, true); }
    }
}
