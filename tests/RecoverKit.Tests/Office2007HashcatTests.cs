using System.Text;
using System.Text.Json;
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
public sealed class Office2007HashcatTests(ITestOutputHelper output)
{
    public static IEnumerable<object[]> IndependentFixtures => Office2007CpuTests.KnownAnswers
        .Where(row => (string)row[0] is "128-ascii" or "256-ascii" or "128-unicode" or "256-empty"
            or "128-ascii-256" or "256-ascii-256")
        .Select(row => new object[] { row[1], row[2] })
        .Prepend([Office2007CpuTests.HashcatExample, "hashcat"]);

    public static IEnumerable<object[]> IndependentRawByteFixtures => Office2007CpuTests.RawUtf8KnownAnswers
        .Select(row => new object[] { row[0], row[2] });

    [Theory]
    [MemberData(nameof(IndependentRawByteFixtures))]
    public async Task HashcatRawF4DictionaryBytesAgreeWithNativeAndManagedVerification(string rawHex, string hash)
    {
        var tool = Tool();
        string dir = Directory.CreateTempSubdirectory("rk-office-raw-").FullName;
        try
        {
            string hashFile = Path.Combine(dir, "target.hash"), words = Path.Combine(dir, "words");
            byte[] password = Convert.FromHexString(rawHex);
            await File.WriteAllTextAsync(hashFile, hash);
            await File.WriteAllBytesAsync(words, [.. "wrong\n"u8, .. password, (byte)'\n', .. "another-wrong\n"u8]);
            var attack = new PreparedAttack { Description = "Office 2007 raw F4 dictionary", Args = { "-a", "0", words } };
            using var stop = new CancellationTokenSource(TimeSpan.FromMinutes(3));
            var runner = new HashcatRunner(tool);
            runner.OutputLine += output.WriteLine;
            var result = await runner.RunAsync(Request(dir, hashFile, attack, "raw"), stop.Token);
            Assert.True(result.Outcome == RunOutcome.Cracked, result.Error ?? $"hashcat returned {result.Outcome}");
            Assert.Contains("$HEX[" + rawHex + "]", result.RawPasswords);
            var kernel = Assert.IsType<Office2007Kernel>(Office2007Kernel.TryParse(hash));
            Assert.True(kernel.Verify(password));
            Assert.Equal(0, kernel.CreateWorker().SearchPasswords(password, password.Length, 1));
        }
        finally { Directory.Delete(dir, true); }
    }

    [Theory]
    [MemberData(nameof(IndependentFixtures))]
    public async Task IndependentVectorsAgreeWithHashcat(string hash, string password)
    {
        var tool = Tool();
        string dir = Directory.CreateTempSubdirectory("rk-office-kat-").FullName;
        try
        {
            string hashFile = Path.Combine(dir, "target.hash"), words = Path.Combine(dir, "words");
            await File.WriteAllTextAsync(hashFile, hash);
            await File.WriteAllLinesAsync(words, ["wrong", password, "another-wrong"], new UTF8Encoding(false));
            var kernel = Assert.IsType<Office2007Kernel>(Office2007Kernel.TryParse(hash));
            Assert.True(kernel.Verify(Encoding.UTF8.GetBytes(password)));
            var attack = new PreparedAttack { Description = "Office 2007 independent vector", Args = { "-a", "0", words } };
            using var stop = new CancellationTokenSource(TimeSpan.FromMinutes(3));
            var runner = new HashcatRunner(tool);
            runner.OutputLine += output.WriteLine;
            var result = await runner.RunAsync(Request(dir, hashFile, attack, "known"), stop.Token);
            Assert.True(result.Outcome == RunOutcome.Cracked, result.Error ?? $"hashcat returned {result.Outcome}");
            Assert.Contains(password, result.Passwords);
        }
        finally { Directory.Delete(dir, true); }
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(true, false)]
    [InlineData(false, true)]
    public async Task HybridDictionaryRulesFindOnBothDevicesAndResume(bool cpuHit, bool resume)
    {
        var tool = Tool();
        Assert.True(RkNative.Available, "Build native/build.sh before native/hashcat integration tests.");
        string dir = Directory.CreateTempSubdirectory("rk-office-hybrid-").FullName;
        try
        {
            string hash = Office2007CpuTests.HashcatExample, hashFile = Path.Combine(dir, "target.hash");
            string words = Path.Combine(dir, "words"), rules = Path.Combine(dir, "rules");
            // Keep the GPU's early hit outside the CPU's first 65536-word batch during GPU startup.
            int count = cpuHit ? 10000 : 100000;
            var candidates = Enumerable.Range(0, count).Select(i => $"wrong{i:00000}").ToArray();
            candidates[cpuHit ? count - 1 : 4] = "hashca";
            await File.WriteAllTextAsync(hashFile, hash);
            await File.WriteAllLinesAsync(words, candidates);
            await File.WriteAllTextAsync(rules, "$t\n");
            var attack = new PreparedAttack { Description = "Office 2007 dictionary rules", Args = { "-a", "0", words, "-r", rules } };
            var dictionary = Assert.IsType<DictionaryAttack>(DictionaryAttack.Parse(attack.Args));
            var kernel = Assert.IsType<Office2007Kernel>(Office2007Kernel.TryParse(hash));
            using var stop = new CancellationTokenSource(TimeSpan.FromMinutes(5));
            var request = Request(dir, hashFile, attack, "hybrid") with { Restore = resume };
            if (resume)
            {
                Assert.True(await dictionary.PrepareAsync(tool, 9400, stop.Token));
                var checkpoint = new HybridResumePoint
                {
                    Length = 0, BaseCount = dictionary.BaseCount, Lo = 3,
                    BatchLo = dictionary.BaseCount, BatchHi = dictionary.BaseCount,
                    DictionaryFingerprint = dictionary.Fingerprint,
                };
                await File.WriteAllTextAsync(HybridRunner.RestoreFile(dir, "hybrid"), JsonSerializer.Serialize(checkpoint));
            }
            var messages = new List<string>();
            var warnings = new List<string>();
            var runner = new HybridRunner
            {
                ForceGpu = true, ThreadsOverride = 1, HashcatStartupSeconds = .001,
                InitialGpuSpeed = 100000, InitialCpuSpeed = 10, BatchSeconds = .01,
            };
            runner.OutputLine += line => { lock (messages) messages.Add(line); output.WriteLine(line); };
            runner.Warning += line => { lock (warnings) warnings.Add(line); };
            var result = await runner.RunAsync(new HybridPlan(kernel, null) { Dictionary = dictionary }, hash, request, tool, stop.Token);
            Assert.True(result.Outcome == RunOutcome.Cracked, result.Error ?? $"hybrid returned {result.Outcome}");
            Assert.Contains("hashcat", result.Passwords);
            Assert.Empty(warnings);
            Assert.Contains(cpuHit ? "Found by the built-in CPU engine." : "Found by hashcat.", messages);
            Assert.False(File.Exists(HybridRunner.RestoreFile(dir, "hybrid")));
        }
        finally { Directory.Delete(dir, true); }
    }

    [Fact]
    public async Task NativeMaskResultAndPasswordCacheAgreeWithHashcat()
    {
        var tool = Tool();
        string dir = Directory.CreateTempSubdirectory("rk-office-native-").FullName;
        try
        {
            string hash = Office2007CpuTests.HashcatExample, hashFile = Path.Combine(dir, "target.hash");
            string cache = Path.Combine(dir, "potfile");
            await File.WriteAllTextAsync(hashFile, hash);
            var attack = new PreparedAttack { Description = "Office 2007 native mask", Args = { "-a", "3", "-1", "xt", "hashca?1" } };
            var kernel = Assert.IsType<Office2007Kernel>(Office2007Kernel.TryParse(hash));
            using var stop = new CancellationTokenSource(TimeSpan.FromMinutes(3));
            var request = Request(dir, hashFile, attack, "native") with
            {
                Settings = new Settings { MaxCpuThreads = 1, Priority = ProcessPriority.Normal, SessionsDir = dir },
                PasswordCachePath = cache,
                ConfirmPassword = bytes => kernel.Verify(bytes),
            };
            var runner = new NativeRunner();
            runner.OutputLine += output.WriteLine;
            var result = await runner.RunAsync(kernel, MaskSpace.FromHashcatArgs(attack.Args)!, hash, request, stop.Token);
            Assert.Equal(RunOutcome.Cracked, result.Outcome);
            Assert.Contains("hashcat", result.Passwords);
            Assert.Contains("hashcat", await tool.ShowAsync(9400, hashFile, cache));
        }
        finally { Directory.Delete(dir, true); }
    }

    private static HashcatTool Tool()
    {
        string? executable = Environment.GetEnvironmentVariable("RECOVERKIT_TEST_HASHCAT");
        Assert.False(string.IsNullOrWhiteSpace(executable), "Set RECOVERKIT_TEST_HASHCAT to a private hashcat 8 copy.");
        return Assert.IsType<HashcatTool>(HashcatTool.Locate(executable));
    }

    private static RunRequest Request(string dir, string hashFile, PreparedAttack attack, string session) => new()
    {
        Mode = 9400, HashFile = hashFile, Attack = attack, SessionName = session, SessionDir = dir,
        UseOptimizedKernel = false,
        Settings = new Settings { DontUsePasswordCache = true, MaxCpuThreads = 1, Priority = ProcessPriority.Normal, SessionsDir = dir },
        PasswordCachePath = Path.Combine(dir, "potfile"),
    };
}
