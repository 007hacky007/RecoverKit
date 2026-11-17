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
public sealed class OfficeAgileHashcatTests(ITestOutputHelper output)
{
    public static IEnumerable<object[]> IndependentFixtures => OfficeAgileCpuTests.AcceptedVectors
        .Where(row => new[] { "-ascii", "-empty", "-unicode", "-supplementary", "-utf8-256", "-ascii-256", "-raw-f4908080", "-raw-f4bfbfbf" }
            .Any(suffix => ((string)row[0]).EndsWith(suffix, StringComparison.Ordinal)))
        .Select(row => new object[] { row[1], row[2], row[3] })
        .Concat(OfficeAgileCpuTests.Examples.Select(row => new object[] { row[0], row[1], Convert.ToHexString("hashcat"u8) }));

    [Theory]
    [MemberData(nameof(IndependentFixtures))]
    public async Task IndependentVectorsAndRawDictionaryBytesAgreeWithHashcat(int mode, string hash, string rawHex)
    {
        var tool = Tool();
        string dir = Directory.CreateTempSubdirectory("rk-agile-kat-").FullName;
        try
        {
            byte[] password = Convert.FromHexString(rawHex);
            string hashFile = Path.Combine(dir, "target.hash"), words = Path.Combine(dir, "words");
            await File.WriteAllTextAsync(hashFile, hash);
            await File.WriteAllBytesAsync(words, [.. "wrong\n"u8, .. password, (byte)'\n', .. "another-wrong\n"u8]);
            var kernel = Assert.IsType<OfficeAgileKernel>(NativeKernels.TryCreate(mode, hash));
            Assert.True(kernel.Verify(password));
            var attack = new PreparedAttack { Description = "Office Agile independent dictionary", Args = { "-a", "0", words } };
            using var stop = new CancellationTokenSource(TimeSpan.FromMinutes(3));
            var runner = new HashcatRunner(tool);
            runner.OutputLine += output.WriteLine;
            var result = await runner.RunAsync(Request(mode, dir, hashFile, attack, "known"), stop.Token);
            Assert.True(result.Outcome == RunOutcome.Cracked, result.Error ?? $"hashcat returned {result.Outcome}");
            // The GPU output must preserve even hashcat's F4 surrogate edge bytes.
            Assert.Contains(result.RawPasswords, raw => PasswordConfirmation.PlainBytes(raw).AsSpan().SequenceEqual(password));
            Assert.Equal(0, kernel.CreateWorker().SearchPasswords(password, password.Length, 1));
        }
        finally { Directory.Delete(dir, true); }
    }

    [Theory]
    [MemberData(nameof(OfficeAgileCpuTests.Examples), MemberType = typeof(OfficeAgileCpuTests))]
    public async Task NativeMaskResultAndPasswordCacheAgreeWithHashcat(int mode, string hash)
    {
        var tool = Tool();
        string dir = Directory.CreateTempSubdirectory("rk-agile-native-").FullName;
        try
        {
            string hashFile = Path.Combine(dir, "target.hash"), cache = Path.Combine(dir, "potfile");
            await File.WriteAllTextAsync(hashFile, hash);
            var attack = new PreparedAttack { Description = "Office Agile native mask", Args = { "-a", "3", "-1", "xt", "hashca?1" } };
            var kernel = Assert.IsType<OfficeAgileKernel>(NativeKernels.TryCreate(mode, hash));
            using var stop = new CancellationTokenSource(TimeSpan.FromMinutes(3));
            var request = Request(mode, dir, hashFile, attack, "native") with
            {
                Settings = new Settings { MaxCpuThreads = 1, Priority = ProcessPriority.Normal, SessionsDir = dir },
                PasswordCachePath = cache, ConfirmPassword = bytes => kernel.Verify(bytes),
            };
            var runner = new NativeRunner();
            runner.OutputLine += output.WriteLine;
            var result = await runner.RunAsync(kernel, MaskSpace.FromHashcatArgs(attack.Args)!, hash, request, stop.Token);
            Assert.Equal(RunOutcome.Cracked, result.Outcome);
            Assert.Contains("hashcat", result.Passwords);
            Assert.Contains("hashcat", await tool.ShowAsync(mode, hashFile, cache));
        }
        finally { Directory.Delete(dir, true); }
    }

    public static IEnumerable<object[]> HybridCases => OfficeAgileCpuTests.Examples.SelectMany(row =>
        new[] { new object[] { row[0], row[1], false, false },
            new object[] { row[0], row[1], true, false }, new object[] { row[0], row[1], false, true } });

    [Theory]
    [MemberData(nameof(HybridCases))]
    public async Task HybridDictionaryRulesFindOnBothDevicesAndResume(int mode, string hash, bool cpuHit, bool resume)
    {
        var tool = Tool();
        Assert.True(RkNative.Available, "Build native/build.sh before native/hashcat integration tests.");
        string dir = Directory.CreateTempSubdirectory("rk-agile-hybrid-").FullName;
        try
        {
            string hashFile = Path.Combine(dir, "target.hash");
            string words = Path.Combine(dir, "words"), rules = Path.Combine(dir, "rules");
            // GPU's early hit stays outside the CPU's first 65536-word startup batch.
            int count = cpuHit ? 10000 : 100000;
            var candidates = Enumerable.Range(0, count).Select(i => $"wrong{i:00000}").ToArray();
            candidates[cpuHit ? count - 1 : 4] = "hashca";
            await File.WriteAllTextAsync(hashFile, hash);
            await File.WriteAllLinesAsync(words, candidates);
            await File.WriteAllTextAsync(rules, "$t\n");
            var attack = new PreparedAttack { Description = "Office Agile dictionary rules", Args = { "-a", "0", words, "-r", rules } };
            var dictionary = Assert.IsType<DictionaryAttack>(DictionaryAttack.Parse(attack.Args));
            var kernel = Assert.IsType<OfficeAgileKernel>(NativeKernels.TryCreate(mode, hash));
            using var stop = new CancellationTokenSource(TimeSpan.FromMinutes(5));
            var request = Request(mode, dir, hashFile, attack, "hybrid") with { Restore = resume };
            if (resume)
            {
                Assert.True(await dictionary.PrepareAsync(tool, mode, stop.Token));
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

    private static HashcatTool Tool()
    {
        string? executable = Environment.GetEnvironmentVariable("RECOVERKIT_TEST_HASHCAT");
        Assert.False(string.IsNullOrWhiteSpace(executable), "Set RECOVERKIT_TEST_HASHCAT to a private hashcat 8.0.0 copy.");
        var tool = Assert.IsType<HashcatTool>(HashcatTool.Locate(executable));
        Assert.Equal(new Version(8, 0, 0), HashcatTool.ParseVersion(tool.FullVersion));
        return tool;
    }

    private static RunRequest Request(int mode, string dir, string hashFile, PreparedAttack attack, string session) => new()
    {
        Mode = mode, HashFile = hashFile, Attack = attack, SessionName = session, SessionDir = dir,
        UseOptimizedKernel = false,
        Settings = new Settings { DontUsePasswordCache = true, MaxCpuThreads = 1, Priority = ProcessPriority.Normal, SessionsDir = dir },
        PasswordCachePath = Path.Combine(dir, "potfile"),
    };
}
