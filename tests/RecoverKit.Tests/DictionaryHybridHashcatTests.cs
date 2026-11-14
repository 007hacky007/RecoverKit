using System.Security.Cryptography;
using System.Diagnostics;
using System.Text.Json;
using RecoverKit.Core.Attacks;
using Xunit.Abstractions;
using System.Text;
using RecoverKit.Core;
using RecoverKit.Core.Hashcat;
using RecoverKit.Core.Native;
using RecoverKit.Core.Native.Kernels;
using Xunit;

namespace RecoverKit.Tests;

[Trait("Category", "Slow")]
public class DictionaryHybridHashcatTests(ITestOutputHelper log)
{
    [Fact]
    public async Task Rar3DeferredExpandedPasswordSurvivesStopAndResume()
    {
        string? exe = Environment.GetEnvironmentVariable("RECOVERKIT_TEST_HASHCAT");
        Assert.False(string.IsNullOrEmpty(exe), "Set RECOVERKIT_TEST_HASHCAT to a private hashcat 8 copy.");
        var tool = HashcatTool.Locate(exe)!;
        string dir = Directory.CreateTempSubdirectory("rk-dict-rar3-tail").FullName;
        try
        {
            string password = new('q', 28);
            const string salt = "0001020304050607";
            var reference = Rar3Kernel.TryParse($"$RAR3$*0*{salt}*{new string('0', 32)}")!;
            var (digest, iv) = reference.ReferenceHash(Encoding.ASCII.GetBytes(password));
            byte[] key = Enumerable.Range(0, 16).Select(i => digest[(i / 4) * 4 + 3 - i % 4]).ToArray();
            using var aes = Aes.Create();
            aes.Key = key;
            byte[] encrypted = aes.EncryptCbc(new byte[] { 0xc4, 0x3d, 0x7b, 0, 0x40, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, iv, PaddingMode.None);
            string hash = $"$RAR3$*0*{salt}*{Convert.ToHexString(encrypted)}";
            string words = Path.Combine(dir, "words"), rules = Path.Combine(dir, "rules"), hashes = Path.Combine(dir, "hashes");
            await File.WriteAllLinesAsync(words, Enumerable.Range(0, 100).Select(i => $"w{i:000000}").Append(password));
            await File.WriteAllTextAsync(rules, ":\n$1\n");
            await File.WriteAllTextAsync(hashes, hash);
            var attack = new PreparedAttack { Description = "deferred dictionary", Args = { "-a", "0", words, "-r", rules } };
            var request = new RunRequest
            {
                Mode = 12500, HashFile = hashes, Attack = attack, SessionName = "rk_deferred", SessionDir = dir,
                Settings = new Settings { DontUsePasswordCache = true, Priority = ProcessPriority.Normal },
            };
            using var stop = new CancellationTokenSource(TimeSpan.FromMinutes(3));
            var runner = new HybridRunner { ThreadsOverride = 2 };
            runner.OutputLine += line => { log.WriteLine(line); if (line.StartsWith("Checking ")) stop.Cancel(); };
            var result = await runner.RunAsync(new HybridPlan(Rar3Kernel.TryParse(hash)!, null)
                { Dictionary = DictionaryAttack.Parse(attack.Args) }, hash, request, tool, stop.Token);
            Assert.Equal(RunOutcome.Aborted, result.Outcome);
            var checkpoint = JsonSerializer.Deserialize<HybridResumePoint>(await File.ReadAllTextAsync(HybridRunner.RestoreFile(dir, request.SessionName)))!;
            Assert.Equal(2, checkpoint.LeftoverCount);
            Assert.Equal(0, checkpoint.LeftoverLo);
            using var timeout = new CancellationTokenSource(TimeSpan.FromMinutes(4));
            result = await new HybridRunner { ThreadsOverride = 2 }.RunAsync(new HybridPlan(Rar3Kernel.TryParse(hash)!, null)
                { Dictionary = DictionaryAttack.Parse(attack.Args) }, hash, request with { Restore = true }, tool, timeout.Token);
            Assert.Equal(RunOutcome.Cracked, result.Outcome);
            Assert.Equal(password, Assert.Single(result.Passwords));
        }
        finally { Directory.Delete(dir, true); }
    }

    [Theory]
    [InlineData(13000, 300000, 0, false)]
    [InlineData(13000, 300000, 150000, false)]
    [InlineData(13000, 300000, 299999, false)]
    [InlineData(12500, 8000, 0, false)]
    [InlineData(12500, 8000, 4000, false)]
    [InlineData(12500, 8000, 7999, false)]
    [InlineData(13000, 300000, 150000, true)]
    [InlineData(12500, 8000, 4000, true)]
    public async Task RealRarFindsInBothSharesAndResumes(int mode, int count, int target, bool resume)
    {
        string? exe = Environment.GetEnvironmentVariable("RECOVERKIT_TEST_HASHCAT");
        Assert.False(string.IsNullOrEmpty(exe), "Set RECOVERKIT_TEST_HASHCAT to a private hashcat 8 copy.");
        var tool = HashcatTool.Locate(exe)!;
        string hash = NativeKernels.BenchmarkHashes[mode];
        var kernel = NativeKernels.TryCreate(mode, hash);
        Assert.NotNull(kernel);
        log.WriteLine($"Native API {NativeKernels.NativeApiVersion}: {NativeKernels.CpuFeatures()}");
        string dir = Directory.CreateTempSubdirectory("rk-dict-rar").FullName;
        try
        {
            string words = Path.Combine(dir, "words"), rule = Path.Combine(dir, "test.rule"), hashFile = Path.Combine(dir, "hash");
            await File.WriteAllLinesAsync(words, Enumerable.Range(0, count).Select(i => i == target ? "hashcat" : $"{(resume ? 'a' : 'w')}{i:000000}"));
            await File.WriteAllTextAsync(rule, ":\n$1\n");
            await File.WriteAllTextAsync(hashFile, hash);
            var attack = new PreparedAttack { Description = "dictionary", Args = { "-a", "0", words, "-r", rule } };
            var request = new RunRequest
            {
                Mode = mode, HashFile = hashFile, Attack = attack, SessionName = "rk_dict_" + Guid.NewGuid().ToString("N"), SessionDir = dir,
                Settings = new Settings { DontUsePasswordCache = true, Priority = ProcessPriority.Normal },
            };
            var messages = new List<string>();
            HybridRunner Runner()
            {
                var runner = new HybridRunner
                {
                    Devices = null, ForceGpu = true, ThreadsOverride = 3, HashcatStartupSeconds = .01,
                    InitialGpuSpeed = mode == 13000 ? 60000 : 10000, InitialCpuSpeed = 3000,
                };
                runner.OutputLine += line => { messages.Add(line); log.WriteLine(line); };
                runner.Warning += log.WriteLine;
                runner.StatusReceived += status => log.WriteLine($"{status.ProgressDone}/{status.ProgressTotal}: "
                    + string.Join(", ", status.Devices.Select(d => $"{d.Name} {d.Speed:F0}/s")));
                return runner;
            }
            if (resume)
            {
                using var stop = new CancellationTokenSource(TimeSpan.FromMinutes(3));
                var first = Runner();
                first.StatusReceived += status => { if (status.ProgressDone > 0 && status.ProgressDone < status.ProgressTotal) stop.Cancel(); };
                var stopped = await first.RunAsync(new HybridPlan(kernel!, null) { Dictionary = DictionaryAttack.Parse(attack.Args) }, hash, request, tool, stop.Token);
                Assert.Equal(RunOutcome.Aborted, stopped.Outcome);
                Assert.True(File.Exists(HybridRunner.RestoreFile(dir, request.SessionName)));
                request = request with { Restore = true };
            }
            using var timeout = new CancellationTokenSource(TimeSpan.FromMinutes(5));
            var result = await Runner().RunAsync(new HybridPlan(kernel!, null) { Dictionary = DictionaryAttack.Parse(attack.Args) }, hash, request, tool, timeout.Token);
            Assert.Equal(RunOutcome.Cracked, result.Outcome);
            Assert.Equal("hashcat", Assert.Single(result.Passwords));
            if (target == count - 1) Assert.Contains("Found by the built-in CPU engine.", messages);
            else Assert.Contains(messages, message => message.StartsWith("Found by "));
        }
        finally { Directory.Delete(dir, true); }
    }

    [Theory]
    [InlineData(13000, 32000)]
    [InlineData(12500, 16000)]
    public async Task ResumesAfterGpuAdvancesInsideItsRange(int mode, int count)
    {
        // Keep the unfinished CPU batch above zero so its lower boundary does not clamp the GPU cursor.
        count = Math.Max(count, 100000);
        // Keep enough work for a status interval on a discrete GPU.
        if (OperatingSystem.IsWindows()) count = Math.Max(count, 300000);
        string? exe = Environment.GetEnvironmentVariable("RECOVERKIT_TEST_HASHCAT");
        Assert.False(string.IsNullOrEmpty(exe), "Set RECOVERKIT_TEST_HASHCAT to a private hashcat 8 copy.");
        var tool = HashcatTool.Locate(exe)!;
        string hash = NativeKernels.BenchmarkHashes[mode];
        var kernel = NativeKernels.TryCreate(mode, hash);
        Assert.NotNull(kernel);
        string dir = Directory.CreateTempSubdirectory("rk-dict-gpu-resume").FullName;
        try
        {
            string words = Path.Combine(dir, "words"), rules = Path.Combine(dir, "rules"), hashes = Path.Combine(dir, "hashes");
            await File.WriteAllLinesAsync(words, Enumerable.Range(0, count).Select(i => $"w{i:0000000}"));
            await File.WriteAllTextAsync(rules, ":\n$1\n");
            await File.WriteAllTextAsync(hashes, hash);
            var attack = new PreparedAttack { Description = "dictionary", Args = { "-a", "0", words, "-r", rules } };
            var request = new RunRequest
            {
                Mode = mode, HashFile = hashes, Attack = attack, SessionName = "rk_gpu_resume_" + Guid.NewGuid().ToString("N"), SessionDir = dir,
                // Bound GPU dispatches so the test can stop inside a range on devices with large autotuned batches.
                Settings = new Settings { DontUsePasswordCache = true, Priority = ProcessPriority.Normal, ExtraArguments = "--force -n 1" },
            };
            using var stop = new CancellationTokenSource(TimeSpan.FromMinutes(8));
            HybridRunner Runner(Action<HashcatStatus> rawStatus) => new()
            {
                ForceGpu = true, ThreadsOverride = 2, HashcatStartupSeconds = 1,
                InitialGpuSpeed = mode == 13000 ? 12000 : 4000, InitialCpuSpeed = 500,
                GuardEvents = h => h.StatusReceived += rawStatus,
            };
            var first = Runner(status =>
            {
                if (status.Status == 3 && status.RestorePoint > 0 && status.RestorePoint < count)
                {
                    log.WriteLine($"GPU stop: progress {status.ProgressDone}, restore {status.RestorePoint}");
                    stop.Cancel();
                }
            });
            var result = await first.RunAsync(new HybridPlan(kernel!, null) { Dictionary = DictionaryAttack.Parse(attack.Args) }, hash, request, tool, stop.Token);
            Assert.Equal(RunOutcome.Aborted, result.Outcome);
            var checkpoint = JsonSerializer.Deserialize<HybridResumePoint>(await File.ReadAllTextAsync(HybridRunner.RestoreFile(dir, request.SessionName)))!;
            Assert.InRange(checkpoint.Lo, 1, count - 1);
            log.WriteLine($"Saved GPU base-word cursor: {checkpoint.Lo}");
            HashcatStatus? raw = null;
            bool relativeProgress = false;
            var resumed = Runner(status =>
            {
                if (status.Status != 3) return;
                log.WriteLine($"Resume raw status: progress {status.ProgressDone}/{status.ProgressTotal}, restore {status.RestorePoint}, speed {status.TotalSpeed:F0}");
                if (status.TotalSpeed > 0) raw ??= status;
                if (status.RestorePoint > checkpoint.Lo && status.ProgressDone < status.RestorePoint * 2) relativeProgress = true;
            });
            using var timeout = new CancellationTokenSource(TimeSpan.FromMinutes(8));
            result = await resumed.RunAsync(new HybridPlan(kernel!, null) { Dictionary = DictionaryAttack.Parse(attack.Args) }, hash, request with { Restore = true }, tool, timeout.Token);
            Assert.Equal(RunOutcome.Exhausted, result.Outcome);
            Assert.NotNull(raw);
            log.WriteLine($"Resumed raw GPU progress {raw!.ProgressDone}, skip {checkpoint.Lo}, amplifier 2");
            Assert.True(relativeProgress, "hashcat dictionary progress is relative to the requested range");
            Assert.Equal((long)count * 2, result.LastStatus!.ProgressDone);
        }
        finally { Directory.Delete(dir, true); }
    }

    [Theory]
    [InlineData(128)]
    [InlineData(256)]
    public async Task LongRar5ReferenceFallbackMatchesHashcat(int length)
    {
        string? exe = Environment.GetEnvironmentVariable("RECOVERKIT_TEST_HASHCAT");
        Assert.False(string.IsNullOrEmpty(exe), "Set RECOVERKIT_TEST_HASHCAT to a private hashcat 8 copy.");
        var tool = HashcatTool.Locate(exe)!;
        string dir = Directory.CreateTempSubdirectory("rk-dict-long-oracle").FullName;
        try
        {
            byte[] password = Enumerable.Range(0, length).Select(i => (byte)(i % 251)).ToArray();
            byte[] salt = Enumerable.Range(0, 16).Select(i => (byte)i).ToArray();
            string hash = $"$rar5$16${Convert.ToHexString(salt)}$01${new string('0', 32)}$8${Convert.ToHexString(Rar5Kernel.CheckValue(password, salt, 1))}";
            string hashes = Path.Combine(dir, "hash"), words = Path.Combine(dir, "words"), output = Path.Combine(dir, "output");
            await File.WriteAllTextAsync(hashes, hash);
            await File.WriteAllTextAsync(words, PasswordConfirmation.HexPlain(password) + "\n");
            var (code, o, e) = await tool.RunAsync(["-m", "13000", hashes, "-a", "0", words, "--potfile-disable", "--restore-disable",
                "--session", "rk_dictionary_long", "--quiet", "-o", output, "--outfile-format", "3"], TimeSpan.FromMinutes(3));
            Assert.True(code == 0, $"hashcat {code}: {o} {e}");
            Assert.Equal(password, Convert.FromHexString(Assert.Single(await File.ReadAllLinesAsync(output))));
            var attack = new PreparedAttack { Description = "long dictionary", Args = { "-a", "0", words } };
            var request = new RunRequest
            {
                Mode = 13000, HashFile = hashes, Attack = attack, SessionName = "rk_long_cpu", SessionDir = dir,
                PasswordCachePath = Path.Combine(dir, "cache"), Settings = new Settings { DontUsePasswordCache = false },
            };
            var result = await new HybridRunner { ThreadsOverride = 1 }.RunAsync(
                new HybridPlan(Rar5Kernel.TryParse(hash)!, null) { Dictionary = DictionaryAttack.Parse(attack.Args) }, hash, request, tool, CancellationToken.None);
            Assert.Equal(RunOutcome.Cracked, result.Outcome);
            Assert.Equal(password, PasswordConfirmation.PlainBytes(Assert.Single(result.Passwords)));
            var cached = await tool.ShowRawAsync(13000, hashes, request.PasswordCachePath!, preserveBom: true);
            Assert.Equal(password, PasswordConfirmation.PlainBytes(Assert.Single(cached)));
        }
        finally { Directory.Delete(dir, true); }
    }

    [Fact]
    public async Task StdoutAndCrackingAgreeWhenRulesRejectOrGrowWords()
    {
        string? exe = Environment.GetEnvironmentVariable("RECOVERKIT_TEST_HASHCAT");
        Assert.False(string.IsNullOrEmpty(exe), "Set RECOVERKIT_TEST_HASHCAT to a private hashcat 8 copy.");
        var tool = HashcatTool.Locate(exe)!;
        string dir = Directory.CreateTempSubdirectory("rk-dict-reject").FullName;
        try
        {
            string words = Path.Combine(dir, "words"), rules = Path.Combine(dir, "rules"), hashes = Path.Combine(dir, "hashes");
            await File.WriteAllLinesAsync(words, new[] { "", "a", "abc", "abcde", new string('x', 250), "tail" });
            await File.WriteAllTextAsync(rules, ":\nD4\n'3\nd\n");
            var args = new List<string> { "-a", "0", words, "-r", rules };
            var dictionary = new DictionaryAttack(args);
            Assert.True(await dictionary.PrepareAsync(tool, 0, CancellationToken.None));
            Assert.Equal(6, dictionary.BaseCount);
            Assert.Equal(4, dictionary.AmplifierCount);
            var all = await dictionary.ReadCandidates(0, 6, CancellationToken.None);
            await File.WriteAllLinesAsync(hashes, all.Select(p => Convert.ToHexString(MD5.HashData(p))).Distinct());
            for (int lo = 0; lo < 6; lo += 2)
            {
                var candidates = await dictionary.ReadCandidates(lo, 2, CancellationToken.None);
                string output = Path.Combine(dir, $"out-{lo}");
                var (code, o, e) = await tool.RunAsync(["-m", "0", hashes, .. args, "--skip", lo.ToString(), "--limit", "2",
                    "--potfile-disable", "--restore-disable", "--session", "rk_dictionary_reject", "--quiet", "-o", output, "--outfile-format", "3"], TimeSpan.FromMinutes(3));
                Assert.True(code is 0 or 1, $"hashcat {code}: {o} {e}");
                Assert.Equal(candidates.Select(p => Convert.ToHexString(p)).Distinct().Order(), File.ReadAllLines(output).Select(s => s.ToUpperInvariant()).Order());
            }
        }
        finally { Directory.Delete(dir, true); }
    }

    [Fact]
    public async Task ReportsCandidateSupplyCost()
    {
        string? exe = Environment.GetEnvironmentVariable("RECOVERKIT_TEST_HASHCAT");
        Assert.False(string.IsNullOrEmpty(exe), "Set RECOVERKIT_TEST_HASHCAT to a private hashcat 8 copy.");
        var tool = HashcatTool.Locate(exe)!;
        string dir = Directory.CreateTempSubdirectory("rk-dict-supply").FullName;
        try
        {
            string words = Path.Combine(dir, "words"), rules = Path.Combine(dir, "rules");
            await File.WriteAllLinesAsync(words, Enumerable.Range(0, 300000).Select(i => $"w{i:000000}"));
            await File.WriteAllTextAsync(rules, ":\n$1\n$2\n$3\n");
            var dictionary = new DictionaryAttack(["-a", "0", words, "-r", rules]);
            Assert.True(await dictionary.PrepareAsync(tool, 13000, CancellationToken.None));
            for (int i = 0; i < 3; i++)
            {
                var elapsed = Stopwatch.StartNew();
                var candidates = await dictionary.ReadCandidates(295000, 5000, CancellationToken.None);
                elapsed.Stop();
                Assert.Equal(20000, candidates.Count);
                log.WriteLine($"stdout: {candidates.Count} candidates, {elapsed.Elapsed.TotalSeconds:F3} s, {candidates.Count / elapsed.Elapsed.TotalSeconds:F0}/s");
            }
        }
        finally { Directory.Delete(dir, true); }
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    public async Task StdoutAndCrackingUseTheSameWordRanges(int ruleFiles)
    {
        string? exe = Environment.GetEnvironmentVariable("RECOVERKIT_TEST_HASHCAT");
        Assert.False(string.IsNullOrEmpty(exe), "Set RECOVERKIT_TEST_HASHCAT to a private hashcat 8 copy.");
        var tool = HashcatTool.Locate(exe)!;
        string dir = Directory.CreateTempSubdirectory("rk-dict-numbering").FullName;
        try
        {
            string words = Path.Combine(dir, "words"), r1 = Path.Combine(dir, "one.rule"), r2 = Path.Combine(dir, "two.rule");
            // Empty, CRLF, decoded HEX, non-UTF-8, UTF-8, embedded NUL, overlong and unterminated final words.
            byte[][] decoded = ["aa"u8.ToArray(), [], "bb"u8.ToArray(), "cc"u8.ToArray(), [255, 100, 100],
                Encoding.UTF8.GetBytes("\u00e9"), [120, 0, 121], [239, 187, 191, 97], Encoding.UTF8.GetBytes("\u00f8"), Enumerable.Repeat((byte)'x', 260).ToArray(), "ee"u8.ToArray(), "$HEX[no]"u8.ToArray()];
            await File.WriteAllBytesAsync(words, [.. "aa\r\n\r\nbb\n$HEX[6363]\n"u8, 255, 100, 100, 10,
                .. Encoding.UTF8.GetBytes("\u00e9\n"), .. "$HEX[780079]\n$HEX[efbbbf61]\n"u8, .. Encoding.UTF8.GetBytes("\u00f8\n"), .. decoded[9], 10, .. "ee\n$HEX[no]"u8]);
            await File.WriteAllTextAsync(r1, ":\n$1\n");
            await File.WriteAllTextAsync(r2, ":\n$2\n");
            var args = new List<string> { "-a", "0", words };
            if (ruleFiles >= 1) args.AddRange(["-r", r1]);
            if (ruleFiles >= 2) args.AddRange(["-r", r2]);
            var dictionary = new DictionaryAttack(args);
            Assert.True(await dictionary.PrepareAsync(tool, 0, CancellationToken.None));
            Assert.Equal(decoded.Length, dictionary.BaseCount);
            Assert.Equal(1 << ruleFiles, dictionary.AmplifierCount);
            byte[][] suffixes = ruleFiles switch { 0 => [[]], 1 => [[], [49]], _ => [[], [49], [50], [49, 50]] };
            var all = decoded.Where(w => w.Length < 256).SelectMany(w => suffixes.Select(s => w.Concat(s).ToArray())).ToArray();
            string hashes = Path.Combine(dir, "hashes");
            await File.WriteAllLinesAsync(hashes, all.Select(p => Convert.ToHexString(MD5.HashData(p))));
            foreach ((long lo, long count) in new[] { (0L, 2L), (2L, 5L), (7L, 5L) })
            {
                var expected = decoded.Skip((int)lo).Take((int)count).Where(w => w.Length < 256)
                    .SelectMany(w => suffixes.Select(s => Convert.ToHexString(w.Concat(s).ToArray()))).Order().ToArray();
                var exported = await dictionary.ReadCandidates(lo, count, CancellationToken.None);
                Assert.Equal(expected, exported.Select(p => Convert.ToHexString(p)).Order().ToArray());
                string output = Path.Combine(dir, $"out-{lo}");
                var (code, o, e) = await tool.RunAsync(["-m", "0", hashes, .. args, "--skip", lo.ToString(), "--limit", count.ToString(),
                    "--potfile-disable", "--restore-disable", "--session", "rk_dictionary_numbering", "--quiet", "-o", output, "--outfile-format", "3"], TimeSpan.FromMinutes(3));
                Assert.True(code is 0 or 1, $"hashcat {code}: {o} {e}");
                Assert.Equal(expected, File.ReadAllLines(output).Select(s => s.ToUpperInvariant()).Order().ToArray());
            }
        }
        finally { Directory.Delete(dir, true); }
    }
}
