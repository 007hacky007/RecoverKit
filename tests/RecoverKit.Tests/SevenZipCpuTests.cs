using RecoverKit.Core.Formats;
using RecoverKit.Core.Native;
using RecoverKit.Core.Native.Kernels;
using System.Text;
using RecoverKit.Core;
using RecoverKit.Core.Attacks;
using RecoverKit.Core.Hashcat;
using System.Security.Cryptography;
using System.IO.Compression;
using Xunit;

namespace RecoverKit.Tests;

public class SevenZipCpuTests
{
    [Theory]
    [InlineData(0u)]
    [InlineData(1u)]
    [InlineData(1024u)]
    [InlineData(4095u)]
    public void Lzma1UsesTheSdkMinimumDictionary(uint dictionary)
    {
        // Python's public liblzma raw LZMA1 encoding, with a 4096-byte dictionary.
        byte[] packed = Convert.FromHexString("00241949986f1019c6d731eb36d842bce1312a65396e6bdb8c1a85ffffd57f0000");
        byte[] properties = [0x5d, 0, 0, 0, 0];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(properties.AsSpan(1), dictionary);
        byte[] expected = Encoding.ASCII.GetBytes(string.Concat(Enumerable.Repeat("Hello world! ", 100)));
        Assert.Equal(expected, SevenZipLzma.Decode(packed, properties, expected.Length));
    }

    [Theory]
    [InlineData(0x80)]
    [InlineData(0xa0)]
    public void Lzma2DictionaryResetRequiresNewProperties(int control)
    {
        // liblzma's raw LZMA2 encoding of "Hello world! " repeated 100 times.
        byte[] initialized = Convert.FromHexString("e00513001b5d00241949986f1019c6d731eb36d842bce1312a65396e6bdb2ec9320000");
        byte[] data = [.. initialized[..^1], 1, 0, 0, 65, (byte)control, 0, 0, 0, 4, 0, 0, 0, 0, 0];
        using var input = new MemoryStream(data);
        using var decoder = SevenZipLzma.Open(input, [0], 1302, true);
        var output = new byte[1302];
        var error = Assert.Throws<FormatException>(() => decoder.ReadExactly(output));
        Assert.Contains("properties", error.Message);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    public void Lzma2ControlBytesFollowSdkInitializationLevels(int stage)
    {
        byte[] initialized = Convert.FromHexString("e00513001b5d00241949986f1019c6d731eb36d842bce1312a65396e6bdb2ec9320000");
        byte[] prefix = stage == 0 ? [] : initialized[..^1];
        if (stage == 2) prefix = [.. prefix, 1, 0, 0, 65];
        int decodedPrefix = stage == 0 ? 0 : stage == 1 ? 1300 : 1301;
        for (int control = 0; control < 256; control++)
        {
            // SDK needInitLevel: E0 initially, 0 after LZMA, C0 after control 1.
            int level = stage == 0 ? 0xe0 : stage == 1 ? 0 : 0xc0;
            bool accepted = control == 1 || control == 2 && stage != 0 || control >= Math.Max(0x80, level);
            byte[] data = [.. prefix, (byte)control, 0, 0, 0, 5,
                .. control >= 0xc0 ? new byte[] { 0 } : Array.Empty<byte>(), 0, 0, 0, 0, 0, 0];
            using var input = new MemoryStream(data);
            using var decoder = SevenZipLzma.Open(input, [0], decodedPrefix + 1, true);
            decoder.ReadExactly(new byte[decodedPrefix]);
            if (accepted) Assert.True(decoder.ReadByte() >= 0, $"stage {stage}, control {control:X2}");
            else Assert.Throws<FormatException>(() => decoder.ReadByte());
        }
    }

    [Fact]
    public void EngineWinnerCancellationReachesStreamingWorkers()
    {
        var kernel = new CaptureWorkerTokenKernel(CpuTarget("7zz-copy-off"));
        var space = MaskSpace.FromHashcatArgs(["-a", "3", "kit?d"])!;
        var result = new NativeEngine(kernel, space) { Threads = 1 }.Run(null, default);
        Assert.Equal(NativeOutcome.Found, result.Outcome);
        Assert.True(kernel.WorkerToken.IsCancellationRequested);
        Assert.True(kernel.Verify("kit7"u8));
    }

    [Fact]
    public void WorkerTokenStopsChecksWithoutStoppingIndependentVerification()
    {
        var kernel = new SevenZipKernel(CpuTarget("7zz-copy-off"));
        using var stop = new CancellationTokenSource(); stop.Cancel();
        Assert.Equal(-1, kernel.CreateWorker(stop.Token).Search("kit"u8, "7"u8));
        Assert.True(kernel.Verify("kit7"u8));
    }

    private sealed class CaptureWorkerTokenKernel(SevenZipCpuTarget target) : NativeKernel
    {
        private readonly SevenZipKernel inner = new(target);
        internal CancellationToken WorkerToken;
        public override string Name => inner.Name;
        public override double SpeedHint => inner.SpeedHint;
        public override bool Verify(ReadOnlySpan<byte> password) => inner.Verify(password);
        public override KernelWorker CreateWorker() => inner.CreateWorker();
        public override KernelWorker CreateWorker(CancellationToken stop)
        {
            WorkerToken = stop;
            return inner.CreateWorker(stop);
        }
    }

    [Fact]
    public async Task MissingArchiveStopsMaskAndDictionarySessionsWithAnError()
    {
        string dir = SevenZipGeneratedTests.Scratch();
        try
        {
            var cpu = CpuTarget("7zz-LZMA2-off") with { Paths = [Path.Combine(dir, "missing.7z")] };
            var target = new HashTarget { FormatId = "7ZIP", FormatName = "7-Zip archive", Protection = "AES",
                Modes = [], HashLines = "$recoverkit-7z$missing", SevenZipCpu = cpu };
            string exe = Path.Combine(dir, "hashcat"), dict = Path.Combine(dir, "words.txt");
            File.WriteAllText(exe, "not executable"); File.WriteAllText(dict, "kit7\n");
            var session = new RecoverySession(HashcatTool.Locate(exe, dir, dir)!,
                new Settings { SessionsDir = dir, DontUsePasswordCache = true, MaxCpuThreads = 1 });
            foreach (var attack in new[] { new AttackSpec { Kind = AttackKind.Mask, HashcatMask = "kit?d" },
                new AttackSpec { Kind = AttackKind.Dictionary, Dictionaries = [dict, null, null, null] } })
            {
                var result = await session.RunAsync(target, cpu.Paths[0], [attack], null, default);
                Assert.Equal(SessionOutcome.Error, result.Outcome);
                Assert.Contains("missing.7z", result.Error);
            }
        }
        finally { Directory.Delete(dir, true); }
    }

    [Fact]
    public void DeflateTrialPrefixExhaustionIsInconclusive()
    {
        string dir = SevenZipGeneratedTests.Scratch();
        try
        {
            var data = new byte[8192]; new Random(714).NextBytes(data);
            using var packed = new MemoryStream();
            // Valid empty non-final stored blocks can delay the first output past the trial prefix.
            for (int i = 0; i < 14000; i++) packed.Write([0, 0, 0, 255, 255]);
            using (var deflate = new DeflateStream(packed, CompressionLevel.Optimal, leaveOpen: true)) deflate.Write(data);
            int aesLength = (int)packed.Length;
            byte[] plain = new byte[(aesLength + 15) / 16 * 16]; packed.ToArray().CopyTo(plain, 0);
            using var aes = Aes.Create(); byte[] key = SevenZipKernel.DeriveKey("secret"u8, [], 8); aes.Key = key;
            string path = Path.Combine(dir, "deflate.bin"); File.WriteAllBytes(path, aes.EncryptCbc(plain, aes.IV, PaddingMode.None));
            var target = new SevenZipCpuTarget([path], 0, plain.Length, aesLength, data.Length, data.Length,
                ZipCryptoSample.Crc32(data), 7, [], 8, [], aes.IV);
            Assert.Equal(SevenZipKernel.CheckResult.Match, new SevenZipKernel(target).CheckKey(key));
        }
        finally { Directory.Delete(dir, true); }
    }

    [Fact]
    public void CancellationInsideLastCharacterLoopCannotSkipTheRightPassword()
    {
        var target = CpuTarget("7zz-LZMA2-off");
        var space = MaskSpace.FromHashcatArgs(["-a", "3", "kit?d"])!;
        using var stop = new CancellationTokenSource();
        var first = new NativeEngine(new CancelInSearchKernel(target, stop), space) { Threads = 1 }.Run(null, stop.Token);
        Assert.Equal(NativeOutcome.Stopped, first.Outcome);
        Assert.Equal(0, first.ResumeAt!.PrefixIndex);
        var rest = new NativeEngine(new SevenZipKernel(target), space) { Threads = 1 }.Run(first.ResumeAt, default);
        Assert.Equal(NativeOutcome.Found, rest.Outcome);
        Assert.Equal("kit7"u8.ToArray(), rest.Password);
    }

    private sealed class CancelInSearchKernel(SevenZipCpuTarget target, CancellationTokenSource stop) : NativeKernel
    {
        private readonly SevenZipKernel kernel = new(target, stop.Token);
        public override string Name => kernel.Name;
        public override double SpeedHint => kernel.SpeedHint;
        public override bool Verify(ReadOnlySpan<byte> password) => kernel.Verify(password);
        public override KernelWorker CreateWorker() => new Worker(kernel.CreateWorker(), stop);
        private sealed class Worker(KernelWorker inner, CancellationTokenSource stop) : KernelWorker
        {
            public override int Search(ReadOnlySpan<byte> prefix, ReadOnlySpan<byte> last)
            {
                int first = inner.Search(prefix, last[..1]);
                stop.Cancel();
                if (first >= 0) return first;
                int rest = inner.Search(prefix, last[1..]);
                return rest < 0 ? -1 : rest + 1;
            }
        }
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(4)]
    [InlineData(5)]
    [InlineData(6)]
    [InlineData(7)]
    [InlineData(8)]
    [InlineData(9)]
    [InlineData(10)]
    [InlineData(11)]
    [InlineData(12)]
    [InlineData(13)]
    [InlineData(14)]
    [InlineData(15)]
    public void CopyChecksEveryPaddingLengthAndUsesCrcAsFinalDecision(int padding)
    {
        string dir = SevenZipGeneratedTests.Scratch();
        try
        {
            byte[] data = new byte[96 - padding]; new Random(716 + padding).NextBytes(data);
            byte[] key = SevenZipKernel.DeriveKey("secret"u8, [], 8);
            using var aes = Aes.Create(); aes.Key = key;
            byte[] plain = new byte[96]; data.CopyTo(plain, 0);
            string path = Path.Combine(dir, "copy.bin");
            File.WriteAllBytes(path, aes.EncryptCbc(plain, aes.IV, PaddingMode.None));
            var target = new SevenZipCpuTarget([path], 0, 96, data.Length, data.Length, data.Length,
                ZipCryptoSample.Crc32(data), 0, [], 8, [], aes.IV);
            Assert.Equal(SevenZipKernel.CheckResult.Match, new SevenZipKernel(target).CheckKey(key));
            if (padding != 0)
            {
                plain[^1] = 1;
                File.WriteAllBytes(path, aes.EncryptCbc(plain, aes.IV, PaddingMode.None));
                Assert.Equal(SevenZipKernel.CheckResult.Padding, new SevenZipKernel(target).CheckKey(key));
            }
            plain[^1] = 0; plain[40] ^= 1;
            File.WriteAllBytes(path, aes.EncryptCbc(plain, aes.IV, PaddingMode.None));
            Assert.Equal(SevenZipKernel.CheckResult.Crc, new SevenZipKernel(target).CheckKey(key));
            using (var file = File.OpenWrite(path)) file.SetLength(95);
            Assert.ThrowsAny<IOException>(() => new SevenZipKernel(target).Verify("secret"u8));
            File.Delete(path);
            Assert.ThrowsAny<IOException>(() => new SevenZipKernel(target).Verify("secret"u8));
        }
        finally { Directory.Delete(dir, true); }
    }

    [Fact]
    public void MaskStopResumesAtOrBeforeEveryUntestedCandidate()
    {
        string dir = SevenZipGeneratedTests.Scratch();
        try
        {
            var original = CpuTarget("7zz-copy-off");
            using var aes = Aes.Create();
            byte[] bytes = File.ReadAllBytes(original.Paths[0]).AsSpan((int)original.DataOffset, (int)original.PackedSize).ToArray();
            aes.Key = SevenZipKernel.DeriveKey("kit7"u8, [], 19);
            byte[] plain = aes.DecryptCbc(bytes, original.Iv, PaddingMode.None);
            aes.Key = SevenZipKernel.DeriveKey("ki99"u8, [], 19);
            string path = Path.Combine(dir, "copy.bin"); File.WriteAllBytes(path, aes.EncryptCbc(plain, original.Iv, PaddingMode.None));
            var target = original with { Paths = [path], DataOffset = 0 };
            // The known password is late in the mask; stop after at least one completed prefix.
            var space = MaskSpace.FromHashcatArgs(["-a", "3", "ki?d?d"])!;
            using var stop = new CancellationTokenSource();
            var engine = new NativeEngine(new SevenZipKernel(target, stop.Token), space)
            { Threads = 1, Priority = ThreadPriority.Normal, ProgressInterval = TimeSpan.FromMilliseconds(5) };
            engine.Progress += p => { if (p.Done > 0) stop.Cancel(); };
            var first = engine.Run(null, stop.Token);
            Assert.Equal(NativeOutcome.Stopped, first.Outcome);
            Assert.NotNull(first.ResumeAt);
            Assert.True(first.Tested > 0);
            var rest = new NativeEngine(new SevenZipKernel(target), space) { Threads = 2, Priority = ThreadPriority.Normal }.Run(first.ResumeAt, default);
            Assert.Equal(NativeOutcome.Found, rest.Outcome);
            Assert.Equal("ki99"u8.ToArray(), rest.Password);
        }
        finally { Directory.Delete(dir, true); }
    }

    [Fact]
    public void ManagedKdfHonorsCancellationDuringLongDerivation()
    {
        {
            using var stop = new CancellationTokenSource(TimeSpan.FromMilliseconds(30));
            var watch = System.Diagnostics.Stopwatch.StartNew();
            SevenZipKernel.DeriveKey(new byte[256].Select(_ => (byte)'x').ToArray(), [], 24, stop.Token);
            Assert.True(stop.IsCancellationRequested);
            Assert.True(watch.Elapsed < TimeSpan.FromSeconds(3), "The KDF must stop within a buffer of work.");
        }
    }

    [Fact]
    public async Task DictionaryResumeReplaysInterruptedBatchAndRefusesChangedInput()
    {
        string dir = SevenZipGeneratedTests.Scratch();
        try
        {
            var cpu = CpuTarget("7zz-LZMA2-off");
            var target = new HashTarget { FormatId = "7ZIP", FormatName = "7-Zip archive", Protection = "AES",
                Modes = [], HashLines = "$recoverkit-7z$test", SevenZipCpu = cpu };
            string dictionary = Path.Combine(dir, "words.txt");
            File.WriteAllLines(dictionary, Enumerable.Range(0, 40).Select(i => "wrong" + i).Append("kit7"));
            var spec = new AttackSpec { Kind = AttackKind.Dictionary, Dictionaries = [dictionary, null, null, null] };
            var context = new PlannerContext();
            var attack = AttackPlanner.Prepare(spec, target, context);
            var settings = new Settings { SessionsDir = dir, DontUsePasswordCache = true, MaxCpuThreads = 2 };
            RunRequest Request(bool restore) => new() { Mode = 0, HashFile = "", Attack = attack, Settings = settings,
                SessionDir = dir, SessionName = "resume-test", Restore = restore };
            using var stop = new CancellationTokenSource();
            var runner = new SevenZipDictionaryRunner { ProgressInterval = TimeSpan.FromMilliseconds(1),
                Status = s => { if (s.ProgressDone > 0) stop.Cancel(); } };
            var first = await runner.RunAsync(target, Request(false), spec, context, stop.Token);
            Assert.Equal(RunOutcome.Aborted, first.Outcome);
            Assert.True(first.LastStatus!.ProgressDone > 0);
            string restoreFile = SevenZipDictionaryRunner.RestoreFile(dir, "resume-test");
            string saved = File.ReadAllText(restoreFile);
            var resumed = await new SevenZipDictionaryRunner().RunAsync(target, Request(true), spec, context, default);
            Assert.Equal(RunOutcome.Cracked, resumed.Outcome);
            Assert.Equal(["kit7"], resumed.Passwords);
            Assert.Equal(first.LastStatus.ProgressDone, resumed.LastStatus!.ResumedFrom);
            File.WriteAllText(restoreFile, saved);
            File.AppendAllText(dictionary, "changed\n");
            var changed = await new SevenZipDictionaryRunner().RunAsync(target, Request(true), spec, context, default);
            Assert.Equal(RunOutcome.Error, changed.Outcome);
            Assert.Contains("dictionary changed", changed.Error);
        }
        finally { Directory.Delete(dir, true); }
    }

    [Fact]
    public async Task CpuSessionSupportsMasksDictionariesAndResumeWithoutCallingHashcat()
    {
        string dir = Path.Combine(Environment.GetEnvironmentVariable("RECOVERKIT_HOME") ?? Path.GetTempPath(), "7z-session-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            var cpu = CpuTarget("7zz-LZMA2-off");
            HashTarget target;
            try
            {
                SevenZipExtractor.TestDataLimit = 1;
                target = FormatDetector.Detect(Fixture("7zz-LZMA2-off")).Target!;
            }
            finally { SevenZipExtractor.TestDataLimit = 0; }
            string exe = Path.Combine(dir, "hashcat"); File.WriteAllText(exe, "not executable");
            var settings = new Settings { SessionsDir = dir, DontUsePasswordCache = true, MaxCpuThreads = 2 };
            var session = new RecoverySession(HashcatTool.Locate(exe, dir, dir)!, settings)
            { Devices = [new BackendDevice { Id = 1, Type = "GPU", Backend = "Metal" }] };
            var mask = new AttackSpec { Kind = AttackKind.Mask, HashcatMask = "kit?d" };
            var found = await session.RunAsync(target, cpu.Paths[0], [mask], null, default);
            Assert.Equal(SessionOutcome.Found, found.Outcome);
            Assert.Equal(["kit7"], found.Passwords);
            var brute = await session.RunAsync(target, cpu.Paths[0], [new AttackSpec
            { Kind = AttackKind.BruteForce, Smalls = false, Digits = false, UseUserCharset = true,
                UserCharset = "789", Mask = "kit?", MinLength = 4, MaxLength = 4 }], null, default);
            Assert.Equal(SessionOutcome.Found, brute.Outcome);
            string dict = Path.Combine(dir, "words.txt"); File.WriteAllText(dict, "wrong\nkit7\nother\n");
            var attack = new AttackSpec { Kind = AttackKind.Dictionary, Dictionaries = [dict, null, null, null] };
            using var stop = new CancellationTokenSource(); stop.Cancel();
            var stopped = await session.RunAsync(target, cpu.Paths[0], [attack], null, stop.Token);
            Assert.Equal(SessionOutcome.Stopped, stopped.Outcome);
            var saved = SessionState.Load(settings, target);
            Assert.NotNull(saved);
            var resumed = await session.RunAsync(target, cpu.Paths[0], [attack], saved, default);
            Assert.Equal(SessionOutcome.Found, resumed.Outcome);
            Assert.Equal(["kit7"], resumed.Passwords);
            File.WriteAllText(dict, "wrong\n$HEX[6b697437]\n", Encoding.Unicode);
            var converted = await session.RunAsync(target, cpu.Paths[0], [attack], null, default);
            Assert.Equal(SessionOutcome.Found, converted.Outcome);
            Assert.Equal(["kit7"], converted.Passwords);
            attack.Rules = RulesPreset.Simple;
            var refused = await session.RunAsync(target, cpu.Paths[0], [attack], null, default);
            Assert.Equal(SessionOutcome.Error, refused.Outcome);
            Assert.Contains("without rules", refused.Error);
            bool started = false;
            session.StepStarted += (_, _, _, _) => started = true;
            var mixed = await session.RunAsync(target, cpu.Paths[0],
                [new AttackSpec { Kind = AttackKind.Mask, HashcatMask = "wrong" }, attack], null, default);
            Assert.Equal(SessionOutcome.Error, mixed.Outcome);
            Assert.False(started);
        }
        finally { Directory.Delete(dir, true); }
    }

    [Theory]
    [InlineData("", "", 0, "af5570f5a1810b7af78caf4bc70a660f0df51e42baf91d4de5b2328de0e83dfc")]
    [InlineData("kit7", "", 8, "6fde91b18860e5a50b3eae0dae0e680f5592ae462f37dacdd5a465a805be76c6")]
    [InlineData("kit7", "", 19, "2b867e77867b35047a85fc5bf3e3d8ffbdd58399db7aa503b2320158fad87a83")]
    [InlineData("příliš🔑", "000102030405060708090a0b0c0d0e0f", 19, "75691672300306e0f78666d8589b3b721e90e4549d60147ad4dc3e0adf4d7cdd")]
    public void KdfMatchesIndependentKnownAnswers(string password, string salt, int power, string expected)
    {
        Assert.Equal(expected, Convert.ToHexString(SevenZipKernel.DeriveKey(Encoding.UTF8.GetBytes(password),
            Convert.FromHexString(salt), power)).ToLowerInvariant());
    }

    [Theory]
    [InlineData("7zz-copy-off")]
    [InlineData("7zz-LZMA-off")]
    [InlineData("7zz-LZMA2-off")]
    [InlineData("7zz-Deflate-off")]
    [InlineData("solid")]
    [InlineData("many-off")]
    [InlineData("large-lzma2")]
    public void RealArchivesVerifyRightPasswordAndRejectWrongPassword(string fixture)
    {
        var target = CpuTarget(fixture);
        var kernel = new SevenZipKernel(target);
        Assert.True(kernel.Verify("kit7"u8));
        Assert.False(kernel.Verify("wrong"u8));
        Assert.Equal(0, kernel.CreateWorker().Search("kit"u8, "789"u8));
        Assert.False(new SevenZipKernel(target with { Crc = target.Crc ^ 1 }).Verify("kit7"u8));
    }

    internal static SevenZipCpuTarget CpuTarget(string fixture)
    {
        try
        {
            SevenZipExtractor.TestDataLimit = 1;
            return Assert.IsType<SevenZipCpuTarget>(FormatDetector.Detect(Fixture(fixture)).Target?.SevenZipCpu);
        }
        finally { SevenZipExtractor.TestDataLimit = 0; }
    }

    [Theory]
    [InlineData("7zz-copy-off")]
    [InlineData("7zz-LZMA-off")]
    [InlineData("7zz-LZMA2-off")]
    [InlineData("7zz-Deflate-off")]
    public void OversizedStreamUsesCpuWithoutHashcatMode(string fixture)
    {
        try
        {
            SevenZipExtractor.TestDataLimit = 1;
            var d = FormatDetector.Detect(Fixture(fixture));
            Assert.Null(d.Message);
            Assert.NotNull(d.Target);
            Assert.Empty(d.Target.Modes);
            Assert.Contains("processor", d.Target.Notes);
            Assert.Contains("graphics card", d.Target.Notes);
            Assert.Contains(d.Info, p => p.Value.Contains("processor"));
        }
        finally { SevenZipExtractor.TestDataLimit = 0; }
    }

    internal static string Fixture(string name) => Path.Combine(AppContext.BaseDirectory, "Fixtures", "SevenZip", name + ".7z");
}

public sealed class SevenZipManagedKdfTests
{
    [Fact]
    public void BatchedKdfHandlesRecordAndBlockBoundaries()
    {
        foreach (int length in new[] { 0, 1, 23, 24, 25, 31, 32, 127, 256 })
        foreach (int saltLength in new[] { 0, 16 })
        {
            byte[] password = Encoding.ASCII.GetBytes(new string('x', length));
            byte[] salt = Enumerable.Range(0, saltLength).Select(i => (byte)i).ToArray();
            using var reference = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            byte[] record = [.. salt, .. Encoding.Unicode.GetBytes(new string('x', length)), .. new byte[8]];
            for (ulong i = 0; i < 256; i++)
            {
                System.Buffers.Binary.BinaryPrimitives.WriteUInt64LittleEndian(record.AsSpan(record.Length - 8), i);
                reference.AppendData(record);
            }
            byte[] expected = reference.GetHashAndReset();
            foreach (int bytes in new[] { 4096, 65536, 262144 })
                Assert.Equal(expected, SevenZipKernel.DeriveKey(password, salt, 8, scratch: new byte[bytes]));
        }
    }
}
