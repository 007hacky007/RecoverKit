using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using System.IO.Compression;
using RecoverKit.Core;
using RecoverKit.Core.Attacks;
using RecoverKit.Core.Formats;
using RecoverKit.Core.Native;
using RecoverKit.Core.Native.Kernels;
using Xunit;

namespace RecoverKit.Tests;

[Collection("NativeFeatures")]
public sealed class Rar3FileCpuTests
{
    [Fact]
    public async Task AnAmbiguousWrongKeyDoesNotHideALaterCorrectPassword()
    {
        if (!RkNative.Available) return;
        using var sample = new CompressedSample();
        string wrong = sample.UnsupportedPassword;
        Assert.False(new Rar3FileKernel(sample.Entry).Verify(Encoding.ASCII.GetBytes(wrong)));
        var reasons = new List<string>();
        Assert.False(new Rar3FileKernel(sample.Entry) { Unconfirmed = (_, reason) => reasons.Add(reason) }.Verify(Encoding.ASCII.GetBytes(wrong)));
        Assert.Empty(reasons);
        await File.WriteAllLinesAsync(sample.Dictionary, [wrong, "kit3"]);
        var result = await new RecoverySession(null, sample.Settings).RunAsync(sample.Target, sample.Path,
            [sample.Attack], null, CancellationToken.None);
        Assert.Equal(SessionOutcome.Found, result.Outcome);
        Assert.Equal(["kit3"], result.Passwords);
        Assert.Null(SessionState.Load(sample.Settings, sample.Target));
    }

    [Fact]
    public async Task PossiblePasswordsSurviveStopAndResumeWithoutBecomingFound()
    {
        if (!RkNative.Available) return;
        using var sample = new CompressedSample(unconfirmed: true);
        await File.WriteAllLinesAsync(sample.Dictionary, ["kit3"]);
        using var stop = new CancellationTokenSource();
        var session = new RecoverySession(null, sample.Settings);
        session.Status += status => { if (status.Status == 3) stop.Cancel(); };
        var first = await session.RunAsync(sample.Target, sample.Path, [sample.Attack], null, stop.Token);
        Assert.Equal(SessionOutcome.Stopped, first.Outcome);
        var possible = Assert.Single(first.PossiblePasswords);
        Assert.Equal("kit3", possible.DisplayPassword);
        Assert.Empty(first.Passwords);
        var saved = Assert.IsType<SessionState>(SessionState.Load(sample.Settings, sample.Target));
        Assert.Equal(possible, Assert.Single(saved.Rar3PossiblePasswords));
        var resumed = await new RecoverySession(null, sample.Settings).RunAsync(sample.Target, sample.Path,
            [sample.Attack], saved, CancellationToken.None);
        Assert.Equal(SessionOutcome.Error, resumed.Outcome);
        Assert.Contains("must be tried by hand", resumed.Error!);
        Assert.Equal(possible, Assert.Single(resumed.PossiblePasswords));
        Assert.Empty(resumed.Passwords);
        Assert.Equal(possible, Assert.Single(SessionState.Load(sample.Settings, sample.Target)!.Rar3PossiblePasswords));
    }

    [Fact]
    public async Task AnUncheckedFirstStepDoesNotHideACorrectPasswordInALaterStep()
    {
        if (!RkNative.Available) return;
        using var sample = new CompressedSample();
        await File.WriteAllLinesAsync(sample.Dictionary, [sample.UnsupportedPassword]);
        string second = sample.Dictionary + ".second";
        await File.WriteAllLinesAsync(second, ["kit3"]);
        var later = new AttackSpec { Kind = AttackKind.Dictionary, Dictionaries = [second, null, null, null] };
        var result = await new RecoverySession(null, sample.Settings).RunAsync(sample.Target, sample.Path,
            [sample.Attack, later], null, CancellationToken.None);
        Assert.Equal(SessionOutcome.Found, result.Outcome);
        Assert.Equal(["kit3"], result.Passwords);
        Assert.Null(SessionState.Load(sample.Settings, sample.Target));
    }

    [Theory]
    [InlineData(129)]
    [InlineData(512)]
    public async Task OverlengthDictionaryCandidatesAreSkippedAndCounted(int length)
    {
        using var sample = new Sample("ab");
        string dictionary = System.IO.Path.Combine(sample.Directory, "words.txt");
        await File.WriteAllLinesAsync(dictionary, ["", new string('x', length), "wrong", ""]);
        var attack = new AttackSpec { Kind = AttackKind.Dictionary, Dictionaries = [dictionary, null, null, null] };
        var session = new RecoverySession(null, sample.Settings);
        RecoverKit.Core.Hashcat.HashcatStatus? last = null;
        session.Status += status => last = status;
        var result = await session.RunAsync(sample.Target, sample.Path, [attack], null, CancellationToken.None);
        Assert.Equal(SessionOutcome.NotFound, result.Outcome);
        Assert.Equal(2, last!.ProgressDone);
        Assert.Equal(last.ProgressTotal, last.ProgressDone);
        await File.WriteAllLinesAsync(dictionary, [new string('x', length), "ab"]);
        result = await session.RunAsync(sample.Target, sample.Path, [attack], null, CancellationToken.None);
        Assert.Equal(SessionOutcome.Found, result.Outcome);
        Assert.Equal(["ab"], result.Passwords);
    }

    [Theory]
    [InlineData(129)]
    [InlineData(512)]
    public async Task OverlengthMasksAreSkippedAndCounted(int length)
    {
        using var sample = new Sample("ab");
        var attack = new AttackSpec { Kind = AttackKind.Mask, HashcatMask = new string('x', length) };
        var session = new RecoverySession(null, sample.Settings);
        RecoverKit.Core.Hashcat.HashcatStatus? last = null;
        session.Status += status => last = status;
        var result = await session.RunAsync(sample.Target, sample.Path, [attack], null, CancellationToken.None);
        Assert.Equal(SessionOutcome.NotFound, result.Outcome);
        Assert.Equal(1, last!.ProgressDone);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task PossiblePasswordLimitKeepsTheUnfinishedBatchForReplay(bool mask)
    {
        if (!RkNative.Available) return;
        using var sample = new CompressedSample(unconfirmed: true);
        await File.WriteAllLinesAsync(sample.Dictionary, ["kit3", "wrong"]);
        var attack = mask ? new AttackSpec { Kind = AttackKind.Mask, HashcatMask = "kit3" } : sample.Attack;
        var state = new SessionState
        {
            Key = SessionState.KeyFor(sample.Target), FilePath = sample.Path, Steps = [attack],
            Rar3PossiblePasswords = Enumerable.Range(0, 63).Select(i => new PossiblePassword("saved-" + i, "bounded filter")).ToList(),
        };
        var result = await new RecoverySession(null, sample.Settings).RunAsync(sample.Target, sample.Path,
            [attack], state, CancellationToken.None);
        Assert.Equal(SessionOutcome.Error, result.Outcome);
        Assert.Contains("limit of 64", result.Error!);
        Assert.Equal(64, result.PossiblePasswords.Count);
        Assert.Contains(result.PossiblePasswords, p => p.DisplayPassword == "kit3");
        var saved = Assert.IsType<SessionState>(SessionState.Load(sample.Settings, sample.Target));
        Assert.Equal(64, saved.Rar3PossiblePasswords.Count);
        string checkpoint = System.IO.Directory.GetFiles(sample.Settings.SessionsDir, mask ? "*.native.json" : "*.rar3.dictionary.json").Single();
        using var json = System.Text.Json.JsonDocument.Parse(await File.ReadAllTextAsync(checkpoint));
        Assert.Equal(0, json.RootElement.GetProperty(mask ? "PrefixIndex" : "Done").GetInt64());
        var resumed = await new RecoverySession(null, sample.Settings).RunAsync(sample.Target, sample.Path,
            [attack], saved, CancellationToken.None);
        Assert.Equal(SessionOutcome.Error, resumed.Outcome);
        Assert.Equal(result.PossiblePasswords, resumed.PossiblePasswords);
    }

    [Fact]
    public void ConcurrentSessionSavesDoNotRaceOrCorruptPossiblePasswords()
    {
        using var sample = new Sample("ab");
        var state = new SessionState { Key = SessionState.KeyFor(sample.Target) };
        Parallel.For(0, 100, i =>
        {
            if ((i & 1) == 0)
            {
                lock (state)
                {
                    state.Rar3PossiblePasswords.Add(new PossiblePassword("candidate-" + i, "bounded filter"));
                    state.Save(sample.Settings);
                }
            }
            else state.Save(sample.Settings);
        });
        Assert.Equal(50, SessionState.Load(sample.Settings, sample.Target)!.Rar3PossiblePasswords.Count);
    }

    [Fact]
    public void LongPasswordsMatchTheRealRar29BufferMutation()
    {
        string password = "long-" + string.Concat(Enumerable.Repeat("abc123", 15));
        var (digest, iv) = Rar3Kernel.DeriveUtf16(Encoding.Unicode.GetBytes(password), Convert.FromHexString("003b478157339919"));
        var key = new byte[16];
        for (int i = 0; i < 16; i++) key[i] = digest[(i & ~3) + 3 - (i & 3)];
        // Independently derived and checked against a RAR 6.24 -ma4 archive's full CRC.
        Assert.Equal("2b658f5be693fe31484655ec87758323", Convert.ToHexString(key).ToLowerInvariant());
        Assert.Equal("6b337bcebef74077b30bd9e8c0a27a49", Convert.ToHexString(iv).ToLowerInvariant());
    }

    [Fact]
    public void AFull128CharacterKeyIsCheckedBeforeThe127CharacterAlias()
    {
        string password = new('a', 128);
        using var sample = new Sample(password);
        Assert.True(new Rar3FileKernel(sample.Entry).Verify(Encoding.UTF8.GetBytes(password)));
        Assert.False(new Rar3FileKernel(sample.Entry).Verify(Encoding.UTF8.GetBytes(password[..127])));
    }

    [Theory]
    [InlineData("pw26-0", 26, 26, "aabd972bdc30512a", "218fc9bdac0494fb3a4f9ca2b7bf11c583531ad5", "32029f4085751fdc3d28be759160a5ca")]
    [InlineData("pw26-1", 26, 26, "6a80950e8f352b0e", "f8217a21ce1232f9c681bc513b1e2e56b1b65f66", "379ca62f90d9278dc915f2fe5f18d4dc")]
    [InlineData("pw27-0", 27, 27, "bc19af875a786856", "d54fbd95b0b70cd7c0ee2f89c1e0021f6725d333", "af6c6e01561333cb1a60b5bc73420975")]
    [InlineData("pw27-1", 27, 27, "9fafc0bbd408c144", "ebf8ec512001f472ca795161933ba62bd2d308ca", "08c326279404e3e3b8073928c410dfe4")]
    [InlineData("pw28-0", 28, 28, "3c1b69664644c81e", "b8bc8a4062b52a7f0e3efc65612dff06bcafec32", "afa934d55b3b6ecc75ec3a260a9280d1")]
    [InlineData("pw28-1", 28, 28, "25cff918ea909f1d", "0d762da3692e41fc04346eec63927fb2d792a497", "a035fa9baee5dc1341dba722c9557191")]
    [InlineData("pw29-0", 29, 29, "72b174d8efca5b20", "250e3b0a9fdec6e0017c2cb27e0152cd27918222", "f3677d6af276bb359a5ebbf6eeb5c1f3")]
    [InlineData("pw29-1", 29, 29, "d92bd4b345995796", "9fc6f7b002b8cc98aaec9d5aa2aaefde08d2d260", "fba692894f301d912efd49cc3f4bce25")]
    [InlineData("pw32-0", 32, 32, "85b88f7e332fcb00", "0de2b0fa68862bfddadd7bf19c4e15949a2a0f15", "97b104ff6082cce3ffdd8a59b66deb4c")]
    [InlineData("pw32-1", 32, 32, "27a42bccac459dd8", "ff8e3f6ff0186ed9382f0766382251f4eb8c2d06", "ee3ed8ea7d627da8764b423794e11282")]
    [InlineData("pw64-0", 64, 64, "505c72392c48b098", "c0c2ef4bdaba969898ece4169c9f856d2638294c", "bcf119a72caec0c88b24208864cc71d8")]
    [InlineData("pw64-1", 64, 64, "0c05f08cdcb97fd0", "10b364d23aa6065d1da2fa39b0ba73adb5677842", "eeb156c8b904de0549f1cfc81e44dbe6")]
    [InlineData("pw95-0", 95, 95, "200c8ceea590aff5", "1a8313475f96638cdaa9ccaf92847a6142997563", "bea400777d39318262e743925cde7f4f")]
    [InlineData("pw95-1", 95, 95, "9500f9de831829ea", "06dbccd50a395f2add593ae43391ca7fec30cfb5", "e352f9445239bbd5f174c230bd84ab48")]
    [InlineData("pw127-0", 127, 127, "898abdab00ae59ed", "738cef90a3ba9a259ae0786e552501ee6168d020", "46372e2b97eb7946ca4aa2bf546907df")]
    [InlineData("pw127-1", 127, 127, "5a6cd573c5c69188", "fbeb33072ba4dfb7c65d9d6b62079fbbc0961265", "dff7d5dbfb9cf79e8a174a1c0539b375")]
    [InlineData("pw128-0", 128, 127, "38f5b876371be8be", "44b9fb1e59c25761f5475dea3db0f7b7cf5ae8ca", "2c0dc95d7a311274bebcb29c4f313d0b")]
    [InlineData("pw128-1", 128, 127, "a708fbaf325c8eb1", "8e107348e3785584cd9d71b271ea694c27dd0261", "866d29190ffe101ac1a84032c459e6cb")]
    [InlineData("unicode29", 29, 29, "3827ab16f2e5bd82", "2419104393081a88b91590c4318ddc67a9c7f596", "217a55679c5f4dd6526f74c70778d24f")]
    [InlineData("unicode32", 32, 32, "63ac2a5d40c8f7b7", "41676371a0f65c52608f2721d2a9f8ba5a5594e3", "5c95bf47bd54c67370e54ae892101bf8")]
    [InlineData("unicode64", 64, 64, "89a548d3689ed452", "c75fccc4c452ce094c4065948734492c682759c2", "1237a151cc20f64232fb9371f3b41a67")]
    [InlineData("unicode95", 95, 95, "3e96874c1afe5a56", "9194c5e79454c0c2eb1c7a54752af3c58534386c", "60f6c5b62caa6baeee450b2ac73ade79")]
    public void GenuineArchivesCoverKdfBoundariesAndBoth128CharacterMeanings(string name, int length,
        int effectiveLength, string saltHex, string expectedDigest, string expectedIv)
    {
        string alphabet = name.StartsWith("unicode", StringComparison.Ordinal) ? "\u017elu\u0165ou\u010dk\u00fd" : "abc12345";
        string original = string.Concat(Enumerable.Repeat(alphabet, 128))[..length];
        string password = original[..effectiveLength];
        var (digest, iv) = Rar3Kernel.DeriveUtf16(Encoding.Unicode.GetBytes(password), Convert.FromHexString(saltHex));
        Assert.Equal(expectedDigest, Convert.ToHexString(digest).ToLowerInvariant());
        Assert.Equal(expectedIv, Convert.ToHexString(iv).ToLowerInvariant());
        string directory = System.IO.Path.Combine(Settings.AppDataDir, "rar3-tests", Guid.NewGuid().ToString("N"));
        System.IO.Directory.CreateDirectory(directory);
        string path = System.IO.Path.Combine(directory, name + ".rar");
        try
        {
            using (var resource = typeof(Rar3FileCpuTests).Assembly.GetManifestResourceStream(
                "RecoverKit.Tests.Fixtures.Rar3Kdf." + name + ".rar")!)
            using (var output = File.Create(path)) resource.CopyTo(output);
            var detection = new Detection { FilePath = path };
            using (var stream = File.OpenRead(path)) RarExtractor.Extract(stream, detection);
            var hash = detection.Target!.HashLines.Split('*');
            long packed = long.Parse(hash[4]), unpacked = long.Parse(hash[5]);
            var bytes = File.ReadAllBytes(path);
            int offset = 20 + BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(25));
            var target = new Rar3FileTarget(path, offset, packed, unpacked, 0x30, 65536,
                Convert.FromHexString(hash[2]), BinaryPrimitives.ReadUInt32LittleEndian(Convert.FromHexString(hash[3])));
            var kernel = new Rar3FileKernel(target);
            Assert.True(kernel.Verify(Encoding.UTF8.GetBytes(password)));
            if (length != effectiveLength) Assert.True(kernel.Verify(Encoding.UTF8.GetBytes(original)));
            Assert.False(kernel.Verify("wrong"u8));
        }
        finally { System.IO.Directory.Delete(directory, recursive: true); }
    }

    [Fact]
    public void ExtractsLargeStoredEntryWithoutAHashcatMode()
    {
        using var sample = new Sample("ab");
        Assert.Empty(sample.Target.Modes);
        Assert.NotNull(sample.Target.Rar3File);
        Assert.Contains("327,680", sample.Target.Notes!);
        Assert.Contains("655,360", sample.Target.Notes!);
        Assert.Contains("processor without the graphics card", sample.Target.Notes!);
        Assert.Contains("Password recovery", sample.Detection.Info.Select(x => x.Key));
        Assert.True(new Rar3FileKernel(sample.Entry).Verify("ab"u8));
        Assert.False(new Rar3FileKernel(sample.Entry).Verify("ac"u8));
    }

    [Fact]
    public void StoredEntryRequiresTheEntireCrcAndHasBoundedManagedMemory()
    {
        using var sample = new Sample("ab", size: 4 * 1024 * 1024 + 3);
        var kernel = new Rar3FileKernel(sample.Entry);
        Assert.True(kernel.Verify("ab"u8));
        long allocated = GC.GetAllocatedBytesForCurrentThread();
        Assert.True(kernel.Verify("ab"u8));
        Assert.True(GC.GetAllocatedBytesForCurrentThread() - allocated < 512 * 1024);
        Assert.False(new Rar3FileKernel(sample.Entry with { Crc = sample.Entry.Crc ^ 1 }).Verify("ab"u8));
        using (var file = File.Open(sample.Path, FileMode.Open, FileAccess.ReadWrite))
        {
            file.Position = sample.Entry.DataOffset + sample.Entry.PackedLength - 32;
            int b = file.ReadByte();
            file.Position--;
            file.WriteByte((byte)(b ^ 1));
        }
        Assert.False(kernel.Verify("ab"u8));
    }

    [Fact]
    public void ATruncatedEntryFailsWithAReason()
    {
        using var sample = new Sample("ab");
        using (var file = File.OpenWrite(sample.Path)) file.SetLength(sample.Entry.DataOffset + sample.Entry.PackedLength - 1);
        Assert.Contains("truncated", Assert.Throws<InvalidDataException>(() => new Rar3FileKernel(sample.Entry).Verify("ab"u8)).Message);
    }

    [Theory]
    [InlineData("ab")]
    [InlineData("p\u0159\u00edli\u0161\ud83d\udd11")]
    [InlineData("a-password-longer-than-the-native-layout")]
    public async Task PlainDictionariesSupportShortLongAndUnicodePasswords(string password)
    {
        using var sample = new Sample(password);
        string dictionary = System.IO.Path.Combine(sample.Directory, "words.txt");
        await File.WriteAllLinesAsync(dictionary, ["wrong", password, "also-wrong"]);
        var attack = new AttackSpec { Kind = AttackKind.Dictionary, Dictionaries = [dictionary, null, null, null] };
        var session = new RecoverySession(null, sample.Settings);
        var statuses = new List<RecoverKit.Core.Hashcat.HashcatStatus>();
        session.Status += statuses.Add;
        var result = await session.RunAsync(sample.Target, sample.Path, [attack], null, CancellationToken.None);
        Assert.Equal(SessionOutcome.Found, result.Outcome);
        Assert.Equal([password], result.Passwords);
        Assert.All(statuses.SelectMany(s => s.Devices), d => Assert.Equal("CPU", d.Type));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task BruteForceAndMasksRunWithoutHashcat(bool brute)
    {
        using var sample = new Sample("ab");
        var attack = brute ? new AttackSpec
        {
            Kind = AttackKind.BruteForce, Smalls = false, Digits = false, UseUserCharset = true,
            UserCharset = "abc", MinLength = 2, MaxLength = 2,
        } : new AttackSpec { Kind = AttackKind.Mask, HashcatMask = "a?1", CustomCharsets = ["bc", "", "", "", "", "", "", ""] };
        var result = await new RecoverySession(null, sample.Settings).RunAsync(sample.Target, sample.Path,
            [attack], null, CancellationToken.None);
        Assert.Equal(SessionOutcome.Found, result.Outcome);
        Assert.Equal(["ab"], result.Passwords);
    }

    [Fact]
    public async Task DictionaryStopResumeRetainsAllCandidatesAndChecksItsInput()
    {
        using var sample = new Sample("99");
        string dictionary = System.IO.Path.Combine(sample.Directory, "words.txt");
        string[] words = [new string('x', 129), .. Enumerable.Range(0, 100).Select(i => i.ToString("D2"))];
        await File.WriteAllLinesAsync(dictionary, words);
        var attack = new AttackSpec { Kind = AttackKind.Dictionary, Dictionaries = [dictionary, null, null, null] };
        using var stop = new CancellationTokenSource();
        var session = new RecoverySession(null, sample.Settings);
        session.Status += status => { if (status.Status == 3) stop.Cancel(); };
        Assert.Equal(SessionOutcome.Stopped, (await session.RunAsync(sample.Target, sample.Path,
            [attack], null, stop.Token)).Outcome);
        var saved = Assert.IsType<SessionState>(SessionState.Load(sample.Settings, sample.Target));
        await File.AppendAllTextAsync(dictionary, "changed\n");
        var changed = await new RecoverySession(null, sample.Settings).RunAsync(sample.Target, sample.Path, [attack], saved, CancellationToken.None);
        Assert.Equal(SessionOutcome.Error, changed.Outcome);
        Assert.Contains("changed", changed.Error!);
        await File.WriteAllLinesAsync(dictionary, words);
        var resumed = await new RecoverySession(null, sample.Settings).RunAsync(sample.Target, sample.Path, [attack], saved, CancellationToken.None);
        Assert.Equal(SessionOutcome.Found, resumed.Outcome);
        Assert.Equal(["99"], resumed.Passwords);
        Assert.Null(SessionState.Load(sample.Settings, sample.Target));
    }

    [Fact]
    public async Task MaskStopResumeCannotSkipTheRightPassword()
    {
        using var sample = new Sample("99");
        var attack = new AttackSpec { Kind = AttackKind.Mask, HashcatMask = "?d?d" };
        using var stop = new CancellationTokenSource();
        stop.CancelAfter(5);
        var interrupted = await new RecoverySession(null, sample.Settings).RunAsync(sample.Target, sample.Path, [attack], null, stop.Token);
        Assert.Equal(SessionOutcome.Stopped, interrupted.Outcome);
        var saved = Assert.IsType<SessionState>(SessionState.Load(sample.Settings, sample.Target));
        var result = await new RecoverySession(null, sample.Settings).RunAsync(sample.Target, sample.Path, [attack], saved, CancellationToken.None);
        Assert.Equal(SessionOutcome.Found, result.Outcome);
        Assert.Equal(["99"], result.Passwords);
    }

    [Theory]
    [InlineData(RulesPreset.Simple)]
    [InlineData(RulesPreset.TwoWords)]
    public async Task RefusesUnsupportedRulesWithAReason(RulesPreset rules)
    {
        using var sample = new Sample("ab");
        var attack = new AttackSpec { Kind = AttackKind.Dictionary, Rules = rules };
        var result = await new RecoverySession(null, sample.Settings).RunAsync(sample.Target, sample.Path,
            [attack], null, CancellationToken.None);
        Assert.Equal(SessionOutcome.Error, result.Outcome);
        Assert.Contains("without rules", result.Error!);
    }

    [Fact]
    public void SolidEntriesGiveTheirSpecificReason()
    {
        using var sample = new Sample("ab");
        byte[] archive = File.ReadAllBytes(sample.Path);
        archive[23] |= 0x10;
        using var stream = new MemoryStream(archive);
        var detection = new Detection { FilePath = sample.Path };
        RarExtractor.Extract(stream, detection);
        Assert.Null(detection.Target);
        Assert.Contains("solid entries depend on earlier files", detection.Message!);
    }

    private sealed class Sample : IDisposable
    {
        internal string Directory { get; } = System.IO.Path.Combine(Settings.AppDataDir, "rar3-tests", Guid.NewGuid().ToString("N"));
        internal string Path => System.IO.Path.Combine(Directory, "large.rar");
        internal Detection Detection { get; }
        internal HashTarget Target => Detection.Target!;
        internal Rar3FileTarget Entry => Target.Rar3File!;
        internal Settings Settings { get; }

        internal Sample(string password, int size = 327537)
        {
            System.IO.Directory.CreateDirectory(Directory);
            Settings = new Settings { SessionsDir = Directory, DontUsePasswordCache = true, MaxCpuThreads = 1 };
            var content = new byte[size];
            new Random(23700).NextBytes(content);
            byte[] salt = [1, 2, 3, 4, 5, 6, 7, 8];
            var (digest, iv) = Rar3Kernel.DeriveUtf16(Encoding.Unicode.GetBytes(password), salt);
            byte[] key = new byte[16];
            for (int i = 0; i < 16; i++) key[i] = digest[(i & ~3) + 3 - (i & 3)];
            using var aes = Aes.Create();
            aes.Key = key;
            byte[] plain = new byte[(size + 15) / 16 * 16];
            content.CopyTo(plain, 0);
            new Random(37).NextBytes(plain.AsSpan(size));
            byte[] encrypted = aes.EncryptCbc(plain, iv, PaddingMode.None);
            byte[] header = new byte[41];
            header[2] = 0x74;
            BinaryPrimitives.WriteUInt16LittleEndian(header.AsSpan(3), 0x8404);
            BinaryPrimitives.WriteUInt16LittleEndian(header.AsSpan(5), (ushort)header.Length);
            BinaryPrimitives.WriteUInt32LittleEndian(header.AsSpan(7), (uint)encrypted.Length);
            BinaryPrimitives.WriteUInt32LittleEndian(header.AsSpan(11), (uint)size);
            BinaryPrimitives.WriteUInt32LittleEndian(header.AsSpan(16), ZipCryptoSample.Crc32(content));
            header[24] = 29; header[25] = 0x30; header[26] = 1; header[32] = (byte)'f';
            salt.CopyTo(header, 33);
            File.WriteAllBytes(Path, [0x52, 0x61, 0x72, 0x21, 0x1a, 7, 0,
                0, 0, 0x73, 0, 0, 13, 0, 0, 0, 0, 0, 0, 0, .. header, .. encrypted,
                0, 0, 0x7b, 0, 0, 7, 0]);
            Detection = new Detection { FilePath = Path };
            using var stream = File.OpenRead(Path);
            RarExtractor.Extract(stream, Detection);
        }

        public void Dispose() => System.IO.Directory.Delete(Directory, recursive: true);
    }

    private sealed class CompressedSample : IDisposable
    {
        private readonly string _directory = System.IO.Path.Combine(Settings.AppDataDir, "rar3-tests", Guid.NewGuid().ToString("N"));
        internal string Path => System.IO.Path.Combine(_directory, "entry.bin");
        internal string Dictionary => System.IO.Path.Combine(_directory, "words.txt");
        internal Rar3FileTarget Entry { get; }
        internal Settings Settings { get; }
        internal AttackSpec Attack => new() { Kind = AttackKind.Dictionary, Dictionaries = [Dictionary, null, null, null] };
        internal HashTarget Target => new()
        {
            FormatId = "RAR3", FormatName = "RAR 3.x archive", Protection = "AES-128",
            HashLines = "$RK-RAR3$unsupported-candidate-test", Modes = [], Rar3File = Entry, MaxPasswordLength = 128,
        };

        internal CompressedSample(bool unconfirmed = false)
        {
            System.IO.Directory.CreateDirectory(_directory);
            Settings = new Settings { SessionsDir = _directory, DontUsePasswordCache = true, MaxCpuThreads = 1 };
            using var resource = typeof(Rar3FileCpuTests).Assembly.GetManifestResourceStream(
                "RecoverKit.Tests.Fixtures.Rar3.small-ppm.packed.gz")!;
            using var gzip = new GZipStream(resource, CompressionMode.Decompress);
            using var buffer = new MemoryStream();
            gzip.CopyTo(buffer);
            byte[] packed = unconfirmed ? Rar3DecoderTests.UnsupportedFilterStream() : buffer.ToArray();
            Array.Resize(ref packed, (packed.Length + 15) / 16 * 16);
            byte[] salt = [1, 2, 3, 4, 5, 6, 7, 8];
            var (digest, iv) = Rar3Kernel.DeriveUtf16(Encoding.Unicode.GetBytes("kit3"), salt);
            var key = new byte[16];
            for (int i = 0; i < 16; i++) key[i] = digest[(i & ~3) + 3 - (i & 3)];
            using var aes = Aes.Create();
            aes.Key = key;
            File.WriteAllBytes(Path, aes.EncryptCbc(packed, iv, PaddingMode.None));
            Entry = new Rar3FileTarget(Path, 0, packed.Length, unconfirmed ? 262145 : 8192, 0x35, 131072, salt, 0x57021da4);
        }

        // This wrong key used to stop at an unimplemented PPM transition.
        internal string UnsupportedPassword => "z001263";

        public void Dispose() => System.IO.Directory.Delete(_directory, recursive: true);
    }
}
