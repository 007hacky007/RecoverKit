using System.Diagnostics;
using System.Text;
using RecoverKit.Core;
using RecoverKit.Core.Attacks;
using RecoverKit.Core.Formats;
using RecoverKit.Core.Hashcat;
using RecoverKit.Core.Native;
using RecoverKit.Core.Native.Kernels;
using Xunit;

namespace RecoverKit.Tests;

/// <summary>
/// False positives of classic ZIP: a wrong password that passes the attacked entry's check byte and
/// CRC-32 must be rejected by the archive's other entries, and the search must go on to the real one.
/// </summary>
public sealed class ZipFalsePositiveTests : IDisposable
{
    // A stored 64-byte entry (data descriptor, check byte = DOS time 0x6d2b's high byte) built so that
    // the wrong password "qxza" passes its check byte and CRC-32 as well as the real "qxzm": the header's
    // first 10 bytes and the last bytes of the content were searched for that (a small C program,
    // about 2^32 trials). Info-ZIP's unzip agrees: "qxza" opens this entry, but not a second one.
    private const string Real = "qxzm", Wrong = "qxza";
    private static readonly byte[] CollidingHeader = Convert.FromHexString("d75d0385636c58d74b94");
    private static readonly byte[] CollidingContent = Convert.FromHexString(
        "5265636f7665724b69742066616c736520706f736974697665207465737420656e7472792e204f6e6c7920746865207265616c2070617373776f729794b4840a");

    private readonly string _dir = Directory.CreateTempSubdirectory("rk-zipfp").FullName;

    public void Dispose()
    {
        try { Directory.Delete(_dir, true); } catch (IOException) { }
    }

    private static ZipCryptoSample.Entry Colliding => new("a-small.txt", CollidingContent, Deflate: false, DataDescriptor: true, Header: CollidingHeader);

    private static byte[] Archive(params ZipCryptoSample.Entry[] entries) => ZipCryptoSample.Archive(entries, Encoding.ASCII.GetBytes(Real), new Random(7));

    private static byte[] TwoEntries() => Archive(Colliding, new ZipCryptoSample.Entry("b-report.txt", Encoding.ASCII.GetBytes(string.Concat(Enumerable.Repeat("Second file. ", 100))), false));

    private static Detection Detect(byte[] archive)
    {
        var d = new Detection { FilePath = "test.zip" };
        using var s = new MemoryStream(archive);
        ZipExtractor.Extract(s, d);
        return d;
    }

    private static byte[] B(string s) => Encoding.ASCII.GetBytes(s);

    [Fact]
    public void WrongPasswordPassesTheAttackedEntryButNotTheOtherOne()
    {
        var d = Detect(TwoEntries());
        var t = d.Target!;
        Assert.Contains(d.Info, kv => kv.Key == "Attacked entry" && kv.Value.StartsWith("a-small.txt"));
        var kernel = ZipCryptoKernel.TryParse(t.HashLines)!;
        Assert.True(kernel.Verify(B(Real)));
        Assert.True(kernel.Verify(B(Wrong)));              // the false positive the hash alone accepts
        Assert.NotNull(t.ConfirmPassword);
        Assert.True(t.ConfirmPassword!(B(Real)));
        Assert.False(t.ConfirmPassword(B(Wrong)));
        Assert.Contains(d.Info, kv => kv.Key == "Also checked against" && kv.Value.StartsWith("1 other"));
        Assert.Null(t.Notes);
    }

    [Fact]
    public void ConfirmerChecksHeadersOfEntriesItCannotKeep()
    {
        // An entry with an unsupported method is still checked by its header's check byte.
        var big = new ZipCryptoSample.Entry("b.bin", new byte[100], false);
        var archive = Archive(Colliding, big);
        // Pretend b.bin is compressed with method 12 (bzip2): central and local headers.
        PatchMethod(archive, "b.bin", 12);
        var t = Detect(archive).Target!;
        Assert.True(t.ConfirmPassword!(B(Real)));
        // With only a check byte, 1 in 256 wrong passwords passes; this one does not.
        Assert.False(t.ConfirmPassword(B(Wrong)));
    }

    private static void PatchMethod(byte[] zip, string name, ushort method)
    {
        var n = Encoding.ASCII.GetBytes(name);
        for (int i = 0; i + 46 < zip.Length; i++)
        {
            uint sig = BitConverter.ToUInt32(zip, i);
            if (sig == 0x04034b50 && zip.AsSpan(i + 30, n.Length).SequenceEqual(n)) BitConverter.TryWriteBytes(zip.AsSpan(i + 8, 2), method);
            if (sig == 0x02014b50 && zip.AsSpan(i + 46, n.Length).SequenceEqual(n)) BitConverter.TryWriteBytes(zip.AsSpan(i + 10, 2), method);
        }
    }

    [Fact]
    public void SingleStoredEntryHasNoConfirmationButANote()
    {
        var t = Detect(Archive(Colliding)).Target!;
        Assert.Null(t.ConfirmPassword);
        Assert.Contains("Open the archive", t.Notes);
        var deflated = Detect(Archive(new ZipCryptoSample.Entry("d.txt", ZipCryptoSample.Text(2000, new Random(1)), true))).Target!;
        Assert.Null(deflated.ConfirmPassword);
        Assert.Null(deflated.Notes);
    }

    [Fact]
    public void DeflatedEntryIsPreferredUnlessTheStoredOneIsMuchSmaller()
    {
        var text = new ZipCryptoSample.Entry("text.txt", ZipCryptoSample.Text(4000, new Random(2)), true);
        var stored200 = new ZipCryptoSample.Entry("s200.bin", new byte[200], false);
        var stored20 = new ZipCryptoSample.Entry("s20.bin", new byte[20], false);
        Assert.Contains(Detect(Archive(stored200, text)).Info, kv => kv.Key == "Attacked entry" && kv.Value.StartsWith("text.txt"));
        Assert.Contains(Detect(Archive(stored20, text)).Info, kv => kv.Key == "Attacked entry" && kv.Value.StartsWith("s20.bin"));
    }

    [Fact]
    public void BuiltInEngineRejectsTheFalsePositiveAndFindsTheRealPassword()
    {
        var t = Detect(TwoEntries()).Target!;
        var kernel = ZipCryptoKernel.TryParse(t.HashLines)!;
        var space = MaskSpace.FromHashcatArgs(["-a", "3", "?l?l?l?l"])!;

        // Without the check the engine stops at the wrong password ...
        var plain = new NativeEngine(kernel, space) { Threads = 4 }.Run(null, CancellationToken.None);
        Assert.Equal(Wrong, Encoding.ASCII.GetString(plain.Password!));

        // ... with it, the wrong one is rejected and the search goes on in the same batch: "qxza" and
        // "qxzm" share their prefix, so they are tested in one kernel call.
        var rejected = new List<string>();
        var r = new NativeEngine(kernel, space)
        {
            Threads = 4, Confirm = t.ConfirmPassword,
            Rejected = pw => { lock (rejected) rejected.Add(Encoding.ASCII.GetString(pw)); },
        }.Run(null, CancellationToken.None);
        Assert.Equal(NativeOutcome.Found, r.Outcome);
        Assert.Equal(Real, Encoding.ASCII.GetString(r.Password!));
        Assert.Equal([Wrong], rejected);
    }

    /// <summary>Records every candidate it tests; candidates in <c>hits</c> pass the kernel's check.</summary>
    private sealed class HitKernel(HashSet<string> hits, int prefixBatch) : NativeKernel
    {
        public readonly List<string> Tested = new();
        public readonly HashSet<string> Hits = hits;
        public override string Name => "hits";
        public override double SpeedHint => 1;
        public override int PrefixBatch(int lastCount) => prefixBatch;
        public override KernelWorker CreateWorker() => new Worker(this);
        public override bool Verify(ReadOnlySpan<byte> password) => Hits.Contains(Encoding.ASCII.GetString(password));

        private sealed class Worker(HitKernel k) : KernelWorker
        {
            public override int Search(ReadOnlySpan<byte> prefix, ReadOnlySpan<byte> last)
            {
                for (int i = 0; i < last.Length; i++)
                {
                    string c = Encoding.ASCII.GetString(prefix) + (char)last[i];
                    lock (k.Tested) k.Tested.Add(c);
                    if (k.Hits.Contains(c)) return i;
                }
                return -1;
            }
        }
    }

    [Theory]
    [InlineData(1)]
    [InlineData(4)]     // several prefixes per kernel call: SearchBatch
    public void RejectedHitDoesNotSkipTheRestOfTheBatch(int prefixBatch)
    {
        var kernel = new HitKernel(["ab", "ad", "ca", "cc"], prefixBatch);
        var space = MaskSpace.FromHashcatArgs(["-a", "3", "-1", "abcd", "?1?1"])!;
        var rejected = new List<string>();
        var r = new NativeEngine(kernel, space)
        {
            Threads = 1, Confirm = pw => Encoding.ASCII.GetString(pw) == "cc",
            Rejected = pw => rejected.Add(Encoding.ASCII.GetString(pw)),
        }.Run(null, CancellationToken.None);
        Assert.Equal("cc", Encoding.ASCII.GetString(r.Password!));
        Assert.Equal(["ab", "ad", "ca"], rejected);
        // Every candidate up to the find, in order, each once.
        string[] expected = ["aa", "ab", "ac", "ad", "ba", "bb", "bc", "bd", "ca", "cb", "cc"];
        Assert.Equal(expected, kernel.Tested);
    }

    [Fact]
    public void RejectedHitsLeaveTheSearchExhaustedWhenNothingIsConfirmed()
    {
        var kernel = new HitKernel(["ab", "dd"], 4);
        var space = MaskSpace.FromHashcatArgs(["-a", "3", "-1", "abcd", "?1?1"])!;
        int rejected = 0;
        var r = new NativeEngine(kernel, space) { Threads = 2, Confirm = _ => false, Rejected = _ => Interlocked.Increment(ref rejected) }
            .Run(null, CancellationToken.None);
        Assert.Equal(NativeOutcome.Exhausted, r.Outcome);
        Assert.Equal(2, rejected);
        Assert.Equal(16, kernel.Tested.Distinct().Count());
        Assert.Equal(16, kernel.Tested.Count);
    }

    [Fact]
    public void FalsePositiveLogShowsOnlyTheFirstFewWithoutPasswords()
    {
        var lines = new List<string>();
        var log = new FalsePositiveLog(lines.Add);
        for (int i = 0; i < 10; i++) log.Rejected(8, "hashcat");
        Assert.Equal(10, log.Count);
        Assert.Equal(FalsePositiveLog.Logged, lines.Count);
        Assert.All(lines, l => Assert.Contains("8-character", l));
    }

    [Fact]
    public void OutfileIsReadAsHashcatAppendsToIt()
    {
        string file = Path.Combine(_dir, "run.out");
        var lines = new List<string>();
        var c = new HashcatRunner.OutfileConfirmer(file, pw => Encoding.ASCII.GetString(pw) == Real, new FalsePositiveLog(lines.Add));
        Assert.False(c.Poll(final: false));                     // no file yet
        File.WriteAllText(file, Wrong + "\nqx");                 // a hit and half of the next line
        Assert.False(c.Poll(final: false));
        Assert.Single(lines);
        File.AppendAllText(file, "zz\r\n");
        Assert.False(c.Poll(final: false));
        Assert.Equal(2, lines.Count);
        File.AppendAllText(file, "$HEX[" + Convert.ToHexString(B(Real)) + "]");   // last line without a line break
        Assert.False(c.Poll(final: false));
        Assert.True(c.Poll(final: true));
        Assert.Equal("$HEX[" + Convert.ToHexString(B(Real)) + "]", c.Confirmed);
        Assert.Equal(Real, HashcatTool.DecodePlain(c.Confirmed!));
    }

    [Theory]
    [InlineData("qxza", false)]
    [InlineData("$HEX[71787a6d]", true)]
    [InlineData("$HEX[71787a]", false)]
    public void PlainBytesDecodeHashcatsHexForm(string raw, bool real)
        => Assert.Equal(real, PasswordConfirmation.PlainBytes(raw).AsSpan().SequenceEqual(B(Real)));

    // ------------------------------------------------------------------ hashcat stand-in (Python)

    /// <summary>
    /// A Python script in place of hashcat (Unix only): writes its arguments to args.txt, then the given
    /// lines to the outfile (-o) one per second, then waits to be stopped (exit 2 on SIGINT, as hashcat)
    /// or exits with <paramref name="exitCode"/>. For --show it prints <paramref name="show"/>.
    /// </summary>
    private HashcatTool? FakeHashcat(string[] lines, int? exitCode, string show = "")
    {
        if (OperatingSystem.IsWindows()) return null;
        string dir = Path.Combine(_dir, "hc");
        Directory.CreateDirectory(dir);
        string script = Path.Combine(dir, "hashcat");
        string Py(string v) => "'" + v.Replace("\\", "\\\\").Replace("'", "\\'").Replace("\n", "\\n") + "'";
        File.WriteAllText(script, $$"""
            #!/usr/bin/env python3
            import signal, sys, time
            args = sys.argv[1:]
            open({{Py(Path.Combine(dir, "args.txt"))}}, 'w').write('\n'.join(args) + '\n')
            if '--show' in args:
                sys.stdout.write({{Py(show)}})
                sys.exit(0)
            signal.signal(signal.SIGINT, lambda *a: sys.exit(2))
            out = args[args.index('-o') + 1]
            for line in [{{string.Join(", ", lines.Select(Py))}}]:
                time.sleep(1)
                with open(out, 'a') as f:
                    f.write(line + '\n')
            {{(exitCode is int code ? $"sys.exit({code})" : "time.sleep(30)\nsys.exit(1)")}}
            """);
        File.SetUnixFileMode(script, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        return HashcatTool.Locate(script);
    }

    private RunRequest Request(HashTarget t, string potfile)
    {
        string hashFile = Path.Combine(_dir, "zip.hash");
        File.WriteAllText(hashFile, t.HashLines + "\n");
        return new RunRequest
        {
            Mode = 17210, HashFile = hashFile, SessionName = "fp", SessionDir = _dir,
            Attack = new PreparedAttack { Description = "mask", Args = { "-a", "3", "?l?l?l?l" } },
            Settings = new Settings { SessionsDir = _dir }, PasswordCachePath = potfile,
            ConfirmPassword = t.ConfirmPassword,
        };
    }

    [Fact]
    public async Task HashcatIsStoppedAtTheFirstConfirmedPasswordAndOnlyThatIsCached()
    {
        var t = Detect(TwoEntries()).Target!;
        if (FakeHashcat([Wrong, "$HEX[" + Convert.ToHexString(B(Real)).ToLowerInvariant() + "]"], exitCode: null) is not { } tool) return;
        string potfile = Path.Combine(_dir, "cache.potfile");
        var runner = new HashcatRunner(tool) { HashcatMajorVersion = 8, OutfilePollInterval = TimeSpan.FromMilliseconds(100) };
        var output = new List<string>();
        runner.OutputLine += l => { lock (output) output.Add(l); };
        var sw = Stopwatch.StartNew();
        var res = await runner.RunAsync(Request(t, potfile), CancellationToken.None);
        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(20), "hashcat was not stopped at the confirmed password");
        Assert.Equal(RunOutcome.Cracked, res.Outcome);
        Assert.Equal([Real], res.Passwords);
        var args = File.ReadAllLines(Path.Combine(_dir, "hc", "args.txt"));
        Assert.Contains("--keep-guessing", args);
        Assert.Contains("--potfile-disable", args);
        Assert.DoesNotContain("--potfile-path", args);
        Assert.Equal([t.HashLines + ":$HEX[71787a6d]"], File.ReadAllLines(potfile));
        Assert.Single(output, l => l.StartsWith("False positive rejected"));
        Assert.DoesNotContain(output, l => l.Contains(Wrong));
    }

    [Theory]
    [InlineData(0)]     // hashcat says "cracked": it found the false positive
    [InlineData(1)]     // hashcat says "exhausted"
    public async Task HashcatRunWithOnlyFalsePositivesIsExhausted(int exitCode)
    {
        var t = Detect(TwoEntries()).Target!;
        if (FakeHashcat([Wrong], exitCode) is not { } tool) return;
        string potfile = Path.Combine(_dir, "cache.potfile");
        var runner = new HashcatRunner(tool) { HashcatMajorVersion = 8, OutfilePollInterval = TimeSpan.FromMilliseconds(100) };
        var res = await runner.RunAsync(Request(t, potfile), CancellationToken.None);
        Assert.Equal(RunOutcome.Exhausted, res.Outcome);
        Assert.Empty(res.Passwords);
        Assert.False(File.Exists(potfile));
    }

    [Fact]
    public async Task CachedFalsePositivesAreDropped()
    {
        var t = Detect(TwoEntries()).Target!;
        // hashcat's --show reports one plaintext per hash (the last matching line): here the false positive.
        if (FakeHashcat([], 0, show: Wrong + "\n") is not { } tool) return;
        string potfile = Path.Combine(_dir, "cache.potfile");
        string hashFile = Path.Combine(_dir, "zip.hash");
        File.WriteAllText(hashFile, t.HashLines + "\n");

        File.WriteAllText(potfile, t.HashLines + ":" + Wrong + "\n");
        var (none, rejected) = await RecoverySession.ConfirmedCacheAsync(tool, 17210, hashFile, potfile, t, t.ConfirmPassword!);
        Assert.Empty(none);
        Assert.Equal(1, rejected);

        // RecoverKit's own line for the confirmed password is found even when --show prints the other one.
        await PasswordConfirmation.AppendAsync(potfile, t.HashLines, B(Real));
        var (found, rejected2) = await RecoverySession.ConfirmedCacheAsync(tool, 17210, hashFile, potfile, t, t.ConfirmPassword!);
        Assert.Equal([Real], found);
        Assert.Equal(1, rejected2);
    }
}
