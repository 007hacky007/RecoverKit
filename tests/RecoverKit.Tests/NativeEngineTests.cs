using System.Text;
using RecoverKit.Core.Native;
using RecoverKit.Core.Native.Kernels;
using Xunit;

namespace RecoverKit.Tests;

public class NativeEngineTests
{
    // hashcat's published example hashes; the password is always "hashcat".
    internal const string Pkzip17210 = "$pkzip2$1*1*2*0*1d1*1c5*eda7a8de*0*28*0*1d1*eda7*5096*1dea673da43d9fc7e2be1a1f4f664269fceb6cb88723a97408ae1fe07f774d31d1442ea8485081e63f919851ca0b7588d5e3442317fff19fe547a4ef97492ed75417c427eea3c4e146e16c100a2f8b6abd7e5988dc967e5a0e51f641401605d673630ea52ebb04da4b388489901656532c9aa474ca090dbac7cf8a21428d57b42a71da5f3d83fed927361e5d385ca8e480a6d42dea5b4bf497d3a24e79fc7be37c8d1721238cbe9e1ea3ae1eb91fc02aabdf33070d718d5105b70b3d7f3d2c28b3edd822e89a5abc0c8fee117c7fbfbfd4b4c8e130977b75cb0b1da080bfe1c0859e6483c42f459c8069d45a76220e046e6c2a2417392fd87e4aa4a2559eaab3baf78a77a1b94d8c8af16a977b4bb45e3da211838ad044f209428dba82666bf3d54d4eed82c64a9b3444a44746b9e398d0516a2596d84243b4a1d7e87d9843f38e45b6be67fd980107f3ad7b8453d87300e6c51ac9f5e3f6c3b702654440c543b1d808b62f7a313a83b31a6faaeedc2620de7057cd0df80f70346fe2d4dccc318f0b5ed128bcf0643e63d754bb05f53afb2b0fa90b34b538b2ad3648209dff587df4fa18698e4fa6d858ad44aa55d2bba3b08dfdedd3e28b8b7caf394d5d9d95e452c2ab1c836b9d74538c2f0d24b9b577*$/pkzip2$";
    internal const string Pkzip17200 = "$pkzip2$1*1*2*0*e3*1c5*eda7a8de*0*28*8*e3*eda7*5096*a9fc1f4e951c8fb3031a6f903e5f4e3211c8fdc4671547bf77f6f682afbfcc7475d83898985621a7af9bccd1349d1976500a68c48f630b7f22d7a0955524d768e34868880461335417ddd149c65a917c0eb0a4bf7224e24a1e04cf4ace5eef52205f4452e66ded937db9545f843a68b1e84a2e933cc05fb36d3db90e6c5faf1bee2249fdd06a7307849902a8bb24ec7e8a0886a4544ca47979a9dfeefe034bdfc5bd593904cfe9a5309dd199d337d3183f307c2cb39622549a5b9b8b485b7949a4803f63f67ca427a0640ad3793a519b2476c52198488e3e2e04cac202d624fb7d13c2*$/pkzip2$";

    internal static string Find(NativeKernel kernel, params string[] hashcatArgs)
    {
        var space = MaskSpace.FromHashcatArgs(hashcatArgs) ?? throw new InvalidOperationException("mask not parsed");
        var r = new NativeEngine(kernel, space) { Threads = 4, Priority = ThreadPriority.Normal }.Run(null, CancellationToken.None);
        return r.Outcome == NativeOutcome.Found ? Encoding.Latin1.GetString(r.Password!) : "<" + r.Outcome + ">";
    }

    [Fact]
    public void MaskSpaceFollowsHashcatSemantics()
    {
        var m = MaskSpace.FromHashcatArgs(["-a", "3", "-1", "?dab", "-i", "--increment-min", "2", "--increment-max", "3", "x?1?l"])!;
        Assert.Equal(2, m.MinLength);
        Assert.Equal(3, m.MaxLength);
        Assert.Equal("x"u8.ToArray(), m.Positions[0]);
        Assert.Equal(12, m.Positions[1].Length);
        Assert.Equal(26, m.Positions[2].Length);
        Assert.Equal(12 + 12 * 26, (int)m.TotalKeyspace);

        // --hex-charset applies to custom charsets and to mask literals, as in hashcat.
        var h = MaskSpace.FromHashcatArgs(["-a", "3", "--hex-charset", "-1", "616263", "41?1"])!;
        Assert.Equal("A"u8.ToArray(), h.Positions[0]);
        Assert.Equal("abc"u8.ToArray(), h.Positions[1]);

        Assert.Null(MaskSpace.FromHashcatArgs(["-a", "0", "words.txt"]));
        Assert.Null(MaskSpace.FromHashcatArgs(["-a", "3", "--some-unknown-option", "?l"]));
    }

    [Fact]
    public void ZipCryptoStoredFindsHashcatExamplePassword()
    {
        var k = ZipCryptoKernel.TryParse(Pkzip17210)!;
        Assert.True(k.Verify("hashcat"u8));
        Assert.False(k.Verify("hashcab"u8));
        Assert.Equal("hashcat", Find(k, "-a", "3", "has?l?l?l?l"));
    }

    [Fact]
    public void ZipCryptoDeflateFindsHashcatExamplePassword()
    {
        var k = ZipCryptoKernel.TryParse(Pkzip17200)!;
        Assert.True(k.Verify("hashcat"u8));
        Assert.Equal("hashcat", Find(k, "-a", "3", "-i", "--increment-min", "6", "--increment-max", "7", "hash?l?l?l"));
    }

    [Fact]
    public void ZipCryptoBenchmarkSampleIsTheCpuTestArchive()
    {
        var k = ZipCryptoKernel.TryParse(RecoverKit.Core.Native.NativeKernels.BenchmarkHashes[17210])!;
        Assert.True(k.Verify("zq7"u8));
        Assert.Equal("zq7", Find(k, "-a", "3", "-i", "--increment-min", "1", "--increment-max", "3", "?l?l?d"));
    }

    [Fact]
    public void Office97FindsHashcatExamplePassword()
    {
        var k = Office97Kernel.TryParse("$oldoffice$0*55045061647456688860411218030058*e7e24d163fbd743992d4b8892bf3f2f7*493410dbc832557d3fe1870ace8397e2")!;
        Assert.True(k.Verify("hashcat"u8));
        Assert.False(k.Verify("hashcas"u8));
        Assert.Equal("hashcat", Find(k, "-a", "3", "hashc?l?l"));
    }

    [Fact]
    public void Office2003FindsHashcatExamplePassword()
    {
        var k = Office2003Kernel.TryParse("$oldoffice$3*83328705222323020515404251156288*2855956a165ff6511bc7f4cd77b9e101*941861655e73a09c40f7b1e9dfd0c256ed285acd")!;
        Assert.True(k.Verify("hashcat"u8));
        Assert.False(k.Verify("hashcab"u8));
        Assert.Equal("hashcat", Find(k, "-a", "3", "-i", "--increment-min", "6", "--increment-max", "7", "hashc?l?l"));
    }

    [Theory]
    [InlineData("$pdf$1*2*40*-1*0*16*01221086741440841668371056103222*32*27c3fecef6d46a78eb61b8b4dbc690f5f8a2912bbb9afc842c12d79481568b74*32*0000000000000000000000000000000000000000000000000000000000000000")]
    [InlineData("$pdf$2*3*128*-4*1*16*62888255846156252261477183186121*32*6879919b1afd520bd3b7dbcc0868a0a500000000000000000000000000000000*32*0000000000000000000000000000000000000000000000000000000000000000")]
    public void PdfFindsHashcatExamplePassword(string hash)
    {
        var k = PdfRc4Kernel.TryParse(hash)!;
        Assert.True(k.Verify("hashcat"u8));
        Assert.False(k.Verify("hashcas"u8));
        Assert.Equal("hashcat", Find(k, "-a", "3", "hashc?l?l"));
    }

    [Fact]
    public void Rar3VerifiesHashcatExampleAndSearchesWithVectors()
    {
        var k = Rar3Kernel.TryParse("$RAR3$*0*45109af8ab5f297a*adbf6c5385d7a40373e8f77d7b89d317")!;
        Assert.True(k.Verify("hashcat"u8));
        Assert.False(k.Verify("hashcab"u8));
        // The vector search is ~100,000 SHA-1 blocks per candidate: only run it with a real vector path.
        if (Rar3Kernel.NativeFast || System.Runtime.Intrinsics.Vector256.IsHardwareAccelerated)
            Assert.Equal("hashcat", Find(k, "-a", "3", "hashca?l"));
    }

    [Fact]
    public void ZipCryptoReportsExhaustionAndResumes()
    {
        var k = ZipCryptoKernel.TryParse(Pkzip17210)!;
        Assert.Equal("<Exhausted>", Find(k, "-a", "3", "zz?l?l"));

        // Stop immediately, then continue from the resume point: the password is still found.
        var space = MaskSpace.FromHashcatArgs(["-a", "3", "?lashcat"])!;
        var cts = new CancellationTokenSource();
        cts.Cancel();
        var stopped = new NativeEngine(k, space) { Threads = 2 }.Run(null, cts.Token);
        Assert.Equal(NativeOutcome.Stopped, stopped.Outcome);
        var resumed = new NativeEngine(k, space) { Threads = 2 }.Run(stopped.ResumeAt, CancellationToken.None);
        Assert.Equal("hashcat", Encoding.ASCII.GetString(resumed.Password!));
    }

    [Fact]
    public void NativeRar3MatchesReferenceWherePresent()
    {
        if (!RkNative.Available) return;    // library not built for this platform
        var k = Rar3Kernel.TryParse("$RAR3$*0*45109af8ab5f297a*adbf6c5385d7a40373e8f77d7b89d317")!;
        // 17 candidates: one full 16-lane batch plus a partial one; the match sits in the second batch.
        var last = "abcdefghijklmnopt"u8.ToArray();
        var res = k.NativeHash("hashca"u8, last);
        for (int i = 0; i < last.Length; i++)
            Assert.Equal(last[i] == (byte)'t', k.Decrypts(res.AsSpan(36 * i, 20), res.AsSpan(36 * i + 20, 16)));
        // Every length has its own period layout; compare digest and IV byte for byte.
        foreach (var prefix in new[] { "", "h", "ha", "hashc", "hashca", "hashcat", "0123456789abcdefghijklm" })
        {
            var p = Encoding.ASCII.GetBytes(prefix);
            var got = k.NativeHash(p, "x"u8);
            var (d, iv) = k.ReferenceHash([.. p, (byte)'x']);
            Assert.Equal([.. d, .. iv], got);
        }

        // Several prefixes in one call: positions 0 and 5 vary across lanes, the rest is shared.
        var batch = k.NativeHash("hashcbhashcaxashca"u8, 3, "tx"u8);
        string[] order = ["hashcbt", "hashcbx", "hashcat", "hashcax", "xashcat", "xashcax"];
        for (int i = 0; i < order.Length; i++)
        {
            var (d, iv) = k.ReferenceHash(Encoding.ASCII.GetBytes(order[i]));
            Assert.Equal([.. d, .. iv], batch.AsSpan(36 * i, 36).ToArray());
        }
    }

    [Theory]
    [InlineData(9700, "$oldoffice$0*55045061647456688860411218030058*e7e24d163fbd743992d4b8892bf3f2f7*493410dbc832557d3fe1870ace8397e2")]
    [InlineData(9800, "$oldoffice$3*83328705222323020515404251156288*2855956a165ff6511bc7f4cd77b9e101*941861655e73a09c40f7b1e9dfd0c256ed285acd")]
    [InlineData(10400, "$pdf$1*2*40*-1*0*16*01221086741440841668371056103222*32*27c3fecef6d46a78eb61b8b4dbc690f5f8a2912bbb9afc842c12d79481568b74*32*0000000000000000000000000000000000000000000000000000000000000000")]
    [InlineData(10500, "$pdf$2*3*128*-4*1*16*62888255846156252261477183186121*32*6879919b1afd520bd3b7dbcc0868a0a500000000000000000000000000000000*32*0000000000000000000000000000000000000000000000000000000000000000")]
    public unsafe void NativeRc4FiltersFindTheExamplePassword(int mode, string hash)
    {
        if (!RkNative.HasVectorPath) return;    // AVX2 or NEON
        var k = NativeKernels.TryCreate(mode, hash)!;
        Assert.IsType<NativeFilterWorker>(k.CreateWorker());
        // 40 candidates of length 7 (three 16-lane groups, the last one partial); "hashcat" is number 37.
        var pws = new byte[40 * 7];
        for (int i = 0; i < 40; i++) Encoding.ASCII.GetBytes(i == 37 ? "hashcat" : $"hash{i:000}").CopyTo(pws, 7 * i);
        var hits = new int[64];
        int nh;
        fixed (byte* p = pws) fixed (int* h = hits) nh = ((INativeFilter)k).Filter(p, 7, 40, h, 64);
        Assert.Contains(37, hits.Take(nh));
        Assert.True(nh <= 2, $"{nh} false positives");
    }

    private static string PdfR6Line(byte[] u48) =>
        "$pdf$5*6*256*-4*1*16*" + new string('0', 32) + "*48*" + Convert.ToHexString(u48) + "*48*" + new string('0', 96) + "*32*" + new string('0', 64) + "*32*" + new string('0', 64);

    [Fact]
    public void PdfR6ReferenceMatchesARealDocument()
    {
        // /U of a test PDF that macOS PDFKit opens with "Qz7#Kp2" (and rejects other passwords).
        var k = NativeKernels_PdfR6("5b152edd133e7a6af935153d535b08b0e4b26cd44ef0d51c06496d0943d7afd969b113434acc604df4c060075d1fe9ee");
        Assert.True(k.Verify("Qz7#Kp2"u8));
        Assert.False(k.Verify("Qz7#Kp3"u8));
    }

    private static PdfR6Kernel NativeKernels_PdfR6(string uHex) => PdfR6Kernel.TryParse(PdfR6Line(Convert.FromHexString(uHex)))!;

    [Fact]
    public unsafe void NativeR6FindsEveryPlantedPassword()
    {
        if (!PdfR6Kernel.NativeFast) return;
        var rng = new Random(6);
        foreach (int len in new[] { 0, 1, 5, 16, 33, 127 })
        {
            var salt = new byte[16];
            rng.NextBytes(salt);
            int n = 150;
            var pws = new byte[n * len];
            rng.NextBytes(pws);
            var target = pws.AsSpan(77 * len, len).ToArray();
            var u = new byte[48];
            PdfR6Kernel.Hash(target, salt.AsSpan(0, 8)).CopyTo(u, 0);
            salt.CopyTo(u, 32);
            var k = PdfR6Kernel.TryParse(PdfR6Line(u))!;
            target.CopyTo(pws, 149 * len);
            var hits = new int[64];
            int nh;
            fixed (byte* p = pws) fixed (int* h = hits) nh = ((INativeFilter)k).Filter(p, len, n, h, 64);
            var found = hits.Take(nh).Order().ToArray();
            // An empty password makes every candidate equal.
            if (len == 0) Assert.Equal(n, nh);
            else Assert.Equal(new[] { 77, 149 }, found);
        }
    }

    [Fact]
    public void NativeR6EngineFindsAMaskPassword()
    {
        if (!PdfR6Kernel.NativeFast) return;
        var salt = Convert.FromHexString("0011223344556677");
        var u = new byte[48];
        PdfR6Kernel.Hash("7a5"u8, salt).CopyTo(u, 0);
        salt.CopyTo(u, 32);
        var k = (PdfR6Kernel)NativeKernels.TryCreate(10700, PdfR6Line(u))!;
        Assert.Equal("7a5", Find(k, "-a", "3", "?d?l?d"));
    }

    [Fact]
    public void EngineBatchesPrefixesAndReportsTheRightCandidate()
    {
        // A kernel that asks for batches of 3 prefixes and matches one password.
        var k = new BatchProbe("bcz"u8.ToArray());
        Assert.Equal("bcz", Find(k, "-a", "3", "?l?l?l"));
        Assert.Equal("<Exhausted>", Find(new BatchProbe("BCZ"u8.ToArray()), "-a", "3", "?l?l?l"));
        Assert.True(k.Batches > 0);
    }

    private sealed class BatchProbe(byte[] target) : NativeKernel
    {
        public int Batches;
        public override string Name => "probe";
        public override double SpeedHint => 1000;
        public override int PrefixBatch(int lastCount) => 3;
        public override bool Verify(ReadOnlySpan<byte> password) => password.SequenceEqual(target);
        public override KernelWorker CreateWorker() => new W(this);

        private sealed class W(BatchProbe k) : KernelWorker
        {
            public override int Search(ReadOnlySpan<byte> prefix, ReadOnlySpan<byte> last)
            {
                for (int i = 0; i < last.Length; i++)
                    if (k.Verify([.. prefix, last[i]])) return i;
                return -1;
            }

            public override int SearchBatch(ReadOnlySpan<byte> prefixes, int count, ReadOnlySpan<byte> last)
            {
                Interlocked.Increment(ref k.Batches);
                return base.SearchBatch(prefixes, count, last);
            }
        }
    }
}
