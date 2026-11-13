using System.Security.Cryptography;
using RecoverKit.Core;
using RecoverKit.Core.Formats;
using RecoverKit.Core.Native;
using RecoverKit.Core.Native.Kernels;
using Xunit;

namespace RecoverKit.Tests;

/// <summary>
/// The native multi-lane PBKDF2-HMAC-SHA256 against .NET's, on every lane path this CPU has
/// (AVX-512 / AVX2 / scalar on x64, ARMv8 SHA-256 / NEON / scalar on arm64), and the RAR 5 kernel
/// built on it against real archives and hashcat's example.
/// </summary>
[Collection("NativeFeatures")]
public class Pbkdf2Sha256Tests
{
    // hashcat 7.1.2 module_13000 self-test hash, password "hashcat".
    private const string HashcatExample = "$rar5$16$38466361001011015181344360681307$15$00000000000000000000000000000000$8$cc7a30583e62676a";

    // r5.rar: WinRAR 5 format, 2^15 iterations, password "ab1", file names not encrypted.
    private const string R5Rar =
        "UmFyIRoHAQDz4YLrCwEFBwAGAQGAgIAAiSgOG1ICAzywAAS6FyC2OdaHgAMABWEudHh0MAEAAw86" +
        "nPWFmPQvJIj1Ad/48mf85P2HJTtpk3UjwOJNjXnRJlYZo4PkPnAXBh5lsAoDAlfwXhnOct0B6Ec9" +
        "fIUDLTRJcnceJmY4KFgLabqMMsR0oS4SX3vSRRHsQ3n/oS/Y/rr54Zcg1yREHXdWUQMFBAA=";

    /// <summary>Feature masks that select each lane path of this CPU, widest first.</summary>
    private static IEnumerable<(string Name, RkNative.Feature Mask)> Paths()
    {
        var all = (RkNative.Feature)~0;
        var f = RkNative.Features;
        if (f.HasFlag(RkNative.Feature.Avx512)) yield return ("AVX-512", all);
        if (f.HasFlag(RkNative.Feature.Avx2)) yield return ("AVX2", all & ~RkNative.Feature.Avx512);
        if (f.HasFlag(RkNative.Feature.ArmSha2)) yield return ("ARMv8 SHA-256", all);
        if (f.HasFlag(RkNative.Feature.Neon)) yield return ("NEON", all & ~RkNative.Feature.ArmSha2);
        yield return ("scalar", all & ~(RkNative.Feature.Avx512 | RkNative.Feature.Avx2 | RkNative.Feature.Neon | RkNative.Feature.ArmSha2));
    }

    private static unsafe byte[] Native(byte[] pws, int stride, int[]? lens, int n, byte[] salt, int iter, int dkLen)
    {
        var dk = new byte[Math.Max(1, n * dkLen)];
        fixed (byte* p = pws, s = salt, d = dk)
        fixed (int* l = lens)
            Assert.Equal(0, RkNative.Pbkdf2Sha256(p, stride, l, n, s, salt.Length, (uint)iter, d, dkLen));
        return dk;
    }

    private static void OnEachPath(Action<string, int> body)
    {
        try
        {
            foreach (var (name, mask) in Paths())
            {
                RkNative.LimitFeatures(mask);
                body(name, RkNative.Pbkdf2Sha256Lanes());
            }
        }
        finally { RkNative.LimitFeatures((RkNative.Feature)~0); }
    }

    [Fact]
    public void MatchesDotNetOnEveryLanePath()
    {
        if (!RkNative.Available) return;
        var rng = new Random(13000);
        OnEachPath((name, lanes) =>
        {
            // Group sizes around the lane count (partial groups repeat lane 0 internally), key lengths on
            // both sides of the 64-byte HMAC block, and salts that need one or two SHA-256 blocks.
            foreach (var (n, iter, dkLen) in new[] { (1, 1, 32), (lanes - 1, 2, 32), (lanes, 3, 20), (lanes + 1, 50, 64), (2 * lanes + 3, 17, 33) })
            {
                if (n < 1) continue;
                const int stride = 100;
                var pws = new byte[n * stride];
                rng.NextBytes(pws);
                var lens = Enumerable.Range(0, n).Select(i => i switch { 0 => 0, 1 => 64, 2 => 65, 3 => 100, _ => rng.Next(1, 80) }).ToArray();
                var salt = new byte[rng.Next(0, 3) switch { 0 => 0, 1 => 16, _ => 60 }];
                rng.NextBytes(salt);
                var dk = Native(pws, stride, lens, n, salt, iter, dkLen);
                for (int i = 0; i < n; i++)
                {
                    var want = Rfc2898DeriveBytes.Pbkdf2(pws.AsSpan(i * stride, lens[i]), salt, iter, HashAlgorithmName.SHA256, dkLen);
                    Assert.True(want.AsSpan().SequenceEqual(dk.AsSpan(i * dkLen, dkLen)), $"{name} ({lanes} lanes): n={n} i={i} len={lens[i]} iter={iter}");
                }
            }
        });
    }

    [Fact]
    public void ReportsTheWidestPath()
    {
        if (!RkNative.Available) return;
        var f = RkNative.Features;
        int want = f.HasFlag(RkNative.Feature.Avx512) ? 16 : f.HasFlag(RkNative.Feature.Avx2) ? 8
            : f.HasFlag(RkNative.Feature.ArmSha2) ? 8 : f.HasFlag(RkNative.Feature.Neon) ? 8 : 1;
        Assert.Equal(want, RkNative.Pbkdf2Sha256Lanes());
    }

    [Fact]
    public void ParsesHashLines()
    {
        Assert.NotNull(Rar5Kernel.TryParse(HashcatExample));
        Assert.Null(Rar5Kernel.TryParse(HashcatExample.Replace("$15$", "$0$")));
        Assert.Null(Rar5Kernel.TryParse(HashcatExample.Replace("$15$", "$25$")));
        Assert.Null(Rar5Kernel.TryParse(HashcatExample.Replace("$8$", "$7$")));
        Assert.Null(Rar5Kernel.TryParse(HashcatExample[..^2]));
        Assert.Null(Rar5Kernel.TryParse("$RAR3$*0*45109af8ab5f297a*adbf6c5385d7a40373e8f77d7b89d317"));
    }

    [Fact]
    public void ReferenceMatchesHashcatExample()
    {
        var k = Rar5Kernel.TryParse(HashcatExample)!;
        Assert.True(k.Verify("hashcat"u8));
        Assert.False(k.Verify("hashcaT"u8));
    }

    /// <summary>A real archive: extraction, the reference check and the native search agree.</summary>
    [Fact]
    public void FindsArchivePassword()
    {
        var d = new Detection { FilePath = "r5.rar" };
        using (var s = new MemoryStream(Convert.FromBase64String(R5Rar))) RarExtractor.Extract(s, d);
        Assert.Equal([13000], d.Target!.Modes);
        var k = Rar5Kernel.TryParse(d.Target.HashLines)!;
        Assert.True(k.Verify("ab1"u8));
        Assert.False(k.Verify("ab2"u8));
        if (!RkNative.HasVectorPath) return;
        Assert.NotNull(NativeKernels.TryCreate(13000, d.Target.HashLines));
        // "ab1" in the middle of a batch of 12, in one call.
        var w = k.CreateWorker();
        Assert.Equal(1 * 6 + 3, w.SearchBatch("aaab"u8, 2, "xyz1+-"u8));
        Assert.Equal(-1, w.SearchBatch("aaac"u8, 2, "xyz1+-"u8));
    }

    /// <summary>Low iteration counts (from the hash, not a constant) on every path, through the search export.</summary>
    [Fact]
    public unsafe void SearchUsesTheHashIterationCount()
    {
        if (!RkNative.Available) return;
        var rng = new Random(5);
        var salt = new byte[16];
        rng.NextBytes(salt);
        var pw = "Pw!7"u8.ToArray();
        foreach (int lg2 in new[] { 1, 4, 6 })
        {
            var check = Rar5Kernel.CheckValue(pw, salt, lg2);
            var line = $"$rar5$16${Convert.ToHexString(salt).ToLowerInvariant()}${lg2}${new string('0', 32)}$8${Convert.ToHexString(check).ToLowerInvariant()}";
            var k = Rar5Kernel.TryParse(line)!;
            Assert.True(k.Verify(pw));
            OnEachPath((name, lanes) =>
            {
                const int n = 37;
                var pws = new byte[n * 4];
                for (int i = 0; i < n; i++) "Pw!"u8.CopyTo(pws.AsSpan(4 * i));
                for (int i = 0; i < n; i++) pws[4 * i + 3] = (byte)('0' + i);   // index 7 is "Pw!7"
                var hits = new int[4];
                int nh;
                fixed (byte* s = salt, c = check, p = pws)
                fixed (int* h = hits)
                    nh = RkNative.Rar5Search(s, lg2, c, p, 4, n, h, hits.Length);
                Assert.True(nh == 1 && hits[0] == 7, $"{name}: lg2={lg2} hits={nh}");
            });
        }
    }
}

[CollectionDefinition("NativeFeatures", DisableParallelization = true)]
public class NativeFeaturesCollection;
