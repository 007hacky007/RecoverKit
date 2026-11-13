using RecoverKit.Core.Formats;
using RecoverKit.Core.Native;
using RecoverKit.Core.Native.Kernels;
using Xunit;

namespace RecoverKit.Tests;

[Collection("NativeFeatures")]
public class ZipCryptoNativeTests
{
    private static IEnumerable<int> Paths()
    {
        for (int path = 1; path <= 5; path++)
            if (RkNative.ZipPath(path) == path) yield return path;
    }

    [Fact]
    public unsafe void HeaderSurvivorsMatchScalarInOrder()
    {
        if (!RkNative.Available) return;
        var rng = new Random(17210);
        foreach (int path in Paths())
        foreach (int n in new[] { 0, 1, 3, 4, 7, 8, 15, 16, 17, 31, 32, 47, 48, 49, 63, 64, 65, 255, 256 })
        for (int trial = 0; trial < 8; trial++)
        {
            byte[] header = new byte[12], last = new byte[n];
            rng.NextBytes(header); rng.NextBytes(last);
            uint a = (uint)rng.NextInt64(1L << 32), b = (uint)rng.NextInt64(1L << 32), c = (uint)rng.NextInt64(1L << 32);
            byte c1 = (byte)rng.Next(256), c2 = trial % 2 == 0 ? c1 : (byte)rng.Next(256);
            var want = new List<int>();
            for (int i = 0; i < n; i++)
            {
                uint x = a, y = b, z = c;
                Step(ref x, ref y, ref z, last[i]);
                byte plain = 0;
                for (int j = 0; j < 12; j++)
                {
                    uint t = (z | 2) & 0xffff;
                    plain = (byte)(header[j] ^ (byte)((t * (t ^ 1)) >> 8));
                    Step(ref x, ref y, ref z, plain);
                }
                if (plain == c1 || plain == c2) want.Add(i);
            }
            var hits = new int[n + 1];
            fixed (byte* h = header, l = last)
            fixed (int* p = hits)
            {
                int count = RkNative.ZipSearch(h, c1, c2, a, b, c, l, n, p, n, path);
                Assert.Equal(want, hits.Take(count));
                // Capacity is reported even when the caller cannot hold all survivors.
                Assert.Equal(count, RkNative.ZipSearch(h, c1, c2, a, b, c, l, n, p, 0, path));
            }
        }
    }

    [Fact]
    public void SearchMatchesManagedScalarForArchivesAndPrefixChanges()
    {
        if (!RkNative.Available) return;
        int saved = ZipCryptoNative.RequestedPath;
        var rng = new Random(17200);
        try
        {
            foreach (bool deflate in new[] { false, true })
            foreach (bool descriptor in new[] { false, true })
            foreach (int checkBytes in new[] { 1, 2 })
            foreach (int length in new[] { 1, 2, 7, 64 })
            {
                var password = new byte[length]; rng.NextBytes(password);
                byte[] content = ZipCryptoSample.Text(100, rng);
                var target = ZipCryptoSample.Extract(ZipCryptoSample.Archive([new("test.dat", content, deflate, descriptor)], password, rng));
                string line = target.HashLines.Replace("$pkzip2$1*1*", $"$pkzip2$1*{checkBytes}*");
                // Two-byte hashes name the checksum actually encrypted in the header.
                if (checkBytes == 2 && descriptor)
                {
                    var fields = line.Split('*'); fields[11] = fields[12];
                    line = string.Join('*', fields);
                }
                var kernel = ZipCryptoKernel.TryParse(line)!;
                Assert.True(kernel.Verify(password), $"deflate={deflate} descriptor={descriptor} checks={checkBytes} length={length}");
                byte[] last = Enumerable.Range(0, 256).Select(i => (byte)i).ToArray();
                byte[] prefix = password[..^1];
                ZipCryptoNative.RequestedPath = -2;
                var scalar = kernel.CreateWorker();
                int want = scalar.Search(prefix, last);
                Assert.Equal(password[^1], want);
                foreach (int path in Paths())
                {
                    ZipCryptoNative.RequestedPath = path;
                    var worker = kernel.CreateWorker();
                    Assert.Equal(want, worker.Search(prefix, last));
                    Assert.Equal(want, worker.Search(prefix, last));
                    // Exercise the existing batched order, prefix cache invalidation and duplicates.
                    Assert.Equal(want, worker.SearchBatch(prefix.Concat(prefix).ToArray(), 2, last));
                    if (prefix.Length > 0)
                    {
                        prefix[^1] ^= 1;
                        ZipCryptoNative.RequestedPath = -2;
                        int miss = scalar.Search(prefix, last);
                        ZipCryptoNative.RequestedPath = path;
                        Assert.Equal(miss, worker.Search(prefix, last));
                        byte[] packed = prefix.Concat(password[..^1]).ToArray();
                        Assert.Equal(last.Length + want, worker.SearchBatch(packed, 2, last));
                        prefix[^1] ^= 1;
                        Assert.Equal(want, worker.Search(prefix, last));
                    }
                }
            }
            foreach (string fixture in new[] { NativeEngineTests.Pkzip17200, NativeEngineTests.Pkzip17210 })
            foreach (int path in Paths())
            {
                ZipCryptoNative.RequestedPath = path;
                Assert.Equal(2, ZipCryptoKernel.TryParse(fixture)!.CreateWorker().Search("hashca"u8, "xytzt"u8));
            }
        }
        finally { ZipCryptoNative.RequestedPath = saved; }
    }

    [Fact]
    public void FeatureMaskDisablesUnsupportedPaths()
    {
        if (!RkNative.Available) return;
        try
        {
            RkNative.LimitFeatures(0);
            Assert.Equal(1, RkNative.ZipPath(0));
            for (int path = 2; path <= 5; path++) Assert.Equal(-1, RkNative.ZipPath(path));
        }
        finally { RkNative.LimitFeatures((RkNative.Feature)~0); }
    }

    [Fact]
    public void AutomaticSelectionKeepsMeasuredWinnerAndManagedFallback()
    {
        int saved = ZipCryptoNative.RequestedPath;
        bool disabled = RkNative.Disabled;
        try
        {
            ZipCryptoNative.RequestedPath = 0;
            var f = RkNative.Features;
            int want = (f & RkNative.Feature.ArmCrc) != 0 ? 5 : (f & RkNative.Feature.Neon) != 0 ? 2 : -1;
            Assert.Equal(want, ZipCryptoNative.Path);
            if (RkNative.Available)
            {
                RkNative.LimitFeatures(RkNative.Feature.Neon);
                Assert.Equal((f & RkNative.Feature.Neon) != 0 ? 2 : -1, ZipCryptoNative.Path);
            }
            RkNative.Disabled = true;
            Assert.Equal(-1, ZipCryptoNative.Path);
            Assert.Equal(2, ZipCryptoKernel.TryParse(NativeEngineTests.Pkzip17210)!.CreateWorker().Search("hashca"u8, "xyt"u8));
        }
        finally
        {
            RkNative.Disabled = disabled;
            RkNative.LimitFeatures((RkNative.Feature)~0);
            ZipCryptoNative.RequestedPath = saved;
        }
    }

    private static void Step(ref uint a, ref uint b, ref uint c, byte plain)
    {
        a = Crc(a, plain);
        b = unchecked((b + (byte)a) * 134775813u + 1);
        c = Crc(c, (byte)(b >> 24));
    }

    private static uint Crc(uint x, byte b)
    {
        x ^= b;
        for (int i = 0; i < 8; i++) x = (x >> 1) ^ ((x & 1) == 0 ? 0u : 0xedb88320u);
        return x;
    }
}
