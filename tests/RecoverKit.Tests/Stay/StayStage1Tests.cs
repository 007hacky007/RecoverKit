using System.Text;
using RecoverKit.Core.Attacks.Stay;
using Xunit;

namespace RecoverKit.Tests.Stay;

/// <summary>True intermediates computed from the generator's password, for filter tests.</summary>
internal static class StayTruth
{
    public const uint M = 0x08088405u;
    public static readonly uint[] T = ZipStayArchive.BuildCrcTable();

    public static uint A0(uint x) => (x >> 8) ^ T[x & 0xff];
    public static uint Crc(uint z) => (z >> 8) ^ T[z & 0xff];
    public static byte Ks(uint z) => ZipStayArchive.Keystream(z);
    public static byte By(uint y) => (byte)((y * M) >> 24);
    public static byte By2(uint y) => (byte)((y * unchecked(M * M)) >> 24);
}

public class StayStage1Tests
{
    private const string Password = "&THPOL101%ISLAME@|1";

    internal static GeneratedZip MakeZip(int files, uint seed = 0x12345678, int sharedFirstByteFiles = 0)
    {
        // sharedFirstByteFiles: rescan seeds until that many leading files share r[0]
        uint s = seed;
        while (true)
        {
            var specs = Enumerable.Range(0, files).Select(i => new GeneratedEntry
            {
                Name = $"file{i:D2}.txt",
                Content = Encoding.ASCII.GetBytes($"stage one file {i} {new string('s', 50 + i * 9)}"),
                Method = i % 2 == 0 ? 0 : 8,
            }).ToList();
            var zip = ZipStayArchive.Generate(specs, Password, ZipRngVariant.Msvc, s);
            if (sharedFirstByteFiles <= 1) return zip;
            var distinct = zip.R.Take(sharedFirstByteFiles).Select(r => r[0]).Distinct().Count();
            if (distinct == 1) return zip;
            s += 0x9e37;
        }
    }

    internal static List<StayFileData> FileData(GeneratedZip zip)
        => zip.R.Zip(zip.StoredHeaders, (r, st) => new StayFileData { R = r, Stored = st }).ToList();

    [Fact]
    public void Filter_accepts_true_guess_all_files()
    {
        var zip = MakeZip(5);
        var files = FileData(zip);
        var cv = (StayTruth.Crc(zip.Z) >> 2) & 0x3fff;
        byte k = StayTruth.Ks(zip.Z);
        byte a0 = (byte)StayTruth.A0(zip.X);
        byte bY = StayTruth.By(zip.Y);

        for (int i = 0; i < 5; i++)
        {
            Assert.True(StayStage1.FilterPasses(files[i], (uint)cv, k, a0, bY), $"file {i}");
            var combos = StayStage1.PassingCarries(files[i], (uint)cv, k, a0, bY);
            Assert.NotEmpty(combos);   // the true carry pair is in there
        }
    }

    [Fact]
    public void Filter_rejects_random_guesses()
    {
        var zip = MakeZip(5);
        var files = FileData(zip);
        var rng = new Random(99);

        int file0Pass = 0, allPass = 0;
        for (int t = 0; t < 10_000; t++)
        {
            uint cv = (uint)rng.Next(1 << 14);
            byte k = (byte)rng.Next(256);
            byte a0 = (byte)rng.Next(256);
            byte bY = (byte)rng.Next(256);
            if (StayStage1.FilterPasses(files[0], cv, k, a0, bY)) file0Pass++;
            if (files.All(f => StayStage1.FilterPasses(f, cv, k, a0, bY))) allPass++;
        }
        // one file passes with probability ~4/256; five files filter essentially everything
        Assert.True(file0Pass < 10_000 * 4 / 256 * 3 / 2, $"file0 pass rate too high: {file0Pass}");
        Assert.True(allPass < 5, $"too many full passes: {allPass}");
    }

    [Fact]
    public void Filter_accepts_true_guess_when_files_share_first_byte()
    {
        var zip = MakeZip(5, sharedFirstByteFiles: 2);
        Assert.Equal(zip.R[0][0], zip.R[1][0]);   // correlated filters, as promised

        var files = FileData(zip);
        var cv = (StayTruth.Crc(zip.Z) >> 2) & 0x3fff;
        byte k = StayTruth.Ks(zip.Z);
        byte a0 = (byte)StayTruth.A0(zip.X);
        byte bY = StayTruth.By(zip.Y);
        for (int i = 0; i < 5; i++)
            Assert.True(StayStage1.FilterPasses(files[i], (uint)cv, k, a0, bY), $"file {i}");
    }

    [Fact]
    public void Scalar_and_avx2_agree_on_subrange()
    {
        var zip = MakeZip(5);
        var files = FileData(zip);
        var cv = (int)((StayTruth.Crc(zip.Z) >> 2) & 0x3fff);
        byte k = StayTruth.Ks(zip.Z);
        byte a0 = (byte)StayTruth.A0(zip.X);
        byte bY = StayTruth.By(zip.Y);

        // window containing the truth
        var truthWindow = new StayFileData.Window(Math.Max(0, k - 2), k + 3, Math.Max(0, cv - 64), cv + 65);
        var scalar = StayStage1.SearchScalar(files, truthWindow);
        Assert.Contains(scalar, s => s.K == k && s.A0 == a0 && s.BY == bY);

        if (StayStage1.VectorWidth == 1) return;   // no SIMD on this host
        var simd = StayStage1.SearchVector(files, truthWindow);
        Assert.Equal(
            scalar.Select(s => (s.Cv, s.K, s.A0, s.BY)).OrderBy(x => x),
            simd.Select(s => (s.Cv, s.K, s.A0, s.BY)).OrderBy(x => x));

        // a few random windows too
        var rng = new Random(7);
        for (int w = 0; w < 3; w++)
        {
            var kf = rng.Next(250); var cf = Math.Max(0, rng.Next(1 << 14) - 32);
            var window = new StayFileData.Window(kf, kf + 6, cf, cf + 64);
            var s2 = StayStage1.SearchScalar(files, window);
            var v2 = StayStage1.SearchVector(files, window);
            Assert.Equal(
                s2.Select(s => (s.Cv, s.K, s.A0, s.BY)).OrderBy(x => x),
                v2.Select(s => (s.Cv, s.K, s.A0, s.BY)).OrderBy(x => x));
        }
    }

    [Fact]
    public void Search_finds_true_guess_in_full_keyspace()
    {
        var zip = MakeZip(5);
        var files = FileData(zip);
        var cv = (StayTruth.Crc(zip.Z) >> 2) & 0x3fff;
        byte k = StayTruth.Ks(zip.Z);
        byte a0 = (byte)StayTruth.A0(zip.X);
        byte bY = StayTruth.By(zip.Y);

        var survivors = StayStage1.Search(files, CancellationToken.None);
        Assert.True(survivors.Count > 0 && survivors.Count <= 1 << 10, $"survivor count {survivors.Count}");
        var truth = Assert.Single(survivors, s => s.K == k && s.A0 == a0 && s.BY == bY && s.Cv == (uint)cv);
        // the survivor records the true m1 values (MSB of k1 after byte 0) for every file and pass
        for (int i = 0; i < 5; i++)
        {
            var pf = truth.PerFile[i];
            byte b0e1 = files[i].R[0];
            byte b0e2 = (byte)(files[i].R[0] ^ k);
            byte l1e1 = (byte)(a0 ^ (StayTruth.T[b0e1] & 0xff));
            byte l1e2 = (byte)(a0 ^ (StayTruth.T[b0e2] & 0xff));
            byte m1e1 = (byte)(((zip.Y + l1e1) * StayTruth.M + 1) >> 24);
            byte m1e2 = (byte)(((zip.Y + l1e2) * StayTruth.M + 1) >> 24);
            Assert.Contains((m1e1, m1e2), pf!);
        }
    }
}
