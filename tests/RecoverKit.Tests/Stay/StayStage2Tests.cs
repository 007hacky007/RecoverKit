using System.Text;
using RecoverKit.Core.Attacks.Stay;
using Xunit;

namespace RecoverKit.Tests.Stay;

public class StayStage2Tests
{
    private const string Password = "&THPOL101%ISLAME@|1";

    internal static GeneratedZip MakeZip(int files = 5, uint seed = 0x12345678)
    {
        var specs = Enumerable.Range(0, files).Select(i => new GeneratedEntry
        {
            Name = $"file{i:D2}.txt",
            Content = Encoding.ASCII.GetBytes($"stage two file {i} {new string('t', 45 + i * 7)}"),
            Method = i % 2 == 0 ? 0 : 8,
        }).ToList();
        return ZipStayArchive.Generate(specs, Password, ZipRngVariant.Msvc, seed);
    }

    internal static List<StayFileData> FileData(GeneratedZip zip)
        => zip.R.Zip(zip.StoredHeaders, (r, st) => new StayFileData { R = r, Stored = st }).ToList();

    /// <summary>The true stage-1 survivor, constructed directly from the generator's keys.</summary>
    internal static Stage1Survivor TrueStage1(GeneratedZip zip, List<StayFileData> files)
    {
        uint a0Full = StayTruth.A0(zip.X);
        uint c = StayTruth.Crc(zip.Z);
        byte k = StayTruth.Ks(zip.Z);
        byte a0 = (byte)a0Full;
        byte bY = StayTruth.By(zip.Y);
        uint cv = (c >> 2) & 0x3fff;
        var perFile = new IReadOnlyList<(byte, byte)>[files.Count];
        for (int i = 0; i < files.Count; i++)
        {
            byte b0e1 = files[i].R[0];
            byte b0e2 = (byte)(files[i].R[0] ^ k);
            byte l1e1 = (byte)(a0 ^ (StayTruth.T[b0e1] & 0xff));
            byte l1e2 = (byte)(a0 ^ (StayTruth.T[b0e2] & 0xff));
            byte m1e1 = (byte)(((zip.Y + l1e1) * StayTruth.M + 1) >> 24);
            byte m1e2 = (byte)(((zip.Y + l1e2) * StayTruth.M + 1) >> 24);
            perFile[i] = new List<(byte, byte)> { (m1e1, m1e2) };
        }
        return new Stage1Survivor { Cv = cv, K = k, A0 = a0, BY = bY, PerFile = perFile };
    }

    internal static (byte A1, byte BY2, byte Ch, byte Cl) TrueStage2Guesses(GeneratedZip zip)
    {
        uint a0Full = StayTruth.A0(zip.X);
        uint c = StayTruth.Crc(zip.Z);
        return ((byte)(a0Full >> 8), StayTruth.By2(zip.Y), (byte)(c >> 16), (byte)(c & 3));
    }

    [Fact]
    public void Filter_accepts_true_guess_all_files()
    {
        var zip = MakeZip();
        var files = FileData(zip);
        var s1 = TrueStage1(zip, files);
        var (a1, bY2, ch, cl) = TrueStage2Guesses(zip);

        for (int i = 0; i < files.Count; i++)
            Assert.True(StayStage2.FilterPasses(files[i], i, s1, a1, bY2, ch, cl), $"file {i}");
    }

    [Fact]
    public void Filter_rejects_wrong_guesses()
    {
        var zip = MakeZip();
        var files = FileData(zip);
        var s1 = TrueStage1(zip, files);
        var (a1, bY2, ch, cl) = TrueStage2Guesses(zip);

        // perturb each dimension; the true value passes, wrong ones mostly fail
        int passes = 0, total = 0;
        foreach (var (da, db, dc, dd) in new[] { (1, 0, 0, 0), (0, 1, 0, 0), (0, 0, 1, 0), (0, 0, 0, 1) })
        {
            var guess = ((byte)(a1 + da), (byte)(bY2 + db), (byte)(ch + dc), (byte)(cl ^ dd));
            bool all = files.Select((f, i) => StayStage2.FilterPasses(f, i, s1, guess.Item1, guess.Item2, guess.Item3, guess.Item4)).All(x => x);
            total++;
            if (all) passes++;
        }
        Assert.True(passes <= 1, $"{passes} of {total} wrong guesses passed all files");
    }

    [Fact]
    public void Search_refines_true_stage1_survivor()
    {
        var zip = MakeZip();
        var files = FileData(zip);
        var s1 = TrueStage1(zip, files);
        var (a1, bY2, ch, cl) = TrueStage2Guesses(zip);

        var survivors = StayStage2.Search([s1], files);
        Assert.True(survivors.Count > 0 && survivors.Count <= 1 << 8, $"count {survivors.Count}");

        var truth = Assert.Single(survivors, s => s.A1 == a1 && s.BY2 == bY2 && s.C24 == (StayTruth.Crc(zip.Z) & 0xffffff));
        Assert.Equal(a1, truth.A1);
        Assert.Equal(bY2, truth.BY2);
    }

    [Fact]
    public void Constraints_are_satisfied_by_true_Y()
    {
        var zip = MakeZip();
        var files = FileData(zip);
        var s1 = TrueStage1(zip, files);
        var (a1, bY2, ch, cl) = TrueStage2Guesses(zip);

        var survivors = StayStage2.Search([s1], files);
        var truth = survivors.Single(s => s.A1 == a1 && s.BY2 == bY2 && s.C24 == (StayTruth.Crc(zip.Z) & 0xffffff));

        uint y24 = zip.Y % (1u << 24);
        int constraintCount = 0;
        for (int i = 0; i < files.Count; i++)
        {
            // at least one option per file has all its constraints satisfied by the true Y
            Assert.Contains(truth.PerFileOptions[i], option =>
            {
                foreach (var cn in option)
                {
                    constraintCount++;
                    uint w = (uint)(((ulong)y24 * cn.Mult) % (1u << 24));
                    bool ok = cn.AtLeast ? w >= cn.Threshold : w < cn.Threshold;
                    if (!ok) return false;
                }
                return true;
            });
        }
        Assert.True(constraintCount >= 4 * files.Count, $"only {constraintCount} constraints recorded");
    }
}
