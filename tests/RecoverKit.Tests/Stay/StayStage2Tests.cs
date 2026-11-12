using System.Text;
using RecoverKit.Core.Attacks.Stay;
using Xunit;

namespace RecoverKit.Tests.Stay;

public class StayStage2Tests
{
    [Fact]
    public void Filter_accepts_true_guess_all_files()
    {
        var zip = StayTestZip.MakeZip();
        var files = StayTestZip.FileData(zip);
        var s1 = StayTestZip.TrueStage1(zip, files);
        var (a1, bY2, ch, cl, _) = StayTestZip.TrueStage2Guesses(zip);

        for (int i = 0; i < files.Count; i++)
            Assert.True(StayStage2.FilterPasses(files[i], i, s1, a1, bY2, ch, cl), $"file {i}");
    }

    [Fact]
    public void Filter_rejects_wrong_guesses()
    {
        var zip = StayTestZip.MakeZip();
        var files = StayTestZip.FileData(zip);
        var s1 = StayTestZip.TrueStage1(zip, files);
        var (a1, bY2, ch, cl, _) = StayTestZip.TrueStage2Guesses(zip);

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
        var zip = StayTestZip.MakeZip();
        var files = StayTestZip.FileData(zip);
        var s1 = StayTestZip.TrueStage1(zip, files);
        var (a1, bY2, ch, cl, _) = StayTestZip.TrueStage2Guesses(zip);

        var survivors = StayStage2.Search([s1], files);
        Assert.True(survivors.Count > 0 && survivors.Count <= 1 << 8, $"count {survivors.Count}");

        var truth = Assert.Single(survivors, s => s.A1 == a1 && s.BY2 == bY2 && s.C24 == (StayTruth.Crc(zip.Z) & 0xffffff));
        Assert.Equal(a1, truth.A1);
        Assert.Equal(bY2, truth.BY2);
    }

    [Fact]
    public void Constraints_are_satisfied_by_true_Y()
    {
        var zip = StayTestZip.MakeZip();
        var files = StayTestZip.FileData(zip);
        var s1 = StayTestZip.TrueStage1(zip, files);
        var (a1, bY2, ch, cl, _) = StayTestZip.TrueStage2Guesses(zip);

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
