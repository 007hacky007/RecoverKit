using RecoverKit.Core;
using RecoverKit.Core.Attacks;
using RecoverKit.Core.Attacks.Stay;
using RecoverKit.Core.Formats;
using RecoverKit.Tests.Stay;
using Xunit;

namespace RecoverKit.Tests;

[Trait("Category", "Stay")]
public class StayZipFeatureTests
{
    private static (string Path, HashTarget Target) ZipTarget(int files, uint seed = 0x3f5a7c11)
    {
        var zip = StayTestZip.MakeZip(files, seed);
        return StayTestZip.ExtractToTemp(zip);
    }

    [Fact]
    public void ScenarioLineParsesStayAttack()
    {
        var a = ScenarioParser.ParseLine("/a:s");
        Assert.Equal(AttackKind.StayZip, a.Kind);
    }

    [Fact]
    public void DescribeNamesTheAttack()
        => Assert.Equal("Fast key search: Stay attack on ZipCrypto headers (WinZip-style archives, 5+ files)",
            new AttackSpec { Kind = AttackKind.StayZip }.Describe());

    [Fact]
    public void PlannerRejectsNonZipTargets()
    {
        var target = new HashTarget { FormatId = "PDF2", FormatName = "PDF", Protection = "RC4 40-bit", Modes = [10500], HashLines = "x" };
        Assert.Throws<AttackPlanException>(() =>
            AttackPlanner.Prepare(new AttackSpec { Kind = AttackKind.StayZip }, target, new PlannerContext()));
    }

    [Fact]
    public void PlannerRejectsTooFewZipCryptoEntries()
    {
        var (path, target) = ZipTarget(3);
        try
        {
            Assert.Equal("ZIPC", target.FormatId);
            Assert.Throws<AttackPlanException>(() =>
                AttackPlanner.Prepare(new AttackSpec { Kind = AttackKind.StayZip }, target, new PlannerContext()));
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public void PlannerPreparesForCompatibleZip()
    {
        var (path, target) = ZipTarget(5);
        try
        {
            var plan = AttackPlanner.Prepare(new AttackSpec { Kind = AttackKind.StayZip }, target, new PlannerContext());
            Assert.Contains("Stay attack", plan.Description);
            Assert.Equal(1L << 38, plan.Keyspace);
            Assert.Empty(plan.Args);   // no hashcat run: the session executes it internally
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public void DefaultScenarioRunsStayFirstForZipCrypto()
    {
        var list = ScenarioParser.LoadDefault();
        var zip = list.Single(s => s.DefaultFor.Contains("ZIPC"));
        Assert.Equal(AttackKind.StayZip, zip.Steps[0].Kind);
        Assert.Contains(zip.Steps, s => s.Kind == AttackKind.BruteForce);   // password attacks still follow
        // no other scenario claims ZIPC
        Assert.Single(list, s => s.DefaultFor.Contains("ZIPC"));

        // the old fast-formats defaults survive for PDF R2-R5
        var pdf = list.Single(s => s.DefaultFor.Contains("PDF2"));
        Assert.Contains("PDF3", pdf.DefaultFor);
        Assert.Contains("PDF5", pdf.DefaultFor);
        Assert.Equal(AttackKind.BruteForce, pdf.Steps[0].Kind);
    }

    [Fact]
    public void SettingsEnableStayAttackByDefault()
        => Assert.True(new Settings().TryStayZipAttack);
}
