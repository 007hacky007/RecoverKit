using RecoverKit.Core.Attacks.Stay;
using RecoverKit.Core.Formats;
using Xunit;

namespace RecoverKit.Tests.Stay;

public class StayAttackTests
{
    [Fact]
    public void Stage3_recovers_exact_keys_from_true_survivor()
    {
        var zip = StayTestZip.MakeZip(5);
        var files = StayTestZip.FileData(zip);
        var s2 = StayTestZip.TrueStage2(zip, files);

        var keys = StayStage3.RecoverKeys(s2, files, CancellationToken.None).ToList();
        Assert.Contains(new ZipStayKeys(zip.X, zip.Y, zip.Z), keys);
        Assert.True(keys.Count <= 8, $"too many key candidates: {keys.Count}");
    }

    [Fact]
    public void VerifyKeys_accepts_true_and_rejects_corrupted()
    {
        var zip = StayTestZip.MakeZip(5, lastIsDescriptor: true);   // file 4 uses a data descriptor
        var (path, target) = StayTestZip.ExtractToTemp(zip);
        try
        {
            var keys = new ZipStayKeys(zip.X, zip.Y, zip.Z);
            var indices = Enumerable.Range(0, 5).ToArray();
            Assert.True(StayAttack.VerifyKeys(target.StayZip!, keys, zip.R, indices, path));

            var corrupted = target.StayZip!;
            corrupted.Entries[2].StoredHeader[5] ^= 0x40;
            Assert.False(StayAttack.VerifyKeys(corrupted, keys, zip.R, indices, path));

            var wrongKeys = new ZipStayKeys(zip.X, zip.Y ^ 1, zip.Z);
            Assert.False(StayAttack.VerifyKeys(target.StayZip!, wrongKeys, zip.R, indices, path));
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public async Task Run_recovers_keys_end_to_end()
    {
        var zip = StayTestZip.MakeZip(5, seed: 0x13579bdf);
        var (path, target) = StayTestZip.ExtractToTemp(zip);
        try
        {
            var result = await StayAttack.RunAsync(target.StayZip!, CancellationToken.None, archivePath: path);
            Assert.NotNull(result);
            Assert.Equal(new ZipStayKeys(zip.X, zip.Y, zip.Z), result!.Keys);
            Assert.Equal(ZipRngVariant.Msvc, result.Variant);
            Assert.Equal(5, result.ExplainedFiles);
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public async Task Run_recovers_keys_winzip_variant()
    {
        var zip = StayTestZip.MakeZip(5, seed: 0x00c0ffee, variant: ZipRngVariant.WinZip);
        var (path, target) = StayTestZip.ExtractToTemp(zip);
        try
        {
            var result = await StayAttack.RunAsync(target.StayZip!, CancellationToken.None, archivePath: path);
            Assert.NotNull(result);
            Assert.Equal(new ZipStayKeys(zip.X, zip.Y, zip.Z), result!.Keys);
            Assert.Equal(ZipRngVariant.WinZip, result.Variant);
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public async Task Run_explains_prefix_and_verifies_all_matched()
    {
        var zip = StayTestZip.MakeZip(7, seed: 0x2468ace0, sessions: 5);
        var (path, target) = StayTestZip.ExtractToTemp(zip);
        try
        {
            var result = await StayAttack.RunAsync(target.StayZip!, CancellationToken.None, archivePath: path);
            Assert.NotNull(result);
            Assert.Equal(5, result!.ExplainedFiles);
            Assert.Equal(new ZipStayKeys(zip.X, zip.Y, zip.Z), result.Keys);
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public async Task Run_returns_null_for_incompatible()
    {
        // too few files
        var zip4 = StayTestZip.MakeZip(4);
        var (p4, t4) = StayTestZip.ExtractToTemp(zip4);
        try { Assert.Null(await StayAttack.RunAsync(t4.StayZip!, CancellationToken.None, archivePath: p4)); }
        finally { File.Delete(p4); }

        // every file from its own session: no 5-file RNG chain exists
        var zipRandom = StayTestZip.MakeZip(5, sessions: 1);
        var (pr, tr) = StayTestZip.ExtractToTemp(zipRandom);
        try { Assert.Null(await StayAttack.RunAsync(tr.StayZip!, CancellationToken.None, archivePath: pr)); }
        finally { File.Delete(pr); }
    }

    [Fact]
    public async Task Run_returns_null_for_truncated_archive()
    {
        var specs = Enumerable.Range(0, 5).Select(i => new GeneratedEntry
        {
            Name = $"file{i:D2}.txt",
            Content = "truncated test"u8.ToArray(),
            Method = 0,
            ForceCompSize = i < 3 ? 8 : null,   // three entries claim fewer than 12 bytes
        }).ToList();
        var zip = ZipStayArchive.Generate(specs, StayTestZip.Password, ZipRngVariant.Msvc, 0x77aa55aa);
        var (path, target) = StayTestZip.ExtractToTemp(zip);
        try
        {
            Assert.True(target.StayZip!.Entries.Count < 5, "short entries were not skipped");
            Assert.Null(await StayAttack.RunAsync(target.StayZip!, CancellationToken.None, archivePath: path));
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public async Task Run_reports_progress_and_cancels()
    {
        var zip = StayTestZip.MakeZip(5);
        var (path, target) = StayTestZip.ExtractToTemp(zip);
        try
        {
            var gate = new object();
            var fractions = new List<double>();
            var result = await StayAttack.RunAsync(target.StayZip!, CancellationToken.None,
                progress: (f, _) => { lock (gate) fractions.Add(f); }, archivePath: path);
            Assert.NotNull(result);
            Assert.True(fractions.Count >= 2, "no progress reported");
            Assert.Equal(fractions.OrderBy(x => x), fractions);   // non-decreasing

            using var cts = new CancellationTokenSource();
            int seen = 0;
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => StayAttack.RunAsync(
                target.StayZip!, cts.Token,
                progress: (f, _) => { lock (gate) { fractions.Add(f); if (++seen >= 3) cts.Cancel(); } },
                archivePath: path));
        }
        finally { File.Delete(path); }
    }
}
