using System.Text;
using RecoverKit.Core.Attacks.Stay;
using Xunit;

namespace RecoverKit.Tests.Stay;

[Trait("Category", "Stay")]
public class ZipRngTests
{
    private const string Password = "&THPOL101%ISLAME@|1";

    private static byte[][] FirstBytes(GeneratedZip zip, int files)
        => Enumerable.Range(0, files).Select(i => new[] { zip.StoredHeaders[i][0] }).ToArray();

    private static byte[] FirstBytesFlat(GeneratedZip zip, int files)
        => Enumerable.Range(0, files).Select(i => zip.StoredHeaders[i][0]).ToArray();

    private static GeneratedZip Zip(int files, ZipRngVariant variant = ZipRngVariant.Msvc, uint seed = 0x12345678,
        int sessions = int.MaxValue)
    {
        var specs = Enumerable.Range(0, files).Select(i => new GeneratedEntry
        {
            Name = $"file{i:D2}.txt",
            Content = Encoding.ASCII.GetBytes($"content number {i} {new string('q', 40 + i * 11)}"),
            Method = i % 2 == 0 ? 0 : 8,
        }).ToList();
        return ZipStayArchive.Generate(specs, Password, variant, seed, filesInFirstSession: sessions);
    }

    private static uint StateAfterFirstStep(uint seed, ZipRngVariant v)
        => unchecked(seed * 214013u + (v == ZipRngVariant.Msvc ? 2531011u : 0u));

    [Fact]
    public void Recovers_unique_state_for_msvc()
    {
        var zip = Zip(5, ZipRngVariant.Msvc, 0x12345678);
        var solutions = ZipRng.RecoverStates(FirstBytesFlat(zip, 5), ZipRngVariant.Msvc, minMatched: 5);

        var solution = Assert.Single(solutions);
        Assert.Equal(ZipRngVariant.Msvc, solution.Variant);
        // the recovered state is the state after the first rand() step of file 0, observable bits 23..30
        uint truth = StateAfterFirstStep(0x12345678, ZipRngVariant.Msvc) & 0x7fffffff;
        Assert.Equal(truth & 0x7fffffff, solution.State);
        Assert.Equal(5, solution.MatchedFiles);

        // headers regenerate exactly from the recovered state
        var r = ZipRng.RandomHeaders(solution.State, ZipRngVariant.Msvc, 5);
        for (int i = 0; i < 5; i++)
            Assert.Equal(zip.R[i], r[i]);
    }

    [Fact]
    public void Recovers_winzip_variant()
    {
        var zip = Zip(5, ZipRngVariant.WinZip, 0x00c0ffee);
        var solutions = ZipRng.RecoverStates(FirstBytesFlat(zip, 5), ZipRngVariant.WinZip, minMatched: 5);

        var solution = Assert.Single(solutions);
        var r = ZipRng.RandomHeaders(solution.State, ZipRngVariant.WinZip, 5);
        for (int i = 0; i < 5; i++)
            Assert.Equal(zip.R[i], r[i]);
    }

    [Fact]
    public void Explains_prefix_of_appended_archive()
    {
        var zip = Zip(7, ZipRngVariant.Msvc, 0x2468ace0, sessions: 5);
        var solutions = ZipRng.RecoverStates(FirstBytesFlat(zip, 7), ZipRngVariant.Msvc, minMatched: 5);

        var solution = Assert.Single(solutions);
        Assert.Equal(5, solution.MatchedFiles);
        var r = ZipRng.RandomHeaders(solution.State, ZipRngVariant.Msvc, 5);
        for (int i = 0; i < 5; i++)
            Assert.Equal(zip.R[i], r[i]);
    }

    [Fact]
    public void Returns_none_for_random_headers()
    {
        var rng = new Random(1234);
        for (int trial = 0; trial < 8; trial++)
        {
            var bytes = new byte[5];
            rng.NextBytes(bytes);
            Assert.Empty(ZipRng.RecoverStates(bytes, ZipRngVariant.Msvc, minMatched: 5));
            Assert.Empty(ZipRng.RecoverStates(bytes, ZipRngVariant.WinZip, minMatched: 5));
        }
    }

    [Fact]
    public void Few_files_leave_multiple_candidates()
    {
        // 2^23 candidate states, 8 bits of filter per extra file: 3 files -> ~2^7 candidates,
        // 4 files -> ~1.5, 5 files -> the truth alone (the attack's gate).
        var zip3 = Zip(3, ZipRngVariant.Msvc, 0x77aa55aa);
        var sol3 = ZipRng.RecoverStates(FirstBytesFlat(zip3, 3), ZipRngVariant.Msvc, minMatched: 3);
        Assert.True(sol3.Count > 8, $"expected many candidates, got {sol3.Count}");
        uint truth = StateAfterFirstStep(0x77aa55aa, ZipRngVariant.Msvc) & 0x7fffffff;
        Assert.Contains(sol3, s => s.State == truth);

        var zip4 = Zip(4, ZipRngVariant.Msvc, 0x77aa55aa);
        var sol4 = ZipRng.RecoverStates(FirstBytesFlat(zip4, 4), ZipRngVariant.Msvc, minMatched: 4);
        Assert.Contains(sol4, s => s.State == truth);   // truth always survives
    }

    [Fact]
    public void Recovery_is_fast()
    {
        var zip = Zip(5);
        var bytes = FirstBytesFlat(zip, 5);
        var sw = System.Diagnostics.Stopwatch.StartNew();
        ZipRng.RecoverStates(bytes, ZipRngVariant.Msvc, minMatched: 5);
        ZipRng.RecoverStates(bytes, ZipRngVariant.WinZip, minMatched: 5);
        sw.Stop();
        Assert.True(sw.ElapsedMilliseconds < 5000, $"took {sw.ElapsedMilliseconds} ms");
    }
}
