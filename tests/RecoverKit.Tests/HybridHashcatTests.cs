using System.Security.Cryptography;
using System.Text;
using RecoverKit.Core;
using RecoverKit.Core.Hashcat;
using RecoverKit.Core.Native;
using Xunit;

namespace RecoverKit.Tests;

/// <summary>
/// Checks <see cref="HashcatOrder"/> against a real hashcat: with the ordered Markov table, a
/// --skip/--limit run cracks exactly the candidates whose base word lies in the range, for a fast
/// mode (one and three amplifier positions), a UTF-16 mode and a slow (iterated) mode. Needs hashcat
/// (RECOVERKIT_TEST_HASHCAT, or the usual install locations) and a GPU or OpenCL device; does nothing
/// without hashcat. Run with: dotnet test -p:RunSlowTests=true --filter Category=Slow
/// </summary>
[Trait("Category", "Slow")]
[Collection("NativeFeatures")]   // one hashcat at a time: GPU tests must not run in parallel
public class HybridHashcatTests
{
    private static HashcatTool? Tool() => HashcatTool.Locate(Environment.GetEnvironmentVariable("RECOVERKIT_TEST_HASHCAT"));

    private static string Md5(byte[] b) => Convert.ToHexString(MD5.HashData(b)).ToLowerInvariant();

    private static string Pbkdf2(byte[] pw, int i)
    {
        var salt = Encoding.ASCII.GetBytes("rk-salt-" + i);
        var dk = Rfc2898DeriveBytes.Pbkdf2(pw, salt, 1000, HashAlgorithmName.SHA256, 24);
        return $"sha256:1000:{Convert.ToBase64String(salt)}:{Convert.ToBase64String(dk)}";
    }

    [Theory]
    [InlineData(0, "?1?l?d?1", 1)]             // fast mode, short mask: one amplifier position
    [InlineData(0, "?l?l?d?1?d?l?1", 3)]       // fast mode, long mask: three
    [InlineData(70, "?l?d?1?l?d?d", 2)]        // md5(utf16le($pass)): hashcat counts UTF-16 positions
    [InlineData(10900, "?l?d?1?d", 1)]         // PBKDF2-HMAC-SHA256, run outside the kernel
    public async Task SkipAndLimitCrackExactlyTheBaseWordRange(int mode, string mask, int amplifier)
    {
        var tool = Tool();
        if (tool is null) return;
        var space = MaskSpace.FromHashcatArgs(["-a", "3", "-1", "xa7", mask])!;
        int len = space.MaxLength;
        var sorted = HashcatOrder.SortedPositions(space, len);
        long? baseCount = await tool.KeyspaceAsync(mode, HashcatOrder.MaskArgs(sorted)!);
        Assert.NotNull(baseCount);
        var order = HashcatOrder.FromKeyspace(sorted, baseCount!.Value)!;
        Assert.Equal(amplifier, order.AmplifierPositions);

        long n = order.BaseCount, lo = n / 3 + 1, hi = 2 * n / 3 + 1;
        var words = new[] { 0, lo - 1, lo, lo + 1, hi - 2, hi - 1, hi, n - 1 };
        var dir = Directory.CreateTempSubdirectory("rk-hybrid-hc").FullName;
        try
        {
            var lines = new List<string>();
            var byHash = new Dictionary<string, (long Word, string Pw)>();
            int i = 0;
            foreach (long w in words)
                foreach (long amp in new[] { 0, order.AmplifierCount - 1 })
                {
                    var pw = order.Candidate(amp, w);
                    string h = mode switch
                    {
                        0 => Md5(pw),
                        70 => Md5(Encoding.Unicode.GetBytes(Encoding.ASCII.GetString(pw))),
                        _ => Pbkdf2(pw, i++),
                    };
                    lines.Add(h);
                    byHash[h] = (w, Encoding.ASCII.GetString(pw));
                }
            string hashFile = Path.Combine(dir, "h.txt"), outFile = Path.Combine(dir, "out.txt");
            File.WriteAllLines(hashFile, lines);
            var args = new List<string> { "-m", mode.ToString(), hashFile };
            args.AddRange(order.HashcatMaskArgs()!);
            args.AddRange(["--skip", lo.ToString(), "--limit", (hi - lo).ToString(), "--markov-hcstat2", OrderedMarkov.Ensure(dir),
                           "--potfile-disable", "-o", outFile, "--outfile-format", "2", "--quiet", "--session", "rk_hybrid_test_" + mode,
                           "--restore-disable"]);
            var (code, o, e) = await tool.RunAsync(args, TimeSpan.FromMinutes(5));
            Assert.True(code is 0 or 1, $"hashcat exit {code}: {o} {e}");
            var cracked = File.Exists(outFile) ? File.ReadAllLines(outFile).ToHashSet() : [];
            foreach (var (_, (w, pw)) in byHash)
                Assert.True(cracked.Contains(pw) == (w >= lo && w < hi), $"word {w} ({pw}): cracked {cracked.Contains(pw)}, range [{lo},{hi})");

            // The built-in engine's boxes for the same range hold the same candidates.
            var inBoxes = order.Boxes(lo, hi).Sum(b => (long)b.Keyspace(len));
            Assert.Equal((hi - lo) * order.AmplifierCount, inBoxes);
        }
        finally { try { Directory.Delete(dir, true); } catch (IOException) { } }
    }
}
