using System.Reflection;
using System.Text;

namespace RecoverKit.Core.Native;

/// <summary>
/// One length of a mask, numbered the way hashcat numbers it in a mask attack (-a 3) that uses
/// RecoverKit's ordered Markov table, so a hashcat --skip/--limit range and a set of built-in engine
/// keyspaces can cover exactly the same candidates.
///
/// hashcat splits the mask positions in two (src/mpsp.c, mp_css_split_cnt): the first
/// <see cref="AmplifierPositions"/> positions are the "amplifier", which the kernel runs through in
/// full for every base word, and the remaining positions form the base word. --skip, --limit and the
/// restore point count base words. A base word's number is a mixed-radix number whose least
/// significant digit is the first base position (src/mpsp.c sp_exec, OpenCL/markov_le.cl). Each
/// position's characters are ordered by the Markov table; with <see cref="OrderedMarkov"/> that is
/// ascending byte order, so digit value i is the i-th smallest byte of the position's charset.
///
/// How many positions the amplifier takes depends on the hash mode and the mask (fast modes use more,
/// UTF-16 modes count expanded positions). Instead of repeating hashcat's rules, the number is
/// derived from hashcat's own --keyspace output: the base word count is the product of the base
/// positions' charset sizes.
/// </summary>
public sealed class HashcatOrder
{
    /// <summary>Charset of each position, sorted ascending (hashcat's order with the ordered table).</summary>
    public IReadOnlyList<byte[]> Positions { get; }
    public int Length => Positions.Count;
    public int AmplifierPositions { get; }
    /// <summary>Number of base words, the unit of --skip / --limit / restore points.</summary>
    public long BaseCount { get; }
    /// <summary>Candidates per base word.</summary>
    public long AmplifierCount { get; }
    public long Candidates => BaseCount * AmplifierCount;

    private readonly long[] _unit;   // _unit[k]: base words per step of base digit k (digit k = position r + k)

    private HashcatOrder(IReadOnlyList<byte[]> positions, int r)
    {
        Positions = positions;
        AmplifierPositions = r;
        long a = 1, b = 1;
        for (int i = 0; i < r; i++) a = checked(a * positions[i].Length);
        _unit = new long[positions.Count - r + 1];
        _unit[0] = 1;
        for (int k = 0; k < positions.Count - r; k++)
        {
            b = checked(b * positions[r + k].Length);
            _unit[k + 1] = b;
        }
        BaseCount = b;
        AmplifierCount = a;
        _ = checked(a * b);   // the whole length must fit in a long
    }

    /// <summary>The first <paramref name="length"/> positions of <paramref name="space"/>, sorted.</summary>
    public static IReadOnlyList<byte[]> SortedPositions(MaskSpace space, int length)
        => space.Positions.Take(length).Select(p => p.Distinct().OrderBy(b => b).ToArray()).ToList();

    /// <summary>
    /// The numbering for one length, given the base word count hashcat reported (--keyspace), or null
    /// when no split of the positions matches it or the length does not fit in 64 bits.
    /// </summary>
    public static HashcatOrder? FromKeyspace(IReadOnlyList<byte[]> sortedPositions, long hashcatBaseCount)
    {
        int n = sortedPositions.Count;
        // The smallest r whose base product matches. Positions with a single character do not change
        // the product, so several r can match; they describe the same numbering.
        for (int r = 0; r <= n; r++)
        {
            long prod = 1;
            bool overflow = false;
            for (int i = r; i < n && !overflow; i++)
            {
                try { prod = checked(prod * sortedPositions[i].Length); }
                catch (OverflowException) { overflow = true; }
            }
            if (overflow || prod != hashcatBaseCount) continue;
            try { return new HashcatOrder(sortedPositions, r); }
            catch (OverflowException) { return null; }
        }
        return null;
    }

    /// <summary>For tests and planning: a numbering with a known amplifier size.</summary>
    public static HashcatOrder WithAmplifier(IReadOnlyList<byte[]> sortedPositions, int amplifierPositions)
        => new(sortedPositions, amplifierPositions);

    /// <summary>The candidate with amplifier number <paramref name="amp"/> and base word <paramref name="baseWord"/>.</summary>
    public byte[] Candidate(long amp, long baseWord)
    {
        var pw = new byte[Length];
        for (int i = 0; i < AmplifierPositions; i++)
        {
            var p = Positions[i];
            pw[i] = p[amp % p.Length];
            amp /= p.Length;
        }
        for (int i = AmplifierPositions; i < Length; i++)
        {
            var p = Positions[i];
            pw[i] = p[baseWord % p.Length];
            baseWord /= p.Length;
        }
        return pw;
    }

    /// <summary>The base word that contains <paramref name="password"/> (which must fit the mask).</summary>
    public long BaseWordOf(ReadOnlySpan<byte> password)
    {
        long w = 0;
        for (int i = Length - 1; i >= AmplifierPositions; i--)
            w = w * Positions[i].Length + Array.IndexOf(Positions[i], password[i]);
        return w;
    }

    /// <summary>
    /// Mask spaces (all of this length) that together hold exactly the candidates of base words
    /// [<paramref name="lo"/>, <paramref name="hi"/>), each once. The range is cut into blocks where
    /// one base digit runs over a sub-range, the digits below it are free and the ones above fixed.
    /// </summary>
    public List<MaskSpace> Boxes(long lo, long hi)
    {
        var boxes = new List<MaskSpace>();
        int m = Length - AmplifierPositions;
        if (lo >= hi) return boxes;
        if (m == 0)
        {
            boxes.Add(new MaskSpace { Positions = Positions, MinLength = Length, MaxLength = Length });
            return boxes;
        }
        long cur = lo;
        while (cur < hi)
        {
            int j = 0;
            while (j + 1 < m && cur % _unit[j + 1] == 0 && cur + _unit[j + 1] <= hi) j++;
            int radix = Positions[AmplifierPositions + j].Length;
            long digit = cur / _unit[j] % radix;
            long count = Math.Min((hi - cur) / _unit[j], radix - digit);
            var pos = new byte[Length][];
            for (int i = 0; i < AmplifierPositions + j; i++) pos[i] = Positions[i];
            pos[AmplifierPositions + j] = Positions[AmplifierPositions + j][(int)digit..(int)(digit + count)];
            for (int k = j + 1; k < m; k++)
            {
                var p = Positions[AmplifierPositions + k];
                pos[AmplifierPositions + k] = [p[cur / _unit[k] % p.Length]];
            }
            boxes.Add(new MaskSpace { Positions = pos, MinLength = Length, MaxLength = Length });
            cur += count * _unit[j];
        }
        return boxes;
    }

    /// <summary>
    /// A start in [lo, hi) close to <paramref name="target"/> on a boundary of the coarsest base digit
    /// whose blocks are no larger than <paramref name="size"/>, so batches split into few, large boxes.
    /// </summary>
    public long AlignDown(long target, long size, long lo)
    {
        long unit = 1;
        foreach (var u in _unit) if (u <= Math.Max(1, size)) unit = u;
        return Math.Max(lo, Math.Max(0, target) / unit * unit);
    }

    /// <summary>
    /// hashcat arguments for exactly this length, with every charset given in hex: -1..-8 for the
    /// positions with several characters, hex literals for fixed ones. Null when more than eight
    /// different charsets would be needed.
    /// </summary>
    public List<string>? HashcatMaskArgs() => MaskArgs(Positions);

    /// <inheritdoc cref="HashcatMaskArgs"/>
    public static List<string>? MaskArgs(IReadOnlyList<byte[]> positions)
    {
        var sets = new List<byte[]>();
        var mask = new StringBuilder();
        foreach (var p in positions)
        {
            if (p.Length == 1) { mask.Append(Convert.ToHexString(p).ToLowerInvariant()); continue; }
            int idx = sets.FindIndex(s => s.AsSpan().SequenceEqual(p));
            if (idx < 0)
            {
                if (sets.Count == 8) return null;
                sets.Add(p);
                idx = sets.Count - 1;
            }
            mask.Append('?').Append((char)('1' + idx));
        }
        var args = new List<string> { "-a", "3", "--hex-charset" };
        for (int i = 0; i < sets.Count; i++) args.AddRange([$"-{i + 1}", Convert.ToHexString(sets[i]).ToLowerInvariant()]);
        args.Add(mask.ToString());
        return args;
    }
}

/// <summary>
/// The Markov statistics file that makes hashcat enumerate every mask position in ascending byte
/// order (see Native/Resources/make-ordered-hcstat2.py). Written once next to the session files.
/// </summary>
public static class OrderedMarkov
{
    public const string FileName = "recoverkit-ordered.hcstat2";

    public static string Ensure(string dir)
    {
        string path = Path.Combine(dir, FileName);
        using var res = Assembly.GetExecutingAssembly().GetManifestResourceStream("RecoverKit.ordered.hcstat2")
            ?? throw new InvalidOperationException("ordered Markov table resource missing");
        if (File.Exists(path) && new FileInfo(path).Length == res.Length) return path;
        string tmp = path + ".tmp";
        using (var f = File.Create(tmp)) res.CopyTo(f);
        File.Move(tmp, path, overwrite: true);
        return path;
    }
}
