using System.Text;

namespace RecoverKit.Core.Attacks;

/// <summary>
/// CPU-side candidate generators, piped to hashcat's stdin for cases hashcat
/// cannot express natively: Unicode brute-force charsets, three-word
/// combinations, separator variants and length-filtered or UTF-16 dictionaries.
/// The formats this tool targets use slow hashes, so stdin bandwidth is not the
/// bottleneck; the GPU still does all hashing.
/// </summary>
public static class Generators
{
    public static IEnumerable<string> BruteForce(string charset, int min, int max, string mask = "", char maskSymbol = '?')
    {
        var chars = charset.EnumerateRunes().Select(r => r.ToString()).ToArray();
        if (chars.Length == 0) yield break;

        if (mask.Length > 0)
        {
            var template = mask.EnumerateRunes().Select(r => r.ToString()).ToArray();
            var slots = template.Select((c, i) => (c, i)).Where(x => x.c == maskSymbol.ToString()).Select(x => x.i).ToArray();
            foreach (var combo in Odometer(chars, slots.Length))
            {
                var t = (string[])template.Clone();
                for (int k = 0; k < slots.Length; k++) t[slots[k]] = combo[k];
                yield return string.Concat(t);
            }
            yield break;
        }

        for (int len = Math.Max(1, min); len <= max; len++)
            foreach (var combo in Odometer(chars, len))
                yield return string.Concat(combo);
    }

    private static IEnumerable<string[]> Odometer(string[] chars, int len)
    {
        if (len == 0) { yield return []; yield break; }
        var idx = new int[len];
        var cur = new string[len];
        for (int i = 0; i < len; i++) cur[i] = chars[0];
        while (true)
        {
            yield return cur;
            int p = len - 1;
            while (p >= 0)
            {
                idx[p]++;
                if (idx[p] < chars.Length) { cur[p] = chars[idx[p]]; break; }
                idx[p] = 0;
                cur[p] = chars[0];
                p--;
            }
            if (p < 0) yield break;
        }
    }

    public static readonly string[] Separators = ["", " ", "_", "-", "."];

    /// <summary>Word combinations from up to three dictionaries.</summary>
    public static IEnumerable<string> Combine(IReadOnlyList<string> dicts, int words, bool advanced, int minLen, int maxLen)
    {
        string d1 = dicts[0];
        string d2 = dicts.Count > 1 && !string.IsNullOrEmpty(dicts[1]) ? dicts[1] : d1;
        string d3 = dicts.Count > 2 && !string.IsNullOrEmpty(dicts[2]) ? dicts[2] : d2;
        var second = Wordlists.ReadWords(d2).ToList();
        var third = words == 3 ? Wordlists.ReadWords(d3).ToList() : [""];
        var seps = advanced ? Separators : [""];

        foreach (var a in Wordlists.ReadWords(d1))
        foreach (var b in second)
        foreach (var c in third)
        foreach (var sep in seps)
        {
            if (Accept(a + sep + b + (c.Length > 0 ? sep + c : ""), minLen, maxLen, out var plain))
                yield return plain;
            if (advanced)
            {
                var cap = Cap(a) + sep + Cap(b) + (c.Length > 0 ? sep + Cap(c) : "");
                if (cap != plain && Accept(cap, minLen, maxLen, out var capped)) yield return capped;
            }
        }
    }

    public static long CombineVariants(int words, bool advanced) => advanced ? Separators.Length * 2L : 1L;

    private static bool Accept(string s, int min, int max, out string r)
    {
        r = s;
        int n = Charsets.RuneCount(s);
        return (min <= 0 || n >= min) && (max <= 0 || n <= max);
    }

    private static string Cap(string w) => w.Length == 0 ? w : char.ToUpperInvariant(w[0]) + w[1..].ToLowerInvariant();

    /// <summary>Writes candidates to a stream as UTF-8 lines; stops quietly when the reader goes away.</summary>
    public static void Pump(IEnumerable<string> candidates, Stream output, CancellationToken ct)
    {
        using var w = new StreamWriter(output, new UTF8Encoding(false), 1 << 20) { NewLine = "\n", AutoFlush = false };
        try
        {
            foreach (var c in candidates)
            {
                if (ct.IsCancellationRequested) break;
                w.WriteLine(c);
            }
            w.Flush();
        }
        catch (IOException) { /* hashcat exited or closed the pipe */ }
        catch (ObjectDisposedException) { }
    }
}
