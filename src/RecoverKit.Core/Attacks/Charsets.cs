using System.Numerics;
using System.Text;

namespace RecoverKit.Core.Attacks;

public static class Charsets
{
    public const string LatinOnly = "Latin only";
    public const string Capitals = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    public const string Smalls = "abcdefghijklmnopqrstuvwxyz";
    public const string Digits = "0123456789";
    public const string Specials = " !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";

    /// <summary>Extra national letters (capitals, smalls) added to the Latin alphabet.</summary>
    public static readonly IReadOnlyDictionary<string, (string Caps, string Smalls)> National =
        new Dictionary<string, (string, string)>
        {
            [LatinOnly] = ("", ""),
            ["Czech/Slovak"] = ("ÁČĎÉĚÍĹĽŇÓÔŔŘŠŤÚŮÝŽÄ", "áčďéěíĺľňóôŕřšťúůýžä"),
            ["Polish"] = ("ĄĆĘŁŃÓŚŹŻ", "ąćęłńóśźż"),
            ["Russian"] = ("АБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ", "абвгдеёжзийклмнопрстуфхцчшщъыьэюя"),
            ["German"] = ("ÄÖÜ", "äöüß"),
            ["Spanish"] = ("ÁÉÍÑÓÚÜ", "áéíñóúü"),
            ["French"] = ("ÀÂÆÇÈÉÊËÎÏÔŒÙÛÜŸ", "àâæçèéêëîïôœùûüÿ"),
            ["Portuguese"] = ("ÀÁÂÃÇÉÊÍÓÔÕÚ", "àáâãçéêíóôõú"),
            ["Italian"] = ("ÀÈÉÌÒÙ", "àèéìòù"),
            ["Swedish/Finnish"] = ("ÄÅÖ", "äåö"),
            ["Norwegian/Danish"] = ("ÆØÅ", "æøå"),
            ["Dutch"] = ("ÉËÏÓÖÜ", "éëïóöü"),
            ["Turkish"] = ("ÇĞİÖŞÜ", "çğıöşü"),
            ["Romanian"] = ("ĂÂÎȘȚ", "ăâîșț"),
            ["Hungarian"] = ("ÁÉÍÓÖŐÚÜŰ", "áéíóöőúüű"),
        };

    /// <summary>Unique characters selected for a brute-force attack, in a stable order.</summary>
    public static string Build(AttackSpec a)
    {
        var sb = new StringBuilder();
        var nat = National.TryGetValue(a.Alphabet, out var n) ? n : ("", "");
        if (a.Smalls) sb.Append(Smalls).Append(nat.Item2);
        if (a.Caps) sb.Append(Capitals).Append(nat.Item1);
        if (a.Digits) sb.Append(Digits);
        if (a.Specials) sb.Append(Specials);
        if (a.UseUserCharset) sb.Append(a.UserCharset);
        return Distinct(sb.ToString());
    }

    public static string Distinct(string s)
    {
        var seen = new HashSet<int>();
        var sb = new StringBuilder();
        foreach (var r in s.EnumerateRunes())
            if (seen.Add(r.Value)) sb.Append(r.ToString());
        return sb.ToString();
    }

    public static bool IsAscii(string s) => s.All(c => c < 128);

    public static int RuneCount(string s) => s.EnumerateRunes().Count();

    // ------------------------------------------------------------ hashcat masks

    private static readonly IReadOnlyDictionary<char, string> Builtin = new Dictionary<char, string>
    {
        ['l'] = Smalls,
        ['u'] = Capitals,
        ['d'] = Digits,
        ['s'] = Specials,
        ['h'] = "0123456789abcdef",
        ['H'] = "0123456789ABCDEF",
    };

    /// <summary>Expands a hashcat charset definition (may reference ?l ?u ?d ...) to its byte set size.</summary>
    public static int CharsetSize(string def, string[] custom, int depth = 0)
    {
        if (depth > 8) return 0;
        var set = new HashSet<int>();
        for (int i = 0; i < def.Length; i++)
        {
            if (def[i] == '?' && i + 1 < def.Length)
            {
                char k = def[++i];
                if (k == '?') set.Add('?');
                else if (k == 'a') foreach (var c in Smalls + Capitals + Digits + Specials) set.Add(c);
                else if (k == 'b') for (int b = 0; b < 256; b++) set.Add(b);
                else if (Builtin.TryGetValue(k, out var bs)) foreach (var c in bs) set.Add(c);
                else if (k is >= '1' and <= '8' && !string.IsNullOrEmpty(custom[k - '1']))
                {
                    // Nested custom charsets are rare; approximate by expanding literally.
                    foreach (var c in ExpandLiteral(custom[k - '1'], custom, depth + 1)) set.Add(c);
                }
            }
            else
            {
                foreach (var b in Encoding.UTF8.GetBytes(def[i].ToString())) set.Add(b);
            }
        }
        return set.Count;
    }

    private static IEnumerable<int> ExpandLiteral(string def, string[] custom, int depth)
    {
        for (int i = 0; i < def.Length; i++)
        {
            if (def[i] == '?' && i + 1 < def.Length)
            {
                char k = def[++i];
                if (k == '?') yield return '?';
                else if (k == 'a') foreach (var c in Smalls + Capitals + Digits + Specials) yield return c;
                else if (Builtin.TryGetValue(k, out var bs)) foreach (var c in bs) yield return c;
            }
            else yield return def[i];
        }
    }

    /// <summary>Splits a hashcat mask into per-position charset sizes.</summary>
    public static List<int> MaskPositions(string mask, string[] custom)
    {
        var r = new List<int>();
        for (int i = 0; i < mask.Length; i++)
        {
            if (mask[i] == '?' && i + 1 < mask.Length)
            {
                char k = mask[++i];
                if (k == '?') r.Add(1);
                else if (k == 'a') r.Add(95);
                else if (k == 'b') r.Add(256);
                else if (Builtin.TryGetValue(k, out var bs)) r.Add(bs.Length);
                else if (k is >= '1' and <= '8') r.Add(CharsetSize(custom[k - '1'] ?? "", custom));
                else r.Add(1);
            }
            else r.Add(1);
        }
        return r;
    }

    public static BigInteger MaskKeyspace(string mask, string[] custom, bool increment, int min, int max)
    {
        var pos = MaskPositions(mask, custom);
        if (pos.Count == 0) return 0;
        if (!increment) return pos.Aggregate(BigInteger.One, (acc, n) => acc * n);
        BigInteger total = 0, prod = 1;
        for (int i = 0; i < pos.Count; i++)
        {
            prod *= pos[i];
            int len = i + 1;
            if (len >= Math.Max(1, min) && len <= max) total += prod;
        }
        return total;
    }

    public static BigInteger BruteKeyspace(AttackSpec a)
    {
        int n = RuneCount(Build(a));
        if (n == 0) return 0;
        if (a.Mask.Length > 0)
        {
            int unknown = a.Mask.Count(c => c == a.MaskSymbol);
            return BigInteger.Pow(n, unknown);
        }
        BigInteger total = 0;
        for (int len = Math.Max(1, a.MinLength); len <= a.MaxLength; len++) total += BigInteger.Pow(n, len);
        return total;
    }
}
