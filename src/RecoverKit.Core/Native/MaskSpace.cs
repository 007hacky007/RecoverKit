using System.Numerics;

namespace RecoverKit.Core.Native;

/// <summary>
/// A hashcat-compatible brute-force/mask keyspace, built from the same "-a 3" arguments the attack
/// planner passes to hashcat, so the built-in CPU engine tests exactly the candidates hashcat would.
/// Supports ?l ?u ?d ?h ?H ?s ?a ?b ??, custom charsets -1..-8, --hex-charset (which in hashcat also
/// applies to mask literals) and -i / --increment-min / --increment-max.
/// </summary>
public sealed class MaskSpace
{
    /// <summary>Allowed bytes for each mask position, in hashcat's order.</summary>
    public required IReadOnlyList<byte[]> Positions { get; init; }
    public int MinLength { get; init; }
    public int MaxLength { get; init; }

    public BigInteger Keyspace(int length)
    {
        BigInteger k = 1;
        for (int i = 0; i < length; i++) k *= Positions[i].Length;
        return k;
    }

    public BigInteger TotalKeyspace
    {
        get
        {
            BigInteger t = 0;
            for (int l = MinLength; l <= MaxLength; l++) t += Keyspace(l);
            return t;
        }
    }

    private static readonly byte[] Lower = Range('a', 'z'), Upper = Range('A', 'Z'), Digits = Range('0', '9');
    private static readonly byte[] HexLower = [.. Digits, .. Range('a', 'f')], HexUpper = [.. Digits, .. Range('A', 'F')];
    private static readonly byte[] Special = " !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"u8.ToArray();
    private static readonly byte[] All = [.. Lower, .. Upper, .. Digits, .. Special];
    private static readonly byte[] AnyByte = Enumerable.Range(0, 256).Select(i => (byte)i).ToArray();

    private static byte[] Range(char a, char b) => Enumerable.Range(a, b - a + 1).Select(i => (byte)i).ToArray();

    /// <summary>
    /// Builds the keyspace from hashcat arguments, or returns null when they describe anything else
    /// (another attack mode, an option the native engine does not understand, an empty charset).
    /// </summary>
    public static MaskSpace? FromHashcatArgs(IReadOnlyList<string> args)
    {
        string? attackMode = null, mask = null;
        bool hex = false, increment = false;
        int? incMin = null, incMax = null;
        var custom = new string?[8];
        for (int i = 0; i < args.Count; i++)
        {
            string a = args[i];
            switch (a)
            {
                case "-a": if (++i >= args.Count) return null; attackMode = args[i]; break;
                case "--hex-charset": hex = true; break;
                case "-i": case "--increment": increment = true; break;
                case "--increment-min": if (++i >= args.Count || !int.TryParse(args[i], out var mn)) return null; incMin = mn; break;
                case "--increment-max": if (++i >= args.Count || !int.TryParse(args[i], out var mx)) return null; incMax = mx; break;
                default:
                    if (a.Length == 2 && a[0] == '-' && a[1] is >= '1' and <= '8')
                    {
                        if (++i >= args.Count) return null;
                        custom[a[1] - '1'] = args[i];
                    }
                    else if (a.StartsWith('-')) return null;      // unknown option: leave it to hashcat
                    else if (mask is null) mask = a;
                    else return null;
                    break;
            }
        }
        if (attackMode != "3" || string.IsNullOrEmpty(mask)) return null;

        var customSets = new byte[]?[8];
        for (int k = 0; k < 8; k++)
            if (custom[k] is { } c)
            {
                customSets[k] = hex ? FromHex(c) : ExpandCharset(c, customSets);
                if (customSets[k] is null) return null;
            }

        var positions = ParseMask(mask, customSets, hex);
        if (positions is null || positions.Count == 0 || positions.Any(p => p.Length == 0)) return null;

        int min = positions.Count, max = positions.Count;
        if (increment)
        {
            min = Math.Clamp(incMin ?? 1, 1, positions.Count);
            max = Math.Clamp(incMax ?? positions.Count, min, positions.Count);
        }
        return new MaskSpace { Positions = positions, MinLength = min, MaxLength = max };
    }

    private static List<byte[]>? ParseMask(string mask, byte[]?[] custom, bool hex)
    {
        var list = new List<byte[]>();
        for (int i = 0; i < mask.Length; i++)
        {
            char c = mask[i];
            if (c == '?')
            {
                if (++i >= mask.Length) return null;
                var set = Builtin(mask[i], custom);
                if (set is null) return null;
                list.Add(set);
            }
            else if (hex)
            {
                if (i + 1 >= mask.Length || !IsHex(c) || !IsHex(mask[i + 1])) return null;
                list.Add([Convert.ToByte(mask.Substring(i, 2), 16)]);
                i++;
            }
            else
            {
                if (c > 0x7f) return null;        // non-ASCII literal: hashcat would split UTF-8 bytes; let it handle that
                list.Add([(byte)c]);
            }
        }
        return list;
    }

    private static byte[]? Builtin(char c, byte[]?[] custom) => c switch
    {
        'l' => Lower, 'u' => Upper, 'd' => Digits, 'h' => HexLower, 'H' => HexUpper,
        's' => Special, 'a' => All, 'b' => AnyByte, '?' => [(byte)'?'],
        >= '1' and <= '8' => custom[c - '1'],
        _ => null,
    };

    /// <summary>A non-hex custom charset: literal characters plus ?x references, de-duplicated in order.</summary>
    private static byte[]? ExpandCharset(string s, byte[]?[] earlier)
    {
        var seen = new bool[256];
        var outp = new List<byte>();
        void Add(IEnumerable<byte> bs) { foreach (var b in bs) if (!seen[b]) { seen[b] = true; outp.Add(b); } }
        for (int i = 0; i < s.Length; i++)
        {
            if (s[i] == '?' && i + 1 < s.Length)
            {
                var set = Builtin(s[++i], earlier);
                if (set is null) return null;
                Add(set);
            }
            else if (s[i] > 0x7f) return null;
            else Add([(byte)s[i]]);
        }
        return outp.ToArray();
    }

    private static byte[]? FromHex(string s)
    {
        if (s.Length % 2 != 0 || !s.All(IsHex)) return null;
        var b = Convert.FromHexString(s);
        var seen = new bool[256];
        return b.Where(x => !seen[x] && (seen[x] = true)).ToArray();
    }

    private static bool IsHex(char c) => c is >= '0' and <= '9' or >= 'a' and <= 'f' or >= 'A' and <= 'F';
}
