using System.Text;
using RecoverKit.Core.Formats;
using RecoverKit.Core.Hashcat;

namespace RecoverKit.Core.Attacks;

/// <summary>
/// Key search for 40-bit RC4 encryption (MS Office 97-2003 and PDF 1.1-1.3): instead of passwords,
/// all 2^40 RC4 keys are tried (hashcat "collider #1"), which always succeeds. A password that
/// derives the same key is then searched (collider #2), so the document opens in its usual
/// application. Recovered keys are kept in the key cache.
/// </summary>
public static class KeySearch
{
    public const long KeyCount = 1L << 40;

    /// <summary>hashcat (collider #1, collider #2) modes for a format, or null if key search does not apply.</summary>
    public static (int KeyMode, int PasswordMode, int MaxPasswordLength)? ModesFor(string formatId) => formatId switch
    {
        "972K" => (9710, 9720, 15),
        "XP03" => (9810, 9820, 15),
        "PDF2" => (10410, 10420, 32),
        _ => null,
    };

    public static bool Supports(HashTarget t) => ModesFor(t.FormatId) is not null;

    public static PreparedAttack Prepare(AttackSpec a, HashTarget t)
    {
        if (!Supports(t)) throw new AttackPlanException("Key search applies only to 40-bit RC4 encryption (MS Office 97-2003, PDF 1.1-1.3).");
        var p = new PreparedAttack { Description = a.Describe(), Keyspace = KeyCount };
        p.Args.AddRange(["-a", "3", "?b?b?b?b?b"]);
        return p;
    }

    /// <summary>Collider #2: printable passwords of length 1-8 whose derived key equals the recovered one.</summary>
    public static PreparedAttack EquivalentPasswordAttack(int maxLength)
    {
        int len = Math.Min(8, maxLength);
        var p = new PreparedAttack { Description = $"Password for the recovered key (printable, length 1-{len})" };
        p.Args.AddRange(["-a", "3", "-i", "--increment-min", "1", "--increment-max", len.ToString(), string.Concat(Enumerable.Repeat("?a", len))]);
        System.Numerics.BigInteger ks = 0;
        for (int i = 1; i <= len; i++) ks += System.Numerics.BigInteger.Pow(95, i);
        p.Keyspace = ks;
        return p;
    }

    /// <summary>The 5-byte key from hashcat's output ($HEX[..] or raw), as lower-case hex.</summary>
    public static string? KeyHex(string raw)
    {
        if (raw.StartsWith("$HEX[", StringComparison.Ordinal) && raw.EndsWith(']')) return raw[5..^1].ToLowerInvariant();
        var b = Encoding.Latin1.GetBytes(raw);
        return b.Length == 5 ? Convert.ToHexString(b).ToLowerInvariant() : null;
    }
}

/// <summary>Recovered RC4 keys, one "hash TAB key" line each (Preferences: Key Cache).</summary>
public static class KeyCache
{
    public static string? Lookup(string path, string hash)
    {
        if (!File.Exists(path)) return null;
        foreach (var line in File.ReadLines(path))
        {
            int t = line.LastIndexOf('\t');
            if (t > 0 && line.AsSpan(0, t).Equals(hash.Trim(), StringComparison.OrdinalIgnoreCase)) return line[(t + 1)..].Trim();
        }
        return null;
    }

    public static void Store(string path, string hash, string keyHex)
    {
        if (Lookup(path, hash) is not null) return;
        File.AppendAllText(path, hash.Trim() + "\t" + keyHex + Environment.NewLine);
    }
}
