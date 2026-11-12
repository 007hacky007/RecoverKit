using System.Text;
using System.Text.RegularExpressions;

namespace RecoverKit.Core.Formats;

/// <summary>
/// Finds the standard security handler dictionary of a PDF and produces
/// hashcat hashes for the document open (user) password:
/// R2 (10400), R3/R4 (10500), R5 (10600) and R6 (10700).
/// The encryption dictionary may be referenced from a classic trailer or from
/// a cross-reference stream dictionary; both are uncompressed by specification.
/// </summary>
public static partial class PdfExtractor
{
    public static bool IsPdf(byte[] head) => Bin.IndexOf(head, "%PDF-"u8) is >= 0 and < 1024;

    public static void Extract(Stream s, Detection d)
    {
        if (s.Length > 1L << 31) throw new UnsupportedFormatException("PDF files over 2 GB are not supported.");
        var bytes = new byte[s.Length];
        s.Position = 0;
        s.ReadExactly(bytes);
        string t = Encoding.Latin1.GetString(bytes);

        var ver = PdfVersion().Match(t);
        d.TypeName = ver.Success ? $"Adobe PDF {ver.Groups[1].Value} document" : "Adobe PDF document";

        if (s.Length <= PdfDocument.MaxBytes && PdfDecryptor.TryAddUnlock(bytes, d)) return;

        var refs = EncryptRef().Matches(t);
        string? dict = null;
        if (refs.Count > 0)
        {
            var last = refs[^1];
            string num = last.Groups[1].Value, gen = last.Groups[2].Value;
            var objs = new Regex($@"(?<![0-9]){num}\s+{gen}\s+obj\b").Matches(t);
            if (objs.Count == 0) throw new FormatException("Encryption dictionary object not found.");
            int start = t.IndexOf("<<", objs[^1].Index, StringComparison.Ordinal);
            dict = ReadDictionary(t, start);
        }
        else
        {
            int direct = t.LastIndexOf("/Encrypt", StringComparison.Ordinal);
            if (direct >= 0)
            {
                int start = t.IndexOf("<<", direct, StringComparison.Ordinal);
                if (start > direct && start - direct < 32) dict = ReadDictionary(t, start);
            }
        }
        if (dict is null) { d.Message = "Document is not encrypted."; return; }

        string filter = Name(dict, "Filter") ?? "";
        if (filter != "Standard") throw new UnsupportedFormatException($"Security handler '{filter}' is not supported (only the password-based Standard handler).");

        int v = Int(dict, "V") ?? 0, r = Int(dict, "R") ?? 0, p = Int(dict, "P") ?? 0;
        int length = Int(dict, "Length") ?? 40;
        bool encMeta = !Regex.IsMatch(dict, @"/EncryptMetadata\s+false");
        var o = Str(dict, "O") ?? throw new FormatException("Missing /O entry.");
        var u = Str(dict, "U") ?? throw new FormatException("Missing /U entry.");

        var idMatches = IdArray().Matches(t);
        byte[] id = idMatches.Count > 0 ? ParseString(idMatches[^1].Groups[1].Value) : [];

        d.Add("Security handler", $"Standard, V={v}, R={r}");
        d.Add("Permissions (P)", p.ToString());

        string hash;
        int mode;
        string protection;
        SpeedClass speed;
        switch (r)
        {
            case 2:
                mode = 10400; protection = "RC4 40-bit, MD5"; speed = SpeedClass.VeryFast;
                hash = $"$pdf$1*2*40*{p}*{(encMeta ? 1 : 0)}*{id.Length}*{Bin.Hex(id)}*32*{Bin.Hex(Pad(u, 32))}*32*{Bin.Hex(Pad(o, 32))}";
                break;
            case 3:
            case 4:
                mode = 10500; speed = SpeedClass.Fast;
                if (v == 4) length = 128;
                protection = v == 4 && Regex.IsMatch(dict, @"/CFM\s*/AESV2") ? "AES-128, MD5" : $"RC4 {length}-bit, MD5";
                hash = $"$pdf${(v == 4 ? 4 : 2)}*{r}*{length}*{p}*{(encMeta ? 1 : 0)}*{id.Length}*{Bin.Hex(id)}*32*{Bin.Hex(Pad(u, 32))}*32*{Bin.Hex(Pad(o, 32))}";
                break;
            case 5:
            case 6:
                mode = r == 5 ? 10600 : 10700;
                protection = r == 5 ? "AES-256, SHA-256 (Acrobat 9)" : "AES-256, SHA-256/384/512 (Acrobat X+)";
                speed = r == 5 ? SpeedClass.VeryFast : SpeedClass.Slow;
                if (u.Length < 48) throw new FormatException("/U entry is too short for revision 5/6.");
                hash = $"$pdf$5*{r}*256*{p}*{(encMeta ? 1 : 0)}*{id.Length}*{Bin.Hex(id)}*127*{Bin.Hex(Pad(u, 127))}*127*{Bin.Hex(Pad(o, 127))}*32*{Bin.Hex(new byte[32])}*32*{Bin.Hex(new byte[32])}";
                break;
            default:
                throw new UnsupportedFormatException($"PDF security handler revision {r} is not supported.");
        }

        d.Target = new HashTarget
        {
            FormatId = r == 2 ? "PDF2" : r <= 4 ? "PDF3" : r == 5 ? "PDF5" : "PDF6",
            FormatName = d.TypeName,
            Protection = protection,
            Modes = [mode],
            HashLines = hash,
            Speed = speed,
            MaxPasswordLength = r >= 5 ? 127 : 32,
            Notes = "The attack searches for the document open (user) password. If the document opens without a password, " +
                    "only an owner (permissions) password is set and it can be removed without recovery.",
        };
    }

    // -------------------------------------------------------------- tiny parser

    private static string ReadDictionary(string t, int start)
    {
        if (start < 0) throw new FormatException("Dictionary not found.");
        int depth = 0;
        for (int i = start; i < t.Length - 1; i++)
        {
            char c = t[i];
            if (c == '(') { i = SkipLiteral(t, i); continue; }
            if (c == '<' && t[i + 1] == '<') { depth++; i++; continue; }
            if (c == '>' && t[i + 1] == '>') { depth--; i++; if (depth == 0) return t.Substring(start, i - start + 1); continue; }
        }
        throw new FormatException("Unterminated dictionary.");
    }

    private static int SkipLiteral(string t, int i)
    {
        int depth = 0;
        for (; i < t.Length; i++)
        {
            char c = t[i];
            if (c == '\\') { i++; continue; }
            if (c == '(') depth++;
            else if (c == ')' && --depth == 0) return i;
        }
        return i;
    }

    private static string? Name(string dict, string key)
    {
        var m = Regex.Match(dict, $@"/{key}\s*/([A-Za-z0-9#._-]+)");
        return m.Success ? m.Groups[1].Value : null;
    }

    private static int? Int(string dict, string key)
    {
        var m = Regex.Match(dict, $@"/{key}\s+(-?\d+)(?!\s+\d+\s+R)");
        return m.Success ? (int)long.Parse(m.Groups[1].Value) : null;
    }

    private static byte[]? Str(string dict, string key)
    {
        var m = Regex.Match(dict, $@"/{key}\s*(?=[(<])");
        if (!m.Success) return null;
        int i = m.Index + m.Length;
        if (dict[i] == '<')
        {
            int end = dict.IndexOf('>', i);
            return ParseString(dict.Substring(i, end - i + 1));
        }
        int close = SkipLiteral(dict, i);
        return ParseString(dict.Substring(i, close - i + 1));
    }

    /// <summary>Decodes a PDF literal "(...)" or hex "&lt;...&gt;" string into raw bytes.</summary>
    public static byte[] ParseString(string s)
    {
        s = s.Trim();
        if (s.StartsWith('<'))
        {
            var hex = new StringBuilder();
            foreach (char c in s.AsSpan(1, s.Length - 2)) if (Uri.IsHexDigit(c)) hex.Append(c);
            if (hex.Length % 2 == 1) hex.Append('0');
            return Convert.FromHexString(hex.ToString());
        }
        var r = new List<byte>();
        for (int i = 1; i < s.Length - 1; i++)
        {
            char c = s[i];
            if (c != '\\') { r.Add((byte)c); continue; }
            if (++i >= s.Length - 1) break;
            c = s[i];
            switch (c)
            {
                case 'n': r.Add(10); break;
                case 'r': r.Add(13); break;
                case 't': r.Add(9); break;
                case 'b': r.Add(8); break;
                case 'f': r.Add(12); break;
                case '\r': if (i + 1 < s.Length && s[i + 1] == '\n') i++; break;
                case '\n': break;
                default:
                    if (c is >= '0' and <= '7')
                    {
                        int val = 0, n = 0;
                        while (n < 3 && i < s.Length - 1 && s[i] is >= '0' and <= '7') { val = val * 8 + (s[i] - '0'); i++; n++; }
                        i--;
                        r.Add((byte)val);
                    }
                    else r.Add((byte)c);
                    break;
            }
        }
        return r.ToArray();
    }

    private static byte[] Pad(byte[] b, int len)
    {
        var r = new byte[len];
        Array.Copy(b, r, Math.Min(b.Length, len));
        return r;
    }

    [GeneratedRegex(@"%PDF-(\d\.\d)")] private static partial Regex PdfVersion();
    [GeneratedRegex(@"/Encrypt\s+(\d+)\s+(\d+)\s+R")] private static partial Regex EncryptRef();
    [GeneratedRegex(@"/ID\s*\[\s*(<[0-9A-Fa-f\s]*>|\((?:\\.|[^\\)])*\))")] private static partial Regex IdArray();
}
