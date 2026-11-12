using System.Globalization;
using System.Text;

namespace RecoverKit.Core.Attacks;

public enum WordlistEncoding { Utf8, Utf8Bom, Utf16Le, Utf16Be, Ansi }

/// <summary>Dictionary file helpers: encoding detection, line counting and word streaming.</summary>
public static class Wordlists
{
    static Wordlists() => Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);

    public static Encoding AnsiEncoding
    {
        get
        {
            try { return Encoding.GetEncoding(CultureInfo.CurrentCulture.TextInfo.ANSICodePage); }
            catch { return Encoding.Latin1; }
        }
    }

    public static WordlistEncoding Detect(string path)
    {
        using var s = File.OpenRead(path);
        var buf = new byte[64 * 1024];
        int n = s.Read(buf, 0, buf.Length);
        if (n >= 2 && buf[0] == 0xFF && buf[1] == 0xFE) return WordlistEncoding.Utf16Le;
        if (n >= 2 && buf[0] == 0xFE && buf[1] == 0xFF) return WordlistEncoding.Utf16Be;
        if (n >= 3 && buf[0] == 0xEF && buf[1] == 0xBB && buf[2] == 0xBF) return WordlistEncoding.Utf8Bom;
        // Trim a possibly cut multi-byte sequence at the end of the sample before validating.
        int end = n;
        while (end > 0 && end > n - 4 && (buf[end - 1] & 0xC0) == 0x80) end--;
        if (end > 0 && buf[end - 1] >= 0xC0) end--;
        try
        {
            new UTF8Encoding(false, true).GetCharCount(buf, 0, end);
            return WordlistEncoding.Utf8;
        }
        catch (DecoderFallbackException)
        {
            return WordlistEncoding.Ansi;
        }
    }

    /// <summary>True when hashcat can read the file directly (byte-oriented UTF-8/ASCII without BOM).</summary>
    public static bool HashcatCanReadDirectly(string path) => Detect(path) == WordlistEncoding.Utf8;

    public static Encoding EncodingFor(WordlistEncoding e) => e switch
    {
        WordlistEncoding.Utf16Le => Encoding.Unicode,
        WordlistEncoding.Utf16Be => Encoding.BigEndianUnicode,
        WordlistEncoding.Ansi => AnsiEncoding,
        _ => new UTF8Encoding(false),
    };

    public static long CountLines(string path, CancellationToken ct = default)
    {
        var enc = Detect(path);
        bool wide = enc is WordlistEncoding.Utf16Le or WordlistEncoding.Utf16Be;
        using var s = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 1 << 20);
        var buf = new byte[1 << 20];
        long lines = 0;
        int n;
        bool lastWasNewline = true;
        long total = 0;
        while ((n = s.Read(buf, 0, buf.Length)) > 0)
        {
            ct.ThrowIfCancellationRequested();
            total += n;
            if (!wide)
            {
                var span = buf.AsSpan(0, n);
                int c = span.Count((byte)'\n');
                lines += c;
                lastWasNewline = span[^1] == '\n';
            }
            else
            {
                for (int i = 0; i + 1 < n; i += 2)
                {
                    bool nl = enc == WordlistEncoding.Utf16Le ? buf[i] == '\n' && buf[i + 1] == 0 : buf[i] == 0 && buf[i + 1] == '\n';
                    if (nl) lines++;
                }
                lastWasNewline = n >= 2 && (enc == WordlistEncoding.Utf16Le ? buf[n - 2] == '\n' : buf[n - 1] == '\n');
            }
        }
        if (total > 0 && !lastWasNewline) lines++;
        return lines;
    }

    public static IEnumerable<string> ReadWords(string path, int minLen = 0, int maxLen = 0)
    {
        var enc = EncodingFor(Detect(path));
        using var r = new StreamReader(path, enc, detectEncodingFromByteOrderMarks: true, bufferSize: 1 << 20);
        string? line;
        while ((line = r.ReadLine()) is not null)
        {
            if (line.Length == 0) continue;
            int len = Charsets.RuneCount(line);
            if (minLen > 0 && len < minLen) continue;
            if (maxLen > 0 && len > maxLen) continue;
            yield return line;
        }
    }

    /// <summary>Counts non-empty, non-comment rule lines in a hashcat rule file.</summary>
    public static int CountRules(string path)
    {
        int n = 0;
        foreach (var l in File.ReadLines(path))
        {
            var t = l.TrimEnd('\r');
            if (t.Length == 0 || t.StartsWith('#')) continue;
            n++;
        }
        return Math.Max(n, 1);
    }
}
