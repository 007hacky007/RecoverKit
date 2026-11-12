using System.Globalization;
using System.Text;

namespace RecoverKit.Core.Formats;

// Values retain byte strings and decoded names separately. Stream bytes never pass through a tokenizer.
internal abstract record PdfValue;
internal sealed record PdfNumber(string Text) : PdfValue
{
    public int Integer => int.TryParse(Text, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out int n)
        ? n : throw new FormatException("PDF integer is out of range.");
}
internal sealed record PdfName(string Text) : PdfValue;
internal sealed record PdfString(byte[] Bytes) : PdfValue;
internal sealed record PdfReference(int Number, int Generation) : PdfValue;
internal sealed record PdfKeyword(string Text) : PdfValue;
internal sealed record PdfArray(List<PdfValue> Items) : PdfValue;
internal sealed record PdfDictionary(Dictionary<string, PdfValue> Items) : PdfValue
{
    public PdfValue? Get(string key) => Items.GetValueOrDefault(key);
    public int Int(string key) => Get(key) is PdfNumber n ? n.Integer : throw new FormatException($"Missing PDF integer /{key}.");
    public string? Name(string key) => (Get(key) as PdfName)?.Text;
    public byte[] Bytes(string key) => Get(key) is PdfString s ? s.Bytes : throw new FormatException($"Missing PDF string /{key}.");
}
internal sealed record PdfObject(int Number, int Generation, PdfValue Value, byte[]? Stream);

internal sealed class PdfSyntax(byte[] data, int position = 0)
{
    public int Position { get; set; } = position;
    internal static bool White(byte c) => c is 0 or 9 or 10 or 12 or 13 or 32;
    private static bool Delimiter(byte c) => White(c) || c is (byte)'(' or (byte)')' or (byte)'<' or (byte)'>' or (byte)'[' or (byte)']' or (byte)'/' or (byte)'%';

    public void Skip()
    {
        while (Position < data.Length)
        {
            if (White(data[Position])) { Position++; continue; }
            if (data[Position] != '%') return;
            while (Position < data.Length && data[Position] is not (10 or 13)) Position++;
        }
    }

    public bool Take(string word)
    {
        Skip();
        var bytes = Encoding.ASCII.GetBytes(word);
        if (!data.AsSpan(Position).StartsWith(bytes)) return false;
        int end = Position + bytes.Length;
        if (end < data.Length && !Delimiter(data[end])) return false;
        Position = end;
        return true;
    }

    public void Require(string word)
    {
        if (!Take(word)) throw new FormatException($"Expected PDF token '{word}'.");
    }

    public int Integer()
    {
        Skip();
        string s = Token();
        if (!int.TryParse(s, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out int n))
            throw new FormatException("Invalid PDF integer.");
        return n;
    }

    private string Token()
    {
        int start = Position;
        while (Position < data.Length && !Delimiter(data[Position])) Position++;
        if (start == Position) throw new FormatException("Unexpected PDF delimiter or end of file.");
        if (Position - start > 256) throw new FormatException("PDF token is too long.");
        return Encoding.Latin1.GetString(data, start, Position - start);
    }

    public PdfValue Read(int depth = 0)
    {
        if (depth > 64) throw new FormatException("PDF nesting exceeds 64 levels.");
        Skip();
        if (Position >= data.Length) throw new FormatException("Truncated PDF value.");
        byte c = data[Position++];
        if (c == '/')
        {
            var name = new List<byte>();
            while (Position < data.Length && !Delimiter(data[Position]))
            {
                byte b = data[Position++];
                if (b == '#')
                {
                    if (Position + 2 > data.Length || !byte.TryParse(Encoding.ASCII.GetString(data, Position, 2), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out b))
                        throw new FormatException("Invalid PDF name escape.");
                    Position += 2;
                }
                name.Add(b);
            }
            return new PdfName(Encoding.Latin1.GetString(name.ToArray()));
        }
        if (c == '(')
        {
            var bytes = new List<byte>();
            int nesting = 1;
            while (Position < data.Length)
            {
                byte b = data[Position++];
                if (b == '\\')
                {
                    if (Position == data.Length) break;
                    b = data[Position++];
                    if (b == 13) { if (Position < data.Length && data[Position] == 10) Position++; continue; }
                    if (b == 10) continue;
                    if (b is >= (byte)'0' and <= (byte)'7')
                    {
                        int n = b - '0';
                        for (int i = 0; i < 2 && Position < data.Length && data[Position] is >= (byte)'0' and <= (byte)'7'; i++) n = n * 8 + data[Position++] - '0';
                        bytes.Add((byte)n); continue;
                    }
                    bytes.Add(b switch { (byte)'n' => 10, (byte)'r' => 13, (byte)'t' => 9, (byte)'b' => 8, (byte)'f' => 12, _ => b });
                    continue;
                }
                if (b == '(') { if (++nesting > 64) throw new FormatException("PDF string nesting is too deep."); }
                if (b == ')' && --nesting == 0) return new PdfString(bytes.ToArray());
                if (b == 13) { if (Position < data.Length && data[Position] == 10) Position++; b = 10; }
                bytes.Add(b);
            }
            throw new FormatException("Unterminated PDF string.");
        }
        if (c == '<')
        {
            if (Position < data.Length && data[Position] == '<')
            {
                Position++;
                var dict = new Dictionary<string, PdfValue>(StringComparer.Ordinal);
                while (true)
                {
                    Skip();
                    if (Position + 1 < data.Length && data[Position] == '>' && data[Position + 1] == '>') { Position += 2; break; }
                    if (Read(depth + 1) is not PdfName key) throw new FormatException("PDF dictionary key is not a name.");
                    var value = Read(depth + 1);
                    if (!dict.TryAdd(key.Text, value)) throw new FormatException("Duplicate PDF dictionary key.");
                }
                return new PdfDictionary(dict);
            }
            var hex = new StringBuilder();
            while (Position < data.Length && data[Position] != '>')
            {
                byte b = data[Position++];
                if (White(b)) continue;
                if (!Uri.IsHexDigit((char)b)) throw new FormatException("Invalid PDF hexadecimal string.");
                hex.Append((char)b);
            }
            if (Position == data.Length) throw new FormatException("Unterminated PDF hexadecimal string.");
            Position++;
            if (hex.Length % 2 != 0) hex.Append('0');
            return new PdfString(Convert.FromHexString(hex.ToString()));
        }
        if (c == '[')
        {
            var items = new List<PdfValue>();
            while (true)
            {
                Skip();
                if (Position < data.Length && data[Position] == ']') { Position++; return new PdfArray(items); }
                items.Add(Read(depth + 1));
                if (items.Count > PdfDocument.MaxObjects) throw new FormatException("PDF array is too large.");
            }
        }
        Position--;
        string token = Token();
        if (token is "true" or "false" or "null") return new PdfKeyword(token);
        if (!decimal.TryParse(token, NumberStyles.AllowLeadingSign | NumberStyles.AllowDecimalPoint, CultureInfo.InvariantCulture, out _))
            throw new FormatException("Invalid PDF value.");
        var number = new PdfNumber(token);
        int saved = Position;
        Skip();
        if (Position < data.Length && data[Position] is >= (byte)'0' and <= (byte)'9' && int.TryParse(token, out int id))
        {
            string generation = Token();
            if (int.TryParse(generation, NumberStyles.None, CultureInfo.InvariantCulture, out int gen) && Take("R"))
            {
                if (id <= 0 || id >= PdfDocument.MaxObjects || gen is < 0 or > 65535) throw new FormatException("Invalid PDF reference.");
                return new PdfReference(id, gen);
            }
        }
        Position = saved;
        return number;
    }

}
