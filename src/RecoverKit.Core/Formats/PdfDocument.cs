using System.IO.Compression;
using System.Text;
using System.Text.RegularExpressions;

namespace RecoverKit.Core.Formats;

internal sealed class PdfDocument
{
    internal const int MaxObjects = 1_000_000;
    internal const int MaxBytes = 256 * 1024 * 1024;
    private readonly byte[] data;
    private readonly Dictionary<int, Entry> entries = new();
    private readonly Dictionary<int, PdfObject> objects = new();
    private readonly HashSet<int> loading = new();
    private readonly HashSet<int> xrefs = new();
    private long decodedBytes;
    private readonly Dictionary<int, ObjectStream> objectStreams = new();
    private sealed record ObjectStream(byte[] Data, int First, int[] Numbers, int[] Offsets);
    public string Version { get; }
    private sealed record Entry(int Type, int Offset, int Generation);
    public PdfDictionary Trailer { get; } = new(new(StringComparer.Ordinal));
    public Func<PdfObject, PdfObject>? Decrypt { get; set; }
    public IEnumerable<int> ObjectNumbers => entries.Where(p => p.Value.Type != 0).Select(p => p.Key).Order();

    public PdfDocument(byte[] bytes)
    {
        data = bytes;
        var version = Regex.Match(Encoding.Latin1.GetString(bytes, 0, Math.Min(bytes.Length, 1024)), @"%PDF-(1\.[0-7]|2\.0)");
        if (!version.Success) throw new FormatException("Unsupported or missing PDF version.");
        Version = version.Groups[1].Value;
        if (data.Length > MaxBytes) throw new UnsupportedFormatException("PDF permission removal supports files up to 256 MiB.");
        string tail = Encoding.Latin1.GetString(data, Math.Max(0, data.Length - 4096), Math.Min(data.Length, 4096));
        var end = Regex.Match(tail, @"startxref\s+(\d+)\s+%%EOF\s*$", RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1));
        if (!end.Success || !int.TryParse(end.Groups[1].Value, out int offset)) throw new FormatException("PDF has no valid final startxref/EOF.");
        int sections = 0;
        while (true)
        {
            if (++sections > 128 || xrefs.Count >= 128 || !xrefs.Add(offset)) throw new FormatException("PDF cross-reference chain is cyclic or too long.");
            var section = new Dictionary<int, Entry>();
            var trailer = ReadXref(offset, section, false);
            foreach (var pair in section) entries.TryAdd(pair.Key, pair.Value);
            foreach (var pair in trailer.Items) Trailer.Items.TryAdd(pair.Key, pair.Value);
            if (trailer.Get("Prev") is null) break;
            offset = trailer.Int("Prev");
        }
        if (Trailer.Get("Root") is not PdfReference) throw new FormatException("PDF trailer has no catalog reference.");
    }

    private PdfDictionary ReadXref(int offset, Dictionary<int, Entry> section, bool hybrid)
    {
        CheckOffset(offset);
        var p = new PdfSyntax(data, offset);
        PdfDictionary trailer;
        if (p.Take("xref"))
        {
            if (hybrid) throw new FormatException("PDF XRefStm must point to a cross-reference stream.");
            while (true)
            {
                if (p.Take("trailer")) break;
                int start = p.Integer(), count = p.Integer();
                CheckRange(start, count);
                for (int i = 0; i < count; i++)
                {
                    int pos = p.Integer(), gen = p.Integer();
                    int type = p.Take("n") ? 1 : p.Take("f") ? 0 : throw new FormatException("Invalid PDF xref entry.");
                    if (pos < 0 || gen is < 0 or > 65535) throw new FormatException("Invalid PDF xref offset or generation.");
                    section.TryAdd(start + i, new(type, pos, gen));
                }
            }
            trailer = p.Read() as PdfDictionary ?? throw new FormatException("Invalid PDF trailer.");
            if (trailer.Get("XRefStm") is not null)
            {
                int extra = trailer.Int("XRefStm");
                if (xrefs.Count >= 128 || !xrefs.Add(extra)) throw new FormatException("Cyclic hybrid PDF xref.");
                ReadXref(extra, section, true);
            }
        }
        else
        {
            var obj = ReadIndirect(offset, null);
            trailer = obj.Value as PdfDictionary ?? throw new FormatException("Invalid PDF xref stream dictionary.");
            if (trailer.Name("Type") != "XRef" || obj.Stream is null) throw new FormatException("startxref does not point to an xref table or stream.");
            var bytes = Decode(obj.Stream, trailer);
            var widths = IntArray(trailer.Get("W"));
            if (widths.Length != 3 || widths.Any(w => w is < 0 or > 4) || widths.Sum() == 0) throw new FormatException("Unsupported PDF xref field widths.");
            int size = trailer.Int("Size");
            CheckRange(0, size);
            var ranges = trailer.Get("Index") is { } index ? IntArray(index) : [0, size];
            if (ranges.Length % 2 != 0) throw new FormatException("Invalid PDF xref Index.");
            int cursor = 0;
            for (int j = 0; j < ranges.Length; j += 2)
            {
                int start = ranges[j], count = ranges[j + 1];
                CheckRange(start, count);
                for (int i = 0; i < count; i++)
                {
                    int[] f = new int[3];
                    for (int k = 0; k < 3; k++)
                    {
                        long n = k == 0 && widths[0] == 0 ? 1 : 0;
                        for (int b = 0; b < widths[k]; b++)
                        {
                            if (cursor >= bytes.Length) throw new FormatException("Truncated PDF xref stream.");
                            n = (n << 8) | bytes[cursor++];
                        }
                        if (n > int.MaxValue) throw new FormatException("PDF xref field is out of range.");
                        f[k] = (int)n;
                    }
                    if (f[0] is < 0 or > 2 || f[0] != 2 && f[2] > 65535) throw new FormatException("Unsupported PDF xref entry.");
                    var entry = new Entry(f[0], f[1], f[2]);
                    if (hybrid && section.TryGetValue(start + i, out var old) && old.Type == 0) section[start + i] = entry;
                    else section.TryAdd(start + i, entry);
                }
            }
            if (cursor != bytes.Length) throw new FormatException("PDF xref stream length does not match its index.");
        }
        return trailer;
    }

    public PdfValue? Resolve(PdfValue? value)
    {
        var seen = new HashSet<int>();
        while (value is PdfReference r)
        {
            if (seen.Count >= 64 || !seen.Add(r.Number)) throw new FormatException("Cyclic PDF indirect value.");
            var obj = Get(r.Number);
            if (obj.Generation != r.Generation) throw new FormatException("PDF reference generation does not match.");
            value = obj.Value;
        }
        return value;
    }

    public PdfObject Get(int number)
    {
        if (objects.TryGetValue(number, out var cached)) return cached;
        if (loading.Count >= 64 || !loading.Add(number)) throw new FormatException("Cyclic PDF object dependency.");
        try
        {
            if (!entries.TryGetValue(number, out var e) || e.Type == 0) throw new FormatException($"PDF references missing object {number}.");
            PdfObject obj;
            if (e.Type == 1)
            {
                obj = ReadIndirect(e.Offset, number);
                if (obj.Generation != e.Generation) throw new FormatException("PDF xref generation does not match object.");
                if (Decrypt is not null) obj = Decrypt(obj);
            }
            else
            {
                if (!objectStreams.TryGetValue(e.Offset, out var compressed))
                {
                    var container = Get(e.Offset);
                    if (container.Value is not PdfDictionary dict || dict.Name("Type") != "ObjStm" || container.Stream is null)
                        throw new FormatException("PDF compressed object has no object stream.");
                    int count = dict.Int("N"), first = dict.Int("First");
                    if (count is < 1 or > MaxObjects) throw new FormatException("Invalid PDF object stream count.");
                    var content = Decode(container.Stream, dict);
                    if (first < 0 || first > content.Length) throw new FormatException("Invalid PDF object stream First offset.");
                    var header = new PdfSyntax(content);
                    var ids = new HashSet<int>();
                    var numbers = new int[count]; var offsets = new int[count + 1];
                    int previous = -1;
                    for (int i = 0; i < count; i++)
                    {
                        int id = header.Integer(), off = header.Integer();
                        if (id <= 0 || id >= MaxObjects || !ids.Add(id) || off <= previous || off >= content.Length - first)
                            throw new FormatException("Invalid PDF object stream header.");
                        previous = off; numbers[i] = id; offsets[i] = off;
                    }
                    header.Skip();
                    if (header.Position != first) throw new FormatException("PDF object stream header length does not match First.");
                    offsets[count] = content.Length - first;
                    compressed = new(content, first, numbers, offsets);
                    objectStreams.Add(e.Offset, compressed);
                }
                if (e.Generation >= compressed.Numbers.Length || compressed.Numbers[e.Generation] != number)
                    throw new FormatException("PDF object stream index does not match object number.");
                int start = compressed.First + compressed.Offsets[e.Generation];
                int length = compressed.Offsets[e.Generation + 1] - compressed.Offsets[e.Generation];
                var parser = new PdfSyntax(compressed.Data.AsSpan(start, length).ToArray());
                var value = parser.Read();
                parser.Skip();
                if (parser.Position != length) throw new FormatException("Invalid PDF compressed object boundary.");
                obj = new(number, 0, value, null); // Strings inside object streams are already decrypted with the stream.
            }
            objects[number] = obj;
            return obj;
        }
        finally { loading.Remove(number); }
    }

    private PdfObject ReadIndirect(int offset, int? expected)
    {
        CheckOffset(offset);
        var p = new PdfSyntax(data, offset);
        int number = p.Integer(), gen = p.Integer();
        if (number <= 0 || number >= MaxObjects || gen is < 0 or > 65535 || expected is not null && number != expected)
            throw new FormatException("PDF object header does not match xref.");
        p.Require("obj");
        var value = p.Read();
        byte[]? stream = null;
        if (p.Take("stream"))
        {
            if (value is not PdfDictionary dict) throw new FormatException("PDF stream has no dictionary.");
            int pos = p.Position;
            if (pos < data.Length && data[pos] == 13) pos++;
            else if (pos >= data.Length || data[pos] != 10) throw new FormatException("PDF stream has no line break.");
            if (pos < data.Length && data[pos] == 10) pos++;
            var len = Resolve(dict.Get("Length")) as PdfNumber ?? throw new FormatException("PDF stream has no valid Length.");
            int length = len.Integer;
            if (length < 0 || length > data.Length - pos) throw new FormatException("Truncated PDF stream.");
            stream = data.AsSpan(pos, length).ToArray();
            p.Position = pos + length;
            p.Require("endstream");
        }
        p.Require("endobj");
        return new(number, gen, value, stream);
    }

    public byte[] Decode(byte[] bytes, PdfDictionary dict)
    {
        var filter = Resolve(dict.Get("Filter"));
        var filters = filter is PdfArray a ? a.Items : filter is null ? [] : new List<PdfValue> { filter };
        var parameters = Resolve(dict.Get("DecodeParms"));
        for (int i = 0; i < filters.Count; i++)
        {
            string name = (Resolve(filters[i]) as PdfName)?.Text ?? throw new FormatException("Invalid PDF stream filter.");
            var param = Resolve(parameters is PdfArray pa ? i < pa.Items.Count ? pa.Items[i] : null : parameters) as PdfDictionary;
            if (name is "FlateDecode" or "Fl")
            {
                using var input = new MemoryStream(bytes);
                using var z = new ZLibStream(input, CompressionMode.Decompress);
                using var output = new MemoryStream();
                var buffer = new byte[8192];
                int n;
                while ((n = z.Read(buffer)) > 0)
                {
                    if (output.Length + n > MaxBytes || decodedBytes + n > MaxBytes) throw new FormatException("PDF decoded data exceeds 256 MiB.");
                    output.Write(buffer, 0, n); decodedBytes += n;
                }
                bytes = UndoPredictor(output.ToArray(), param);
            }
            else if (name is "ASCIIHexDecode" or "AHx")
            {
                int end = Array.IndexOf(bytes, (byte)'>');
                if (end < 0) throw new FormatException("Unterminated PDF ASCIIHex stream.");
                bytes = ((PdfString)new PdfSyntax(Encoding.Latin1.GetBytes("<" + Encoding.Latin1.GetString(bytes, 0, end) + "> ")).Read()).Bytes;
            }
            else throw new UnsupportedFormatException($"PDF structural stream filter /{name} is not supported; no copy was written.");
        }
        return bytes;
    }

    private static byte[] UndoPredictor(byte[] bytes, PdfDictionary? p)
    {
        int predictor = p?.Get("Predictor") is PdfNumber n ? n.Integer : 1;
        if (predictor == 1) return bytes;
        int colors = p?.Get("Colors") is PdfNumber c ? c.Integer : 1;
        int bits = p?.Get("BitsPerComponent") is PdfNumber b ? b.Integer : 8;
        int columns = p?.Get("Columns") is PdfNumber col ? col.Integer : 1;
        if (colors <= 0 || columns <= 0 || bits != 8 || (long)colors * columns > MaxBytes)
            throw new UnsupportedFormatException("Unsupported PDF structural stream predictor dimensions.");
        int row = colors * columns;
        if (predictor == 2)
        {
            if (bytes.Length % row != 0) throw new FormatException("Truncated TIFF predictor row.");
            for (int i = 0; i < bytes.Length; i++) if (i % row >= colors) bytes[i] += bytes[i - colors];
            return bytes;
        }
        if (predictor is < 10 or > 15) throw new UnsupportedFormatException("Unsupported PDF structural stream predictor.");
        if (bytes.Length % (row + 1) != 0) throw new FormatException("Truncated PNG predictor row.");
        var result = new byte[bytes.Length / (row + 1) * row];
        int src = 0, dst = 0;
        while (src < bytes.Length)
        {
            int filter = bytes[src++];
            if (filter > 4) throw new FormatException("Invalid PNG predictor filter.");
            for (int x = 0; x < row; x++, dst++)
            {
                int left = x >= colors ? result[dst - colors] : 0;
                int up = dst >= row ? result[dst - row] : 0;
                int ul = dst >= row && x >= colors ? result[dst - row - colors] : 0;
                int estimate = left + up - ul;
                int a = Math.Abs(estimate - left), b2 = Math.Abs(estimate - up), c2 = Math.Abs(estimate - ul);
                int paeth = a <= b2 && a <= c2 ? left : b2 <= c2 ? up : ul;
                result[dst] = (byte)(bytes[src++] + (filter switch { 0 => 0, 1 => left, 2 => up, 3 => (left + up) / 2, _ => paeth }));
            }
        }
        return result;
    }

    private static int[] IntArray(PdfValue? value) => value is PdfArray a && a.Items.All(v => v is PdfNumber)
        ? a.Items.Cast<PdfNumber>().Select(n => n.Integer).ToArray() : throw new FormatException("Invalid PDF integer array.");
    private void CheckOffset(int offset) { if (offset < 0 || offset >= data.Length) throw new FormatException("PDF xref offset is outside the file."); }
    private static void CheckRange(int start, int count)
    {
        if (start < 0 || count < 0 || start >= MaxObjects || count > MaxObjects - start) throw new FormatException("PDF object count exceeds the supported limit.");
    }
}
