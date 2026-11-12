using System.Globalization;
using System.Text;

namespace RecoverKit.Core.Formats;

internal static class PdfWriter
{
    public static void Write(PdfDocument document, Stream output, CancellationToken ct)
    {
        var excluded = new HashSet<int>();
        if (document.Trailer.Get("Encrypt") is PdfReference encrypt) excluded.Add(encrypt.Number);
        var objects = new List<PdfObject>();
        foreach (int id in document.ObjectNumbers)
        {
            ct.ThrowIfCancellationRequested();
            if (excluded.Contains(id)) continue;
            var obj = document.Get(id);
            if (obj.Value is PdfDictionary dict)
            {
                string? type = dict.Name("Type");
                if (type is "XRef" or "ObjStm") { excluded.Add(id); continue; }
                if (type == "Sig" || dict.Name("FT") == "Sig" || dict.Get("ByteRange") is not null)
                    throw new UnsupportedFormatException("Signed PDFs cannot be rewritten without invalidating their signatures; no copy was written.");
                if (type == "Catalog" && dict.Get("Perms") is not null)
                    throw new UnsupportedFormatException("PDF certification permissions cannot be preserved by a full rewrite.");
            }
            objects.Add(obj);
        }
        var available = objects.ToDictionary(o => o.Number, o => o.Generation);
        void Check(PdfValue value)
        {
            switch (value)
            {
                case PdfReference r:
                    if (!available.TryGetValue(r.Number, out int gen) || gen != r.Generation) throw new FormatException($"PDF references unavailable object {r.Number}; no copy was written.");
                    break;
                case PdfArray a: foreach (var item in a.Items) Check(item); break;
                case PdfDictionary d: foreach (var item in d.Items.Values) Check(item); break;
            }
        }
        var trailer = new PdfDictionary(document.Trailer.Items.Where(p => p.Key is "Root" or "Info" or "ID").ToDictionary(p => p.Key, p => p.Value, StringComparer.Ordinal));
        foreach (var obj in objects) Check(obj.Value);
        Check(trailer);
        if (document.Resolve(trailer.Get("Root")) is not PdfDictionary root || root.Name("Type") != "Catalog" || root.Get("Pages") is not PdfReference)
            throw new FormatException("PDF catalog or page tree is missing.");
        void Text(string text)
        {
            if (output.Position + text.Length > PdfDocument.MaxBytes) throw new FormatException("Rewritten PDF exceeds 256 MiB.");
            output.Write(Encoding.Latin1.GetBytes(text));
        }
        void Value(PdfValue value)
        {
            switch (value)
            {
                case PdfNumber n: Text(n.Text); break;
                case PdfKeyword k: Text(k.Text); break;
                case PdfName n:
                    Text("/");
                    foreach (byte b in Encoding.Latin1.GetBytes(n.Text)) Text(b is >= 33 and <= 126 && b is not (35 or 37 or 40 or 41 or 47 or 60 or 62 or 91 or 93 or 123 or 125) ? ((char)b).ToString() : "#" + b.ToString("X2", CultureInfo.InvariantCulture));
                    break;
                case PdfString s: Text("<" + Convert.ToHexString(s.Bytes) + ">"); break;
                case PdfReference r: Text($"{r.Number} {r.Generation} R"); break;
                case PdfArray a:
                    Text("["); foreach (var item in a.Items) { Value(item); Text(" "); } Text("]"); break;
                case PdfDictionary d:
                    Text("<<"); foreach (var pair in d.Items) { Text("\n"); Value(new PdfName(pair.Key)); Text(" "); Value(pair.Value); } Text("\n>>"); break;
                default: throw new FormatException("Unknown PDF value.");
            }
        }
        Text($"%PDF-{document.Version}\n%\xe2\xe3\xcf\xd3\n");
        var offsets = new Dictionary<int, long>();
        foreach (var obj in objects)
        {
            ct.ThrowIfCancellationRequested();
            offsets[obj.Number] = output.Position;
            Text($"{obj.Number} {obj.Generation} obj\n"); Value(obj.Value);
            if (obj.Stream is { } stream)
            {
                Text("\nstream\n");
                if (output.Position + stream.Length > PdfDocument.MaxBytes) throw new FormatException("Rewritten PDF exceeds 256 MiB.");
                output.Write(stream); Text("\nendstream");
            }
            Text("\nendobj\n");
        }
        int size = available.Keys.Max() + 1;
        long xref = output.Position;
        Text($"xref\n0 {size}\n");
        // Link all free entries so independent validators see a complete free list.
        var free = Enumerable.Range(1, size - 1).Where(i => !available.ContainsKey(i)).Append(0).ToArray();
        Text($"{free[0]:D10} 65535 f \n");
        int freeIndex = 0;
        for (int i = 1; i < size; i++)
        {
            if (available.TryGetValue(i, out int gen)) Text($"{offsets[i]:D10} {gen:D5} n \n");
            else Text($"{free[++freeIndex]:D10} 00000 f \n");
        }
        trailer.Items["Size"] = new PdfNumber(size.ToString(CultureInfo.InvariantCulture));
        Text("trailer\n"); Value(trailer); Text($"\nstartxref\n{xref}\n%%EOF\n");
    }
}
