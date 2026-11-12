using System.IO.Compression;
using System.Text;
using RecoverKit.Core.Formats;
using Xunit;

namespace RecoverKit.Tests;

public class PdfDocumentTests
{
    [Fact]
    public void OlderHybridXrefCannotReviveNewlyFreedObject()
    {
        using var data = new MemoryStream();
        void Put(string s) => data.Write(Encoding.ASCII.GetBytes(s));
        Put("%PDF-1.7\n"); int obj = (int)data.Position; Put("5 0 obj\n42\nendobj\n");
        int stream = (int)data.Position;
        Put("6 0 obj\n<< /Type /XRef /Size 7 /W [1 4 2] /Index [5 1] /Length 7 >>\nstream\n");
        data.Write(new byte[] { 1, 0, 0, (byte)(obj >> 8), (byte)obj, 0, 0 }); Put("\nendstream\nendobj\n");
        int older = (int)data.Position;
        Put($"xref\n0 1\n0 65535 f\n5 1\n0 0 f\ntrailer\n<< /Root 1 0 R /XRefStm {stream} >>\n");
        int latest = (int)data.Position;
        Put($"xref\n5 1\n0 1 f\ntrailer\n<< /Root 1 0 R /Prev {older} >>\nstartxref\n{latest}\n%%EOF\n");
        var pdf = new PdfDocument(data.ToArray());
        Assert.DoesNotContain(5, pdf.ObjectNumbers);
        Assert.Throws<FormatException>(() => pdf.Get(5));
    }

    [Fact]
    public void HybridOffsetMustPointToAStream()
    {
        using var data = new MemoryStream();
        void Put(string s) => data.Write(Encoding.ASCII.GetBytes(s));
        Put("%PDF-1.7\n"); int old = (int)data.Position;
        Put("xref\n0 1\n0 65535 f\ntrailer\n<< /Root 1 0 R >>\n");
        int latest = (int)data.Position;
        Put($"xref\n0 1\n0 65535 f\ntrailer\n<< /Root 1 0 R /XRefStm {old} >>\nstartxref\n{latest}\n%%EOF\n");
        Assert.Throws<FormatException>(() => new PdfDocument(data.ToArray()));
    }

    [Fact]
    public void ManyCompressedObjectsDecodeTheirContainerOnlyOnce()
    {
        using var data = new MemoryStream();
        void Put(string s) => data.Write(Encoding.ASCII.GetBytes(s));
        const int count = 300;
        string header = string.Concat(Enumerable.Range(0, count).Select(i => $"{5 + i} {3 * i} "));
        var content = Encoding.ASCII.GetBytes(header + string.Concat(Enumerable.Repeat("42 ", count - 1)) + new string(' ', 1024 * 1024) + "42 ");
        using var encoded = new MemoryStream();
        using (var z = new ZLibStream(encoded, CompressionMode.Compress, true)) z.Write(content);
        Put("%PDF-1.7\n"); int obj = (int)data.Position;
        Put($"4 0 obj\n<< /Type /ObjStm /N {count} /First {header.Length} /Length {encoded.Length} /Filter /FlateDecode >>\nstream\n");
        data.Write(encoded.ToArray()); Put("\nendstream\nendobj\n");
        int xref = (int)data.Position;
        Put($"305 0 obj\n<< /Type /XRef /Root 1 0 R /Size 306 /W [1 4 2] /Index [4 301] /Length {301 * 7} >>\nstream\n");
        data.Write(new byte[] { 1, 0, 0, (byte)(obj >> 8), (byte)obj, 0, 0 });
        for (int i = 0; i < count; i++) data.Write(new byte[] { 2, 0, 0, 0, 4, (byte)(i >> 8), (byte)i });
        Put($"\nendstream\nendobj\nstartxref\n{xref}\n%%EOF\n");
        var pdf = new PdfDocument(data.ToArray());
        for (int i = 0; i < count; i++) Assert.Equal(42, Assert.IsType<PdfNumber>(pdf.Get(5 + i).Value).Integer);
    }

    [Fact]
    public void CyclicPrevIsRefused()
    {
        var bytes = "%PDF-1.7\nxref\n0 1\n0 65535 f\ntrailer\n<< /Root 1 0 R /Prev 9 >>\nstartxref\n9\n%%EOF\n"u8.ToArray();
        Assert.Throws<FormatException>(() => new PdfDocument(bytes));
    }
}
