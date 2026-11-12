using System.Buffers.Binary;
using System.Text;
using System.Xml;

namespace RecoverKit.Core.Formats;

/// <summary>
/// Minimal Apple property-list reader: enough of the binary (bplist00) and XML formats to read the
/// top-level dictionary's string keys and their data / bool / integer / string values. Used by the
/// Apple backup extractor; not a general-purpose plist library.
/// </summary>
public static class Plist
{
    /// <summary>Parses the root dictionary of a plist. Values are byte[], bool, long, or string.</summary>
    public static Dictionary<string, object?> ParseRootDict(byte[] data)
    {
        if (data.Length >= 8 && Encoding.ASCII.GetString(data, 0, 6) == "bplist")
            return ParseBinary(data);
        return ParseXml(data);
    }

    // ---------------------------------------------------------------- binary

    private static Dictionary<string, object?> ParseBinary(byte[] d)
    {
        if (d.Length < 40) throw new FormatException("Binary plist is too short.");
        int trailer = d.Length - 32;
        int offsetSize = d[trailer + 6];
        int refSize = d[trailer + 7];
        long numObjects = (long)BinaryPrimitives.ReadUInt64BigEndian(d.AsSpan(trailer + 8, 8));
        long topObject = (long)BinaryPrimitives.ReadUInt64BigEndian(d.AsSpan(trailer + 16, 8));
        long offsetTableStart = (long)BinaryPrimitives.ReadUInt64BigEndian(d.AsSpan(trailer + 24, 8));
        if (numObjects <= 0 || numObjects > 10_000_000) throw new FormatException("Binary plist object count is invalid.");

        var offsets = new long[numObjects];
        for (long i = 0; i < numObjects; i++)
            offsets[i] = ReadSized(d, (int)(offsetTableStart + i * offsetSize), offsetSize);

        var ctx = new BCtx { D = d, Offsets = offsets, RefSize = refSize };
        try
        {
            if (ReadObject(ctx, topObject) is Dictionary<string, object?> root) return root;
            throw new FormatException("Binary plist root object is not a dictionary.");
        }
        catch (Exception ex) when (ex is IndexOutOfRangeException or ArgumentException or OverflowException)
        {
            throw new FormatException("Binary plist is malformed: " + ex.Message);
        }
    }

    private sealed class BCtx { public required byte[] D; public required long[] Offsets; public required int RefSize; }

    private static object? ReadObject(BCtx c, long index)
    {
        if (index < 0 || index >= c.Offsets.Length) throw new FormatException("Binary plist object reference out of range.");
        long po = c.Offsets[index];
        if (po < 0 || po >= c.D.Length) throw new FormatException("Binary plist object offset is out of range.");
        int p = (int)po;
        byte marker = c.D[p];
        int type = marker >> 4, info = marker & 0x0F;
        switch (type)
        {
            case 0x0:
                return info switch { 0x08 => false, 0x09 => true, _ => (object?)null };
            case 0x1: // integer
            {
                int len = 1 << info;
                return ReadSized(c.D, p + 1, len);
            }
            case 0x4: // data
            {
                var (len, start) = ReadLength(c, p, info);
                return c.D.AsSpan(start, len).ToArray();
            }
            case 0x5: // ASCII string
            {
                var (len, start) = ReadLength(c, p, info);
                return Encoding.ASCII.GetString(c.D, start, len);
            }
            case 0x6: // UTF-16BE string
            {
                var (len, start) = ReadLength(c, p, info);
                return Encoding.BigEndianUnicode.GetString(c.D, start, len * 2);
            }
            case 0xD: // dictionary
            {
                var (count, start) = ReadLength(c, p, info);
                var dict = new Dictionary<string, object?>();
                for (int i = 0; i < count; i++)
                {
                    long keyRef = ReadSized(c.D, start + i * c.RefSize, c.RefSize);
                    long valRef = ReadSized(c.D, start + (count + i) * c.RefSize, c.RefSize);
                    if (ReadObject(c, keyRef) is string key) dict[key] = ReadObject(c, valRef);
                }
                return dict;
            }
            default:
                return null; // arrays/reals/dates not needed here
        }
    }

    /// <summary>Returns (count, dataStart) for data/string/dict markers, handling the 0xF extended-length form.</summary>
    private static (int Count, int Start) ReadLength(BCtx c, int p, int info)
    {
        if (info != 0x0F) return (info, p + 1);
        if (p + 1 >= c.D.Length) throw new FormatException("Binary plist extended length is truncated.");
        byte sizeMarker = c.D[p + 1];
        if ((sizeMarker >> 4) != 0x1) throw new FormatException("Binary plist extended length is malformed.");
        int sizeLen = 1 << (sizeMarker & 0x0F);
        int count = (int)ReadSized(c.D, p + 2, sizeLen);
        return (count, p + 2 + sizeLen);
    }

    private static long ReadSized(byte[] d, int offset, int size)
    {
        if (offset < 0 || offset + size > d.Length) throw new FormatException("Binary plist read is out of range.");
        long v = 0;
        for (int i = 0; i < size; i++) v = (v << 8) | d[offset + i];
        return v;
    }

    // ---------------------------------------------------------------- xml

    private static Dictionary<string, object?> ParseXml(byte[] d)
    {
        var doc = new XmlDocument();
        var settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Ignore, XmlResolver = null };
        using var ms = new MemoryStream(d);
        using var reader = XmlReader.Create(ms, settings);
        doc.Load(reader);
        var dictNode = doc.SelectSingleNode("/plist/dict") ?? throw new FormatException("XML plist has no root dictionary.");
        var result = new Dictionary<string, object?>();
        XmlNode? key = null;
        foreach (XmlNode child in dictNode.ChildNodes)
        {
            if (child.NodeType != XmlNodeType.Element) continue;
            if (child.Name == "key") { key = child; continue; }
            if (key is null) continue;
            result[key.InnerText] = child.Name switch
            {
                "data" => Convert.FromBase64String(child.InnerText.Trim()),
                "true" => true,
                "false" => false,
                "integer" => long.TryParse(child.InnerText.Trim(), out var n) ? n : 0L,
                "string" or "real" => child.InnerText,
                _ => null,
            };
            key = null;
        }
        return result;
    }
}
