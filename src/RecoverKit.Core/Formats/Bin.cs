using System.Buffers.Binary;

namespace RecoverKit.Core.Formats;

internal static class Bin
{
    public static ushort U16(byte[] b, int o) => BinaryPrimitives.ReadUInt16LittleEndian(b.AsSpan(o, 2));
    public static uint U32(byte[] b, int o) => BinaryPrimitives.ReadUInt32LittleEndian(b.AsSpan(o, 4));
    public static uint U32BE(byte[] b, int o) => BinaryPrimitives.ReadUInt32BigEndian(b.AsSpan(o, 4));
    public static ulong U64(byte[] b, int o) => BinaryPrimitives.ReadUInt64LittleEndian(b.AsSpan(o, 8));
    public static int I32(byte[] b, int o) => BinaryPrimitives.ReadInt32LittleEndian(b.AsSpan(o, 4));

    public static string Hex(ReadOnlySpan<byte> b) => Convert.ToHexString(b).ToLowerInvariant();
    public static string Hex(byte[] b, int o, int len) => Hex(b.AsSpan(o, len));

    public static byte[] Slice(byte[] b, int o, int len)
    {
        if (o < 0 || len < 0 || o + len > b.Length)
            throw new FormatException("Unexpected end of data.");
        return b.AsSpan(o, len).ToArray();
    }

    public static void Need(byte[] b, int o, int len)
    {
        if (o < 0 || len < 0 || (long)o + len > b.Length)
            throw new FormatException("Unexpected end of data.");
    }

    public static byte[] ReadAt(Stream s, long offset, int count)
    {
        if (offset < 0 || offset >= s.Length) throw new FormatException("Offset is outside of file.");
        s.Position = offset;
        var buf = new byte[(int)Math.Min(count, s.Length - offset)];
        s.ReadExactly(buf);
        return buf;
    }

    public static int IndexOf(byte[] hay, ReadOnlySpan<byte> needle, int start = 0)
    {
        if (start >= hay.Length) return -1;
        int i = hay.AsSpan(start).IndexOf(needle);
        return i < 0 ? -1 : i + start;
    }
}
