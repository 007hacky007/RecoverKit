using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics;

namespace RecoverKit.Core.Native.Simd;

/// <summary>Helpers to move data between 8 per-lane byte buffers and word-major vectors.</summary>
internal static class Lanes
{
    public const int Count = 8;

    /// <summary>Builds 16 message words from 8 lanes of 64 bytes (lane l at <c>blocks[l*64..]</c>).</summary>
    public static void LoadBlock(ReadOnlySpan<byte> blocks, Span<Vector256<uint>> w, bool bigEndian)
    {
        Span<uint> tmp = stackalloc uint[Count];
        for (int k = 0; k < 16; k++)
        {
            for (int l = 0; l < Count; l++)
            {
                uint v = BinaryPrimitives.ReadUInt32LittleEndian(blocks.Slice(l * 64 + k * 4, 4));
                tmp[l] = bigEndian ? BinaryPrimitives.ReverseEndianness(v) : v;
            }
            w[k] = Vector256.Create((ReadOnlySpan<uint>)tmp);
        }
    }

    /// <summary>Writes the little-endian bytes of word <paramref name="v"/> for every lane.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static uint Lane(Vector256<uint> v, int lane) => v.GetElement(lane);

    /// <summary>Copies a 16-byte (MD5) or 20-byte (SHA-1) digest of one lane to bytes.</summary>
    public static void DigestLe(Span<byte> dst, int lane, params Vector256<uint>[] state)
    {
        for (int i = 0; i < state.Length && i * 4 < dst.Length; i++)
            BinaryPrimitives.WriteUInt32LittleEndian(dst[(i * 4)..], state[i].GetElement(lane));
    }

    public static void DigestBe(Span<byte> dst, int lane, params Vector256<uint>[] state)
    {
        for (int i = 0; i < state.Length && i * 4 < dst.Length; i++)
            BinaryPrimitives.WriteUInt32BigEndian(dst[(i * 4)..], state[i].GetElement(lane));
    }
}
