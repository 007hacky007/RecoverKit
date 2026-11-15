namespace RecoverKit.Core.Formats;

// LZMA1 decoding adapted from Igor Pavlov's public-domain LZMA SDK 23.01.
// LZMA2 controls follow his public-domain Lzma2Dec.c (2024-03-01).
internal static class SevenZipLzma
{
    public static byte[] Decode(byte[] input, byte[] properties, int size)
    {
        if (size < 0 || size > 16 * 1024 * 1024) throw new FormatException("Invalid LZMA header size.");
        using var source = new MemoryStream(input, writable: false);
        using var decoder = Open(source, properties, size, false);
        var output = new byte[size];
        try { decoder.ReadExactly(output); }
        catch (EndOfStreamException ex) { throw new FormatException("Truncated LZMA header stream.", ex); }
        return output;
    }

    internal static Stream Open(Stream input, byte[] properties, long size, bool lzma2, Buffers? buffers = null)
        => new Decoder(input, properties, size, lzma2, buffers ?? new Buffers());

    internal static uint DictionarySize(byte[] properties, bool lzma2)
    {
        if (!lzma2)
        {
            if (properties.Length != 5) throw new FormatException("Invalid LZMA properties.");
            return Math.Max(4096u, Bin.U32(properties, 1));
        }
        if (properties.Length != 1 || properties[0] > 40) throw new FormatException("Invalid LZMA2 properties.");
        int p = properties[0];
        return p == 40 ? uint.MaxValue : (uint)(2 | (p & 1)) << (p / 2 + 11);
    }

    internal sealed class Buffers
    {
        internal readonly List<byte[]> History = [];
        internal ushort[] Models = [];
    }

    private sealed class Decoder : Stream
    {
        private readonly Stream input;
        private readonly bool lzma2;
        private readonly long size;
        private readonly uint dictionary;
        // Allocate history pages only as output arrives, never a whole-file output buffer.
        private readonly Buffers buffers;
        private readonly List<byte[]> history;
        private ushort[] models = [];
        private Range? range;
        private uint state, rep0, rep1, rep2, rep3;
        private long position, dictionaryStart;
        private int lc, lp, pb, pending, chunkLeft;
        private bool uncompressed, needDictionary = true, needState = true, needProperties = true;
        private LimitedReadStream? chunk;

        public Decoder(Stream source, byte[] properties, long outputSize, bool isLzma2, Buffers scratch)
        {
            buffers = scratch; history = buffers.History;
            input = source; size = outputSize; lzma2 = isLzma2;
            if (size < 0) throw new FormatException("Invalid LZMA output size.");
            dictionary = DictionarySize(properties, lzma2);
            if (!lzma2)
            {
                Properties(properties[0]); ResetState();
                range = new Range(input);
            }
        }

        private void Properties(int p)
        {
            if (p >= 225) throw new FormatException("Invalid LZMA literal properties.");
            lc = p % 9; lp = p / 9 % 5; pb = p / 45;
            if (lzma2 && lc + lp > 4) throw new FormatException("Invalid LZMA2 literal properties.");
            int count = 1846 + (0x300 << (lc + lp));
            if (buffers.Models.Length < count) buffers.Models = new ushort[count];
            models = buffers.Models;
        }

        private void ResetState()
        {
            Array.Fill(models, (ushort)1024);
            state = rep0 = rep1 = rep2 = rep3 = 0;
            pending = 0;
        }

        private int Byte()
        {
            int b = input.ReadByte();
            if (b < 0) throw new EndOfStreamException("Truncated LZMA2 chunk.");
            return b;
        }

        private void NextChunk()
        {
            if (chunk is not null)
            {
                // Range coders may leave their final normalization bytes unread.
                while (chunk.ReadByte() >= 0) { }
                chunk = null;
            }
            int control = Byte();
            if (control == 0) throw new FormatException("LZMA2 stream ended before its declared output size.");
            if (control is 1 or 2)
            {
                if (control == 1)
                {
                    dictionaryStart = position; needDictionary = false;
                    needState = needProperties = true;
                }
                else if (needDictionary) throw new FormatException("Missing LZMA2 dictionary reset.");
                chunkLeft = (Byte() << 8 | Byte()) + 1;
                // Control 2 preserves the probabilities, repeats and literal properties.
                uncompressed = true;
            }
            else
            {
                if (control < 0x80) throw new FormatException("Invalid LZMA2 chunk control.");
                if (control >= 0xe0) { dictionaryStart = position; needDictionary = false; }
                if (needDictionary) throw new FormatException("Missing LZMA2 dictionary reset.");
                chunkLeft = ((control & 31) << 16 | Byte() << 8 | Byte()) + 1;
                int packed = (Byte() << 8 | Byte()) + 1;
                if (control >= 0xc0) { Properties(Byte()); needProperties = false; }
                if (needProperties) throw new FormatException("Missing LZMA2 properties.");
                if (control >= 0xa0) { ResetState(); needState = false; }
                if (needState) throw new FormatException("Missing LZMA2 state reset.");
                chunk = new LimitedReadStream(input, packed);
                range = new Range(chunk); uncompressed = false;
            }
        }

        private byte Previous(uint distance)
        {
            if (distance >= position - dictionaryStart || distance >= dictionary)
                throw new FormatException("Invalid LZMA match distance.");
            long index = (position - distance - 1) % dictionary;
            return history[(int)(index / 65536)][(int)(index % 65536)];
        }

        private void Emit(byte value)
        {
            long index = position % dictionary;
            if (index / 65536 == history.Count) history.Add(new byte[65536]);
            history[(int)(index / 65536)][(int)(index % 65536)] = value;
            position++;
            if (lzma2) chunkLeft--;
        }

        public override int Read(Span<byte> output)
        {
            int written = 0;
            while (written < output.Length && position < size)
            {
                if (lzma2 && chunkLeft == 0) NextChunk();
                byte value;
                if (lzma2 && uncompressed) value = (byte)Byte();
                else
                {
                    if (pending == 0)
                    {
                        int literal = Symbol();
                        if (literal >= 0) { value = (byte)literal; output[written++] = value; Emit(value); continue; }
                    }
                    value = Previous(rep0); pending--;
                }
                output[written++] = value; Emit(value);
            }
            return written;
        }

        // One symbol may straddle any caller's output buffer, including the trial-decode boundary.
        private int Symbol()
        {
            var r = range!;
            int pos = (int)((position - dictionaryStart) & ((1 << pb) - 1));
            if (r.Bit(models, (int)(state * 16) + pos) == 0)
            {
                byte previous = position == dictionaryStart ? (byte)0 : Previous(0);
                int context = (((int)(position - dictionaryStart) & ((1 << lp) - 1)) << lc) + (previous >> (8 - lc));
                int start = 1846 + context * 0x300;
                uint symbol = 1;
                if (state >= 7)
                {
                    byte match = Previous(rep0);
                    do
                    {
                        uint matchBit = (uint)(match >> 7); match <<= 1;
                        uint bit = r.Bit(models, start + (int)(((1 + matchBit) << 8) + symbol));
                        symbol = (symbol << 1) | bit;
                        if (bit != matchBit) break;
                    } while (symbol < 256);
                }
                while (symbol < 256) symbol = (symbol << 1) | r.Bit(models, start + (int)symbol);
                state = state < 4 ? 0 : state < 10 ? state - 3 : state - 6;
                return (byte)symbol;
            }
            uint length;
            if (r.Bit(models, 192 + (int)state) != 0)
            {
                if (r.Bit(models, 204 + (int)state) == 0)
                {
                    if (r.Bit(models, 240 + (int)state * 16 + pos) == 0)
                    { state = state < 7 ? 9u : 11u; pending = 1; return -1; }
                }
                else
                {
                    uint distance;
                    if (r.Bit(models, 216 + (int)state) == 0) distance = rep1;
                    else
                    {
                        if (r.Bit(models, 228 + (int)state) == 0) distance = rep2;
                        else { distance = rep3; rep3 = rep2; }
                        rep2 = rep1;
                    }
                    rep1 = rep0; rep0 = distance;
                }
                length = r.Length(models, 1332, pos) + 2;
                state = state < 7 ? 8u : 11u;
            }
            else
            {
                rep3 = rep2; rep2 = rep1; rep1 = rep0;
                length = r.Length(models, 818, pos) + 2;
                state = state < 7 ? 7u : 10u;
                uint slot = r.Tree(models, 432 + (int)Math.Min(length - 2, 3) * 64, 6);
                rep0 = slot;
                if (slot >= 4)
                {
                    int bits = (int)(slot >> 1) - 1;
                    rep0 = (2 | (slot & 1)) << bits;
                    if (slot < 14) rep0 += r.Reverse(models, 688 + (int)(rep0 - slot - 1), bits);
                    else { rep0 += r.Direct(bits - 4) << 4; rep0 += r.Reverse(models, 802, 4); }
                }
            }
            if (lzma2 && length > chunkLeft) throw new FormatException("LZMA match crosses a chunk boundary.");
            pending = (int)length;
            return -1;
        }

        public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => size;
        public override long Position { get => position; set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }

    private sealed class Range
    {
        private readonly Stream input;
        private uint code, range = uint.MaxValue;
        public Range(Stream bytes)
        {
            input = bytes;
            if (Read() != 0) throw new FormatException("Invalid LZMA range header.");
            for (int i = 0; i < 4; i++) code = (code << 8) | Read();
        }
        private uint Read()
        {
            int b = input.ReadByte();
            if (b < 0) throw new EndOfStreamException("Truncated LZMA stream.");
            return (uint)b;
        }
        private void Normalize()
        {
            if (range < (1 << 24)) { range <<= 8; code = (code << 8) | Read(); }
        }
        public uint Bit(ushort[] models, int index)
        {
            uint probability = models[index], bound = (range >> 11) * probability;
            uint bit;
            if (code < bound)
            {
                range = bound; models[index] = (ushort)(probability + ((2048 - probability) >> 5)); bit = 0;
            }
            else
            {
                range -= bound; code -= bound; models[index] = (ushort)(probability - (probability >> 5)); bit = 1;
            }
            Normalize(); return bit;
        }
        public uint Tree(ushort[] models, int start, int bits)
        {
            uint value = 1;
            for (int i = 0; i < bits; i++) value = (value << 1) | Bit(models, start + (int)value);
            return value - (1u << bits);
        }
        public uint Reverse(ushort[] models, int start, int bits)
        {
            uint value = 1, result = 0;
            for (int i = 0; i < bits; i++)
            {
                uint bit = Bit(models, start + (int)value);
                value = (value << 1) | bit; result |= bit << i;
            }
            return result;
        }
        public uint Direct(int bits)
        {
            uint result = 0;
            for (int i = 0; i < bits; i++)
            {
                range >>= 1;
                uint bit = code >= range ? 1u : 0u;
                if (bit != 0) code -= range;
                result = (result << 1) | bit; Normalize();
            }
            return result;
        }
        public uint Length(ushort[] models, int start, int posState)
        {
            if (Bit(models, start) == 0) return Tree(models, start + 2 + posState * 8, 3);
            if (Bit(models, start + 1) == 0) return 8 + Tree(models, start + 130 + posState * 8, 3);
            return 16 + Tree(models, start + 258, 8);
        }
    }
}
