namespace RecoverKit.Core.Formats;

// LZMA1 decoding adapted from Igor Pavlov's public-domain LZMA SDK 23.01.
// Metadata only: output is bounded by the caller, and distances refer to that output buffer.
internal static class SevenZipLzma
{
    public static byte[] Decode(byte[] input, byte[] properties, int size)
    {
        if (properties.Length != 5 || properties[0] >= 225 || size < 0 || size > 16 * 1024 * 1024)
            throw new FormatException("Invalid LZMA header properties.");
        int lc = properties[0] % 9, lp = properties[0] / 9 % 5, pb = properties[0] / 45;
        uint dictionary = Math.Max(1u, Bin.U32(properties, 1));
        var output = new byte[size];
        var models = new ushort[1846 + (0x300 << (lc + lp))];
        Array.Fill(models, (ushort)1024);
        var range = new Range(input);
        uint state = 0, rep0 = 0, rep1 = 0, rep2 = 0, rep3 = 0;
        int position = 0, posMask = (1 << pb) - 1, literalMask = (1 << lp) - 1;
        while (position < size)
        {
            int posState = position & posMask;
            if (range.Bit(models, (int)(state * 16) + posState) == 0)
            {
                byte previous = position == 0 ? (byte)0 : output[position - 1];
                int context = ((position & literalMask) << lc) + (previous >> (8 - lc));
                int start = 1846 + context * 0x300;
                uint symbol = 1;
                if (state >= 7)
                {
                    if (rep0 >= position) throw new FormatException("Invalid LZMA literal distance.");
                    byte match = output[position - (int)rep0 - 1];
                    do
                    {
                        uint matchBit = (uint)(match >> 7); match <<= 1;
                        uint bit = range.Bit(models, start + (int)(((1 + matchBit) << 8) + symbol));
                        symbol = (symbol << 1) | bit;
                        if (bit != matchBit) break;
                    } while (symbol < 256);
                }
                while (symbol < 256) symbol = (symbol << 1) | range.Bit(models, start + (int)symbol);
                output[position++] = (byte)symbol;
                state = state < 4 ? 0 : state < 10 ? state - 3 : state - 6;
                continue;
            }

            uint length;
            if (range.Bit(models, 192 + (int)state) != 0)
            {
                if (range.Bit(models, 204 + (int)state) == 0)
                {
                    if (range.Bit(models, 240 + (int)state * 16 + posState) == 0)
                    {
                        state = state < 7 ? 9u : 11u;
                        Copy(1); continue;
                    }
                }
                else
                {
                    uint distance;
                    if (range.Bit(models, 216 + (int)state) == 0) distance = rep1;
                    else
                    {
                        if (range.Bit(models, 228 + (int)state) == 0) distance = rep2;
                        else { distance = rep3; rep3 = rep2; }
                        rep2 = rep1;
                    }
                    rep1 = rep0; rep0 = distance;
                }
                length = range.Length(models, 1332, posState) + 2;
                state = state < 7 ? 8u : 11u;
            }
            else
            {
                rep3 = rep2; rep2 = rep1; rep1 = rep0;
                length = range.Length(models, 818, posState) + 2;
                state = state < 7 ? 7u : 10u;
                uint slot = range.Tree(models, 432 + (int)Math.Min(length - 2, 3) * 64, 6);
                rep0 = slot;
                if (slot >= 4)
                {
                    int bits = (int)(slot >> 1) - 1;
                    rep0 = (2 | (slot & 1)) << bits;
                    if (slot < 14) rep0 += range.Reverse(models, 688 + (int)(rep0 - slot - 1), bits);
                    else
                    {
                        rep0 += range.Direct(bits - 4) << 4;
                        rep0 += range.Reverse(models, 802, 4);
                    }
                }
            }
            Copy(length);
        }
        return output;

        void Copy(uint length)
        {
            if (rep0 >= position || rep0 >= dictionary || length > size - position)
                throw new FormatException("Invalid LZMA match or output size.");
            for (int i = 0; i < length; i++)
            {
                output[position] = output[position - (int)rep0 - 1];
                position++;
            }
        }
    }

    private sealed class Range
    {
        private readonly byte[] input;
        private int position;
        private uint code, range = uint.MaxValue;
        public Range(byte[] bytes)
        {
            input = bytes;
            if (Read() != 0) throw new FormatException("Invalid LZMA range header.");
            for (int i = 0; i < 4; i++) code = (code << 8) | Read();
        }
        private uint Read()
        {
            if (position == input.Length) throw new FormatException("Truncated LZMA header stream.");
            return input[position++];
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
