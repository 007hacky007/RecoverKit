namespace RecoverKit.Core.Formats;

/// <summary>7z streams and AES properties, serialized for hashcat 7.1.2 mode 11600.</summary>
public static class SevenZipExtractor
{
    private static ReadOnlySpan<byte> Signature => [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c];
    private const int HeaderLimit = 16 * 1024 * 1024;
    internal const ulong DataLimit = 8 * 1024 * 1024;
    internal const ulong CrcLimit = 9_999_999;
    private const string AesId = "06f10701";
    private static readonly uint[] CrcTable = Enumerable.Range(0, 256).Select(i =>
    {
        uint c = (uint)i;
        for (int j = 0; j < 8; j++) c = (c >> 1) ^ ((c & 1) != 0 ? 0xedb88320u : 0);
        return c;
    }).ToArray();

    public static bool IsSevenZip(ReadOnlySpan<byte> head) => head.StartsWith(Signature);

    public static long FindSignature(Stream s)
        => Bin.IndexOf(Bin.ReadAt(s, 0, (int)Math.Min(s.Length, 4 * 1024 * 1024)), Signature);

    public static void Extract(Stream s, Detection d)
    {
        d.TypeName = "7-Zip archive";
        // A split stream has no volume flag: its numbered filename is the only reliable hint.
        if (System.Text.RegularExpressions.Regex.IsMatch(d.FilePath, @"\.7z\.\d{3,}$", System.Text.RegularExpressions.RegexOptions.IgnoreCase))
            throw new UnsupportedFormatException("Multi-volume 7z archives are not supported. Join all .7z.001, .002, ... parts in order, then open the combined .7z file.");
        long offset = FindSignature(s);
        if (offset < 0) throw new FormatException("7z signature not found.");
        if (offset > 0) d.Add("Self-extracting prefix", $"{offset:N0} bytes");
        var start = Read(s, (ulong)offset, 32);
        if (start[6] != 0) throw new UnsupportedFormatException("Unsupported 7z major version.");
        CheckCrc(start.AsSpan(12), Bin.U32(start, 8));
        ulong dataBase = (ulong)offset + 32;
        ulong nextOffset = Bin.U64(start, 12), nextSize = Bin.U64(start, 20);
        if (nextSize == 0) { d.Message = "Archive is empty and not password protected."; return; }
        if (nextSize > HeaderLimit) throw new UnsupportedFormatException("7z metadata exceeds the 16 MiB parsing limit.");
        if (nextOffset > (ulong)s.Length - dataBase) throw new FormatException("7z end header is outside the file (possibly an incomplete multi-volume archive).");
        ulong headerStart = dataBase + nextOffset;
        byte[] header = Read(s, headerStart, nextSize);
        CheckCrc(header, Bin.U32(start, 28));

        for (int depth = 0; depth < 4; depth++)
        {
            var r = new Reader(header);
            int type = r.Byte();
            if (type == 0x17)
            {
                var streams = Streams(r);
                ValidateRanges(streams, dataBase, headerStart);
                if (streams.Folders.Any(f => f.Coders.Any(c => c.Id == AesId)))
                {
                    d.Add("Encrypted file names", "yes");
                    SetTarget(s, streams, dataBase, d, true);
                    return;
                }
                header = DecodeHeader(s, streams, dataBase);
                continue;
            }
            if (type != 1) throw new FormatException("Expected a 7z header.");
            StreamsInfo? main = null;
            for (int id; (id = r.Byte()) != 0;)
            {
                switch (id)
                {
                    case 2: SkipProperties(r); break;
                    case 3: Streams(r); break;
                    case 4: main = Streams(r); break;
                    case 5: r.Count(); SkipProperties(r); break;
                    default: throw new FormatException("Unknown 7z header property.");
                }
            }
            d.Add("Encrypted file names", "no");
            if (main is null) d.Message = "Archive is not password protected (no encrypted data streams).";
            else
            {
                ValidateRanges(main, dataBase, headerStart);
                SetTarget(s, main, dataBase, d, false);
            }
            return;
        }
        throw new FormatException("Too many nested 7z headers.");
    }

    private static void SetTarget(Stream s, StreamsInfo info, ulong dataBase, Detection d, bool encryptedHeader)
    {
        Candidate? best = null;
        bool encrypted = false;
        var reasons = new HashSet<string>();
        foreach (var f in info.Folders)
        {
            if (!f.Coders.Any(c => c.Id == AesId)) continue;
            encrypted = true;
            var chain = f.Chain();
            if (chain is null || chain.Count == 0 || chain[0].Id != AesId || chain.Count > 2)
            { reasons.Add("filter chains or multiple packed streams"); continue; }
            var aes = chain[0];
            var props = AesProperties(aes.Properties);
            if (props.Salt.Length != 0) { reasons.Add("salted AES (hashcat requires an empty salt)"); continue; }
            if (props.Power > 24) { reasons.Add("NumCyclesPower above 24 (including direct-key mode)"); continue; }
            int type = 0;
            byte[] attributes = [];
            if (chain.Count == 2)
            {
                var c = chain[1];
                type = c.Id switch { "00" => 0, "030101" => 1, "21" => 2, "040108" => 7, _ => -1 };
                attributes = c.Properties;
                if (type < 0) { reasons.Add($"compression method {c.Id} (PPMd/BZip2 and other methods are unsupported)"); continue; }
                if ((type == 1 && (attributes.Length != 5 || attributes[0] >= 225)) ||
                    (type == 2 && (attributes.Length != 1 || attributes[0] > 40)) ||
                    (type is 0 or 7 && attributes.Length != 0))
                    throw new FormatException("Invalid 7z compression properties.");
            }
            ulong packed = info.Sizes[f.PackIndex], unpacked = f.UnpackSizes[aes.Output];
            if (packed == 0 || packed % 16 != 0 || unpacked == 0 || unpacked > packed || packed - unpacked > 15)
                throw new FormatException("Invalid AES stream sizes.");
            if (packed > DataLimit) { reasons.Add("encrypted streams larger than hashcat's 8 MiB limit"); continue; }
            ulong crcLength = f.FinalSize;
            uint? crc = f.Crc;
            if (f.SubSizes.Count > 0 && f.SubCrcs[0].HasValue && f.SubSizes[0] > 0 &&
                (!crc.HasValue || f.SubSizes[0] < crcLength))
            { crc = f.SubCrcs[0]; crcLength = f.SubSizes[0]; }
            if (!crc.HasValue || crcLength == 0) { reasons.Add("streams without a usable CRC"); continue; }
            if (type != 0 && crcLength > CrcLimit) { reasons.Add("CRC data larger than hashcat's 9,999,999-byte limit"); continue; }
            // The tokenizer includes the CRC-length/properties suffix in its 16 MiB hex-data field.
            if (type != 0 && packed == DataLimit)
            { reasons.Add("compressed data at hashcat's 8 MiB token limit (no room for compression properties)"); continue; }
            if (type == 0 && crcLength > unpacked) throw new FormatException("Invalid uncompressed CRC length.");
            var candidate = new Candidate(f, props, type, attributes, packed, unpacked, crc.Value, crcLength);
            // Avoid tiny CRC checks when a stronger candidate is available, then minimize encrypted input.
            if (best is null || (candidate.CrcLength >= 8 && best.CrcLength < 8) ||
                ((candidate.CrcLength >= 8) == (best.CrcLength >= 8) && candidate.Packed < best.Packed)) best = candidate;
        }
        if (best is null)
        {
            d.Message = encrypted
                ? "No encrypted 7z stream is usable by hashcat 11600: " + string.Join("; ", reasons) + ". Try an archive with encrypted headers (-mhe=on)."
                : "Archive is not password protected (no encrypted data streams).";
            return;
        }
        var b = best;
        var data = Read(s, dataBase + info.Positions[b.Folder.PackIndex], b.Packed);
        var iv = new byte[16]; b.Aes.Iv.CopyTo(iv, 0);
        string hash = FormattableString.Invariant($"$7z${b.Type}${b.Aes.Power}${b.Aes.Salt.Length}${Bin.Hex(b.Aes.Salt)}${b.Aes.Iv.Length}${Bin.Hex(iv)}${b.Crc}${b.Packed}${(b.Type == 0 ? b.CrcLength : b.Unpacked)}${Bin.Hex(data)}");
        if (b.Type != 0) hash += FormattableString.Invariant($"${b.CrcLength}${Bin.Hex(b.Attributes)}");
        d.Add("Selected encrypted stream", $"{b.Packed:N0} bytes");
        d.Target = new HashTarget
        {
            FormatId = "7ZIP", FormatName = "7-Zip archive", Modes = [11600], HashLines = hash,
            Protection = $"AES-256, SHA-256 x {1UL << b.Aes.Power:N0}",
            Speed = SpeedClass.VerySlow, MaxPasswordLength = 256, Utf16Password = true,
            Notes = "Very slow SHA-256 key derivation (2^19 iterations by default). " +
                (encryptedHeader ? "Verifies the encrypted archive header. " : "Recovers the password of the selected encrypted stream; other streams can use different passwords. ") +
                (b.CrcLength < 8 ? "The selected data is short; verify any recovered password with 7-Zip because false positives are possible. " : "") +
                "Hashcat supports Copy, LZMA1, LZMA2 and Deflate without filters, with no AES salt.",
        };
    }

    private static byte[] DecodeHeader(Stream s, StreamsInfo info, ulong dataBase)
    {
        if (info.Folders.Count != 1) throw new UnsupportedFormatException("7z metadata uses multiple folders.");
        var f = info.Folders[0];
        var chain = f.Chain();
        if (chain is null || chain.Count != 1) throw new UnsupportedFormatException("Unsupported 7z metadata coder chain.");
        if (f.FinalSize > HeaderLimit || info.Sizes[f.PackIndex] > HeaderLimit)
            throw new UnsupportedFormatException("7z metadata exceeds the 16 MiB parsing limit.");
        var input = Read(s, dataBase + info.Positions[f.PackIndex], info.Sizes[f.PackIndex]);
        var c = chain[0];
        byte[] result = c.Id switch
        {
            "00" => input,
            "030101" => SevenZipLzma.Decode(input, c.Properties, (int)f.FinalSize),
            _ => throw new UnsupportedFormatException("Unsupported 7z metadata compression (expected Copy or LZMA1)."),
        };
        if ((ulong)result.Length != f.FinalSize) throw new FormatException("Wrong decoded 7z header size.");
        if (f.Crc.HasValue) CheckCrc(result, f.Crc.Value);
        return result;
    }

    private static AesInfo AesProperties(byte[] p)
    {
        var r = new Reader(p);
        int first = r.Byte(), power = first & 63, saltSize = 0, ivSize = 0;
        if ((first & 0xc0) != 0)
        {
            int second = r.Byte();
            saltSize = ((first >> 7) & 1) + (second >> 4);
            ivSize = ((first >> 6) & 1) + (second & 15);
        }
        var salt = r.Bytes(saltSize); var iv = r.Bytes(ivSize);
        if (!r.End) throw new FormatException("Unexpected AES properties.");
        return new(power, salt, iv);
    }

    private static StreamsInfo Streams(Reader r)
    {
        var info = new StreamsInfo();
        if (r.Peek() == 6)
        {
            r.Byte(); info.PackPos = r.Number();
            int n = r.Count();
            r.Expect(9);
            for (int i = 0; i < n; i++) info.Sizes.Add(r.Number());
            if (r.Peek() == 10) { r.Byte(); Digests(r, n); }
            r.Expect(0);
        }
        if (r.Peek() == 7)
        {
            r.Byte(); r.Expect(11);
            int n = r.Count();
            if (r.Byte() != 0) throw new UnsupportedFormatException("External 7z folder metadata is unsupported.");
            for (int i = 0; i < n; i++) info.Folders.Add(ReadFolder(r));
            r.Expect(12);
            foreach (var f in info.Folders)
                for (int i = 0; i < f.Outputs; i++) f.UnpackSizes.Add(r.Number());
            if (r.Peek() == 10)
            {
                r.Byte(); var crcs = Digests(r, n);
                for (int i = 0; i < n; i++) info.Folders[i].Crc = crcs[i];
            }
            r.Expect(0);
        }
        foreach (var f in info.Folders) { f.SubSizes.Add(f.FinalSize); f.SubCrcs.Add(f.Crc); }
        if (r.Peek() == 8) ReadSubStreams(r, info.Folders);
        r.Expect(0);
        int packIndex = 0;
        ulong position = info.PackPos;
        foreach (ulong size in info.Sizes)
        {
            info.Positions.Add(position);
            if (size > ulong.MaxValue - position) throw new FormatException("7z packed size overflow.");
            position += size;
        }
        foreach (var f in info.Folders) { f.PackIndex = packIndex; packIndex += f.Packed.Count; }
        if (packIndex != info.Sizes.Count) throw new FormatException("7z packed stream count mismatch.");
        return info;
    }

    private static Folder ReadFolder(Reader r)
    {
        var f = new Folder();
        int n = r.Count(64), inputs = 0;
        if (n == 0) throw new FormatException("Empty 7z coder list.");
        for (int i = 0; i < n; i++)
        {
            int flags = r.Byte(), idSize = flags & 15;
            if (idSize == 0 || (flags & 0xc0) != 0) throw new FormatException("Invalid 7z coder flags.");
            string id = Bin.Hex(r.Bytes(idSize));
            int ins = 1, outs = 1;
            if ((flags & 16) != 0) { ins = r.Count(64); outs = r.Count(64); }
            if (ins == 0 || outs == 0 || inputs + ins > 64 || f.Outputs + outs > 64)
                throw new FormatException("Invalid 7z coder stream count.");
            byte[] properties = (flags & 32) != 0 ? r.Bytes(r.Count(1024)) : [];
            f.Coders.Add(new(id, properties, inputs, f.Outputs, ins, outs));
            inputs += ins; f.Outputs += outs;
        }
        var boundOutputs = new HashSet<int>();
        for (int i = 0; i < f.Outputs - 1; i++)
        {
            int input = r.Count(inputs - 1), output = r.Count(f.Outputs - 1);
            if (!f.Binds.TryAdd(input, output) || !boundOutputs.Add(output)) throw new FormatException("Duplicate 7z bind pair.");
        }
        int packed = inputs - f.Binds.Count;
        if (packed <= 0) throw new FormatException("Invalid 7z bind pairs.");
        if (packed == 1) f.Packed.Add(Enumerable.Range(0, inputs).Single(i => !f.Binds.ContainsKey(i)));
        else
            for (int i = 0; i < packed; i++)
            {
                int index = r.Count(inputs - 1);
                if (f.Binds.ContainsKey(index) || f.Packed.Contains(index)) throw new FormatException("Invalid 7z packed index.");
                f.Packed.Add(index);
            }
        f.FinalOutput = Enumerable.Range(0, f.Outputs).Single(i => !boundOutputs.Contains(i));
        return f;
    }

    private static void ReadSubStreams(Reader r, List<Folder> folders)
    {
        r.Expect(8);
        var counts = folders.Select(_ => 1).ToArray();
        if (r.Peek() == 13) { r.Byte(); for (int i = 0; i < counts.Length; i++) counts[i] = r.Count(); }
        if (counts.Sum(c => (long)c) > 100000) throw new FormatException("Too many 7z substreams.");
        bool sizes = r.Peek() == 9;
        if (sizes) r.Byte();
        for (int i = 0; i < folders.Count; i++)
        {
            var f = folders[i]; f.SubSizes.Clear(); f.SubCrcs.Clear();
            ulong remaining = f.FinalSize;
            if (counts[i] > 1 && !sizes) throw new FormatException("Missing 7z substream sizes.");
            for (int j = 1; j < counts[i]; j++)
            {
                ulong size = r.Number();
                if (size > remaining) throw new FormatException("Invalid 7z substream size.");
                f.SubSizes.Add(size); remaining -= size;
            }
            if (counts[i] > 0) f.SubSizes.Add(remaining);
        }
        int numDigests = folders.Select((f, i) => counts[i] == 1 && f.Crc.HasValue ? 0 : counts[i]).Sum();
        uint?[] digests = new uint?[numDigests];
        if (r.Peek() == 10) { r.Byte(); digests = Digests(r, numDigests); }
        int k = 0;
        for (int i = 0; i < folders.Count; i++)
        {
            var f = folders[i];
            for (int j = 0; j < counts[i]; j++) f.SubCrcs.Add(counts[i] == 1 && f.Crc.HasValue ? f.Crc : digests[k++]);
        }
        r.Expect(0);
    }

    private static uint?[] Digests(Reader r, int count)
    {
        bool all = r.Byte() != 0;
        byte[] defined = all ? [] : r.Bytes((count + 7) / 8);
        var result = new uint?[count];
        for (int i = 0; i < count; i++)
            if (all || (defined[i / 8] & (0x80 >> (i % 8))) != 0) result[i] = Bin.U32(r.Bytes(4), 0);
        return result;
    }

    private static void SkipProperties(Reader r)
    {
        while (r.Byte() != 0) r.Bytes(r.Count(HeaderLimit));
    }

    private static void ValidateRanges(StreamsInfo info, ulong dataBase, ulong end)
    {
        for (int i = 0; i < info.Sizes.Count; i++)
            if (info.Positions[i] > end - dataBase || info.Sizes[i] > end - dataBase - info.Positions[i])
                throw new FormatException("7z packed stream is outside the archive.");
    }

    private static byte[] Read(Stream s, ulong offset, ulong size)
    {
        if (offset > (ulong)s.Length || size > (ulong)s.Length - offset || size > int.MaxValue)
            throw new FormatException("Truncated 7z stream (possibly an incomplete multi-volume archive).");
        if (size == 0) return [];
        return Bin.ReadAt(s, (long)offset, (int)size);
    }

    private static void CheckCrc(ReadOnlySpan<byte> bytes, uint expected)
    {
        uint crc = uint.MaxValue;
        foreach (byte b in bytes) crc = (crc >> 8) ^ CrcTable[(crc ^ b) & 255];
        if (~crc != expected) throw new FormatException("7z header CRC mismatch.");
    }

    private sealed class Reader(byte[] bytes)
    {
        private int position;
        public bool End => position == bytes.Length;
        public int Peek() { Bin.Need(bytes, position, 1); return bytes[position]; }
        public int Byte() { int b = Peek(); position++; return b; }
        public void Expect(int b) { if (Byte() != b) throw new FormatException("Unexpected 7z property."); }
        public byte[] Bytes(int n) { var result = Bin.Slice(bytes, position, n); position += n; return result; }
        public ulong Number()
        {
            int first = Byte(), mask = 0x80;
            ulong value = 0;
            for (int i = 0; i < 8; i++, mask >>= 1)
            {
                if ((first & mask) == 0) return value | ((ulong)(first & (mask - 1)) << (8 * i));
                value |= (ulong)Byte() << (8 * i);
            }
            return value;
        }
        public int Count(int limit = 100000)
        {
            ulong n = Number();
            if (n > (ulong)limit) throw new FormatException("7z count exceeds the parsing limit.");
            return (int)n;
        }
    }

    private sealed class StreamsInfo
    {
        public ulong PackPos;
        public List<ulong> Sizes = [], Positions = [];
        public List<Folder> Folders = [];
    }
    private sealed class Folder
    {
        public List<Coder> Coders = [];
        public Dictionary<int, int> Binds = [];
        public List<int> Packed = [];
        public List<ulong> UnpackSizes = [], SubSizes = [];
        public List<uint?> SubCrcs = [];
        public int Outputs, FinalOutput, PackIndex;
        public uint? Crc;
        public ulong FinalSize => UnpackSizes[FinalOutput];
        public List<Coder>? Chain()
        {
            if (Packed.Count != 1 || Coders.Any(c => c.Inputs != 1 || c.Outputs != 1)) return null;
            var chain = new List<Coder>();
            int input = Packed[0];
            while (chain.Count < Coders.Count)
            {
                var c = Coders.Single(c => c.Input == input);
                if (chain.Contains(c)) throw new FormatException("Cyclic 7z coder chain.");
                chain.Add(c);
                if (c.Output == FinalOutput)
                    return chain.Count == Coders.Count ? chain : throw new FormatException("Disconnected 7z coder chain.");
                input = Binds.Single(b => b.Value == c.Output).Key;
            }
            throw new FormatException("Cyclic 7z coder chain.");
        }
    }
    private sealed record Coder(string Id, byte[] Properties, int Input, int Output, int Inputs, int Outputs);
    private sealed record AesInfo(int Power, byte[] Salt, byte[] Iv);
    private sealed record Candidate(Folder Folder, AesInfo Aes, int Type, byte[] Attributes, ulong Packed, ulong Unpacked, uint Crc, ulong CrcLength);
}
