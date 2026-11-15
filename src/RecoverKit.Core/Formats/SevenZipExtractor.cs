namespace RecoverKit.Core.Formats;

/// <summary>7z streams and AES properties, serialized for hashcat 8.0.0 mode 11600.</summary>
public static class SevenZipExtractor
{
    private static ReadOnlySpan<byte> Signature => [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c];
    private const int HeaderLimit = 16 * 1024 * 1024;
    private const ulong HashcatDataLimit = 8 * 1024 * 1024;
    /// <summary>A smaller limit for tests on this thread, so small fixtures exercise the large-stream path.</summary>
    [ThreadStatic] internal static ulong TestDataLimit;
    internal static ulong DataLimit => TestDataLimit > 0 ? TestDataLimit : HashcatDataLimit;
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
    {
        const int limit = 4 * 1024 * 1024;
        var bytes = Bin.ReadAt(s, 0, (int)Math.Min(s.Length, limit + 32));
        for (int position = 0; position < limit;)
        {
            int found = Bin.IndexOf(bytes, Signature, position);
            if (found < 0 || found >= limit) return -1;
            // Keep direct damaged archives recognizable, but skip signature constants in SFX stubs.
            if (found == 0 || (found + 32 <= bytes.Length && bytes[found + 6] == 0 &&
                Crc32(bytes.AsSpan(found + 12, 20)) == Bin.U32(bytes, found + 8))) return found;
            position = found + Signature.Length;
        }
        return -1;
    }

    public static void Extract(Stream s, Detection d)
    {
        d.TypeName = "7-Zip archive";
        // A split archive has no volume flag; FormatDetector reads its numbered parts as one stream.
        bool split = s is MultiVolumeStream;
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
        if (nextOffset > (ulong)s.Length - dataBase)
            throw new FormatException(split
                ? $"The archive continues after {Path.GetFileName(((MultiVolumeStream)s).Paths[^1])}: a later part is missing. Put all parts in the same folder."
                : "7z end header is outside the file (possibly an incomplete multi-volume archive: open its .7z.001 part).");
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
        Candidate? cpuBest = null;
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
            if (props.Salt.Length != 0) { reasons.Add("salted AES (neither hashcat nor the built-in processor check supports it)"); continue; }
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
            // CRCs concatenate in file order, including empty files. Never send a tiny check to hashcat.
            ulong prefixSize = 0;
            uint? prefixCrc = 0;
            int prefixFiles = 0;
            while (prefixFiles < f.SubSizes.Count && prefixSize < 8)
            {
                ulong size = f.SubSizes[prefixFiles];
                uint? subCrc = size == 0 ? 0 : f.SubCrcs[prefixFiles];
                if (!subCrc.HasValue) { prefixCrc = null; break; }
                prefixCrc = CombineCrc(prefixCrc!.Value, subCrc.Value, size);
                prefixSize += size;
                prefixFiles++;
            }
            ulong cpuLength = f.FinalSize;
            uint? cpuCrc = f.Crc;
            if (prefixCrc.HasValue && prefixSize > 0)
            { cpuLength = prefixSize; cpuCrc = prefixCrc; }
            // A tiny Copy file still has at least nine zero padding bytes, checked by the CPU kernel.
            bool tinyCopy = type == 0 && cpuLength is > 0 and < 8 && packed - unpacked >= 8;
            if (cpuCrc.HasValue && (cpuLength >= 8 || tinyCopy))
            {
                var cpu = new Candidate(f, props, type, attributes, packed, unpacked, cpuCrc.Value, cpuLength);
                if (cpuBest is null || cpu.CrcLength < cpuBest.CrcLength) cpuBest = cpu;
            }
            else if (cpuLength < 8) reasons.Add("the checksum covers fewer than 8 bytes without enough Copy padding for a reliable processor check");
            else if (!cpuCrc.HasValue) reasons.Add("no usable first-file or whole-stream CRC for the CPU check");
            if (packed > DataLimit)
            {
                // Hashcat checks the first crc_len decoded bytes, so adjacent file CRCs form one prefix.
                // Deflate is left out because hashcat inflates the whole input it is given.
                if (type is 0 or 1 or 2 && f.SubSizes.Count > 1 && prefixCrc.HasValue
                    && prefixSize is >= 8 and <= CrcLimit && PrefixInput(type, prefixSize, packed) is var need && need < DataLimit)
                {
                    var prefix = new Candidate(f, props, type, attributes, need, type == 0 ? prefixSize : Math.Min(unpacked, need),
                        prefixCrc.Value, prefixSize) { FirstFileOnly = true };
                    if (best is null || prefix.Packed < best.Packed) best = prefix;
                    continue;
                }
                reasons.Add(f.SubSizes.Count > 1
                    ? "encrypted streams larger than hashcat's 8 MiB limit without a usable checksum prefix that fits"
                    : "encrypted streams larger than hashcat's 8 MiB limit (a single large file per stream)");
                continue;
            }
            ulong crcLength = f.FinalSize;
            uint? crc = f.Crc;
            if (prefixCrc.HasValue && prefixSize > 0)
            {
                // Hashcat estimates LZMA input from CRC length. Cover the packed size so
                // it decrypts the whole stream instead of under-reading a solid prefix.
                for (int i = prefixFiles; type is 1 or 2 && prefixSize < packed && i < f.SubSizes.Count; i++)
                {
                    if (!f.SubCrcs[i].HasValue || f.SubSizes[i] > CrcLimit - Math.Min(prefixSize, CrcLimit)) break;
                    prefixCrc = CombineCrc(prefixCrc.Value, f.SubCrcs[i]!.Value, f.SubSizes[i]);
                    prefixSize += f.SubSizes[i];
                }
                if (prefixSize >= 8 && (!crc.HasValue || prefixSize < crcLength))
                { crc = prefixCrc; crcLength = prefixSize; }
            }
            if (!crc.HasValue || crcLength == 0) { reasons.Add("streams without a usable CRC"); continue; }
            if (crcLength < 8) { reasons.Add("the checksum covers fewer than 8 bytes; hashcat does not check AES padding"); continue; }
            if (type != 0 && crcLength > CrcLimit) { reasons.Add("CRC data larger than hashcat's 9,999,999-byte limit"); continue; }
            ulong estimatedInput = type switch
            {
                1 => (ulong)(32.5 + crcLength * 1.05),
                2 => (ulong)(4.5 + crcLength * 1.01),
                _ => packed,
            };
            if (crcLength != f.FinalSize && ((Math.Min(packed, estimatedInput) + 15) / 16 * 16) < packed)
            { reasons.Add("solid prefixes too short for hashcat's LZMA input estimate"); continue; }
            // The tokenizer includes the CRC-length/properties suffix in its 16 MiB hex-data field.
            if (type != 0 && packed == DataLimit)
            { reasons.Add("compressed data at hashcat's 8 MiB token limit (no room for compression properties)"); continue; }
            if (type == 0 && crcLength > unpacked) throw new FormatException("Invalid uncompressed CRC length.");
            var candidate = new Candidate(f, props, type, attributes, packed, unpacked, crc.Value, crcLength);
            if (best is null || candidate.Packed < best.Packed) best = candidate;
        }
        if (best is null)
        {
            if (cpuBest is not null)
            {
                SetCpuTarget(s, info, dataBase, d, cpuBest, reasons);
                return;
            }
            d.Message = encrypted
                ? "No encrypted 7z stream is usable by hashcat 11600 or the built-in processor check: " + string.Join("; ", reasons) + ". Try an archive with encrypted headers (-mhe=on)."
                : "Archive is not password protected (no encrypted data streams).";
            return;
        }
        var b = best;
        var data = Read(s, dataBase + info.Positions[b.Folder.PackIndex], b.Packed);
        var iv = new byte[16]; b.Aes.Iv.CopyTo(iv, 0);
        string hash = FormattableString.Invariant($"$7z${b.Type}${b.Aes.Power}${b.Aes.Salt.Length}${Bin.Hex(b.Aes.Salt)}${b.Aes.Iv.Length}${Bin.Hex(iv)}${b.Crc}${b.Packed}${(b.Type == 0 ? b.CrcLength : b.Unpacked)}${Bin.Hex(data)}");
        if (b.Type != 0) hash += FormattableString.Invariant($"${b.CrcLength}${Bin.Hex(b.Attributes)}");
        d.Add("Selected encrypted stream", b.FirstFileOnly
            ? $"first {b.Packed:N0} bytes of a solid block, checked against its first file(s) ({b.CrcLength:N0} bytes)"
            : $"{b.Packed:N0} bytes");
        // Confirm every hashcat hit against the original stream and its AES padding.
        var confirmer = new Native.Kernels.SevenZipKernel(CpuTarget(s, info, dataBase, d, b));
        d.Target = new HashTarget
        {
            FormatId = "7ZIP", FormatName = "7-Zip archive", Modes = [11600], HashLines = hash,
            ConfirmPassword = bytes => confirmer.Verify(bytes),
            Protection = $"AES-256, SHA-256 x {1UL << b.Aes.Power:N0}",
            Speed = SpeedClass.VerySlow, MaxPasswordLength = 256, Utf16Password = true,
            Notes = "Very slow SHA-256 key derivation (2^19 iterations by default). " +
                (encryptedHeader ? "Verifies the encrypted archive header. " : "Recovers the password of the selected encrypted stream; other streams can use different passwords. ") +
                "Hashcat supports Copy, LZMA1, LZMA2 and Deflate without filters, with no AES salt.",
        };
    }

    private static void SetCpuTarget(Stream s, StreamsInfo info, ulong dataBase, Detection d, Candidate b, IReadOnlyCollection<string> reasons)
    {
        var cpu = CpuTarget(s, info, dataBase, d, b);
        long offset = cpu.DataOffset;
        // Stable cache/session identity without an archive path or a full-file read.
        string metadata = System.Text.Json.JsonSerializer.Serialize(new { cpu.DataOffset, cpu.PackedSize,
            cpu.AesOutputSize, cpu.OutputSize, cpu.CrcLength, cpu.Crc, cpu.Method, cpu.Properties, cpu.Power, cpu.Salt, cpu.Iv });
        using var identity = System.Security.Cryptography.IncrementalHash.CreateHash(System.Security.Cryptography.HashAlgorithmName.SHA256);
        identity.AppendData(System.Text.Encoding.UTF8.GetBytes(metadata));
        identity.AppendData(Read(s, (ulong)offset, Math.Min(64, b.Packed)));
        identity.AppendData(Read(s, (ulong)offset + b.Packed - 16, 16));
        ulong history = b.Type is 1 or 2
            ? Math.Min(SevenZipLzma.DictionarySize(b.Attributes, b.Type == 2), b.CrcLength) : 0;
        history = (history + 65535) / 65536 * 65536;
        string speed = b.Type switch
        {
            0 => "roughly 500-700 passwords per second for an unpadded 14 MiB Copy file. " +
                "Without padding every guess reads and checks the selected data, so larger files are slower; zero padding usually rejects wrong guesses early. ",
            1 or 2 => "roughly 1,000-1,400 passwords per second for LZMA/LZMA2. ",
            _ => "roughly 600-1,100 passwords per second for Deflate. ",
        };
        string notes = (b.CrcLength < 8
            ? "Hashcat does not check AES zero padding, and this stream has fewer than 8 checksum bytes. " +
                "RecoverKit therefore checks its padding and whole-file checksum on the processor without the graphics card. "
            : "Hashcat can check encrypted files only up to 8 MiB, with at most 9,999,999 bytes for the decompressed checksum. " +
                "None of this archive's encrypted streams fits hashcat: " + string.Join("; ", reasons) + ". " +
                "RecoverKit therefore checks passwords on the processor without the graphics card. ") +
            "As an example from one machine, an Apple M1 Pro with 10 threads, seven-byte passwords and the default 2^19 SHA-256 iterations checked " + speed +
            "Speed depends on the processor, password length and thread count. " +
            "Copy, LZMA, LZMA2 and Deflate are supported; PPMd, BZip2, BCJ filters and salted AES are not. " +
            (history > 0 ? $"A full check may use up to {history / 1024:N0} KiB of dictionary history, plus decoder models and stream buffers. " +
                "Only one full check runs at a time and reuses that history; initial password checks run in parallel. " : "") +
            "Recovers the password of the selected stream; other streams can use different passwords.";
        d.Add("Password checking", notes);
        d.Add("Selected encrypted stream", $"{b.Packed:N0} encrypted bytes, checking {b.CrcLength:N0} decoded bytes on the processor");
        var kernel = new Native.Kernels.SevenZipKernel(cpu);
        d.Target = new HashTarget
        {
            FormatId = "7ZIP", FormatName = "7-Zip archive", Modes = [],
            HashLines = "$recoverkit-7z$" + Convert.ToHexString(identity.GetHashAndReset()).ToLowerInvariant(),
            SevenZipCpu = cpu, ConfirmPassword = bytes => kernel.Verify(bytes),
            Protection = $"AES-256, SHA-256 x {1UL << b.Aes.Power:N0} (CPU)",
            Speed = SpeedClass.VerySlow, MaxPasswordLength = 256, Utf16Password = true, Notes = notes,
        };
    }

    private static SevenZipCpuTarget CpuTarget(Stream s, StreamsInfo info, ulong dataBase, Detection d, Candidate b)
    {
        var iv = new byte[16]; b.Aes.Iv.CopyTo(iv, 0);
        return new SevenZipCpuTarget(s is MultiVolumeStream volumes ? volumes.Paths : [d.FilePath],
            checked((long)(dataBase + info.Positions[b.Folder.PackIndex])),
            checked((long)info.Sizes[b.Folder.PackIndex]), checked((long)b.Folder.UnpackSizes[b.Folder.Chain()![0].Output]),
            checked((long)b.Folder.FinalSize), checked((long)b.CrcLength), b.Crc, b.Type, b.Attributes, b.Aes.Power, b.Aes.Salt, iv);
    }

    /// <summary>
    /// Encrypted bytes hashcat 11600 decrypts to check a stream's first <paramref name="crcLength"/> bytes:
    /// the CRC length itself for Copy, and hashcat's own upper estimate of the compressed size for LZMA
    /// (32.5 + 5%) and LZMA2 (4.5 + 1%), in whole AES blocks, never more than the stream.
    /// </summary>
    internal static ulong PrefixInput(int type, ulong crcLength, ulong packed)
    {
        double estimate = type switch { 1 => 32.5 + crcLength * 1.05, 2 => 4.5 + crcLength * 1.01, _ => crcLength };
        ulong bytes = (ulong)Math.Ceiling(estimate) + 1;
        return Math.Min(packed, (bytes + 15) / 16 * 16);
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
            r.Byte(); info.PackPos = r.Size();
            int n = r.Count();
            r.Expect(9);
            for (int i = 0; i < n; i++) info.Sizes.Add(r.Size());
            if (r.Peek() == 10) { r.Byte(); Digests(r, n); }
            r.Expect(0);
        }
        if (r.Peek() == 7)
        {
            r.Byte(); r.Expect(11);
            int n = r.Count(10000);
            if (r.Byte() != 0) throw new UnsupportedFormatException("External 7z folder metadata is unsupported.");
            int totalCoders = 0;
            for (int i = 0; i < n; i++)
            {
                var folder = ReadFolder(r);
                totalCoders += folder.Coders.Count;
                if (totalCoders > 100000) throw new FormatException("Too many 7z coders.");
                info.Folders.Add(folder);
            }
            r.Expect(12);
            foreach (var f in info.Folders)
                for (int i = 0; i < f.Outputs; i++) f.UnpackSizes.Add(r.Size());
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
                ulong size = r.Size();
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
        if (Crc32(bytes) != expected) throw new FormatException("7z header CRC mismatch.");
    }

    private static uint Crc32(ReadOnlySpan<byte> bytes)
    {
        uint crc = uint.MaxValue;
        foreach (byte b in bytes) crc = (crc >> 8) ^ CrcTable[(crc ^ b) & 255];
        return ~crc;
    }

    private static uint CombineCrc(uint left, uint right, ulong rightLength)
    {
        // Advance a CRC by rightLength zero bytes in GF(2), then add the next stream's CRC.
        uint[] matrix = Enumerable.Range(0, 32).Select(i =>
        {
            uint c = 1u << i;
            return (c >> 8) ^ CrcTable[c & 255];
        }).ToArray();
        while (rightLength != 0)
        {
            if ((rightLength & 1) != 0) left = Times(matrix, left);
            rightLength >>= 1;
            if (rightLength != 0) matrix = matrix.Select(c => Times(matrix, c)).ToArray();
        }
        return left ^ right;

        static uint Times(uint[] matrix, uint vector)
        {
            uint sum = 0;
            for (int i = 0; vector != 0; i++, vector >>= 1)
                if ((vector & 1) != 0) sum ^= matrix[i];
            return sum;
        }
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
        public ulong Size()
        {
            ulong value = Number();
            if (value > long.MaxValue) throw new FormatException("7z stream size exceeds the supported 64-bit range.");
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
    private sealed record Candidate(Folder Folder, AesInfo Aes, int Type, byte[] Attributes, ulong Packed, ulong Unpacked, uint Crc, ulong CrcLength)
    {
        /// <summary>Only the beginning of a large solid block, checked against its first files.</summary>
        public bool FirstFileOnly { get; init; }
    }
}
