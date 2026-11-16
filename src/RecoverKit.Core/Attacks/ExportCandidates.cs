using System.Text;
using RecoverKit.Core.Native;

namespace RecoverKit.Core.Attacks;

/// <summary>Local rule-free lists and masks, plus a combinator fallback when no compute backend exists.</summary>
internal static class ExportCandidates
{
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);

    public static IEnumerable<string>? TryCreate(PreparedAttack attack, CancellationToken ct, string? workingDirectory = null, string? executable = null,
        bool combinatorFallback = false)
    {
        ct.ThrowIfCancellationRequested();
        if (attack.Stdin is not null) return null;
        string? mode = null;
        bool optimized = false, hex = false, increment = false;
        int? min = null, max = null;
        var custom = new string?[8];
        var inputs = new List<string>();
        var args = attack.Args;
        for (int i = 0; i < args.Count; i++)
        {
            string arg = args[i];
            switch (arg)
            {
                case "-a": if (++i >= args.Count) return null; mode = args[i]; break;
                case "-O": case "--optimized-kernel-enable": optimized = true; break;
                case "--hex-charset": hex = true; break;
                case "-i": case "--increment": increment = true; break;
                case "--increment-min": if (++i >= args.Count || !int.TryParse(args[i], out int mn)) return null; min = mn; break;
                case "--increment-max": if (++i >= args.Count || !int.TryParse(args[i], out int mx)) return null; max = mx; break;
                default:
                    if (arg.Length == 2 && arg[0] == '-' && arg[1] is >= '1' and <= '8')
                    {
                        if (++i >= args.Count) return null;
                        custom[arg[1] - '1'] = args[i];
                    }
                    else if (arg.StartsWith('-')) return null;
                    else inputs.Add(arg);
                    break;
            }
        }

        // Combinator order depends on hashcat's device tuning; use the local loop only without a backend.
        if (mode == "1" && !combinatorFallback) return null;
        if (combinatorFallback && mode != "1") return null;

        string FullPath(string path) => Path.GetFullPath(path, workingDirectory ?? Environment.CurrentDirectory);
        if ((mode == "0" && inputs.Count == 1 || mode == "1" && inputs.Count == 2)
            && !hex && !increment && min is null && max is null && custom.All(c => c is null))
        {
            string[] paths = inputs.Select(FullPath).ToArray();
            Span<byte> header = stackalloc byte[6];
            foreach (string path in paths)
            {
                // Containers are decoded by hashcat's feeds; ordinary dictionaries are read as bytes here.
                using var file = File.OpenRead(path);
                int n = file.Read(header);
                if (n == 0 || n == 3 && header[..3].SequenceEqual(new byte[] { 0xef, 0xbb, 0xbf })
                    || WordlistLengthCache.IsCompressed(header[..n]) || header[..n].StartsWith(new byte[] { 0xff, 0xfe })
                    || header[..n].StartsWith(new byte[] { 0xfe, 0xff })) return null;
            }
            int wordLimit = optimized ? 31 : 256;
            return mode == "0" ? Words(paths[0], wordLimit, ct, DecodeWord)
                : Decode(Combinations(paths[0], paths[1], wordLimit, optimized, ct), ct);
        }
        if (mode != "3" || inputs.Count != 1 || (!increment && (min is not null || max is not null))) return null;
        if (File.Exists(FullPath(inputs[0]))) return null; // A mask file has its own per-line options.

        // Reuse the CPU engine's mask parser after converting UTF-8 literals and mixed hex charsets.
        var sets = new byte[]?[8];
        var normalized = new List<string> { "-a", "3", "--hex-charset" };
        for (int i = 0; i < custom.Length; i++)
        {
            if (custom[i] is not { } definition) continue;
            if (File.Exists(FullPath(definition))) return null;
            sets[i] = Expand(definition, sets, hex);
            if (sets[i] is not { Length: > 0 } bytes) return null;
            normalized.AddRange([$"-{i + 1}", Convert.ToHexString(bytes)]);
        }
        string? mask = NormalizeMask(inputs[0], hex);
        if (mask is null) return null;
        normalized.Add(mask);
        var space = MaskSpace.FromHashcatArgs(normalized);
        if (space is null) return null;
        int first = increment ? min ?? 1 : space.MaxLength;
        int last = increment ? Math.Min(max ?? space.MaxLength, space.MaxLength) : space.MaxLength;
        if (first < 1 || first > last || max is <= 0) return null;
        // --stdout uses the generic mask limits, independently of the format being recovered.
        int limit = optimized ? 55 : 256;
        if (first > limit) return null;
        last = Math.Min(last, limit);
        var ranks = HashcatMaskOrder.TryGet(executable);
        if (ranks is null)
        {
            DebugLog.Info($"Candidate export falling back to hashcat: mask order unknown for {executable ?? "default runtime"}.");
            return null;
        }
        var positions = space.Positions.Select(p => p.OrderBy(b => ranks[b]).ToArray()).ToArray();
        return Decode(Masks(positions, first, last, ct), ct);
    }

    private static byte[]? Expand(string definition, byte[]?[] earlier, bool hex)
    {
        var bytes = new List<byte>();
        for (int i = 0; i < definition.Length; i++)
        {
            if (definition[i] == '?')
            {
                if (++i >= definition.Length) return null;
                char token = definition[i];
                var set = token is >= '1' and <= '8' ? earlier[token - '1']
                    : MaskSpace.FromHashcatArgs(["-a", "3", "?" + token])?.Positions[0];
                if (set is null) return null;
                bytes.AddRange(set);
            }
            else if (hex)
            {
                if (i + 1 >= definition.Length || !char.IsAsciiHexDigit(definition[i]) || !char.IsAsciiHexDigit(definition[i + 1])
                    || !byte.TryParse(definition.AsSpan(i, 2), System.Globalization.NumberStyles.HexNumber,
                    System.Globalization.CultureInfo.InvariantCulture, out byte value)) return null;
                bytes.Add(value);
                i++;
            }
            else
            {
                int count = char.IsHighSurrogate(definition[i]) && i + 1 < definition.Length && char.IsLowSurrogate(definition[i + 1]) ? 2 : 1;
                bytes.AddRange(Encoding.UTF8.GetBytes(definition.Substring(i, count)));
                i += count - 1;
            }
        }
        return bytes.Distinct().ToArray();
    }

    private static string? NormalizeMask(string mask, bool hex)
    {
        if (hex) return mask;
        var result = new StringBuilder();
        for (int i = 0; i < mask.Length; i++)
        {
            if (mask[i] == '?')
            {
                if (++i >= mask.Length) return null;
                result.Append('?').Append(mask[i]);
            }
            else
            {
                int count = char.IsHighSurrogate(mask[i]) && i + 1 < mask.Length && char.IsLowSurrogate(mask[i + 1]) ? 2 : 1;
                result.Append(Convert.ToHexString(Encoding.UTF8.GetBytes(mask.Substring(i, count))));
                i += count - 1;
            }
        }
        return result.ToString();
    }

    private static IEnumerable<byte[]> Masks(byte[][] positions, int min, int max, CancellationToken ct)
    {
        for (int length = min; length <= max; length++)
        {
            var indexes = new int[length];
            var word = positions.Take(length).Select(p => p[0]).ToArray();
            while (true)
            {
                ct.ThrowIfCancellationRequested();
                yield return word;
                int p = 0;
                for (; p < length; p++)
                {
                    if (++indexes[p] < positions[p].Length) { word[p] = positions[p][indexes[p]]; break; }
                    indexes[p] = 0;
                    word[p] = positions[p][0];
                }
                if (p == length) break;
            }
        }
    }

    private static IEnumerable<ReadOnlyMemory<byte>> Words(string path, int limit, CancellationToken ct)
        => Words(path, limit, ct, static (bytes, _) => bytes);

    private static IEnumerable<T> Words<T>(string path, int limit, CancellationToken ct, Func<ReadOnlyMemory<byte>, bool, T> convert)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 1);
        // A decoded HEX word can be longer than the ordinary input limit. Bound retained bytes even for huge lines.
        var line = new byte[2 * limit + 6];
        var buffer = new byte[65536];
        int available = stream.ReadAtLeast(buffer, 3, throwOnEndOfStream: false);
        int position = available >= 3 && buffer.AsSpan(0, 3).SequenceEqual(new byte[] { 0xef, 0xbb, 0xbf }) ? 3 : 0;
        int length = 0, carriageReturns = 0;
        bool any = false, overflow = false, first = true;
        for (long offset = 0; ; offset++)
        {
            if ((offset & 4095) == 0) ct.ThrowIfCancellationRequested();
            if (position == available)
            {
                available = stream.Read(buffer);
                position = 0;
            }
            if (!any && available > 0)
            {
                int newline = buffer.AsSpan(position, available - position).IndexOf((byte)'\n');
                if (newline >= 0)
                {
                    ct.ThrowIfCancellationRequested();
                    int end = position + newline;
                    while (end > position && buffer[end - 1] == '\r') end--;
                    int start = position, count = end - position;
                    position += newline + 1;
                    if (count <= limit && (count == 0 || buffer[start] != '$'))
                    {
                        yield return convert(buffer.AsMemory(start, count), first);
                        first = false;
                    }
                    else if (ReadWord(buffer.AsMemory(start, count), limit) is { } word)
                    {
                        yield return convert(word, first);
                        first = false;
                    }
                    continue;
                }
            }
            int value = available == 0 ? -1 : buffer[position++];
            if (value == '\n' || value < 0)
            {
                if (value < 0 && !any) yield break;
                if (!overflow && ReadWord(line.AsMemory(0, length), limit) is { } word)
                {
                    ct.ThrowIfCancellationRequested();
                    yield return convert(word, first);
                    first = false;
                }
                if (value < 0) yield break;
                length = carriageReturns = 0;
                any = overflow = false;
                continue;
            }
            any = true;
            if (value == '\r') { if (carriageReturns <= line.Length) carriageReturns++; continue; }
            if (length + carriageReturns >= line.Length) overflow = true;
            if (!overflow)
            {
                while (carriageReturns-- > 0) line[length++] = (byte)'\r';
                line[length++] = (byte)value;
            }
            carriageReturns = 0;
        }
    }

    private static ReadOnlyMemory<byte>? ReadWord(ReadOnlyMemory<byte> word, int limit)
    {
        if (word.Length > 2 * limit + 6) return null;
        if (word.Span.StartsWith("$HEX["u8) && word.Span.EndsWith("]"u8))
        {
            try { word = Convert.FromHexString(Encoding.ASCII.GetString(word.Span[5..^1])); }
            catch (FormatException) { }
        }
        if (word.Length > limit) return null;
        return word;
    }

    private static IEnumerable<ReadOnlyMemory<byte>> Combinations(string left, string right, int limit, bool optimized, CancellationToken ct)
    {
        // Keep the small-list traversal, but device-tuned right-list blocks cannot be reproduced here.
        bool swap = optimized && Wordlists.CountLines(right, ct) > Wordlists.CountLines(left, ct);
        var word = new byte[limit];
        foreach (var outer in Words(swap ? right : left, limit, ct))
        foreach (var inner in Words(swap ? left : right, limit, ct))
        {
            ct.ThrowIfCancellationRequested();
            ReadOnlyMemory<byte> a = swap ? inner : outer, b = swap ? outer : inner;
            int length = Math.Min(limit, a.Length + b.Length);
            int leftBytes = Math.Min(a.Length, length);
            a.Span[..leftBytes].CopyTo(word);
            b.Span[..(length - leftBytes)].CopyTo(word.AsSpan(leftBytes));
            yield return word.AsMemory(0, length);
        }
    }

    // Byte buffers are reused by the producers; decode each word before advancing them.
    private static IEnumerable<string> Decode(IEnumerable<ReadOnlyMemory<byte>> source, CancellationToken ct)
    {
        bool first = true;
        foreach (var bytes in source)
        {
            ct.ThrowIfCancellationRequested();
            string word = DecodeWord(bytes, first);
            first = false;
            yield return word;
        }
    }

    private static string DecodeWord(ReadOnlyMemory<byte> bytes, bool first)
    {
        try
        {
            string word = StrictUtf8.GetString(bytes.Span);
            // Process.StandardOutput consumes a leading UTF-8 BOM, unless hashcat hex-escapes the word.
            if (first && word.StartsWith('\uFEFF') && !bytes.Span.ContainsAnyInRange((byte)0, (byte)31)
                && !bytes.Span.Contains((byte)127)) word = word[1..];
            return word;
        }
        catch (DecoderFallbackException) { return Encoding.Latin1.GetString(bytes.Span); }
    }

    private static IEnumerable<string> Decode(IEnumerable<byte[]> source, CancellationToken ct)
    {
        bool first = true;
        foreach (var bytes in source)
        {
            ct.ThrowIfCancellationRequested();
            string word;
            try
            {
                word = StrictUtf8.GetString(bytes);
                // Process.StandardOutput consumes a leading UTF-8 BOM, unless hashcat hex-escapes the word.
                if (first && word.StartsWith('\uFEFF') && !bytes.Any(b => b < 32 || b == 127)) word = word[1..];
            }
            catch (DecoderFallbackException) { word = Encoding.Latin1.GetString(bytes); }
            first = false;
            yield return word;
        }
    }
}
