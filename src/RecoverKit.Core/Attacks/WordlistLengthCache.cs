using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace RecoverKit.Core.Attacks;

public sealed class DictionaryFileStamp
{
    [JsonRequired] public string Path { get; set; } = "";
    [JsonRequired] public long Size { get; set; }
    [JsonRequired] public DateTime ModifiedUtc { get; set; }

    public static DictionaryFileStamp Capture(string path)
    {
        var file = new FileInfo(System.IO.Path.GetFullPath(path));
        return new() { Path = file.FullName, Size = file.Length, ModifiedUtc = file.LastWriteTimeUtc };
    }

    public bool Matches()
    {
        try
        {
            var file = new FileInfo(Path);
            return file.Exists && file.Length == Size && file.LastWriteTimeUtc == ModifiedUtc;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        { return false; }
    }
}

internal sealed class WordlistLengthInfo
{
    [JsonRequired] public DictionaryFileStamp Source { get; set; } = new();
    [JsonRequired] public Dictionary<int, long> Lengths { get; set; } = new();
    public bool? HasAutohexWords { get; set; }
    [JsonIgnore] public int Maximum => Lengths.Count == 0 ? 0 : Lengths.Keys.Max();
    [JsonIgnore] public long Words => Lengths.Values.Sum();
    public long LongerThan(int threshold) => Lengths.Where(pair => pair.Key > threshold).Sum(pair => pair.Value);
}

internal static class WordlistLengthCache
{
    private sealed class CacheEntry
    {
        [JsonRequired] public int Version { get; set; }
        [JsonRequired] public DictionaryFileStamp Source { get; set; } = new();
        [JsonRequired] public Dictionary<int, long> Lengths { get; set; } = new();
        [JsonRequired] public int Maximum { get; set; }
        public bool? HasAutohexWords { get; set; }
    }

    public static Task<WordlistLengthInfo?> AnalyzeAsync(string path, Action<long, long>? progress = null,
        CancellationToken ct = default, string? cacheDirectory = null, bool allowScan = true)
        => Task.Run(() => Analyze(path, progress, ct, cacheDirectory, allowScan), ct);

    public static WordlistLengthInfo? Analyze(string path, Action<long, long>? progress = null,
        CancellationToken ct = default, string? cacheDirectory = null, bool allowScan = true)
    {
        ct.ThrowIfCancellationRequested();
        try
        {
            var source = DictionaryFileStamp.Capture(path);
            string? cachePath = CachePath(source.Path, cacheDirectory);
            var cached = ReadCache(cachePath, source);
            ct.ThrowIfCancellationRequested();
            if (cached is not null && source.Matches()) return cached;
            if (!allowScan) return null;

            using var stream = new FileStream(source.Path, FileMode.Open, FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete, 65536, FileOptions.SequentialScan);
            var info = new WordlistLengthInfo { Source = source, HasAutohexWords = false };
            var timer = Stopwatch.StartNew();
            long reportedAt = 0, consumed = 0;
            progress?.Invoke(0, source.Size);
            ct.ThrowIfCancellationRequested();
            var buffer = new byte[65536];
            int current = 0, n;
            byte last = 0;
            bool autohexPrefix = true;
            while ((n = stream.Read(buffer)) > 0)
            {
                ct.ThrowIfCancellationRequested();
                if (consumed == 0 && IsCompressed(buffer.AsSpan(0, n))) return null;
                consumed += n;
                var remaining = buffer.AsSpan(0, n);
                while (!remaining.IsEmpty)
                {
                    int newline = remaining.IndexOf((byte)'\n');
                    int count = newline < 0 ? remaining.Length : newline;
                    if (current < 5 && count > 0)
                    {
                        int prefix = Math.Min(count, 5 - current);
                        autohexPrefix &= remaining[..prefix].SequenceEqual("$HEX["u8.Slice(current, prefix));
                        if (autohexPrefix && current + count >= 5) info.HasAutohexWords = true;
                    }
                    current = checked(current + count);
                    if (count > 0) last = remaining[count - 1];
                    if (newline < 0) break;
                    AddLine(info.Lengths, current - (last == '\r' ? 1 : 0));
                    current = 0;
                    last = 0;
                    autohexPrefix = true;
                    remaining = remaining[(newline + 1)..];
                }
                if (consumed < source.Size && timer.ElapsedMilliseconds - reportedAt >= 500)
                {
                    progress?.Invoke(consumed, source.Size);
                    reportedAt = timer.ElapsedMilliseconds;
                }
            }
            if (current > 0) AddLine(info.Lengths, current - (last == '\r' ? 1 : 0));
            ct.ThrowIfCancellationRequested();
            if (consumed != source.Size || !source.Matches()) return null;
            progress?.Invoke(consumed, source.Size);
            ct.ThrowIfCancellationRequested();
            if (!source.Matches()) return null;
            WriteCache(cachePath, info);
            ct.ThrowIfCancellationRequested();
            return info;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException or OverflowException)
        { return null; }
    }

    private static void AddLine(Dictionary<int, long> lengths, int length)
        => lengths[length] = checked(lengths.GetValueOrDefault(length) + 1);

    internal static bool IsCompressed(ReadOnlySpan<byte> bytes)
        // Hashcat decompresses these containers before reading candidate lines.
        => bytes.StartsWith(new byte[] { 0x1f, 0x8b }) || bytes.StartsWith("PK"u8) || bytes.StartsWith("BZh"u8)
            || bytes.StartsWith(new byte[] { 0xfd, 0x37, 0x7a, 0x58, 0x5a, 0 })
            || bytes.StartsWith(new byte[] { 0x28, 0xb5, 0x2f, 0xfd });

    private static string? CachePath(string path, string? directory)
    {
        try
        {
            string key = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(path)));
            return Path.Combine(directory ?? Path.Combine(Settings.AppDataDir, "wordlist-lengths"), key + ".json");
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        { return null; }
    }

    private static WordlistLengthInfo? ReadCache(string? path, DictionaryFileStamp source)
    {
        if (path is null) return null;
        try
        {
            var entry = JsonSerializer.Deserialize<CacheEntry>(File.ReadAllText(path));
            if (entry is null || entry.Version != 2 || entry.Source is null || entry.Lengths is null
                || entry.Source.Path != source.Path || entry.Source.Size != source.Size
                || entry.Source.ModifiedUtc != source.ModifiedUtc) return null;
            if (entry.Maximum != (entry.Lengths.Count == 0 ? 0 : entry.Lengths.Keys.Max())) return null;
            long words = 0, bytes = 0;
            foreach (var (length, count) in entry.Lengths)
            {
                if (length < 0 || count <= 0) return null;
                words = checked(words + count);
                bytes = checked(bytes + checked(length * count));
            }
            // Every record has an LF except possibly the final one, and at most one trimmed CR.
            if (source.Size == 0 ? words != 0
                : words == 0 || checked(bytes + words - 1) > source.Size || checked(bytes + 2 * words) < source.Size)
                return null;
            return new() { Source = source, Lengths = entry.Lengths, HasAutohexWords = entry.HasAutohexWords };
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException
            or ArgumentException or NotSupportedException or OverflowException)
        { return null; }
    }

    private static void WriteCache(string? path, WordlistLengthInfo info)
    {
        if (path is null) return;
        string temp = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            File.WriteAllText(temp, JsonSerializer.Serialize(new CacheEntry { Version = 2, Source = info.Source, Lengths = info.Lengths, Maximum = info.Maximum, HasAutohexWords = info.HasAutohexWords }));
            File.Move(temp, path, overwrite: true);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        { }
        finally
        {
            try { File.Delete(temp); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException) { }
        }
    }
}
