using System.Text.RegularExpressions;

namespace RecoverKit.Core.Formats;

/// <summary>
/// Read-only concatenation of ZIP or 7-Zip parts, read in place without joining them on disk.
/// PKZIP callers can also resolve offsets relative to an individual disk.
/// </summary>
public sealed partial class MultiVolumeStream : Stream
{
    private readonly FileStream?[] _parts;
    private readonly long[] _starts;
    private long _position;

    public IReadOnlyList<string> Paths { get; }

    public bool DiskRelative { get; }

    public bool HasMissingParts => _parts.Any(p => p is null);
    public int PresentCount => _parts.Count(p => p is not null);
    internal long PresentLength => _parts.Sum(p => p?.Length ?? 0);
    internal bool IsPresent(uint disk) => disk < _parts.Length && _parts[disk] is not null;

    internal long DiskOffset(uint disk, long offset)
    {
        if (disk >= _parts.Length || offset < 0)
            throw new FormatException("ZIP disk number or offset is outside its part.");
        var part = _parts[disk] ?? throw new MissingZipPartException([Paths[(int)disk]]);
        if (offset >= part.Length) throw new FormatException("ZIP disk number or offset is outside its part.");
        return checked(_starts[disk] + offset);
    }

    internal (uint Disk, long Offset) DiskPosition(long position)
    {
        int disk = PartAt(position);
        return ((uint)disk, position - _starts[disk]);
    }

    internal long AvailableTailStart
    {
        get
        {
            int disk = _parts.Length - 1;
            while (disk > 0 && _parts[disk - 1] is not null) disk--;
            return _starts[disk];
        }
    }

    internal void RequireDisks(uint first, uint last)
    {
        if (first > last || last >= _parts.Length) throw new FormatException("Invalid ZIP directory disk range.");
        var missing = Enumerable.Range((int)first, (int)(last - first + 1))
            .Where(i => _parts[i] is null).Select(i => Paths[i]).ToArray();
        if (missing.Length > 0) throw new MissingZipPartException(missing);
    }

    internal void EnsureAvailable(long offset, long count)
    {
        if (offset < 0 || count < 0 || offset > Length) throw new FormatException("ZIP entry is outside the archive.");
        long end = offset + Math.Min(count, Length - offset);
        var missing = new List<string>();
        for (int i = PartAt(offset); i < _parts.Length && _starts[i] < end; i++)
        {
            if (_parts[i] is not null) continue;
            missing.Add(Paths[i]);
            if (DiskRelative) break; // An absent spanned disk's length is unknown; report the first blocker.
        }
        if (missing.Count > 0) throw new MissingZipPartException(missing);
        if (count > Length - offset) throw new FormatException("ZIP entry is truncated.");
    }

    internal string PartsDescription
    {
        get
        {
            if (!HasMissingParts)
                return Paths.Count == 1 ? Path.GetFileName(Paths[0])
                    : $"{Paths.Count} ({Path.GetFileName(Paths[0])} to {Path.GetFileName(Paths[^1])})";
            var ranges = new List<string>();
            for (int i = 0; i < _parts.Length; i++)
            {
                if (_parts[i] is not null) continue;
                int first = i;
                while (i + 1 < _parts.Length && _parts[i + 1] is null) i++;
                ranges.Add(first == i ? Path.GetFileName(Paths[i]) : $"{Path.GetFileName(Paths[first])}-{Path.GetFileName(Paths[i])}");
            }
            return $"{PresentCount} of {Paths.Count} present (missing: {string.Join(", ", ranges)})";
        }
    }

    internal void ValidateDiskCount(uint count)
    {
        if (count != _parts.Length) throw new FormatException("ZIP disk count does not match its parts.");
    }

    public MultiVolumeStream(IReadOnlyList<string> paths, bool diskRelative = false, long? missingPartSize = null)
    {
        if (paths.Count == 0) throw new ArgumentException("No parts.", nameof(paths));
        Paths = paths.ToArray();
        DiskRelative = diskRelative;
        _parts = new FileStream?[paths.Count];
        _starts = new long[paths.Count + 1];
        try
        {
            for (int i = 0; i < paths.Count; i++)
            {
                if (File.Exists(paths[i]) || (!diskRelative && missingPartSize is null))
                    _parts[i] = new FileStream(paths[i], FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                // Missing spanned disks have no known byte length. An unreadable barrier separates
                // their neighbours; these logical positions are never on-disk archive offsets.
                long length = _parts[i]?.Length ?? missingPartSize ?? 1;
                _starts[i + 1] = checked(_starts[i] + length);
            }
        }
        catch
        {
            foreach (var p in _parts) p?.Dispose();
            throw;
        }
    }

    private int PartAt(long position)
    {
        if (position == Length) return _parts.Length;
        int i = Array.BinarySearch(_starts, position);
        if (i < 0) i = ~i - 1;
        while (i < _parts.Length && _starts[i + 1] <= position) i++;
        return i;
    }

    /// <summary>
    /// The parts of the split 7z archive that <paramref name="path"/> belongs to, from .001 up to the
    /// last consecutive part, or null when the name is not a numbered 7z part. Throws when .001 or a
    /// part before <paramref name="path"/> is missing.
    /// </summary>
    public static List<string>? SevenZipParts(string path)
    {
        var m = SevenZipPart().Match(path);
        if (!m.Success) return null;
        string stem = m.Groups[1].Value;
        int width = m.Groups[2].Value.Length;
        int opened = int.Parse(m.Groups[2].Value);
        var parts = new List<string>();
        for (int n = 1; ; n++)
        {
            string part = stem + n.ToString().PadLeft(width, '0');
            if (!File.Exists(part)) break;
            parts.Add(part);
        }
        if (parts.Count < opened)
            throw new UnsupportedFormatException(
                $"Part {Path.GetFileName(stem + (parts.Count + 1).ToString().PadLeft(width, '0'))} of this split 7z archive is missing. " +
                "Put all parts (.001, .002, ...) in the same folder.");
        return parts;
    }

    [GeneratedRegex(@"^(.*\.7z\.)(\d{3,})$", RegexOptions.IgnoreCase)]
    private static partial Regex SevenZipPart();

    public override bool CanRead => true;
    public override bool CanSeek => true;
    public override bool CanWrite => false;
    public override long Length => _starts[^1];

    public override long Position
    {
        get => _position;
        set => _position = value >= 0 ? value : throw new ArgumentOutOfRangeException(nameof(value));
    }

    public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));

    public override int Read(Span<byte> buffer)
    {
        int total = 0;
        while (buffer.Length > 0 && _position < Length)
        {
            int i = PartAt(_position);
            var part = _parts[i] ?? throw new MissingZipPartException([Paths[i]]);
            part.Position = _position - _starts[i];
            int n = part.Read(buffer[..(int)Math.Min(buffer.Length, _starts[i + 1] - _position)]);
            if (n == 0) break;
            _position += n;
            total += n;
            buffer = buffer[n..];
        }
        return total;
    }

    public override long Seek(long offset, SeekOrigin origin)
        => Position = origin switch
        {
            SeekOrigin.Begin => offset,
            SeekOrigin.Current => _position + offset,
            _ => Length + offset,
        };

    public override void Flush() { }
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

    protected override void Dispose(bool disposing)
    {
        if (disposing) foreach (var p in _parts) p?.Dispose();
        base.Dispose(disposing);
    }
}

/// <summary>A requested ZIP disk or byte range belongs to an absent volume.</summary>
public sealed class MissingZipPartException(IReadOnlyList<string> parts) : IOException(
    $"Required ZIP part(s) missing: {string.Join(", ", parts.Select(Path.GetFileName))}. Put them in the same folder.")
{
    public IReadOnlyList<string> Parts { get; } = parts;
}
