using System.Text.RegularExpressions;

namespace RecoverKit.Core.Formats;

/// <summary>
/// Read-only concatenation of ZIP or 7-Zip parts, read in place without joining them on disk.
/// PKZIP callers can also resolve offsets relative to an individual disk.
/// </summary>
public sealed partial class MultiVolumeStream : Stream
{
    private readonly FileStream[] _parts;
    private readonly long[] _starts;
    private long _position;

    public IReadOnlyList<string> Paths { get; }

    public bool DiskRelative { get; }

    internal long DiskOffset(uint disk, long offset)
    {
        if (disk >= _parts.Length || offset < 0 || offset >= _parts[disk].Length)
            throw new FormatException("ZIP disk number or offset is outside its part.");
        return checked(_starts[disk] + offset);
    }

    internal void ValidateDiskCount(uint count)
    {
        if (count != _parts.Length) throw new FormatException("ZIP disk count does not match its parts.");
    }

    public MultiVolumeStream(IReadOnlyList<string> paths, bool diskRelative = false)
    {
        if (paths.Count == 0) throw new ArgumentException("No parts.", nameof(paths));
        Paths = paths;
        DiskRelative = diskRelative;
        _parts = new FileStream[paths.Count];
        _starts = new long[paths.Count + 1];
        try
        {
            for (int i = 0; i < paths.Count; i++)
            {
                _parts[i] = new FileStream(paths[i], FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                _starts[i + 1] = _starts[i] + _parts[i].Length;
            }
        }
        catch
        {
            foreach (var p in _parts) p?.Dispose();
            throw;
        }
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
            int i = Array.BinarySearch(_starts, _position);
            if (i < 0) i = ~i - 1;
            // Empty parts share a start with the next one; skip to the part that holds the position.
            while (_starts[i + 1] <= _position) i++;
            var part = _parts[i];
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
        if (disposing) foreach (var p in _parts) p.Dispose();
        base.Dispose(disposing);
    }
}
