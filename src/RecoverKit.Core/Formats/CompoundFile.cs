using System.Text;

namespace RecoverKit.Core.Formats;

/// <summary>
/// Minimal read-only MS-CFB (OLE2 compound file) reader. Supports 512 and 4096 byte
/// sectors, DIFAT chains and the mini stream. Reads sectors on demand from a stream,
/// so large encrypted packages are not loaded into memory.
/// </summary>
public sealed class CompoundFile
{
    private const uint MaxRegSect = 0xFFFFFFFA;
    private static readonly byte[] Signature = [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];

    private readonly Stream _s;
    private readonly int _sectorSize;
    private readonly int _miniSectorSize;
    private readonly uint _miniCutoff;
    private readonly uint[] _fat;
    private readonly uint[] _miniFat;
    private readonly byte[] _miniStream;

    public sealed record Entry(string Name, int Type, uint Start, long Size);

    public IReadOnlyList<Entry> Entries { get; }

    public static bool IsCompoundFile(ReadOnlySpan<byte> head)
        => head.Length >= 8 && head[..8].SequenceEqual(Signature);

    public CompoundFile(Stream s)
    {
        _s = s;
        var h = Bin.ReadAt(s, 0, 512);
        if (h.Length < 512 || !IsCompoundFile(h)) throw new FormatException("Not an OLE compound file.");

        int sectorShift = Bin.U16(h, 0x1E), miniShift = Bin.U16(h, 0x20);
        if (sectorShift is not (9 or 12) || miniShift != 6) throw new FormatException("Unsupported compound file sector size.");
        _sectorSize = 1 << sectorShift;
        _miniSectorSize = 1 << miniShift;

        uint numFat = Bin.U32(h, 0x2C), firstDir = Bin.U32(h, 0x30);
        _miniCutoff = Bin.U32(h, 0x38);
        uint firstMiniFat = Bin.U32(h, 0x3C), firstDifat = Bin.U32(h, 0x44), numDifat = Bin.U32(h, 0x48);

        var fatSectors = new List<uint>();
        for (int i = 0; i < 109 && fatSectors.Count < numFat; i++)
        {
            uint sid = Bin.U32(h, 0x4C + i * 4);
            if (sid < MaxRegSect) fatSectors.Add(sid);
        }
        uint dif = firstDifat;
        for (uint guard = 0; dif < MaxRegSect && guard <= numDifat && fatSectors.Count < numFat; guard++)
        {
            var sec = ReadSector(dif);
            int n = _sectorSize / 4 - 1;
            for (int i = 0; i < n && fatSectors.Count < numFat; i++)
            {
                uint sid = Bin.U32(sec, i * 4);
                if (sid < MaxRegSect) fatSectors.Add(sid);
            }
            dif = Bin.U32(sec, n * 4);
        }

        int perSector = _sectorSize / 4;
        _fat = new uint[fatSectors.Count * perSector];
        for (int k = 0; k < fatSectors.Count; k++)
        {
            var sec = ReadSector(fatSectors[k]);
            for (int i = 0; i < perSector; i++) _fat[k * perSector + i] = Bin.U32(sec, i * 4);
        }

        var dir = ReadRegular(firstDir, long.MaxValue);
        var entries = new List<Entry>();
        for (int off = 0; off + 128 <= dir.Length; off += 128)
        {
            int nameLen = Bin.U16(dir, off + 64);
            int type = dir[off + 66];
            if (type == 0) { entries.Add(new Entry("", 0, 0, 0)); continue; }
            string name = nameLen >= 2 && nameLen <= 64
                ? Encoding.Unicode.GetString(dir, off, nameLen - 2)
                : "";
            uint start = Bin.U32(dir, off + 116);
            long size = _sectorSize == 512 ? Bin.U32(dir, off + 120) : (long)Bin.U64(dir, off + 120);
            entries.Add(new Entry(name, type, start, size));
        }
        if (entries.Count == 0 || entries[0].Type != 5) throw new FormatException("Compound file has no root entry.");
        Entries = entries;

        _miniFat = firstMiniFat < MaxRegSect ? ToU32(ReadRegular(firstMiniFat, long.MaxValue)) : [];
        var root = entries[0];
        _miniStream = root.Start < MaxRegSect && root.Size > 0 ? ReadRegular(root.Start, root.Size) : [];
    }

    public bool HasStream(string name) => Find(name) is not null;

    public Entry? Find(string name)
        => Entries.FirstOrDefault(e => e.Type == 2 && string.Equals(e.Name, name, StringComparison.OrdinalIgnoreCase));

    /// <summary>Reads a whole stream, or at most <paramref name="maxBytes"/> bytes of it.</summary>
    public byte[]? ReadStream(string name, long maxBytes = long.MaxValue)
    {
        var e = Find(name);
        if (e is null) return null;
        long size = Math.Min(e.Size, maxBytes);
        if (size > int.MaxValue) throw new FormatException("Stream is too large.");
        return e.Size < _miniCutoff ? ReadMini(e.Start, size) : ReadRegular(e.Start, size);
    }

    /// <summary>Patches existing bytes only; stream sizes, directory entries and allocation stay unchanged.</summary>
    internal void WriteStreamRange(string name, long offset, byte[] data)
    {
        var entry = Find(name) ?? throw new FormatException($"Missing compound stream '{name}'.");
        if (offset < 0 || offset > entry.Size - data.Length) throw new FormatException("Patch is outside the compound stream.");
        bool mini = entry.Size < _miniCutoff;
        int blockSize = mini ? _miniSectorSize : _sectorSize;
        var chunks = new List<(long Position, int Offset, int Count)>();
        for (int done = 0; done < data.Length;)
        {
            long logical = offset + done;
            uint sid = SectorAt(entry.Start, logical / blockSize, mini ? _miniFat : _fat);
            long position = mini ? (long)sid * _miniSectorSize + logical % blockSize : logical % blockSize;
            if (mini)
            {
                if (position + Math.Min(blockSize - logical % blockSize, data.Length - done) > Entries[0].Size)
                    throw new FormatException("Patch is outside the compound mini stream.");
                sid = SectorAt(Entries[0].Start, position / _sectorSize, _fat);
                position %= _sectorSize;
            }
            position += ((long)sid + 1) * _sectorSize;
            int count = (int)Math.Min(blockSize - logical % blockSize, data.Length - done);
            if (position > _s.Length - count) throw new FormatException("Patch sector is outside the file.");
            chunks.Add((position, done, count));
            done += count;
        }
        foreach (var chunk in chunks)
        {
            _s.Position = chunk.Position;
            _s.Write(data, chunk.Offset, chunk.Count);
        }
    }

    private static uint SectorAt(uint start, long index, uint[] fat)
    {
        if (index < 0 || index >= fat.Length) throw new FormatException("Invalid compound stream offset.");
        var seen = new HashSet<uint>();
        uint sid = start;
        for (long i = 0; i <= index; i++)
        {
            if (sid >= fat.Length || !seen.Add(sid)) throw new FormatException("Invalid compound stream chain.");
            if (i == index) return sid;
            sid = fat[sid];
        }
        throw new FormatException("Invalid compound stream chain.");
    }

    /// <summary>Replaces stream bytes in an existing copy without reallocating sectors.</summary>
    internal void WriteStreamSameLength(string name, ReadOnlySpan<byte> data, Stream destination)
    {
        var entry = Find(name) ?? throw new FormatException("Compound stream is missing.");
        if (data.Length != entry.Size) throw new FormatException("Compound stream length must not change.");
        bool mini = entry.Size < _miniCutoff;
        var chain = mini ? _miniFat : _fat;
        int unit = mini ? _miniSectorSize : _sectorSize;
        uint sid = entry.Start;
        var seen = new HashSet<uint>();
        for (int offset = 0; offset < data.Length; offset += unit)
        {
            if (sid >= chain.Length || !seen.Add(sid)) throw new FormatException("Invalid compound stream chain.");
            long physical;
            if (mini)
            {
                long logical = (long)sid * _miniSectorSize;
                if (logical + unit > _miniStream.Length) throw new FormatException("Invalid compound mini sector.");
                uint rootSector = Entries[0].Start;
                for (long skip = logical / _sectorSize; skip > 0; skip--)
                {
                    if (rootSector >= _fat.Length) throw new FormatException("Invalid compound root chain.");
                    rootSector = _fat[rootSector];
                }
                if (rootSector >= _fat.Length) throw new FormatException("Invalid compound root sector.");
                physical = ((long)rootSector + 1) * _sectorSize + logical % _sectorSize;
            }
            else physical = ((long)sid + 1) * _sectorSize;
            int count = Math.Min(unit, data.Length - offset);
            if (physical + count > destination.Length) throw new FormatException("Truncated compound stream sector.");
            destination.Position = physical;
            destination.Write(data.Slice(offset, count));
            sid = chain[sid];
        }
    }

    private byte[] ReadSector(uint sid)
    {
        long off = ((long)sid + 1) * _sectorSize;
        if (off >= _s.Length) throw new FormatException("Compound file sector is outside of file.");
        var b = Bin.ReadAt(_s, off, _sectorSize);
        if (b.Length < _sectorSize) Array.Resize(ref b, _sectorSize);
        return b;
    }

    private byte[] ReadRegular(uint start, long size)
    {
        using var ms = new MemoryStream();
        uint sid = start;
        int guard = 0;
        while (sid < MaxRegSect && ms.Length < size)
        {
            if (guard++ > _fat.Length) throw new FormatException("Corrupted compound file (FAT loop).");
            if (sid >= _fat.Length) throw new FormatException("Corrupted compound file (bad sector id).");
            var sec = ReadSector(sid);
            ms.Write(sec, 0, (int)Math.Min(sec.Length, size - ms.Length));
            sid = _fat[sid];
        }
        return ms.ToArray();
    }

    private byte[] ReadMini(uint start, long size)
    {
        using var ms = new MemoryStream();
        uint sid = start;
        int guard = 0;
        while (sid < MaxRegSect && ms.Length < size)
        {
            if (guard++ > _miniFat.Length) throw new FormatException("Corrupted compound file (mini FAT loop).");
            long off = (long)sid * _miniSectorSize;
            if (sid >= _miniFat.Length || off + _miniSectorSize > _miniStream.Length)
                throw new FormatException("Corrupted compound file (bad mini sector id).");
            ms.Write(_miniStream, (int)off, (int)Math.Min(_miniSectorSize, size - ms.Length));
            sid = _miniFat[sid];
        }
        return ms.ToArray();
    }

    private static uint[] ToU32(byte[] b)
    {
        var r = new uint[b.Length / 4];
        for (int i = 0; i < r.Length; i++) r[i] = Bin.U32(b, i * 4);
        return r;
    }
}
