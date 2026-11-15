namespace RecoverKit.Core.Formats;

/// <summary>A 7z AES stream checked locally when none of the archive's streams fits hashcat.</summary>
public sealed record SevenZipCpuTarget(IReadOnlyList<string> Paths, long DataOffset, long PackedSize,
    long AesOutputSize, long OutputSize, long CrcLength, uint Crc, int Method, byte[] Properties,
    int Power, byte[] Salt, byte[] Iv)
{
    internal Stream Open() => Paths.Count == 1 ? File.OpenRead(Paths[0]) : new MultiVolumeStream(Paths);
}

/// <summary>A non-owning bounded view. Premature EOF is an error, including during trial decoding.</summary>
internal sealed class LimitedReadStream(Stream input, long length, bool archive = false) : Stream
{
    private readonly long _length = length;
    internal long Remaining { get; private set; } = length;
    public override int Read(Span<byte> buffer)
    {
        int count = (int)Math.Min(buffer.Length, Remaining);
        if (count == 0) return 0;
        int n = input.Read(buffer[..count]);
        if (n == 0) Truncated();
        Remaining -= n;
        return n;
    }
    public override int ReadByte()
    {
        if (Remaining == 0) return -1;
        int b = input.ReadByte();
        if (b < 0) Truncated();
        Remaining--;
        return b;
    }
    public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));
    private void Truncated()
    {
        if (archive) throw new IOException("The encrypted 7z stream was truncated while checking passwords. Open the archive again.");
        throw new EndOfStreamException("Truncated 7z stream.");
    }
    public override bool CanRead => true;
    public override bool CanSeek => false;
    public override bool CanWrite => false;
    public override long Length => _length;
    public override long Position { get => _length - Remaining; set => throw new NotSupportedException(); }
    public override void Flush() { }
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
}
