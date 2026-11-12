namespace RecoverKit.Core.Formats;

/// <summary>One classic ZipCrypto entry's stored encryption header and metadata, for Stay's header-RNG attack.</summary>
public sealed class ZipStayEntry
{
    public required string Name { get; init; }
    /// <summary>The stored (still encrypted) 12-byte encryption header.</summary>
    public required byte[] StoredHeader { get; init; }
    public uint Crc { get; init; }
    public ushort Flags { get; init; }
    public ushort Method { get; init; }
    public long CompSize { get; init; }
    public long UncompSize { get; init; }
    public long LocalOffset { get; init; }
    /// <summary>Absolute offset of the encrypted body (12-byte header + data) in the archive file.</summary>
    public long DataOffset { get; init; }

    /// <summary>False for data-descriptor entries (flag bit 3): their check bytes may be time-based, not CRC-based.</summary>
    public bool HasCrcCheckBytes => (Flags & 8) == 0;
}

/// <summary>
/// Every classic ZipCrypto entry of a ZIP archive in central-directory (archive) order -
/// the payload for Stay's attack on the weak rand()-seeded encryption headers.
/// </summary>
public sealed class ZipStayTarget
{
    public required IReadOnlyList<ZipStayEntry> Entries { get; init; }
}
