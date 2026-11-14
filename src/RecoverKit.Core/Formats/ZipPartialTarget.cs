namespace RecoverKit.Core.Formats;

/// <summary>
/// Archive data needed to confirm a bounded ZipCrypto hash against the whole entry.
/// <see cref="Siblings"/> are the archive's other ZipCrypto entries (encryption header and accepted
/// check bytes): a candidate that passes the attacked entry's header check (1 in 256) is tried on
/// them before the whole entry is decrypted from the file, which costs as much as thousands of
/// candidates.
/// </summary>
public sealed record ZipPartialTarget(string ArchivePath, long DataOffset, long CompressedLength,
    long UncompressedLength, uint Crc, int Method)
{
    public IReadOnlyList<ZipHeaderCheck> Siblings { get; init; } = [];
}

/// <summary>
/// One ZipCrypto entry's 12-byte encryption header and the check bytes a right password decrypts its
/// last byte to (the CRC's high byte, or the DOS time's with a data descriptor).
/// </summary>
public sealed record ZipHeaderCheck(byte[] Header, byte CrcCheck, byte TimeCheck);
