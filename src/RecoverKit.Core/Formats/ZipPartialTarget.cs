namespace RecoverKit.Core.Formats;

/// <summary>
/// Archive data needed to confirm a bounded ZipCrypto hash against the whole entry.
/// <see cref="Siblings"/> contains <see cref="ZipPasswordConfirmer.HeaderChecks"/> from the session's
/// confirmer. Checking them before reading the archive cannot change the result: the confirmer
/// rejects every candidate that fails the same checks.
/// </summary>
public sealed record ZipPartialTarget(string ArchivePath, long DataOffset, long CompressedLength,
    long UncompressedLength, uint Crc, int Method)
{
    // Spanned positions stay relative to their disk when the available sibling set changes.
    public uint? ArchiveDisk { get; init; }

    internal Stream OpenData()
    {
        var stream = ZipArchiveSource.Open(ArchivePath);
        try
        {
            long offset = ArchiveDisk is { } disk
                ? (stream as MultiVolumeStream ?? throw new FormatException("ZIP parts have changed.")).DiskOffset(disk, DataOffset)
                : DataOffset;
            if (stream is MultiVolumeStream volumes) volumes.EnsureAvailable(offset, CompressedLength);
            if (offset < 0 || offset > stream.Length || CompressedLength > stream.Length - offset)
                throw new FormatException("ZIP entry is truncated.");
            stream.Position = offset;
            return stream;
        }
        catch { stream.Dispose(); throw; }
    }

    public IReadOnlyList<ZipHeaderCheck> Siblings { get; init; } = [];
}

/// <summary>
/// One ZipCrypto entry's 12-byte encryption header and the check bytes a right password decrypts its
/// last byte to (the CRC's high byte, or the DOS time's with a data descriptor).
/// </summary>
public sealed record ZipHeaderCheck(byte[] Header, byte CrcCheck, byte TimeCheck);
