namespace RecoverKit.Core.Formats;

/// <summary>Archive data needed to confirm a bounded ZipCrypto hash against the whole entry.</summary>
public sealed record ZipPartialTarget(string ArchivePath, long DataOffset, long CompressedLength,
    long UncompressedLength, uint Crc, int Method);
