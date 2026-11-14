namespace RecoverKit.Core.Formats;

/// <summary>A complete RAR 3 entry checked on the processor when it exceeds hashcat's limits.</summary>
public sealed record Rar3FileTarget(string ArchivePath, long DataOffset, long PackedLength,
    long UnpackedLength, int Method, int DictionarySize, byte[] Salt, uint Crc);
