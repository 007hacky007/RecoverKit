using System.Buffers.Binary;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using RecoverKit.Core.Formats;

namespace RecoverKit.Core.Native.Kernels;

/// <summary>7z AES with bounded decoding and a CRC check of the selected decoded prefix.</summary>
public sealed class SevenZipKernel(SevenZipCpuTarget target, CancellationToken stop = default) : NativeKernel
{
    private readonly CancellationToken _stop = stop;
    private readonly SemaphoreSlim fullDecode = new(1);
    private readonly SevenZipLzma.Buffers fullBuffers = new();
    private static readonly UTF8Encoding Utf8 = new(false, true);
    private static readonly uint[] CrcTable = CreateCrcTable();

    public override string Name => $"7-Zip AES-256 (SHA-256 x {1UL << target.Power:N0}, streaming CRC)";
    public override int MaxPasswordLength => 256;
    // One-thread M1 Pro estimate: KDF plus streaming AES/IEEE CRC at about 2 GB/s for unpadded Copy.
    public override double SpeedHint => 1.0 / ((1UL << target.Power) / (175.0 * 524288) +
        (target.Method == 0 && target.PackedSize == target.AesOutputSize ? target.CrcLength / 2_000_000_000.0 : 0));
    public override bool SupportsDictionaryPassword(ReadOnlySpan<byte> password)
    {
        try { return Utf8.GetCharCount(password) <= MaxPasswordLength; }
        catch (DecoderFallbackException) { return false; }
    }

    internal enum CheckResult { Header, Padding, Trial, Crc, Match }

    public override bool Verify(ReadOnlySpan<byte> password)
    {
        return CreatePasswordWorker().Verify(password);
    }

    internal CheckResult CheckKey(byte[] key, CancellationToken ct = default, SevenZipLzma.Buffers? trialBuffers = null)
    {
        try
        {
            if (ct.IsCancellationRequested) return CheckResult.Crc;
            using var file = target.Open();
            if (target.DataOffset < 0 || target.PackedSize < 16 || target.PackedSize % 16 != 0 ||
                target.DataOffset > file.Length - target.PackedSize)
                throw new IOException("The selected encrypted 7z stream is damaged or truncated. Open the archive again.");
            using var aes = Aes.Create(); aes.Key = key;
            file.Position = target.DataOffset;
            byte[] first = new byte[16]; ReadArchive(file, first);
            byte[] plain = aes.DecryptCbc(first, target.Iv, PaddingMode.None);
            if (target.Method == 1 && plain[0] != 0 || target.Method == 2 &&
                (plain[0] != 1 && plain[0] < 0xe0 || plain[0] >= 0xe0 && plain[6] != 0)) return CheckResult.Header;

            int padding = checked((int)(target.PackedSize - target.AesOutputSize));
            if (padding is < 0 or > 15) return CheckResult.Crc;
            if (padding != 0)
            {
                byte[] tail = new byte[target.PackedSize == 16 ? 16 : 32];
                file.Position = target.DataOffset + target.PackedSize - tail.Length;
                ReadArchive(file, tail);
                byte[] last = aes.DecryptCbc(tail.AsSpan(tail.Length - 16),
                    tail.Length == 16 ? target.Iv : tail.AsSpan(0, 16), PaddingMode.None);
                if (last.AsSpan(16 - padding).ContainsAnyExcept((byte)0)) return CheckResult.Padding;
            }

            if (target.Method is 1 or 2 or 7)
            {
                file.Position = target.DataOffset;
                int bytes = (int)Math.Min(65536, target.PackedSize);
                var prefix = new byte[bytes]; ReadArchive(file, prefix);
                byte[] decrypted = aes.DecryptCbc(prefix, target.Iv, PaddingMode.None);
                using var input = new MemoryStream(decrypted, 0, (int)Math.Min(bytes, target.AesOutputSize), writable: false);
                try
                {
                    using var trial = Decode(input, trialBuffers);
                    Span<byte> output = stackalloc byte[4096];
                    int need = (int)Math.Min(output.Length, target.CrcLength);
                    trial.ReadExactly(output[..need]);
                }
                // A bounded prefix can run out inside a valid symbol. Only a format violation rejects it.
                catch (EndOfStreamException) { }
                catch (Exception ex) when (ex is FormatException or InvalidDataException) { return CheckResult.Trial; }
            }

            // LZMA workers share a large history; Copy and Deflate have only bounded private buffers.
            bool needsHistory = target.Method is 1 or 2;
            if (needsHistory) fullDecode.Wait(ct);
            try
            {
                file.Position = target.DataOffset;
                using var encrypted = new LimitedReadStream(file, target.PackedSize, archive: true);
                // 7z stores zero padding, not PKCS7 padding.
                aes.Padding = PaddingMode.None;
                using var rawDecryptor = aes.CreateDecryptor(key, target.Iv);
                using var decryptedStream = new CryptoStream(encrypted, rawDecryptor, CryptoStreamMode.Read, leaveOpen: true);
                using var packed = new LimitedReadStream(decryptedStream, target.AesOutputSize);
                using var buffered = new BufferedStream(packed, 65536);
                using var decoded = Decode(buffered, needsHistory ? fullBuffers : null);
                var buffer = new byte[65536];
                long remaining = target.CrcLength;
                uint crc = uint.MaxValue;
                while (remaining > 0)
                {
                    if (ct.IsCancellationRequested) return CheckResult.Crc;
                    int n = decoded.Read(buffer, 0, (int)Math.Min(buffer.Length, remaining));
                    if (n == 0) return CheckResult.Crc;
                    crc = UpdateCrc(crc, buffer.AsSpan(0, n));
                    remaining -= n;
                }
                return ~crc == target.Crc ? CheckResult.Match : CheckResult.Crc;
            }
            finally { if (needsHistory) fullDecode.Release(); }
        }
        catch (Exception ex) when (ex is EndOfStreamException or InvalidDataException or FormatException or CryptographicException)
        { return CheckResult.Crc; }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { return CheckResult.Crc; }
    }

    // ARM CRC32 uses the IEEE polynomial. x86 SSE4.2 CRC32 uses CRC-32C and cannot be used here.
    internal static uint UpdateCrc(uint crc, ReadOnlySpan<byte> bytes)
    {
        if (!System.Runtime.Intrinsics.Arm.Crc32.Arm64.IsSupported) return UpdateCrcSoftware(crc, bytes);
        while (bytes.Length >= 8)
        {
            crc = System.Runtime.Intrinsics.Arm.Crc32.Arm64.ComputeCrc32(crc, BinaryPrimitives.ReadUInt64LittleEndian(bytes));
            bytes = bytes[8..];
        }
        foreach (byte b in bytes) crc = System.Runtime.Intrinsics.Arm.Crc32.ComputeCrc32(crc, b);
        return crc;
    }

    internal static uint UpdateCrcSoftware(uint crc, ReadOnlySpan<byte> bytes)
    {
        while (bytes.Length >= 8)
        {
            uint low = crc ^ BinaryPrimitives.ReadUInt32LittleEndian(bytes);
            uint high = BinaryPrimitives.ReadUInt32LittleEndian(bytes[4..]);
            crc = CrcTable[1792 + (low & 255)] ^ CrcTable[1536 + ((low >> 8) & 255)] ^
                CrcTable[1280 + ((low >> 16) & 255)] ^ CrcTable[1024 + (low >> 24)] ^
                CrcTable[768 + (high & 255)] ^ CrcTable[512 + ((high >> 8) & 255)] ^
                CrcTable[256 + ((high >> 16) & 255)] ^ CrcTable[high >> 24];
            bytes = bytes[8..];
        }
        foreach (byte b in bytes) crc = (crc >> 8) ^ CrcTable[(crc ^ b) & 255];
        return crc;
    }

    private static uint[] CreateCrcTable()
    {
        var table = new uint[8 * 256];
        for (int i = 0; i < 256; i++)
        {
            uint c = (uint)i;
            for (int bit = 0; bit < 8; bit++) c = (c >> 1) ^ ((c & 1) != 0 ? 0xedb88320u : 0);
            table[i] = c;
        }
        for (int i = 256; i < table.Length; i++)
        {
            uint c = table[i - 256];
            table[i] = (c >> 8) ^ table[c & 255];
        }
        return table;
    }

    private static void ReadArchive(Stream file, byte[] buffer)
    {
        try { file.ReadExactly(buffer); }
        catch (EndOfStreamException ex)
        { throw new IOException("The encrypted 7z stream was truncated while checking passwords. Open the archive again.", ex); }
    }

    private Stream Decode(Stream input, SevenZipLzma.Buffers? buffers = null) => target.Method switch
    {
        0 => new LimitedReadStream(input, target.OutputSize),
        1 or 2 => SevenZipLzma.Open(input, target.Properties, target.OutputSize, target.Method == 2, buffers),
        7 => new DeflateStream(input, CompressionMode.Decompress, leaveOpen: true),
        _ => throw new FormatException("Unsupported 7z compression method."),
    };

    internal static byte[] DeriveKey(ReadOnlySpan<byte> password, byte[] salt, int power,
        CancellationToken stop = default, byte[]? scratch = null)
    {
        if (power is < 0 or > 24 || salt.Length > 16) throw new ArgumentOutOfRangeException(nameof(power));
        byte[] utf16 = Encoding.Unicode.GetBytes(Utf8.GetString(password));
        if (utf16.Length > 512) throw new ArgumentOutOfRangeException(nameof(password));
        byte[] key = new byte[32];
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        int record = salt.Length + utf16.Length + 8;
        var buffer = scratch ?? new byte[65536];
        int count = buffer.Length / record;
        if (count == 0) throw new ArgumentException("KDF buffer is too small.", nameof(scratch));
        for (int i = 0; i < count; i++)
        {
            salt.CopyTo(buffer, i * record);
            utf16.CopyTo(buffer, i * record + salt.Length);
        }
        ulong rounds = 1UL << power;
        for (ulong i = 0; i < rounds;)
        {
            if (stop.IsCancellationRequested) return key;
            int n = (int)Math.Min((ulong)count, rounds - i);
            for (int j = 0; j < n; j++) BinaryPrimitives.WriteUInt64LittleEndian(buffer.AsSpan((j + 1) * record - 8), i++);
            hash.AppendData(buffer.AsSpan(0, n * record));
        }
        return hash.GetHashAndReset();
    }

    private byte[] DeriveWorkerKey(ReadOnlySpan<byte> password, byte[] buffer, CancellationToken stop)
        => DeriveKey(password, target.Salt, target.Power, stop, buffer);

    public override KernelWorker CreateWorker() => CreatePasswordWorker();
    public override KernelWorker CreateWorker(CancellationToken stop) => CreatePasswordWorker(stop);
    internal Worker CreatePasswordWorker() => new(this, _stop);
    internal Worker CreatePasswordWorker(CancellationToken stop) => new(this, stop);
    internal sealed class Worker(SevenZipKernel kernel, CancellationToken stop) : KernelWorker
    {
        private readonly SevenZipLzma.Buffers trialBuffers = new();
        private readonly byte[] kdfBuffer = new byte[65536];

        // Search returns a hit only after this instance's complete streaming CRC check.
        internal bool VerifiedBy(NativeKernel source) => ReferenceEquals(kernel, source);

        internal bool Verify(ReadOnlySpan<byte> password)
        {
            if (!kernel.SupportsDictionaryPassword(password) || stop.IsCancellationRequested) return false;
            byte[] key = kernel.DeriveWorkerKey(password, kdfBuffer, stop);
            return kernel.CheckKey(key, stop, trialBuffers) == CheckResult.Match;
        }

        public override int Search(ReadOnlySpan<byte> prefix, ReadOnlySpan<byte> last)
        {
            Span<byte> password = stackalloc byte[prefix.Length + 1]; prefix.CopyTo(password);
            for (int i = 0; i < last.Length; i++)
            {
                if (stop.IsCancellationRequested) return -1;
                password[^1] = last[i];
                if (Verify(password)) return i;
            }
            return -1;
        }
    }
}
