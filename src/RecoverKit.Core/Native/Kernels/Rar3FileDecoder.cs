using System.Runtime.CompilerServices;
using System.Runtime.ExceptionServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using RecoverKit.Core.Formats;

namespace RecoverKit.Core.Native.Kernels;

internal static unsafe class Rar3FileDecoder
{
    private static readonly uint[] CrcTable = MakeCrcTable();
    // One process-wide PPM model, at most 256 MiB, instead of one per attack thread.
    private static readonly SemaphoreSlim PpmGate = new(1, 1);
    private static void* PpmArena;
    private static nuint PpmCapacity;

    internal static (bool Match, int Stage) Check(Rar3FileTarget target, ReadOnlySpan<byte> digest,
        ReadOnlySpan<byte> iv, CancellationToken ct = default)
    {
        bool retry = false;
        while (true)
        {
            ct.ThrowIfCancellationRequested();
            bool serial = retry;
            if (serial) PpmGate.Wait(ct);
            try { return CheckAttempt(target, digest, iv, ct, serial); }
            catch (OutOfMemoryException) { retry = true; }
            finally { if (serial) PpmGate.Release(); }
            // Retry the same key from the start. Neither progress nor checkpoints may pass it.
            if (ct.WaitHandle.WaitOne(100)) ct.ThrowIfCancellationRequested();
        }
    }

    private static (bool Match, int Stage) CheckAttempt(Rar3FileTarget target, ReadOnlySpan<byte> digest,
        ReadOnlySpan<byte> iv, CancellationToken ct, bool gateHeld)
    {
        if (target.Method != 0x30 && !RkNative.Available)
            throw new NotSupportedException("Compressed RAR 3 files larger than hashcat's limit need the native RAR decoder. Rebuild or reinstall RecoverKit's native library.");
        using var file = new FileStream(target.ArchivePath, FileMode.Open, FileAccess.Read, FileShare.Read,
            4096, FileOptions.SequentialScan);
        if (target.DataOffset < 0 || target.PackedLength <= 0 || target.PackedLength % 16 != 0 ||
            target.UnpackedLength <= 0 || target.DataOffset > file.Length ||
            target.PackedLength > file.Length - target.DataOffset)
            throw new InvalidDataException("The selected encrypted RAR 3 entry is damaged or truncated.");
        file.Position = target.DataOffset;
        using var aes = Aes.Create();
        var key = new byte[16];
        for (int i = 0; i < key.Length; i++) key[i] = digest[(i & ~3) + 3 - (i & 3)];
        aes.Key = key;
        aes.IV = iv.ToArray();
        aes.Padding = PaddingMode.None;
        using var transform = aes.CreateDecryptor();
        using var bounded = new EntryStream(file, target.PackedLength);
        using var plain = new CryptoStream(bounded, transform, CryptoStreamMode.Read);
        if (target.Method == 0x30)
        {
            if (target.PackedLength != (target.UnpackedLength + 15) / 16 * 16)
                throw new InvalidDataException("The stored RAR 3 entry has inconsistent sizes.");
            var buffer = new byte[64 * 1024];
            long remaining = target.UnpackedLength;
            uint crc = uint.MaxValue;
            while (remaining > 0)
            {
                ct.ThrowIfCancellationRequested();
                int n = plain.Read(buffer, 0, (int)Math.Min(buffer.Length, remaining));
                if (n == 0) throw new InvalidDataException("The stored RAR 3 entry is truncated.");
                for (int i = 0; i < n; i++) crc = CrcTable[(crc ^ buffer[i]) & 255] ^ (crc >> 8);
                remaining -= n;
            }
            bool match = (crc ^ uint.MaxValue) == target.Crc;
            return (match, match ? 3 : 2);
        }
        var reader = new Reader(plain, ct) { HasArena = gateHeld };
        var handle = GCHandle.Alloc(reader);
        try
        {
            int stage = 0;
            int result = RkNative.Rar3DecodeStreamAlloc(&Read, GCHandle.ToIntPtr(handle), (ulong)target.PackedLength,
                (ulong)target.UnpackedLength, (uint)target.DictionarySize, target.Crc, &stage, &AllocatePpm);
            if (reader.Error is { } error) ExceptionDispatchInfo.Capture(error).Throw();
            return result switch
            {
                0 => (false, stage),
                1 => (true, stage),
                -1 => throw new NotSupportedException("The encrypted RAR 3 entry uses a filter block or pending filter queue beyond the CPU decoder's bounded limits."),
                -4 => throw new NotSupportedException("The RAR 3 filter points outside the current file or uses a deferred dictionary window the streaming CPU decoder cannot schedule."),
                -5 => throw new NotSupportedException("The RAR 3 entry has overlapping filter blocks with different positions or lengths the streaming CPU decoder cannot combine."),
                -6 => throw new NotSupportedException("The RAR 3 entry uses nonstandard filter register values or an RGB row width not aligned to its three channels."),
                -7 => throw new NotSupportedException("The RAR 3 entry resets its compression filters after output has started; the CPU decoder cannot verify that filter layout."),
                -3 => throw new OutOfMemoryException("The CPU is waiting for memory to check this RAR 3 candidate."),
                _ => throw new InvalidDataException("The CPU could not read the encrypted RAR 3 entry."),
            };
        }
        finally
        {
            handle.Free();
            if (reader.HasArena && !gateHeld) PpmGate.Release();
        }
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static void* AllocatePpm(nint opaque, nuint size)
    {
        var reader = (Reader)GCHandle.FromIntPtr(opaque).Target!;
        try
        {
            if (!reader.HasArena)
            {
                PpmGate.Wait(reader.Token);
                reader.HasArena = true;
            }
            reader.Token.ThrowIfCancellationRequested();
            if (size > PpmCapacity)
            {
                // A PPM reset discards the old model; never hold both allocations while growing.
                NativeMemory.Free(PpmArena);
                PpmArena = null;
                PpmCapacity = 0;
                PpmArena = NativeMemory.Alloc(size);
                PpmCapacity = size;
            }
            return PpmArena;
        }
        catch (OutOfMemoryException) { return null; }
        catch (Exception ex) { reader.Error = ex; return null; }
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static int Read(nint opaque, byte* buffer, int length)
    {
        var reader = (Reader)GCHandle.FromIntPtr(opaque).Target!;
        try
        {
            reader.Token.ThrowIfCancellationRequested();
            if (length == 0) return 0;
            return reader.Stream.Read(new Span<byte>(buffer, length));
        }
        catch (Exception ex) { reader.Error = ex; return -1; }
    }

    private sealed class Reader(Stream stream, CancellationToken token)
    {
        internal Stream Stream { get; } = stream;
        internal CancellationToken Token { get; } = token;
        internal Exception? Error { get; set; }
        internal bool HasArena { get; set; }
    }

    private sealed class EntryStream(Stream source, long remaining) : Stream
    {
        public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));
        public override int Read(Span<byte> buffer)
        {
            int read = source.Read(buffer[..(int)Math.Min(buffer.Length, remaining)]);
            remaining -= read;
            return read;
        }
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }

    private static uint[] MakeCrcTable()
    {
        var table = new uint[256];
        for (uint i = 0; i < 256; i++)
        {
            uint c = i;
            for (int bit = 0; bit < 8; bit++) c = (c & 1) != 0 ? 0xedb88320 ^ (c >> 1) : c >> 1;
            table[i] = c;
        }
        return table;
    }
}
