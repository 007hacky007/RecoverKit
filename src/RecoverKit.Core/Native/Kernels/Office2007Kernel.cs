using System.Buffers;
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace RecoverKit.Core.Native.Kernels;

/// <summary>ECMA-376 Standard Encryption: SHA-1 x 50000 and AES-128/256 (9400).</summary>
public sealed unsafe class Office2007Kernel : NativeKernel, INativeFilter
{
    private readonly int _keyBytes;
    private readonly byte[] _salt, _verifier, _verifierHash;

    private Office2007Kernel(int keyBytes, byte[] salt, byte[] verifier, byte[] verifierHash)
        => (_keyBytes, _salt, _verifier, _verifierHash) = (keyBytes, salt, verifier, verifierHash);

    public override string Name => $"Office 2007 AES-{_keyBytes * 8} (SHA-1 x 50000)";
    public override int MaxPasswordLength => 256;
    public override double SpeedHint => 300;
    internal static bool NativeFast => RkNative.Available;

    public static Office2007Kernel? TryParse(string hashLine)
    {
        if (string.IsNullOrWhiteSpace(hashLine)) return null;
        var f = hashLine.Trim().Split('*');
        // Match module_09400: it accepts 128/256-bit keys and exactly 20 hash bytes.
        if (f.Length != 8 || f[0] != "$office$" || f[1] != "2007" || f[2] != "20" ||
            f[3] is not ("128" or "256") || f[4] != "16" || f[5].Length != 32 ||
            f[6].Length != 32 || f[7].Length != 40) return null;
        try
        {
            return new Office2007Kernel(f[3] == "128" ? 16 : 32, Convert.FromHexString(f[5]),
                Convert.FromHexString(f[6]), Convert.FromHexString(f[7]));
        }
        catch (FormatException) { return null; }
    }

    private static int Encode(ReadOnlySpan<byte> password, Span<byte> utf16)
    {
        int written = 0;
        while (!password.IsEmpty)
        {
            int codePoint, consumed;
            if (Rune.DecodeFromUtf8(password, out var rune, out consumed) == OperationStatus.Done)
                codePoint = rune.Value;
            // hashcat 8's encoder accepts F4 90..BF and emits these raw surrogate units.
            else if (password.Length >= 4 && password[0] == 0xf4 && password[1] is >= 0x90 and <= 0xbf
                && password[2] is >= 0x80 and <= 0xbf && password[3] is >= 0x80 and <= 0xbf)
            {
                codePoint = (password[0] & 7) << 18 | (password[1] & 63) << 12 | (password[2] & 63) << 6 | (password[3] & 63);
                consumed = 4;
            }
            else return -1;
            if (codePoint > 0xffff)
            {
                codePoint -= 0x10000;
                BinaryPrimitives.WriteUInt16LittleEndian(utf16[written..], (ushort)(0xd800 + (codePoint >> 10)));
                written += 2;
                codePoint = 0xdc00 + (codePoint & 1023);
            }
            BinaryPrimitives.WriteUInt16LittleEndian(utf16[written..], (ushort)codePoint);
            written += 2;
            password = password[consumed..];
        }
        return written;
    }

    public override bool SupportsDictionaryPassword(ReadOnlySpan<byte> password)
    {
        if (password.Length > MaxPasswordLength) return false;
        Span<byte> utf16 = stackalloc byte[512];
        return Encode(password, utf16) >= 0;
    }

    /// <summary>Independent .NET SHA-1 and AES confirmation, including the complete spin chain.</summary>
    public override bool Verify(ReadOnlySpan<byte> password)
    {
        if (password.Length > MaxPasswordLength) return false;
        Span<byte> utf16 = stackalloc byte[512], hash = stackalloc byte[20];
        int length = Encode(password, utf16);
        if (length < 0) return false;
        SpinManaged(utf16[..length], _salt, hash);
        return CheckSpin(hash);
    }

    internal static void SpinManaged(ReadOnlySpan<byte> utf16Password, ReadOnlySpan<byte> salt, Span<byte> hash)
    {
        using var sha1 = IncrementalHash.CreateHash(HashAlgorithmName.SHA1);
        sha1.AppendData(salt);
        sha1.AppendData(utf16Password);
        sha1.GetHashAndReset(hash);
        Span<byte> index = stackalloc byte[4];
        for (int i = 0; i < 50000; i++)
        {
            BinaryPrimitives.WriteInt32LittleEndian(index, i);
            sha1.AppendData(index);
            sha1.AppendData(hash);
            sha1.GetHashAndReset(hash);
        }
    }

    private bool CheckSpin(ReadOnlySpan<byte> spin)
    {
        Span<byte> finalInput = stackalloc byte[24], final = stackalloc byte[20];
        finalInput.Clear();
        spin.CopyTo(finalInput);
        SHA1.HashData(finalInput, final);
        Span<byte> pad = stackalloc byte[64], key = stackalloc byte[40];
        pad.Fill(0x36);
        for (int i = 0; i < 20; i++) pad[i] ^= final[i];
        SHA1.HashData(pad, key[..20]);
        if (_keyBytes > 20)
        {
            pad.Fill(0x5c);
            for (int i = 0; i < 20; i++) pad[i] ^= final[i];
            SHA1.HashData(pad, key[20..]);
        }
        using var aes = Aes.Create();
        aes.Key = key[.._keyBytes].ToArray();
        Span<byte> verifier = stackalloc byte[16], expected = stackalloc byte[16], digest = stackalloc byte[20];
        aes.DecryptEcb(_verifier, verifier, PaddingMode.None);
        aes.DecryptEcb(_verifierHash.AsSpan(0, 16), expected, PaddingMode.None);
        SHA1.HashData(verifier, digest);
        // The hashcat line truncates the second AES block. Its first block gives a 128-bit check.
        return CryptographicOperations.FixedTimeEquals(digest[..16], expected);
    }

    public override KernelWorker CreateWorker() => new NativeFilterWorker(this, this, new ReferenceWorker(this));
    public override int PrefixBatch(int lastCount) => RkNative.BatchFor(lastCount, 64);

    int INativeFilter.Filter(byte* pws, int len, int n, int* hits, int maxHits)
    {
        if (!RkNative.Available || len < 0 || len > MaxPasswordLength || n < 0) return -1;
        byte* utf16 = stackalloc byte[64 * 512];
        byte* hashes = stackalloc byte[64 * 20];
        int* lengths = stackalloc int[64];
        Span<bool> valid = stackalloc bool[64];
        int found = 0;
        fixed (byte* salt = _salt)
        {
            for (int offset = 0; offset < n; offset += 64)
            {
                int count = Math.Min(64, n - offset);
                for (int i = 0; i < count; i++)
                {
                    int length = Encode(new ReadOnlySpan<byte>(pws + (offset + i) * len, len), new Span<byte>(utf16 + i * 512, 512));
                    valid[i] = length >= 0;
                    lengths[i] = Math.Max(0, length);
                }
                if (RkNative.Office2007Spin(utf16, 512, lengths, count, salt, hashes) != 0) return -1;
                for (int i = 0; i < count; i++)
                {
                    if (!valid[i] || !CheckSpin(new ReadOnlySpan<byte>(hashes + i * 20, 20))) continue;
                    if (found == maxHits) return maxHits + 1;
                    hits[found++] = offset + i;
                }
            }
        }
        return found;
    }

    private sealed class ReferenceWorker(Office2007Kernel kernel) : KernelWorker
    {
        public override int SearchPasswords(ReadOnlySpan<byte> passwords, int length, int count)
        {
            for (int i = 0; i < count; i++)
                if (kernel.Verify(passwords.Slice(i * length, length))) return i;
            return -1;
        }

        public override int Search(ReadOnlySpan<byte> prefix, ReadOnlySpan<byte> last)
        {
            if (prefix.Length >= kernel.MaxPasswordLength) return -1;
            Span<byte> password = stackalloc byte[prefix.Length + 1];
            prefix.CopyTo(password);
            for (int i = 0; i < last.Length; i++)
            {
                password[^1] = last[i];
                if (kernel.Verify(password)) return i;
            }
            return -1;
        }
    }
}
