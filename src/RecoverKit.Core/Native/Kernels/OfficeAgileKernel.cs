using System.Buffers.Binary;
using System.Security.Cryptography;

namespace RecoverKit.Core.Native.Kernels;

/// <summary>ECMA-376 Agile Encryption: SHA-1 (9500) or SHA-512 (9600) and AES-CBC.</summary>
public sealed unsafe class OfficeAgileKernel : NativeKernel, INativeFilter
{
    private readonly byte[] _salt, _verifier, _verifierHash;
    private int HashBytes => Mode == 9500 ? 20 : 64;
    private int KeyBytes => Mode == 9500 ? 16 : 32;
    public int Mode { get; }

    private OfficeAgileKernel(int mode, byte[] salt, byte[] verifier, byte[] verifierHash)
        => (Mode, _salt, _verifier, _verifierHash) = (mode, salt, verifier, verifierHash);

    public override string Name => Mode == 9500
        ? "Office 2010 AES-128 (SHA-1 x 100000)" : "Office 2013+ AES-256 (SHA-512 x 100000)";
    public override int MaxPasswordLength => 256;
    public override double SpeedHint => Mode == 9500 ? 200 : 100;
    internal static bool NativeFast => RkNative.Available;
    internal static bool SupportsMode(int mode) => mode is 9500 or 9600;

    public static OfficeAgileKernel? TryParse(string hashLine)
    {
        if (string.IsNullOrWhiteSpace(hashLine)) return null;
        var f = hashLine.Trim().Split('*');
        // Match hashcat 8 module_09500/module_09600 exactly. Other variants stay with hashcat.
        if (f.Length != 8 || f[0] != "$office$" || f[2] != "100000" || f[4] != "16" ||
            f[5].Length != 32 || f[6].Length != 32 || f[7].Length != 64) return null;
        int mode = (f[1], f[3]) switch { ("2010", "128") => 9500, ("2013", "256") => 9600, _ => 0 };
        if (mode == 0) return null;
        try
        {
            return new OfficeAgileKernel(mode, Convert.FromHexString(f[5]),
                Convert.FromHexString(f[6]), Convert.FromHexString(f[7]));
        }
        catch (FormatException) { return null; }
    }

    public override bool SupportsDictionaryPassword(ReadOnlySpan<byte> password)
    {
        if (password.Length > MaxPasswordLength) return false;
        Span<byte> utf16 = stackalloc byte[512];
        return Office2007Kernel.Encode(password, utf16) >= 0;
    }

    /// <summary>Independent .NET SHA and AES confirmation, including all 100000 spins.</summary>
    public override bool Verify(ReadOnlySpan<byte> password)
    {
        if (password.Length > MaxPasswordLength) return false;
        Span<byte> utf16 = stackalloc byte[512], hash = stackalloc byte[64];
        int length = Office2007Kernel.Encode(password, utf16);
        if (length < 0) return false;
        SpinManaged(utf16[..length], _salt, Mode, 100000, hash[..HashBytes]);
        return CheckSpin(hash[..HashBytes]);
    }

    internal static void SpinManaged(ReadOnlySpan<byte> utf16Password, ReadOnlySpan<byte> salt,
        int mode, uint spins, Span<byte> hash)
    {
        if (!SupportsMode(mode)) throw new ArgumentOutOfRangeException(nameof(mode));
        hash = hash[..(mode == 9500 ? 20 : 64)];
        using var sha = IncrementalHash.CreateHash(mode == 9500 ? HashAlgorithmName.SHA1 : HashAlgorithmName.SHA512);
        sha.AppendData(salt);
        sha.AppendData(utf16Password);
        sha.GetHashAndReset(hash);
        Span<byte> index = stackalloc byte[4];
        for (uint i = 0; i < spins; i++)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(index, i);
            sha.AppendData(index);
            sha.AppendData(hash);
            sha.GetHashAndReset(hash);
        }
    }

    private void Hash(ReadOnlySpan<byte> data, Span<byte> digest)
    {
        if (Mode == 9500) SHA1.HashData(data, digest);
        else SHA512.HashData(data, digest);
    }

    private bool CheckSpin(ReadOnlySpan<byte> spin)
    {
        Span<byte> input = stackalloc byte[72], key = stackalloc byte[64];
        spin.CopyTo(input);
        ReadOnlySpan<byte> inputBlockKey = [0xfe, 0xa7, 0xd2, 0x76, 0x3b, 0x4b, 0x9e, 0x79];
        inputBlockKey.CopyTo(input[HashBytes..]);
        Hash(input[..(HashBytes + 8)], key);
        using var aes = Aes.Create();
        aes.Key = key[..KeyBytes].ToArray();
        Span<byte> verifier = stackalloc byte[16], digest = stackalloc byte[64], expected = stackalloc byte[16];
        aes.DecryptCbc(_verifier, _salt, verifier, PaddingMode.None);
        Hash(verifier, digest);
        ReadOnlySpan<byte> hashBlockKey = [0xd7, 0xaa, 0x0f, 0x6d, 0x30, 0x61, 0x34, 0x4e];
        hashBlockKey.CopyTo(input[HashBytes..]);
        Hash(input[..(HashBytes + 8)], key);
        aes.Key = key[..KeyBytes].ToArray();
        // Both hashcat 8 kernels compare the first CBC block, a 128-bit check.
        aes.DecryptCbc(_verifierHash.AsSpan(0, 16), _salt, expected, PaddingMode.None);
        return CryptographicOperations.FixedTimeEquals(digest[..16], expected);
    }

    public override KernelWorker CreateWorker() => new NativeFilterWorker(this, this, new ReferenceWorker(this));
    public override int PrefixBatch(int lastCount) => RkNative.BatchFor(lastCount, 64);

    int INativeFilter.Filter(byte* pws, int len, int n, int* hits, int maxHits)
    {
        if (!RkNative.Available || len < 0 || len > MaxPasswordLength || n < 0) return -1;
        byte* utf16 = stackalloc byte[64 * 512];
        byte* hashes = stackalloc byte[64 * 64];
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
                    int length = Office2007Kernel.Encode(new ReadOnlySpan<byte>(pws + (offset + i) * len, len),
                        new Span<byte>(utf16 + i * 512, 512));
                    valid[i] = length >= 0;
                    lengths[i] = Math.Max(0, length);
                }
                if (RkNative.OfficeAgileSpin(Mode, utf16, 512, lengths, count, salt, 100000, hashes) != 0) return -1;
                for (int i = 0; i < count; i++)
                {
                    if (!valid[i] || !CheckSpin(new ReadOnlySpan<byte>(hashes + i * HashBytes, HashBytes))) continue;
                    if (found == maxHits) return maxHits + 1;
                    hits[found++] = offset + i;
                }
            }
        }
        return found;
    }

    private sealed class ReferenceWorker(OfficeAgileKernel kernel) : KernelWorker
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
