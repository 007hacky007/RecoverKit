using System.Globalization;
using System.Security.Cryptography;

namespace RecoverKit.Core.Native.Kernels;

/// <summary>WinZip AES (13600): PBKDF2-SHA1 verifier filtering followed by full ciphertext HMAC confirmation.</summary>
public sealed unsafe class WinZipAesKernel : NativeKernel, INativeFilter
{
    private readonly byte[] _salt, _verifier, _data, _auth;
    private readonly int _keyBytes;

    private WinZipAesKernel(int keyBytes, byte[] salt, byte[] verifier, byte[] data, byte[] auth)
        => (_keyBytes, _salt, _verifier, _data, _auth) = (keyBytes, salt, verifier, data, auth);

    public override string Name => $"WinZip AES-{_keyBytes * 8} (PBKDF2-HMAC-SHA1 x 1000)";
    public override int MaxPasswordLength => 256;
    public override double SpeedHint => 3000;
    internal static bool NativeFast => RkNative.Available;

    public static WinZipAesKernel? TryParse(string hashLine)
    {
        if (string.IsNullOrWhiteSpace(hashLine)) return null;
        var f = hashLine.Trim().Split('*');
        if (f.Length != 10 || f[0] != "$zip2$" || f[1] != "0" || f[3] != "0" || f[9] != "$/zip2$") return null;
        int keyBytes = f[2] switch { "1" => 16, "2" => 24, "3" => 32, _ => 0 };
        if (keyBytes == 0 || f[4].Length != keyBytes || f[5].Length != 4 || f[8].Length != 20) return null;
        if (f[6].Length is < 1 or > 8 || !uint.TryParse(f[6], NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture, out uint length)
            || (f[7].Length & 1) != 0 || length != f[7].Length / 2) return null;
        try
        {
            return new WinZipAesKernel(keyBytes, Convert.FromHexString(f[4]), Convert.FromHexString(f[5]),
                Convert.FromHexString(f[7]), Convert.FromHexString(f[8]));
        }
        catch (FormatException) { return null; }
    }

    /// <summary>Independent managed reference, including the complete 80-bit authentication code.</summary>
    public override bool Verify(ReadOnlySpan<byte> password)
    {
        if (password.Length > MaxPasswordLength) return false;
        Span<byte> derived = stackalloc byte[_keyBytes * 2 + 2];
        Rfc2898DeriveBytes.Pbkdf2(password, _salt, derived, 1000, HashAlgorithmName.SHA1);
        if (!derived.Slice(_keyBytes * 2, 2).SequenceEqual(_verifier)) return false;
        Span<byte> auth = stackalloc byte[20];
        HMACSHA1.HashData(derived.Slice(_keyBytes, _keyBytes), _data, auth);
        return CryptographicOperations.FixedTimeEquals(auth[..10], _auth);
    }

    public override KernelWorker CreateWorker() => new NativeFilterWorker(this, this, new ReferenceWorker(this));
    public override int PrefixBatch(int lastCount) => RkNative.BatchFor(lastCount, 64);

    int INativeFilter.Filter(byte* pws, int len, int n, int* hits, int maxHits)
    {
        if (!RkNative.Available || len < 0 || len > MaxPasswordLength || n < 0) return -1;
        // The verifier is at offset 32/48/64, so only PBKDF2 block 2/3/4 is needed for rejection.
        int verifierOffset = _keyBytes * 2 % 20;
        uint block = (uint)(_keyBytes * 2 / 20 + 1);
        byte* derived = stackalloc byte[64 * 20];
        int found = 0;
        fixed (byte* salt = _salt)
        {
            for (int offset = 0; offset < n; offset += 64)
            {
                int count = Math.Min(64, n - offset);
                if (RkNative.Pbkdf2Sha1Block(pws + offset * len, len, null, count, salt, _salt.Length, 1000, block, derived) != 0)
                    return -1;
                for (int i = 0; i < count; i++)
                {
                    byte* check = derived + i * 20 + verifierOffset;
                    if (check[0] != _verifier[0] || check[1] != _verifier[1]) continue;
                    if (found == maxHits) return maxHits + 1;
                    hits[found++] = offset + i;
                }
            }
        }
        return found;
    }

    private sealed class ReferenceWorker(WinZipAesKernel kernel) : KernelWorker
    {
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
