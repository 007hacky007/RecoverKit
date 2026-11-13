using System.Security.Cryptography;

namespace RecoverKit.Core.Native.Kernels;

/// <summary>
/// RAR 5 archives (hashcat 13000, <c>$rar5$16$salt$lg2$iv$8$check</c>). WinRAR derives the key with
/// PBKDF2-HMAC-SHA256 over 2^lg2 iterations (lg2 = 15 by default) and keeps going to 2^lg2 + 32 for the
/// password check value: that 32-byte value, folded to 8 bytes by xoring byte i into byte i % 8, is
/// stored in the header. The native library runs the iterations on 16 (AVX-512) or 8 (AVX2, NEON, or
/// interleaved ARMv8 SHA-256 instructions) candidates at once; the check is exact, as in hashcat's kernel.
/// </summary>
public sealed unsafe class Rar5Kernel : NativeKernel, INativeFilter
{
    private readonly byte[] _salt, _check;
    private readonly int _lg2;

    public override string Name => $"RAR 5 (PBKDF2-HMAC-SHA256 x {1 << _lg2})";
    public override int MaxPasswordLength => 127;           // WinRAR's limit; RarExtractor sets the same
    public override double SpeedHint => 300.0 * 32768 / (1 << _lg2);

    private Rar5Kernel(byte[] salt, int lg2, byte[] check) => (_salt, _lg2, _check) = (salt, lg2, check);

    /// <summary>True when the native PBKDF2-SHA256 has a vector path on this machine (AVX2 or NEON).</summary>
    internal static bool NativeFast => RkNative.HasVectorPath;

    public static Rar5Kernel? TryParse(string line)
    {
        var f = line.Trim().Split('$');
        // "", "rar5", "16", salt, lg2, iv, "8", check
        if (f.Length != 8 || f[0] != "" || f[1] != "rar5" || f[2] != "16" || f[6] != "8" || f[3].Length != 32 || f[7].Length != 16)
            return null;
        // hashcat accepts any two-digit count; WinRAR writes at most 24 (2^24 iterations).
        if (!int.TryParse(f[4], System.Globalization.NumberStyles.None, null, out int lg2) || lg2 < 1 || lg2 > 24) return null;
        try { return new Rar5Kernel(Convert.FromHexString(f[3]), lg2, Convert.FromHexString(f[7])); }
        catch (FormatException) { return null; }
    }

    /// <summary>Reference check with .NET's PBKDF2, independent of the native path.</summary>
    public override bool Verify(ReadOnlySpan<byte> password)
    {
        if (password.Length > MaxPasswordLength) return false;
        return CheckValue(password, _salt, _lg2).AsSpan().SequenceEqual(_check);
    }

    /// <summary>The 8-byte password check value for a password (WinRAR's PswCheck).</summary>
    internal static byte[] CheckValue(ReadOnlySpan<byte> password, byte[] salt, int lg2)
    {
        var v = Rfc2898DeriveBytes.Pbkdf2(password, salt, (1 << lg2) + 32, HashAlgorithmName.SHA256, 32);
        var c = new byte[8];
        for (int i = 0; i < 32; i++) c[i % 8] ^= v[i];
        return c;
    }

    public override KernelWorker CreateWorker() => new NativeFilterWorker(this, this, new ReferenceWorker(this));

    /// <summary>Enough candidates per call to fill the 16-lane groups.</summary>
    public override int PrefixBatch(int lastCount) => RkNative.BatchFor(lastCount, 64);

    int INativeFilter.Filter(byte* pws, int len, int n, int* hits, int maxHits)
    {
        fixed (byte* salt = _salt, check = _check)
            return RkNative.Rar5Search(salt, _lg2, check, pws, len, n, hits, maxHits);
    }

    /// <summary>Used only if the native call declines: plain reference checks.</summary>
    private sealed class ReferenceWorker(Rar5Kernel k) : KernelWorker
    {
        public override int Search(ReadOnlySpan<byte> prefix, ReadOnlySpan<byte> last)
        {
            Span<byte> pw = stackalloc byte[prefix.Length + 1];
            prefix.CopyTo(pw);
            for (int i = 0; i < last.Length; i++)
            {
                pw[^1] = last[i];
                if (k.Verify(pw)) return i;
            }
            return -1;
        }
    }
}
