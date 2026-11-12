using System.Security.Cryptography;

namespace RecoverKit.Core.Native.Kernels;

/// <summary>
/// PDF standard security handler revision 6 (hashcat 10700, AES-256, PDF 2.0 / Acrobat X+): the
/// user password check of ISO 32000-2 algorithm 2.B. Each candidate runs 64 or more rounds of
/// AES-128-CBC over 64 copies of (password || K) followed by SHA-256, -384 or -512, chosen by the
/// data. The native library keeps a pool of candidates per thread and runs the rounds in groups
/// of eight that need the same hash; there is no managed fast path, so the kernel is only offered
/// when that library can run (AVX2 + AES-NI, or the ARMv8 AES / SHA-2 / SHA-512 instructions).
/// </summary>
public sealed unsafe class PdfR6Kernel : NativeKernel, INativeFilter
{
    private readonly byte[] _u;         // /U: hash (32) || validation salt (8) || key salt (8)

    public override string Name => "PDF R6 (SHA-256/384/512 + AES)";
    public override int MaxPasswordLength => 127;
    public override double SpeedHint => 2_500;

    private PdfR6Kernel(byte[] u) => _u = u;

    /// <summary>True when the native R6 path can run on this machine.</summary>
    internal static bool NativeFast => RkNative.HasPdf6Path;

    public static PdfR6Kernel? TryParse(string line)
    {
        line = line.Trim();
        if (!line.StartsWith("$pdf$", StringComparison.Ordinal)) return null;
        var f = line["$pdf$".Length..].Split('*');
        try
        {
            if (f.Length < 11 || f[0] != "5" || f[1] != "6") return null;
            var u = Convert.FromHexString(f[8]);
            return u.Length >= 48 ? new PdfR6Kernel(u[..48]) : null;
        }
        catch (FormatException) { return null; }
    }

    /// <summary>Reference implementation (ISO 32000-2, 7.6.4.3.4, algorithm 2.B with no user key).</summary>
    public override bool Verify(ReadOnlySpan<byte> password)
    {
        if (password.Length > MaxPasswordLength) return false;
        return Hash(password, _u.AsSpan(32, 8)).AsSpan().SequenceEqual(_u.AsSpan(0, 32));
    }

    internal static byte[] Hash(ReadOnlySpan<byte> password, ReadOnlySpan<byte> salt)
    {
        byte[] k = SHA256.HashData([.. password, .. salt]);
        using var aes = Aes.Create();
        for (int round = 1; ; round++)
        {
            int p = password.Length + k.Length;
            var k1 = new byte[64 * p];
            for (int i = 0; i < 64; i++)
            {
                password.CopyTo(k1.AsSpan(i * p));
                k.CopyTo(k1.AsSpan(i * p + password.Length));
            }
            aes.Key = k[..16];
            var e = aes.EncryptCbc(k1, k.AsSpan(16, 16), PaddingMode.None);
            int sum = 0;
            for (int i = 0; i < 16; i++) sum += e[i];
            k = (sum % 3) switch { 0 => SHA256.HashData(e), 1 => SHA384.HashData(e), _ => SHA512.HashData(e) };
            if (round >= 64 && e[^1] <= round - 32) return k[..32];
        }
    }

    public override KernelWorker CreateWorker() => new NativeFilterWorker(this, this, new ReferenceWorker(this));

    /// <summary>The native pool works best on a few hundred candidates per call.</summary>
    public override int PrefixBatch(int lastCount) => RkNative.BatchFor(lastCount, 768);

    int INativeFilter.Filter(byte* pws, int len, int n, int* hits, int maxHits)
    {
        fixed (byte* u = _u)
            return RkNative.Pdf6Search(u, pws, len, n, hits, maxHits);
    }

    /// <summary>Used only if the native call declines: plain reference checks.</summary>
    private sealed class ReferenceWorker(PdfR6Kernel k) : KernelWorker
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
