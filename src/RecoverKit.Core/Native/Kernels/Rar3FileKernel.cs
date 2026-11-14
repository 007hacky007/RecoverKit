using System.Text;
using RecoverKit.Core.Formats;

namespace RecoverKit.Core.Native.Kernels;

/// <summary>RAR 3 file data: the existing RAR KDF followed by a streaming whole-entry CRC check.</summary>
public sealed class Rar3FileKernel(Rar3FileTarget target, CancellationToken cancellation = default) : NativeKernel
{
    public override string Name => "RAR 3.x file (SHA-1 x 262144 + AES-128 + full CRC32)";
    public override int MaxPasswordLength => 512;
    public override double SpeedHint => 400;
    internal Action<byte[], string>? Unconfirmed { get; init; }

    private bool Check(ReadOnlySpan<byte> password, ReadOnlySpan<byte> digest, ReadOnlySpan<byte> iv)
    {
        try { return Rar3FileDecoder.Check(target, digest, iv, cancellation).Match; }
        catch (NotSupportedException ex) when (Unconfirmed is not null)
        {
            Unconfirmed(password.ToArray(), ex.Message);
            return false;
        }
    }

    public override bool Verify(ReadOnlySpan<byte> password)
    {
        try
        {
            string text = PasswordText(password);
            if (text.Length > 128) return false;
            var (digest, iv) = Derive(password);
            NotSupportedException? fullLengthError = null;
            try { if (Check(password, digest, iv)) return true; }
            catch (NotSupportedException ex) when (text.Length == 128) { fullLengthError = ex; }
            if (text.Length == 128)
            {
                // RAR's command-line creator truncates 128-character input to 127; try both keys.
                byte[] wide = Encoding.Unicode.GetBytes(text);
                (digest, iv) = Rar3Kernel.DeriveUtf16(wide.AsSpan(0, 127 * 2), target.Salt, cancellation);
                if (Check(password, digest, iv)) return true;
            }
            if (fullLengthError is not null) throw fullLengthError;
            return false;
        }
        catch (OperationCanceledException) when (cancellation.IsCancellationRequested) { return false; }
    }

    internal (byte[] Digest, byte[] Iv) Derive(ReadOnlySpan<byte> password)
        => Rar3Kernel.DeriveUtf16(Encoding.Unicode.GetBytes(PasswordText(password)), target.Salt, cancellation);

    private static string PasswordText(ReadOnlySpan<byte> password)
    {
        string text;
        try { text = new UTF8Encoding(false, true).GetString(password); }
        catch (DecoderFallbackException) { text = Encoding.Latin1.GetString(password); }
        return text;
    }

    public override int PrefixBatch(int lastCount)
    {
        if (!Rar3Kernel.NativeFast) return 1;
        int lanes = RkNative.Rar3Lanes();
        for (int count = 1; count <= lanes; count++)
            if (count * lastCount >= .98 * lanes * ((count * lastCount + lanes - 1) / lanes)) return count;
        return lanes;
    }

    public override KernelWorker CreateWorker() => new Worker(this, target, cancellation);

    private sealed class Worker(Rar3FileKernel kernel, Rar3FileTarget entry, CancellationToken ct) : KernelWorker
    {
        public override int Search(ReadOnlySpan<byte> prefix, ReadOnlySpan<byte> last) => SearchBatch(prefix, 1, last);

        public override int SearchBatch(ReadOnlySpan<byte> prefixes, int count, ReadOnlySpan<byte> last)
        {
            int prefixLength = prefixes.Length / count, length = prefixLength + 1;
            var passwords = new byte[length * count * last.Length];
            for (int p = 0; p < count; p++)
                for (int i = 0; i < last.Length; i++)
                {
                    int offset = (p * last.Length + i) * length;
                    prefixes.Slice(p * prefixLength, prefixLength).CopyTo(passwords.AsSpan(offset));
                    passwords[offset + prefixLength] = last[i];
                }
            return SearchPasswords(passwords, length, count * last.Length);
        }

        public override int SearchPasswords(ReadOnlySpan<byte> passwords, int length, int count)
        {
            if (ct.IsCancellationRequested) return -1;
            if (!Rar3Kernel.NativeFast || length is < 1 or > 26 ||
                passwords.IndexOfAnyInRange((byte)128, byte.MaxValue) >= 0)
            {
                for (int i = 0; i < count; i++)
                    if (kernel.Verify(passwords.Slice(i * length, length))) return i;
                return -1;
            }
            var hashes = Rar3Kernel.HashPasswords(entry.Salt, passwords, length, count);
            for (int i = 0; i < count; i++)
            {
                if (ct.IsCancellationRequested) return -1;
                try
                {
                    if (kernel.Check(passwords.Slice(i * length, length), hashes.AsSpan(i * 36, 20), hashes.AsSpan(i * 36 + 20, 16)))
                        return i;
                }
                catch (OperationCanceledException) when (ct.IsCancellationRequested) { return -1; }
            }
            return -1;
        }
    }
}
