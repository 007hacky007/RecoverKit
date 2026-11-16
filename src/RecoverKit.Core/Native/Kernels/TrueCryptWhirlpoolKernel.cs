using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;

namespace RecoverKit.Core.Native.Kernels;

/// <summary>TrueCrypt PBKDF2-Whirlpool with single-cipher AES/Serpent/Twofish XTS (mode 29331).</summary>
public sealed unsafe class TrueCryptWhirlpoolKernel : NativeKernel
{
    private readonly byte[] _salt, _encrypted;
    public override string Name => "TrueCrypt Whirlpool + XTS 512 bit";
    public override double SpeedHint => 500;

    private TrueCryptWhirlpoolKernel(byte[] salt, byte[] encrypted) => (_salt, _encrypted) = (salt, encrypted);

    public static TrueCryptWhirlpoolKernel? TryParse(string line)
    {
        var f = line.Trim().Split('$');
        if (f.Length != 4 || f[0] != "" || f[1] != "truecrypt" || f[2].Length != 128 || f[3].Length != 896) return null;
        try { return new(Convert.FromHexString(f[2]), Convert.FromHexString(f[3])); }
        catch (FormatException) { return null; }
    }

    internal static byte[] Derive(ReadOnlySpan<byte> password, byte[] salt)
    {
        var kdf = new Pkcs5S2ParametersGenerator(new WhirlpoolDigest());
        kdf.Init(password.ToArray(), salt, 1000);
        return ((KeyParameter)kdf.GenerateDerivedMacParameters(512)).GetKey();
    }

    public override bool Verify(ReadOnlySpan<byte> password) => password.Length <= MaxPasswordLength
        && new TrueCryptHeaderCheck(_encrypted).Verify(Derive(password, _salt));

    public override KernelWorker CreateWorker() => new Worker(this);

    public override int PrefixBatch(int lastCount)
    {
        int lanes = RkNative.Available ? RkNative.WhirlpoolLanes() : 1;
        for (int count = 1; count < lanes; count++)
            if (count * lastCount % lanes == 0) return count;
        return lanes;
    }

    private sealed class Worker(TrueCryptWhirlpoolKernel kernel) : KernelWorker
    {
        private readonly TrueCryptHeaderCheck _check = new(kernel._encrypted);
        private byte[] _passwords = [], _keys = [];

        public override int Search(ReadOnlySpan<byte> prefix, ReadOnlySpan<byte> last) => SearchBatch(prefix, 1, last);

        public override int SearchBatch(ReadOnlySpan<byte> prefixes, int count, ReadOnlySpan<byte> last)
        {
            if (count <= 0) return -1;
            int plen = prefixes.Length / count, len = plen + 1, n = count * last.Length;
            if (len > kernel.MaxPasswordLength || n == 0) return -1;
            if (_passwords.Length < n * len) _passwords = new byte[n * len];
            if (_keys.Length < n * 64) _keys = new byte[n * 64];
            for (int k = 0, i = 0; k < count; k++)
            for (int j = 0; j < last.Length; j++, i++)
            {
                prefixes.Slice(k * plen, plen).CopyTo(_passwords.AsSpan(i * len));
                _passwords[i * len + len - 1] = last[j];
            }
            return SearchPasswords(_passwords.AsSpan(0, n * len), len, n);
        }

        public override int SearchPasswords(ReadOnlySpan<byte> passwords, int len, int n)
        {
            if (_keys.Length < n * 64) _keys = new byte[n * 64];
            if (RkNative.Available)
            {
                fixed (byte* salt = kernel._salt, pws = passwords, keys = _keys)
                    if (RkNative.WhirlpoolPbkdf2(salt, pws, len, n, keys) != n)
                        throw new InvalidOperationException("rknative rejected the Whirlpool request");
            }
            else
                for (int i = 0; i < n; i++)
                    Derive(passwords.Slice(i * len, len), kernel._salt).CopyTo(_keys, i * 64);
            for (int i = 0; i < n; i++)
                if (_check.Verify(_keys.AsSpan(i * 64, 64)) && kernel.Verify(passwords.Slice(i * len, len))) return i;
            return -1;
        }
    }

}
