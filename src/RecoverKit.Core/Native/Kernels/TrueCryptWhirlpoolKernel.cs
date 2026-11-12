using System.Buffers.Binary;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
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
        && new HeaderCheck(_encrypted).Verify(Derive(password, _salt));

    public override KernelWorker CreateWorker() => new Worker(this);

    private sealed class Worker(TrueCryptWhirlpoolKernel kernel) : KernelWorker
    {
        private readonly HeaderCheck _check = new(kernel._encrypted);
        private byte[] _passwords = [], _keys = [];

        public override int Search(ReadOnlySpan<byte> prefix, ReadOnlySpan<byte> last)
        {
            int len = prefix.Length + 1, n = last.Length;
            if (len > kernel.MaxPasswordLength || n == 0) return -1;
            if (_passwords.Length < n * len) _passwords = new byte[n * len];
            if (_keys.Length < n * 64) _keys = new byte[n * 64];
            for (int i = 0; i < n; i++)
            {
                prefix.CopyTo(_passwords.AsSpan(i * len));
                _passwords[i * len + len - 1] = last[i];
            }
            if (RkNative.Available)
            {
                fixed (byte* salt = kernel._salt, pws = _passwords, keys = _keys)
                    RkNative.WhirlpoolPbkdf2(salt, pws, len, n, keys);
            }
            else
                for (int i = 0; i < n; i++)
                    Derive(_passwords.AsSpan(i * len, len), kernel._salt).CopyTo(_keys, i * 64);
            for (int i = 0; i < n; i++)
                if (_check.Verify(_keys.AsSpan(i * 64, 64)) && kernel.Verify(_passwords.AsSpan(i * len, len))) return i;
            return -1;
        }
    }

    private sealed class HeaderCheck(byte[] encrypted)
    {
        private readonly IBlockCipher[] _ciphers = [new AesEngine(), new SerpentEngine(), new TwofishEngine()];
        private readonly byte[] _tweak = new byte[16], _block = new byte[16], _plain = new byte[448];

        public bool Verify(ReadOnlySpan<byte> key)
        {
            foreach (var cipher in _ciphers)
            {
                cipher.Init(true, new KeyParameter(key[32..].ToArray()));
                Array.Clear(_block);
                cipher.ProcessBlock(_block, 0, _tweak, 0); // Header data unit 0.
                cipher.Init(false, new KeyParameter(key[..32].ToArray()));
                for (int offset = 0; offset < 448; offset += 16)
                {
                    for (int j = 0; j < 16; j++) _block[j] = (byte)(encrypted[offset + j] ^ _tweak[j]);
                    cipher.ProcessBlock(_block, 0, _block, 0);
                    for (int j = 0; j < 16; j++) _plain[offset + j] = (byte)(_block[j] ^ _tweak[j]);
                    if (offset == 0 && !_plain.AsSpan(0, 4).SequenceEqual("TRUE"u8)) break;
                    if (offset == 432)
                    {
                        // Offsets are relative to the encrypted area, which starts at volume byte 64.
                        if (BinaryPrimitives.ReadUInt32BigEndian(_plain.AsSpan(8)) == Crc32(_plain.AsSpan(192, 256))
                            && (BinaryPrimitives.ReadUInt16BigEndian(_plain.AsSpan(4)) < 4
                                || BinaryPrimitives.ReadUInt32BigEndian(_plain.AsSpan(188)) == Crc32(_plain.AsSpan(0, 188)))) return true;
                        break;
                    }
                    int carry = 0;
                    for (int j = 0; j < 16; j++)
                    {
                        int v = (_tweak[j] << 1) | carry;
                        _tweak[j] = (byte)v;
                        carry = v >> 8;
                    }
                    if (carry != 0) _tweak[0] ^= 0x87;
                }
            }
            return false;
        }
    }

    private static uint Crc32(ReadOnlySpan<byte> bytes)
    {
        uint crc = uint.MaxValue;
        foreach (byte b in bytes)
        {
            crc ^= b;
            for (int i = 0; i < 8; i++) crc = (crc >> 1) ^ (0xedb88320u & (0u - (crc & 1)));
        }
        return ~crc;
    }
}
