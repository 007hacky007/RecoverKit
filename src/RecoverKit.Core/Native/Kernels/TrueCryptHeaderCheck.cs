using System.Buffers.Binary;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;

namespace RecoverKit.Core.Native.Kernels;

/// <summary>Managed reference for TrueCrypt/VeraCrypt XTS headers and cipher cascades.</summary>
internal sealed class TrueCryptHeaderCheck
{
    // Each chain is in encryption/key order, the reverse of hashcat's displayed cascade name.
    private static readonly int[][] TrueCryptChains = [[0], [1], [2], [2, 0], [0, 1], [1, 2], [1, 2, 0], [0, 2, 1]];
    private static readonly int[][] VeraCryptChains = [.. TrueCryptChains, [3], [4], [4, 3], [1, 3], [2, 4], [0, 4], [3, 1, 4]];
    private readonly IBlockCipher[] _ciphers = [new AesEngine(), new SerpentEngine(), new TwofishEngine(), new CamelliaEngine(), new KuznyechikEngine()];
    private readonly byte[][] _tweaks = [new byte[16], new byte[16], new byte[16]];
    private readonly byte[] _encrypted, _block = new byte[16], _plain = new byte[448];
    private readonly bool _vera;
    private readonly int _maxCiphers;

    internal TrueCryptHeaderCheck(byte[] encrypted, bool vera = false, int maxCiphers = 1)
        => (_encrypted, _vera, _maxCiphers) = (encrypted, vera, maxCiphers);

    internal bool Verify(ReadOnlySpan<byte> key)
    {
        foreach (int[] chain in _vera ? VeraCryptChains : TrueCryptChains)
        {
            int count = chain.Length;
            if (count > _maxCiphers || key.Length < count * 64) continue;
            for (int i = 0; i < count; i++)
            {
                var cipher = _ciphers[chain[i]];
                cipher.Init(true, new KeyParameter(key.Slice((count + i) * 32, 32).ToArray()));
                Array.Clear(_block);
                cipher.ProcessBlock(_block, 0, _tweaks[i], 0); // The header uses XTS data unit zero.
                cipher.Init(false, new KeyParameter(key.Slice(i * 32, 32).ToArray()));
            }
            bool signature = false;
            for (int offset = 0; offset < 448; offset += 16)
            {
                _encrypted.AsSpan(offset, 16).CopyTo(_block);
                for (int i = count - 1; i >= 0; i--)
                {
                    for (int j = 0; j < 16; j++) _block[j] ^= _tweaks[i][j];
                    _ciphers[chain[i]].ProcessBlock(_block, 0, _block, 0);
                    for (int j = 0; j < 16; j++) _block[j] ^= _tweaks[i][j];
                }
                if (offset == 0)
                {
                    signature = _block.AsSpan(0, 4).SequenceEqual(_vera ? "VERA"u8 : "TRUE"u8);
                    if (!signature) break;
                }
                _block.CopyTo(_plain, offset);
                for (int i = 0; i < count; i++)
                {
                    int carry = 0;
                    for (int j = 0; j < 16; j++)
                    {
                        int v = (_tweaks[i][j] << 1) | carry;
                        _tweaks[i][j] = (byte)v; carry = v >> 8;
                    }
                    if (carry != 0) _tweaks[i][0] ^= 0x87;
                }
            }
            // Offsets are relative to the encrypted area, starting at volume byte 64.
            if (signature && BinaryPrimitives.ReadUInt32BigEndian(_plain.AsSpan(8)) == Crc32(_plain.AsSpan(192, 256))
                && (BinaryPrimitives.ReadUInt16BigEndian(_plain.AsSpan(4)) < 4
                    || BinaryPrimitives.ReadUInt32BigEndian(_plain.AsSpan(188)) == Crc32(_plain.AsSpan(0, 188)))) return true;
        }
        return false;
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
