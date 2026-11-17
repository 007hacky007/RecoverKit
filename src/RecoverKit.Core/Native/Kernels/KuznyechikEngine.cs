using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;

namespace RecoverKit.Core.Native.Kernels;

// Bouncy Castle 2.7 has no Kuznyechik engine. RFC 7801 defines this byte-oriented reference.
internal sealed class KuznyechikEngine : IBlockCipher
{
    private static readonly byte[] S =
    [
        252,238,221,17,207,110,49,22,251,196,250,218,35,197,4,77,
        233,119,240,219,147,46,153,186,23,54,241,187,20,205,95,193,
        249,24,101,90,226,92,239,33,129,28,60,66,139,1,142,79,
        5,132,2,174,227,106,143,160,6,11,237,152,127,212,211,31,
        235,52,44,81,234,200,72,171,242,42,104,162,253,58,206,204,
        181,112,14,86,8,12,118,18,191,114,19,71,156,183,93,135,
        21,161,150,41,16,123,154,199,243,145,120,111,157,158,178,177,
        50,117,25,61,255,53,138,126,109,84,198,128,195,189,13,87,
        223,245,36,169,62,168,67,201,215,121,214,246,124,34,185,3,
        224,15,236,222,122,148,176,188,220,232,40,80,78,51,10,74,
        167,151,96,115,30,0,98,68,26,184,56,130,100,159,38,65,
        173,69,70,146,39,94,85,47,140,163,165,125,105,213,149,59,
        7,88,179,64,134,172,29,247,48,55,107,228,136,217,231,137,
        225,27,131,73,76,63,248,254,141,83,170,144,202,216,133,97,
        32,113,103,164,45,43,9,91,203,155,37,208,190,229,108,82,
        89,166,116,210,230,244,180,192,209,102,175,194,57,75,99,182,
    ];
    private static readonly byte[] InverseS = InvertS();
    private static readonly byte[,] Products = MakeProducts();
    private static readonly byte[][] Constants = MakeConstants();
    private readonly byte[] _keys = new byte[160];
    private bool _encrypt, _initialized;

    public string AlgorithmName => "Kuznyechik";
    public int GetBlockSize() => 16;

    public void Init(bool forEncryption, ICipherParameters parameters)
    {
        if (parameters is not KeyParameter kp || kp.GetKey().Length != 32)
            throw new ArgumentException("Kuznyechik requires a 256-bit key", nameof(parameters));
        byte[] key = kp.GetKey();
        key.CopyTo(_keys, 0);
        Span<byte> a = stackalloc byte[16], b = stackalloc byte[16], t = stackalloc byte[16];
        key.AsSpan(0, 16).CopyTo(a); key.AsSpan(16, 16).CopyTo(b);
        for (int round = 0; round < 32; round++)
        {
            for (int i = 0; i < 16; i++) t[i] = S[a[i] ^ Constants[round][i]];
            Linear(t, inverse: false);
            for (int i = 0; i < 16; i++) t[i] ^= b[i];
            a.CopyTo(b); t.CopyTo(a);
            if ((round & 7) == 7)
            {
                a.CopyTo(_keys.AsSpan((round / 8 + 1) * 32));
                b.CopyTo(_keys.AsSpan((round / 8 + 1) * 32 + 16));
            }
        }
        _encrypt = forEncryption;
        _initialized = true;
    }

    public int ProcessBlock(byte[] input, int inOff, byte[] output, int outOff)
        => ProcessBlock(input.AsSpan(inOff), output.AsSpan(outOff));

    public int ProcessBlock(ReadOnlySpan<byte> input, Span<byte> output)
    {
        if (!_initialized) throw new InvalidOperationException("Kuznyechik is not initialized");
        if (input.Length < 16 || output.Length < 16) throw new DataLengthException("Kuznyechik requires a complete block");
        Span<byte> block = stackalloc byte[16];
        input[..16].CopyTo(block);
        if (_encrypt)
        {
            for (int round = 0; round < 9; round++)
            {
                for (int i = 0; i < 16; i++) block[i] = S[block[i] ^ _keys[round * 16 + i]];
                Linear(block, inverse: false);
            }
            for (int i = 0; i < 16; i++) block[i] ^= _keys[144 + i];
        }
        else
        {
            for (int i = 0; i < 16; i++) block[i] ^= _keys[144 + i];
            for (int round = 8; round >= 0; round--)
            {
                Linear(block, inverse: true);
                for (int i = 0; i < 16; i++) block[i] = (byte)(InverseS[block[i]] ^ _keys[round * 16 + i]);
            }
        }
        block.CopyTo(output);
        return 16;
    }

    private static void Linear(Span<byte> block, bool inverse)
    {
        for (int step = 0; step < 16; step++)
        {
            byte x;
            if (inverse)
            {
                x = block[0];
                for (int i = 0; i < 15; i++) { block[i] = block[i + 1]; x ^= Products[i, block[i]]; }
                block[15] = x;
            }
            else
            {
                x = block[15];
                for (int i = 14; i >= 0; i--) { x ^= Products[i, block[i]]; block[i + 1] = block[i]; }
                block[0] = x;
            }
        }
    }

    private static byte[,] MakeProducts()
    {
        byte[] coefficients = [148,32,133,16,194,192,1,251,1,192,194,16,133,32,148];
        var products = new byte[15, 256];
        for (int i = 0; i < 15; i++)
        for (int value = 0; value < 256; value++)
        {
            int a = value, b = coefficients[i], p = 0;
            while (b != 0)
            {
                if ((b & 1) != 0) p ^= a;
                a = ((a << 1) ^ ((a & 0x80) != 0 ? 0x1c3 : 0)) & 255;
                b >>= 1;
            }
            products[i, value] = (byte)p;
        }
        return products;
    }

    private static byte[][] MakeConstants()
    {
        var constants = new byte[32][];
        for (int i = 0; i < 32; i++)
        {
            constants[i] = new byte[16]; constants[i][15] = (byte)(i + 1);
            Linear(constants[i], inverse: false);
        }
        return constants;
    }

    private static byte[] InvertS()
    {
        var inverse = new byte[256];
        for (int i = 0; i < 256; i++) inverse[S[i]] = (byte)i;
        return inverse;
    }
}
