using System.Security.Cryptography;
using System.Text;
using System.Xml.Linq;

namespace RecoverKit.Core.Formats;

/// <summary>
/// Decrypts an encrypted MS Office OOXML document (2007 standard and 2010-2021 agile encryption)
/// once the password is known, writing the plaintext package. Implements MS-OFFCRYPTO key
/// derivation and package decryption. Legacy 97-2003 RC4 documents are not covered.
/// </summary>
public static class OfficeDecryptor
{
    private static readonly byte[] BlockEncryptedKeyValue = [0x14, 0x6e, 0x0b, 0xe7, 0xab, 0xac, 0xd0, 0xd6];

    public static bool CanDecrypt(string formatId) => formatId is "OF07" or "OF10" or "OF13";

    /// <summary>Decrypts <paramref name="inputPath"/> with <paramref name="password"/> into <paramref name="outputPath"/>.</summary>
    public static void DecryptToFile(string inputPath, string password, string outputPath)
    {
        using var fs = File.OpenRead(inputPath);
        var cf = new CompoundFile(fs);
        if (!cf.HasStream("EncryptionInfo") || !cf.HasStream("EncryptedPackage"))
            throw new UnsupportedFormatException("This file is not an encrypted OOXML package.");
        var info = cf.ReadStream("EncryptionInfo")!;
        var package = cf.ReadStream("EncryptedPackage")!;
        int vMajor = Bin.U16(info, 0), vMinor = Bin.U16(info, 2);

        byte[] plain = vMajor == 4 && vMinor == 4
            ? DecryptAgile(info, package, password)
            : DecryptStandard(info, package, password);

        if (plain.Length < 4 || plain[0] != 0x50 || plain[1] != 0x4B)
            throw new UnsupportedFormatException("Decryption did not produce a valid document (wrong password?).");
        File.WriteAllBytes(outputPath, plain);
    }

    // ---------------------------------------------------------------- agile (4.4)

    private static byte[] DecryptAgile(byte[] info, byte[] package, string password)
    {
        string xml = Encoding.UTF8.GetString(info, 8, info.Length - 8).TrimEnd('\0').Trim('﻿');
        var doc = XDocument.Parse(xml);
        XElement El(string local) => doc.Descendants().First(e => e.Name.LocalName == local);
        var keyData = El("keyData");
        var enc = El("encryptedKey");
        string A(XElement e, string n) => e.Attribute(n)?.Value ?? throw new FormatException($"Missing {n} in EncryptionInfo.");

        string hash = A(enc, "hashAlgorithm");
        int spin = int.Parse(A(enc, "spinCount"));
        var pSalt = Convert.FromBase64String(A(enc, "saltValue"));
        int keyBits = int.Parse(A(enc, "keyBits"));
        var encKeyValue = Convert.FromBase64String(A(enc, "encryptedKeyValue"));

        string kdHash = A(keyData, "hashAlgorithm");
        var kdSalt = Convert.FromBase64String(A(keyData, "saltValue"));
        int kdBlock = int.Parse(A(keyData, "blockSize"));
        if (!A(keyData, "cipherChaining").Equals("ChainingModeCBC", StringComparison.OrdinalIgnoreCase))
            throw new UnsupportedFormatException("Only CBC chaining is supported for agile decryption.");

        // Derive the intermediate key that unwraps the package key.
        byte[] h = PasswordHash(hash, pSalt, password, spin);
        byte[] keyBytes = Fit(Hash(hash, h, BlockEncryptedKeyValue), keyBits / 8);
        byte[] secretKey = AesCbcNoPad(encKeyValue, keyBytes, Fit(pSalt, 16), decrypt: true);

        // Decrypt the package in 4096-byte segments, each with IV = Hash(keyDataSalt || segmentIndex).
        long total = (long)Bin.U64(package, 0);
        int offset = 8, seg = 0;
        var outBuf = new byte[package.Length - 8];
        int written = 0;
        var segIdx = new byte[4];
        while (offset < package.Length)
        {
            int n = Math.Min(4096, package.Length - offset);
            BitConverter.TryWriteBytes(segIdx, seg);
            byte[] iv = Fit(Hash(kdHash, kdSalt, segIdx), kdBlock);
            byte[] dec = AesCbcNoPad(package.AsSpan(offset, n).ToArray(), secretKey, iv, decrypt: true);
            Array.Copy(dec, 0, outBuf, written, dec.Length);
            written += dec.Length;
            offset += n; seg++;
        }
        if (total > written) total = written;
        return outBuf[..(int)total];
    }

    // ---------------------------------------------------------------- standard (<=4.2)

    private static byte[] DecryptStandard(byte[] info, byte[] package, string password)
    {
        int headerSize = (int)Bin.U32(info, 8);
        int h = 12;
        int keySizeBits = (int)Bin.U32(info, h + 16);
        if (keySizeBits == 0) keySizeBits = 128;
        int v = h + headerSize;
        int saltSize = (int)Bin.U32(info, v);
        var salt = Bin.Slice(info, v + 4, saltSize);

        byte[] key = StandardKey(salt, password, keySizeBits);

        long total = (long)Bin.U64(package, 0);
        byte[] cipher = package[8..];
        byte[] plain = AesEcbNoPad(cipher, key, decrypt: true);
        if (total > plain.Length) total = plain.Length;
        return plain[..(int)total];
    }

    private static byte[] Xor(byte[] hash, byte pad)
    {
        var b = new byte[64];
        for (int i = 0; i < 64; i++) b[i] = (byte)((i < hash.Length ? hash[i] : 0) ^ pad);
        return b;
    }

    internal static byte[] StandardKey(byte[] salt, string password, int keyBits)
    {
        byte[] hv = Hash("SHA1", PasswordHash("SHA1", salt, password, 50000), new byte[4]);
        return Fit([.. SHA1.HashData(Xor(hv, 0x36)), .. SHA1.HashData(Xor(hv, 0x5C))], keyBits / 8);
    }

    // Reuse the hash state and buffers: detection runs this once per candidate, without package I/O.
    internal static byte[] PasswordHash(string algorithm, byte[] salt, string password, int spin)
    {
        using var hash = IncrementalHash.CreateHash(new HashAlgorithmName(algorithm.ToUpperInvariant()));
        hash.AppendData(salt);
        hash.AppendData(Encoding.Unicode.GetBytes(password));
        byte[] value = hash.GetHashAndReset();
        Span<byte> iteration = stackalloc byte[4];
        for (int i = 0; i < spin; i++)
        {
            System.Buffers.Binary.BinaryPrimitives.WriteInt32LittleEndian(iteration, i);
            hash.AppendData(iteration);
            hash.AppendData(value);
            hash.GetHashAndReset(value);
        }
        return value;
    }

    // ---------------------------------------------------------------- primitives

    internal static byte[] Hash(string alg, params byte[][] parts)
    {
        using HashAlgorithm h = alg.ToUpperInvariant() switch
        {
            "SHA1" => SHA1.Create(),
            "SHA256" => SHA256.Create(),
            "SHA384" => SHA384.Create(),
            "SHA512" => SHA512.Create(),
            _ => throw new UnsupportedFormatException($"Hash algorithm {alg} is not supported."),
        };
        foreach (var p in parts) h.TransformBlock(p, 0, p.Length, null, 0);
        h.TransformFinalBlock([], 0, 0);
        return h.Hash!;
    }

    /// <summary>Truncates to <paramref name="len"/>, or right-pads with 0x36 when shorter (MS-OFFCRYPTO).</summary>
    internal static byte[] Fit(byte[] b, int len)
    {
        if (b.Length == len) return b;
        var r = new byte[len];
        if (b.Length >= len) Array.Copy(b, r, len);
        else { Array.Copy(b, r, b.Length); for (int i = b.Length; i < len; i++) r[i] = 0x36; }
        return r;
    }

    internal static byte[] AesCbcNoPad(byte[] data, byte[] key, byte[] iv, bool decrypt)
    {
        using var aes = Aes.Create();
        aes.Key = key;
        aes.IV = iv.Length == 16 ? iv : Fit(iv, 16);
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.None;
        int usable = data.Length - data.Length % 16;
        using var dec = decrypt ? aes.CreateDecryptor() : aes.CreateEncryptor();
        return dec.TransformFinalBlock(data, 0, usable);
    }

    internal static byte[] AesEcbNoPad(byte[] data, byte[] key, bool decrypt)
    {
        using var aes = Aes.Create();
        aes.Key = key;
        aes.Mode = CipherMode.ECB;
        aes.Padding = PaddingMode.None;
        int usable = data.Length - data.Length % 16;
        using var dec = decrypt ? aes.CreateDecryptor() : aes.CreateEncryptor();
        return dec.TransformFinalBlock(data, 0, usable);
    }
}
