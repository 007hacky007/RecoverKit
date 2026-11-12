using System.Security.Cryptography;
using System.Text;
using System.Xml;
using System.Xml.Linq;
using RecoverKit.Core.Native.Kernels;
using RecoverKit.Core.Native.Simd;

namespace RecoverKit.Core.Formats;

/// <summary>Checks only Office password verifiers, never the encrypted document contents.</summary>
internal static class OfficeKnownPasswords
{
    private const string ExcelDefault = "VelvetSweatshop";
    private static readonly byte[] VerifierInputBlock = [0xfe, 0xa7, 0xd2, 0x76, 0x3b, 0x4b, 0x9e, 0x79];
    private static readonly byte[] VerifierHashBlock = [0xd7, 0xaa, 0x0f, 0x6d, 0x30, 0x61, 0x34, 0x4e];

    internal static XElement AgileKey(byte[] info)
    {
        try
        {
            var doc = XDocument.Parse(Encoding.UTF8.GetString(info, 8, info.Length - 8).TrimEnd('\0').Trim('\uFEFF'));
            return doc.Descendants().FirstOrDefault(e => e.Name.LocalName == "encryptedKey" && e.Attribute("spinCount") is not null)
                ?? throw new FormatException("Agile encryption descriptor has no password key encryptor.");
        }
        catch (XmlException ex) { throw new FormatException("Invalid Agile encryption descriptor.", ex); }
    }

    internal static int Number(string value) => int.TryParse(value, out int result)
        ? result : throw new FormatException("Invalid integer in Office encryption header.");

    internal static void CheckOoxml(byte[] info, Detection d)
    {
        Func<string, bool> verify;
        if (Bin.U16(info, 0) == 4 && Bin.U16(info, 2) == 4)
        {
            var enc = AgileKey(info);
            string A(string name) => enc.Attribute(name)?.Value ?? throw new FormatException($"Missing {name} in EncryptionInfo.");
            int spin = Number(A("spinCount")), bits = Number(A("keyBits"));
            string algorithm = OfficeDecryptor.HashName(A("hashAlgorithm"));
            byte[] salt = Convert.FromBase64String(A("saltValue"));
            byte[] input = Convert.FromBase64String(A("encryptedVerifierHashInput"));
            byte[] expected = Convert.FromBase64String(A("encryptedVerifierHashValue"));
            int hashSize = algorithm switch { "SHA1" => 20, "SHA256" => 32, "SHA384" => 48, "SHA512" => 64, _ => 0 };
            if (hashSize == 0 || !A("cipherAlgorithm").Equals("AES", StringComparison.OrdinalIgnoreCase)) return;
            if (spin < 0 || bits is not (128 or 192 or 256) || salt.Length != 16 || input.Length != 16 ||
                expected.Length != (hashSize + 15) / 16 * 16 || Number(A("blockSize")) != 16 ||
                Number(A("saltSize")) != 16 || Number(A("hashSize")) != hashSize)
                throw new FormatException("Invalid Agile password verifier parameters.");
            if (!A("cipherChaining").Equals("ChainingModeCBC", StringComparison.OrdinalIgnoreCase)) return;
            // shortcut: bound attacker-controlled KDF work during detection; use an attack for higher counts.
            if (spin > 1_000_000)
            {
                d.Add("Instant unlock", "Default and empty password checks skipped above 1000000 Agile iterations.");
                return;
            }
            verify = password =>
            {
                var h = OfficeDecryptor.PasswordHash(algorithm, salt, password, spin);
                byte[] Key(byte[] block) => OfficeDecryptor.Fit(OfficeDecryptor.Hash(algorithm, h, block), bits / 8);
                var plain = OfficeDecryptor.AesCbcNoPad(input, Key(VerifierInputBlock), salt, decrypt: true);
                var actual = OfficeDecryptor.Hash(algorithm, plain);
                var decryptedHash = OfficeDecryptor.AesCbcNoPad(expected, Key(VerifierHashBlock), salt, decrypt: true);
                return CryptographicOperations.FixedTimeEquals(actual, decryptedHash.AsSpan(0, hashSize));
            };
        }
        else
        {
            int v = checked(12 + (int)Bin.U32(info, 8));
            Bin.Need(info, v, 72);
            int bits = (int)Bin.U32(info, 28);
            if (bits == 0) bits = 128;
            if (bits is not (128 or 192 or 256) || Bin.U32(info, v) != 16 || Bin.U32(info, v + 36) != 20)
                throw new FormatException("Invalid Standard password verifier parameters.");
            byte[] salt = Bin.Slice(info, v + 4, 16), input = Bin.Slice(info, v + 20, 16), expected = Bin.Slice(info, v + 40, 32);
            verify = password =>
            {
                var key = OfficeDecryptor.StandardKey(salt, password, bits);
                var plain = OfficeDecryptor.AesEcbNoPad(input, key, decrypt: true);
                var actual = SHA1.HashData(plain);
                var decryptedHash = OfficeDecryptor.AesEcbNoPad(expected, key, decrypt: true);
                return CryptographicOperations.FixedTimeEquals(actual, decryptedHash.AsSpan(0, 20));
            };
        }
        Check(d, verify, excel: true, canSave: true);
    }

    internal static void CheckRc4(byte[] header, int offset, Detection d, bool excel)
    {
        Func<string, bool> verify;
        if (Bin.U16(header, offset) == 1)
        {
            var kernel = Office97Kernel.TryParse(d.Target!.HashLines)!;
            verify = password => kernel.Verify(Encoding.ASCII.GetBytes(password));
        }
        else
        {
            int h = offset + 12;
            int size = (int)Bin.U32(header, h + 16);
            if (size == 0) size = 40;
            if (size < 40 || size > 128 || size % 8 != 0 || Bin.U32(header, h + 8) != 0x6801 ||
                Bin.U32(header, h + 12) != 0x8004)
                return;
            int v = h + (int)Bin.U32(header, offset + 8);
            if (Bin.U32(header, v) != 16 || Bin.U32(header, v + 36) != 20)
                throw new FormatException("Invalid RC4 CryptoAPI password verifier parameters.");
            byte[] salt = Bin.Slice(header, v + 4, 16), encrypted = [.. Bin.Slice(header, v + 20, 16), .. Bin.Slice(header, v + 40, 20)];
            verify = password =>
            {
                var h0 = SHA1.HashData([.. salt, .. Encoding.Unicode.GetBytes(password)]);
                var hash = SHA1.HashData([.. h0, 0, 0, 0, 0]);
                byte[] key = size == 40 ? [.. hash.AsSpan(0, 5), .. new byte[11]] : hash[..(size / 8)];
                var plain = Rc4.Apply(key, encrypted);
                return CryptographicOperations.FixedTimeEquals(SHA1.HashData(plain.AsSpan(0, 16)), plain.AsSpan(16));
            };
        }
        Check(d, verify, excel, canSave: false);
    }

    private static void Check(Detection d, Func<string, bool> verify, bool excel, bool canSave)
    {
        foreach (string password in excel ? new[] { ExcelDefault, "" } : new[] { "" })
        {
            if (!verify(password)) continue;
            d.Unlocks.Add(new InstantUnlock
            {
                Title = password.Length == 0 ? "Empty Office password" : "Excel default password",
                Description = (password.Length == 0
                    ? "This file is encrypted with an empty password. No user password was set."
                    : "This file uses Excel's built-in default password. No user password was set.") +
                    (canSave ? " Save a decrypted copy to open it without a password." : " Saving a decrypted copy of legacy RC4 documents is not supported."),
                Password = password,
                SaveLabel = canSave ? "Save decrypted copy..." : null,
                SaveCopyAsync = canSave ? (source, output, ct) => SaveCopyAsync(source, output, password, ct) : null,
            });
            break;
        }
    }

    private static Task SaveCopyAsync(string source, string output, string password, CancellationToken ct) => Task.Run(() =>
    {
        string temp = Path.Combine(Path.GetDirectoryName(Path.GetFullPath(output))!, $".recoverkit-{Guid.NewGuid():N}.tmp");
        try
        {
            ct.ThrowIfCancellationRequested();
            OfficeDecryptor.DecryptToFile(source, password, temp);
            ct.ThrowIfCancellationRequested();
            File.Move(temp, output, overwrite: true);
        }
        finally { if (File.Exists(temp)) File.Delete(temp); }
    }, ct);
}
