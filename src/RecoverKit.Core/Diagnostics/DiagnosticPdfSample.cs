using System.Buffers.Binary;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using RecoverKit.Core.Native.Kernels;
using RecoverKit.Core.Native.Simd;

namespace RecoverKit.Core.Diagnostics;

// Fixed keys, salts and IVs make these synthetic benchmark files reproducible, not secure storage.
internal static class DiagnosticPdfSample
{
    private static readonly byte[] Pad = Convert.FromHexString("28BF4E5E4E758A4164004E56FFFA01082E2E00B6D0683E802F0CA9FE6453697A");
    private static readonly byte[] Id = SHA256.HashData("RecoverKit diagnostic PDF identifier"u8)[..16];
    private const string OwnerPassword = "diagnostic-owner";

    public static byte[] Create(bool revision6, string password)
    {
        ArgumentNullException.ThrowIfNull(password);
        if (password.Length > (revision6 ? 127 : 32) || password.Any(c => c is < ' ' or > '~'))
            throw new ArgumentException("Diagnostic PDF passwords must be printable ASCII within the revision's password limit.", nameof(password));
        byte[] user = Encoding.ASCII.GetBytes(password);
        (string security, byte[] content) = revision6 ? Revision6(user) : Revision3(user);

        using var pdf = new MemoryStream();
        void Write(string text) => pdf.Write(Encoding.ASCII.GetBytes(text));
        Write(revision6 ? "%PDF-2.0\n" : "%PDF-1.4\n");
        pdf.Write([0x25, 0xe2, 0xe3, 0xcf, 0xd3, 0x0a]);
        long[] offsets = new long[7];
        void Object(int number, string value)
        {
            offsets[number] = pdf.Position;
            Write($"{number} 0 obj\n{value}\nendobj\n");
        }
        Object(1, "<< /Type /Catalog /Pages 2 0 R >>");
        Object(2, "<< /Type /Pages /Count 1 /Kids [3 0 R] >>");
        Object(3, "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>");
        Object(4, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>");
        offsets[5] = pdf.Position;
        Write($"5 0 obj\n<< /Length {content.Length} >>\nstream\n");
        pdf.Write(content);
        Write("\nendstream\nendobj\n");
        Object(6, security);
        long xref = pdf.Position;
        Write("xref\n0 7\n0000000000 65535 f \n");
        for (int i = 1; i < offsets.Length; i++)
            Write(offsets[i].ToString("D10", CultureInfo.InvariantCulture) + " 00000 n \n");
        Write($"trailer\n<< /Size 7 /Root 1 0 R /Encrypt 6 0 R /ID [{Hex(Id)} {Hex(Id)}] >>\nstartxref\n{xref.ToString(CultureInfo.InvariantCulture)}\n%%EOF\n");
        return pdf.ToArray();
    }

    private static ReadOnlySpan<byte> PageContent => "BT /F1 18 Tf 72 720 Td (Synthetic diagnostic sample) Tj ET\n"u8;
    private static string Hex(byte[] bytes) => "<" + Convert.ToHexString(bytes) + ">";

    private static byte[] Padded(ReadOnlySpan<byte> password)
    {
        byte[] bytes = new byte[32];
        password.CopyTo(bytes);
        Pad.AsSpan(0, 32 - password.Length).CopyTo(bytes.AsSpan(password.Length));
        return bytes;
    }

    private static byte[] Rc4Rounds(byte[] key, byte[] value)
    {
        for (int round = 0; round < 20; round++)
            value = Rc4.Apply(key.Select(b => (byte)(b ^ round)).ToArray(), value);
        return value;
    }

    private static (string Security, byte[] Content) Revision3(byte[] password)
    {
        byte[] ownerKey = MD5.HashData(Padded(Encoding.ASCII.GetBytes(OwnerPassword)));
        for (int i = 0; i < 50; i++) ownerKey = MD5.HashData(ownerKey);
        byte[] owner = Rc4Rounds(ownerKey, Padded(password));
        byte[] permissions = new byte[4];
        BinaryPrimitives.WriteInt32LittleEndian(permissions, -4);
        byte[] key = MD5.HashData([.. Padded(password), .. owner, .. permissions, .. Id]);
        for (int i = 0; i < 50; i++) key = MD5.HashData(key);
        byte[] user = [.. Rc4Rounds(key, MD5.HashData([.. Pad, .. Id])), .. new byte[16]];
        byte[] objectKey = MD5.HashData([.. key, 5, 0, 0, 0, 0]);
        return ($"<< /Filter /Standard /V 2 /R 3 /Length 128 /P -4 /O {Hex(owner)} /U {Hex(user)} >>",
            Rc4.Apply(objectKey, PageContent));
    }

    private static (string Security, byte[] Content) Revision6(byte[] password)
    {
        byte[] key = SHA256.HashData("RecoverKit diagnostic PDF file key"u8);
        byte[] validationSalt = Convert.FromHexString("0011223344556677");
        byte[] keySalt = Convert.FromHexString("8899AABBCCDDEEFF");
        byte[] ownerValidationSalt = Convert.FromHexString("1021324354657687");
        byte[] ownerKeySalt = Convert.FromHexString("98A9BACBDCEDFE0F");
        byte[] user = [.. PdfR6Kernel.Hash(password, validationSalt), .. validationSalt, .. keySalt];
        byte[] ownerPassword = Encoding.ASCII.GetBytes(OwnerPassword);
        byte[] owner = [.. OwnerHash(ownerPassword, ownerValidationSalt, user), .. ownerValidationSalt, .. ownerKeySalt];
        using var aes = Aes.Create();
        aes.Key = PdfR6Kernel.Hash(password, keySalt);
        byte[] ue = aes.EncryptCbc(key, new byte[16], PaddingMode.None);
        aes.Key = OwnerHash(ownerPassword, ownerKeySalt, user);
        byte[] oe = aes.EncryptCbc(key, new byte[16], PaddingMode.None);
        aes.Key = key;
        byte[] perms = aes.EncryptEcb([0xfc, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, (byte)'T', (byte)'a', (byte)'d', (byte)'b', 0, 0x11, 0x22, 0x33], PaddingMode.None);
        byte[] iv = Convert.FromHexString("31415926535897932384626433832795");
        byte[] content = [.. iv, .. aes.EncryptCbc(PageContent, iv, PaddingMode.PKCS7)];
        return ($"<< /Filter /Standard /V 5 /R 6 /Length 256 /P -4 /EncryptMetadata true /O {Hex(owner)} /U {Hex(user)} /OE {Hex(oe)} /UE {Hex(ue)} /Perms {Hex(perms)} /CF << /StdCF << /CFM /AESV3 /AuthEvent /DocOpen /Length 32 >> >> /StmF /StdCF /StrF /StdCF >>", content);
    }

    // Algorithm 2.B's owner form appends all 48 user bytes to the initial hash and every round.
    private static byte[] OwnerHash(ReadOnlySpan<byte> password, ReadOnlySpan<byte> salt, byte[] user)
    {
        byte[] k = SHA256.HashData([.. password, .. salt, .. user]);
        using var aes = Aes.Create();
        for (int round = 1; ; round++)
        {
            int length = password.Length + k.Length + user.Length;
            byte[] repeated = new byte[64 * length];
            for (int i = 0; i < 64; i++)
            {
                password.CopyTo(repeated.AsSpan(i * length));
                k.CopyTo(repeated.AsSpan(i * length + password.Length));
                user.CopyTo(repeated.AsSpan(i * length + password.Length + k.Length));
            }
            aes.Key = k[..16];
            byte[] encrypted = aes.EncryptCbc(repeated, k.AsSpan(16, 16), PaddingMode.None);
            int sum = 0;
            for (int i = 0; i < 16; i++) sum += encrypted[i];
            k = (sum % 3) switch { 0 => SHA256.HashData(encrypted), 1 => SHA384.HashData(encrypted), _ => SHA512.HashData(encrypted) };
            if (round >= 64 && encrypted[^1] <= round - 32) return k[..32];
        }
    }
}
