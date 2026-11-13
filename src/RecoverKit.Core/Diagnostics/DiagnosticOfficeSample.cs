using System.Buffers.Binary;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using RecoverKit.Core.Formats;

namespace RecoverKit.Core.Diagnostics;

/// <summary>Builds synthetic encrypted documents for diagnostics, with deliberately fixed keys and salts.</summary>
internal static class DiagnosticOfficeSample
{
    public static byte[] Create(bool agile, string password)
    {
        ArgumentNullException.ThrowIfNull(password);
        byte[] document = CreateDocument();
        return agile ? CreateAgile(document, password) : CreateStandard(document, password);
    }

    private static byte[] CreateDocument()
    {
        using var output = new MemoryStream();
        using (var zip = new ZipArchive(output, ZipArchiveMode.Create, leaveOpen: true))
        {
            Add("[Content_Types].xml", "<Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\"><Default Extension=\"rels\" ContentType=\"application/vnd.openxmlformats-package.relationships+xml\"/><Override PartName=\"/word/document.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml\"/></Types>");
            Add("_rels/.rels", "<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\"><Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument\" Target=\"word/document.xml\"/></Relationships>");
            // Keep the package above the CFB mini-stream cutoff with one synthetic paragraph.
            string text = string.Join(" ", Enumerable.Repeat("Synthetic diagnostic document.", 160));
            Add("word/document.xml", $"<w:document xmlns:w=\"http://schemas.openxmlformats.org/wordprocessingml/2006/main\"><w:body><w:p><w:r><w:t>{text}</w:t></w:r></w:p></w:body></w:document>");

            void Add(string name, string xml)
            {
                var entry = zip.CreateEntry(name, CompressionLevel.NoCompression);
                entry.LastWriteTime = new DateTimeOffset(2000, 1, 1, 0, 0, 0, TimeSpan.Zero);
                using var stream = entry.Open();
                stream.Write(Encoding.UTF8.GetBytes(xml));
            }
        }
        return output.ToArray();
    }

    private static byte[] CreateStandard(byte[] document, string password)
    {
        byte[] salt = FixedBytes(16, 1), verifier = FixedBytes(16, 33);
        byte[] key = OfficeDecryptor.StandardKey(salt, password, 128);
        using var info = new MemoryStream();
        using (var writer = new BinaryWriter(info, Encoding.UTF8, leaveOpen: true))
        {
            writer.Write((ushort)4);
            writer.Write((ushort)2);
            writer.Write(0x24u);
            writer.Write(34u); // Fixed encryption header followed by an empty UTF-16 provider name.
            writer.Write(0x24u);
            writer.Write(0u);
            writer.Write(0x660eu);
            writer.Write(0x8004u);
            writer.Write(128u);
            writer.Write(0x18u);
            writer.Write(0u);
            writer.Write(0u);
            writer.Write((ushort)0);
            writer.Write(16u);
            writer.Write(salt);
            writer.Write(OfficeDecryptor.AesEcbNoPad(verifier, key, decrypt: false));
            writer.Write(20u);
            writer.Write(OfficeDecryptor.AesEcbNoPad(Pad(SHA1.HashData(verifier), 16), key, decrypt: false));
        }
        byte[] encrypted = OfficeDecryptor.AesEcbNoPad(Pad(document, 16), key, decrypt: false);
        return CreateCompound(info.ToArray(), Package(document.Length, encrypted));
    }

    private static byte[] CreateAgile(byte[] document, string password)
    {
        byte[] salt = FixedBytes(16, 1), dataSalt = FixedBytes(16, 65);
        byte[] verifier = FixedBytes(16, 33), secretKey = FixedBytes(32, 97);
        byte[] hash = OfficeDecryptor.PasswordHash("SHA512", salt, password, 100000);
        byte[] EncryptPassword(byte[] data, byte[] block) => OfficeDecryptor.AesCbcNoPad(data,
            OfficeDecryptor.Hash("SHA512", hash, block)[..32], salt, decrypt: false);
        byte[] encryptedInput = EncryptPassword(verifier, [0xfe, 0xa7, 0xd2, 0x76, 0x3b, 0x4b, 0x9e, 0x79]);
        byte[] encryptedHash = EncryptPassword(SHA512.HashData(verifier), [0xd7, 0xaa, 0x0f, 0x6d, 0x30, 0x61, 0x34, 0x4e]);
        byte[] encryptedKey = EncryptPassword(secretKey, [0x14, 0x6e, 0x0b, 0xe7, 0xab, 0xac, 0xd0, 0xd6]);

        using var encrypted = new MemoryStream();
        for (int offset = 0, segment = 0; offset < document.Length; offset += 4096, segment++)
        {
            byte[] index = new byte[4];
            BinaryPrimitives.WriteInt32LittleEndian(index, segment);
            byte[] iv = OfficeDecryptor.Hash("SHA512", dataSalt, index)[..16];
            byte[] block = document.AsSpan(offset, Math.Min(4096, document.Length - offset)).ToArray();
            encrypted.Write(OfficeDecryptor.AesCbcNoPad(Pad(block, 16), secretKey, iv, decrypt: false));
        }
        byte[] package = Package(document.Length, encrypted.ToArray());
        byte[] hmacKey = FixedBytes(64, 129);
        byte[] EncryptIntegrity(byte[] data, byte[] block) => OfficeDecryptor.AesCbcNoPad(data, secretKey,
            OfficeDecryptor.Hash("SHA512", dataSalt, block)[..16], decrypt: false);
        byte[] encryptedHmacKey = EncryptIntegrity(hmacKey, [0x5f, 0xb2, 0xad, 0x01, 0x0c, 0xb9, 0xe1, 0xf6]);
        byte[] encryptedHmac = EncryptIntegrity(HMACSHA512.HashData(hmacKey, package), [0xa0, 0x67, 0x7f, 0x02, 0xb2, 0x2c, 0x84, 0x33]);
        static string B64(byte[] value) => Convert.ToBase64String(value);
        const string parameters = "saltSize=\"16\" blockSize=\"16\" keyBits=\"256\" hashSize=\"64\" cipherAlgorithm=\"AES\" cipherChaining=\"ChainingModeCBC\" hashAlgorithm=\"SHA512\"";
        string xml = $"""
            <encryption xmlns="http://schemas.microsoft.com/office/2006/encryption" xmlns:p="http://schemas.microsoft.com/office/2006/keyEncryptor/password">
              <keyData {parameters} saltValue="{B64(dataSalt)}"/>
              <dataIntegrity encryptedHmacKey="{B64(encryptedHmacKey)}" encryptedHmacValue="{B64(encryptedHmac)}"/>
              <keyEncryptors><keyEncryptor uri="http://schemas.microsoft.com/office/2006/keyEncryptor/password">
                <p:encryptedKey spinCount="100000" {parameters} saltValue="{B64(salt)}" encryptedVerifierHashInput="{B64(encryptedInput)}" encryptedVerifierHashValue="{B64(encryptedHash)}" encryptedKeyValue="{B64(encryptedKey)}"/>
              </keyEncryptor></keyEncryptors>
            </encryption>
            """;
        return CreateCompound([4, 0, 4, 0, 0x40, 0, 0, 0, .. Encoding.UTF8.GetBytes(xml)], package);
    }

    private static byte[] FixedBytes(int length, int start) => Enumerable.Range(start, length).Select(i => (byte)i).ToArray();

    private static byte[] Pad(byte[] bytes, int blockSize)
    {
        var padded = new byte[(bytes.Length + blockSize - 1) / blockSize * blockSize];
        bytes.CopyTo(padded, 0);
        return padded;
    }

    private static byte[] Package(int length, byte[] encrypted)
    {
        var package = new byte[8 + encrypted.Length];
        BinaryPrimitives.WriteUInt64LittleEndian(package, (ulong)length);
        encrypted.CopyTo(package, 8);
        return package;
    }

    private static byte[] CreateCompound(byte[] info, byte[] package)
    {
        const uint free = 0xffffffff, end = 0xfffffffe;
        const int sectorSize = 512;
        // Both streams use regular sectors; XML trailing whitespace keeps Agile padding valid.
        int infoLength = info.Length;
        bool agile = info[2] == 4;
        Array.Resize(ref info, 4096);
        if (agile) info.AsSpan(infoLength).Fill((byte)' ');
        int packageSectors = (package.Length + sectorSize - 1) / sectorSize;
        int fatSector = 9 + packageSectors;
        var file = new byte[(fatSector + 2) * sectorSize];
        void U16(int offset, ushort value) => BinaryPrimitives.WriteUInt16LittleEndian(file.AsSpan(offset), value);
        void U32(int offset, uint value) => BinaryPrimitives.WriteUInt32LittleEndian(file.AsSpan(offset), value);
        new byte[] { 0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1 }.CopyTo(file, 0);
        U16(0x18, 0x003e);
        U16(0x1a, 3);
        U16(0x1c, 0xfffe);
        U16(0x1e, 9);
        U16(0x20, 6);
        U32(0x2c, 1);
        U32(0x30, 0);
        U32(0x38, 4096);
        U32(0x3c, end);
        U32(0x44, end);
        for (int i = 0; i < 109; i++) U32(0x4c + i * 4, i == 0 ? (uint)fatSector : free);

        DirectoryEntry(0, "Root Entry", 5, end, 0, 1, free, 1);
        DirectoryEntry(1, "EncryptionInfo", 2, 1, info.Length, free, 2, 1);
        DirectoryEntry(2, "EncryptedPackage", 2, 9, package.Length, free, free, 0);
        info.CopyTo(file, 2 * sectorSize);
        package.CopyTo(file, 10 * sectorSize);
        int fatOffset = (fatSector + 1) * sectorSize;
        for (int i = 0; i < 128; i++)
        {
            uint next = i == fatSector ? 0xfffffffd : i == 0 || i == 8 || i == fatSector - 1 ? end
                : i < fatSector ? (uint)(i + 1) : free;
            U32(fatOffset + i * 4, next);
        }
        return file;

        void DirectoryEntry(int id, string name, byte type, uint start, int size, uint child, uint right, byte color)
        {
            int offset = sectorSize + id * 128;
            Encoding.Unicode.GetBytes(name + '\0').CopyTo(file, offset);
            U16(offset + 64, (ushort)((name.Length + 1) * 2));
            file[offset + 66] = type;
            file[offset + 67] = color;
            U32(offset + 68, free);
            U32(offset + 72, right);
            U32(offset + 76, child);
            U32(offset + 116, start);
            U32(offset + 120, (uint)size);
        }
    }
}
