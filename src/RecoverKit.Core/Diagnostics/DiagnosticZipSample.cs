using System.Security.Cryptography;
using System.Text;

namespace RecoverKit.Core.Diagnostics;

internal static class DiagnosticZipSample
{
    public static byte[] AesArchive(string password)
    {
        byte[] salt = Enumerable.Range(0, 16).Select(i => (byte)(i * 13 + 7)).ToArray();
        byte[] plain = Enumerable.Range(0, 1024).Select(i => (byte)(i % 251)).ToArray();
        byte[] derived = Rfc2898DeriveBytes.Pbkdf2(Encoding.UTF8.GetBytes(password), salt, 1000, HashAlgorithmName.SHA1, 66);
        byte[] encrypted = new byte[plain.Length];
        using var aes = Aes.Create();
        aes.Key = derived[..32];
        byte[] counter = new byte[16];
        for (int offset = 0; offset < plain.Length; offset += 16)
        {
            System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(counter, (uint)(offset / 16 + 1));
            byte[] keyStream = aes.EncryptEcb(counter, PaddingMode.None);
            for (int i = 0; i < 16 && offset + i < plain.Length; i++) encrypted[offset + i] = (byte)(plain[offset + i] ^ keyStream[i]);
        }
        byte[] body = [.. salt, .. derived[64..66], .. encrypted, .. HMACSHA1.HashData(derived[32..64], encrypted)[..10]];
        byte[] name = "synthetic.dat"u8.ToArray();
        byte[] extra = [0x01, 0x99, 7, 0, 2, 0, (byte)'A', (byte)'E', 3, 0, 0];
        using var output = new MemoryStream();
        using var w = new BinaryWriter(output, Encoding.UTF8, leaveOpen: true);
        w.Write(0x04034b50u); w.Write((ushort)51); w.Write((ushort)1); w.Write((ushort)99);
        w.Write((ushort)0); w.Write((ushort)0x5b6c); w.Write(0u); w.Write((uint)body.Length); w.Write((uint)plain.Length);
        w.Write((ushort)name.Length); w.Write((ushort)extra.Length); w.Write(name); w.Write(extra); w.Write(body);
        long central = output.Position;
        w.Write(0x02014b50u); w.Write((ushort)51); w.Write((ushort)51); w.Write((ushort)1); w.Write((ushort)99);
        w.Write((ushort)0); w.Write((ushort)0x5b6c); w.Write(0u); w.Write((uint)body.Length); w.Write((uint)plain.Length);
        w.Write((ushort)name.Length); w.Write((ushort)extra.Length); w.Write((ushort)0); w.Write((ushort)0); w.Write((ushort)0);
        w.Write(0u); w.Write(0u); w.Write(name); w.Write(extra);
        uint centralLength = (uint)(output.Position - central);
        w.Write(0x06054b50u); w.Write((ushort)0); w.Write((ushort)0); w.Write((ushort)1); w.Write((ushort)1);
        w.Write(centralLength); w.Write((uint)central); w.Write((ushort)0);
        return output.ToArray();
    }
}
