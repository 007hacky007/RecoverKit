using System.Buffers.Binary;
using System.Text;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;

namespace RecoverKit.Core.Formats;

/// <summary>Recovers the reversible database password stored in Jet 3/4 header pages.</summary>
internal static class AccessExtractor
{
    public static bool IsAccess(ReadOnlySpan<byte> head) => head.Length >= 20 &&
        head[..4].SequenceEqual(new byte[] { 0, 1, 0, 0 }) &&
        (head.Slice(4, 16).SequenceEqual("Standard Jet DB\0"u8) ||
         head.Slice(4, 16).SequenceEqual("Standard ACE DB\0"u8));

    public static void Extract(Stream s, Detection d)
    {
        var header = Bin.ReadAt(s, 0, 4096);
        if (!IsAccess(header)) throw new FormatException("Missing Access database header.");
        Bin.Need(header, 0, 24);
        bool ace = header[13] == 'A';
        int version = header[20];
        d.TypeName = ace ? "Access 2007+ database (ACE)" : version switch
        {
            0 => "Access 97 database (Jet 3)",
            1 => "Access 2000-2003 database (Jet 4)",
            _ => "Access database (Jet)",
        };
        if ((!ace && version > 1) || (ace && version is < 2 or > 6))
            throw new UnsupportedFormatException($"Access database version {version} is not supported.");
        Bin.Need(header, 0, version == 0 ? 2048 : 4096);

        // The fixed RC4 keystream is the documented header XOR mask (mdbtools HACKING.md).
        var rc4 = new RC4Engine();
        rc4.Init(false, new KeyParameter([0xc7, 0xda, 0x39, 0x6b]));
        rc4.ProcessBytes(header, 0x18, version == 0 ? 126 : 128, header, 0x18);

        if (Path.GetExtension(d.FilePath).Equals(".mdw", StringComparison.OrdinalIgnoreCase))
        {
            d.TypeName = "Access workgroup security file";
            d.Message = "Access workgroup (.mdw) user-level security is not supported.";
            return;
        }
        if (ace)
        {
            d.Message = Bin.U32(header, 0x3e) == 0
                ? "Database is not password protected. Access workgroup user-level security is not supported."
                : "Access 2007+ encrypted databases (.accdb) are not supported yet. They use Office-style encryption, not a reversible Jet password.";
            return;
        }

        var passwordBytes = Bin.Slice(header, 0x42, version == 0 ? 20 : 40);
        if (version == 1)
        {
            double date = BinaryPrimitives.ReadDoubleLittleEndian(header.AsSpan(0x72, 8));
            if (!double.IsFinite(date) || date < int.MinValue || date > int.MaxValue)
                throw new FormatException("Invalid Jet database creation date.");
            Span<byte> mask = stackalloc byte[4];
            BinaryPrimitives.WriteInt32LittleEndian(mask, (int)date);
            for (int i = 0; i < passwordBytes.Length; i++) passwordBytes[i] ^= mask[i % 4];
        }

        int length = 0, width = version == 0 ? 1 : 2;
        while (length < passwordBytes.Length &&
               (passwordBytes[length] != 0 || (width == 2 && passwordBytes[length + 1] != 0))) length += width;
        if (length == 0)
        {
            d.Message = "Database is not password protected. Access workgroup user-level security is not supported.";
            return;
        }

        Encoding encoding;
        if (version == 0)
        {
            int codePage = Bin.U16(header, 0x3c);
            Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
            // Code page 0 means the machine default; never guess from the recovery machine's locale.
            try
            {
                if (codePage == 0) throw new ArgumentException();
                encoding = Encoding.GetEncoding(codePage, EncoderFallback.ExceptionFallback, DecoderFallback.ExceptionFallback);
            }
            catch (Exception ex) when (ex is ArgumentException or NotSupportedException)
            {
                throw new UnsupportedFormatException($"Jet 3 password code page {codePage} is not supported.");
            }
        }
        else encoding = new UnicodeEncoding(false, false, true);

        string password;
        try { password = encoding.GetString(passwordBytes, 0, length); }
        catch (DecoderFallbackException) { throw new FormatException("Invalid Jet database password encoding."); }
        d.Add("Protection", "Reversible database password (instant recovery)");
        d.Unlocks.Add(new InstantUnlock
        {
            Title = "Access database password recovered",
            Description = "The database password is stored reversibly in the Jet header. Use it to open the database in Access. " +
                          "Workgroup (.mdw) user-level security is not supported.",
            Password = password,
        });
    }
}
