using System.Globalization;
using System.Text;

namespace RecoverKit.Core.Formats;

/// <summary>Reads standard adb/Helium Android backup headers for hashcat mode 18900.</summary>
public static class AndroidBackupExtractor
{
    public static bool IsBackup(byte[] head) => head.AsSpan().StartsWith("ANDROID BACKUP\n"u8);

    public static void Extract(Stream s, Detection d)
    {
        d.TypeName = "Android backup";
        s.Position = 0;
        if (ReadLine(s) != "ANDROID BACKUP") throw new FormatException("Android backup signature not found.");
        int version = ReadNumber(s, "version");
        if (version is < 1 or > 5) throw new UnsupportedFormatException($"Unsupported Android backup version {version}.");
        string compressed = ReadLine(s);
        if (compressed is not ("0" or "1")) throw new FormatException("Invalid Android backup compression flag.");
        d.Add("Backup version", version.ToString(CultureInfo.InvariantCulture));
        d.Add("Compressed", compressed == "1" ? "yes" : "no");
        string encryption = ReadLine(s);
        if (encryption == "none")
        {
            d.Message = "Backup is not password protected.";
            return;
        }
        if (encryption != "AES-256")
            throw new UnsupportedFormatException($"Unsupported Android backup encryption: {encryption}.");

        // hashcat 7.1.2 requires these exact token sizes and at most six decimal iteration digits.
        string userSalt = ReadHex(s, "user password salt", 64);
        string checksumSalt = ReadHex(s, "master key checksum salt", 64);
        int rounds = ReadNumber(s, "PBKDF2 rounds");
        if (rounds is < 1 or > 999999) throw new FormatException("Android backup PBKDF2 rounds must be 1 to 999999 for hashcat.");
        string iv = ReadHex(s, "user key IV", 16);
        string blob = ReadHex(s, "encrypted master key blob", 96);

        d.Target = new HashTarget
        {
            FormatId = "ANDB",
            FormatName = "Android backup",
            Protection = $"AES-256-CBC, PBKDF2-HMAC-SHA1 {rounds} iterations",
            Modes = [18900],
            HashLines = FormattableString.Invariant($"$ab${version}*0*{rounds}*{userSalt}*{checksumSalt}*{iv}*{blob}"),
            Speed = SpeedClass.VerySlow,
            MaxPasswordLength = 256,
            Notes = "Supports standard adb and Helium Android backup headers, versions 1-5. " +
                "PBKDF2 makes recovery slow. Hashcat verifies key blob padding, not the master key checksum; " +
                "verify a recovered password by restoring or unpacking the backup. " +
                "Non-ASCII passwords in older version 1 backups may require legacy 8-bit dictionary encoding.",
        };
    }

    private static string ReadLine(Stream s)
    {
        var line = new StringBuilder();
        while (true)
        {
            int b = s.ReadByte();
            if (b < 0) throw new FormatException("Truncated Android backup header.");
            if (b == '\n') return line.ToString();
            if (b is < 32 or > 126 || line.Length >= 192)
                throw new FormatException("Invalid or overlong Android backup header line.");
            line.Append((char)b);
        }
    }

    private static int ReadNumber(Stream s, string field)
    {
        string value = ReadLine(s);
        if (value.Length == 0 || value.Any(c => c is < '0' or > '9') ||
            !int.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out int number))
            throw new FormatException($"Invalid Android backup {field}.");
        return number;
    }

    private static string ReadHex(Stream s, string field, int bytes)
    {
        string value = ReadLine(s);
        if (value.Length != bytes * 2 || value.Any(c => !Uri.IsHexDigit(c)))
            throw new FormatException($"Invalid Android backup {field}: expected {bytes} bytes of hex.");
        return value.ToLowerInvariant();
    }
}
