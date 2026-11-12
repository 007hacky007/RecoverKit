using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace RecoverKit.Core.Formats;

/// <summary>KeePass 1 KDB and KDBX 2/3/4 headers for hashcat 13400 and 34300.</summary>
public static class KeePassExtractor
{
    private const int MaxHeader = 1024 * 1024;
    private const string Aes = "31c1f2e6bf714350be5805216afc5aff";
    private const string Twofish = "ad68f29f576f4bb9a36ad47af965346c";
    private const string ChaCha = "d6038a2b8b6f4cb5a524339a31dbb59a";
    private const string AesKdf = "c9d9f39a628a4460bf740d08c18a4fea";
    private const string Argon2d = "ef636ddf8c29444b91f7a9a403e30a0c";
    private const string Argon2id = "9e298b1956db4773b23dfc3ec6f0a1e6";

    public static bool IsKeePass(byte[] head) => head.Length >= 8 && Bin.U32(head, 0) == 0x9AA2D903 &&
        Bin.U32(head, 4) is 0xB54BFB65 or 0xB54BFB67;

    public static void Extract(Stream s, Detection d, string? keyfile = null)
    {
        var h = Read(s, 0, (int)Math.Min(s.Length, MaxHeader));
        if (!IsKeePass(h)) throw new FormatException("KeePass signature not found.");
        d.TypeName = "KeePass database";
        if (Bin.U32(h, 4) == 0xB54BFB65) { Kdb(s, h, d, keyfile); return; }
        Bin.Need(h, 8, 4);
        uint version = Bin.U32(h, 8), major = version >> 16;
        if (major is < 2 or > 4) throw new UnsupportedFormatException($"Unsupported KeePass KDBX version {major}.{version & 0xffff}.");
        d.TypeName = $"KeePass KDBX {major}.{version & 0xffff} database";
        var fields = new Dictionary<byte, byte[]>();
        int pos = 12;
        while (true)
        {
            Bin.Need(h, pos, major == 4 ? 5 : 3);
            byte id = h[pos++];
            uint size = major == 4 ? Bin.U32(h, pos) : Bin.U16(h, pos);
            pos += major == 4 ? 4 : 2;
            if (size > MaxHeader) throw new FormatException("KeePass header field is too large.");
            var value = Bin.Slice(h, pos, (int)size);
            pos += (int)size;
            if (!fields.TryAdd(id, value)) throw new FormatException("Duplicate KeePass header field.");
            if (id == 0)
            {
                if (!value.AsSpan().SequenceEqual("\r\n\r\n"u8)) throw new FormatException("Invalid KeePass header terminator.");
                break;
            }
        }
        string cipher = Bin.Hex(Required(fields, 2, 16));
        string cipherName = cipher switch
        {
            Aes => "AES-256", Twofish => "Twofish-256", ChaCha => "ChaCha20",
            _ => throw new UnsupportedFormatException("Unsupported KeePass cipher UUID: " + cipher + "."),
        };
        var master = Required(fields, 4, 32);
        var iv = Required(fields, 7, cipher == ChaCha ? 12 : 16);
        if (major < 4)
        {
            if (cipher != Aes) throw new UnsupportedFormatException($"KDBX {major} with {cipherName} is not supported by hashcat 13400; only AES is supported.");
            var seed = Required(fields, 5, 32);
            ulong rounds = Bin.U64(Required(fields, 6, 8), 0);
            CheckRounds(rounds);
            var expected = Required(fields, 9, 32);
            var data = Read(s, pos, 32);
            SetTarget(d, 13400, $"{cipherName}, AES-KDF {N(rounds)} rounds",
                $"$keepass$*2*{N(rounds)}*0*{Bin.Hex(master)}*{Bin.Hex(seed)}*{Bin.Hex(iv)}*{Bin.Hex(expected)}*{Bin.Hex(data)}", keyfile);
        }
        else
        {
            var header = h.AsSpan(0, pos);
            var auth = Read(s, pos, 64);
            if (!SHA256.HashData(header).AsSpan().SequenceEqual(auth.AsSpan(0, 32)))
                throw new FormatException("KeePass header SHA-256 checksum does not match.");
            var kdf = Dictionary(Required(fields, 11));
            string uuid = Bin.Hex(Parameter(kdf, "$UUID", 0x42, 16));
            if (uuid == AesKdf) throw new UnsupportedFormatException("KDBX 4 with AES-KDF is not supported by hashcat 34300. Only Argon2d and Argon2id are supported.");
            if (uuid is not (Argon2d or Argon2id)) throw new UnsupportedFormatException("Unsupported KDBX 4 KDF UUID: " + uuid + ".");
            var seed = Parameter(kdf, "S", 0x42, 32);
            ulong rounds = Bin.U64(Parameter(kdf, "I", 5, 8), 0);
            ulong memory = Bin.U64(Parameter(kdf, "M", 5, 8), 0);
            uint parallel = Bin.U32(Parameter(kdf, "P", 4, 4), 0);
            uint argonVersion = Bin.U32(Parameter(kdf, "V", 4, 4), 0);
            if (rounds is < 1 or > 99999 || parallel is < 1 or > 32 || argonVersion is not (16 or 19) ||
                memory > uint.MaxValue || memory < 8192UL * parallel || memory % 1024 != 0)
                throw new UnsupportedFormatException("KDBX 4 Argon2 parameters exceed hashcat 34300 limits (1-99999 iterations, 1-32 lanes, version 16/19, memory below 4 GiB in whole KiB).");
            if (kdf.Any(x => x.Key is "K" or "A" && x.Value.Data.Length != 0))
                throw new UnsupportedFormatException("KDBX 4 Argon2 secret keys and associated data are not supported by hashcat 34300.");
            // Hashcat 7.1.2's tokenizer and HMAC kernel both hard-code 253 header bytes.
            if (pos != 253) throw new UnsupportedFormatException($"KDBX 4 with {cipherName} has a {pos}-byte header. Hashcat 34300 requires exactly 253 bytes; ChaCha20 and custom headers usually do not fit.");
            string name = uuid == Argon2d ? "Argon2d" : "Argon2id";
            SetTarget(d, 34300, $"{cipherName}, {name} {N(rounds)} iterations, {N(memory / 1024)} KiB, {parallel} lanes",
                $"$keepass$*4*{N(rounds)}*{uuid[..8]}*{N(memory)}*{argonVersion}*{parallel}*{Bin.Hex(master)}*{Bin.Hex(seed)}*{Bin.Hex(header)}*{Bin.Hex(auth, 32, 32)}", keyfile);
        }
    }

    private static void Kdb(Stream s, byte[] h, Detection d, string? keyfile)
    {
        Bin.Need(h, 0, 124);
        d.TypeName = "KeePass 1.x KDB database";
        if ((Bin.U32(h, 12) >> 16) != 3) throw new UnsupportedFormatException("Unsupported KeePass 1 KDB version.");
        uint flags = Bin.U32(h, 8), rounds = Bin.U32(h, 120);
        int algorithm = (flags & 0xa) switch
        {
            2 => 0, 8 => 1,
            _ => throw new UnsupportedFormatException("KeePass 1 recovery supports AES and Twofish encryption only."),
        };
        CheckRounds(rounds);
        long length = s.Length - 124;
        if (length < 16 || length % 16 != 0) throw new FormatException("Truncated or invalid KeePass 1 encrypted contents.");
        if (length > 0x800000) throw new UnsupportedFormatException("KeePass 1 encrypted contents exceed hashcat 13400's 8 MiB limit.");
        if (length == 32 && keyfile is null)
            throw new UnsupportedFormatException("KeePass 1 with exactly 32 encrypted bytes and no keyfile triggers a hashcat 13400 parser limitation.");
        var data = Read(s, 124, (int)length);
        SetTarget(d, 13400, $"{(algorithm == 0 ? "AES-256" : "Twofish-256")}, AES-KDF {rounds} rounds",
            $"$keepass$*1*{rounds}*{algorithm}*{Bin.Hex(h, 16, 16)}*{Bin.Hex(h, 88, 32)}*{Bin.Hex(h, 32, 16)}*{Bin.Hex(h, 56, 32)}*1*{length}*{Bin.Hex(data)}", keyfile, legacy: true);
    }

    private static void SetTarget(Detection d, int mode, string protection, string hash, string? keyfile, bool legacy = false)
    {
        if (keyfile is not null) hash += "*1*64*" + Bin.Hex(KeePassKeyfile.Read(keyfile, legacy));
        d.Add("Keyfile", keyfile is null ? "none selected" : "selected");
        d.Target = new HashTarget
        {
            FormatId = mode == 34300 ? "KDB4" : "KDBX", FormatName = d.TypeName,
            Protection = protection, Modes = [mode], HashLines = hash,
            Speed = SpeedClass.VerySlow, MaxPasswordLength = 256,
            Notes = (mode == 34300 ? "Argon2 is memory-hard and very slow. Use a short, targeted dictionary. " : "") +
                (keyfile is null ? "If this database requires a keyfile, reopen it and select that keyfile. " : "The selected keyfile is required along with the password. Reopen the database to change it. ") +
                "Windows account keys and external key providers are not supported.",
        };
    }

    private static string N(ulong n) => n.ToString(CultureInfo.InvariantCulture);
    private static void CheckRounds(ulong rounds)
    {
        if (rounds is < 1 or > uint.MaxValue) throw new UnsupportedFormatException("KeePass AES-KDF rounds must be between 1 and 4294967295 for hashcat 13400.");
    }

    private static byte[] Read(Stream s, long pos, int count)
    {
        if (pos < 0 || count < 0 || pos > s.Length || count > s.Length - pos) throw new FormatException("Truncated KeePass database.");
        if (count == 0) return [];
        return Bin.ReadAt(s, pos, count);
    }

    private static byte[] Required(Dictionary<byte, byte[]> fields, byte id, int? length = null)
    {
        if (!fields.TryGetValue(id, out var value) || length is int n && value.Length != n)
            throw new FormatException($"Missing or invalid KeePass header field {id}.");
        return value;
    }

    private static Dictionary<string, (byte Type, byte[] Data)> Dictionary(byte[] bytes)
    {
        Bin.Need(bytes, 0, 2);
        if (Bin.U16(bytes, 0) >> 8 > 1) throw new UnsupportedFormatException("Unsupported KeePass KDF dictionary version.");
        var result = new Dictionary<string, (byte, byte[])>(StringComparer.Ordinal);
        int pos = 2;
        while (true)
        {
            Bin.Need(bytes, pos, 1);
            byte type = bytes[pos++];
            if (type == 0)
            {
                if (pos != bytes.Length) throw new FormatException("Trailing KeePass KDF dictionary data.");
                return result;
            }
            var key = Encoding.UTF8.GetString(Value());
            var value = Value();
            if (!result.TryAdd(key, (type, value))) throw new FormatException("Duplicate KeePass KDF parameter.");
        }
        byte[] Value()
        {
            Bin.Need(bytes, pos, 4);
            uint size = Bin.U32(bytes, pos); pos += 4;
            if (size > bytes.Length - pos) throw new FormatException("Truncated KeePass KDF parameter.");
            var value = Bin.Slice(bytes, pos, (int)size); pos += (int)size;
            return value;
        }
    }

    private static byte[] Parameter(Dictionary<string, (byte Type, byte[] Data)> kdf, string key, byte type, int length)
    {
        if (!kdf.TryGetValue(key, out var value) || value.Type != type || value.Data.Length != length)
            throw new FormatException($"Missing or invalid KeePass KDF parameter {key}.");
        return value.Data;
    }
}
