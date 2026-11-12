namespace RecoverKit.Core.Formats;

public enum VolumeKind { TrueCrypt, VeraCrypt }

[Flags]
public enum VolumeKdf
{
    None = 0,
    Ripemd160 = 1,
    Sha512 = 2,
    Whirlpool = 4,
    Sha256 = 8,      // VeraCrypt only
    Streebog = 16,   // VeraCrypt only
}

[Flags]
public enum VolumeCipher
{
    None = 0,
    Single = 1,      // AES, Serpent, Twofish, Camellia, Kuznyechik (512-bit XTS key)
    Double = 2,      // two-cipher cascades (1024-bit)
    Triple = 4,      // three-cipher cascades (1536-bit)
}

/// <summary>Options from the "Open as TrueCrypt/VeraCrypt" dialog.</summary>
public sealed class VolumeOptions
{
    public VolumeKind Kind { get; set; } = VolumeKind.VeraCrypt;
    public long HeaderOffset { get; set; }
    public bool BootVolume { get; set; }
    public VolumeKdf Kdfs { get; set; } = VolumeKdf.Sha512;
    public VolumeCipher Ciphers { get; set; } = VolumeCipher.Single;

    public List<string> Keyfiles { get; set; } = new();
    public int Pim { get; set; }

    public const long NormalOffset = 0;
    public const long HiddenOffset = 65536;
    public const long BootOffset = 31744; // sector 62, system encryption header
}

/// <summary>
/// TrueCrypt and VeraCrypt volumes have no signature, so the user must say what
/// they are. The first 512 header bytes become a $truecrypt$/$veracrypt$ hash and
/// the selected KDF/cipher combinations map to the hashcat 293xx/294xx modes.
/// </summary>
public static class CryptVolume
{
    public static Detection Open(string path, VolumeOptions opt)
    {
        var credentials = new VolumeCredentials(opt);
        var d = new Detection { FilePath = path, TypeName = opt.Kind == VolumeKind.TrueCrypt ? "TrueCrypt volume" : "VeraCrypt volume" };
        using var s = File.OpenRead(path);
        long off = opt.BootVolume && opt.HeaderOffset == 0 ? VolumeOptions.BootOffset : opt.HeaderOffset;
        if (off < 0 || off > s.Length - 512) throw new FormatException("File is too small for a volume header at this offset.");
        var h = Bin.ReadAt(s, off, 512);
        var modes = Modes(opt);
        if (modes.Count == 0) throw new ArgumentException("Select at least one hash algorithm and one encryption type.");

        string prefix = opt.Kind == VolumeKind.TrueCrypt ? "$truecrypt$" : "$veracrypt$";
        d.Add("Header offset", $"{off:N0}");
        d.Add("Combinations to test", $"{modes.Count} hashcat mode(s): {string.Join(", ", modes)}");
        if (opt.Keyfiles.Count > 0) d.Add("Keyfiles", opt.Keyfiles.Count.ToString());
        if (opt.Kind == VolumeKind.VeraCrypt) d.Add("PIM", opt.Pim == 0 ? "Default" : opt.Pim.ToString());
        d.Target = new HashTarget
        {
            FormatId = opt.Kind == VolumeKind.TrueCrypt ? "TRUE" : "VERA",
            FormatName = d.TypeName,
            Protection = $"{opt.Kdfs} / {opt.Ciphers} cipher(s), XTS",
            Modes = modes,
            HashLines = prefix + Bin.Hex(h, 0, 64) + "$" + Bin.Hex(h, 64, 448),
            VolumeCredentials = credentials.Arguments.Count > 0 ? credentials : null,
            Speed = SpeedClass.VerySlow,
            MaxPasswordLength = 64,
            Notes = "Every additional hash algorithm or cascade multiplies the work.",
        };
        return d;
    }

    public static List<int> Modes(VolumeOptions o)
    {
        var bases = new List<int>();
        bool tc = o.Kind == VolumeKind.TrueCrypt;
        void Add(VolumeKdf k, int normal, int boot)
        {
            if (!o.Kdfs.HasFlag(k)) return;
            int b = o.BootVolume ? boot : normal;
            if (b > 0) bases.Add(b);
        }
        if (tc)
        {
            Add(VolumeKdf.Ripemd160, 29310, 29340);
            Add(VolumeKdf.Sha512, 29320, 0);
            Add(VolumeKdf.Whirlpool, 29330, 0);
        }
        else
        {
            Add(VolumeKdf.Sha512, 29420, 0);
            Add(VolumeKdf.Sha256, 29450, 29460);
            Add(VolumeKdf.Ripemd160, 29410, 29440);
            Add(VolumeKdf.Whirlpool, 29430, 0);
            Add(VolumeKdf.Streebog, 29470, 29480);
        }
        var modes = new List<int>();
        foreach (var b in bases)
        {
            if (o.Ciphers.HasFlag(VolumeCipher.Single)) modes.Add(b + 1);
            if (o.Ciphers.HasFlag(VolumeCipher.Double)) modes.Add(b + 2);
            if (o.Ciphers.HasFlag(VolumeCipher.Triple)) modes.Add(b + 3);
        }
        return modes;
    }
}
