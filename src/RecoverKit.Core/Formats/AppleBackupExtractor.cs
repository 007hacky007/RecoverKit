using System.Text;

namespace RecoverKit.Core.Formats;

/// <summary>
/// Extracts the password hash from an encrypted Apple iOS / iTunes backup by reading its
/// <c>Manifest.plist</c> and the embedded BackupKeyBag, producing a hashcat $itunes_backup$ hash
/// (mode 14700 for backups made before iOS 10.2, mode 14800 for the double-protected newer ones).
///
/// NOTE: implemented to the documented keybag/hash format and hashcat's example hashes, but not
/// runtime-verified against a real backup in this environment.
/// </summary>
public static class AppleBackupExtractor
{
    public static bool IsManifest(string path, byte[] head)
    {
        if (Path.GetFileName(path).Equals("Manifest.plist", StringComparison.OrdinalIgnoreCase)) return true;
        if (head.Length >= 8 && Encoding.ASCII.GetString(head, 0, 6) == "bplist") return true;
        var text = Encoding.ASCII.GetString(head, 0, Math.Min(head.Length, 256));
        return text.Contains("<?xml") || text.Contains("<plist");
    }

    public static void Extract(Stream s, string path, Detection d)
    {
        d.TypeName = "Property list";
        var data = Bin.ReadAt(s, 0, (int)Math.Min(s.Length, 8 * 1024 * 1024));

        Dictionary<string, object?> root;
        try { root = Plist.ParseRootDict(data); }
        catch (FormatException ex) { d.Message = "Cannot read property list: " + ex.Message; return; }

        if (!root.TryGetValue("BackupKeyBag", out var kbObj) || kbObj is not byte[] keybag)
        {
            d.Message = "This is a property list but not an encrypted iOS backup Manifest.plist (no BackupKeyBag).";
            return;
        }
        d.TypeName = "Apple iOS / iTunes backup";
        if (root.TryGetValue("ProductVersion", out var pv) && pv is string pvs) d.Add("iOS version", pvs);
        bool encrypted = root.TryGetValue("IsEncrypted", out var enc) && enc is true;
        if (!encrypted)
        {
            d.Message = "This backup is not password-encrypted; there is nothing to recover.";
            return;
        }

        var (salt, iter, dpsl, dpic, wpky) = ParseKeybag(keybag);
        if (salt is null || iter is null || wpky is null)
        {
            d.Message = "The BackupKeyBag does not contain the expected SALT/ITER/WPKY fields.";
            return;
        }

        bool v10 = dpsl is not null && dpic is not null;
        int mode = v10 ? 14800 : 14700;
        int ver = v10 ? 10 : 9;
        string hash = $"$itunes_backup$*{ver}*{Bin.Hex(wpky)}*{iter}*{Bin.Hex(salt)}*{(v10 ? dpic.ToString() : "")}*{(v10 ? Bin.Hex(dpsl!) : "")}";

        d.Target = new HashTarget
        {
            FormatId = v10 ? "APL0" : "APL7",
            FormatName = v10 ? "Apple iOS backup (iOS 10.2+)" : "Apple iOS backup (pre-iOS 10.2)",
            Protection = $"PBKDF2-SHA256, {iter} iterations" + (v10 ? $", double protection ({dpic} iterations)" : ""),
            Modes = [mode],
            HashLines = hash,
            Speed = SpeedClass.VerySlow,
            MaxPasswordLength = 256,
            Notes = "Open the Manifest.plist from the backup folder. Backup recovery is implemented but not runtime-verified.",
        };
    }

    /// <summary>Walks the keybag TLV stream (4-byte ASCII tag, 4-byte big-endian length, value).</summary>
    private static (byte[]? Salt, uint? Iter, byte[]? Dpsl, uint? Dpic, byte[]? Wpky) ParseKeybag(byte[] kb)
    {
        byte[]? salt = null, dpsl = null, wpky = null;
        uint? iter = null, dpic = null;
        int i = 0;
        while (i + 8 <= kb.Length)
        {
            string tag = Encoding.ASCII.GetString(kb, i, 4);
            long len = Bin.U32BE(kb, i + 4);
            int val = i + 8;
            if (len < 0 || (long)val + len > kb.Length) break;
            int ilen = (int)len;
            switch (tag)
            {
                case "SALT" when salt is null: salt = kb[val..(val + ilen)]; break;
                case "ITER" when iter is null && ilen == 4: iter = Bin.U32BE(kb, val); break;
                case "DPSL" when dpsl is null: dpsl = kb[val..(val + ilen)]; break;
                case "DPIC" when dpic is null && ilen == 4: dpic = Bin.U32BE(kb, val); break;
                case "WPKY" when wpky is null && ilen == 40: wpky = kb[val..(val + ilen)]; break;
            }
            i = val + ilen;
        }
        return (salt, iter, dpsl, dpic, wpky);
    }
}
