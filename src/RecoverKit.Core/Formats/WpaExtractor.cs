using System.Text;

namespace RecoverKit.Core.Formats;

/// <summary>
/// WPA/WPA2 handshakes: hashcat 22000 text lines (passed through), and the
/// older binary .hccapx (393-byte records) and .hccap (392-byte records)
/// containers converted to 22000 EAPOL lines. Raw .cap/.pcapng captures must be
/// converted first (hcxpcapngtool).
/// </summary>
public static class WpaExtractor
{
    public static bool IsHashLines(byte[] head) => head.Length >= 6 && Encoding.ASCII.GetString(head, 0, 6) is "WPA*01" or "WPA*02";
    public static bool IsHccapx(byte[] head) => head.Length >= 4 && head[0] == 'H' && head[1] == 'C' && head[2] == 'P' && head[3] == 'X';

    public static void Extract(Stream s, string path, byte[] head, Detection d)
    {
        var all = Bin.ReadAt(s, 0, (int)Math.Min(s.Length, 64 * 1024 * 1024));
        var lines = new List<string>();
        var essids = new HashSet<string>();

        if (IsHashLines(head))
        {
            d.TypeName = "WPA handshake / PMKID (hashcat 22000)";
            foreach (var line in Encoding.ASCII.GetString(all).Split('\n'))
            {
                var l = line.Trim();
                if (!l.StartsWith("WPA*0")) continue;
                lines.Add(l);
                var f = l.Split('*');
                if (f.Length > 5) essids.Add(EssidText(Convert.FromHexString(f[5])));
            }
        }
        else if (IsHccapx(head))
        {
            d.TypeName = "WPA handshake (hccapx)";
            for (int o = 0; o + 393 <= all.Length; o += 393)
            {
                if (!IsHccapx(all.AsSpan(o, 4).ToArray())) break;
                int msgPair = all[o + 8], essidLen = Math.Min(all[o + 9], (byte)32);
                var essid = all.AsSpan(o + 10, essidLen).ToArray();
                var mic = all.AsSpan(o + 43, 16).ToArray();
                var macAp = all.AsSpan(o + 59, 6).ToArray();
                var nonceAp = all.AsSpan(o + 65, 32).ToArray();
                var macSta = all.AsSpan(o + 97, 6).ToArray();
                int eapolLen = Math.Min((int)Bin.U16(all, o + 135), 256);
                var eapol = all.AsSpan(o + 137, eapolLen).ToArray();
                lines.Add(Line(mic, macAp, macSta, essid, nonceAp, eapol, msgPair));
                essids.Add(EssidText(essid));
            }
        }
        else if (path.EndsWith(".hccap", StringComparison.OrdinalIgnoreCase) && all.Length % 392 == 0 && all.Length > 0)
        {
            d.TypeName = "WPA handshake (hccap)";
            for (int o = 0; o + 392 <= all.Length; o += 392)
            {
                var essidRaw = all.AsSpan(o, 36).ToArray();
                int z = Array.IndexOf(essidRaw, (byte)0);
                var essid = essidRaw.AsSpan(0, z < 0 ? 32 : Math.Min(z, 32)).ToArray();
                var macAp = all.AsSpan(o + 36, 6).ToArray();
                var macSta = all.AsSpan(o + 42, 6).ToArray();
                var anonce = all.AsSpan(o + 80, 32).ToArray();
                int eapolLen = Math.Min(Bin.I32(all, o + 368), 256);
                var eapol = all.AsSpan(o + 112, eapolLen).ToArray();
                var mic = all.AsSpan(o + 376, 16).ToArray();
                lines.Add(Line(mic, macAp, macSta, essid, anonce, eapol, 0));
                essids.Add(EssidText(essid));
            }
        }
        else
        {
            throw new UnsupportedFormatException("Unknown WPA container.");
        }

        if (lines.Count == 0) { d.Message = "No usable handshakes found."; return; }
        d.Add("Handshakes / PMKIDs", lines.Count.ToString());
        d.Add("Networks (ESSID)", string.Join(", ", essids.Take(10)));
        d.Target = new HashTarget
        {
            FormatId = "WPAH",
            FormatName = "WPA/WPA2 handshake",
            Protection = "PBKDF2-HMAC-SHA1 4096 iterations (salt = ESSID)",
            Modes = [22000],
            HashLines = string.Join('\n', lines.Distinct()),
            Speed = SpeedClass.Slow,
            MaxPasswordLength = 63,
            Notes = "WPA passphrases are 8 to 63 bytes long. Dictionary rules can shorten or extend words up to 256 bytes; longer words are skipped.",
        };
    }

    private static string Line(byte[] mic, byte[] macAp, byte[] macSta, byte[] essid, byte[] anonce, byte[] eapol, int msgPair)
    {
        var e = (byte[])eapol.Clone();
        if (e.Length >= 97) Array.Clear(e, 81, 16); // MIC field inside the EAPOL-Key frame must be zero
        return $"WPA*02*{Bin.Hex(mic)}*{Bin.Hex(macAp)}*{Bin.Hex(macSta)}*{Bin.Hex(essid)}*{Bin.Hex(anonce)}*{Bin.Hex(e)}*{msgPair:x2}";
    }

    private static string EssidText(byte[] essid)
    {
        try { return new UTF8Encoding(false, true).GetString(essid); }
        catch { return "$HEX[" + Bin.Hex(essid) + "]"; }
    }
}
