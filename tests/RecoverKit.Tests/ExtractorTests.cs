using RecoverKit.Core.Formats;
using Xunit;

namespace RecoverKit.Tests;

public class ExtractorTests
{
    [Fact]
    public void PdfStringParsesHexAndLiteral()
    {
        Assert.Equal([0x01, 0x23, 0xAB], PdfExtractor.ParseString("<0123AB>"));
        Assert.Equal("ABC"u8.ToArray(), PdfExtractor.ParseString("(ABC)"));
        Assert.Equal([0x0A, 0x28], PdfExtractor.ParseString("(\\n\\050)")); // newline, octal 050 = '('
    }

    [Fact]
    public void WpaHashLineDetection()
    {
        Assert.True(WpaExtractor.IsHashLines("WPA*01*abc"u8.ToArray()));
        Assert.True(WpaExtractor.IsHashLines("WPA*02*abc"u8.ToArray()));
        Assert.False(WpaExtractor.IsHashLines("PK\x03\x04"u8.ToArray()));
    }

    [Fact]
    public void VolumeModesForSingleKdfSingleCipher()
    {
        var o = new VolumeOptions { Kind = VolumeKind.VeraCrypt, Kdfs = VolumeKdf.Sha512, Ciphers = VolumeCipher.Single };
        Assert.Equal([29421], CryptVolume.Modes(o));
    }

    [Fact]
    public void VolumeModesMultiplyOut()
    {
        var o = new VolumeOptions
        {
            Kind = VolumeKind.VeraCrypt,
            Kdfs = VolumeKdf.Sha512 | VolumeKdf.Ripemd160,
            Ciphers = VolumeCipher.Single | VolumeCipher.Triple,
        };
        var modes = CryptVolume.Modes(o);
        Assert.Equal(4, modes.Count);
        Assert.Contains(29421, modes); // SHA512 single
        Assert.Contains(29423, modes); // SHA512 triple
        Assert.Contains(29411, modes); // RIPEMD160 single
        Assert.Contains(29413, modes); // RIPEMD160 triple
    }

    [Fact]
    public void TrueCryptBootModeUsesBootVariant()
    {
        var o = new VolumeOptions { Kind = VolumeKind.TrueCrypt, Kdfs = VolumeKdf.Ripemd160, Ciphers = VolumeCipher.Single, BootVolume = true };
        Assert.Equal([29341], CryptVolume.Modes(o));
    }

    [Fact]
    public void ManualHashTargetPassesThrough()
    {
        var d = FormatDetector.FromManualHash("x", 22000, "WPA*02*deadbeef");
        Assert.NotNull(d.Target);
        Assert.Equal([22000], d.Target!.Modes);
        Assert.Equal("WPA*02*deadbeef", d.Target.HashLines);
    }

    [Fact]
    public void MissingFileReportsMessage()
    {
        var d = FormatDetector.Detect(Path.Combine(Path.GetTempPath(), "does-not-exist-" + Guid.NewGuid() + ".zip"));
        Assert.Null(d.Target);
        Assert.NotNull(d.Message);
    }

    [Fact]
    public void PdfDetectedFromHeader()
    {
        Assert.True(PdfExtractor.IsPdf("%PDF-1.7\nrest"u8.ToArray()));
        Assert.False(PdfExtractor.IsPdf("not a pdf"u8.ToArray()));
    }

    // Reconstruct a keybag that must reproduce hashcat's own -m 14800 example hash, validating the
    // keybag TLV parser, the plist reader and the $itunes_backup$ assembly end to end.
    [Fact]
    public void AppleBackupProducesHashcatExampleHash()
    {
        const string wpky = "17a3b858e79bc273be43a9f113b71efe7ec8e7e401396b350180b4592ef45db67ffef7b2d64329a5";
        const string salt = "2721336781705041205314422175267631184867";
        const string dpsl = "99fafc983e732998adb9fadc162a2e382143f115";
        const string expected = $"$itunes_backup$*10*{wpky}*10000*{salt}*1000*{dpsl}";

        static byte[] Be32(uint v) => [(byte)(v >> 24), (byte)(v >> 16), (byte)(v >> 8), (byte)v];
        static byte[] Tlv(string tag, byte[] val) => [.. System.Text.Encoding.ASCII.GetBytes(tag), .. Be32((uint)val.Length), .. val];
        byte[] keybag =
        [
            .. Tlv("SALT", Convert.FromHexString(salt)),
            .. Tlv("ITER", Be32(10000)),
            .. Tlv("DPSL", Convert.FromHexString(dpsl)),
            .. Tlv("DPIC", Be32(1000)),
            .. Tlv("UUID", new byte[16]),
            .. Tlv("WPKY", Convert.FromHexString(wpky)),
        ];
        string xml = "<?xml version=\"1.0\"?><plist version=\"1.0\"><dict>" +
                     "<key>IsEncrypted</key><true/>" +
                     "<key>BackupKeyBag</key><data>" + Convert.ToBase64String(keybag) + "</data>" +
                     "</dict></plist>";

        var d = new Detection { FilePath = "Manifest.plist" };
        AppleBackupExtractor.Extract(new MemoryStream(System.Text.Encoding.UTF8.GetBytes(xml)), "Manifest.plist", d);
        Assert.NotNull(d.Target);
        Assert.Equal([14800], d.Target!.Modes);
        Assert.Equal(expected, d.Target.HashLines);
    }

    // hashcat's own -m 14700 example hash ends with TWO trailing asterisks (empty DPIC and DPSL
    // fields): "$itunes_backup$*9*<wpky>*10000*<salt>**". This locks that format in.
    [Fact]
    public void AppleBackupPreIos10ProducesTrailingDoubleAsterisk()
    {
        const string wpky = "ebd7f9b33293b2511f0a4139d5b213feff51476968863cef60ec38d720497b6ff39a0bb63fa9f84e";
        const string salt = "2202015774208421818002001652122401871832";
        const string expected = $"$itunes_backup$*9*{wpky}*10000*{salt}**";

        static byte[] Be32(uint v) => [(byte)(v >> 24), (byte)(v >> 16), (byte)(v >> 8), (byte)v];
        static byte[] Tlv(string tag, byte[] val) => [.. System.Text.Encoding.ASCII.GetBytes(tag), .. Be32((uint)val.Length), .. val];
        byte[] keybag =
        [
            .. Tlv("SALT", Convert.FromHexString(salt)),
            .. Tlv("ITER", Be32(10000)),
            .. Tlv("UUID", new byte[16]),
            .. Tlv("WPKY", Convert.FromHexString(wpky)),
        ];
        string xml = "<?xml version=\"1.0\"?><plist version=\"1.0\"><dict>" +
                     "<key>IsEncrypted</key><true/>" +
                     "<key>BackupKeyBag</key><data>" + Convert.ToBase64String(keybag) + "</data>" +
                     "</dict></plist>";

        var d = new Detection { FilePath = "Manifest.plist" };
        AppleBackupExtractor.Extract(new MemoryStream(System.Text.Encoding.UTF8.GetBytes(xml)), "Manifest.plist", d);
        Assert.NotNull(d.Target);
        Assert.Equal([14700], d.Target!.Modes);
        Assert.Equal(expected, d.Target.HashLines);
    }

    [Fact]
    public void PlistBinaryRoundTripsDataAndBool()
    {
        // bplist00 with a dict {"k": <01 02 03>, "b": true} built by hand.
        // Objects: 0=dict, 1="k", 2=data, 3="b", 4=true
        var objs = new byte[][]
        {
            new byte[] { 0xD2, 1, 3, 2, 4 },   // dict count=2, keyrefs[1,3], valrefs[2,4]
            new byte[] { 0x51, (byte)'k' },     // ascii "k"
            new byte[] { 0x43, 1, 2, 3 },       // data len 3
            new byte[] { 0x51, (byte)'b' },     // ascii "b"
            new byte[] { 0x09 },                // true
        };
        var body = new List<byte>(System.Text.Encoding.ASCII.GetBytes("bplist00"));
        var offsets = new List<int>();
        foreach (var o in objs) { offsets.Add(body.Count); body.AddRange(o); }
        int tableOffset = body.Count;
        foreach (var off in offsets) body.Add((byte)off);
        body.AddRange(new byte[6]);
        body.Add(1); // offsetIntSize
        body.Add(1); // objectRefSize
        body.AddRange(Be64((ulong)objs.Length));
        body.AddRange(Be64(0));          // top object
        body.AddRange(Be64((ulong)tableOffset));

        var root = Plist.ParseRootDict(body.ToArray());
        Assert.Equal(new byte[] { 1, 2, 3 }, (byte[])root["k"]!);
        Assert.Equal(true, root["b"]);

        static byte[] Be64(ulong v)
        {
            var b = new byte[8];
            for (int i = 7; i >= 0; i--) { b[i] = (byte)v; v >>= 8; }
            return b;
        }
    }
}
