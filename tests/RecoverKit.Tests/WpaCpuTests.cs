using System.Text;
using RecoverKit.Core.Native;
using RecoverKit.Core.Native.Kernels;
using Xunit;

namespace RecoverKit.Tests;

[Collection("NativeFeatures")]
public class WpaCpuTests
{
    // hashcat 8.0.0 module_22000.c self-test, password "hashcat!".
    private const string HashcatExample = "WPA*01*4d4fe7aac3a2cecab195321ceb99a7d0*fc690c158264*f4747f87f9f4*686173686361742d6573736964***";
    // Python hashlib and cryptography CMAC fixtures following hashcat's m22000.py, password "password".
    private const string Pmkid = "WPA*01*2c5f58eac753301a96ea027d7e59c87f*001122334455*aabbccddeeff*49454545***";
    private const string Eapol1_123 = "WPA*02*429cc1e350a6fa655416349575e225af*001122334455*aabbccddeeff*49454545*000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f*0103007702010900000000000000000000202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000018b5bcc3cad1d8dfe6edf4fb020910171e252c333a41484f56*00";
    private const string Eapol2_121 = "WPA*02*8762bc5755c9e6a6f9f79ab4fb1186e8*aabbccddeeff*001122334455*49454545*202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f*0103007502010a00000000000000000000000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000016b5bcc3cad1d8dfe6edf4fb020910171e252c333a4148*00";
    private const string Eapol3_121 = "WPA*02*e1d85cf663a6231dd63a88b52ddee370*001122334455*aabbccddeeff*49454545*000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f*0103007502010b00000000000000000000202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000016b5bcc3cad1d8dfe6edf4fb020910171e252c333a4148*00";
    private const string Eapol3_112 = "WPA*02*d8b05c71289009875694af9385502019*aabbccddeeff*001122334455*49454545*202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f*0103006c02010b00000000000000000000000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000db5bcc3cad1d8dfe6edf4fb0209*00";
    private const string Eapol3_99 = "WPA*02*074af6bcca37f137cd89ac555e921adc*001122334455*aabbccddeeff*49454545*000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f*0103005f02010b00000000000000000000202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000*00";

    private static string[] Lines => [HashcatExample, Pmkid, Eapol1_123, Eapol2_121, Eapol3_121, Eapol3_112, Eapol3_99];
    public static IEnumerable<object[]> KnownAnswers => Lines.Concat(new[] { "00", "01", "04", "10", "80", "ff", "02", "03", "12", "82" }
        .Select(PmkidWithPair)).Select(line => new object[] { line });

    private static string PmkidWithPair(string pair)
    {
        string line = Pmkid + pair;
        if ((Convert.ToByte(pair, 16) & 2) == 0) return line;
        byte[] pmk = System.Security.Cryptography.Rfc2898DeriveBytes.Pbkdf2("password"u8, "IEEE"u8, 4096, System.Security.Cryptography.HashAlgorithmName.SHA1, 32);
        byte[] data = [.. "PMK Name"u8, .. Convert.FromHexString("001122334455aabbccddeeff")];
        string expected = Convert.ToHexStringLower(System.Security.Cryptography.HMACSHA256.HashData(pmk, data).AsSpan(0, 16));
        return line.Replace("2c5f58eac753301a96ea027d7e59c87f", expected);
    }

    [Theory]
    [MemberData(nameof(KnownAnswers))]
    public void ReferenceMatchesIndependentAnswers(string line)
    {
        var kernel = Assert.IsType<WpaKernel>(WpaKernel.TryParse(line));
        var password = line == HashcatExample ? "hashcat!"u8.ToArray() : "password"u8.ToArray();
        Assert.True(kernel.Verify(password));
        password[^1] ^= 1;
        Assert.False(kernel.Verify(password));
    }

    [Fact]
    public void NativeApiExecutesEveryKnownAnswer()
    {
        if (!RkNative.Available) return;
        Assert.Equal(19, RkNative.ApiVersion);
        foreach (string line in Lines)
        {
            RkNative.ResetExecutedPaths(22000);
            var kernel = Assert.IsType<WpaKernel>(NativeKernels.TryCreate(22000, line));
            byte[] password = line == HashcatExample ? "hashcat!"u8.ToArray() : "password"u8.ToArray();
            Assert.Equal(0, kernel.CreateWorker().SearchPasswords(password, password.Length, 1));
            Assert.NotEqual(0, RkNative.Pbkdf2Sha1ExecutedPaths());
        }
    }

    [Theory]
    [InlineData(1, "c337d9c5341ddf3416485d5cf5677886")]
    [InlineData(2, "e866318321c1a00ec6fa3b674d3f642d")]
    [InlineData(3, "6578bda410a3c7c45793f8e905aea5ac")]
    public void PreservesEncodedEapolMicBytesLikeHashcat(int version, string expected)
    {
        string[] fields = (version == 1 ? Eapol1_123 : version == 2 ? Eapol2_121 : Eapol3_121).Split('*');
        byte[] frame = Convert.FromHexString(fields[7]);
        for (int i = 0; i < 16; i++) frame[81 + i] = (byte)(i + 1);
        fields[7] = Convert.ToHexString(frame);
        Assert.False(WpaKernel.TryParse(string.Join('*', fields))!.Verify("password"u8));
        fields[2] = expected; // Independent Python HMAC/CMAC answer over the nonzero encoded MIC field.
        Assert.True(WpaKernel.TryParse(string.Join('*', fields))!.Verify("password"u8));
    }

    [Theory]
    [InlineData(98, false)]
    [InlineData(99, true)]
    [InlineData(512, true)]
    [InlineData(513, false)]
    public void BoundsTheEncodedEapolLength(int length, bool supported)
    {
        string[] fields = Eapol3_99.Split('*');
        byte[] frame = Convert.FromHexString(fields[7]);
        Array.Resize(ref frame, length);
        fields[7] = Convert.ToHexString(frame);
        Assert.Equal(supported, WpaKernel.TryParse(string.Join('*', fields)) != null);
        fields[7] += "0";
        Assert.Null(WpaKernel.TryParse(string.Join('*', fields)));
    }

    [Fact]
    public void VerifiesMaximumEapolLengthUsingEncodedRatherThanHeaderLength()
    {
        string[] fields = Eapol3_99.Split('*');
        byte[] frame = Convert.FromHexString(fields[7]);
        Array.Resize(ref frame, 512);
        fields[7] = Convert.ToHexString(frame);
        fields[2] = "b06c3283e3362ef5d289b18b19fd8e0a"; // Independent Python AES-CMAC answer.
        Assert.True(WpaKernel.TryParse(string.Join('*', fields))!.Verify("password"u8));
    }

    [Fact]
    public void MatchesAnyNetworkAndAnyRecordForOneEssid()
    {
        var kernel = WpaKernel.TryParse(HashcatExample + "\r\n" + Eapol2_121 + "\n" + Pmkid + "\n")!;
        Assert.True(kernel.Verify("password"u8));
        Assert.True(kernel.Verify("hashcat!"u8));
        Assert.False(kernel.Verify("incorrect"u8));
        var worker = kernel.CreateWorker();
        Assert.Equal(1, worker.SearchPasswords("wrongonepassword"u8, 8, 2));
        Assert.Equal(1, worker.SearchPasswords("wrongonehashcat!"u8, 8, 2));
    }

    [Fact]
    public void IdentifiesTheActualMatchingLineForPasswordCaching()
    {
        string lines = HashcatExample + "\r\n" + Pmkid + "\n";
        var kernel = WpaKernel.TryParse(lines)!;
        Assert.Equal(Pmkid, kernel.MatchingHashLine("password"u8, lines));
        Assert.Equal(HashcatExample, kernel.MatchingHashLine("hashcat!"u8, lines));
        Assert.Null(kernel.MatchingHashLine("incorrect"u8, lines));
        Assert.Null(kernel.MatchingHashLine("password"u8, lines + "WPA*02*deadbeef"));
    }

    [Fact]
    public void BuildsHashcatPotfileKeyForTheActualMatchingEssid()
    {
        // IEEE 802.11 PBKDF2 known answer: password "password", ESSID "IEEE".
        const string expected = "f42c6fc52df0ebef9ebb4b90b38a5f902e83fe1b135a70e23aed762e9710a12e*49454545";
        var sameEssid = WpaKernel.TryParse(Pmkid + "\n" + Eapol2_121)!;
        Assert.Equal(expected, sameEssid.PotfileKey("password"u8, Pmkid + "\n" + Eapol2_121));
        string lines = HashcatExample + "\r\n" + Pmkid + "\n";
        var kernel = WpaKernel.TryParse(lines)!;
        Assert.Equal(expected, kernel.PotfileKey("password"u8, lines));
        Assert.Null(kernel.PotfileKey("incorrect"u8, lines));
    }

    [Theory]
    [InlineData("1234567", "2acce745d570e3bca4e790113e2275f1", false)]
    [InlineData("12345678", "f974a7ec30e7a5e5f822f66852d747d0", true)]
    [InlineData("abcd\u00e9\u00e9", "5d3c03ec8a5b5fe131cdc3c5a2abfb44", true)]
    public void UsesPasswordByteLength(string password, string expected, bool supported)
    {
        var bytes = Encoding.UTF8.GetBytes(password);
        var kernel = WpaKernel.TryParse(Pmkid.Replace("2c5f58eac753301a96ea027d7e59c87f", expected))!;
        Assert.Equal(supported, kernel.SupportsDictionaryPassword(bytes));
        Assert.Equal(supported, kernel.Verify(bytes));
        Assert.Equal(supported ? 0 : -1, kernel.CreateWorker().SearchPasswords(bytes, bytes.Length, 1));
    }

    [Theory]
    [InlineData(63, "8f1d88121e6cf4b76b38ff6825b52a1c", true)]
    [InlineData(64, "58bd580f2b70e92e2afd52b57c1b696b", false)]
    public void EnforcesMaximumPasswordBytes(int length, string expected, bool supported)
    {
        var password = Encoding.ASCII.GetBytes(new string('x', length));
        var kernel = WpaKernel.TryParse(Pmkid.Replace("2c5f58eac753301a96ea027d7e59c87f", expected))!;
        Assert.Equal(supported, kernel.Verify(password));
        Assert.Equal(supported, kernel.SupportsDictionaryPassword(password));
        Assert.Equal(supported ? 0 : -1, kernel.CreateWorker().SearchPasswords(password, length, 1));
        Assert.Equal(supported ? 0 : -1, kernel.CreateWorker().Search(password.AsSpan(0, length - 1), password.AsSpan(length - 1)));
    }

    [Fact]
    public void RejectsSixtyFourUtf8BytesEvenWithThirtyTwoCharacters()
    {
        var password = Encoding.UTF8.GetBytes(new string('\u00e9', 32));
        var kernel = WpaKernel.TryParse(Pmkid.Replace("2c5f58eac753301a96ea027d7e59c87f", "6d8e44ee78a42deb5c09f3976ce00e09"))!;
        Assert.False(kernel.Verify(password));
        Assert.False(kernel.SupportsDictionaryPassword(password));
        Assert.Equal(-1, kernel.CreateWorker().SearchPasswords(password, password.Length, 1));
    }

    [Theory]
    [InlineData("00", true)]
    [InlineData("01", true)]
    [InlineData("02", true)]
    [InlineData("03", true)]
    [InlineData("04", true)]
    [InlineData("05", true)]
    [InlineData("06", false)]
    [InlineData("08", false)]
    [InlineData("20", true)]
    [InlineData("40", true)]
    [InlineData("80", false)]
    [InlineData("a0", false)]
    [InlineData("c0", false)]
    [InlineData("90", true)]
    public void RespectsMessagePairNonceCorrectionMetadata(string pair, bool supported)
    {
        var line = Eapol2_121[..^2] + pair;
        Assert.Equal(supported, WpaKernel.TryParse(line) != null);
        if (supported) Assert.True(WpaKernel.TryParse(line)!.Verify("password"u8));
        else Assert.Null(WpaKernel.TryParse(Pmkid + "\n" + line));
    }

    [Theory]
    [InlineData("00", false)]
    [InlineData("01", false)]
    [InlineData("04", false)]
    [InlineData("10", false)]
    [InlineData("80", false)]
    [InlineData("ff", true)]
    [InlineData("02", true)]
    [InlineData("03", true)]
    [InlineData("12", true)]
    [InlineData("82", true)]
    public void PmkidUsesOnlyTheSha256MessagePairBit(string pair, bool sha256)
    {
        string line = PmkidWithPair(pair);
        Assert.Equal(sha256, (Convert.ToByte(pair, 16) & 2) != 0);
        var kernel = Assert.IsType<WpaKernel>(WpaKernel.TryParse(line));
        Assert.True(kernel.Verify("password"u8));
        Assert.False(kernel.Verify("wrongone"u8));
        Assert.Equal(0, kernel.CreateWorker().SearchPasswords("password"u8, 8, 1));
    }

    [Fact]
    public void RejectsEveryUnsupportedOrMalformedLine()
    {
        var fields = Eapol2_121.Split('*');
        var invalid = new List<string> { "", "WPA*02*deadbeef", Pmkid.Replace("WPA*01", "WPA*03"), Pmkid + "zz", Pmkid.Replace("49454545", new string('a', 66)), Pmkid.Replace("49454545", "123") };
        foreach (var (field, value) in new[] { (0, "OTHER"), (1, "04"), (2, "00"), (3, "001122"), (4, "zz1122334455"), (6, "00"), (7, "01030000020000"), (8, ""), (8, "000") })
        {
            var bad = (string[])fields.Clone();
            bad[field] = value;
            invalid.Add(string.Join('*', bad));
        }
        var badKey = (string[])fields.Clone();
        badKey[7] = badKey[7][..12] + "08" + badKey[7][14..];
        invalid.Add(string.Join('*', badKey));
        foreach (string line in invalid)
        {
            Assert.Null(WpaKernel.TryParse(line));
            if (line.Length > 0) Assert.Null(WpaKernel.TryParse(Pmkid + "\n" + line));
        }
    }

    [Fact]
    public void ManagedAndNativeWorkersAgreeOnBatchIndexes()
    {
        foreach (string line in Lines)
        {
            var kernel = WpaKernel.TryParse(line)!;
            byte[] password = line == HashcatExample ? "hashcat!"u8.ToArray() : "password"u8.ToArray();
            var prefixes = new byte[(password.Length - 1) * 2];
            prefixes.AsSpan(0, password.Length - 1).Fill((byte)'x');
            password.AsSpan(0, password.Length - 1).CopyTo(prefixes.AsSpan(password.Length - 1));
            byte[] last = [(byte)'X', password[^1], (byte)'Z'];
            bool disabled = RkNative.Disabled;
            try
            {
                RkNative.Disabled = true;
                Assert.Equal(4, kernel.CreateWorker().SearchBatch(prefixes, 2, last));
                RkNative.Disabled = disabled;
                Assert.Equal(4, kernel.CreateWorker().SearchBatch(prefixes, 2, last));
                Assert.Equal(1, kernel.CreateWorker().Search(password.AsSpan(0, password.Length - 1), last));
                Assert.Equal(-1, kernel.CreateWorker().Search("xxxxxxxx"u8, last));
                Assert.Equal(-1, kernel.CreateWorker().SearchBatch([], 0, last));
            }
            finally { RkNative.Disabled = disabled; }
        }
    }

    [Fact]
    public void NativePathsHandlePartialAndMultipleGroups()
    {
        if (!RkNative.Available) return;
        var kernel = WpaKernel.TryParse(Pmkid)!;
        var all = (RkNative.Feature)~0;
        try
        {
            foreach (var mask in new[] { all, all & ~RkNative.Feature.Avx512, (RkNative.Feature)0 })
            {
                RkNative.LimitFeatures(mask);
                RkNative.ResetExecutedPaths(22000);
                foreach (int count in new[] { 1, 7, 8, 9, 15, 16, 17, 33, 65 })
                {
                    var passwords = Enumerable.Repeat((byte)'x', count * 8).ToArray();
                    "password"u8.CopyTo(passwords.AsSpan((count - 1) * 8));
                    Assert.Equal(count - 1, kernel.CreateWorker().SearchPasswords(passwords, 8, count));
                }
                Assert.NotEqual(0, RkNative.Pbkdf2Sha1ExecutedPaths());
            }
        }
        finally { RkNative.LimitFeatures(all); }
    }

    [Fact]
    public void RechecksAnOverflowOfMatchingCandidates()
    {
        var kernel = WpaKernel.TryParse(Pmkid)!;
        var passwords = new byte[65 * 8];
        for (int i = 0; i < 65; i++) "password"u8.CopyTo(passwords.AsSpan(i * 8));
        Assert.Equal(0, kernel.CreateWorker().SearchPasswords(passwords, 8, 65));
    }
}
