using System.Security.Cryptography;

namespace RecoverKit.Core.Native.Kernels;

/// <summary>WPA 22000 PMKID and EAPOL checks, with native batched PBKDF2 and managed MIC verification.</summary>
public sealed unsafe class WpaKernel : NativeKernel, INativeFilter
{
    private sealed record Record(byte[] Essid, byte[] Expected, byte[] KeyData, byte[] Eapol, int Version);
    private readonly Record[][] _networks;

    private WpaKernel(List<Record> records) => _networks = records
        .GroupBy(r => Convert.ToHexString(r.Essid)).Select(g => g.ToArray()).ToArray();

    public override string Name => "WPA/WPA2 (PBKDF2-HMAC-SHA1 x 4096)";
    public override int MaxPasswordLength => 63;
    public override double SpeedHint => 1000.0 / _networks.Length;
    public override bool SupportsDictionaryPassword(ReadOnlySpan<byte> password) => password.Length is >= 8 and <= 63;
    internal static bool NativeFast => RkNative.Available;

    /// <summary>Hashcat indexes WPA potfile entries by PMK and ESSID rather than by the original capture line.</summary>
    internal string? PotfileKey(ReadOnlySpan<byte> password, string lines)
    {
        string? line = MatchingHashLine(password, lines);
        if (line is null) return null;
        byte[] essid = Convert.FromHexString(line.Split('*')[5]);
        byte[] pmk = Rfc2898DeriveBytes.Pbkdf2(password, essid, 4096, HashAlgorithmName.SHA1, 32);
        return Convert.ToHexStringLower(pmk) + "*" + Convert.ToHexStringLower(essid);
    }

    /// <summary>A multi-network hit belongs only to the record that independently verified it.</summary>
    internal string? MatchingHashLine(ReadOnlySpan<byte> password, string lines)
    {
        if (TryParse(lines) is null) return null;
        foreach (string line in lines.Split('\n', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries))
            if (TryParse(line)!.Verify(password)) return line;
        return null;
    }

    /// <summary>Any unsupported record sends the entire target to hashcat, including supported records.</summary>
    public static WpaKernel? TryParse(string lines)
    {
        var records = new List<Record>();
        try
        {
            foreach (string line in lines.Split('\n', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries))
            {
                var f = line.Split('*');
                if (f.Length != 9 || f[0] != "WPA" || (f[1] != "01" && f[1] != "02") ||
                    f[2].Length != 32 || f[3].Length != 12 || f[4].Length != 12 || f[5].Length > 64 ||
                    (f[8].Length != 0 && f[8].Length != 2)) return null;
                byte[] expected = Convert.FromHexString(f[2]), ap = Convert.FromHexString(f[3]), sta = Convert.FromHexString(f[4]),
                    essid = Convert.FromHexString(f[5]);
                int pair = f[8].Length == 0 ? 0 : Convert.FromHexString(f[8])[0];
                if (f[1] == "01")
                {
                    // Only bit 1 selects the PMKID digest; the other bits are capture metadata.
                    if (f[6].Length != 0 || f[7].Length != 0) return null;
                    var data = new byte[20];
                    "PMK Name"u8.CopyTo(data);
                    ap.CopyTo(data, 8);
                    sta.CopyTo(data, 14);
                    records.Add(new Record(essid, expected, data, [], (pair & 2) != 0 ? -1 : 0));
                    continue;
                }
                if (f[6].Length != 64 || f[7].Length is < 198 or > 1024 || f[8].Length != 2 ||
                    (pair & 7) > 5 || (pair & 8) != 0) return null;
                // hashcat module_22000 postprocess: bit 7 needs nonce correction unless AP-less bit 4 is set.
                if ((pair & 0x80) != 0 && (pair & 0x10) == 0) return null;
                byte[] nonce = Convert.FromHexString(f[6]), eapol = Convert.FromHexString(f[7]);
                int version = eapol[6] & 7;
                if (version is < 1 or > 3) return null;
                byte[] keyData = new byte[version == 3 ? 102 : 100];
                int offset;
                if (version == 3)
                {
                    keyData[0] = 1; // KDF counter and output size are little endian.
                    "Pairwise key expansion"u8.CopyTo(keyData.AsSpan(2));
                    keyData[100] = 0x80;
                    keyData[101] = 1;
                    offset = 24;
                }
                else
                {
                    "Pairwise key expansion"u8.CopyTo(keyData);
                    offset = 23; // NUL after the label; final PRF counter is also zero.
                }
                CopySorted(ap, sta, keyData.AsSpan(offset));
                CopySorted(nonce, eapol.AsSpan(17, 32), keyData.AsSpan(offset + 12));
                records.Add(new Record(essid, expected, keyData, eapol, version));
            }
        }
        catch (FormatException) { return null; }
        return records.Count == 0 ? null : new WpaKernel(records);
    }

    private static void CopySorted(ReadOnlySpan<byte> first, ReadOnlySpan<byte> second, Span<byte> output)
    {
        if (first.SequenceCompareTo(second) <= 0)
        {
            first.CopyTo(output);
            second.CopyTo(output[first.Length..]);
        }
        else
        {
            second.CopyTo(output);
            first.CopyTo(output[second.Length..]);
        }
    }

    public override bool Verify(ReadOnlySpan<byte> password)
    {
        if (!SupportsDictionaryPassword(password)) return false;
        Span<byte> pmk = stackalloc byte[32];
        foreach (var network in _networks)
        {
            Rfc2898DeriveBytes.Pbkdf2(password, network[0].Essid, pmk, 4096, HashAlgorithmName.SHA1);
            foreach (var record in network)
                if (CheckPmk(pmk, record)) return true;
        }
        return false;
    }

    private static bool CheckPmk(ReadOnlySpan<byte> pmk, Record record)
    {
        Span<byte> digest = stackalloc byte[32];
        if (record.Version == -1) HMACSHA256.HashData(pmk, record.KeyData, digest);
        else if (record.Version == 0) HMACSHA1.HashData(pmk, record.KeyData, digest);
        else
        {
            if (record.Version == 3) HMACSHA256.HashData(pmk, record.KeyData, digest);
            else HMACSHA1.HashData(pmk, record.KeyData, digest);
            Span<byte> kck = stackalloc byte[16];
            digest[..16].CopyTo(kck);
            if (record.Version == 1) HMACMD5.HashData(kck, record.Eapol, digest);
            else if (record.Version == 2) HMACSHA1.HashData(kck, record.Eapol, digest);
            else Cmac(kck, record.Eapol, digest[..16]);
        }
        return CryptographicOperations.FixedTimeEquals(digest[..16], record.Expected);
    }

    private static void Cmac(ReadOnlySpan<byte> key, ReadOnlySpan<byte> message, Span<byte> result)
    {
        using var aes = Aes.Create();
        aes.Key = key.ToArray();
        Span<byte> subkey = stackalloc byte[16], block = stackalloc byte[16];
        subkey.Clear();
        aes.EncryptEcb(subkey, subkey, PaddingMode.None);
        Double(subkey);
        bool complete = message.Length % 16 == 0;
        if (!complete) Double(subkey);
        block.Clear();
        int last = (message.Length - 1) / 16 * 16;
        for (int offset = 0; offset < last; offset += 16)
        {
            for (int i = 0; i < 16; i++) block[i] ^= message[offset + i];
            aes.EncryptEcb(block, block, PaddingMode.None);
        }
        for (int i = 0; i < message.Length - last; i++) block[i] ^= message[last + i];
        if (!complete) block[message.Length - last] ^= 0x80;
        for (int i = 0; i < 16; i++) block[i] ^= subkey[i];
        aes.EncryptEcb(block, result, PaddingMode.None);
    }

    private static void Double(Span<byte> block)
    {
        int carry = block[0] >> 7;
        for (int i = 0; i < 15; i++) block[i] = (byte)((block[i] << 1) | (block[i + 1] >> 7));
        block[15] = (byte)((block[15] << 1) ^ (carry * 0x87));
    }

    public override KernelWorker CreateWorker() => new NativeFilterWorker(this, this, new ReferenceWorker(this));
    public override int PrefixBatch(int lastCount) => RkNative.BatchFor(lastCount, 64);

    int INativeFilter.Filter(byte* pws, int len, int n, int* hits, int maxHits)
    {
        if (len is < 8 or > 63 || n <= 0) return 0;
        if (!RkNative.Available) return -1;
        var pmks = new byte[checked(n * 32)];
        var matched = new bool[n];
        fixed (byte* keys = pmks)
        {
            foreach (var network in _networks)
            {
                fixed (byte* salt = network[0].Essid)
                    if (RkNative.Pbkdf2Sha1(pws, len, null, n, salt, network[0].Essid.Length, 4096, keys, 32) != 0) return -1;
                for (int i = 0; i < n; i++)
                {
                    if (matched[i]) continue;
                    foreach (var record in network)
                    {
                        if (!CheckPmk(pmks.AsSpan(i * 32, 32), record)) continue;
                        matched[i] = true;
                        break;
                    }
                }
            }
        }
        int count = 0;
        for (int i = 0; i < n; i++)
        {
            if (!matched[i]) continue;
            if (count == maxHits) return -1;
            hits[count++] = i;
        }
        return count;
    }

    private sealed class ReferenceWorker(WpaKernel kernel) : KernelWorker
    {
        public override int Search(ReadOnlySpan<byte> prefix, ReadOnlySpan<byte> last)
        {
            if (prefix.Length is < 7 or > 62) return -1;
            Span<byte> password = stackalloc byte[prefix.Length + 1];
            prefix.CopyTo(password);
            for (int i = 0; i < last.Length; i++)
            {
                password[^1] = last[i];
                if (kernel.Verify(password)) return i;
            }
            return -1;
        }
    }
}
