using System.Text;
using Xunit;

namespace RecoverKit.Tests.Stay;

public class ZipStayArchiveTests
{
    private const string Password = "&THPOL101%ISLAME@|1";

    private static List<GeneratedEntry> Entries(int count, bool lastIsExotic = false, bool withDescriptor = false)
    {
        var list = new List<GeneratedEntry>();
        for (int i = 0; i < count; i++)
        {
            var text = $"Stay attack file number {i}\n{new string('x', 60 + i * 17)}\n";
            var content = Encoding.ASCII.GetBytes(text);
            list.Add(new GeneratedEntry
            {
                Name = $"file{i:D2}.txt",
                Content = content,
                Method = lastIsExotic && i == count - 1 ? 12 : (i % 2 == 0 ? 0 : 8),
                DataDescriptor = withDescriptor && i == count - 1,
                ExoticCompData = lastIsExotic && i == count - 1 ? new byte[] { 0x42, 0x31, 0x2e, 0x30, 0xff } : null,
            });
        }
        return list;
    }

    [Fact]
    public void Generated_archive_round_trips_through_oracle()
    {
        var zip = ZipStayArchive.Generate(Entries(5), Password, TestRngVariant.Msvc, seed: 0x12345678);

        for (int i = 0; i < 5; i++)
        {
            var e = zip.Entries[i];
            var plain = ZipStayArchive.OracleDecrypt(zip.EncryptedBytes(i), zip.X, zip.Y, zip.Z);

            // first 12 decrypted bytes are the pass-2 plaintext: c1[0..9] plus the two check bytes
            Assert.Equal(zip.C1[i], plain[..10]);
            if (e.DataDescriptor)
            {
                Assert.Equal(e.DosTime & 0xff, plain[10]);
                Assert.Equal((e.DosTime >> 8) & 0xff, plain[11]);
            }
            else
            {
                Assert.Equal((int)((e.Crc >> 16) & 0xff), plain[10]);
                Assert.Equal((int)((e.Crc >> 24) & 0xff), plain[11]);
            }

            var comp = plain[12..];
            Assert.Equal(e.CompData, comp);
            var data = e.Method == 8 ? ZipStayArchive.Inflate(comp) : comp;
            Assert.Equal(e.Content, data);
            Assert.Equal(ZipStayArchiveTests.Crc32(e.Content), e.Crc);
        }
    }

    [Fact]
    public void First_stored_byte_equals_first_random_byte()
    {
        var zip = ZipStayArchive.Generate(Entries(5), Password, TestRngVariant.Msvc, seed: 0xabcdef01);
        for (int i = 0; i < 5; i++)
            Assert.Equal(zip.R[i][0], zip.StoredHeaders[i][0]);
    }

    [Fact]
    public void Random_bytes_match_direct_lcg_computation()
    {
        uint seed = 0x13579bdf;
        var zip = ZipStayArchive.Generate(Entries(5), Password, TestRngVariant.Msvc, seed);

        // independent recomputation: MSVC rand chain, one rand() call per header byte
        uint s = seed;
        for (int i = 0; i < 5; i++)
            for (int j = 0; j < 10; j++)
            {
                s = unchecked(s * 214013 + 2531011);
                Assert.Equal((int)((s >> 23) & 0xff), zip.R[i][j]);
            }

        var wz = ZipStayArchive.Generate(Entries(5), Password, TestRngVariant.WinZip, seed);
        uint t = seed;
        for (int i = 0; i < 5; i++)
            for (int j = 0; j < 10; j++)
            {
                t = unchecked(t * 214013);
                Assert.Equal((int)((t >> 23) & 0xff), wz.R[i][j]);
            }
    }

    [Fact]
    public void WinZip_variant_differs_from_msvc()
    {
        uint seed = 0x00c0ffee;
        var msvc = ZipStayArchive.Generate(Entries(5), Password, TestRngVariant.Msvc, seed);
        var winzip = ZipStayArchive.Generate(Entries(5), Password, TestRngVariant.WinZip, seed);
        Assert.NotEqual(msvc.R, winzip.R);
        Assert.NotEqual(msvc.StoredHeaders, winzip.StoredHeaders);
    }

    [Fact]
    public void Second_session_files_use_a_separate_rng_chain()
    {
        var zip = ZipStayArchive.Generate(Entries(7), Password, TestRngVariant.Msvc, seed: 0x2468ace0, filesInFirstSession: 5);

        // first five files follow the seed chain
        uint s = 0x2468ace0;
        for (int i = 0; i < 5; i++)
            for (int j = 0; j < 10; j++)
            {
                s = unchecked(s * 214013 + 2531011);
                Assert.Equal((int)((s >> 23) & 0xff), zip.R[i][j]);
            }
        // files 5..6 do not continue it
        Assert.NotEqual((int)((unchecked(s * 214013 + 2531011) >> 23) & 0xff), zip.R[5][0]);
        // but the attack's clear first byte still holds for every file
        Assert.Equal(zip.R[5][0], zip.StoredHeaders[5][0]);
    }

    [Fact]
    public void Exotic_method_and_descriptor_entries_are_generated()
    {
        var zip = ZipStayArchive.Generate(Entries(4, lastIsExotic: true, withDescriptor: true), Password, TestRngVariant.Msvc, 0x77aa55aa);
        Assert.Equal(12, zip.Entries[^1].Method);
        Assert.True(zip.Entries[^1].DataDescriptor);
        Assert.Equal([0, 8, 0, 12], zip.Entries.Select(e => e.Method).ToArray()); // stored, deflate, stored, exotic
        // round-trips too
        var plain = ZipStayArchive.OracleDecrypt(zip.EncryptedBytes(3), zip.X, zip.Y, zip.Z);
        Assert.Equal(zip.C1[3], plain[..10]);
        Assert.Equal(zip.Entries[3].DosTime & 0xff, plain[10]);
        Assert.Equal(zip.Entries[3].CompData, plain[12..]);
    }

    private static uint Crc32(byte[] data)
    {
        uint crc = 0xffffffff;
        foreach (var b in data)
        {
            crc ^= b;
            for (int i = 0; i < 8; i++)
                crc = (crc >> 1) ^ (0xedb88320 & (uint)-(int)(crc & 1));
        }
        return ~crc;
    }
}
