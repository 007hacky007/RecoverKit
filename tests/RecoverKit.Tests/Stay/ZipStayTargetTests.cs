using System.Text;
using RecoverKit.Core.Formats;
using Xunit;

namespace RecoverKit.Tests.Stay;

public class ZipStayTargetTests
{
    private const string Password = "&THPOL101%ISLAME@|1";

    private static List<GeneratedEntry> Entries(int count)
    {
        var list = new List<GeneratedEntry>();
        for (int i = 0; i < count; i++)
        {
            var text = $"Stay attack file number {i}\n{new string('y', 70 + i * 13)}\n";
            list.Add(new GeneratedEntry
            {
                Name = $"file{i:D2}.txt",
                Content = Encoding.ASCII.GetBytes(text),
                Method = i % 2 == 0 ? 0 : 8,
            });
        }
        return list;
    }

    private static GeneratedZip Zip(int count, TestRngVariant variant = TestRngVariant.Msvc, uint seed = 0x12345678,
        int sessions = int.MaxValue)
        => ZipStayArchive.Generate(Entries(count), Password, variant, seed, filesInFirstSession: sessions);

    private static Detection Extract(GeneratedZip zip)
    {
        var d = new Detection { FilePath = "test.zip" };
        using var ms = new MemoryStream(zip.Archive);
        ZipExtractor.Extract(ms, d);
        return d;
    }

    [Fact]
    public void Payload_matches_generator_records()
    {
        var zip = Zip(5);
        var d = Extract(zip);

        Assert.NotNull(d.Target);
        Assert.Equal("ZIPC", d.Target!.FormatId);
        Assert.NotNull(d.Target.StayZip);
        var payload = d.Target.StayZip!;
        Assert.Equal(5, payload.Entries.Count);
        for (int i = 0; i < 5; i++)
        {
            var e = payload.Entries[i];
            var g = zip.Entries[i];
            Assert.Equal(g.Name, e.Name);
            Assert.Equal(zip.StoredHeaders[i], e.StoredHeader);
            Assert.Equal(g.Crc, e.Crc);
            Assert.Equal(g.Flags, e.Flags);
            Assert.Equal(g.Method, e.Method);
            Assert.Equal(g.CompSize, e.CompSize);
            Assert.Equal(g.Content.Length, e.UncompSize);
            Assert.Equal(g.LocalOffset, e.LocalOffset);
            Assert.Equal((g.Flags & 8) == 0, e.HasCrcCheckBytes);
        }
    }

    [Fact]
    public void Payload_includes_exotic_method_entries()
    {
        var specs = Entries(4);
        specs[3] = new GeneratedEntry
        {
            Name = "weird.bin",
            Content = [1, 2, 3],
            Method = 12,
            ExoticCompData = [0x42, 0x31, 0x2e, 0x30, 0xff, 0xaa],
        };
        var zip = ZipStayArchive.Generate(specs, Password, TestRngVariant.Msvc, 0x2468ace0);
        var d = Extract(zip);

        Assert.Equal("ZIPC", d.Target!.FormatId);          // hash line still built from a 0/8 entry
        Assert.Equal(4, d.Target.StayZip!.Entries.Count);   // the exotic entry participates in the attack
        Assert.Contains(d.Target.StayZip.Entries, e => e.Method == 12);
    }

    [Fact]
    public void Payload_skips_entries_with_short_headers()
    {
        var specs = Entries(4);
        specs[2] = new GeneratedEntry
        {
            Name = "short.txt",
            Content = Encoding.ASCII.GetBytes("tiny"),
            Method = 0,
            ForceCompSize = 8,                               // central directory claims fewer than 12 bytes
        };
        var zip = ZipStayArchive.Generate(specs, Password, TestRngVariant.Msvc, 0x77aa55aa);
        var d = Extract(zip);

        Assert.NotNull(d.Target);                            // still attackable through the other entries
        var payload = d.Target!.StayZip!;
        Assert.Equal(3, payload.Entries.Count);
        Assert.DoesNotContain(payload.Entries, e => e.Name == "short.txt");
    }

    [Fact]
    public void Payload_absent_for_odf_and_aes_archives()
    {
        var odfSpecs = new List<GeneratedEntry>
        {
            new() { Name = "mimetype", Content = "application/vnd.oasis.opendocument.text"u8.ToArray(), Method = 0, Classic = false },
            new() { Name = "META-INF/manifest.xml", Content = "<manifest/>"u8.ToArray(), Method = 8, Classic = false },
            new() { Name = "content.xml", Content = Encoding.ASCII.GetBytes(new string('z', 200)), Method = 8 },
        };
        var d = Extract(ZipStayArchive.Generate(odfSpecs, Password, TestRngVariant.Msvc, 1));
        Assert.True(d.Target is null || d.Target.FormatId != "ZIPC");   // ODF path taken, never ZIPC
        Assert.Null(d.Target?.StayZip);

        var aesSpecs = Entries(3);
        aesSpecs.Add(new GeneratedEntry
        {
            Name = "aes.txt",
            Content = "top secret"u8.ToArray(),
            Method = 8,
            FakeAes = true,
        });
        d = Extract(ZipStayArchive.Generate(aesSpecs, Password, TestRngVariant.Msvc, 2));
        Assert.Equal("WZAE", d.Target!.FormatId);
        Assert.Null(d.Target.StayZip);
    }

    [Fact]
    public void Payload_uses_central_directory_order_across_sessions()
    {
        var zip = Zip(7, sessions: 5);
        var d = Extract(zip);

        var payload = d.Target!.StayZip!;
        Assert.Equal(7, payload.Entries.Count);
        for (int i = 0; i < 7; i++)
            Assert.Equal(zip.StoredHeaders[i], payload.Entries[i].StoredHeader);
    }
}
