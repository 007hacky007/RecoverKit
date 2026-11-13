using System.Text;
using RecoverKit.Core.Formats;
using RecoverKit.Core.Attacks.Stay;
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

    private static GeneratedZip Zip(int count, ZipRngVariant variant = ZipRngVariant.Msvc, uint seed = 0x12345678,
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
        var zip = ZipStayArchive.Generate(specs, Password, ZipRngVariant.Msvc, 0x2468ace0);
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
        var zip = ZipStayArchive.Generate(specs, Password, ZipRngVariant.Msvc, 0x77aa55aa);
        var d = Extract(zip);

        Assert.NotNull(d.Target);                            // still attackable through the other entries
        var payload = d.Target!.StayZip!;
        Assert.Equal(3, payload.Entries.Count);
        Assert.DoesNotContain(payload.Entries, e => e.Name == "short.txt");
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Payload_absent_for_odf_archives(bool encrypted)
    {
        // ODF encrypts part bytes using manifest metadata, leaving ZIP encryption flags clear.
        var encryption = encrypted ? """
            <m:encryption-data m:checksum-type="SHA256/1K" m:checksum="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=">
              <m:algorithm m:algorithm-name="http://www.w3.org/2001/04/xmlenc#aes256-cbc" m:initialisation-vector="AAAAAAAAAAAAAAAAAAAAAA=="/>
              <m:key-derivation m:key-derivation-name="PBKDF2" m:iteration-count="1024" m:key-size="32" m:salt="AAAAAAAAAAAAAAAAAAAAAA=="/>
              <m:start-key-generation m:start-key-generation-name="SHA256"/>
            </m:encryption-data>
            """ : "";
        var manifest = $"""
            <m:manifest xmlns:m="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0">
              <m:file-entry m:full-path="content.xml" m:media-type="text/xml">{encryption}</m:file-entry>
            </m:manifest>
            """;
        var odfSpecs = new List<GeneratedEntry>
        {
            new() { Name = "mimetype", Content = "application/vnd.oasis.opendocument.text"u8.ToArray(), Method = 0, Classic = false },
            new() { Name = "META-INF/manifest.xml", Content = Encoding.UTF8.GetBytes(manifest), Method = 8, Classic = false },
            // Synthetic part bytes suffice for extraction; no password verification runs here.
            new() { Name = "content.xml", Content = encrypted ? new byte[208] : "<document/>"u8.ToArray(), Method = 0, Classic = false },
        };
        var d = Extract(ZipStayArchive.Generate(odfSpecs, Password, ZipRngVariant.Msvc, 1));
        if (encrypted) Assert.Equal("ODF2", d.Target!.FormatId);
        else Assert.Null(d.Target);
        Assert.StartsWith("OpenDocument", d.TypeName);
        Assert.Null(d.Target?.StayZip);
    }

    [Fact]
    public void Payload_absent_for_aes_archives()
    {
        var aesSpecs = Entries(3);
        aesSpecs.Add(new GeneratedEntry
        {
            Name = "aes.txt",
            Content = "top secret"u8.ToArray(),
            Method = 8,
            FakeAes = true,
        });
        var d = Extract(ZipStayArchive.Generate(aesSpecs, Password, ZipRngVariant.Msvc, 2));
        Assert.Equal("WZAE", d.Target!.FormatId);
        Assert.Null(d.Target.StayZip);
    }

    [Fact]
    public void ZipCrypto_content_with_odf_named_entries_uses_zip_path()
    {
        var specs = Entries(2);
        specs.Add(new() { Name = "mimetype", Content = "application/vnd.oasis.opendocument.text"u8.ToArray(), Method = 0, Classic = false });
        specs.Add(new() { Name = "META-INF/manifest.xml", Content = "<manifest/>"u8.ToArray(), Method = 8, Classic = false });
        var d = Extract(ZipStayArchive.Generate(specs, Password, ZipRngVariant.Msvc, 1));
        Assert.Equal("ZIPC", d.Target!.FormatId);
        Assert.Equal(2, d.Target.StayZip!.Entries.Count);
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


public class ZipStayCorruptEntryTests
{
    [Fact]
    public void Payload_skips_truncated_entries_and_keeps_the_rest()
    {
        // file 2's central directory lies about a much larger compressed size than the data present
        var specs = Enumerable.Range(0, 6).Select(i => new GeneratedEntry
        {
            Name = $"file{i:D2}.txt",
            Content = System.Text.Encoding.ASCII.GetBytes($"corrupt-entry test {i} {new string('q', 50 + i * 5)}"),
            Method = 8,
            ForceCompSize = i == 2 ? 7000 : null,   // inflated: 50 real bytes claimed as 7000
        }).ToList();
        var zip = ZipStayArchive.Generate(specs, StayTestZip.Password, ZipRngVariant.Msvc, 0x33aa11cc);
        var (path, target) = StayTestZip.ExtractToTemp(zip);
        try
        {
            var payload = target.StayZip!;
            Assert.Equal(5, payload.Entries.Count);
            Assert.DoesNotContain(payload.Entries, e => e.Name == "file02.txt");
            Assert.Equal("file00.txt", payload.Entries[0].Name);   // archive order preserved
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public void Payload_skips_zip64_sized_entries()
    {
        var specs = Enumerable.Range(0, 6).Select(i => new GeneratedEntry
        {
            Name = $"file{i:D2}.txt",
            Content = System.Text.Encoding.ASCII.GetBytes($"huge-entry test {i}"),
            Method = 0,
            ForceCompSize = i == 4 ? 3_000_000_000L : null,   // claimed size overflows int
        }).ToList();
        var zip = ZipStayArchive.Generate(specs, StayTestZip.Password, ZipRngVariant.Msvc, 0x44bb22dd);
        var (path, target) = StayTestZip.ExtractToTemp(zip);
        try
        {
            var payload = target.StayZip!;
            Assert.Equal(5, payload.Entries.Count);
            Assert.DoesNotContain(payload.Entries, e => e.Name == "file04.txt");
        }
        finally { File.Delete(path); }
    }
}
