using System.IO.Compression;
using System.Text;
using RecoverKit.Core;
using RecoverKit.Core.Attacks.Stay;
using RecoverKit.Core.Formats;
using Xunit;

namespace RecoverKit.Tests.Stay;

[Trait("Category", "Stay")]
public class ZipStayDecryptorTests
{
    private static List<GeneratedEntry> MixedSpecs(int count) => Enumerable.Range(0, count).Select(i => new GeneratedEntry
    {
        Name = $"file{i:D2}.txt",
        Content = Encoding.ASCII.GetBytes($"decryptor test file {i} {new string('x', 40 + i * 7)}"),
        Method = i % 3 == 0 ? 0 : 8,
    }).ToList();

    private static (string Path, GeneratedZip Zip) WriteArchive(List<GeneratedEntry> specs, string password = "&THPOL101%ISLAME@|1",
        uint seed = 0x1a2b3c4d, int sessions = int.MaxValue)
    {
        var zip = ZipStayArchive.Generate(specs, password, ZipRngVariant.Msvc, seed, filesInFirstSession: sessions);
        var path = Path.Combine(Path.GetTempPath(), $"staydec-{Guid.NewGuid():N}.zip");
        File.WriteAllBytes(path, zip.Archive);
        return (path, zip);
    }

    /// <summary>Re-encrypts one entry's body under a different password, in place, keeping all sizes.</summary>
    private static byte[] WithForeignKeys(GeneratedZip zip, int idx, string password)
    {
        var bytes = (byte[])zip.Archive.Clone();
        var e = zip.Entries[idx];
        var plain = ZipStayArchive.OracleDecrypt(zip.EncryptedBytes(idx), zip.X, zip.Y, zip.Z);
        uint x = 0, y = 0, z = 0;
        ZipStayArchive.InitKeys(password, ref x, ref y, ref z);
        var start = (int)(e.LocalOffset + 30 + Encoding.ASCII.GetByteCount(e.Name));
        for (int i = 0; i < plain.Length; i++)
            bytes[start + i] = ZipStayArchive.Encode(plain[i], ref x, ref y, ref z);
        return bytes;
    }

    /// <summary>Reads one entry's raw stored bytes (after the local header + name + extra) from a ZIP file.</summary>
    private static (ushort Flags, ushort Method, long CompSize, byte[] Data, long DataStart) RawEntry(byte[] zip, string name)
    {
        int eocd = BinLast(zip);
        int total = BitConverter.ToUInt16(zip, eocd + 10);
        int cdOffset = BitConverter.ToInt32(zip, eocd + 16);
        int p = cdOffset;
        for (int i = 0; i < total; i++)
        {
            var nl = BitConverter.ToUInt16(zip, p + 28);
            var el = BitConverter.ToUInt16(zip, p + 30);
            var cl = BitConverter.ToUInt16(zip, p + 32);
            var entryName = Encoding.Latin1.GetString(zip, p + 46, nl);
            var flags = BitConverter.ToUInt16(zip, p + 8);
            var method = BitConverter.ToUInt16(zip, p + 10);
            var comp = BitConverter.ToInt32(zip, p + 20);
            var local = BitConverter.ToInt32(zip, p + 42);
            if (entryName == name)
            {
                var lnl = BitConverter.ToUInt16(zip, local + 26);
                var lel = BitConverter.ToUInt16(zip, local + 28);
                var dataStart = local + 30 + lnl + lel;
                return (flags, method, comp, zip[dataStart .. (int)(dataStart + comp)], dataStart);
            }
            p += 46 + nl + el + cl;
        }
        throw new ArgumentException($"entry {name} not found");
    }

    private static int BinLast(byte[] zip)
    {
        for (int i = zip.Length - 22; i >= 0; i--)
            if (BitConverter.ToUInt32(zip, i) == 0x06054b50) return i;
        throw new FormatException("no EOCD");
    }

    private static string WriteCopy(GeneratedZip zip, string path)
    {
        var keys = new ZipStayKeys(zip.X, zip.Y, zip.Z);
        var target = new ZipStayTarget { Entries = zip.Entries.Select((e, i) => new ZipStayEntry
        {
            Name = e.Name, StoredHeader = zip.StoredHeaders[i], Crc = e.Crc, Flags = e.Flags,
            Method = (ushort)e.Method, CompSize = e.CompSize, UncompSize = e.Content.LongLength,
            LocalOffset = e.LocalOffset, DataOffset = e.LocalOffset,
        }).ToList() };
        var outPath = Path.ChangeExtension(path, ".dec.zip");
        return ZipStayDecryptor.WriteDecryptedCopy(path, target, keys, outPath);
    }

    [Fact]
    public void Copy_opens_without_password_and_contents_match()
    {
        var specs = MixedSpecs(5);
        specs[2] = new GeneratedEntry
        {
            Name = "file02.bin", Content = "exotic payload"u8.ToArray(), Method = 12,
            ExoticCompData = "RAWEXOTICCOMPRESSEDDATA"u8.ToArray(),
        };
        var (path, zip) = WriteArchive(specs);
        try
        {
            var copy = WriteCopy(zip, path);
            using var opened = ZipFile.OpenRead(copy);
            Assert.Equal(5, opened.Entries.Count);
            foreach (var entry in opened.Entries)
            {
                var spec = specs.Single(s => s.Name == entry.Name);
                if (spec.Method is 0 or 8)
                {
                    using var sr = new StreamReader(entry.Open());
                    Assert.Equal(Encoding.ASCII.GetString(spec.Content), sr.ReadToEnd());
                }
            }
            // the method-12 entry: raw compressed bytes preserved (System.IO.Compression cannot inflate bzip2)
            var raw = RawEntry(File.ReadAllBytes(copy), "file02.bin");
            Assert.Equal(specs[2].ExoticCompData, raw.Data);
            Assert.Equal(12, raw.Method);
            Assert.Equal((ushort)0, raw.Flags & 1);   // no longer encrypted
        }
        finally { File.Delete(path); File.Delete(Path.ChangeExtension(path, ".dec.zip")); }
    }

    [Fact]
    public void Decryptor_skips_entries_that_fail_verification()
    {
        var (path, zip) = WriteArchive(MixedSpecs(5));
        var foreign = WithForeignKeys(zip, 4, "WRONG-PASSWORD-2");
        File.WriteAllBytes(path, foreign);
        try
        {
            var copy = WriteCopy(zip, path);
            var raw = File.ReadAllBytes(copy);

            for (int i = 0; i < 4; i++)
            {
                var e = RawEntry(raw, zip.Entries[i].Name);
                Assert.Equal((ushort)0, e.Flags & 1);
                Assert.Equal(zip.Entries[i].CompSize - 12, e.CompSize);
            }
            var e4 = RawEntry(raw, zip.Entries[4].Name);
            Assert.Equal((ushort)1, e4.Flags & 1);                                   // still encrypted
            Assert.Equal(zip.Entries[4].CompSize, e4.CompSize);                       // untouched body
            var origBody = WithForeignKeys(zip, 4, "WRONG-PASSWORD-2");
            var origRaw = RawEntry(origBody, zip.Entries[4].Name);
            Assert.Equal(origRaw.Data, e4.Data);

            using var opened = ZipFile.OpenRead(copy);
            Assert.Equal(5, opened.Entries.Count);
        }
        finally { File.Delete(path); File.Delete(Path.ChangeExtension(path, ".dec.zip")); }
    }

    [Fact]
    public void Decryptor_handles_data_descriptor_entries()
    {
        var specs = MixedSpecs(4);
        specs[3] = new GeneratedEntry
        {
            Name = "file03.txt", Content = "data descriptor entry payload"u8.ToArray(),
            Method = 8, DataDescriptor = true,
        };
        var (path, zip) = WriteArchive(specs);
        try
        {
            var copy = WriteCopy(zip, path);
            var raw = File.ReadAllBytes(copy);
            var e = RawEntry(raw, "file03.txt");
            Assert.Equal((ushort)0, e.Flags & 0x9);   // encryption and descriptor bits cleared

            using var opened = ZipFile.OpenRead(copy);
            Assert.Equal(4, opened.Entries.Count);
            var entry = opened.Entries.Single(x => x.Name == "file03.txt");
            using var sr = new StreamReader(entry.Open());
            Assert.Equal("data descriptor entry payload", sr.ReadToEnd());
        }
        finally { File.Delete(path); File.Delete(Path.ChangeExtension(path, ".dec.zip")); }
    }

    [Fact]
    public void Decryptor_passes_aes_entries_through()
    {
        var specs = MixedSpecs(3);
        specs.Add(new GeneratedEntry
        {
            Name = "aes.txt", Content = "aes content"u8.ToArray(), Method = 8, FakeAes = true,
        });
        var (path, zip) = WriteArchive(specs);
        try
        {
            var copy = WriteCopy(zip, path);
            var raw = File.ReadAllBytes(copy);

            var aes = RawEntry(raw, "aes.txt");
            var orig = RawEntry(zip.Archive, "aes.txt");
            Assert.Equal((ushort)1, aes.Flags & 1);       // still encrypted
            Assert.Equal(99, aes.Method);
            Assert.Equal(orig.Data, aes.Data);            // byte-identical body

            using var opened = ZipFile.OpenRead(copy);
            Assert.Equal(4, opened.Entries.Count);
            using var sr = new StreamReader(opened.Entries.Single(x => x.Name == "file00.txt").Open());
            Assert.Equal(Encoding.ASCII.GetString(specs[0].Content), sr.ReadToEnd());
        }
        finally { File.Delete(path); File.Delete(Path.ChangeExtension(path, ".dec.zip")); }
    }

    [Fact]
    public void Decryptor_passes_unverifiable_descriptor_exotic_entries_through()
    {
        // data-descriptor + exotic method: nothing can be verified, so it stays encrypted
        var specs = new List<GeneratedEntry>
        {
            new() { Name = "file00.txt", Content = "plain stored"u8.ToArray(), Method = 0 },
            new() { Name = "file01.txt", Content = "plain deflated"u8.ToArray(), Method = 8 },
            new() { Name = "dd12.bin", Content = "payload"u8.ToArray(), Method = 12, DataDescriptor = true,
                    ExoticCompData = "EXOTICCOMP"u8.ToArray() },
        };
        var (path, zip) = WriteArchive(specs);
        try
        {
            var copy = WriteCopy(zip, path);
            var raw = File.ReadAllBytes(copy);
            var dd = RawEntry(raw, "dd12.bin");
            Assert.Equal((ushort)9, (ushort)(dd.Flags & 0x9));   // still encrypted, descriptor intact
            var orig = RawEntry(zip.Archive, "dd12.bin");
            Assert.Equal(orig.Data, dd.Data);
        }
        finally { File.Delete(path); File.Delete(Path.ChangeExtension(path, ".dec.zip")); }
    }

    [Fact]
    public void DecryptEntry_drops_header_and_decrypts_body()
    {
        var (path, zip) = WriteArchive(MixedSpecs(2));
        try
        {
            var body = zip.EncryptedBytes(0);
            var plain = ZipStayDecryptor.DecryptEntry(body, new ZipStayKeys(zip.X, zip.Y, zip.Z));
            Assert.Equal(zip.Entries[0].CompData, plain);
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public void OutputPathFor_uses_settings_suffix()
    {
        var directory = Path.GetTempPath();
        var archive = Path.Combine(directory, "vacation.zip");
        Assert.Equal(Path.Combine(directory, "vacation_decrypted.zip"),
            ZipStayDecryptor.OutputPathFor(archive, new Settings()));
        Assert.Equal(Path.Combine(directory, "vacation-clear.zip"),
            ZipStayDecryptor.OutputPathFor(archive, new Settings { DecryptSuffix = "-clear" }));
    }
}
