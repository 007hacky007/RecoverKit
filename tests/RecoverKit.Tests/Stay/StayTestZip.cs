using System.Text;
using RecoverKit.Core.Attacks.Stay;
using RecoverKit.Core.Formats;

namespace RecoverKit.Tests.Stay;

/// <summary>Shared fixtures: generated archives, file data, and true survivors built from the generator's keys.</summary>
internal static class StayTestZip
{
    public const string Password = "&THPOL101%ISLAME@|1";

    public static GeneratedZip MakeZip(int files = 5, uint seed = 0x12345678, ZipRngVariant variant = ZipRngVariant.Msvc,
        int sessions = int.MaxValue, bool lastIsDescriptor = false, int sharedFirstByteFiles = 0)
    {
        uint s = seed;
        while (true)
        {
            var specs = Enumerable.Range(0, files).Select(i => new GeneratedEntry
            {
                Name = $"file{i:D2}.txt",
                Content = Encoding.ASCII.GetBytes($"stay test file {i} {new string('u', 55 + i * 8)}"),
                Method = i % 2 == 0 ? 0 : 8,
                DataDescriptor = lastIsDescriptor && i == files - 1,
            }).ToList();
            var zip = ZipStayArchive.Generate(specs, Password, variant, s, filesInFirstSession: sessions);
            if (sharedFirstByteFiles <= 1) return zip;
            if (zip.R.Take(sharedFirstByteFiles).Select(r => r[0]).Distinct().Count() == 1) return zip;
            s += 0x9e37;
        }
    }

    public static List<StayFileData> FileData(GeneratedZip zip)
        => zip.R.Zip(zip.StoredHeaders, (r, st) => new StayFileData { R = r, Stored = st }).ToList();

    /// <summary>Extracts a generated archive through the production parser.</summary>
    public static (string Path, HashTarget Target) ExtractToTemp(GeneratedZip zip)
    {
        var path = Path.Combine(Path.GetTempPath(), $"stay-{Guid.NewGuid():N}.zip");
        File.WriteAllBytes(path, zip.Archive);
        var d = new Detection { FilePath = path };
        using (var fs = File.OpenRead(path)) ZipExtractor.Extract(fs, d);
        return (path, d.Target!);
    }

    public static Stage1Survivor TrueStage1(GeneratedZip zip, List<StayFileData> files)
    {
        uint a0Full = StayTruth.A0(zip.X);
        uint c = StayTruth.Crc(zip.Z);
        byte k = StayTruth.Ks(zip.Z);
        byte a0 = (byte)a0Full;
        var perFile = new IReadOnlyList<(byte, byte)>[files.Count];
        for (int i = 0; i < files.Count; i++)
        {
            byte l1e1 = (byte)(a0 ^ (StayTruth.T[files[i].R[0]] & 0xff));
            byte l1e2 = (byte)(a0 ^ (StayTruth.T[files[i].R[0] ^ k] & 0xff));
            byte m1e1 = (byte)(((zip.Y + l1e1) * StayTruth.M + 1) >> 24);
            byte m1e2 = (byte)(((zip.Y + l1e2) * StayTruth.M + 1) >> 24);
            perFile[i] = new List<(byte, byte)> { (m1e1, m1e2) };
        }
        return new Stage1Survivor { Cv = (c >> 2) & 0x3fff, K = k, A0 = a0, BY = StayTruth.By(zip.Y), PerFile = perFile };
    }

    public static (byte A1, byte BY2, byte Ch, byte Cl, uint C24) TrueStage2Guesses(GeneratedZip zip)
    {
        uint a0Full = StayTruth.A0(zip.X);
        uint c = StayTruth.Crc(zip.Z);
        return ((byte)(a0Full >> 8), StayTruth.By2(zip.Y), (byte)(c >> 16), (byte)(c & 3), c & 0xffffff);
    }

    public static Stage2Survivor TrueStage2(GeneratedZip zip, List<StayFileData> files)
    {
        var s1 = TrueStage1(zip, files);
        var (a1, bY2, ch, cl, c24) = TrueStage2Guesses(zip);
        var survivors = StayStage2.Search([s1], files);
        return survivors.Single(s => s.A1 == a1 && s.BY2 == bY2 && s.C24 == c24);
    }
}
