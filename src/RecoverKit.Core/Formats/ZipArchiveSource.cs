using System.Text.RegularExpressions;

namespace RecoverKit.Core.Formats;

/// <summary>Opens ZIP volumes in place, preserving PKZIP disk-relative addressing.</summary>
public static partial class ZipArchiveSource
{
    public static Stream Open(string path)
    {
        path = Path.GetFullPath(path);
        var numbered = NumberedPart().Match(path);
        if (numbered.Success)
        {
            if (!File.Exists(path)) throw Missing(path);
            string stem = numbered.Groups[1].Value;
            int width = numbered.Groups[2].Value.Length;
            var siblings = NumberedSiblings(stem, width);
            var paths = Contiguous(stem, width, siblings);
            var stream = new MultiVolumeStream(paths);
            try
            {
                if (ZipExtractor.FindEocd(stream) < 0)
                    throw Missing(stem + (paths.Count + 1).ToString().PadLeft(width, '0'));
                return stream;
            }
            catch { stream.Dispose(); throw; }
        }

        var spanned = SpannedPart().Match(path);
        bool isPart = spanned.Success;
        if (isPart && !File.Exists(path)) throw Missing(path);
        if (!isPart && !path.EndsWith(".zip", StringComparison.OrdinalIgnoreCase))
            return OpenFile(path);
        string basePath = isPart ? spanned.Groups[1].Value : path[..^4];
        string final = isPart ? FindSibling(basePath + ".zip") : path;
        if (!File.Exists(final))
        {
            if (isPart) throw Missing(final);
            return OpenFile(path);
        }
        using (var last = OpenFile(final))
        {
            long end = ZipExtractor.FindEocd(last);
            if (end < 0)
            {
                if (isPart) throw new FormatException("ZIP end of central directory not found in " + Path.GetFileName(final) + ".");
                return OpenFile(path);
            }
            var e = Bin.ReadAt(last, end, 22);
            long disks = Bin.U16(e, 4) + 1L;
            if (end >= 20)
            {
                var locator = Bin.ReadAt(last, end - 20, 20);
                if (Bin.U32(locator, 0) == 0x07064b50) disks = Bin.U32(locator, 16);
            }
            // Some single-file ZIP64 writers store 0 as the total disk count.
            if (disks <= 1 && !isPart) return OpenFile(path);
            var siblings = NumberedSiblings(basePath + ".z", 2);
            // A ZIP64 locator can begin on the preceding disk even when the EOCD uses sentinels.
            if (disks == 65536 && end < 20)
            {
                var available = Contiguous(basePath + ".z", 2, siblings);
                available.Add(final);
                using var tail = new MultiVolumeStream(available);
                long logicalEnd = ZipExtractor.FindEocd(tail);
                if (logicalEnd >= 20)
                {
                    var locator = Bin.ReadAt(tail, logicalEnd - 20, 20);
                    if (Bin.U32(locator, 0) == 0x07064b50) disks = Bin.U32(locator, 16);
                }
            }
            if (disks < 2 || disks > int.MaxValue)
                throw new FormatException("Invalid split ZIP disk count.");
            int found = siblings.Count == 0 ? 0 : siblings.Keys.Max();
            if (found >= disks || (isPart && !siblings.Values.Contains(path, StringComparer.OrdinalIgnoreCase)))
                throw new FormatException("ZIP part numbers do not match the final disk count.");
            var paths = Contiguous(basePath + ".z", 2, siblings, (int)disks - 1);
            paths.Add(final);
            var stream = new MultiVolumeStream(paths, diskRelative: true);
            try
            {
                var signature = Bin.ReadAt(stream, 0, 4);
                Bin.Need(signature, 0, 4);
                if (Bin.U32(signature, 0) != 0x08074b50)
                    throw new FormatException("Split ZIP first part has no split signature.");
                return stream;
            }
            catch { stream.Dispose(); throw; }
        }
    }

    private static FileStream OpenFile(string path)
        => new(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);

    private static Dictionary<int, string> NumberedSiblings(string stem, int width)
    {
        string directory = Path.GetDirectoryName(stem)!;
        string prefix = Path.GetFileName(stem);
        var found = new Dictionary<int, string>();
        foreach (string file in Directory.EnumerateFiles(directory))
        {
            string name = Path.GetFileName(file);
            if (!name.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)) continue;
            string number = name[prefix.Length..];
            if (number.Length < width || !number.All(char.IsAsciiDigit) || !int.TryParse(number, out int n)) continue;
            if (n < 1 || !found.TryAdd(n, file)) throw new FormatException("Ambiguous ZIP part numbering.");
        }
        return found;
    }

    private static List<string> Contiguous(string stem, int width, Dictionary<int, string> found, int? count = null)
    {
        int last = count ?? (found.Count == 0 ? 1 : found.Keys.Max());
        var paths = new List<string>();
        for (int i = 1; i <= last; i++)
        {
            if (!found.TryGetValue(i, out string? file))
                throw Missing(stem + i.ToString().PadLeft(width, '0'));
            paths.Add(file);
        }
        return paths;
    }

    private static string FindSibling(string path)
        => Directory.EnumerateFiles(Path.GetDirectoryName(path)!).FirstOrDefault(p =>
            string.Equals(Path.GetFileName(p), Path.GetFileName(path), StringComparison.OrdinalIgnoreCase)) ?? path;

    private static UnsupportedFormatException Missing(string path) => new(
        $"Part {Path.GetFileName(path)} of this split ZIP archive is missing. Put all parts in the same folder.");

    [GeneratedRegex(@"^(.*\.zip\.)(\d{3,})$", RegexOptions.IgnoreCase)]
    private static partial Regex NumberedPart();
    [GeneratedRegex(@"^(.*)\.z(\d{2,})$", RegexOptions.IgnoreCase)]
    private static partial Regex SpannedPart();
}
