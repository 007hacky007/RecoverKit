using System.IO.Compression;
using System.Xml;
using System.Xml.Linq;

namespace RecoverKit.Core.Formats;

internal static class RestrictionCopy
{
    internal const int XmlLimit = 4 * 1024 * 1024;

    internal static XDocument? ReadXml(ZipArchive zip, string name)
    {
        var matches = zip.Entries.Where(e => e.FullName == name).ToArray();
        if (matches.Length > 1) throw new FormatException($"Duplicate package part '{name}'.");
        if (matches.Length == 0) return null;
        if (matches[0].Length > XmlLimit) throw new FormatException($"Package part '{name}' exceeds the 4 MiB restriction limit.");
        try
        {
            using var input = matches[0].Open();
            using var reader = XmlReader.Create(input, new XmlReaderSettings
            {
                DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null, MaxCharactersInDocument = XmlLimit,
            });
            return XDocument.Load(reader, LoadOptions.PreserveWhitespace);
        }
        catch (XmlException ex) { throw new FormatException($"Invalid XML in '{name}'.", ex); }
        catch (InvalidDataException ex) { throw new FormatException($"Invalid package part '{name}'.", ex); }
    }

    internal static Task SaveZipAsync(string source, string output, CancellationToken ct,
        Action<ZipArchive> update) => SaveAsync(source, output, ct, stream =>
    {
        using var zip = new ZipArchive(stream, ZipArchiveMode.Update, leaveOpen: true);
        update(zip);
    });

    internal static void WriteXml(ZipArchive zip, string name, XDocument doc)
    {
        // Update the existing entry so the rest of the package, including macros, stays intact.
        var entry = zip.GetEntry(name) ?? throw new FormatException($"Missing package part '{name}'.");
        using var stream = entry.Open();
        stream.SetLength(0);
        doc.Save(stream, SaveOptions.DisableFormatting);
    }

    internal static async Task SaveAsync(string source, string output, CancellationToken ct, Action<Stream> update)
    {
        ct.ThrowIfCancellationRequested();
        var comparison = OperatingSystem.IsWindows() || OperatingSystem.IsMacOS() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
        if (string.Equals(ResolvePath(source), ResolvePath(output), comparison))
            throw new IOException("Choose a different file name: the original file is never overwritten.");
        string temp = Path.Combine(Path.GetDirectoryName(Path.GetFullPath(output))!, ".rk-" + Guid.NewGuid().ToString("N") + ".tmp");
        try
        {
            await using (var copy = new FileStream(temp, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None))
            {
                await using (var input = new FileStream(source, FileMode.Open, FileAccess.Read, FileShare.Read))
                    await input.CopyToAsync(copy, ct);
                ct.ThrowIfCancellationRequested();
                copy.Position = 0;
                update(copy);
                await copy.FlushAsync(ct);
            }
            ct.ThrowIfCancellationRequested();
            File.Move(temp, output, overwrite: true);
        }
        finally { if (File.Exists(temp)) File.Delete(temp); }
    }

    private static string ResolvePath(string path)
    {
        string full = Path.GetFullPath(path);
        string? parent = Path.GetDirectoryName(full);
        if (parent is null) return full;
        string resolved = Path.Combine(ResolvePath(parent), Path.GetFileName(full));
        if (!File.Exists(resolved) && !Directory.Exists(resolved)) return resolved;
        FileSystemInfo info = Directory.Exists(resolved) ? new DirectoryInfo(resolved) : new FileInfo(resolved);
        return info.ResolveLinkTarget(true) is { } target ? ResolvePath(target.FullName) : resolved;
    }
}
