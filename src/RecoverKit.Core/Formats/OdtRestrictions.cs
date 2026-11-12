using System.IO.Compression;
using System.Xml.Linq;

namespace RecoverKit.Core.Formats;

internal static class OdtRestrictions
{
    private static readonly XNamespace Text = "urn:oasis:names:tc:opendocument:xmlns:text:1.0";
    private static readonly XNamespace Config = "urn:oasis:names:tc:opendocument:xmlns:config:1.0";

    internal static void ExtractPackage(Stream stream, Detection detection)
    {
        using var zip = new ZipArchive(stream, ZipArchiveMode.Read, leaveOpen: true);
        var mimetype = zip.GetEntry("mimetype");
        if (mimetype is null || mimetype.Length > 256) return;
        using (var reader = new StreamReader(mimetype.Open()))
            if (reader.ReadToEnd() != "application/vnd.oasis.opendocument.text") return;
        var content = RestrictionCopy.ReadXml(zip, "content.xml");
        var settings = RestrictionCopy.ReadXml(zip, "settings.xml");
        bool sections = content is not null && Sections(content).Any();
        bool readOnly = settings is not null && ReadOnlySettings(settings).Any();
        if (sections) Add("OpenDocument text sections can be unprotected");
        if (readOnly) Add("OpenDocument read-only flag can be removed");
        if (sections || readOnly) detection.Message = "Text section protection and read-only settings can be removed without a password.";

        void Add(string title) => detection.Unlocks.Add(new InstantUnlock
        {
            Title = title,
            Description = "Saving removes text section protection and the read-only flag from the copy. The document contents are not encrypted.",
            SaveLabel = "Save unrestricted copy...",
            SaveCopyAsync = SaveAsync,
        });
    }

    private static IEnumerable<XElement> Sections(XDocument content) => content.Descendants(Text + "section")
        .Where(e => (string?)e.Attribute(Text + "protected") is "true" or "1");

    private static IEnumerable<XElement> ReadOnlySettings(XDocument settings) => settings.Descendants(Config + "config-item")
        .Where(e => (string?)e.Attribute(Config + "name") == "LoadReadonly" && e.Value.Trim() is "true" or "1");

    private static Task SaveAsync(string source, string output, CancellationToken ct) =>
        RestrictionCopy.SaveZipAsync(source, output, ct, zip =>
        {
            var manifest = RestrictionCopy.ReadXml(zip, "META-INF/manifest.xml") ?? throw new FormatException("Missing OpenDocument manifest.");
            XNamespace m = "urn:oasis:names:tc:opendocument:xmlns:manifest:1.0";
            if (manifest.Descendants(m + "encryption-data").Any())
                throw new FormatException("Encrypted OpenDocument files cannot be unrestricted without decryption.");
            var content = RestrictionCopy.ReadXml(zip, "content.xml");
            if (content is not null && Sections(content).Any())
            {
                foreach (var section in Sections(content).ToArray())
                {
                    section.Attribute(Text + "protected")?.Remove();
                    section.Attribute(Text + "protection-key")?.Remove();
                    section.Attribute(Text + "protection-key-digest-algorithm")?.Remove();
                }
                RestrictionCopy.WriteXml(zip, "content.xml", content);
            }
            var settings = RestrictionCopy.ReadXml(zip, "settings.xml");
            if (settings is not null && ReadOnlySettings(settings).Any())
            {
                foreach (var item in ReadOnlySettings(settings).ToArray()) item.Value = "false";
                RestrictionCopy.WriteXml(zip, "settings.xml", settings);
            }
        });
}
