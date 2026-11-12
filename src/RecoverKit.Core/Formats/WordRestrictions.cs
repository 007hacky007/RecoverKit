using System.Globalization;
using System.IO.Compression;
using System.Xml.Linq;

namespace RecoverKit.Core.Formats;

/// <summary>Editing restrictions and write reservations on Word files that open without decryption.</summary>
public static class WordRestrictions
{
    private static bool IsWordNamespace(XNamespace ns) => ns.NamespaceName is
        "http://schemas.openxmlformats.org/wordprocessingml/2006/main" or
        "http://purl.oclc.org/ooxml/wordprocessingml/main";

    internal static void ExtractPackage(Stream stream, Detection detection)
    {
        using var zip = new ZipArchive(stream, ZipArchiveMode.Read, leaveOpen: true);
        if (zip.GetEntry("word/document.xml") is null) return;
        var settings = RestrictionCopy.ReadXml(zip, "word/settings.xml");
        if (settings is null) return;
        if (settings.Root is null || settings.Root.Name.LocalName != "settings" || !IsWordNamespace(settings.Root.Name.Namespace))
            throw new FormatException("Invalid Word settings root.");
        var elements = ProtectionElements(settings).ToList();
        foreach (var element in elements)
        {
            bool editing = element.Name.LocalName == "documentProtection";
            string? legacy = (string?)element.Attribute(element.Name.Namespace + "password");
            bool modern = element.Attributes().Any(a => a.Name.LocalName is "hash" or "hashValue");
            string? password = !modern && legacy is { Length: <= 4 } &&
                ushort.TryParse(legacy, NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture, out var verifier)
                ? EquivalentPassword(verifier) : null;
            detection.Unlocks.Add(new InstantUnlock
            {
                Title = editing ? "Word editing restrictions can be removed" : "Word password to modify / read-only recommendation can be removed",
                Description = "Saving removes editing restrictions and write protection from the copy. " +
                    (password is null ? "The document contents are not encrypted." : "The displayed password is an equivalent legacy password, not necessarily the original."),
                Password = password,
                SaveLabel = "Save unrestricted copy...",
                SaveCopyAsync = SavePackageAsync,
            });
        }
        if (elements.Count > 0)
        {
            detection.TypeName = "MS Word document";
            detection.Message = "Word editing / write restrictions can be removed without a password.";
        }
    }

    private static IEnumerable<XElement> ProtectionElements(XDocument doc) => doc.Descendants().Where(e =>
        IsWordNamespace(e.Name.Namespace) && e.Name.LocalName is "documentProtection" or "writeProtection");

    private static Task SavePackageAsync(string source, string output, CancellationToken ct) =>
        RestrictionCopy.SaveZipAsync(source, output, ct, zip =>
        {
            var settings = RestrictionCopy.ReadXml(zip, "word/settings.xml")
                ?? throw new FormatException("Word settings are missing.");
            var elements = ProtectionElements(settings).ToList();
            if (elements.Count == 0) throw new FormatException("Word restriction settings are no longer present.");
            elements.ForEach(e => e.Remove());
            RestrictionCopy.WriteXml(zip, "word/settings.xml", settings);
        });

    // Each toggled low bit contributes one of the 15 rotated verifier bits.
    private static string? EquivalentPassword(ushort verifier)
    {
        if (verifier == 0) return "";
        if ((verifier & 0x8000) == 0) return null;
        var chars = new string('a', 15).ToCharArray();
        int value = 0;
        for (int i = 0; i < 15; i++) value = Rotate(value) ^ 'a';
        int difference = verifier ^ (Rotate(value) ^ 15 ^ 0xCE4B);
        for (int i = 0; i < 15; i++)
            if ((difference & (1 << ((i + 1) % 15))) != 0) chars[i] = '`';
        return new string(chars);
    }

    private static int Rotate(int value) => ((value << 1) & 0x7fff) | (value >> 14);
}
