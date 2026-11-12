using System.Globalization;
using System.IO.Compression;
using System.Text;
using System.Xml;
using System.Xml.Linq;

namespace RecoverKit.Core.Formats;

/// <summary>Editing restrictions in unencrypted spreadsheets, independent of Office encryption.</summary>
public static class SpreadsheetProtection
{
    private const int MaxXmlBytes = 32 * 1024 * 1024;
    private const int MaxWorkbookBytes = 64 * 1024 * 1024;
    private const string EncryptionNote = "Sheet and workbook editing protection can only be inspected after decryption. Decrypt the file, then open the decrypted copy.";
    private static readonly XNamespace Table = "urn:oasis:names:tc:opendocument:xmlns:table:1.0";
    private static readonly XNamespace Office = "urn:oasis:names:tc:opendocument:xmlns:office:1.0";

    public static bool TryExtractZip(Stream stream, Detection d)
    {
        try
        {
            using var zip = new ZipArchive(stream, ZipArchiveMode.Read, leaveOpen: true);
            var findings = new List<InstantUnlock>();
            if (zip.GetEntry("xl/workbook.xml") is { } wb && zip.GetEntry("[Content_Types].xml") is not null)
            {
                EnsureUniqueParts(zip);
                var workbook = ReadXml(wb);
                var ns = workbook.Root?.Name.Namespace ?? XNamespace.None;
                if (!IsSpreadsheetNamespace(ns) || workbook.Root?.Name.LocalName != "workbook")
                    throw new FormatException("Invalid spreadsheet workbook XML.");
                var names = SheetNames(zip, workbook, ns);
                foreach (var entry in zip.Entries.Where(e =>
                    (e.FullName.StartsWith("xl/worksheets/", StringComparison.Ordinal) ||
                     e.FullName.StartsWith("xl/chartsheets/", StringComparison.Ordinal) || names.ContainsKey(e.FullName)) &&
                    e.FullName.EndsWith(".xml", StringComparison.Ordinal)))
                {
                    var doc = ReadXml(entry);
                    if (doc.Root is not { } root || !IsSpreadsheetNamespace(root.Name.Namespace) ||
                        root.Name.LocalName is not ("worksheet" or "chartsheet")) continue;
                    var protection = root.Element(root.Name.Namespace + "sheetProtection");
                    if (protection is null || !HasProtection(protection)) continue;
                    string name = names.GetValueOrDefault(entry.FullName, entry.FullName);
                    findings.Add(XmlUnlock(entry.FullName, protection.Name, 0, false,
                        "Sheet protection can be removed", $"Sheet: {name}. Saving removes this sheet's editing restrictions.",
                        protection, "password", "algorithmName"));
                }
                foreach (var name in new[] { "workbookProtection", "fileSharing" })
                {
                    var element = workbook.Root!.Element(ns + name);
                    if (element is null || !HasProtection(element)) continue;
                    bool sharing = name == "fileSharing";
                    findings.Add(XmlUnlock(wb.FullName, element.Name, 0, false,
                        sharing ? "Read-only recommendation can be removed" : "Workbook structure protection can be removed",
                        sharing ? "Saving removes the read-only recommendation and write-reservation restriction." :
                            "Saving removes workbook structure, window and revision restrictions.",
                        element, sharing ? "reservationPassword" : "workbookPassword",
                        sharing ? "algorithmName" : "workbookAlgorithmName"));
                }
                d.TypeName = "MS Excel spreadsheet (OOXML)";
            }
            else if (zip.GetEntry("mimetype") is { } mime &&
                     ReadText(mime) == "application/vnd.oasis.opendocument.spreadsheet" &&
                     zip.GetEntry("META-INF/manifest.xml") is { } manifest)
            {
                EnsureUniqueParts(zip);
                XNamespace m = "urn:oasis:names:tc:opendocument:xmlns:manifest:1.0";
                if (ReadXml(manifest).Descendants(m + "encryption-data").Any())
                {
                    d.Add("Notes", EncryptionNote);
                    return false;
                }
                var content = zip.GetEntry("content.xml") ?? throw new FormatException("Missing ODS content.xml.");
                var doc = ReadXml(content);
                int index = 0;
                foreach (var table in doc.Descendants(Table + "table"))
                {
                    if (IsTrue(table.Attribute(Table + "protected")) || table.Attribute(Table + "protection-key") is not null)
                        findings.Add(XmlUnlock(content.FullName, table.Name, index, true,
                            "Sheet protection can be removed",
                            $"Sheet: {(string?)table.Attribute(Table + "name") ?? "unnamed"}. Saving removes this sheet's editing restrictions.",
                            table));
                    index++;
                }
                var spreadsheet = doc.Descendants(Office + "spreadsheet").FirstOrDefault();
                if (spreadsheet is not null && (IsTrue(spreadsheet.Attribute(Table + "structure-protected")) ||
                    spreadsheet.Attribute(Table + "protection-key") is not null))
                    findings.Add(XmlUnlock(content.FullName, spreadsheet.Name, 0, true,
                        "Workbook structure protection can be removed", "Saving allows inserting, deleting and renaming sheets.", spreadsheet));
                d.TypeName = "OpenDocument spreadsheet";
            }
            else return false;

            d.Unlocks.AddRange(findings);
            d.Message = findings.Count == 0 ? "Spreadsheet has no sheet or workbook editing protection." :
                "Editing restrictions can be removed without a password attack. Each save action removes the selected restriction.";
            d.Add("Notes", "These restrictions do not encrypt the file. Saved copies preserve other parts; XML changes invalidate document signatures. Reopen each saved copy to remove another restriction.");
            return true;
        }
        catch (Exception ex) when (ex is InvalidDataException or XmlException)
        {
            throw new FormatException("Invalid spreadsheet package or XML.", ex);
        }
    }

    private static bool IsSpreadsheetNamespace(XNamespace ns) => ns.NamespaceName is
        "http://schemas.openxmlformats.org/spreadsheetml/2006/main" or "http://purl.oclc.org/ooxml/spreadsheetml/main";

    private static Dictionary<string, string> SheetNames(ZipArchive zip, XDocument workbook, XNamespace ns)
    {
        var result = new Dictionary<string, string>(StringComparer.Ordinal);
        if (zip.GetEntry("xl/_rels/workbook.xml.rels") is not { } entry) return result;
        XNamespace rel = "http://schemas.openxmlformats.org/package/2006/relationships";
        var relationships = ReadXml(entry).Descendants(rel + "Relationship")
            .Where(e => (string?)e.Attribute("TargetMode") != "External")
            .ToList();
        foreach (var sheet in workbook.Descendants(ns + "sheet"))
        {
            var id = sheet.Attributes().FirstOrDefault(a => a.Name.LocalName == "id")?.Value;
            var target = (string?)relationships.FirstOrDefault(e => (string?)e.Attribute("Id") == id)?.Attribute("Target");
            if (target is null) continue;
            if (!Uri.TryCreate(new Uri("http://package/xl/workbook.xml"), target, out var uri) || uri.Host != "package")
                throw new FormatException("Invalid worksheet relationship target.");
            result[Uri.UnescapeDataString(uri.AbsolutePath.TrimStart('/'))] = (string?)sheet.Attribute("name") ?? "unnamed";
        }
        return result;
    }

    private static InstantUnlock XmlUnlock(string part, XName elementName, int index, bool ods,
        string title, string description, XElement protection, string? passwordAttribute = null, string? algorithmAttribute = null)
    {
        string? algorithm = algorithmAttribute is null ? null : (string?)protection.Attribute(algorithmAttribute);
        string? password = null;
        if (!string.IsNullOrEmpty(algorithm)) description += $" Password verifier: {algorithm}; no password is recovered.";
        else if (passwordAttribute is not null && protection.Attribute(passwordAttribute) is { } legacy)
        {
            if (!ushort.TryParse(legacy.Value, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var hash))
                throw new FormatException("Invalid legacy spreadsheet password hash.");
            password = EquivalentPassword(hash);
            if (password is not null) description += " The displayed password is an equivalent password accepted by Excel, not necessarily the original.";
        }
        return new InstantUnlock
        {
            Title = title, Description = description, Password = password, SaveLabel = "Save unprotected copy...",
            SaveCopyAsync = (source, output, ct) => SaveAtomic(source, output, ct, temp =>
            {
                using var file = new FileStream(temp, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
                using var zip = new ZipArchive(file, ZipArchiveMode.Update);
                EnsureUniqueParts(zip);
                var entry = zip.GetEntry(part) ?? throw new FormatException("Spreadsheet part is missing.");
                var doc = ReadXml(entry);
                var element = (ods ? doc.Descendants(elementName).ElementAtOrDefault(index) : doc.Root?.Element(elementName))
                    ?? throw new FormatException("Selected spreadsheet protection is missing.");
                if (ods)
                {
                    element.Attributes().Where(a => a.Name.Namespace == Table && a.Name.LocalName is
                        "protected" or "structure-protected" or "protection-key" or "protection-key-digest-algorithm" or
                        "protection-key-digest-algorithm-2").Remove();
                }
                else element.Remove();
                using var content = entry.Open();
                content.SetLength(0);
                using var writer = XmlWriter.Create(content, new XmlWriterSettings { Encoding = new UTF8Encoding(false), Indent = false });
                doc.Save(writer);
            }),
        };
    }

    private static bool IsTrue(XAttribute? attribute) => attribute?.Value is "true" or "1";

    private static bool HasProtection(XElement element)
    {
        if (element.Attributes().Any(a => a.Name.LocalName is "password" or "workbookPassword" or
            "revisionsPassword" or "reservationPassword" or "hashValue" or "workbookHashValue" or "revisionsHashValue")) return true;
        string[] flags = element.Name.LocalName switch
        {
            "sheetProtection" => ["sheet", "objects", "scenarios", "content"],
            "workbookProtection" => ["lockStructure", "lockWindows", "lockRevision"],
            _ => ["readOnlyRecommended"],
        };
        return flags.Any(f => IsTrue(element.Attribute(f)));
    }

    private static void EnsureUniqueParts(ZipArchive zip)
    {
        var names = new HashSet<string>(StringComparer.Ordinal);
        foreach (var entry in zip.Entries)
            if (!names.Add(entry.FullName)) throw new FormatException("Duplicate spreadsheet package part.");
    }

    private static XDocument ReadXml(ZipArchiveEntry entry)
    {
        if (entry.Length > MaxXmlBytes) throw new FormatException("Spreadsheet XML exceeds the 32 MiB inspection limit.");
        using var stream = entry.Open();
        using var reader = XmlReader.Create(stream, new XmlReaderSettings
        {
            DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null, MaxCharactersInDocument = MaxXmlBytes,
        });
        return XDocument.Load(reader, LoadOptions.PreserveWhitespace);
    }

    private static string ReadText(ZipArchiveEntry entry)
    {
        if (entry.Length > 256) return "";
        using var reader = new StreamReader(entry.Open());
        return reader.ReadToEnd();
    }

    // Classic printable collision search: eleven A/B characters and a final ASCII character.
    internal static string? EquivalentPassword(ushort hash)
    {
        if (hash == 0) return "";
        if ((hash & 0x8000) == 0) return null;
        Span<char> candidate = stackalloc char[12];
        for (int bits = 0; bits < 2048; bits++)
        {
            int prefix = 12 ^ 0xce4b;
            for (int i = 0; i < 11; i++)
            {
                candidate[i] = (char)('A' + ((bits >> i) & 1));
                int shifted = candidate[i] << (i + 1);
                prefix ^= (shifted & 0x7fff) | (shifted >> 15);
            }
            for (int last = 32; last <= 126; last++)
            {
                int shifted = last << 12;
                if ((prefix ^ ((shifted & 0x7fff) | (shifted >> 15))) != hash) continue;
                candidate[11] = (char)last;
                return new string(candidate);
            }
        }
        return null;
    }

    private sealed record BiffProtection(int Start, bool Workbook)
    {
        public string Name { get; set; } = $"sheet at stream offset {Start}";
        public List<int> Words { get; } = new();
        public ushort? Hash { get; set; }
    }

    public static bool TryExtractBiff(CompoundFile cf, Detection d)
    {
        if (cf.HasStream("EncryptedPackage")) { d.Add("Notes", EncryptionNote); return false; }
        string name = cf.HasStream("Workbook") ? "Workbook" : "Book";
        if (!cf.HasStream(name)) return false;
        if (cf.Find(name)!.Size > MaxWorkbookBytes)
        {
            d.Add("Notes", "Sheet and workbook editing protection inspection is limited to 64 MiB BIFF streams. " + EncryptionNote);
            return false;
        }
        var prefix = cf.ReadStream(name, 1 << 16)!;
        if (prefix.Length < 8 || Bin.U16(prefix, 0) != 0x0809 || Bin.U16(prefix, 4) != 0x0600)
            return false;
        // Keep encrypted detection on OfficeExtractor's existing prefix-only read path.
        for (int pos = 0; pos + 4 <= prefix.Length;)
        {
            int type = Bin.U16(prefix, pos);
            if (type == 0x002f) { d.Add("Notes", EncryptionNote); return false; }
            if (type == 0x000a) break;
            pos += 4 + Bin.U16(prefix, pos + 2);
        }
        var workbook = ReadWorkbook(cf, name);
        var protections = ReadBiff(workbook);
        if (protections is null) { d.Add("Notes", EncryptionNote); return false; }
        var findings = new List<InstantUnlock>();
        foreach (var protection in protections.Where(p => p.Words.Any(o => Bin.U16(workbook, o) != 0)))
        {
            string? password = protection.Hash is { } hash ? EquivalentPassword(hash) : null;
            string description = protection.Workbook ? "Saving removes workbook structure and window restrictions." :
                $"Sheet: {protection.Name}. Saving removes this sheet's editing, object and scenario restrictions.";
            if (password is not null) description += " The displayed password is an equivalent password accepted by Excel, not necessarily the original.";
            findings.Add(new InstantUnlock
            {
                Title = protection.Workbook ? "Workbook structure protection can be removed" : "Sheet protection can be removed",
                Description = description, Password = password, SaveLabel = "Save unprotected copy...",
                SaveCopyAsync = (source, output, ct) => SaveAtomic(source, output, ct, temp =>
                {
                    using var file = new FileStream(temp, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
                    var copy = new CompoundFile(file);
                    var data = ReadWorkbook(copy, name);
                    var selected = ReadBiff(data)?.SingleOrDefault(p => p.Start == protection.Start)
                        ?? throw new FormatException("Selected BIFF protection is missing or the workbook is encrypted.");
                    foreach (var offset in selected.Words) { data[offset] = 0; data[offset + 1] = 0; }
                    copy.WriteStreamSameLength(name, data, file);
                }),
            });
        }
        d.TypeName = "MS Excel 97-2003 workbook";
        d.Unlocks.AddRange(findings);
        d.Message = findings.Count == 0 ? "Workbook has no sheet or workbook editing protection." :
            "Editing restrictions can be removed without a password attack. Each save action removes the selected restriction.";
        return true;
    }

    private static byte[] ReadWorkbook(CompoundFile cf, string name)
    {
        var entry = cf.Find(name) ?? throw new FormatException("Missing workbook stream.");
        if (entry.Size > MaxWorkbookBytes) throw new FormatException("BIFF workbook exceeds the 64 MiB inspection limit.");
        var data = cf.ReadStream(name)!;
        if (data.Length != entry.Size) throw new FormatException("Truncated BIFF workbook stream.");
        return data;
    }

    private static List<BiffProtection>? ReadBiff(byte[] data)
    {
        var result = new List<BiffProtection>();
        var names = new Dictionary<int, string>();
        var stack = new Stack<BiffProtection?>();
        for (int pos = 0; pos < data.Length;)
        {
            if (stack.Count == 0 && data.AsSpan(pos).IndexOfAnyExcept((byte)0) < 0) break;
            Bin.Need(data, pos, 4);
            int type = Bin.U16(data, pos), len = Bin.U16(data, pos + 2), body = pos + 4;
            Bin.Need(data, body, len);
            if (type == 0x002f) return null; // FILEPASS: the remaining stream may be encrypted.
            if (type == 0x0809)
            {
                if (stack.Count >= 64 || result.Count >= 65536) throw new FormatException("Too many BIFF substreams or nesting levels.");
                if (len < 4 || Bin.U16(data, body) != 0x0600) throw new FormatException("Invalid BIFF8 BOF record.");
                int kind = Bin.U16(data, body + 2);
                // Embedded charts have their own password scope; leave them unchanged in a sheet unlock.
                var group = stack.Count == 0 && kind is 5 or 0x10 or 0x20 or 0x40 ? new BiffProtection(pos, kind == 5) : null;
                if (stack.Count == 0 && group is not null) result.Add(group);
                stack.Push(group);
            }
            else if (type == 0x000a)
            {
                if (len != 0 || stack.Count == 0) throw new FormatException("Invalid BIFF EOF record.");
                stack.Pop();
            }
            else if (stack.Count == 0) throw new FormatException("BIFF record outside a substream.");
            else if (stack.Peek() is { } group)
            {
                bool protection = group.Workbook ? type is 0x0019 or 0x0012 or 0x0013 : type is 0x0012 or 0x0013 or 0x0063 or 0x00dd;
                if (protection)
                {
                    if (len != 2) throw new FormatException("Invalid BIFF protection record length.");
                    group.Words.Add(body);
                    if (type == 0x0013) group.Hash = Bin.U16(data, body);
                }
                if (group.Workbook && type == 0x0085)
                {
                    if (len < 8) throw new FormatException("Truncated BIFF sheet name.");
                    int chars = data[body + 6], width = (data[body + 7] & 1) + 1;
                    if (len < 8 + chars * width) throw new FormatException("Truncated BIFF sheet name.");
                    var encoding = width == 2 ? Encoding.Unicode : Encoding.Latin1;
                    uint offset = Bin.U32(data, body);
                    if (offset >= data.Length) throw new FormatException("BIFF sheet offset outside workbook.");
                    names[(int)offset] = encoding.GetString(data, body + 8, chars * width);
                }
            }
            pos = body + len;
        }
        if (stack.Count != 0) throw new FormatException("Truncated BIFF substream.");
        foreach (var group in result.Where(g => !g.Workbook))
            if (names.TryGetValue(group.Start, out var name)) group.Name = name;
        return result;
    }

    private static async Task SaveAtomic(string source, string output, CancellationToken ct, Action<string> edit)
    {
        var comparison = OperatingSystem.IsWindows() || OperatingSystem.IsMacOS() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
        if (string.Equals(ResolveLinks(source), ResolveLinks(output), comparison))
            throw new IOException("Choose a different file name: the original file is never overwritten.");
        string temp = Path.Combine(Path.GetDirectoryName(Path.GetFullPath(output))!, $".recoverkit-{Guid.NewGuid():N}.tmp");
        try
        {
            await using (var input = new FileStream(source, FileMode.Open, FileAccess.Read, FileShare.Read))
            await using (var copy = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None, 81920, true))
                await input.CopyToAsync(copy, ct);
            ct.ThrowIfCancellationRequested();
            edit(temp);
            ct.ThrowIfCancellationRequested();
            File.Move(temp, output, overwrite: true);
        }
        finally { if (File.Exists(temp)) File.Delete(temp); }
    }

    private static string ResolveLinks(string path, int depth = 0)
    {
        if (depth > 40) throw new IOException("Too many symbolic links in spreadsheet path.");
        string full = Path.GetFullPath(path), root = Path.GetPathRoot(full)!;
        string resolved = root;
        foreach (var part in full[root.Length..].Split(Path.DirectorySeparatorChar, StringSplitOptions.RemoveEmptyEntries))
        {
            string candidate = Path.Combine(resolved, part);
            FileSystemInfo info = Directory.Exists(candidate) ? new DirectoryInfo(candidate) : new FileInfo(candidate);
            var target = info.LinkTarget is null ? null : info.ResolveLinkTarget(returnFinalTarget: true);
            resolved = target is null ? candidate : ResolveLinks(target.FullName, depth + 1);
        }
        return resolved;
    }
}
