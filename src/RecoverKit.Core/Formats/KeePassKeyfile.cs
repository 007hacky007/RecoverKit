using System.Security.Cryptography;
using System.Text;
using System.Xml;
using System.Xml.Linq;

namespace RecoverKit.Core.Formats;

/// <summary>Normalizes KeePass keyfiles to their 32-byte key component.</summary>
public static class KeePassKeyfile
{
    public static byte[] Read(string path, bool legacy = false)
    {
        using var s = File.OpenRead(path);
        if (s.Length is 32 or 64)
        {
            var data = new byte[(int)s.Length];
            s.ReadExactly(data);
            if (data.Length == 32) return data;
            string hex = Encoding.ASCII.GetString(data);
            if (hex.All(char.IsAsciiHexDigit)) return Convert.FromHexString(hex);
            s.Position = 0;
        }
        // KeePass 1 treats XML keyfiles as arbitrary files, hashing the whole file.
        if (!legacy)
        {
            XDocument? xml = null;
            try
            {
                using var reader = XmlReader.Create(s, new XmlReaderSettings
                {
                    DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null, CloseInput = false,
                    MaxCharactersInDocument = 1024 * 1024,
                });
                reader.MoveToContent();
                if (reader.Name == "KeyFile" && reader.NamespaceURI.Length == 0)
                {
                    try { xml = XDocument.Load(reader); }
                    catch (XmlException ex) { throw new FormatException("Invalid KeePass XML keyfile (maximum XML size is 1 MiB).", ex); }
                }
            }
            catch (XmlException) { } // Arbitrary files, including non-key XML, use SHA-256.
            if (xml?.Root?.Name == "KeyFile")
            {
                string? version = xml.Root.Element("Meta")?.Element("Version")?.Value.Trim();
                var data = xml.Root.Element("Key")?.Element("Data");
                if (data is null) throw new FormatException("KeePass XML keyfile has no key data.");
                byte[] key;
                if (version is "1.00" or "1.0") key = Convert.FromBase64String(data.Value);
                else if (version is "2.0" or "2.00")
                {
                    key = Convert.FromHexString(string.Concat(data.Value.Where(c => !char.IsWhiteSpace(c))));
                    string? checksum = data.Attribute("Hash")?.Value;
                    if (checksum is null || !Convert.ToHexString(SHA256.HashData(key).AsSpan(0, 4)).Equals(checksum, StringComparison.OrdinalIgnoreCase))
                        throw new FormatException("KeePass XML v2 keyfile checksum does not match.");
                }
                else throw new FormatException("Unsupported KeePass XML keyfile version.");
                if (key.Length != 32) throw new FormatException("KeePass XML keyfile must contain exactly 32 key bytes.");
                return key;
            }
        }
        s.Position = 0;
        return SHA256.HashData(s);
    }
}
