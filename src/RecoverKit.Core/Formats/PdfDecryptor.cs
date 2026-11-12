using System.Buffers.Binary;
using System.Security.Cryptography;
using RecoverKit.Core.Native.Kernels;
using RecoverKit.Core.Native.Simd;

namespace RecoverKit.Core.Formats;

internal sealed class PdfDecryptor
{
    private readonly PdfDocument document;
    private readonly PdfDictionary security;
    private readonly byte[] key;
    private readonly int version;
    private readonly int revision;
    private readonly int? encryptObject;
    private readonly bool encryptMetadata;

    private PdfDecryptor(PdfDocument document)
    {
        this.document = document;
        encryptObject = (document.Trailer.Get("Encrypt") as PdfReference)?.Number;
        security = document.Resolve(document.Trailer.Get("Encrypt")) as PdfDictionary ?? throw new FormatException("Missing PDF encryption dictionary.");
        if (security.Name("Filter") != "Standard") throw new UnsupportedFormatException("Only the Standard PDF security handler is supported.");
        version = security.Int("V"); revision = security.Int("R");
        encryptMetadata = security.Get("EncryptMetadata") is not PdfKeyword { Text: "false" };
        key = EmptyPasswordKey(security, document.Resolve(document.Trailer.Get("ID")) as PdfArray)
            ?? throw new FormatException("The PDF no longer opens with an empty user password.");
        _ = Method(security.Name("StrF") ?? "Identity");
        _ = Method(security.Name("StmF") ?? "Identity");
        if (security.Get("EFF") is not null) _ = Method(security.Name("EFF") ?? throw new FormatException("Invalid PDF EFF filter."));
        document.Decrypt = DecryptObject;
    }

    internal static bool TryAddUnlock(byte[] bytes, Detection detection)
    {
        var document = new PdfDocument(bytes);
        if (document.Resolve(document.Trailer.Get("Encrypt")) is not PdfDictionary s || s.Name("Filter") != "Standard") return false;
        int revision = s.Int("R");
        if (revision is < 2 or > 6 || EmptyPasswordKey(s, document.Resolve(document.Trailer.Get("ID")) as PdfArray) is null) return false;
        detection.Add("Security handler", $"Standard, V={s.Int("V")}, R={revision}");
        detection.Add("Permissions (P)", s.Int("P").ToString(System.Globalization.CultureInfo.InvariantCulture));
        AddUnlock(detection, revision, s.Int("P"));
        return true;
    }

    private static byte[]? EmptyPasswordKey(PdfDictionary s, PdfArray? ids)
    {
        int r = s.Int("R"), v = s.Int("V"), p = s.Int("P");
        var u = s.Bytes("U"); var o = s.Bytes("O");
        if (r is >= 2 and <= 4)
        {
            if (o.Length != 32 || u.Length != 32 || ids?.Items.FirstOrDefault() is not PdfString id) throw new FormatException("Invalid PDF O, U or ID entry.");
            int bits = r == 2 ? 40 : s.Get("Length") is PdfNumber length ? length.Integer : v == 4 ? 128 : 40;
            if (bits is < 40 or > 128 || bits % 8 != 0 || v is not (1 or 2 or 4)) throw new UnsupportedFormatException("Unsupported PDF legacy key length or version.");
            bool meta = s.Get("EncryptMetadata") is not PdfKeyword { Text: "false" };
            string hash = $"$pdf${v}*{r}*{bits}*{p}*{(meta ? 1 : 0)}*{id.Bytes.Length}*{Bin.Hex(id.Bytes)}*32*{Bin.Hex(u)}*32*{Bin.Hex(o)}";
            var kernel = PdfRc4Kernel.TryParse(hash);
            return kernel?.Verify([]) == true ? kernel.Key([]) : null;
        }
        if (r is not (5 or 6) || v != 5 || u.Length != 48 || o.Length != 48) throw new FormatException("Invalid AES-256 PDF security entries.");
        byte[] Hash(ReadOnlySpan<byte> salt) => r == 5 ? SHA256.HashData(salt) : PdfR6Kernel.Hash([], salt);
        if (!Hash(u.AsSpan(32, 8)).AsSpan().SequenceEqual(u.AsSpan(0, 32))) return null;
        var ue = s.Bytes("UE");
        if (ue.Length != 32) throw new FormatException("Invalid PDF UE entry.");
        using var aes = Aes.Create();
        aes.Key = Hash(u.AsSpan(40, 8));
        var fileKey = aes.DecryptCbc(ue, new byte[16], PaddingMode.None);
        var perms = s.Bytes("Perms");
        if (perms.Length != 16) throw new FormatException("Invalid PDF Perms entry.");
        aes.Key = fileKey;
        var clear = aes.DecryptEcb(perms, PaddingMode.None);
        if (BinaryPrimitives.ReadInt32LittleEndian(clear) != p || !clear.AsSpan(4, 4).SequenceEqual(new byte[] { 255, 255, 255, 255 }) ||
            clear[8] != (s.Get("EncryptMetadata") is PdfKeyword { Text: "false" } ? 'F' : 'T') || !clear.AsSpan(9, 3).SequenceEqual("adb"u8))
            throw new FormatException("PDF permissions authentication failed; no copy was written.");
        return fileKey;
    }

    private static void AddUnlock(Detection detection, int revision, int permissions)
    {
        var restrictions = new List<string>();
        void Restricted(int bit, string name) { if ((permissions & (1 << (bit - 1))) == 0) restrictions.Add(name); }
        Restricted(3, "printing"); Restricted(4, "editing"); Restricted(5, "copying text and images"); Restricted(6, "annotations");
        if (revision >= 3)
        {
            Restricted(9, "form filling"); Restricted(10, "accessibility extraction"); Restricted(11, "page assembly"); Restricted(12, "high-quality printing");
        }
        detection.Target = null;
        detection.Unlocks.Add(new InstantUnlock
        {
            Title = "Printing and copying restrictions can be removed",
            Description = "The document opens without a password. " + (restrictions.Count == 0 ? "No permission flags are restricted. " : "Restricted permissions: " + string.Join(", ", restrictions) + ". ") +
                          "Save an unencrypted copy to remove the owner password.",
            SaveLabel = "Save unrestricted copy...",
            SaveCopyAsync = SaveAsync,
        });
    }

    private string Method(string filter)
    {
        if (version < 4) return "V2";
        if (filter == "Identity") return "None";
        var cf = document.Resolve(security.Get("CF")) as PdfDictionary;
        var definition = document.Resolve(cf?.Get(filter)) as PdfDictionary ?? throw new FormatException($"Missing PDF crypt filter /{filter}.");
        string method = definition.Name("CFM") ?? "None";
        if (method is not ("None" or "V2" or "AESV2" or "AESV3") || method == "AESV3" && revision < 5 || revision >= 5 && method is not ("None" or "AESV3"))
            throw new UnsupportedFormatException($"Unsupported PDF crypt filter method /{method}.");
        if (method == "AESV2" && key.Length != 16) throw new FormatException("AESV2 requires a 128-bit PDF key.");
        if (definition.Get("Length") is PdfNumber length && length.Integer != key.Length)
            throw new UnsupportedFormatException("PDF crypt filters with a different key length are not supported.");
        return method;
    }

    private byte[] DecryptBytes(byte[] bytes, int number, int generation, string method)
    {
        if (method == "None") return bytes;
        byte[] objectKey = key;
        if (method != "AESV3")
        {
            byte[] suffix = [(byte)number, (byte)(number >> 8), (byte)(number >> 16), (byte)generation, (byte)(generation >> 8)];
            objectKey = MD5.HashData(method == "AESV2" ? [.. key, .. suffix, 0x73, 0x41, 0x6c, 0x54] : [.. key, .. suffix])[..Math.Min(key.Length + 5, 16)];
        }
        if (method == "V2") return Rc4.Apply(objectKey, bytes);
        if (bytes.Length < 32 || bytes.Length % 16 != 0) throw new FormatException("Truncated PDF AES string or stream.");
        try
        {
            using var aes = Aes.Create(); aes.Key = objectKey;
            return aes.DecryptCbc(bytes.AsSpan(16), bytes.AsSpan(0, 16), PaddingMode.PKCS7);
        }
        catch (CryptographicException ex) { throw new FormatException("PDF AES data has invalid padding; no copy was written.", ex); }
    }

    private PdfObject DecryptObject(PdfObject obj)
    {
        if (obj.Number == encryptObject || obj.Value is PdfDictionary x && x.Name("Type") == "XRef") return obj;
        string strings = Method(security.Name("StrF") ?? "Identity");
        PdfValue Walk(PdfValue value) => value switch
        {
            PdfString s => new PdfString(DecryptBytes(s.Bytes, obj.Number, obj.Generation, strings)),
            PdfArray a => new PdfArray(a.Items.Select(Walk).ToList()),
            PdfDictionary d => new PdfDictionary(d.Items.ToDictionary(p => p.Key, p => Walk(p.Value), StringComparer.Ordinal)),
            _ => value,
        };
        var value = Walk(obj.Value);
        if (obj.Stream is null) return obj with { Value = value };
        var dict = (PdfDictionary)value;
        if (dict.Get("F") is not null) throw new UnsupportedFormatException("PDF external streams cannot be copied safely.");
        string streamFilter = dict.Name("Type") == "EmbeddedFile" ? security.Name("EFF") ?? security.Name("StmF") ?? "Identity" : security.Name("StmF") ?? "Identity";
        var filter = document.Resolve(dict.Get("Filter"));
        var filters = filter is PdfArray array ? array.Items.ToList() : filter is null ? [] : new List<PdfValue> { filter };
        var parms = document.Resolve(dict.Get("DecodeParms"));
        int crypt = filters.FindIndex(f => document.Resolve(f) is PdfName { Text: "Crypt" });
        bool explicitCrypt = crypt >= 0;
        if (explicitCrypt)
        {
            if (crypt != 0 || filters.Skip(1).Any(f => document.Resolve(f) is PdfName { Text: "Crypt" })) throw new UnsupportedFormatException("PDF Crypt filter must appear once, first in the filter chain.");
            var param = document.Resolve(parms is PdfArray pa ? pa.Items.FirstOrDefault() : parms) as PdfDictionary;
            streamFilter = param?.Name("Name") ?? "Identity";
            filters.RemoveAt(0);
            dict.Items.Remove("Filter"); dict.Items.Remove("DecodeParms");
            if (filters.Count > 0)
            {
                dict.Items["Filter"] = new PdfArray(filters);
                if (parms is PdfArray parameters) dict.Items["DecodeParms"] = new PdfArray(parameters.Items.Skip(1).ToList());
            }
        }
        string method = !explicitCrypt && !encryptMetadata && dict.Name("Type") == "Metadata" ? "None" : Method(streamFilter);
        var stream = DecryptBytes(obj.Stream, obj.Number, obj.Generation, method);
        dict.Items["Length"] = new PdfNumber(stream.Length.ToString(System.Globalization.CultureInfo.InvariantCulture));
        return obj with { Value = dict, Stream = stream };
    }

    private static string CanonicalPath(string path, int depth = 0)
    {
        if (depth > 64) throw new IOException("Too many symbolic links in the PDF path.");
        string full = Path.GetFullPath(path), root = Path.GetPathRoot(full)!;
        string current = root;
        foreach (string part in full[root.Length..].Split(Path.DirectorySeparatorChar, StringSplitOptions.RemoveEmptyEntries))
        {
            current = Path.Combine(current, part);
            FileSystemInfo entry = Directory.Exists(current) ? new DirectoryInfo(current) : new FileInfo(current);
            if (entry.LinkTarget is not null)
            {
                var target = entry.ResolveLinkTarget(true) ?? throw new IOException("Cannot resolve a symbolic link in the PDF path.");
                current = CanonicalPath(target.FullName, depth + 1);
            }
        }
        return current;
    }

    internal static async Task SaveAsync(string source, string output, CancellationToken ct)
    {
        var comparison = OperatingSystem.IsWindows() || OperatingSystem.IsMacOS() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
        if (string.Equals(CanonicalPath(source), CanonicalPath(output), comparison)) throw new IOException("Choose a different output file; the original is never overwritten.");
        if (new FileInfo(source).Length > PdfDocument.MaxBytes) throw new UnsupportedFormatException("PDF permission removal supports files up to 256 MiB.");
        var bytes = await File.ReadAllBytesAsync(source, ct);
        string temp = Path.Combine(Path.GetDirectoryName(Path.GetFullPath(output))!, ".rk-pdf-" + Guid.NewGuid().ToString("N") + ".tmp");
        try
        {
            var document = new PdfDocument(bytes);
            _ = new PdfDecryptor(document);
            using (var file = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None)) PdfWriter.Write(document, file, ct);
            ct.ThrowIfCancellationRequested();
            File.Move(temp, output, true);
        }
        catch (InvalidDataException ex) { throw new FormatException("Invalid compressed PDF data; no copy was written.", ex); }
        finally { if (File.Exists(temp)) File.Delete(temp); }
    }
}
