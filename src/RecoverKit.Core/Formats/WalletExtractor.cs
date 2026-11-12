using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace RecoverKit.Core.Formats;

/// <summary>Reads wallet containers without deriving keys or exposing private wallet fields.</summary>
public static class WalletExtractor
{
    private const int MaxFileSize = 32 * 1024 * 1024;
    private const string OwnDevice = "Password recovery needs the wallet file from your own device. ";

    public static bool TryExtract(Stream stream, Detection d)
    {
        var head = Encoding.UTF8.GetString(Bin.ReadAt(stream, 0, 4096));
        string start = head.TrimStart('\uFEFF', ' ', '\r', '\n', '\t');
        bool database = d.FilePath.EndsWith(".ldb", StringComparison.OrdinalIgnoreCase) ||
                        d.FilePath.EndsWith(".log", StringComparison.OrdinalIgnoreCase);
        bool candidate = start.StartsWith('{') || start.StartsWith('"') || start.StartsWith("QklF") ||
                         start.StartsWith("SECO") || head.Contains("\"data\"") || head.Contains("\\\"data\\\"") || head.Contains("\\u0022data") ||
                         (start.Length >= 100 && start.All(c => char.IsAsciiLetterOrDigit(c) || "+/=\r\n".Contains(c)));
        if (!candidate && !database) return false;
        if (stream.Length > MaxFileSize)
            throw new UnsupportedFormatException("Wallet input exceeds 32 MiB. Extract the vault JSON from the database first.");
        string text = Encoding.UTF8.GetString(Bin.ReadAt(stream, 0, (int)stream.Length))
            .TrimStart('\uFEFF').Trim();
        if (text.StartsWith("SECO"))
        {
            d.TypeName = "Exodus SECO wallet";
            d.Message = "Exodus SECO container extraction is not supported; its binary layout has not been verified.";
            return true;
        }
        try
        {
            if (text.StartsWith("QklF")) return ElectrumFile(Base64(text), d);
            if (!text.StartsWith('{') && !text.StartsWith('"') && !database && !text.Contains('{'))
            {
                byte[] payload;
                try { payload = Convert.FromBase64String(text); }
                catch (FormatException) { return false; }
                if (payload.Length < 80 || payload.Length % 16 != 0) return false;
                Blockchain(payload, 10, false, d);
                return true;
            }
            if (text.StartsWith('{') || text.StartsWith('"'))
            {
                string json = text.StartsWith("{'") || Regex.IsMatch(text, @"^\{\s*'", RegexOptions.CultureInvariant)
                    ? PythonLiteral(text) : text;
                try
                {
                    using var doc = JsonDocument.Parse(json);
                    var root = doc.RootElement;
                    if (Has(root, "crypto") || Has(root, "Crypto")) { Ethereum(root, d); return true; }
                    if (Has(root, "payload"))
                    {
                        int version = Number(root, "version", 4);
                        if (version is < 2 or > 4) throw new UnsupportedFormatException("Unsupported Blockchain.com wallet version.");
                        Blockchain(Base64(String(root, "payload")), Number(root, "pbkdf2_iterations", 999999), true, d);
                        return true;
                    }
                    if (Has(root, "wallet_type") || Has(root, "seed_version")) { Electrum(root, d); return true; }
                    if (FindVault(root, d, 0)) return true;
                    return false;
                }
                catch (JsonException) when (database) { /* Scan complete vault records in a database fragment. */ }
            }
            return ScanVaults(text, d);
        }
        catch (JsonException) { throw new FormatException("Invalid wallet JSON."); }
        catch (RegexMatchTimeoutException) { throw new FormatException("Wallet text is too complex to parse."); }
    }

    private static void Ethereum(JsonElement root, Detection d)
    {
        d.TypeName = "Ethereum keystore v3";
        if (Number(root, "version", 3) != 3) throw new UnsupportedFormatException("Only Ethereum keystore v3 is supported.");
        var crypto = Has(root, "crypto") ? Property(root, "crypto") : Property(root, "Crypto");
        if (String(crypto, "cipher") != "aes-128-ctr") throw new UnsupportedFormatException("Unsupported Ethereum cipher.");
        Hex(Property(crypto, "cipherparams"), "iv", 16);
        var kdf = Property(crypto, "kdfparams");
        if (Number(kdf, "dklen", 1024) != 32) throw new UnsupportedFormatException("Ethereum derived key must be 32 bytes.");
        string salt = Hex(kdf, "salt", 16, 32);
        string ct = Hex(crypto, "ciphertext", 32), mac = Hex(crypto, "mac", 32);
        string kind = String(crypto, "kdf");
        if (kind == "pbkdf2")
        {
            if (String(kdf, "prf") != "hmac-sha256") throw new UnsupportedFormatException("Ethereum needs PBKDF2-HMAC-SHA256.");
            int iterations = Number(kdf, "c", 999999);
            Set(d, "ETH3", "Ethereum keystore v3", $"PBKDF2-SHA256, {iterations} iterations, Keccak MAC", 15600,
                $"$ethereum$p*{iterations}*{salt}*{ct}*{mac}", SpeedClass.Slow);
        }
        else if (kind == "scrypt")
        {
            if (salt.Length != 64) throw new UnsupportedFormatException("Ethereum scrypt mode requires a 32-byte salt.");
            int n = Number(kdf, "n", 999999), r = Number(kdf, "r", 999999), p = Number(kdf, "p", 999999);
            if (n < 1024 || (n & (n - 1)) != 0 || n % 1024 != 0 || (long)r * p >= 1L << 30)
                throw new UnsupportedFormatException("Ethereum scrypt needs a power-of-two N of at least 1024 and valid r/p parameters.");
            Set(d, "ETH3", "Ethereum keystore v3", $"scrypt N={n}, r={r}, p={p}, Keccak MAC", 15700,
                $"$ethereum$s*{n}*{r}*{p}*{salt}*{ct}*{mac}", SpeedClass.VerySlow, "scrypt recovery is very slow and needs substantial memory.");
        }
        else throw new UnsupportedFormatException("Unsupported Ethereum KDF.");
    }

    private static bool FindVault(JsonElement value, Detection d, int depth)
    {
        if (depth > 16) throw new FormatException("Wallet nesting is too deep.");
        if (value.ValueKind == JsonValueKind.Object)
        {
            if (Has(value, "data") && Has(value, "iv") && Has(value, "salt")) { MetaMask(value, d); return true; }
            foreach (var property in value.EnumerateObject())
                if (FindVault(property.Value, d, depth + 1)) return true;
        }
        else if (value.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in value.EnumerateArray()) if (FindVault(item, d, depth + 1)) return true;
        }
        else if (value.ValueKind == JsonValueKind.String)
        {
            string s = value.GetString()!;
            if (s.TrimStart().StartsWith('{'))
            {
                using var nested = JsonDocument.Parse(s);
                return FindVault(nested.RootElement, d, depth + 1);
            }
        }
        return false;
    }

    private static bool ScanVaults(string text, Detection d)
    {
        var matches = Regex.Matches(text, "\\{\\s*\"(?:data|iv|salt|keyMetadata)\"\\s*:|\"\\{(?:\\\\|\\s)",
            RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1));
        int count = 0;
        foreach (Match match in matches)
        {
            if (++count > 256) throw new FormatException("Too many vault candidates. Extract one vault JSON first.");
            // Limit each candidate so a damaged record cannot repeatedly copy the entire database.
            byte[] bytes = Encoding.UTF8.GetBytes(text.Substring(match.Index, Math.Min(text.Length - match.Index, 1024 * 1024)));
            try
            {
                var reader = new Utf8JsonReader(bytes);
                using var doc = JsonDocument.ParseValue(ref reader);
                if (FindVault(doc.RootElement, d, 0)) return true;
            }
            catch (Exception ex) when (ex is JsonException or FormatException or UnsupportedFormatException)
            { /* LevelDB can contain incomplete, damaged or unsupported older records. */ }
        }
        return false;
    }

    private static void MetaMask(JsonElement root, Detection d)
    {
        d.TypeName = "MetaMask vault";
        byte[] salt = Base64(String(root, "salt")), iv = Base64(String(root, "iv")), data = Base64(String(root, "data"));
        if (salt.Length != 32 || iv.Length != 16 || data.Length < 46) throw new FormatException("Invalid MetaMask salt, IV or encrypted data length.");
        int iterations = 10000;
        if (Has(root, "keyMetadata"))
        {
            var meta = Property(root, "keyMetadata");
            if (String(meta, "algorithm") != "PBKDF2") throw new UnsupportedFormatException("Unsupported MetaMask KDF.");
            iterations = Number(Property(meta, "params"), "iterations", int.MaxValue);
        }
        bool shortData = data.Length > 3152;
        string prefix = shortData ? "$metamask-short$" : "$metamask$";
        if (iterations != 10000) prefix += $"rounds={iterations}$";
        Set(d, "MTMK", "MetaMask vault", $"PBKDF2-SHA256, {iterations} iterations, AES-256-GCM", shortData ? 26610 : 26600,
            $"{prefix}{Convert.ToBase64String(salt)}${Convert.ToBase64String(iv)}${Convert.ToBase64String(shortData ? data[..64] : data)}",
            iterations >= 600000 ? SpeedClass.VerySlow : SpeedClass.Slow,
            shortData ? "Large vault: checks the first 64 plaintext bytes, without the GCM tag. Verify the recovered password in MetaMask; non-text vaults are unsupported." : "Verifies the AES-GCM authentication tag.");
    }

    private static void Blockchain(byte[] data, int iterations, bool v2, Detection d)
    {
        d.TypeName = "Blockchain.com wallet";
        if (data.Length < 80 || data.Length % 16 != 0) throw new FormatException("Invalid Blockchain.com AES-CBC payload length.");
        // Both kernels verify the first blocks only; keep hashes small for large backups.
        byte[] prefix = data.Length <= 32768 ? data : data[..80];
        string tag = v2 ? $"$blockchain$v2${iterations}$" : "$blockchain$";
        Set(d, "BLCH", "Blockchain.com wallet", $"PBKDF2-SHA1, {iterations} iterations, AES-256-CBC", v2 ? 15200 : 12700,
            $"{tag}{prefix.Length}${Bin.Hex(prefix)}", iterations >= 100000 ? SpeedClass.VerySlow : v2 ? SpeedClass.Slow : SpeedClass.Fast,
            "Checks the wallet JSON prefix. Verify the password in the wallet. " +
            (v2 ? "Recovers the main wallet password, not a second spending password." : "Legacy base64 has no unique signature; confirm this is a Blockchain.com backup. Mode 12700 supports 10 iterations."));
    }

    private static void Electrum(JsonElement root, Detection d)
    {
        d.TypeName = "Electrum wallet";
        if (Has(root, "use_encryption"))
        {
            var encryption = Property(root, "use_encryption");
            if (encryption.ValueKind == JsonValueKind.False) { d.Message = "Electrum wallet is not password encrypted."; return; }
            if (encryption.ValueKind != JsonValueKind.True) throw new FormatException("Invalid Electrum encryption flag.");
        }
        if (Has(root, "seed") && (Has(root, "seed_version") && Number(root, "seed_version", 100) == 4))
        { ElectrumBlock(String(root, "seed"), 1, d); return; }
        if (Has(root, "keystore") && ElectrumKeystore(Property(root, "keystore"), d)) return;
        foreach (var property in root.EnumerateObject())
            if (property.Name.StartsWith('x') && property.Name.EndsWith('/') && ElectrumKeystore(property.Value, d)) return;
        if (Has(root, "master_private_keys"))
        {
            var keys = Property(root, "master_private_keys");
            if (keys.ValueKind != JsonValueKind.Object) throw new FormatException("Invalid Electrum private keys.");
            foreach (var key in keys.EnumerateObject())
                if (key.Value.ValueKind == JsonValueKind.String) { ElectrumBlock(key.Value.GetString()!, 2, d); return; }
        }
        if (Has(root, "accounts"))
        {
            var imported = Property(Property(Property(root, "accounts"), "/x"), "imported");
            if (imported.ValueKind != JsonValueKind.Object) throw new FormatException("Invalid Electrum imported keys.");
            foreach (var pair in imported.EnumerateObject())
                if (pair.Value.ValueKind == JsonValueKind.Array && pair.Value.GetArrayLength() >= 2 && pair.Value[1].ValueKind == JsonValueKind.String)
                { ElectrumBlock(pair.Value[1].GetString()!, 3, d); return; }
        }
        throw new FormatException("No supported encrypted Electrum seed or private key found.");
    }

    private static bool ElectrumKeystore(JsonElement store, Detection d)
    {
        string type = String(store, "type");
        if (type == "old") { ElectrumBlock(String(store, "seed"), 1, d); return true; }
        if (type == "bip32" && Has(store, "xprv") && Property(store, "xprv").ValueKind == JsonValueKind.String)
        { ElectrumBlock(String(store, "xprv"), 2, d); return true; }
        if (type == "imported")
        {
            var pairs = Property(store, "keypairs");
            if (pairs.ValueKind != JsonValueKind.Object) throw new FormatException("Invalid Electrum keypairs.");
            foreach (var key in pairs.EnumerateObject())
                if (key.Value.ValueKind == JsonValueKind.String) { ElectrumBlock(key.Value.GetString()!, 3, d); return true; }
        }
        return false;
    }

    private static void ElectrumBlock(string encoded, int type, Detection d)
    {
        byte[] data = Base64(encoded);
        int length = type == 1 ? 64 : type == 2 ? 128 : 80;
        if (data.Length != length) throw new FormatException("Invalid Electrum encrypted key length.");
        var block = type == 3 ? data[^32..] : data[..32];
        Set(d, "ELCT", "Electrum wallet", $"Double SHA256, AES-256-CBC (salt type {type})", 16600,
            $"$electrum${type}*{Bin.Hex(block[..16])}*{Bin.Hex(block[16..])}", SpeedClass.Fast,
            "Checks seed/key structure or padding. Verify the recovered password in Electrum. Only the selected encrypted key is checked.");
    }

    private static bool ElectrumFile(byte[] data, Detection d)
    {
        d.TypeName = "Electrum encrypted wallet";
        if (data.Length < 4 || !data.AsSpan(0, 4).SequenceEqual("BIE1"u8))
            throw new UnsupportedFormatException("Only password-encrypted Electrum BIE1 files are supported.");
        if (data.Length < 101 || (data.Length - 69) % 16 != 0 || data[4] is not (2 or 3))
            throw new FormatException("Invalid Electrum BIE1 container.");
        bool truncated = data.Length - 32 > 16384;
        byte[] body = truncated ? data[37..1061] : data[..^32];
        Set(d, "ELCT", "Electrum encrypted wallet (2.8+)", "PBKDF2-SHA512, 1024 iterations, secp256k1, AES-128-CBC", truncated ? 21800 : 21700,
            $"$electrum${(truncated ? 5 : 4)}*{Bin.Hex(data[4..37])}*{Bin.Hex(body)}*{Bin.Hex(data[^32..])}", SpeedClass.Slow,
            truncated ? "Large wallet: truncated zlib/plaintext verification without the MAC. Verify the recovered password in Electrum." : "Verifies the complete wallet HMAC-SHA256.");
        return true;
    }

    private static string PythonLiteral(string text)
    {
        // Electrum 1.x saved Python literals. Decode string escapes, never evaluate code.
        return Regex.Replace(text, "[uU]?(?:'(?:\\\\.|[^'\\\\])*'|\"(?:\\\\.|[^\"\\\\])*\")|\\b(?:True|False|None)\\b", match =>
        {
            string token = match.Value;
            if (token[0] is 'u' or 'U') token = token[1..];
            if (token[0] is not ('\'' or '\"')) return token == "True" ? "true" : token == "False" ? "false" : "null";
            try { return JsonSerializer.Serialize(Regex.Unescape(token[1..^1])); }
            catch (ArgumentException) { throw new FormatException("Unsupported escape in Electrum Python literal."); }
        }, RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1));
    }

    private static bool Has(JsonElement root, string name) => root.ValueKind == JsonValueKind.Object && root.TryGetProperty(name, out _);
    private static JsonElement Property(JsonElement root, string name)
        => root.ValueKind == JsonValueKind.Object && root.TryGetProperty(name, out var value) ? value : throw new FormatException("Missing wallet field: " + name);
    private static string String(JsonElement root, string name)
    {
        var value = Property(root, name);
        return value.ValueKind == JsonValueKind.String ? value.GetString()! : throw new FormatException("Invalid wallet field: " + name);
    }
    private static int Number(JsonElement root, string name, int max)
    {
        var value = Property(root, name);
        if (value.ValueKind != JsonValueKind.Number || !value.TryGetInt32(out int n) || n < 1) throw new FormatException("Invalid wallet number: " + name);
        if (n > max) throw new UnsupportedFormatException("Wallet parameter exceeds hashcat's supported range: " + name);
        return n;
    }
    private static byte[] Base64(string text)
    {
        try { return Convert.FromBase64String(text); }
        catch (FormatException) { throw new FormatException("Invalid wallet base64 data."); }
    }
    private static string Hex(JsonElement root, string name, int length, int alternate = -1)
    {
        string text = String(root, name);
        if ((text.Length != length * 2 && text.Length != alternate * 2) || !text.All(char.IsAsciiHexDigit))
            throw new FormatException("Invalid wallet hex field: " + name);
        return text.ToLowerInvariant();
    }
    private static void Set(Detection d, string id, string name, string protection, int mode, string hash, SpeedClass speed, string notes = "")
    {
        d.TypeName = name;
        d.Target = new HashTarget
        {
            FormatId = id, FormatName = name, Protection = protection, Modes = [mode], HashLines = hash,
            Speed = speed, MaxPasswordLength = 256, Notes = OwnDevice + notes,
        };
    }
}
