using RecoverKit.Core.Formats;

namespace RecoverKit.Core.Attacks.Stay;

/// <summary>Outcome of the Stay fast-key-search step: recovered keys and the decrypted copy, if any.</summary>
public sealed record StayStepOutcome(ZipStayKeys? Keys, string? DecryptedCopy, bool Incompatible);

/// <summary>
/// The Stay attack as a recovery step: key-cache lookup, the staged search itself, the key-cache
/// store, and the password-free decrypted copy. Runs entirely in-process - hashcat is not involved.
/// The recovered key values never appear in the logs; they travel in the step outcome and the
/// session result only.
/// </summary>
public static class StayZipStep
{
    /// <summary>Runs the step for a ZIP target whose StayZip payload the planner already accepted.</summary>
    public static async Task<StayStepOutcome> RunAsync(HashTarget target, string filePath, Settings settings,
        Action<LogKind, string> log, CancellationToken ct)
    {
        var payload = target.StayZip ?? throw new ArgumentException("The target has no Stay ZipCrypto payload.");
        string hashLine = target.HashLines.Replace("\r", "").Split('\n', StringSplitOptions.RemoveEmptyEntries)[0].Trim();

        ZipStayKeys keys;
        string? cached = settings.DontUseKeyCache ? null : KeyCache.Lookup(settings.KeyCachePath, hashLine);
        if (cached is not null && TryParseKeys(cached, out var fromCache))
        {
            keys = fromCache;
            log(LogKind.Info, "Cipher keys for this archive were recovered earlier (key cache).");
        }
        else
        {
            int lastTenth = -1;
            var result = await StayAttack.RunAsync(payload, ct,
                progress: (f, _) =>
                {
                    int tenth = (int)(f * 10);
                    if (tenth > lastTenth)
                    {
                        lastTenth = tenth;
                        log(LogKind.Info, $"Fast key search: {Math.Min(tenth * 10, 100)}%");
                    }
                },
                archivePath: filePath);

            if (result is null)
            {
                log(LogKind.Warning, "The fast key search is not compatible with this archive: the encryption headers do not come from a weak WinZip-style generator, or fewer than five files share one.");
                return new StayStepOutcome(null, null, Incompatible: true);
            }

            keys = result.Keys;
            if (!settings.DontUseKeyCache) KeyCache.Store(settings.KeyCachePath, hashLine, KeysHex(keys));
            log(LogKind.Success, "Fast key search recovered the archive's cipher keys; continuing toward the password.");
        }

        string? copy = null;
        try
        {
            string outPath = ZipStayDecryptor.OutputPathFor(filePath, settings);
            if (File.Exists(outPath))
            {
                log(LogKind.Info, $"Decrypted copy already exists, left untouched: {outPath}");
            }
            else
            {
                ZipStayDecryptor.WriteDecryptedCopy(filePath, payload, keys, outPath);
                copy = outPath;
                log(LogKind.Success, $"Decrypted, password-free copy written: {outPath}");
            }
        }
        catch (Exception ex) when (ex is IOException or FormatException or InvalidDataException or UnauthorizedAccessException)
        {
            log(LogKind.Warning, $"The keys were recovered but the decrypted copy could not be written: {ex.Message}");
        }

        return new StayStepOutcome(keys, copy, Incompatible: false);
    }

    /// <summary>The three cipher keys as 24 lower-case hex characters (X, Y, Z little-endian).</summary>
    public static string KeysHex(ZipStayKeys k)
    {
        Span<byte> b = stackalloc byte[12];
        BitConverter.TryWriteBytes(b[..4], k.X);
        BitConverter.TryWriteBytes(b[4..8], k.Y);
        BitConverter.TryWriteBytes(b[8..], k.Z);
        return Convert.ToHexString(b).ToLowerInvariant();
    }

    public static bool TryParseKeys(string hex, out ZipStayKeys keys)
    {
        keys = default;
        if (hex.Length != 24) return false;
        byte[] b;
        try { b = Convert.FromHexString(hex); } catch (FormatException) { return false; }
        if (b.Length != 12) return false;
        keys = new ZipStayKeys(BitConverter.ToUInt32(b, 0), BitConverter.ToUInt32(b, 4), BitConverter.ToUInt32(b, 8));
        return true;
    }
}
