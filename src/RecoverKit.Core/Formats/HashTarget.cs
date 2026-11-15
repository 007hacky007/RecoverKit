namespace RecoverKit.Core.Formats;

/// <summary>Relative recovery speed class shown in the information pane.</summary>
public enum SpeedClass { Instant, VeryFast, Fast, Medium, Slow, VerySlow }

/// <summary>
/// Everything needed to attack one protected file with hashcat: the extracted
/// hash line(s) and the hashcat mode(s) that can verify candidate passwords.
/// </summary>
public sealed class HashTarget
{
    /// <summary>Four-letter format identifier used by scenario files (e.g. OF13, RAR5).</summary>
    public required string FormatId { get; init; }
    public required string FormatName { get; init; }
    public required string Protection { get; init; }

    /// <summary>Hashcat modes to try, in order. Usually one; TrueCrypt/VeraCrypt may need several.</summary>
    public required IReadOnlyList<int> Modes { get; init; }

    /// <summary>Content of the hash file handed to hashcat (one hash per line).</summary>
    public required string HashLines { get; init; }

    public SpeedClass Speed { get; init; } = SpeedClass.Medium;

    /// <summary>Maximum password length the hashcat kernel accepts, when known.</summary>
    public int? MaxPasswordLength { get; init; }

    /// <summary>True if the format hashes the password as UTF-16 (non-ASCII support is limited in hashcat).</summary>
    public bool Utf16Password { get; init; }

    public VolumeCredentials? VolumeCredentials { get; init; }

    /// <summary>Classic ZipCrypto entries (stored headers) for Stay's header-RNG attack, when applicable.</summary>
    public ZipStayTarget? StayZip { get; set; }

    /// <summary>The archive entry used for full confirmation when the GPU receives only a prefix.</summary>
    public ZipPartialTarget? ZipPartial { get; init; }

    /// <summary>A large 7z stream for the built-in CPU engine; these targets have no hashcat modes.</summary>
    public SevenZipCpuTarget? SevenZipCpu { get; init; }

    /// <summary>
    /// A second check for candidates that passed the hash: a password is reported (or taken from the
    /// password cache) only when this also returns true for its bytes. Set for ZIP archives whose other
    /// encrypted entries can be checked too (see <see cref="ZipPasswordConfirmer"/>); the hash covers one
    /// entry, so a wrong password passes it now and then. Null when the hash alone decides.
    /// </summary>
    public Func<byte[], bool>? ConfirmPassword { get; set; }

    public ZipCheckBytesTarget? ZipCheckBytes { get; set; }

    /// <summary>The pre-speed-selection target, for sessions saved by older releases.</summary>
    public HashTarget? LegacyZipTarget { get; set; }

    public string? Notes { get; init; }
}

/// <summary>Result of opening a file: descriptive info plus an attackable target when one exists.</summary>
public sealed class Detection
{
    public required string FilePath { get; init; }
    public string TypeName { get; set; } = "Unknown";
    public List<KeyValuePair<string, string>> Info { get; } = new();
    public HashTarget? Target { get; set; }

    /// <summary>Human-readable explanation when no target was produced (not encrypted, unsupported...).</summary>
    public string? Message { get; set; }

    /// <summary>Weak protections that can be undone right away, without an attack (see <see cref="InstantUnlock"/>).</summary>
    public List<InstantUnlock> Unlocks { get; } = new();

    public void Add(string key, string value) => Info.Add(new(key, value));

    public static Detection Fail(string path, string type, string message)
        => new() { FilePath = path, TypeName = type, Message = message };
}

public sealed class UnsupportedFormatException(string message) : Exception(message);
