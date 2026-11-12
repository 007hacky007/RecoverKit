using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json;

namespace RecoverKit.Core.Formats;

/// <summary>Validated keyfiles and a fixed PIM used by hashcat to interpret a volume header.</summary>
public sealed class VolumeCredentials
{
    public const int MaxPim = 2147468;
    public const int MaxBootPim = 65535;
    private const int KeyfileBytes = 1024 * 1024;

    public int Pim { get; }
    public IReadOnlyList<string> Keyfiles { get; }
    public IReadOnlyList<string> Arguments { get; }
    public string Identity { get; }
    private readonly string _fingerprint;

    public VolumeCredentials(VolumeOptions options)
    {
        int max = options.BootVolume ? MaxBootPim : MaxPim;
        if (options.Pim < 0 || options.Pim > max)
            throw new ArgumentOutOfRangeException(nameof(options), $"PIM must be between 0 and {max} (0 uses the default).");
        if (options.Kind == VolumeKind.TrueCrypt && options.Pim != 0)
            throw new ArgumentException("Custom PIM is only supported for VeraCrypt volumes.");
        if (options.BootVolume && options.Keyfiles.Count > 0)
            throw new ArgumentException("Keyfiles are not supported for system (boot) encryption.");

        Pim = options.Pim;
        var paths = new List<string>();
        foreach (var path in options.Keyfiles)
        {
            if (string.IsNullOrWhiteSpace(path)) throw new ArgumentException("Select a keyfile.");
            string full = Path.GetFullPath(path);
            if (full.Contains(',')) throw new ArgumentException("Keyfile paths cannot contain commas because hashcat uses commas to separate files.");
            paths.Add(full);
        }
        Keyfiles = paths.AsReadOnly();
        _fingerprint = Fingerprint();
        var args = new List<string>();
        if (paths.Count > 0)
            args.AddRange([options.Kind == VolumeKind.TrueCrypt ? "--truecrypt-keyfiles" : "--veracrypt-keyfiles", string.Join(',', paths)]);
        if (Pim > 0)
        {
            string pim = Pim.ToString(CultureInfo.InvariantCulture);
            args.AddRange(["--veracrypt-pim-start", pim, "--veracrypt-pim-stop", pim]);
        }
        Arguments = args.AsReadOnly();
        Identity = JsonSerializer.Serialize(new { Arguments, Fingerprint = _fingerprint });
    }

    // Hashcat uses only the first MiB of each file; hash contents so overwrites invalidate saved progress.
    private string Fingerprint()
    {
        var hashes = new List<string>();
        foreach (var path in Keyfiles)
        {
            using var stream = File.OpenRead(path);
            if (stream.Length == 0) throw new ArgumentException("Keyfiles must not be empty.");
            var bytes = new byte[(int)Math.Min(KeyfileBytes, stream.Length)];
            try
            {
                stream.ReadExactly(bytes);
                hashes.Add(Convert.ToHexString(SHA256.HashData(bytes)));
            }
            finally { CryptographicOperations.ZeroMemory(bytes); }
        }
        return string.Join(',', hashes);
    }

    public void ValidateUnchanged()
    {
        try
        {
            if (Fingerprint() == _fingerprint) return;
        }
        catch (ArgumentException) { } // A keyfile truncated to zero bytes is also a credential change.
        throw new IOException("A selected keyfile has changed. Reopen the volume before starting recovery.");
    }
}
