using RecoverKit.Core.Native.Kernels;

namespace RecoverKit.Core.Formats;

/// <summary>
/// Checks a candidate that opened the attacked ZipCrypto entry against the archive's other classic
/// ZipCrypto entries. The hash (hashcat 17200/17210, the built-in kernel) covers one entry: for a
/// stored entry a wrong password passes its check byte and CRC-32 about once in 5 * 10^11
/// candidates, which a GPU tests in minutes. Each further entry rejects a wrong password with a
/// probability of at least 255 in 256 (the check byte of its encryption header) and, when its data is
/// small enough to keep (stored or deflated), practically always (the full CRC-32, after inflating).
/// Runs only for candidates that already passed the hash, so its cost does not matter.
/// </summary>
public sealed class ZipPasswordConfirmer
{
    /// <summary>One entry: its stored header, the accepted check bytes and, when kept, a full verifier.</summary>
    internal sealed record Check(string Name, byte[] Header, byte CrcCheck, byte TimeCheck, ZipCryptoKernel? Full);

    private readonly Check[] _checks;

    internal ZipPasswordConfirmer(IEnumerable<Check> checks) => _checks = checks.ToArray();

    /// <summary>Entries the candidate is checked against.</summary>
    public int Entries => _checks.Length;

    /// <summary>Entries checked with their whole data (CRC-32), not only the header's check byte.</summary>
    public int FullChecks => _checks.Count(c => c.Full is not null);

    /// <summary>The header checks alone, for a kernel that confirms a large entry from the archive file.</summary>
    public IReadOnlyList<ZipHeaderCheck> HeaderChecks => _checks.Select(c => new ZipHeaderCheck(c.Header, c.CrcCheck, c.TimeCheck)).ToArray();

    /// <summary>True when the password opens every entry checked.</summary>
    public bool Confirm(byte[] password)
    {
        // The header check bytes first: one key schedule each, and a wrong password fails 255 in 256.
        foreach (var c in _checks)
        {
            byte b = ZipCryptoKernel.HeaderCheckByte(password, c.Header);
            if (b != c.CrcCheck && b != c.TimeCheck) return false;
        }
        foreach (var c in _checks)
            if (c.Full is { } k && !k.Verify(password)) return false;
        return true;
    }
}
