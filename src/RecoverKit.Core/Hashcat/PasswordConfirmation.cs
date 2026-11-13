using System.Text;

namespace RecoverKit.Core.Hashcat;

/// <summary>
/// Helpers for targets with a confirmation check (<see cref="Formats.HashTarget.ConfirmPassword"/>):
/// plaintexts as hashcat writes them turned back into bytes, and the password cache (hashcat's
/// potfile) written and read by RecoverKit itself for them.
/// </summary>
public static class PasswordConfirmation
{
    /// <summary>The password bytes of a plaintext as hashcat writes it ($HEX[...] decoded, else UTF-8).</summary>
    public static byte[] PlainBytes(string raw)
    {
        if (raw.StartsWith("$HEX[", StringComparison.Ordinal) && raw.EndsWith(']'))
            try { return Convert.FromHexString(raw.AsSpan(5, raw.Length - 6)); }
            catch (FormatException) { }
        return Encoding.UTF8.GetBytes(raw);
    }

    /// <summary>hashcat's hex form of a plaintext; safe for any byte, including ':' and line breaks.</summary>
    public static string HexPlain(ReadOnlySpan<byte> pw) => "$HEX[" + Convert.ToHexString(pw).ToLowerInvariant() + "]";

    /// <summary>Adds a confirmed password to the password cache as <c>hash:$HEX[...]</c>, which hashcat's --show reads.</summary>
    public static async Task AppendAsync(string potfile, string hashLine, byte[] pw)
    {
        try
        {
            if (Path.GetDirectoryName(potfile) is { Length: > 0 } dir) Directory.CreateDirectory(dir);
            await File.AppendAllTextAsync(potfile, hashLine.Trim() + ":" + HexPlain(pw) + "\n", new UTF8Encoding(false), CancellationToken.None);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { DebugLog.Warn("Could not write potfile: " + ex.Message); }
    }

    /// <summary>
    /// Plaintexts of the cache lines RecoverKit wrote for exactly this hash line. hashcat's --show
    /// reports one plaintext per hash, which may be an earlier false positive; these lines give the
    /// others a chance.
    /// </summary>
    public static List<string> OwnEntries(string potfile, string hashLine)
    {
        var found = new List<string>();
        string prefix = hashLine.Trim() + ":";
        try
        {
            if (!File.Exists(potfile)) return found;
            foreach (var line in File.ReadLines(potfile))
                if (line.StartsWith(prefix, StringComparison.Ordinal)) found.Add(line[prefix.Length..]);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
        return found;
    }

    /// <summary>The first hash line of a hash file (what hashcat's potfile lines start with).</summary>
    public static string FirstHashLine(string hashFile)
    {
        try { return File.ReadLines(hashFile).FirstOrDefault(l => l.Trim().Length > 0)?.Trim() ?? ""; }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return ""; }
    }
}

/// <summary>
/// Logs candidates that passed the hash but not the confirmation check: the first few in the session
/// log (length only, never the candidate), every one in the debug log.
/// </summary>
public sealed class FalsePositiveLog(Action<string> output)
{
    public const int Logged = 3;
    private int _count;

    public int Count => Volatile.Read(ref _count);

    public void Rejected(int length, string engine)
    {
        int n = Interlocked.Increment(ref _count);
        DebugLog.Info($"False positive rejected #{n} ({engine}, {length} characters)");
        if (n > Logged) return;
        output($"False positive rejected: a {length}-character candidate from {engine} opens the attacked file but not the " +
               "archive's other encrypted files; the search goes on." + (n == Logged ? " Further ones are not logged." : ""));
    }
}
