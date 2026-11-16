using System.Diagnostics;
using System.Globalization;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using RecoverKit.Core.Hashcat;

namespace RecoverKit.Core.Attacks;

/// <summary>
/// File > Dictionary Generator and File > WPA-PMK Generator: produce the candidates of an attack
/// instead of testing them. Candidates come from hashcat --stdout (masks, dictionaries, rules) or
/// from RecoverKit's own generators (national alphabets, word combinations).
/// </summary>
public static class CandidateExport
{
    public static readonly string[] Encodings = ["UTF8", "UTF8-BOM", "UTF16", "ANSI/CSL"];

    public static Encoding EncodingFor(string name)
    {
        switch (name)
        {
            case "UTF8-BOM": return new UTF8Encoding(true);
            case "UTF16": return new UnicodeEncoding(false, true);
            case "ANSI/CSL":
                Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
                return Encoding.GetEncoding(CultureInfo.CurrentCulture.TextInfo.ANSICodePage);
            default: return new UTF8Encoding(false);
        }
    }

    /// <summary>Every candidate of a prepared attack, in hashcat's order.</summary>
    public static async IAsyncEnumerable<string> CandidatesAsync(PreparedAttack a, HashcatTool tool, [EnumeratorCancellation] CancellationToken ct)
    {
        bool rules = a.Args.Contains("-r");
        if (a.Stdin is not null && !rules)
        {
            foreach (var c in a.Stdin())
            {
                ct.ThrowIfCancellationRequested();
                yield return c;
            }
            yield break;
        }

        // Natural order for masks (hashcat otherwise orders by Markov statistics, which reads oddly in a dictionary).
        string[] extra = a.Args.Contains("3") && a.Args.IndexOf("-a") is int ai && ai >= 0 && ai + 1 < a.Args.Count && a.Args[ai + 1] == "3"
            ? ["--markov-disable"] : [];
        var psi = tool.StartInfo(["--stdout", "--quiet", .. extra, .. a.Args], redirectStdin: a.Stdin is not null);
        int logId = DebugLog.ProcessStart(psi, "candidate export");
        using var p = new Process { StartInfo = psi };
        p.Start();
        Task pump = Task.CompletedTask;
        if (a.Stdin is not null)
        {
            var src = a.Stdin;
            pump = Task.Run(() =>
            {
                try { Generators.Pump(src(), p.StandardInput.BaseStream, ct); }
                catch (IOException) { }
            }, CancellationToken.None);
        }
        var errTask = p.StandardError.ReadToEndAsync(CancellationToken.None);
        try
        {
            string? line;
            while ((line = await p.StandardOutput.ReadLineAsync(ct)) is not null)
                yield return HashcatTool.DecodePlain(line);
            // hashcat reports a failure (no compute backend, unreadable file, bad rule) only by its exit
            // code and stderr; without this check the generator would save an empty file as a success.
            await p.WaitForExitAsync(ct);
            if (p.ExitCode != 0) throw new IOException(FailureMessage(p.ExitCode, await errTask));
        }
        finally
        {
            if (!p.HasExited) try { p.Kill(true); } catch (InvalidOperationException) { }
            await pump;
            DebugLog.ProcessText(logId, "stderr", await errTask);
        }
    }

    internal static string FailureMessage(int exitCode, string stderr)
    {
        var lines = stderr.Split('\n', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
        string? reason = lines.FirstOrDefault(l => l.StartsWith("ATTENTION!", StringComparison.Ordinal)) is { } attention
            ? attention["ATTENTION!".Length..].Trim()
            : lines.FirstOrDefault(l => !l.StartsWith('*'));
        string text = $"hashcat could not produce the candidates (exit code {exitCode})" + (reason is null ? "." : ": " + reason);
        if (stderr.Contains("No OpenCL, HIP or CUDA compatible platform", StringComparison.Ordinal))
            text += " hashcat needs a GPU driver or the CPU runtime even to list candidates: see Tools > Dependencies.";
        return text;
    }

    /// <summary>Writes all candidates of the steps to a text file. Returns the number of lines.</summary>
    public static async Task<long> WriteDictionaryAsync(IEnumerable<PreparedAttack> steps, HashcatTool tool, string path, Encoding enc,
        IProgress<long>? progress, CancellationToken ct)
    {
        long n = 0;
        await using var w = new StreamWriter(path, false, enc, 1 << 20) { NewLine = "\r\n" };
        foreach (var s in steps)
            await foreach (var c in CandidatesAsync(s, tool, ct))
            {
                await w.WriteLineAsync(c);
                if ((++n & 0xffff) == 0) progress?.Report(n);
            }
        progress?.Report(n);
        return n;
    }

    /// <summary>
    /// Writes a WPA PMK table: PMK = PBKDF2-HMAC-SHA1(password, SSID, 4096, 32) for every candidate
    /// (8-63 characters, the WPA passphrase range). Computed in parallel batches, written in order.
    /// </summary>
    public static async Task<long> WritePmkTableAsync(IEnumerable<PreparedAttack> steps, HashcatTool tool, string path, string ssid,
        int threads, IProgress<long>? progress, CancellationToken ct)
    {
        long n = 0;
        var ssidBytes = Encoding.UTF8.GetBytes(ssid);
        await using var w = new StreamWriter(path, false, new UTF8Encoding(false), 1 << 20) { NewLine = "\n" };
        await w.WriteLineAsync(PmkTable.Header + Convert.ToHexString(ssidBytes).ToLowerInvariant());
        var batch = new List<string>(8192);
        var pmks = new string[8192];
        var opts = new ParallelOptions { MaxDegreeOfParallelism = Math.Max(1, threads), CancellationToken = ct };

        async Task Flush()
        {
            Parallel.For(0, batch.Count, opts, i =>
            {
                var pmk = Rfc2898DeriveBytes.Pbkdf2(Encoding.UTF8.GetBytes(batch[i]), ssidBytes, 4096, HashAlgorithmName.SHA1, 32);
                pmks[i] = Convert.ToHexString(pmk).ToLowerInvariant();
            });
            for (int i = 0; i < batch.Count; i++) await w.WriteLineAsync(pmks[i] + ":" + batch[i]);
            n += batch.Count;
            batch.Clear();
            progress?.Report(n);
        }

        foreach (var s in steps)
            await foreach (var c in CandidatesAsync(s, tool, ct))
            {
                int bytes = Encoding.UTF8.GetByteCount(c);
                if (bytes is < 8 or > 63) continue;
                batch.Add(c);
                if (batch.Count == pmks.Length) await Flush();
            }
        if (batch.Count > 0) await Flush();
        return n;
    }
}

/// <summary>A precomputed PMK table written by the WPA-PMK Generator.</summary>
public sealed class PmkTable
{
    public const string Header = "#RecoverKit-PMK ssid=";

    public required string Path { get; init; }
    public required byte[] Ssid { get; init; }

    /// <summary>Reads the header; null when the file is not a PMK table.</summary>
    public static PmkTable? TryOpen(string? path)
    {
        if (string.IsNullOrEmpty(path) || !File.Exists(path)) return null;
        try
        {
            using var r = new StreamReader(path);
            var first = r.ReadLine();
            if (first is null || !first.StartsWith(Header, StringComparison.Ordinal)) return null;
            return new PmkTable { Path = path, Ssid = Convert.FromHexString(first[Header.Length..].Trim()) };
        }
        catch (Exception ex) when (ex is IOException or FormatException or UnauthorizedAccessException) { return null; }
    }

    /// <summary>Writes the bare PMKs (hashcat -m 22001 wordlist).</summary>
    public long WritePmkWordlist(string dest)
    {
        long n = 0;
        using var w = new StreamWriter(dest, false, new UTF8Encoding(false)) { NewLine = "\n" };
        foreach (var line in File.ReadLines(Path).Skip(1))
        {
            int c = line.IndexOf(':');
            if (c == 64) { w.WriteLine(line[..64]); n++; }
        }
        return n;
    }

    /// <summary>The password whose PMK is <paramref name="pmkHex"/>, or null.</summary>
    public string? PasswordFor(string pmkHex)
    {
        foreach (var line in File.ReadLines(Path).Skip(1))
            if (line.Length > 65 && line[64] == ':' && line.AsSpan(0, 64).Equals(pmkHex, StringComparison.OrdinalIgnoreCase))
                return line[65..];
        return null;
    }
}
