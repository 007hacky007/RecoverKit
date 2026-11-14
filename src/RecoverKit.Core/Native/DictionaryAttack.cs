using System.Diagnostics;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using RecoverKit.Core.Hashcat;

namespace RecoverKit.Core.Native;

/// <summary>A file dictionary in hashcat's base-word numbering; rules remain hashcat's responsibility.</summary>
internal sealed class DictionaryAttack(IReadOnlyList<string> args)
{
    internal IReadOnlyList<string> Args { get; } = args.ToArray();
    internal long BaseCount { get; set; }
    internal long AmplifierCount { get; set; } = 1;
    internal string? Fingerprint { get; private set; }
    internal Func<long, long, CancellationToken, Task<List<byte[]>>> ReadCandidates { get; set; } = null!;
    internal const int MaxBatchCandidates = 65536;

    internal static DictionaryAttack? Parse(IReadOnlyList<string> args)
    {
        bool straight = false;
        int words = 0;
        for (int i = 0; i < args.Count; i++)
        {
            if (args[i] == "-a" && i + 1 < args.Count && args[++i] == "0") straight = true;
            else if (args[i] is "-r" or "--rules-file" && i + 1 < args.Count) i++;
            else if (args[i].StartsWith('-') || ++words > 1) return null;
        }
        return straight && words == 1 ? new DictionaryAttack(args) : null;
    }

    internal async Task<bool> PrepareAsync(HashcatTool tool, int mode, CancellationToken ct)
    {
        BaseCount = await tool.KeyspaceAsync(mode, Args, ct) ?? 0;
        var (code, output, _) = await tool.RunAsync(["-m", mode.ToString(CultureInfo.InvariantCulture), "--total-candidates", "--quiet", .. Args], TimeSpan.FromMinutes(1), ct: ct);
        if (code != 0 || BaseCount <= 0 || !long.TryParse(output.Trim(), out long total)
            || total <= 0 || total % BaseCount != 0) return false;
        AmplifierCount = total / BaseCount;
        if (AmplifierCount > MaxBatchCandidates) return false;
        using var fingerprint = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        foreach (string arg in Args) fingerprint.AppendData(Encoding.UTF8.GetBytes(arg + "\0"));
        for (int i = 0; i < Args.Count; i++)
        {
            if (Args[i] == "-a") { i++; continue; }
            if (Args[i] is "-r" or "--rules-file") i++;
            await using var file = File.OpenRead(Args[i]);
            fingerprint.AppendData(await SHA256.HashDataAsync(file, ct));
        }
        Fingerprint = Convert.ToHexString(fingerprint.GetHashAndReset());
        ReadCandidates = (skip, count, stop) => ReadAsync(tool, skip, count, stop);
        return true;
    }

    private async Task<List<byte[]>> ReadAsync(HashcatTool tool, long skip, long count, CancellationToken ct)
    {
        var psi = tool.StartInfo(["--stdout", "--quiet", .. Args, "--skip", skip.ToString(CultureInfo.InvariantCulture),
            "--limit", count.ToString(CultureInfo.InvariantCulture)]);
        // hashcat autohexes binary candidates; Latin-1 also preserves raw bytes without a UTF-8 roundtrip.
        psi.StandardOutputEncoding = Encoding.Latin1;
        int logId = DebugLog.ProcessStart(psi, "dictionary CPU batch");
        var elapsed = Stopwatch.StartNew();
        using var process = new Process { StartInfo = psi };
        process.Start();
        using var output = new StreamReader(process.StandardOutput.BaseStream, Encoding.Latin1, detectEncodingFromByteOrderMarks: false);
        var error = process.StandardError.ReadToEndAsync(CancellationToken.None);
        var candidates = new List<byte[]>();
        try
        {
            while (await output.ReadLineAsync(ct) is { } line)
            {
                byte[] bytes;
                try
                {
                    bytes = line.StartsWith("$HEX[", StringComparison.Ordinal) && line.EndsWith(']')
                        ? Convert.FromHexString(line.AsSpan(5, line.Length - 6)) : Encoding.Latin1.GetBytes(line);
                }
                // hashcat leaves invalid HEX-looking literals unchanged in stdout.
                catch (FormatException) { bytes = Encoding.Latin1.GetBytes(line); }
                candidates.Add(bytes);
                if (candidates.Count > MaxBatchCandidates) throw new InvalidOperationException("Dictionary batch exceeds the CPU candidate buffer.");
            }
            await process.WaitForExitAsync(ct);
            if (process.ExitCode != 0) throw new IOException("hashcat candidate export failed: " + await error);
            return candidates;
        }
        finally
        {
            if (!process.HasExited) try { process.Kill(true); } catch (InvalidOperationException) { }
            await process.WaitForExitAsync(CancellationToken.None);
            DebugLog.ProcessText(logId, "stderr", await error);
            DebugLog.ProcessExit(logId, process.ExitCode, elapsed.Elapsed);
        }
    }
}
