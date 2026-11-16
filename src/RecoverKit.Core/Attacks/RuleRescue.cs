using System.Diagnostics;
using System.Numerics;
using System.Runtime.InteropServices;
using System.Text;
using RecoverKit.Core.Hashcat;

namespace RecoverKit.Core.Attacks;

internal static class RuleRescue
{
    internal static long MaximumFileCandidates { get; set; } = 50_000_000;
    internal static Func<string, long> AvailableBytes { get; set; } = FreeBytes;

    internal static bool CanMaterialize(long words, long rules, int maxLength, long freeBytes, long maximumCandidates)
    {
        var candidates = (BigInteger)words * rules;
        return candidates > 0 && candidates <= maximumCandidates && freeBytes >= 2 * EstimatedBytes(candidates, maxLength);
    }

    private static BigInteger EstimatedBytes(BigInteger candidates, int maxLength) => candidates * (2L * maxLength + 8);

    private static long FreeBytes(string path)
    {
        try
        {
            string directory = Path.GetDirectoryName(Path.GetFullPath(path))!;
            if (OperatingSystem.IsWindows())
                return GetDiskFreeSpaceEx(directory + Path.DirectorySeparatorChar, out ulong available, out _, out _)
                    ? (long)Math.Min(available, (ulong)long.MaxValue) : 0;
            return new DriveInfo(directory).AvailableFreeSpace;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException) { return 0; }
    }

    [DllImport("kernel32.dll", EntryPoint = "GetDiskFreeSpaceExW", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetDiskFreeSpaceEx(string path, out ulong available, out ulong total, out ulong free);

    internal static async Task<AttackSpec?> PlanAsync(AttackSpec spec, PreparedAttack attack, HashModeInfo info,
        HashcatTool tool, string path, Action<string>? log, CancellationToken ct, IReadOnlyList<string>? deviceArguments = null)
    {
        if (attack.Args.Count <= 3 || info.PasswordLenMin <= 1 && info.PasswordLenMax >= 256) return null;
        if (info.Mode is 22000 or 22001 && PmkTable.TryOpen(attack.Args[2]) is not null) return null;
        var rules = new List<DictionaryFileStamp>();
        for (int i = 3; i < attack.Args.Count; i += 2)
        {
            if (attack.Args[i] != "-r" || i + 1 >= attack.Args.Count) return null;
            rules.Add(DictionaryFileStamp.Capture(attack.Args[i + 1]));
        }
        var pass = new DictionaryKernelPass { Pass = 3, Optimized = false, Source = DictionaryFileStamp.Capture(attack.Args[2]),
            Rules = rules, Minimum = info.PasswordLenMin, Threshold = info.PasswordLenMax, RuleExpanded = true,
            RuleInputPath = path + ".words", ManagedWords = attack.Stdin is not null,
            InputMinimum = spec.SkipShorterThan, InputMaximum = spec.SkipLongerThan };
        if (!pass.ManagedWords && await WordlistLengthCache.AnalyzeAsync(pass.Source.Path, ct: ct, allowScan: false) is { } lengths
            && (lengths.HasAutohexWords == false || info.PasswordLenMin <= 1 && lengths.Lengths.Keys.All(n => n <= 256))
            && lengths.Lengths.Keys.All(n => n == 0 || n > 256 || n >= info.PasswordLenMin && n <= info.PasswordLenMax))
        {
            log?.Invoke("Cached word lengths: no words need the expanded rules pass.");
            return null;
        }
        pass.SelectedWords = await Task.Run(() => SelectWords(pass, tool, log, ct, deviceArguments), ct);
        if (pass.SelectedWords == 0) { File.Delete(pass.RuleInputPath); return null; }
        pass.RuleInputHash = await DictionaryKernelPlanner.HashAsync(pass.RuleInputPath, ct);
        await ChooseOutputAsync(pass, tool, path, log, ct, deviceArguments: deviceArguments);
        if (!pass.StreamRules && pass.Words == 0)
        {
            File.Delete(pass.RuleInputPath);
            File.Delete(pass.TailPath!);
            return null;
        }
        var result = spec.Clone();
        result.DictionaryKernel = pass;
        return result;
    }

    internal static async Task PrepareAsync(DictionaryKernelPass pass, HashcatTool? tool, Action<string>? log, CancellationToken ct,
        IReadOnlyList<string>? deviceArguments = null)
    {
        if (pass.RuleInputPath is null || pass.SelectedWords <= 0 || pass.RuleInputHash is null)
            throw new InvalidDataException("This saved rules pass predates size limits. Start a new attack.");
        if (!File.Exists(pass.RuleInputPath) || await DictionaryKernelPlanner.HashAsync(pass.RuleInputPath, ct) != pass.RuleInputHash)
        {
            long count = await Task.Run(() => SelectWords(pass, tool ?? throw new InvalidDataException("hashcat is needed to rebuild this rules pass."), log, ct, deviceArguments), ct);
            if (count != pass.SelectedWords || await DictionaryKernelPlanner.HashAsync(pass.RuleInputPath, ct) != pass.RuleInputHash)
                throw new InvalidDataException("The saved out-of-range words could not be rebuilt identically.");
        }
        if (!pass.StreamRules && (pass.TailPath is null || pass.TailHash is null))
            throw new InvalidDataException("The saved rules pass is incomplete. Start a new attack.");
        if (!pass.StreamRules && pass.TailPath is { } tail
            && (!File.Exists(tail) || await DictionaryKernelPlanner.HashAsync(tail, ct) != pass.TailHash))
            await ChooseOutputAsync(pass, tool ?? throw new InvalidDataException("hashcat is needed to rebuild this rules pass."), tail, log, ct,
                rebuilding: true, deviceArguments: deviceArguments);
    }

    private static long RuleCount(DictionaryKernelPass pass)
    {
        try { return pass.Rules.Aggregate(1L, (n, rule) => checked(n * Wordlists.CountRules(rule.Path))); }
        catch (OverflowException) { throw new InvalidDataException("The combined rules cannot be numbered safely."); }
    }

    private static async Task ChooseOutputAsync(DictionaryKernelPass pass, HashcatTool tool, string path,
        Action<string>? log, CancellationToken ct, bool rebuilding = false, IReadOnlyList<string>? deviceArguments = null)
    {
        long rules = RuleCount(pass);
        BigInteger upper = (BigInteger)pass.SelectedWords * rules;
        long free = AvailableBytes(path);
        if (!CanMaterialize(pass.SelectedWords, rules, pass.Threshold, free, MaximumFileCandidates))
        {
            log?.Invoke($"Expanded rules pass: stream up to {upper:N0} candidates from {pass.SelectedWords:N0} out-of-range words; a file exceeds the candidate or free-space limit.");
            if (pass.TailPath is { } old && File.Exists(old)) File.Delete(old);
            pass.StreamRules = true;
            pass.TailPath = pass.TailHash = null;
            pass.Words = pass.SelectedWords;
            pass.RuleCount = rules;
            pass.Arguments = ["-a", "0", pass.RuleInputPath!];
            return;
        }
        log?.Invoke($"Expanded rules pass: file for up to {upper:N0} candidates from {pass.SelectedWords:N0} out-of-range words (at most {EstimatedBytes(upper, pass.Threshold):N0} bytes; {free:N0} bytes free).");
        string temporary = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            long words = await Task.Run(() =>
            {
                long count = 0;
                using var writer = new StreamWriter(temporary, false, new UTF8Encoding(false)) { NewLine = "\n" };
                foreach (string candidate in Candidates(pass, tool, ct, log, deviceArguments))
                {
                    if (count >= upper) throw new InvalidDataException("Rule output exceeded its estimated candidate bound.");
                    writer.WriteLine(candidate);
                    count++;
                }
                return count;
            }, ct);
            DictionaryKernelPlanner.ValidateInputs(pass);
            string hash = await DictionaryKernelPlanner.HashAsync(temporary, ct);
            if (rebuilding && hash != pass.TailHash) throw new InvalidDataException("The saved rules file could not be rebuilt identically.");
            File.Move(temporary, path, true);
            pass.TailPath = path;
            pass.TailHash = hash;
            pass.Words = words;
            pass.RuleCount = 1;
            pass.Arguments = ["-a", "0", path];
        }
        finally { if (File.Exists(temporary)) File.Delete(temporary); }
    }

    private static long SelectWords(DictionaryKernelPass pass, HashcatTool tool, Action<string>? log, CancellationToken ct,
        IReadOnlyList<string>? deviceArguments = null)
    {
        DictionaryKernelPlanner.ValidateInputs(pass);
        log?.Invoke($"Selecting dictionary words outside {pass.Minimum}-{pass.Threshold} bytes ...");
        string temporary = pass.RuleInputPath + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            long selected = 0, scanned = 0, bytes = 0, checkedAt = 0;
            long budget = Math.Max(0, AvailableBytes(pass.RuleInputPath!)) / 2;
            var timer = Stopwatch.StartNew();
            using (var writer = new FileStream(temporary, FileMode.Create, FileAccess.Write, FileShare.None, 65536))
            {
                IEnumerable<byte[]> words = pass.ManagedWords
                    ? Wordlists.ReadWords(pass.Source!.Path, pass.InputMinimum, pass.InputMaximum, ct).Select(PasswordConfirmation.PlainBytes)
                    : ReadWords(tool, ["--stdout", "--quiet", "-a", "0", pass.Source!.Path, .. deviceArguments ?? []], ct);
                foreach (byte[] word in words)
                {
                    ct.ThrowIfCancellationRequested();
                    scanned++;
                    if (word.Length <= 256 && (word.Length < pass.Minimum || word.Length > pass.Threshold))
                    {
                        byte[] line = SelectedWordLine(word);
                        if (line.Length > budget - bytes)
                            throw new IOException("Not enough free space to select words for the expanded rules pass. Free some space and start again.");
                        bytes += line.Length;
                        if (bytes - checkedAt >= 1024 * 1024)
                        {
                            writer.Flush();
                            if (AvailableBytes(pass.RuleInputPath!) < bytes + line.Length)
                                throw new IOException("Free space ran low while selecting words for the expanded rules pass. Free some space and start again.");
                            checkedAt = bytes;
                        }
                        writer.Write(line);
                        selected++;
                    }
                    if (timer.ElapsedMilliseconds >= 500)
                    {
                        log?.Invoke($"Checking dictionary words: {scanned:N0} checked, {selected:N0} out of range ...");
                        timer.Restart();
                    }
                }
                writer.Flush();
                if (bytes > 0 && AvailableBytes(pass.RuleInputPath!) < bytes)
                    throw new IOException("Free space ran low while selecting words for the expanded rules pass. Free some space and start again.");
            }
            DictionaryKernelPlanner.ValidateInputs(pass);
            File.Move(temporary, pass.RuleInputPath!, true);
            log?.Invoke($"Selected {selected:N0} of {scanned:N0} words for the expanded rules pass.");
            return selected;
        }
        finally { if (File.Exists(temporary)) File.Delete(temporary); }
    }

    internal static byte[] SelectedWordLine(ReadOnlySpan<byte> word)
    {
        // Preserve literal autohex words, line boundaries, and file signatures hashcat would decode.
        if (word.Contains((byte)0) || word.Contains((byte)'\r') || word.Contains((byte)'\n')
            || word.StartsWith("$HEX["u8) || word.StartsWith(new byte[] { 0xef, 0xbb, 0xbf })
            || word.StartsWith(new byte[] { 0xff, 0xfe }) || word.StartsWith(new byte[] { 0xfe, 0xff }) || WordlistLengthCache.IsCompressed(word))
            return Encoding.ASCII.GetBytes(PasswordConfirmation.HexPlain(word) + "\n");
        byte[] line = new byte[word.Length + 1];
        word.CopyTo(line);
        line[^1] = (byte)'\n';
        return line;
    }

    internal static IEnumerable<string> Candidates(DictionaryKernelPass pass, HashcatTool tool, CancellationToken ct, Action<string>? log = null,
        IReadOnlyList<string>? deviceArguments = null)
    {
        DictionaryKernelPlanner.ValidateInputs(pass);
        var args = new List<string> { "--stdout", "--quiet", "-a", "0", pass.RuleInputPath! };
        foreach (var rule in pass.Rules) args.AddRange(["-r", rule.Path]);
        if (deviceArguments is not null) args.AddRange(deviceArguments);
        foreach (byte[] bytes in ReadWords(tool, args, ct, log))
            if (bytes.Length >= pass.Minimum && bytes.Length <= pass.Threshold)
                yield return PasswordConfirmation.HexPlain(bytes);
        DictionaryKernelPlanner.ValidateInputs(pass);
    }

    private static IEnumerable<byte[]> ReadWords(HashcatTool tool, IReadOnlyList<string> args, CancellationToken ct, Action<string>? log = null)
    {
        var psi = tool.StartInfo(args);
        psi.StandardOutputEncoding = Encoding.Latin1;
        using var process = new Process { StartInfo = psi };
        process.Start();
        using var cancel = ct.Register(() => { try { process.Kill(true); } catch (InvalidOperationException) { } });
        var error = process.StandardError.ReadToEndAsync(CancellationToken.None);
        try
        {
            using var reader = new StreamReader(process.StandardOutput.BaseStream, Encoding.Latin1, detectEncodingFromByteOrderMarks: false);
            var timer = Stopwatch.StartNew();
            long count = 0;
            while (reader.ReadLineAsync(ct).AsTask().GetAwaiter().GetResult() is { } line)
            {
                byte[] bytes;
                try { bytes = line.StartsWith("$HEX[", StringComparison.Ordinal) && line.EndsWith(']')
                    ? Convert.FromHexString(line.AsSpan(5, line.Length - 6)) : Encoding.Latin1.GetBytes(line); }
                catch (FormatException) { bytes = Encoding.Latin1.GetBytes(line); }
                if (++count % 1024 == 0 && timer.ElapsedMilliseconds >= 500)
                {
                    log?.Invoke($"Applying dictionary rules: {count:N0} results checked ...");
                    timer.Restart();
                }
                yield return bytes;
            }
            process.WaitForExitAsync(ct).GetAwaiter().GetResult();
            ct.ThrowIfCancellationRequested();
            if (process.ExitCode != 0) throw new IOException("hashcat rule export failed: " + error.GetAwaiter().GetResult());
        }
        finally
        {
            if (!process.HasExited) try { process.Kill(true); } catch (InvalidOperationException) { }
            process.WaitForExit();
            error.GetAwaiter().GetResult();
        }
    }
}
