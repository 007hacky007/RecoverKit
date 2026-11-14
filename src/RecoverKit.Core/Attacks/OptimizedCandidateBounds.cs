using System.Text;
using RecoverKit.Core.Native;

namespace RecoverKit.Core.Attacks;

/// <summary>Conservative byte bounds for file-backed hashcat candidates.</summary>
internal static class OptimizedCandidateBounds
{
    public static Task<int?> MaximumAsync(PreparedAttack attack, CancellationToken ct = default, string? workingDirectory = null, Action<long, long>? progress = null)
        => Task.Run(() => Maximum(attack, workingDirectory ?? Environment.CurrentDirectory, progress, ct), ct);

    private static int? Maximum(PreparedAttack attack, string workingDirectory, Action<long, long>? progress, CancellationToken ct)
    {
        if (attack.Stdin is not null) return null;
        var files = new List<string>();
        var rules = new List<string>();
        var maskArgs = new List<string> { "-a", "3" };
        int mode = -1;
        for (int i = 0; i < attack.Args.Count; i++)
        {
            string arg = attack.Args[i];
            if (arg == "-a")
            {
                if (++i >= attack.Args.Count || !int.TryParse(attack.Args[i], out mode)) return null;
            }
            else if (arg == "-r")
            {
                if (++i >= attack.Args.Count) return null;
                rules.Add(attack.Args[i]);
            }
            else if (arg is "-i" or "--increment" or "--hex-charset") maskArgs.Add(arg);
            else if (arg is "--increment-min" or "--increment-max"
                     || arg.Length == 2 && arg[0] == '-' && arg[1] is >= '1' and <= '8')
            {
                if (++i >= attack.Args.Count) return null;
                maskArgs.AddRange([arg, attack.Args[i]]);
            }
            else if (arg.StartsWith('-')) return null;
            else files.Add(arg);
        }
        if (mode is not (0 or 1 or 6 or 7) || files.Count != (mode == 0 ? 1 : 2)) return null;
        if ((mode != 0 && rules.Count > 0) || (mode is 0 or 1 && maskArgs.Count != 2)) return null;

        try
        {
            int? length;
            if (mode is 6 or 7)
            {
                string maskText = files[mode == 6 ? 1 : 0];
                if (File.Exists(Path.GetFullPath(maskText, workingDirectory))) return null;
                maskArgs.Add(maskText);
                var mask = MaskSpace.FromHashcatArgs(maskArgs);
                if (mask is null) return null;
                length = checked(LongestWord(Path.GetFullPath(files[mode == 6 ? 0 : 1], workingDirectory), progress, ct) + mask.MaxLength);
            }
            else
            {
                length = LongestWord(Path.GetFullPath(files[0], workingDirectory), progress, ct);
                if (mode == 1) length = checked(length + LongestWord(Path.GetFullPath(files[1], workingDirectory), progress, ct));
            }
            foreach (string rule in rules)
            {
                if (length is null) return null;
                length = RuleMaximum(Path.GetFullPath(rule, workingDirectory), length.Value, ct);
            }
            return length;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or OverflowException or ArgumentException)
        { return null; }
    }

    private static int? LongestWord(string path, Action<long, long>? progress, CancellationToken ct)
        => WordlistLengthCache.Analyze(path, progress, ct)?.Maximum;

    internal static int? MaximumWithRules(IEnumerable<string> rules, int input, CancellationToken ct = default)
    {
        try
        {
            int? maximum = input;
            foreach (string rule in rules)
            {
                if (maximum is null) return null;
                maximum = RuleMaximum(rule, maximum.Value, ct);
            }
            return maximum;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or OverflowException or ArgumentException)
        { return null; }
    }

    internal static int? SafeInputLength(IReadOnlyList<string> rules, int limit, CancellationToken ct = default)
    {
        if (MaximumWithRules(rules, 0, ct) is not { } minimum) return null;
        if (minimum > limit) return -1;
        int low = 0, high = limit;
        while (low < high)
        {
            int middle = low + (high - low + 1) / 2;
            if (MaximumWithRules(rules, middle, ct) is not { } maximum) return null;
            if (maximum <= limit) low = middle;
            else high = middle - 1;
        }
        return low;
    }

    private static int? RuleMaximum(string path, int input, CancellationToken ct)
    {
        // Memory rules and unfamiliar syntax stay on pure; large rule files should not delay startup.
        var info = new FileInfo(path);
        long size = info.Length;
        DateTime modified = info.LastWriteTimeUtc;
        if (size > 1024 * 1024) return null;
        int maximum = input;
        foreach (string raw in Encoding.Latin1.GetString(File.ReadAllBytes(path)).Split('\n'))
        {
            ct.ThrowIfCancellationRequested();
            string line = raw.TrimEnd('\r');
            if (line.Length == 0 || line[0] == '#') continue;
            // Hex-escaped operands must not be reinterpreted as subsequent rule operations.
            if (line.Contains('\\')) return null;
            int length = input;
            for (int i = 0; i < line.Length; i++)
            {
                char op = line[i];
                int parameters;
                switch (op)
                {
                    case ' ': case '\t': case ':': case 'l': case 'u': case 'c': case 'C': case 't':
                    case 'r': case '{': case '}': case '[': case ']': case 'k': case 'K': case 'E':
                        parameters = 0; break;
                    case 'T': case 'D': case '+': case '-': case '.': case ',': case 'L': case 'R':
                        parameters = 1; break;
                    case 'o': case 's': case '*': case 'O':
                        parameters = 2; break;
                    case '\'':
                        if (i + 1 >= line.Length || Number(line[i + 1]) < 0) return null;
                        length = Math.Min(length, Number(line[i + 1])); parameters = 1; break;
                    case 'x':
                        if (i + 2 >= line.Length || Number(line[i + 1]) < 0 || Number(line[i + 2]) < 0) return null;
                        // An out-of-range extraction leaves the word unchanged below start + count.
                        length = Math.Min(length, Number(line[i + 1]) + Number(line[i + 2])); parameters = 2; break;
                    case '$': case '^':
                        length = checked(length + 1); parameters = 1; break;
                    case 'i':
                        length = checked(length + 1); parameters = 2; break;
                    case 'd': case 'f': case 'q':
                        length = checked(length * 2); parameters = 0; break;
                    case 'p': case 'z': case 'Z': case 'y': case 'Y':
                        if (i + 1 >= line.Length) return null;
                        int count = Number(line[i + 1]);
                        if (count < 0) return null;
                        length = op == 'p' ? checked(length * (count + 1)) : checked(length + count);
                        parameters = 1; break;
                    default: return null;
                }
                if (i + parameters >= line.Length) return null;
                i += parameters;
                // Earlier bounds still count when a later operation caps the length.
                maximum = Math.Max(maximum, length);
            }
        }
        info.Refresh();
        return info.Length == size && info.LastWriteTimeUtc == modified ? maximum : null;
    }

    private static int Number(char value) => value is >= '0' and <= '9' ? value - '0'
        : value is >= 'A' and <= 'Z' ? value - 'A' + 10 : -1;
}
