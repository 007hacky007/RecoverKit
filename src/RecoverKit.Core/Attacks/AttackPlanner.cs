using System.Numerics;
using System.Text;
using System.Text.RegularExpressions;
using RecoverKit.Core.Attacks.Stay;
using RecoverKit.Core.Formats;
using RecoverKit.Core.Hashcat;

namespace RecoverKit.Core.Attacks;

/// <summary>Where to look for dictionaries and rule files.</summary>
public sealed class PlannerContext
{
    public string? DataPath { get; init; }
    public string? HashcatDir { get; init; }
    public HashcatTool? Hashcat { get; init; }
    public string? DefaultDictionary { get; init; }
}

/// <summary>An attack translated into hashcat arguments, optionally fed from a CPU generator via stdin.</summary>
public sealed class PreparedAttack
{
    public required string Description { get; init; }
    public List<string> Args { get; } = new();
    public Func<IEnumerable<string>>? Stdin { get; set; }
    internal Func<CancellationToken, IEnumerable<string>>? CancellableStdin { get; set; }
    internal bool StdinTotalIsUpperBound { get; set; }
    public BigInteger Keyspace { get; set; }
    public List<string> Notes { get; } = new();
    public bool CanRestore => Stdin is null;
}

public sealed class AttackPlanException(string message) : Exception(message);

public static class AttackPlanner
{
    public static PreparedAttack Prepare(AttackSpec a, HashTarget target, PlannerContext ctx, Func<string, long>? lineCounter = null)
    {
        if (a.DictionaryKernel is { Arguments: { } args } pass)
        {
            string label = pass.Pass == 1 ? "optimized pass" : pass.Pass == 2 ? "pure long-word pass" : pass.RuleExpanded ? "expanded rules pass" : "pure pass";
            var step = a.Clone();
            step.DictionaryKernel = null;
            step.Dictionaries = [args[2], null, null, null];
            step.SkipShorterThan = step.SkipLongerThan = 0;
            step.Rules = pass.Rules.Count == 0 ? RulesPreset.AsIs : RulesPreset.CustomFile;
            step.RulesFile = pass.Rules.FirstOrDefault()?.Path;
            string count = pass.RuleExpanded ? $", {pass.SelectedWords:N0} {(pass.SelectedWords == 1 ? "word" : "words")}" : "";
            var prepared = Dictionary(step, ctx, _ => pass.Words, rawFile: true, description: a.Describe() + $" [{label}{count}]");
            prepared.Args.Clear();
            prepared.Args.AddRange(args);
            prepared.Keyspace = (BigInteger)pass.Words * pass.RuleCount;
            if (pass.StreamRules)
            {
                var tool = ctx.Hashcat ?? throw new AttackPlanException("hashcat is needed for this streamed rules pass.");
                prepared.Args.Clear();
                prepared.Args.AddRange(["-a", "0"]);
                prepared.Stdin = () => RuleRescue.Candidates(pass, tool, CancellationToken.None);
                prepared.CancellableStdin = ct => RuleRescue.Candidates(pass, tool, ct);
                prepared.StdinTotalIsUpperBound = true;
                prepared.Notes.Add("This rules pass is streamed. Its progress total is an upper bound; after a stop it restarts from the beginning without skipping candidates.");
            }
            return prepared;
        }
        lineCounter ??= p => Wordlists.CountLines(p);
        int maxLen = target.MaxPasswordLength ?? 256;
        return a.Kind switch
        {
            AttackKind.BruteForce => BruteForce(a, target, maxLen),
            AttackKind.Mask => Mask(a),
            AttackKind.KeySearch => KeySearch.Prepare(a, target),
            AttackKind.StayZip => StayZipPlanner.Prepare(a, target),
            _ => Dictionary(a, ctx, lineCounter),
        };
    }

    // ---------------------------------------------------------------- brute force

    private static PreparedAttack BruteForce(AttackSpec a, HashTarget t, int maxLen)
    {
        string cs = Charsets.Build(a);
        if (cs.Length == 0) throw new AttackPlanException("Select at least one character set.");
        int min = Math.Max(1, a.MinLength), max = Math.Min(a.MaxLength, maxLen);
        if (a.Mask.Length == 0 && max < min) throw new AttackPlanException("Maximum length is smaller than minimum length.");
        if (a.Mask.Length > 0 && !a.Mask.Contains(a.MaskSymbol)) throw new AttackPlanException($"Mask has no '{a.MaskSymbol}' positions.");

        var p = new PreparedAttack { Description = a.Describe(), Keyspace = Charsets.BruteKeyspace(a) };

        if (!Charsets.IsAscii(cs))
        {
            p.Stdin = () => Generators.BruteForce(cs, min, max, a.Mask, a.MaskSymbol);
            p.Args.AddRange(["-a", "0"]);
            p.Notes.Add("Charset contains national characters: candidates are generated on the CPU as UTF-8 and streamed to hashcat.");
            if (t.Utf16Password) p.Notes.Add("This format hashes UTF-16 passwords; hashcat handles only Latin-1 characters correctly for it.");
            return p;
        }

        p.Args.AddRange(["-a", "3", "--hex-charset", "-1", HexOf(Encoding.ASCII.GetBytes(cs))]);
        if (a.Mask.Length > 0)
        {
            var mask = new StringBuilder();
            foreach (var r in a.Mask.EnumerateRunes())
            {
                if (r.Value == a.MaskSymbol) mask.Append("?1");
                else mask.Append(HexOf(Encoding.UTF8.GetBytes(r.ToString())));
            }
            p.Args.Add(mask.ToString());
        }
        else
        {
            if (min < max) p.Args.AddRange(["-i", "--increment-min", min.ToString(), "--increment-max", max.ToString()]);
            p.Args.Add(string.Concat(Enumerable.Repeat("?1", max)));
        }
        return p;
    }

    private static string HexOf(byte[] b) => Convert.ToHexString(b).ToLowerInvariant();

    // ---------------------------------------------------------------- mask

    private static PreparedAttack Mask(AttackSpec a)
    {
        if (string.IsNullOrWhiteSpace(a.HashcatMask)) throw new AttackPlanException("Enter a mask.");
        var p = new PreparedAttack
        {
            Description = a.Describe(),
            Keyspace = Charsets.MaskKeyspace(a.HashcatMask, a.CustomCharsets, a.Increment, a.MinLength, a.MaxLength),
        };
        p.Args.AddRange(["-a", "3"]);
        for (int i = 0; i < 8; i++)
        {
            var c = a.CustomCharsets[i];
            if (string.IsNullOrEmpty(c)) continue;
            if (!Charsets.IsAscii(c)) p.Notes.Add($"Custom charset ?{i + 1} contains non-ASCII characters; hashcat treats each UTF-8 byte as a separate symbol.");
            p.Args.AddRange([$"-{i + 1}", c]);
        }
        foreach (Match m in Regex.Matches(a.HashcatMask, @"\?([1-8])"))
        {
            int k = m.Groups[1].Value[0] - '1';
            if (string.IsNullOrEmpty(a.CustomCharsets[k])) throw new AttackPlanException($"Mask uses ?{k + 1} but that custom charset is empty.");
        }
        if (a.Increment)
            p.Args.AddRange(["-i", "--increment-min", Math.Max(1, a.MinLength).ToString(), "--increment-max", a.MaxLength.ToString()]);
        p.Args.Add(a.HashcatMask);
        return p;
    }

    // ---------------------------------------------------------------- dictionary

    private static PreparedAttack Dictionary(AttackSpec a, PlannerContext ctx, Func<string, long> lines, bool rawFile = false, string? description = null)
    {
        var dicts = a.Dictionaries.Select(d => ResolveDictionary(d, ctx)).ToList();
        if (dicts[0] is null) throw new AttackPlanException("Select a primary dictionary.");
        foreach (var d in dicts.Where(d => d is not null))
            if (!File.Exists(d)) throw new AttackPlanException($"Dictionary not found: {d}");

        string d1 = dicts[0]!;
        int min = a.SkipShorterThan, max = a.SkipLongerThan;
        bool filter = min > 0 || max > 0;
        bool direct = (rawFile || Wordlists.HashcatCanReadDirectly(d1)) && !filter;
        var p = new PreparedAttack { Description = description ?? a.Describe() };
        long n1 = lines(d1);

        switch (a.Rules)
        {
            case RulesPreset.AsIs:
                p.Keyspace = n1;
                p.Args.AddRange(["-a", "0"]);
                if (direct) p.Args.Add(d1);
                else p.Stdin = () => Wordlists.ReadWords(d1, min, max);
                break;

            case RulesPreset.Simple:
            case RulesPreset.Advanced:
            case RulesPreset.Complex:
            case RulesPreset.CustomFile:
            {
                string rule = ResolveRules(a, ctx);
                p.Keyspace = (BigInteger)n1 * Wordlists.CountRules(rule);
                p.Args.AddRange(["-a", "0"]);
                if (direct) p.Args.Add(d1);
                else p.Stdin = () => Wordlists.ReadWords(d1, min, max);
                p.Args.AddRange(["-r", rule]);
                if (filter) p.Notes.Add("Length limits are applied to dictionary words before rules are applied.");
                break;
            }

            case RulesPreset.TwoWords:
            {
                string d2 = dicts[1] ?? d1;
                p.Keyspace = (BigInteger)n1 * (d2 == d1 ? n1 : lines(d2));
                if (direct && Wordlists.HashcatCanReadDirectly(d2))
                {
                    p.Args.AddRange(["-a", "1", d1, d2]);
                }
                else
                {
                    var list = new List<string> { d1, d2 };
                    p.Args.AddRange(["-a", "0"]);
                    p.Stdin = () => Generators.Combine(list, 2, false, min, max);
                }
                break;
            }

            case RulesPreset.TwoWordsAdvanced:
            case RulesPreset.ThreeWords:
            {
                int words = a.Rules == RulesPreset.ThreeWords ? 3 : 2;
                bool adv = a.Rules == RulesPreset.TwoWordsAdvanced;
                string d2 = dicts[1] ?? d1;
                string d3 = dicts[2] ?? d2;
                BigInteger ks = (BigInteger)n1 * (d2 == d1 ? n1 : lines(d2));
                if (words == 3) ks *= d3 == d1 ? n1 : lines(d3);
                p.Keyspace = ks * Generators.CombineVariants(words, adv);
                var list = new List<string> { d1, d2, d3 };
                p.Args.AddRange(["-a", "0"]);
                p.Stdin = () => Generators.Combine(list, words, adv, min, max);
                if (adv) p.Notes.Add("Word pairs are tried as-is and capitalized, joined with '', ' ', '_', '-' and '.'.");
                break;
            }
        }
        if (p.Stdin is not null && !filter && !Wordlists.HashcatCanReadDirectly(d1))
            p.Notes.Add($"Dictionary is {Wordlists.Detect(d1)}; it is converted to UTF-8 on the fly.");
        return p;
    }

    public static string? ResolveDictionary(string? d, PlannerContext ctx)
    {
        if (string.IsNullOrWhiteSpace(d)) return null;
        if (BuiltinDictionaries.IsBuiltin(d)) return BuiltinDictionaries.Materialize(d);
        if (!d.StartsWith('*')) return Path.GetFullPath(d); // hashcat runs in its own working directory
        string name = d[1..];
        if (name is "" or "default")
        {
            if (!string.IsNullOrEmpty(ctx.DefaultDictionary)) return Path.GetFullPath(ctx.DefaultDictionary);
            if (ctx.DataPath is not null && Directory.Exists(ctx.DataPath))
            {
                var first = Directory.EnumerateFiles(ctx.DataPath)
                    .Where(f => f.EndsWith(".txt", StringComparison.OrdinalIgnoreCase) || f.EndsWith(".dic", StringComparison.OrdinalIgnoreCase))
                    .OrderBy(f => f, StringComparer.OrdinalIgnoreCase).FirstOrDefault();
                if (first is not null) return Path.GetFullPath(first);
            }
            throw new AttackPlanException("No default dictionary configured (Options > Preferences > Files and Paths).");
        }
        foreach (var dir in new[] { ctx.DataPath }.Where(x => x is not null))
            foreach (var cand in new[] { name, name + ".txt", name + ".dic" })
            {
                var f = Path.Combine(dir!, cand);
                if (File.Exists(f)) return Path.GetFullPath(f);
            }
        throw new AttackPlanException($"Dictionary '{name}' not found in the data folder.");
    }

    private static readonly IReadOnlyDictionary<RulesPreset, string[]> RuleFiles = new Dictionary<RulesPreset, string[]>
    {
        [RulesPreset.Simple] = ["best66.rule", "best64.rule"],
        [RulesPreset.Advanced] = ["rockyou-30000.rule", "d3ad0ne.rule"],
        [RulesPreset.Complex] = ["dive.rule", "d3ad0ne.rule"],
    };

    public static string ResolveRules(AttackSpec a, PlannerContext ctx)
    {
        if (a.Rules == RulesPreset.CustomFile)
        {
            if (string.IsNullOrEmpty(a.RulesFile) || !File.Exists(a.RulesFile)) throw new AttackPlanException("Rules file not found.");
            return Path.GetFullPath(a.RulesFile);
        }
        var dirs = new List<string>();
        if (ctx.DataPath is not null) { dirs.Add(ctx.DataPath); dirs.Add(Path.Combine(ctx.DataPath, "rules")); }
        if (ctx.HashcatDir is not null) dirs.Add(Path.Combine(ctx.HashcatDir, "rules"));
        foreach (var name in RuleFiles[a.Rules])
            foreach (var dir in dirs)
            {
                var f = Path.Combine(dir, name);
                if (File.Exists(f)) return Path.GetFullPath(f);
            }
        throw new AttackPlanException($"Rule file for \"{AttackSpec.RulesName(a.Rules)}\" not found ({string.Join(" or ", RuleFiles[a.Rules])}). " +
                                      "It ships in hashcat's rules folder.");
    }
}
