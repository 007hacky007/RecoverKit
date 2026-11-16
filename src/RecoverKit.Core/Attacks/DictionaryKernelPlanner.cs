using System.Security.Cryptography;
using RecoverKit.Core.Diagnostics;
using RecoverKit.Core.Formats;
using RecoverKit.Core.Hashcat;

namespace RecoverKit.Core.Attacks;

/// <summary>A saved ordinary attack step, including the inputs needed to reproduce its dictionary.</summary>
public sealed class DictionaryKernelPass
{
    public bool? Optimized { get; set; }
    public List<int>? Modes { get; set; }
    public int Pass { get; set; }
    public List<string>? Arguments { get; set; }
    public long Words { get; set; }
    public long RuleCount { get; set; } = 1;
    public DictionaryFileStamp? Source { get; set; }
    public List<DictionaryFileStamp> Rules { get; set; } = [];
    public int Threshold { get; set; }
    public string? TailPath { get; set; }
    public string? TailHash { get; set; }
    public bool RuleExpanded { get; set; }
    public bool StreamRules { get; set; }
    public long SelectedWords { get; set; }
    public string? RuleInputPath { get; set; }
    public string? RuleInputHash { get; set; }
    public bool ManagedWords { get; set; }
    public int InputMinimum { get; set; }
    public int InputMaximum { get; set; }
    public int Minimum { get; set; }
}

internal static class DictionaryKernelPlanner
{
    public static async Task PrepareSessionAsync(SessionState state, HashTarget target, HashcatTool tool, Settings settings,
        IReadOnlyList<BackendDevice>? devices, PlannerContext context, Action<string>? log, CancellationToken ct)
    {
        if (state.DictionaryPlanPending)
        {
            var steps = new List<AttackSpec>();
            PerformanceProfile? profile = null;
            if (state.Steps.Any(s => s.Kind == AttackKind.Dictionary) && state.Modes.Count == 1)
            {
                try
                {
                    profile = PerformanceProfiles.Load();
                    PerformanceProfiles.Invalidate(profile, PerformanceProfiles.CpuFingerprint, PerformanceProfiles.GpuFingerprint(tool, devices ?? []));
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                { log?.Invoke("Performance profile is unavailable; using preferences."); }
            }
            for (int i = 0; i < state.Steps.Count; i++)
            {
                ct.ThrowIfCancellationRequested();
                var spec = state.Steps[i];
                if (spec.Kind != AttackKind.Dictionary || state.Modes.Count == 0)
                { steps.Add(spec); continue; }
                int mode = state.Modes[0];
                var effective = profile is null ? settings : ProfileSettings.ForAttack(settings, profile, devices ?? [], mode, 0, target.HashLines, maskAttack: false);
                if (!string.IsNullOrWhiteSpace(effective.ExtraArguments))
                { steps.Add(spec); continue; }
                PreparedAttack attack;
                try { attack = AttackPlanner.Prepare(spec, target, context, _ => 0); }
                catch (AttackPlanException) { steps.Add(spec); continue; }
                bool managedRules = attack.Stdin is not null && attack.Args.Count >= 4
                    && attack.Args[0] == "-a" && attack.Args[1] == "0" && attack.Args[2] == "-r";
                if (managedRules)
                {
                    var converted = new PreparedAttack { Description = attack.Description, Stdin = attack.Stdin };
                    converted.Args.AddRange(["-a", "0", AttackPlanner.ResolveDictionary(spec.Dictionaries[0], context)!]);
                    converted.Args.AddRange(attack.Args.Skip(2));
                    attack = converted;
                }
                if (attack.Stdin is not null && !managedRules || attack.Args.Count < 3 || attack.Args[0] != "-a" || attack.Args[1] != "0")
                { steps.Add(spec); continue; }
                var infos = new List<HashModeInfo>();
                foreach (int candidateMode in state.Modes)
                    if (await tool.ModeInfoAsync(candidateMode, 0, ct) is { } candidateInfo) infos.Add(candidateInfo);
                var info = infos.FirstOrDefault();
                string tail = Path.Combine(settings.SessionsDir, $"{state.Key}.dictionary-{i}.txt");
                int firstPass = steps.Count;
                var rescued = new List<AttackSpec>();
                foreach (var group in infos.GroupBy(info => (info.PasswordLenMin, info.PasswordLenMax)))
                {
                    var bounds = group.First();
                    if (await RuleLengthPassAsync(spec, attack, bounds, tool, tail + $".rules-{bounds.Mode}", log, ct,
                        HashcatRunner.DeviceArguments(effective, devices)) is not { } extra) continue;
                    extra.DictionaryKernel!.Modes = group.Select(info => info.Mode).ToList();
                    rescued.Add(extra);
                }
                void AddRescued()
                {
                    if (rescued.Count == 0) return;
                    var rescuePass = rescued[0].DictionaryKernel!;
                    // Validate the original pass too, before it can advance the saved session.
                    foreach (var step in steps.Skip(firstPass).Where(s => s.DictionaryKernel?.Source is null))
                    {
                        step.DictionaryKernel ??= new DictionaryKernelPass();
                        step.DictionaryKernel.Source = rescuePass.Source;
                        step.DictionaryKernel.Rules = rescuePass.Rules;
                    }
                    steps.AddRange(rescued);
                }
                if (managedRules || state.Modes.Count != 1 || info is not { HasOptimizedKernel: true, OptimizedPasswordLenMax: > 0 }
                    || !effective.OptimizedKernels || effective.PerformanceChoice?.Optimized == false || effective.GpuPerformanceChoice?.Optimized == false
                    || !RecoverySession.OptimizedDictionaryBackendAllowed(mode, attack, effective, devices, OperatingSystem.IsMacOS()))
                { steps.Add(spec.Clone()); AddRescued(); continue; }
                var (pure, optimized) = Rates(mode, effective);
                double hybrid = 0;
                if (Native.HybridRunner.Plan(mode, target.HashLines, attack, effective, devices, target.VolumeCredentials, target.ZipPartial) is { Dictionary: not null } plan)
                    hybrid = pure + (effective.CpuSpeedByMode.TryGetValue(mode, out var cpu) && cpu > 0 ? cpu
                        : plan.Kernel.SpeedHint * Native.HybridRunner.CpuThreads(effective, devices, hashcatRunning: true));
                steps.AddRange(await PlanAsync(spec, attack, info.OptimizedPasswordLenMax.Value, pure, optimized, tail, log, ct, hybridRate: hybrid));
                AddRescued();
            }
            state.Steps = steps;
            state.DictionaryPlanPending = false;
            state.Save(settings);
        }

    }

    public static async Task PreparePassAsync(DictionaryKernelPass? pass, Action<string>? log, CancellationToken ct, string? extraArguments = null,
        HashcatTool? tool = null, IReadOnlyList<string>? deviceArguments = null)
    {
        if (pass?.Source is null) return;
        if (!string.IsNullOrWhiteSpace(extraArguments))
            throw new InvalidDataException("Extra hashcat arguments changed. Start a new attack instead of resuming these saved dictionary passes.");
        ValidateInputs(pass);
        if (pass.RuleExpanded)
        {
            await RuleRescue.PrepareAsync(pass, tool, log, ct, deviceArguments);
            return;
        }
        if (pass.TailPath is { } tail && (!File.Exists(tail) || await HashAsync(tail, ct) != pass.TailHash))
        {
            log?.Invoke("Rebuilding the saved long-word dictionary ...");
            await Task.Run(() => WriteTail(pass, ct), ct);
            if (await HashAsync(tail, ct) != pass.TailHash) throw new InvalidDataException("The saved long-word dictionary could not be rebuilt identically.");
        }
    }

    internal static Task<AttackSpec?> RuleLengthPassAsync(AttackSpec spec, PreparedAttack attack, HashModeInfo info,
        HashcatTool tool, string tailPath, Action<string>? log, CancellationToken ct, IReadOnlyList<string>? deviceArguments = null)
        => RuleRescue.PlanAsync(spec, attack, info, tool, tailPath, log, ct, deviceArguments);

    internal static (double Pure, double Optimized) Rates(int mode, Settings settings)
    {
        double ratio = mode == 10700 ? 1.14 : mode == 11600 ? 2.0 : 1.9;
        double measured = settings.GpuPerformanceChoice?.Speed ?? 0;
        if (measured <= 0) measured = settings.GpuSpeedByMode.GetValueOrDefault(mode);
        if (measured <= 0) measured = settings.SpeedByMode.GetValueOrDefault(mode);
        if (measured <= 0) measured = mode == 11600 ? 129048 : mode == 10700 ? 11226 : 14962;
        return settings.GpuPerformanceChoice?.Optimized == false ? (measured, measured * ratio) : (measured / ratio, measured);
    }

    internal static async Task<IReadOnlyList<AttackSpec>> PlanAsync(AttackSpec spec, PreparedAttack attack, int limit,
        double pureRate, double optimizedRate, string tailPath, Action<string>? log = null, CancellationToken ct = default,
        string? cacheDirectory = null, double hybridRate = 0)
    {
        AttackSpec Pure()
        {
            var copy = spec.Clone();
            copy.DictionaryKernel = new DictionaryKernelPass { Optimized = false };
            return copy;
        }
        var rulePaths = new List<string>();
        for (int i = 3; i < attack.Args.Count; i += 2)
        {
            if (attack.Args[i] != "-r" || i + 1 >= attack.Args.Count) return [Pure()];
            rulePaths.Add(attack.Args[i + 1]);
        }
        var stamps = rulePaths.Select(DictionaryFileStamp.Capture).ToList();
        long ruleCount;
        try { ruleCount = rulePaths.Aggregate(1L, (n, p) => checked(n * Wordlists.CountRules(p))); }
        catch (OverflowException) { return [Pure()]; }
        int? threshold = OptimizedCandidateBounds.SafeInputLength(rulePaths, limit, ct);
        if (threshold is null || threshold < 0) return [Pure()];
        string source = attack.Args[2];
        // Scan only when its estimated cost is under 5% of a pure attack, rather than imposing a deadline.
        bool scanAllowed = ScanWorthwhile(source, pureRate, ruleCount);
        log?.Invoke("Checking word lengths ...");
        var info = await WordlistLengthCache.AnalyzeAsync(source,
            (done, total) => log?.Invoke($"Checking word lengths ... {(total > 0 ? 100.0 * done / total : 100):F0}%"), ct, cacheDirectory, allowScan: scanAllowed);
        if (info is null) return [Pure()];
        if (stamps.Any(s => !s.Matches())) throw new InvalidDataException("A rules file changed while its length bounds were checked.");
        long longWords = info.LongerThan(threshold.Value);
        double pureSeconds = info.Words * (double)ruleCount / pureRate;
        double splitSeconds = info.Words * (double)ruleCount / optimizedRate + longWords * (double)ruleCount / pureRate;
        // The CPU engine can join only the pure kernel (the optimized one numbers words differently),
        // so the optimized passes must also beat hashcat's pure kernel plus the CPU.
        double hybridSeconds = hybridRate > 0 ? info.Words * (double)ruleCount / hybridRate : double.PositiveInfinity;
        bool split = longWords > 0 && splitSeconds < pureSeconds * 0.95 && splitSeconds < hybridSeconds;
        bool optimizedOnly = longWords == 0 && splitSeconds < hybridSeconds;
        DictionaryKernelPass Pass(bool optimized, int number, long words) => new()
        {
            Optimized = optimized, Pass = number, Arguments = [.. attack.Args], Words = words, RuleCount = ruleCount,
            Source = info.Source, Rules = stamps, Threshold = threshold.Value,
            TailPath = split ? tailPath : null,
        };
        var first = spec.Clone();
        first.DictionaryKernel = Pass(split || optimizedOnly, split || optimizedOnly ? 1 : 0, info.Words);
        if (!split) return [first];
        log?.Invoke($"Two dictionary passes: estimated {splitSeconds:F1}s instead of {pureSeconds:F1}s; {longWords:N0} of {info.Words:N0} words need the pure pass.");
        await Task.Run(() => WriteTail(first.DictionaryKernel, ct), ct);
        using (var tail = File.OpenRead(tailPath))
        {
            var header = new byte[6];
            int length = tail.Read(header);
            // A new first word must not turn a plain dictionary into a container or change its encoding.
            var start = header.AsSpan(0, length);
            if (WordlistLengthCache.IsCompressed(start) || start.StartsWith(new byte[] { 0xef, 0xbb, 0xbf })
                || start.StartsWith(new byte[] { 0xff, 0xfe }) || start.StartsWith(new byte[] { 0xfe, 0xff }))
            {
                tail.Dispose();
                File.Delete(tailPath);
                return [Pure()];
            }
        }
        first.DictionaryKernel.TailHash = await HashAsync(tailPath, ct);
        var second = spec.Clone();
        second.DictionaryKernel = Pass(false, 2, longWords);
        second.DictionaryKernel.TailHash = first.DictionaryKernel.TailHash;
        second.DictionaryKernel.Arguments![2] = tailPath;
        return [first, second];
    }

    private static bool ScanWorthwhile(string source, double pureRate, long rules)
    {
        using var file = File.OpenRead(source);
        if (file.Length < 1024 * 1024) return true;
        var sample = new byte[65536];
        int n = file.Read(sample);
        double words = n > 0 ? Math.Max(1, sample.AsSpan(0, n).Count((byte)'\n')) * (double)file.Length / n : 0;
        return file.Length / (200.0 * 1024 * 1024) < words * rules / pureRate * 0.05;
    }

    internal static void ValidateInputs(DictionaryKernelPass pass)
    {
        if (pass.Source?.Matches() != true || pass.Rules.Any(s => !s.Matches()))
            throw new InvalidDataException("A dictionary or rules file changed. Start a new attack instead of resuming these saved dictionary passes.");
    }

    internal static async Task<string> HashAsync(string path, CancellationToken ct)
    {
        using var file = File.OpenRead(path);
        return Convert.ToHexString(await SHA256.HashDataAsync(file, ct));
    }

    private static void WriteTail(DictionaryKernelPass pass, CancellationToken ct)
    {
        ValidateInputs(pass);
        string temporary = pass.TailPath + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            using (var input = File.OpenRead(pass.Source!.Path))
            using (var output = File.Create(temporary))
            using (var pending = new MemoryStream())
            {
                var buffer = new byte[65536];
                bool writing = false;
                void Finish()
                {
                    var bytes = pending.GetBuffer().AsSpan(0, (int)pending.Length);
                    bool longer = writing || bytes.Length - (bytes.Length > 0 && bytes[^1] == '\r' ? 1 : 0) > pass.Threshold;
                    if (longer)
                    {
                        if (!writing) output.Write(bytes);
                        output.WriteByte((byte)'\n');
                    }
                    pending.SetLength(0);
                    writing = false;
                }
                int n;
                while ((n = input.Read(buffer)) > 0)
                {
                    ct.ThrowIfCancellationRequested();
                    var remaining = buffer.AsSpan(0, n);
                    while (!remaining.IsEmpty)
                    {
                        int newline = remaining.IndexOf((byte)'\n');
                        int count = newline < 0 ? remaining.Length : newline;
                        var part = remaining[..count];
                        if (!writing && pending.Length + count > pass.Threshold + 1)
                        {
                            output.Write(pending.GetBuffer().AsSpan(0, (int)pending.Length));
                            pending.SetLength(0);
                            writing = true;
                        }
                        if (writing) output.Write(part);
                        else pending.Write(part);
                        if (newline < 0) break;
                        Finish();
                        remaining = remaining[(newline + 1)..];
                    }
                }
                if (writing || pending.Length > 0) Finish();
                ValidateInputs(pass);
            }
            File.Move(temporary, pass.TailPath!, true);
        }
        finally { if (File.Exists(temporary)) File.Delete(temporary); }
    }

    public static void Cleanup(Settings settings, string key)
    {
        try
        {
            foreach (string file in Directory.EnumerateFiles(settings.SessionsDir, key + ".dictionary-*"))
                try { File.Delete(file); } catch (IOException) { }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
    }
}
