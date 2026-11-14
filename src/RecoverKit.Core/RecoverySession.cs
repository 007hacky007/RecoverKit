using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using RecoverKit.Core.Attacks;
using RecoverKit.Core.Formats;
using RecoverKit.Core.Attacks.Stay;
using RecoverKit.Core.Hashcat;
using RecoverKit.Core.Diagnostics;

namespace RecoverKit.Core;

public enum LogKind { Info, Step, Warning, Error, Success }

public enum SessionOutcome { Found, FoundInCache, NotFound, Stopped, Error, KeyRecovered }

public sealed class SessionResult
{
    public SessionOutcome Outcome { get; init; }
    public List<string> Passwords { get; init; } = new();
    public string? Error { get; init; }
    /// <summary>Key search: the recovered 40-bit RC4 key (hex).</summary>
    public string? Key { get; init; }

    /// <summary>Stay attack: the password-free decrypted copy written next to the archive, when any.</summary>
    public string? DecryptedCopy { get; init; }
}

/// <summary>Saved progress of an interrupted recovery, so it can continue later.</summary>
public sealed class SessionState
{
    public string FilePath { get; set; } = "";
    public string Key { get; set; } = "";
    public List<int> Modes { get; set; } = new();
    public List<AttackSpec> Steps { get; set; } = new();
    public int StepIndex { get; set; }
    public int ModeIndex { get; set; }
    public string HashcatSession { get; set; } = "";
    public bool Restorable { get; set; }
    /// <summary>Kernel choice for the saved step/mode. Null in older sessions, which resume without -O.</summary>
    public bool? UseOptimizedKernel { get; set; }
    public DateTime SavedUtc { get; set; }

    private static readonly JsonSerializerOptions Json = new() { WriteIndented = true, Converters = { new System.Text.Json.Serialization.JsonStringEnumConverter() } };

    public static string KeyFor(HashTarget t)
    {
        string identity = string.Join(',', t.Modes) + "|" + t.HashLines;
        if (t.VolumeCredentials is { } credentials) identity += "|" + credentials.Identity;
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(identity)))[..16].ToLowerInvariant();
    }

    public static string PasswordCacheFor(Settings s, HashTarget t)
        => t.VolumeCredentials is null ? s.PotfilePath : Path.Combine(s.VolumePasswordCacheDir, KeyFor(t) + ".potfile");

    public static string PathFor(Settings s, string key) => Path.Combine(s.SessionsDir, key + ".session.json");

    public static SessionState? Load(Settings s, HashTarget t)
    {
        var p = PathFor(s, KeyFor(t));
        if (!File.Exists(p)) return null;
        try { return JsonSerializer.Deserialize<SessionState>(File.ReadAllText(p), Json); }
        catch (JsonException) { return null; }
    }

    public void Save(Settings s)
    {
        SavedUtc = DateTime.UtcNow;
        File.WriteAllText(PathFor(s, Key), JsonSerializer.Serialize(this, Json));
    }

    public static void Delete(Settings s, string key)
    {
        try { File.Delete(PathFor(s, key)); } catch (IOException) { }
    }
}

/// <summary>Runs a list of attacks against a target with hashcat until the password is found.</summary>
public sealed class RecoverySession(HashcatTool tool, Settings settings)
{
    public event Action<LogKind, string>? Log;
    public event Action<HashcatStatus>? Status;
    /// <summary>GPU temperature guard paused or resumed the attack.</summary>
    public event Action<Hashcat.ThermalEvent>? Thermal;
    /// <summary>(step index, step count, description, estimated candidates).</summary>
    public event Action<int, int, string, BigInteger>? StepStarted;

    public IReadOnlyList<BackendDevice>? Devices { get; set; }

    /// <summary>
    /// Asked before RecoverKit requests administrator rights for the NVIDIA power limit, with the
    /// explanation to show. Without it (or on "without power limit") the attack runs unlimited.
    /// </summary>
    public Func<PowerLimitRequest, Task<ElevationChoice>>? ConfirmElevation { get; set; }

    public PlannerContext PlannerContext => new()
    {
        DataPath = settings.DataPath,
        HashcatDir = tool.Directory,
        DefaultDictionary = settings.DefaultDictionary,
    };

    public async Task<SessionResult> RunAsync(HashTarget target, string filePath, IReadOnlyList<AttackSpec> steps,
        SessionState? resume, CancellationToken ct)
    {
        target.VolumeCredentials?.ValidateUnchanged();
        string key = SessionState.KeyFor(target);
        string potfile = SessionState.PasswordCacheFor(settings, target);
        string hashFile = Path.Combine(settings.SessionsDir, key + ".hash");
        await File.WriteAllTextAsync(hashFile, target.HashLines.Replace("\r\n", "\n").TrimEnd() + "\n", new UTF8Encoding(false), ct);

        if (resume is null && !settings.DontUsePasswordCache)
        {
            foreach (var mode in target.Modes)
            {
                var cached = target.ConfirmPassword is { } confirm
                    ? await ConfirmedCacheAsync(mode, hashFile, potfile, target, confirm)
                    : await tool.ShowAsync(mode, hashFile, potfile, target.VolumeCredentials);
                if (cached.Count > 0) return new SessionResult { Outcome = SessionOutcome.FoundInCache, Passwords = cached };
            }
        }

        var power = await StartPowerLimitAsync(ct);
        if (power.Cancelled) return new SessionResult { Outcome = SessionOutcome.Stopped };
        try { return await RunStepsAsync(target, filePath, resume, key, potfile, hashFile, steps, ct); }
        finally
        {
            if (power.Session is not null)
            {
                power.Session.Dispose();
                Log?.Invoke(LogKind.Info, "GPU power limit restored.");
            }
        }
    }

    /// <summary>
    /// Cached passwords for a target with a confirmation check: what hashcat's --show reports plus the
    /// lines RecoverKit wrote itself (--show gives one plaintext per hash, the last matching line), each
    /// checked again. Passwords cached before the check existed, or by hashcat elsewhere, may be false
    /// positives; they are dropped.
    /// </summary>
    private async Task<List<string>> ConfirmedCacheAsync(int mode, string hashFile, string potfile, HashTarget target, Func<byte[], bool> confirm)
    {
        var (confirmed, rejected) = await ConfirmedCacheAsync(tool, mode, hashFile, potfile, target, confirm);
        if (rejected > 0)
        {
            DebugLog.Info($"Password cache: {rejected} cached password(s) rejected by the confirmation check");
            Log?.Invoke(LogKind.Warning, $"Ignored {rejected} cached password(s) for this archive: they open the attacked file " +
                                         "but not the archive's other encrypted files (false positives).");
        }
        return confirmed;
    }

    internal static async Task<(List<string> Confirmed, int Rejected)> ConfirmedCacheAsync(HashcatTool tool, int mode, string hashFile,
        string potfile, HashTarget target, Func<byte[], bool> confirm)
    {
        var raw = await tool.ShowRawAsync(mode, hashFile, potfile);
        raw.AddRange(PasswordConfirmation.OwnEntries(potfile, target.HashLines.Replace("\r", "").Split('\n')[0]));
        var confirmed = new List<string>();
        int rejected = 0;
        foreach (var plain in raw.Distinct())
        {
            if (confirm(PasswordConfirmation.PlainBytes(plain)))
            {
                string pw = HashcatTool.DecodePlain(plain, target.VolumeCredentials);
                if (!confirmed.Contains(pw)) confirmed.Add(pw);
            }
            else rejected++;
        }
        return (confirmed, rejected);
    }

    /// <summary>Applies the optional NVIDIA power limit for the whole attack, after the user saw why admin rights are needed.</summary>
    private async Task<(PowerLimitSession? Session, bool Cancelled)> StartPowerLimitAsync(CancellationToken ct)
    {
        if (!settings.GpuPowerLimit || !HashcatRunner.UsesGpu(settings, Devices))
            return (null, false);
        var request = NvidiaPower.BuildRequest(settings, await PowerLimiter.QueryAsync());
        if (request is null) return (null, false);
        var choice = ConfirmElevation is null ? ElevationChoice.WithoutPowerLimit : await ConfirmElevation(request);
        if (choice == ElevationChoice.Cancel) return (null, true);
        if (choice == ElevationChoice.WithoutPowerLimit)
        {
            Log?.Invoke(LogKind.Warning, "Running without the GPU power limit.");
            return (null, false);
        }
        var (session, error) = await PowerLimiter.StartAsync(request, ct);
        if (session is null)
        {
            Log?.Invoke(LogKind.Warning, $"GPU power limit not applied ({error}); running without it.");
            return (null, false);
        }
        Log?.Invoke(LogKind.Info, "GPU power limit set: " +
            string.Join(", ", request.Targets.Select(t => $"{PowerLimitRequest.Watts(t.Watts)} for {t.Name}")) + ".");
        return (session, false);
    }

    private async Task<SessionResult> RunStepsAsync(HashTarget target, string filePath, SessionState? resume, string key,
        string potfile, string hashFile, IReadOnlyList<AttackSpec> steps, CancellationToken ct)
    {
        var state = resume ?? new SessionState { FilePath = filePath, Key = key, Modes = target.Modes.ToList(), Steps = steps.ToList() };
        var runner = new HashcatRunner(tool) { KnownDevices = Devices };
        runner.StatusReceived += s => Status?.Invoke(s);
        runner.OutputLine += l => { if (!settings.ReduceOutput) Log?.Invoke(LogKind.Info, l); };
        runner.GuardMessage += m => Log?.Invoke(LogKind.Warning, m);
        runner.Thermal += e => Thermal?.Invoke(e);
        var guard = HashcatRunner.GuardFor(settings, Devices);
        if (guard is not null) LogGuard(guard);
        var native = new Native.NativeRunner();
        native.StatusReceived += s => Status?.Invoke(s);
        native.OutputLine += l => { if (!settings.ReduceOutput) Log?.Invoke(LogKind.Info, l); };
        var hybrid = new Native.HybridRunner
        {
            Devices = Devices,
            GuardEvents = h =>
            {
                h.GuardMessage += m => Log?.Invoke(LogKind.Warning, m);
                h.Thermal += e => Thermal?.Invoke(e);
            },
        };
        hybrid.StatusReceived += s => Status?.Invoke(s);
        hybrid.OutputLine += l => { if (!settings.ReduceOutput) Log?.Invoke(LogKind.Info, l); };
        hybrid.Warning += m => Log?.Invoke(LogKind.Warning, m);

        string? stayKeysHex = null;   // Stay fast key search: recovered ZipCrypto cipher keys (hex)
        string? stayCopy = null;

        int stepsRun = 0, stepsNeedingCpu = 0;
        string? cpuOnlyReason = null;
        for (int si = state.StepIndex; si < state.Steps.Count; si++)
        {
            var spec = state.Steps[si];
            PreparedAttack attack;
            try { attack = AttackPlanner.Prepare(spec, target, PlannerContext); }
            catch (AttackPlanException ex)
            {
                Log?.Invoke(LogKind.Warning, $"Step {si + 1}/{state.Steps.Count} skipped: {ex.Message}");
                continue;
            }

            if (spec.Kind == AttackKind.KeySearch)
            {
                var ks = await KeySearchStepAsync(runner, target, hashFile, key, si, state, attack, resume, ct);
                if (ks is not null) return ks;
                continue;
            }

            if (spec.Kind == AttackKind.StayZip)
            {
                if (!settings.TryStayZipAttack)
                {
                    Log?.Invoke(LogKind.Info, $"Step {si + 1}/{state.Steps.Count} skipped: the fast key search is disabled in Preferences.");
                    continue;
                }
                StepStarted?.Invoke(si, state.Steps.Count, attack.Description, attack.Keyspace);
                Log?.Invoke(LogKind.Step, $"Step {si + 1}/{state.Steps.Count}: {attack.Description} - {attack.Keyspace:N0} candidates");
                state.StepIndex = si;
                state.ModeIndex = 0;
                state.HashcatSession = "";
                state.Restorable = false;

                StayStepOutcome stay;
                try
                {
                    stay = await StayZipStep.RunAsync(target, filePath, settings, (k, m) => Log?.Invoke(k, m), ct);
                }
                catch (OperationCanceledException)
                {
                    state.Save(settings);
                    return new SessionResult { Outcome = SessionOutcome.Stopped, Key = stayKeysHex, DecryptedCopy = stayCopy };
                }

                if (stay.Keys is { } stayKeys)
                {
                    stayKeysHex = StayZipStep.KeysHex(stayKeys);
                    stayCopy = stay.DecryptedCopy;
                }
                continue;   // keys in hand: keep going, the password attacks may still find the actual password
            }

            // A WPA-PMK Generator table used as the dictionary: test its precomputed PMKs (hashcat 22001).
            PmkTable? pmkTable = target.FormatId == "WPAH" && spec.Kind == AttackKind.Dictionary
                ? PmkTable.TryOpen(AttackPlanner.ResolveDictionary(spec.Dictionaries[0], PlannerContext)) : null;
            if (pmkTable is not null)
            {
                var essids = target.HashLines.Replace("\r", "").Split('\n', StringSplitOptions.RemoveEmptyEntries)
                    .Select(l => l.Split('*')).Where(f => f.Length > 5).Select(f => f[5].ToLowerInvariant()).ToHashSet();
                string tableSsid = Convert.ToHexString(pmkTable.Ssid).ToLowerInvariant();
                if (!essids.Contains(tableSsid))
                {
                    Log?.Invoke(LogKind.Warning, $"Step {si + 1}/{state.Steps.Count} skipped: the PMK table was made for SSID \"{System.Text.Encoding.UTF8.GetString(pmkTable.Ssid)}\", not this network.");
                    continue;
                }
                string list = Path.Combine(settings.SessionsDir, key + ".pmklist");
                long count = pmkTable.WritePmkWordlist(list);
                var pa = new PreparedAttack { Description = $"Precomputed PMK table {Path.GetFileName(pmkTable.Path)}", Keyspace = count };
                pa.Args.AddRange(["-a", "0", list]);
                attack = pa;
            }

            int startMode = si == state.StepIndex ? state.ModeIndex : 0;
            for (int mi = startMode; mi < state.Modes.Count; mi++)
            {
                int mode = pmkTable is not null ? 22001 : state.Modes[mi];
                // Apply measured choices to this step only. Preferences and their explicit limits stay intact.
                var runSettings = settings;
                var mask = Native.MaskSpace.FromHashcatArgs(attack.Args);
                int measuredLength = mask?.MaxLength ?? 0;
                if (target.VolumeCredentials is null)
                {
                    try
                    {
                        var profile = resume is null && measuredLength > 0
                            ? await PerformanceCalibration.EnsureAsync(tool, settings, Devices ?? [], mode, measuredLength,
                                (double)attack.Keyspace, message => Log?.Invoke(LogKind.Info, message), ct)
                            : PerformanceProfiles.Load();
                        PerformanceProfiles.Invalidate(profile, PerformanceProfiles.CpuFingerprint, PerformanceProfiles.GpuFingerprint(tool, Devices ?? []));
                        runSettings = ProfileSettings.ForAttack(settings, profile, Devices ?? [], mode, measuredLength, target.HashLines, (double)attack.Keyspace, maskAttack: mask is not null);
                    }
                    catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                    { Log?.Invoke(LogKind.Warning, "Performance profile is unavailable; using preferences."); }
                }
                if (resume is { Restorable: true } && si == resume.StepIndex && mi == resume.ModeIndex)
                    runSettings = ProfileSettings.PreserveResumeEngine(runSettings, mode, settings.SessionsDir, resume.HashcatSession);
                using var cpuSelection = ProfileSettings.CpuSelection(runSettings, mode);
                int attackMode = HashcatRunner.EffectiveAttackMode(attack, runSettings.ExtraArguments);
                bool resumeDictionary = resume is not null && si == resume.StepIndex && mi == resume.ModeIndex
                    && File.Exists(Native.ZipDictionaryRunner.RestoreFile(runSettings.SessionsDir, resume.HashcatSession));
                bool zipKernelsMissing = false;
                bool partialCpu = target.ZipPartial is { } partial && (partial.Method == 0
                    || resumeDictionary
                    || runSettings.Strategy == DeviceStrategy.CpuOnly || Devices is not null && HashcatRunner.ActiveGpus(runSettings, Devices).Count == 0
                    || (zipKernelsMissing = !HashcatKernels.EnsureFor(tool, mode, attackMode)));
                var nativePlan = Native.NativeRunner.Plan(mode, target.HashLines, attack, runSettings, Devices,
                    ignoreGpu: partialCpu, credentials: target.VolumeCredentials, partial: target.ZipPartial);
                bool cpuDictionary = partialCpu && runSettings.UseNativeCpuEngine
                    && string.IsNullOrWhiteSpace(runSettings.ExtraArguments) && Native.ZipDictionaryRunner.CanRun(attack);
                if (partialCpu)
                {
                    // The GPU kernels are the fast path for a large compressed entry; say why they are not used.
                    string? why = zipKernelsMissing ? HashcatKernels.UnavailableReason(tool) : null;
                    if (nativePlan is null && !cpuDictionary)
                    {
                        const string needsCpu = "This large ZIP file needs the built-in CPU engine for this attack. Enable it in Preferences " +
                                                "and use a brute-force, mask, or plain dictionary attack without rules or extra hashcat options.";
                        cpuOnlyReason ??= why is null ? needsCpu : why + " " + needsCpu;
                        stepsNeedingCpu++;
                        Log?.Invoke(LogKind.Warning, $"Step {si + 1}/{state.Steps.Count} skipped: {cpuOnlyReason}");
                        break;
                    }
                    if (why is not null && mi == startMode) Log?.Invoke(LogKind.Warning, why);
                    Log?.Invoke(LogKind.Info, target.ZipPartial!.Method == 0
                        ? "This large file is not compressed; using the built-in CPU engine so the password cannot be missed among header matches."
                        : "RecoverKit's ZIP GPU kernels are unavailable for this attack; using the built-in CPU engine to check the whole file.");
                }
                // With a GPU: hashcat on the GPUs and the built-in engine on the CPU, each on its own part.
                var hybridPlan = nativePlan is null && !cpuDictionary && pmkTable is null
                    ? Native.HybridRunner.Plan(mode, target.HashLines, attack, runSettings, Devices, target.VolumeCredentials, target.ZipPartial) : null;
                if (nativePlan is null && hybridPlan is null && runSettings.HybridCpuGpu && Native.HybridRunner.CpuAddsTooLittle(runSettings, Devices, mode)
                    && Native.NativeRunner.Plan(mode, target.HashLines, attack, runSettings, Devices, ignoreGpu: true,
                        credentials: target.VolumeCredentials, partial: target.ZipPartial) is not null)
                    Log?.Invoke(LogKind.Info, $"The CPU added less than a quarter of the GPU's speed in the last hybrid attack on this format, " +
                                              "and on an integrated GPU it slows the GPU down: hashcat runs alone.");
                if (runSettings.PerformanceChoice is not null || runSettings.CpuPerformanceChoice is not null || runSettings.GpuPerformanceChoice is not null || runSettings.ZipGpuPerformanceChoice is not null)
                    Log?.Invoke(LogKind.Info, ProfileSettings.Explain(runSettings, Devices ?? [], nativePlan is not null, hybridPlan is not null));
                string restoreFile = cpuDictionary
                    ? Native.ZipDictionaryRunner.RestoreFile(runSettings.SessionsDir, resume?.HashcatSession ?? "")
                    : nativePlan is not null
                        ? Native.NativeRunner.RestoreFile(runSettings.SessionsDir, resume?.HashcatSession ?? "")
                        : hybridPlan is not null
                            ? Native.HybridRunner.RestoreFile(runSettings.SessionsDir, resume?.HashcatSession ?? "")
                            : HashcatRunner.RestoreFile(runSettings.SessionsDir, resume?.HashcatSession ?? "");
                bool restore = resume is not null && si == resume.StepIndex && mi == resume.ModeIndex && resume.Restorable
                               && File.Exists(restoreFile);
                if (resume is { Restorable: true } && si == resume.StepIndex && mi == resume.ModeIndex && !restore)
                    Log?.Invoke(LogKind.Warning, "The saved engine cannot resume this step with the current settings; starting the step again.");
                string session = restore ? resume!.HashcatSession : $"rk_{key}_{si}_{mi}";

                StepStarted?.Invoke(si, state.Steps.Count, attack.Description + (state.Modes.Count > 1 ? $" [mode {mode}]" : ""), attack.Keyspace);
                Log?.Invoke(LogKind.Step, $"Step {si + 1}/{state.Steps.Count}: {attack.Description}" +
                                          (state.Modes.Count > 1 ? $" (hashcat mode {mode})" : "") +
                                          (restore ? " - resuming" : $" - {attack.Keyspace:N0} candidates"));
                foreach (var n in attack.Notes) Log?.Invoke(LogKind.Warning, n);

                bool optimized = nativePlan is null && !cpuDictionary && await SelectOptimizedKernelAsync(tool, mode, attack, runSettings.OptimizedKernels && (runSettings.PerformanceChoice?.Optimized ?? runSettings.GpuPerformanceChoice?.Optimized) != false,
                    restore, state.UseOptimizedKernel);
                state.UseOptimizedKernel = optimized;
                state.StepIndex = si;
                state.ModeIndex = mi;
                state.HashcatSession = session;
                state.Restorable = cpuDictionary || attack.CanRestore;
                state.Save(settings);

                var request = new RunRequest
                {
                    Mode = mode,
                    HashFile = hashFile,
                    Attack = attack,
                    SessionName = session,
                    SessionDir = settings.SessionsDir,
                    Restore = restore,
                    Settings = runSettings,
                    UseOptimizedKernel = optimized,
                    VolumeCredentials = target.VolumeCredentials,
                    PasswordCachePath = potfile,
                    Guard = HashcatRunner.GuardFor(runSettings, Devices),
                    ConfirmPassword = pmkTable is null ? target.ConfirmPassword : null,
                    RequiresPartialZipKernel = target.ZipPartial is not null,
                };
                stepsRun++;
                var result = cpuDictionary
                    ? await new Native.ZipDictionaryRunner { Status = s => Status?.Invoke(s) }.RunAsync(target, request, ct)
                    : nativePlan is { } np
                        ? await native.RunAsync(np.Kernel, np.Space, target.HashLines, request, ct)
                        : hybridPlan is { } hp
                            ? await hybrid.RunAsync(hp, target.HashLines, request, tool, ct)
                            : await runner.RunAsync(request, ct);

                // hashcat refuses some modes on Apple GPUs (e.g. PKZIP 17200 family): run the built-in CPU engine instead.
                if (nativePlan is null && hybridPlan is null && result.Outcome == RunOutcome.Error && HashcatRunner.IsGpuRefusal(result.Error, mode)
                    && Native.NativeRunner.Plan(mode, target.HashLines, attack, runSettings, Devices, ignoreGpu: true,
                        credentials: target.VolumeCredentials, partial: target.ZipPartial) is { } fallback)
                {
                    Log?.Invoke(LogKind.Warning, $"hashcat cannot run hash mode {mode} on this GPU; using the built-in CPU engine instead.");
                    request = request with { Restore = false };
                    result = await native.RunAsync(fallback.Kernel, fallback.Space, target.HashLines, request, ct);
                }
                else if (result.Outcome == RunOutcome.Error && HashcatRunner.IsGpuRefusal(result.Error, mode)
                    && target.ZipPartial is not null && settings.UseNativeCpuEngine
                    && string.IsNullOrWhiteSpace(settings.ExtraArguments) && Native.ZipDictionaryRunner.CanRun(attack))
                {
                    Log?.Invoke(LogKind.Warning, "hashcat cannot check this ZIP file on the GPU; using the built-in CPU engine for the dictionary.");
                    request = request with { Restore = false };
                    state.Restorable = true;
                    result = await new Native.ZipDictionaryRunner { Status = s => Status?.Invoke(s) }.RunAsync(target, request, ct);
                }

                if (result.LastStatus is { TotalSpeed: > 0 } ls) settings.SpeedByMode[mode] = ls.TotalSpeed;

                switch (result.Outcome)
                {
                    case RunOutcome.Cracked:
                        SessionState.Delete(settings, key);
                        Cleanup(session);
                        var found = result.Passwords;
                        if (pmkTable is not null)   // hashcat reports the PMK; map it back to its password
                            found = found.Select(p => pmkTable.PasswordFor(p) ?? p).ToList();
                        return new SessionResult { Outcome = SessionOutcome.Found, Passwords = found, Key = stayKeysHex, DecryptedCopy = stayCopy };
                    case RunOutcome.Aborted:
                        state.Save(settings);
                        return new SessionResult { Outcome = SessionOutcome.Stopped };
                    case RunOutcome.Error:
                        Log?.Invoke(LogKind.Error, result.Error ?? "hashcat failed.");
                        SessionState.Delete(settings, key);
                        Cleanup(session);
                        return new SessionResult { Outcome = SessionOutcome.Error, Error = result.Error };
                    default:
                        Log?.Invoke(LogKind.Info, $"Step {si + 1} finished, password not found ({result.LastStatus?.ProgressDone ?? 0:N0} candidates tested).");
                        Cleanup(session);
                        break;
                }
            }
        }
        SessionState.Delete(settings, key);
        if (stepsRun == 0 && stepsNeedingCpu > 0 && stayKeysHex is null)
            return new SessionResult { Outcome = SessionOutcome.Error, Error = cpuOnlyReason };
        return stayKeysHex is null
            ? new SessionResult { Outcome = SessionOutcome.NotFound }
            : new SessionResult { Outcome = SessionOutcome.KeyRecovered, Key = stayKeysHex, DecryptedCopy = stayCopy };
    }

    /// <summary>
    /// Key search step: all 2^40 RC4 keys (collider #1) unless the key cache has it, then a password
    /// that derives the same key (collider #2). Returns a final result, or null to go on with the next step.
    /// </summary>
    private async Task<SessionResult?> KeySearchStepAsync(HashcatRunner runner, HashTarget target, string hashFile, string key, int si,
        SessionState state, PreparedAttack attack, SessionState? resume, CancellationToken ct)
    {
        var modes = KeySearch.ModesFor(target.FormatId)!.Value;
        string hashLine = target.HashLines.Replace("\r", "").Split('\n', StringSplitOptions.RemoveEmptyEntries)[0].Trim();
        string? rc4 = settings.DontUseKeyCache ? null : KeyCache.Lookup(settings.KeyCachePath, hashLine);

        async Task<RunResult?> Run(int mode, string file, PreparedAttack a, int subIndex)
        {
            string session = $"rk_{key}_{si}_k{subIndex}";
            bool restore = resume is not null && si == resume.StepIndex && resume.ModeIndex == subIndex && resume.Restorable
                           && File.Exists(HashcatRunner.RestoreFile(settings.SessionsDir, session));
            bool optimized = await SelectOptimizedKernelAsync(tool, mode, a, settings.OptimizedKernels,
                restore, state.UseOptimizedKernel);
            state.UseOptimizedKernel = optimized;
            state.StepIndex = si;
            state.ModeIndex = subIndex;
            state.HashcatSession = session;
            state.Restorable = true;
            state.Save(settings);
            StepStarted?.Invoke(si, state.Steps.Count, a.Description, a.Keyspace);
            Log?.Invoke(LogKind.Step, $"Step {si + 1}/{state.Steps.Count}: {a.Description}" + (restore ? " - resuming" : $" - {a.Keyspace:N0} candidates"));
            var r = await runner.RunAsync(new RunRequest
            {
                Mode = mode, HashFile = file, Attack = a, SessionName = session, SessionDir = settings.SessionsDir,
                Restore = restore, Settings = settings, UseOptimizedKernel = optimized,
                Guard = HashcatRunner.GuardFor(settings, Devices),
            }, ct);
            if (r.Outcome is RunOutcome.Cracked or RunOutcome.Exhausted) Cleanup(session);
            return r;
        }

        if (rc4 is not null)
            Log?.Invoke(LogKind.Info, "Encryption key for this document was recovered earlier; searching for a password that produces it.");
        else
        {
            var r1 = await Run(modes.KeyMode, hashFile, attack, 0);
            switch (r1!.Outcome)
            {
                case RunOutcome.Aborted: state.Save(settings); return new SessionResult { Outcome = SessionOutcome.Stopped };
                case RunOutcome.Error:
                    SessionState.Delete(settings, key);
                    return new SessionResult { Outcome = SessionOutcome.Error, Error = r1.Error };
                case RunOutcome.Exhausted:
                    Log?.Invoke(LogKind.Warning, "The whole range of keys was checked but a valid one was not found.");
                    return null;
            }
            rc4 = r1.RawPasswords.Select(KeySearch.KeyHex).FirstOrDefault(k => k is { Length: 10 });
            if (rc4 is null) return new SessionResult { Outcome = SessionOutcome.Error, Error = "hashcat reported an unexpected key format." };
            if (!settings.DontUseKeyCache) KeyCache.Store(settings.KeyCachePath, hashLine, rc4);
            Log?.Invoke(LogKind.Success, "Encryption key recovered.");    // the key itself is in the result, never in the log
        }

        // Collider #2: a password that derives this key opens the document in its usual application.
        string file2 = Path.Combine(settings.SessionsDir, key + ".key.hash");
        await File.WriteAllTextAsync(file2, hashLine + ":" + rc4 + "\n", ct);
        var r2 = await Run(modes.PasswordMode, file2, KeySearch.EquivalentPasswordAttack(modes.MaxPasswordLength), 1);
        switch (r2!.Outcome)
        {
            case RunOutcome.Cracked:
                SessionState.Delete(settings, key);
                return new SessionResult { Outcome = SessionOutcome.Found, Passwords = r2.Passwords, Key = rc4 };
            case RunOutcome.Aborted:
                state.Save(settings);
                return new SessionResult { Outcome = SessionOutcome.Stopped, Key = rc4 };
            default:
                SessionState.Delete(settings, key);
                return new SessionResult { Outcome = SessionOutcome.KeyRecovered, Key = rc4, Error = r2.Error };
        }
    }

    private void LogGuard(ThermalGuard g)
    {
        var parts = new List<string>();
        if (g.TemperatureGuard)
        {
            var source = GpuTemperature.External;
            parts.Add($"pauses the GPU at {g.Limit} °C and resumes at {g.ResumeBelow} °C" +
                      (source is not null ? $" (temperature from {source.Name})" : ""));
        }
        if (g.DutyPercent < 100) parts.Add($"lets the GPU work {g.DutyPercent}% of the time");
        Log?.Invoke(LogKind.Info, "GPU guard: " + string.Join("; ", parts) + ".");
    }

    /// <summary>
    /// Selects the kernel once per attack, or reuses its saved choice on resume. A null attack
    /// selects for hashcat's benchmark mask. Unknown limits and unbounded candidate sources use pure.
    /// </summary>
    public static async Task<bool> SelectOptimizedKernelAsync(HashcatTool tool, int mode, PreparedAttack? attack,
        bool enabled, bool restore = false, bool? savedChoice = null)
    {
        if (restore) return savedChoice ?? false;
        if (!enabled) return false;
        var info = await tool.ModeInfoAsync(mode, 3);
        if (attack is null && info?.BenchmarkMask is { } mask)
        {
            attack = new PreparedAttack { Description = "Benchmark", Args = { "-a", "3" } };
            if (info.BenchmarkCharset1 is { Length: > 0 } cs && cs != "N/A") attack.Args.AddRange(["-1", cs]);
            attack.Args.Add(mask);
        }
        return attack is not null && CanUseOptimizedKernel(info, attack);
    }

    internal static bool CanUseOptimizedKernel(HashModeInfo? info, PreparedAttack attack)
        => info is { HasOptimizedKernel: true, OptimizedPasswordLenMax: > 0 }
           && attack.Stdin is null
           && Native.MaskSpace.FromHashcatArgs(attack.Args) is { } mask
           && mask.MaxLength <= info.OptimizedPasswordLenMax;

    private void Cleanup(string session)
    {
        foreach (var f in new[] { HashcatRunner.RestoreFile(settings.SessionsDir, session), HashcatRunner.OutFile(settings.SessionsDir, session),
                                  Native.NativeRunner.RestoreFile(settings.SessionsDir, session),
                                  Native.ZipDictionaryRunner.RestoreFile(settings.SessionsDir, session),
                                  Native.HybridRunner.RestoreFile(settings.SessionsDir, session) })
            try { File.Delete(f); } catch (IOException) { }
    }
}
