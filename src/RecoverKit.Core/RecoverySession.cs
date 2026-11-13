using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using RecoverKit.Core.Attacks;
using RecoverKit.Core.Formats;
using RecoverKit.Core.Attacks.Stay;
using RecoverKit.Core.Hashcat;

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
                var cached = await tool.ShowAsync(mode, hashFile, potfile, target.VolumeCredentials);
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
                var nativePlan = Native.NativeRunner.Plan(mode, target.HashLines, attack, settings, Devices, credentials: target.VolumeCredentials);
                // With a GPU: hashcat on the GPUs and the built-in engine on the CPU, each on its own part.
                var hybridPlan = nativePlan is null && pmkTable is null
                    ? Native.HybridRunner.Plan(mode, target.HashLines, attack, settings, Devices, target.VolumeCredentials) : null;
                if (nativePlan is null && hybridPlan is null && settings.HybridCpuGpu && Native.HybridRunner.CpuAddsTooLittle(settings, Devices, mode)
                    && Native.NativeRunner.Plan(mode, target.HashLines, attack, settings, Devices, ignoreGpu: true, credentials: target.VolumeCredentials) is not null)
                    Log?.Invoke(LogKind.Info, $"The CPU added less than a quarter of the GPU's speed in the last hybrid attack on this format, " +
                                              "and on an integrated GPU it slows the GPU down: hashcat runs alone.");
                string restoreFile = nativePlan is not null
                    ? Native.NativeRunner.RestoreFile(settings.SessionsDir, resume?.HashcatSession ?? "")
                    : hybridPlan is not null
                        ? Native.HybridRunner.RestoreFile(settings.SessionsDir, resume?.HashcatSession ?? "")
                        : HashcatRunner.RestoreFile(settings.SessionsDir, resume?.HashcatSession ?? "");
                bool restore = resume is not null && si == resume.StepIndex && mi == resume.ModeIndex && resume.Restorable
                               && File.Exists(restoreFile);
                string session = restore ? resume!.HashcatSession : $"rk_{key}_{si}_{mi}";

                StepStarted?.Invoke(si, state.Steps.Count, attack.Description + (state.Modes.Count > 1 ? $" [mode {mode}]" : ""), attack.Keyspace);
                Log?.Invoke(LogKind.Step, $"Step {si + 1}/{state.Steps.Count}: {attack.Description}" +
                                          (state.Modes.Count > 1 ? $" (hashcat mode {mode})" : "") +
                                          (restore ? " - resuming" : $" - {attack.Keyspace:N0} candidates"));
                foreach (var n in attack.Notes) Log?.Invoke(LogKind.Warning, n);

                state.StepIndex = si;
                state.ModeIndex = mi;
                state.HashcatSession = session;
                state.Restorable = attack.CanRestore;
                state.Save(settings);

                bool optimized = settings.OptimizedKernels && CanUseOptimizedKernel(mode, spec)
                                 && (await tool.ModeInfoAsync(mode))?.HasOptimizedKernel == true;

                var request = new RunRequest
                {
                    Mode = mode,
                    HashFile = hashFile,
                    Attack = attack,
                    SessionName = session,
                    SessionDir = settings.SessionsDir,
                    Restore = restore,
                    Settings = settings,
                    UseOptimizedKernel = optimized && !restore,
                    VolumeCredentials = target.VolumeCredentials,
                    PasswordCachePath = potfile,
                    Guard = HashcatRunner.GuardFor(settings, Devices),
                };
                var result = nativePlan is { } np
                    ? await native.RunAsync(np.Kernel, np.Space, target.HashLines, request, ct)
                    : hybridPlan is { } hp
                        ? await hybrid.RunAsync(hp, target.HashLines, request, tool, ct)
                        : await runner.RunAsync(request, ct);

                // hashcat refuses some modes on Apple GPUs (e.g. PKZIP 17200 family): run the built-in CPU engine instead.
                if (nativePlan is null && hybridPlan is null && result.Outcome == RunOutcome.Error && HashcatRunner.IsGpuRefusal(result.Error, mode)
                    && Native.NativeRunner.Plan(mode, target.HashLines, attack, settings, Devices, ignoreGpu: true, credentials: target.VolumeCredentials) is { } fallback)
                {
                    Log?.Invoke(LogKind.Warning, $"hashcat cannot run hash mode {mode} on this GPU; using the built-in CPU engine instead.");
                    request = request with { Restore = false };
                    result = await native.RunAsync(fallback.Kernel, fallback.Space, target.HashLines, request, ct);
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

        async Task<RunResult?> Run(int mode, string file, PreparedAttack a, int subIndex, bool optimized)
        {
            string session = $"rk_{key}_{si}_k{subIndex}";
            bool restore = resume is not null && si == resume.StepIndex && resume.ModeIndex == subIndex && resume.Restorable
                           && File.Exists(HashcatRunner.RestoreFile(settings.SessionsDir, session));
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
                Restore = restore, Settings = settings, UseOptimizedKernel = optimized && !restore,
                Guard = HashcatRunner.GuardFor(settings, Devices),
            }, ct);
            if (r.Outcome is RunOutcome.Cracked or RunOutcome.Exhausted) Cleanup(session);
            return r;
        }

        if (rc4 is not null)
            Log?.Invoke(LogKind.Info, "Encryption key for this document was recovered earlier; searching for a password that produces it.");
        else
        {
            var r1 = await Run(modes.KeyMode, hashFile, attack, 0, true);
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
        var r2 = await Run(modes.PasswordMode, file2, KeySearch.EquivalentPasswordAttack(modes.MaxPasswordLength), 1, true);
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

    internal static bool CanUseOptimizedKernel(int mode, AttackSpec spec)
        => spec.Kind != AttackKind.Dictionary && MaxLen(spec) <= (mode is 11600 or 23700 or 23800 ? 20 : 27);

    private static int MaxLen(AttackSpec s) => s.Kind switch
    {
        AttackKind.BruteForce when s.Mask.Length > 0 => s.Mask.Length,
        AttackKind.Mask => Charsets.MaskPositions(s.HashcatMask, s.CustomCharsets).Count,
        _ => s.MaxLength,
    };

    private void Cleanup(string session)
    {
        foreach (var f in new[] { HashcatRunner.RestoreFile(settings.SessionsDir, session), HashcatRunner.OutFile(settings.SessionsDir, session),
                                  Native.NativeRunner.RestoreFile(settings.SessionsDir, session),
                                  Native.HybridRunner.RestoreFile(settings.SessionsDir, session) })
            try { File.Delete(f); } catch (IOException) { }
    }
}
