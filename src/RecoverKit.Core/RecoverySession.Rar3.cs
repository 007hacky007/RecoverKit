using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using RecoverKit.Core.Attacks;
using RecoverKit.Core.Formats;
using RecoverKit.Core.Hashcat;
using RecoverKit.Core.Native;
using RecoverKit.Core.Native.Kernels;

namespace RecoverKit.Core;

public sealed partial class RecoverySession
{
    private async Task<SessionResult> RunRar3FileAsync(HashTarget target, string filePath,
        IReadOnlyList<AttackSpec> steps, SessionState? resume, CancellationToken ct)
    {
        const string supported = "This large RAR 3 file needs the built-in CPU engine. Enable it in Preferences " +
            "and use a brute-force, mask, or plain dictionary attack without rules or extra hashcat options.";
        if (!settings.UseNativeCpuEngine || !string.IsNullOrWhiteSpace(settings.ExtraArguments))
            return new SessionResult { Outcome = SessionOutcome.Error, Error = supported };
        if (target.Rar3File!.Method != 0x30 && !RkNative.Available)
            return new SessionResult { Outcome = SessionOutcome.Error, Error = "Compressed RAR 3 files larger than hashcat's limit need RecoverKit's native RAR decoder. Rebuild or reinstall the native library." };
        string key = SessionState.KeyFor(target);
        var state = resume ?? new SessionState { Key = key, FilePath = filePath, Steps = steps.ToList() };
        const int possibleLimit = 64;
        using var possibleStop = CancellationTokenSource.CreateLinkedTokenSource(ct);
        ct = possibleStop.Token;
        SessionResult Finish(SessionOutcome outcome, string? error = null, List<string>? passwords = null)
            => new() { Outcome = outcome, Error = error, Passwords = passwords ?? [], PossiblePasswords = state.Rar3PossiblePasswords.ToList() };
        const string possibleMessage = "Possible passwords were saved but could not be verified. They must be tried by hand in an archive utility.";
        const string limitMessage = "The limit of 64 possible passwords was reached. " + possibleMessage +
            " The unfinished batch is checkpointed for replay. Check the saved passwords before starting a new attack.";
        var kernel = new Rar3FileKernel(target.Rar3File, ct)
        {
            Unconfirmed = (password, reason) =>
            {
                lock (state)
                {
                    // Cancellation replays the unfinished batch, including any in-flight candidates.
                    if (ct.IsCancellationRequested) return;
                    string plain = PasswordConfirmation.HexPlain(password);
                    if (state.Rar3PossiblePasswords.Any(p => p.Password == plain)) return;
                    state.Rar3PossiblePasswords.Add(new PossiblePassword(plain, reason));
                    state.Save(settings);
                    if (state.Rar3PossiblePasswords.Count >= possibleLimit) possibleStop.Cancel();
                }
            },
        };
        if (state.Rar3PossiblePasswords.Count >= possibleLimit)
            return Finish(SessionOutcome.Error, limitMessage);
        int ran = 0;
        string? skipped = null;
        try
        {
            if (resume is null && !settings.DontUsePasswordCache)
                foreach (string plain in PasswordConfirmation.OwnEntries(settings.PotfilePath, target.HashLines))
                {
                    byte[] password = PasswordConfirmation.PlainBytes(plain);
                    if (kernel.Verify(password))
                        return Finish(SessionOutcome.FoundInCache, passwords: [HashcatTool.DecodePlain(plain)]);
                }
            Log?.Invoke(LogKind.Info, target.Notes ?? "Using the processor to check this large RAR 3 file without the graphics card.");
            for (int i = state.StepIndex; i < state.Steps.Count; i++)
            {
                var spec = state.Steps[i];
                if (spec.Kind is not (AttackKind.BruteForce or AttackKind.Mask or AttackKind.Dictionary) ||
                    spec.Kind == AttackKind.Dictionary && spec.Rules != RulesPreset.AsIs)
                {
                    skipped = supported;
                    Log?.Invoke(LogKind.Warning, $"Step {i + 1}/{state.Steps.Count} skipped: {supported}");
                    continue;
                }
                PreparedAttack attack;
                try { attack = AttackPlanner.Prepare(spec, target, PlannerContext, path => Rar3DictionaryWords(path, spec).LongCount()); }
                catch (AttackPlanException ex)
                {
                    skipped = ex.Message;
                    Log?.Invoke(LogKind.Warning, $"Step {i + 1}/{state.Steps.Count} skipped: {ex.Message}");
                    continue;
                }
                var space = MaskSpace.FromHashcatArgs(attack.Args);
                bool words = attack.Stdin is not null || spec.Kind == AttackKind.Dictionary && ZipDictionaryRunner.CanRun(attack);
                if (space is null && !words || space is not null && (space.MaxLength > kernel.MaxPasswordLength ||
                    Enumerable.Range(space.MinLength, space.MaxLength - space.MinLength + 1).Any(l => space.Keyspace(l) > long.MaxValue)))
                {
                    skipped = "This RAR 3 CPU attack has an unsupported mask or a keyspace too large to checkpoint. " + supported;
                    Log?.Invoke(LogKind.Warning, skipped);
                    continue;
                }
                string session = $"rk-{key}-rar3-{i}";
                bool restore = resume is { Restorable: true } && i == resume.StepIndex;
                state.StepIndex = i;
                state.HashcatSession = session;
                state.Restorable = true;
                state.Save(settings);
                if (ct.IsCancellationRequested) return Finish(state.Rar3PossiblePasswords.Count >= possibleLimit ? SessionOutcome.Error : SessionOutcome.Stopped,
                        state.Rar3PossiblePasswords.Count >= possibleLimit ? limitMessage : null);
                StepStarted?.Invoke(i, state.Steps.Count, attack.Description, attack.Keyspace);
                Log?.Invoke(LogKind.Step, $"Step {i + 1}/{state.Steps.Count}: {attack.Description} - {attack.Keyspace:N0} candidates");
                ran++;
                RunResult result;
                if (space is not null)
                {
                    var runner = new NativeRunner();
                    runner.StatusReceived += s => Status?.Invoke(s);
                    runner.OutputLine += line => Log?.Invoke(LogKind.Info, line);
                    result = await runner.RunAsync(kernel, space, target.HashLines, new RunRequest
                    {
                        Mode = 0, HashFile = "", Attack = attack, SessionName = session,
                        SessionDir = settings.SessionsDir, Settings = settings, Restore = restore,
                    }, ct);
                }
                else result = await RunRar3WordsAsync(target, kernel, spec, attack, session, restore, ct);
                if (result.Outcome == RunOutcome.Aborted)
                {
                    state.Save(settings);
                    return Finish(state.Rar3PossiblePasswords.Count >= possibleLimit ? SessionOutcome.Error : SessionOutcome.Stopped,
                        state.Rar3PossiblePasswords.Count >= possibleLimit ? limitMessage : null);
                }
                if (result.Outcome == RunOutcome.Cracked)
                {
                    SessionState.Delete(settings, key);
                    return Finish(SessionOutcome.Found, passwords: result.Passwords);
                }
                if (state.Rar3PossiblePasswords.Count > 0 || state.Rar3UnconfirmedReason is not null)
                    Log?.Invoke(LogKind.Warning, "Some candidates remain unconfirmed; continuing with any remaining attacks.");
                File.Delete(NativeRunner.RestoreFile(settings.SessionsDir, session));
                File.Delete(Rar3DictionaryRestore(session));
                state.StepIndex = i + 1;
                state.Restorable = false;
                state.Save(settings);
                Log?.Invoke(LogKind.Info, $"Step {i + 1} finished, no password was confirmed.");
            }
            if (state.Rar3PossiblePasswords.Count > 0 || state.Rar3UnconfirmedReason is not null)
            {
                state.Save(settings);
                string message = state.Rar3PossiblePasswords.Count > 0 ? possibleMessage :
                    "The previous decoder could not verify some candidates, but did not save their passwords. Start a new attack to replay them. " + state.Rar3UnconfirmedReason;
                Log?.Invoke(LogKind.Error, message);
                return Finish(SessionOutcome.Error, message);
            }
            SessionState.Delete(settings, key);
            return ran > 0 ? Finish(SessionOutcome.NotFound) : Finish(SessionOutcome.Error, skipped ?? supported);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            state.Save(settings);
            return Finish(state.Rar3PossiblePasswords.Count >= possibleLimit ? SessionOutcome.Error : SessionOutcome.Stopped,
                        state.Rar3PossiblePasswords.Count >= possibleLimit ? limitMessage : null);
        }
        catch (Exception ex) when (ex is IOException or InvalidDataException or JsonException or UnauthorizedAccessException or NotSupportedException or InvalidOperationException)
        {
            Log?.Invoke(LogKind.Error, ex.Message);
            state.Save(settings);
            return Finish(SessionOutcome.Error, ex.Message);
        }
    }

    private sealed record Rar3DictionaryPoint(long Done, string Fingerprint);
    private string Rar3DictionaryRestore(string session) => Path.Combine(settings.SessionsDir, session + ".rar3.dictionary.json");

    private async Task<RunResult> RunRar3WordsAsync(HashTarget target, Rar3FileKernel kernel, AttackSpec spec,
        PreparedAttack attack, string session, bool restore, CancellationToken ct)
    {
        string checkpoint = Rar3DictionaryRestore(session);
        string fingerprint = JsonSerializer.Serialize(spec);
        string? dictionary = spec.Kind == AttackKind.Dictionary
            ? AttackPlanner.ResolveDictionary(spec.Dictionaries[0], PlannerContext) : null;
        if (dictionary is not null)
        {
            using var input = File.OpenRead(dictionary);
            fingerprint += Convert.ToHexString(await SHA256.HashDataAsync(input, ct));
        }
        fingerprint = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(fingerprint)));
        long resumed = 0;
        if (restore && File.Exists(checkpoint))
        {
            var saved = JsonSerializer.Deserialize<Rar3DictionaryPoint>(await File.ReadAllTextAsync(checkpoint, ct));
            if (saved is null || saved.Done < 0 || saved.Fingerprint != fingerprint)
                throw new InvalidDataException("The RAR 3 CPU dictionary changed since the saved session. Restore the original dictionary before resuming.");
            resumed = saved.Done;
        }
        long done = resumed;
        var watch = System.Diagnostics.Stopwatch.StartNew();
        long started = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        HashcatStatus? last = null;
        int threads = settings.MaxCpuThreads > 0 ? Math.Min(settings.MaxCpuThreads, Environment.ProcessorCount) : Environment.ProcessorCount;
        void Report(int status)
        {
            last = new HashcatStatus
            {
                Status = status, ProgressDone = done, ResumedFrom = resumed,
                ProgressTotal = (long)BigInteger.Min(attack.Keyspace, long.MaxValue), TotalHashes = 1, TimeStart = started,
                Devices = [new DeviceSpeed { Id = 0, Type = "CPU", Name = "CPU (built-in engine)", Speed = (done - resumed) / Math.Max(watch.Elapsed.TotalSeconds, .001) }],
            };
            Status?.Invoke(last);
        }
        return await Task.Run(async () =>
        {
            IEnumerable<string> words = dictionary is not null ? Rar3DictionaryWords(dictionary, spec)
                : attack.Stdin!.Invoke();
            using var iterator = words.GetEnumerator();
            for (long i = 0; i < resumed; i++)
            {
                ct.ThrowIfCancellationRequested();
                if (!iterator.MoveNext()) throw new InvalidDataException("The RAR 3 dictionary checkpoint is beyond the end of its candidates.");
            }
            int size = Math.Max(16, Math.Min(256, threads * 16));
            while (true)
            {
                if (ct.IsCancellationRequested)
                {
                    await File.WriteAllTextAsync(checkpoint, JsonSerializer.Serialize(new Rar3DictionaryPoint(done, fingerprint)), CancellationToken.None);
                    Report(7);
                    return new RunResult { Outcome = RunOutcome.Aborted, LastStatus = last };
                }
                var batch = new List<byte[]>(size);
                while (batch.Count < size && iterator.MoveNext()) batch.Add(PasswordConfirmation.PlainBytes(iterator.Current));
                if (batch.Count == 0)
                {
                    File.Delete(checkpoint);
                    Report(5);
                    return new RunResult { Outcome = RunOutcome.Exhausted, LastStatus = last };
                }
                byte[]? found = null;
                try
                {
                    Parallel.ForEach(batch.GroupBy(p => p.Length).SelectMany(group => group.Chunk(16)),
                        new ParallelOptions { MaxDegreeOfParallelism = threads }, group =>
                        {
                            if (ct.IsCancellationRequested || Volatile.Read(ref found) is not null) return;
                            int length = group[0].Length;
                            int hit;
                            if (length == 0) hit = kernel.Verify([]) ? 0 : -1;
                            else hit = kernel.CreateWorker().SearchPasswords(group.SelectMany(p => p).ToArray(), length, group.Length);
                            if (hit >= 0 && kernel.Verify(group[hit])) Interlocked.CompareExchange(ref found, group[hit], null);
                        });
                }
                catch (AggregateException ex) { System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(ex.Flatten().InnerExceptions[0]).Throw(); }
                if (found is not null)
                {
                    string password = await NativeRunner.RecordFoundAsync(settings, target.HashLines, found);
                    File.Delete(checkpoint);
                    Report(6);
                    return new RunResult { Outcome = RunOutcome.Cracked, Passwords = [password], LastStatus = last };
                }
                if (!ct.IsCancellationRequested) done += batch.Count;
                await File.WriteAllTextAsync(checkpoint, JsonSerializer.Serialize(new Rar3DictionaryPoint(done, fingerprint)), CancellationToken.None);
                Report(3);
            }
        }, CancellationToken.None);
    }

    private static IEnumerable<string> Rar3DictionaryWords(string path, AttackSpec spec)
    {
        return Wordlists.ReadWords(path, spec.SkipShorterThan, spec.SkipLongerThan);
    }
}
