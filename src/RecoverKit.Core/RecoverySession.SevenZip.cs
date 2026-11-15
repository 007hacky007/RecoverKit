using RecoverKit.Core.Attacks;
using RecoverKit.Core.Hashcat;
using RecoverKit.Core.Formats;
using RecoverKit.Core.Native;
using RecoverKit.Core.Native.Kernels;

namespace RecoverKit.Core;

public sealed partial class RecoverySession
{
    private async Task<SessionResult> RunSevenZipCpuAsync(HashTarget target, string filePath,
        IReadOnlyList<AttackSpec> steps, SessionState? resume, CancellationToken ct)
    {
        const string needsCpu = "This 7z stream needs the built-in CPU engine. Enable it in Preferences and use " +
            "a brute-force, mask, or plain dictionary attack without rules or extra hashcat options.";
        if (!settings.UseNativeCpuEngine || !string.IsNullOrWhiteSpace(settings.ExtraArguments))
            return new SessionResult { Outcome = SessionOutcome.Error, Error = needsCpu };
        string key = SessionState.KeyFor(target);
        if (resume is not null && resume.Key != key)
            return new SessionResult { Outcome = SessionOutcome.Error, Error = "The 7z archive changed. Start a new attack instead of resuming." };
        var state = resume ?? new SessionState { FilePath = filePath, Key = key, Modes = [], Steps = steps.ToList() };
        for (int i = state.StepIndex; i < state.Steps.Count; i++)
            if (state.Steps[i].Kind is not (AttackKind.BruteForce or AttackKind.Mask or AttackKind.Dictionary) ||
                state.Steps[i] is { Kind: AttackKind.Dictionary, Rules: not RulesPreset.AsIs })
                return new SessionResult { Outcome = SessionOutcome.Error, Error = $"Step {i + 1} cannot run on this target. " + needsCpu };
        var kernel = new SevenZipKernel(target.SevenZipCpu!, ct);
        if (resume is null && !settings.DontUsePasswordCache)
        {
            foreach (string plain in PasswordConfirmation.OwnEntries(settings.PotfilePath, target.HashLines))
                if (kernel.Verify(PasswordConfirmation.PlainBytes(plain)))
                    return new SessionResult { Outcome = SessionOutcome.FoundInCache, Passwords = [HashcatTool.DecodePlain(plain)] };
        }
        var native = new NativeRunner();
        native.StatusReceived += s => Status?.Invoke(s);
        native.OutputLine += line => Log?.Invoke(LogKind.Info, line);
        for (int si = state.StepIndex; si < state.Steps.Count; si++)
        {
            if (ct.IsCancellationRequested) { state.Save(settings); return new SessionResult { Outcome = SessionOutcome.Stopped }; }
            var spec = state.Steps[si];
            try
            {
                var attack = AttackPlanner.Prepare(spec, target, PlannerContext);
                var space = MaskSpace.FromHashcatArgs(attack.Args);
                bool dictionary = spec.Kind == AttackKind.Dictionary && ZipDictionaryRunner.CanRun(attack);
                if (!dictionary && (space is null || space.MaxLength > kernel.MaxPasswordLength || attack.Stdin is not null))
                    return new SessionResult { Outcome = SessionOutcome.Error, Error = spec.Kind == AttackKind.BruteForce && attack.Stdin is not null
                        ? "The 7z CPU path supports ASCII brute-force charsets. Use an ASCII charset or a plain UTF-8 dictionary for national characters."
                        : $"Step {si + 1} uses a mask or candidate generator the built-in CPU engine cannot run. " + needsCpu };
                string session = $"rk_{key}_{si}_cpu";
                bool restore = resume is { Restorable: true } && si == resume.StepIndex;
                state.StepIndex = si; state.HashcatSession = session; state.Restorable = true;
                state.Save(settings);
                StepStarted?.Invoke(si, state.Steps.Count, attack.Description, attack.Keyspace);
                Log?.Invoke(LogKind.Step, $"Step {si + 1}/{state.Steps.Count}: {attack.Description}" + (restore ? " - resuming" : ""));
                var request = new RunRequest
                {
                    Mode = 0, HashFile = "", Attack = attack, Settings = settings,
                    SessionDir = settings.SessionsDir, SessionName = session, Restore = restore,
                    PasswordCachePath = settings.PotfilePath,
                };
                var result = dictionary
                    ? await new SevenZipDictionaryRunner { Status = s => Status?.Invoke(s) }.RunAsync(target, request,
                        spec, PlannerContext, ct)
                    : await native.RunAsync(kernel, space!, target.HashLines, request, ct);
                if (result.Outcome == RunOutcome.Aborted)
                { state.Save(settings); return new SessionResult { Outcome = SessionOutcome.Stopped }; }
                if (result.Outcome == RunOutcome.Error)
                    return new SessionResult { Outcome = SessionOutcome.Error, Error = result.Error };
                if (result.Outcome == RunOutcome.Cracked)
                {
                    SessionState.Delete(settings, key);
                    return new SessionResult { Outcome = SessionOutcome.Found, Passwords = result.Passwords };
                }
                state.StepIndex = si + 1; state.Restorable = false; state.Save(settings);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            { state.Save(settings); return new SessionResult { Outcome = SessionOutcome.Stopped }; }
            catch (AggregateException ex)
            { return new SessionResult { Outcome = SessionOutcome.Error, Error = "The CPU could not read the 7z archive: " + ex.Flatten().InnerExceptions[0].Message }; }
            catch (Exception ex) when (ex is AttackPlanException or IOException or UnauthorizedAccessException or InvalidOperationException)
            { return new SessionResult { Outcome = SessionOutcome.Error, Error = ex.Message }; }
        }
        SessionState.Delete(settings, key);
        return new SessionResult { Outcome = SessionOutcome.NotFound };
    }
}
