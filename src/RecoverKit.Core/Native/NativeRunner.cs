using System.Diagnostics;
using System.Text;
using System.Text.Json;
using RecoverKit.Core.Hashcat;
using RecoverKit.Core.Formats;

namespace RecoverKit.Core.Native;

/// <summary>
/// Runs one attack step on the built-in CPU engine with the same contract as
/// <see cref="HashcatRunner"/>: hashcat-style status updates, a resume file on stop, and found
/// passwords written to the shared potfile in hashcat's format.
/// </summary>
public sealed class NativeRunner
{
    public event Action<HashcatStatus>? StatusReceived;
    public event Action<string>? OutputLine;

    public static string RestoreFile(string dir, string session) => Path.Combine(dir, session + ".native.json");

    /// <summary>Hits rejected by the confirmation check, over all runs of this runner (a session).</summary>
    internal FalsePositiveLog FalsePositives => _falsePositives ??= new FalsePositiveLog(l => OutputLine?.Invoke(l));
    private FalsePositiveLog? _falsePositives;

    /// <summary>
    /// Returns the kernel and keyspace for this step when the built-in engine should run it: the
    /// format is built in, the attack is a brute-force/mask hashcat would run with -a 3, every length
    /// is supported, and no GPU is going to be used.
    /// </summary>
    public static (NativeKernel Kernel, MaskSpace Space)? Plan(int mode, string hashLines, Attacks.PreparedAttack attack,
        Settings settings, IReadOnlyList<BackendDevice>? devices, bool ignoreGpu = false, VolumeCredentials? credentials = null,
        ZipPartialTarget? partial = null)
    {
        // Extra hashcat options can change candidate interpretation (for example TrueCrypt keyfiles).
        if (credentials is not null || !settings.UseNativeCpuEngine || attack.Stdin is not null || !string.IsNullOrWhiteSpace(settings.ExtraArguments)) return null;
        if (!ignoreGpu && settings.PerformanceChoice?.Engine is "gpu" or "hybrid") return null;
        bool gpu = HashcatRunner.ActiveGpus(settings, devices).Count > 0;
        if (gpu && !ignoreGpu && settings.Strategy != DeviceStrategy.CpuOnly && settings.PerformanceChoice?.Engine != "cpu") return null;
        // A CPU variant timing alone does not establish a win over hashcat's CPU engine.
        if (!ignoreGpu && mode is 9400 or 13600 or 22000 && settings.PerformanceChoice?.Engine != "cpu") return null;
        var lines = hashLines.Replace("\r", "").Split('\n', StringSplitOptions.RemoveEmptyEntries);
        // hashcat searches every network; our CPU runners stop on their first hit.
        if (lines.Length != 1) return null;
        var space = MaskSpace.FromHashcatArgs(attack.Args);
        if (space is null) return null;
        var kernel = NativeKernels.TryCreate(mode, mode == 22000 ? hashLines : lines[0], partial);
        if (kernel is null || space.MaxLength > kernel.MaxPasswordLength) return null;
        return (kernel, space);
    }

    public async Task<RunResult> RunAsync(NativeKernel kernel, MaskSpace space, string hashLine, RunRequest r, CancellationToken ct)
    {
        var s = r.Settings;
        if (r.Mode == 29331) NativeKernels.ConfigureWhirlpool(s);
        NativeKernels.ResetCpuPath(r.Mode);
        string restoreFile = RestoreFile(r.SessionDir, r.SessionName);
        NativeResumePoint? resume = null;
        if (r.Restore && File.Exists(restoreFile))
            try { resume = JsonSerializer.Deserialize<NativeResumePoint>(await File.ReadAllTextAsync(restoreFile, ct)); }
            catch (JsonException) { }

        int threads = s.MaxCpuThreads == 0 && (s.PerformanceChoice?.Engine == "cpu" ? s.PerformanceChoice.Threads : s.CpuPerformanceChoice?.Threads) is > 0 and var measured ? measured : s.MaxCpuThreads > 0 ? Math.Min(s.MaxCpuThreads, Environment.ProcessorCount) : Environment.ProcessorCount;
        OutputLine?.Invoke($"Built-in CPU engine: {kernel.Name}, {threads} thread(s), lengths {space.MinLength}-{space.MaxLength}" +
                           (resume is not null ? $", resuming at length {resume.Length}" : ""));
        DebugLog.Info($"Native engine: {kernel.Name}, mode {r.Mode}, threads {threads}, priority {s.Priority}, " +
                      $"positions {string.Join(",", space.Positions.Select(p => p.Length))}, lengths {space.MinLength}-{space.MaxLength}, resume {resume?.Length}:{resume?.PrefixIndex}");

        HashcatStatus? last = null;
        var engine = new NativeEngine(kernel, space)
        {
            Threads = threads, Priority = ThreadPriorityFor(s.Priority),
            Confirm = r.ConfirmPassword, Rejected = pw => FalsePositives.Rejected(pw.Length, "the built-in CPU engine"),
        };
        engine.Progress += p =>
        {
            last = new HashcatStatus
            {
                Status = 3,
                MaskLength = p.Length,
                ProgressDone = p.Done,
                ResumedFrom = p.ResumedFrom,
                ProgressTotal = p.Total,
                TimeStart = new DateTimeOffset(p.Started).ToUnixTimeSeconds(),   // per length, as progress is per length
                TotalHashes = 1,
                Devices = [new DeviceSpeed { Id = 0, Name = $"CPU (built-in engine, {NativeKernels.CpuPath(r.Mode, actualOnly: true)}, {threads} threads)", Type = "CPU", Speed = p.Speed }],
            };
            StatusReceived?.Invoke(last);
        };

        // "Application priority": lower the whole process while the attack runs, so
        // other programs win but the UI thread still outranks the workers.
        var proc = Process.GetCurrentProcess();
        ProcessPriorityClass? previous = null;
        if (LowersProcessPriority)
            try { previous = proc.PriorityClass; proc.PriorityClass = ProcessClassFor(s.Priority); }
        catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception or PlatformNotSupportedException) { }

        var sw = Stopwatch.StartNew();
        NativeResult result;
        try { result = await Task.Run(() => engine.Run(resume, ct), CancellationToken.None); }
        finally
        {
            if (previous is { } pc)
                try { proc.PriorityClass = pc; } catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception) { }
        }
        if (r.Mode == 29331) OutputLine?.Invoke($"Built-in CPU engine Whirlpool path: {NativeKernels.CpuPath(r.Mode, actualOnly: true)}");
        DebugLog.Info($"Native engine finished: {result.Outcome}, {result.Tested:N0} candidates in {sw.Elapsed.TotalSeconds:F1} s");

        switch (result.Outcome)
        {
            case NativeOutcome.Found:
            {
                var pw = await RecordFoundAsync(s, MatchedHashLine(kernel, hashLine, result.Password!), result.Password!, r.Mode == 9400 || r.ConfirmPassword is not null ? r.PasswordCachePath ?? s.PotfilePath : null);
                TryDelete(restoreFile);
                return new RunResult { Outcome = RunOutcome.Cracked, ExitCode = 0, Passwords = [pw], LastStatus = last };
            }
            case NativeOutcome.Stopped:
                if (result.ResumeAt is { } at)
                    await File.WriteAllTextAsync(restoreFile, JsonSerializer.Serialize(at), CancellationToken.None);
                return new RunResult { Outcome = RunOutcome.Aborted, ExitCode = 2, LastStatus = last };
            default:
                TryDelete(restoreFile);
                return new RunResult { Outcome = RunOutcome.Exhausted, ExitCode = 1, LastStatus = last };
        }
    }

    /// <summary>Chooses the verified network and hashcat's cache key for a CPU hit.</summary>
    internal static string MatchedHashLine(NativeKernel kernel, string lines, byte[] password)
        => kernel is Kernels.WpaKernel wpa ? wpa.PotfileKey(password, lines)
            ?? throw new InvalidOperationException("The WPA password does not verify any target network.") : lines;

    /// <summary>Writes a found password to the password cache in hashcat's format and returns it decoded.</summary>
    internal static async Task<string> RecordFoundAsync(Settings s, string hashLine, byte[] pw, string? confirmedCache = null)
    {
        if (hashLine.TrimStart().StartsWith("$office$*2007*", StringComparison.Ordinal))
        {
            if (!s.DontUsePasswordCache) await PasswordConfirmation.AppendAsync(confirmedCache ?? s.PotfilePath, hashLine, pw);
            return HybridRunner.DictionaryPlain(pw);
        }
        string plain = Printable(pw) ? Encoding.Latin1.GetString(pw) : PasswordConfirmation.HexPlain(pw);
        // A confirmed password goes to the request's cache as hash:$HEX[...] (see PasswordConfirmation).
        if (confirmedCache is not null)
        {
            if (!s.DontUsePasswordCache) await PasswordConfirmation.AppendAsync(confirmedCache, hashLine, pw);
        }
        else if (!s.DontUsePasswordCache)
            try { await File.AppendAllTextAsync(s.PotfilePath, hashLine.Trim() + ":" + plain + "\n", new UTF8Encoding(false), CancellationToken.None); }
            catch (IOException ex) { DebugLog.Warn("Could not write potfile: " + ex.Message); }
        return HashcatTool.DecodePlain(plain);
    }

    private static bool Printable(byte[] pw) => pw.All(b => b is >= 0x20 and < 0x7f);

    private static void TryDelete(string f) { try { File.Delete(f); } catch (IOException) { } }

    /// <summary>
    /// Whether the engine lowers the whole process while it runs. Not on macOS: a niced process (and
    /// "Idle" is nice 19) runs its threads on the efficiency cores, measured at a quarter of the speed
    /// on an M1 Pro (PDF R6: about 14,000 instead of 55,000/s), and an unprivileged process cannot raise
    /// its priority again afterwards. The lower thread priority alone keeps other programs first.
    /// </summary>
    internal static bool LowersProcessPriority => !OperatingSystem.IsMacOS();

    /// <summary>
    /// Worker thread priority. On macOS a lowered priority moves the threads towards the efficiency
    /// cores as soon as anything else runs: measured on an M1 Pro, RAR 3 fell from about 3,700 to
    /// 1,800/s at "below normal", and PDF R6 next to hashcat from 58,000 to 25,000-40,000/s at "lowest".
    /// There the engine runs at normal priority and macOS shares the cores between applications.
    /// </summary>
    public static ThreadPriority ThreadPriorityFor(ProcessPriority p) => OperatingSystem.IsMacOS() && p != ProcessPriority.High ? ThreadPriority.Normal : p switch
    {
        ProcessPriority.Idle => ThreadPriority.Lowest,
        ProcessPriority.BelowNormal => ThreadPriority.BelowNormal,
        ProcessPriority.High => ThreadPriority.AboveNormal,
        _ => ThreadPriority.Normal,
    };

    internal static ProcessPriorityClass ProcessClassFor(ProcessPriority p) => p switch
    {
        ProcessPriority.Idle => ProcessPriorityClass.Idle,
        ProcessPriority.BelowNormal => ProcessPriorityClass.BelowNormal,
        ProcessPriority.High => ProcessPriorityClass.High,
        _ => ProcessPriorityClass.Normal,
    };
}
