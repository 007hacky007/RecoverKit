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

    /// <summary>
    /// Returns the kernel and keyspace for this step when the built-in engine should run it: the
    /// format is built in, the attack is a brute-force/mask hashcat would run with -a 3, every length
    /// is supported, and no GPU is going to be used.
    /// </summary>
    public static (NativeKernel Kernel, MaskSpace Space)? Plan(int mode, string hashLines, Attacks.PreparedAttack attack,
        Settings settings, IReadOnlyList<BackendDevice>? devices, bool ignoreGpu = false, VolumeCredentials? credentials = null)
    {
        // Extra hashcat options can change candidate interpretation (for example TrueCrypt keyfiles).
        if (credentials is not null || !settings.UseNativeCpuEngine || attack.Stdin is not null || !string.IsNullOrWhiteSpace(settings.ExtraArguments)) return null;
        bool gpu = HashcatRunner.ActiveGpus(settings, devices).Count > 0;
        if (gpu && !ignoreGpu && settings.Strategy != DeviceStrategy.CpuOnly) return null;
        var lines = hashLines.Replace("\r", "").Split('\n', StringSplitOptions.RemoveEmptyEntries);
        if (lines.Length != 1) return null;
        var space = MaskSpace.FromHashcatArgs(attack.Args);
        if (space is null) return null;
        var kernel = NativeKernels.TryCreate(mode, lines[0]);
        if (kernel is null || space.MaxLength > kernel.MaxPasswordLength) return null;
        return (kernel, space);
    }

    public async Task<RunResult> RunAsync(NativeKernel kernel, MaskSpace space, string hashLine, RunRequest r, CancellationToken ct)
    {
        var s = r.Settings;
        string restoreFile = RestoreFile(r.SessionDir, r.SessionName);
        NativeResumePoint? resume = null;
        if (r.Restore && File.Exists(restoreFile))
            try { resume = JsonSerializer.Deserialize<NativeResumePoint>(await File.ReadAllTextAsync(restoreFile, ct)); }
            catch (JsonException) { }

        int threads = s.MaxCpuThreads > 0 ? Math.Min(s.MaxCpuThreads, Environment.ProcessorCount) : Environment.ProcessorCount;
        OutputLine?.Invoke($"Built-in CPU engine: {kernel.Name}, {threads} thread(s), lengths {space.MinLength}-{space.MaxLength}" +
                           (resume is not null ? $", resuming at length {resume.Length}" : ""));
        DebugLog.Info($"Native engine: {kernel.Name}, mode {r.Mode}, threads {threads}, priority {s.Priority}, " +
                      $"positions {string.Join(",", space.Positions.Select(p => p.Length))}, lengths {space.MinLength}-{space.MaxLength}, resume {resume?.Length}:{resume?.PrefixIndex}");

        HashcatStatus? last = null;
        var engine = new NativeEngine(kernel, space) { Threads = threads, Priority = ThreadPriorityFor(s.Priority) };
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
                Devices = [new DeviceSpeed { Id = 0, Name = "CPU (built-in engine)", Type = "CPU", Speed = p.Speed }],
            };
            StatusReceived?.Invoke(last);
        };

        // "Application priority": lower the whole process while the attack runs, so
        // other programs win but the UI thread still outranks the workers.
        var proc = Process.GetCurrentProcess();
        ProcessPriorityClass? previous = null;
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
        DebugLog.Info($"Native engine finished: {result.Outcome}, {result.Tested:N0} candidates in {sw.Elapsed.TotalSeconds:F1} s");

        switch (result.Outcome)
        {
            case NativeOutcome.Found:
            {
                var pw = await RecordFoundAsync(s, hashLine, result.Password!);
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

    /// <summary>Writes a found password to the password cache in hashcat's format and returns it decoded.</summary>
    internal static async Task<string> RecordFoundAsync(Settings s, string hashLine, byte[] pw)
    {
        string plain = Printable(pw) ? Encoding.Latin1.GetString(pw) : "$HEX[" + Convert.ToHexString(pw).ToLowerInvariant() + "]";
        if (!s.DontUsePasswordCache)
            try { await File.AppendAllTextAsync(s.PotfilePath, hashLine.Trim() + ":" + plain + "\n", new UTF8Encoding(false), CancellationToken.None); }
            catch (IOException ex) { DebugLog.Warn("Could not write potfile: " + ex.Message); }
        return HashcatTool.DecodePlain(plain);
    }

    private static bool Printable(byte[] pw) => pw.All(b => b is >= 0x20 and < 0x7f);

    private static void TryDelete(string f) { try { File.Delete(f); } catch (IOException) { } }

    internal static ThreadPriority ThreadPriorityFor(ProcessPriority p) => p switch
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
