using System.Diagnostics;
using System.Numerics;
using System.Text;
using System.Text.Json;
using RecoverKit.Core.Attacks;
using RecoverKit.Core.Formats;
using RecoverKit.Core.Hashcat;

namespace RecoverKit.Core.Native;

/// <summary>A hybrid step: the built-in kernel and a mask or file dictionary.</summary>
public sealed record HybridPlan(NativeKernel Kernel, MaskSpace? Space)
{
    internal DictionaryAttack? Dictionary { get; init; }
}

/// <summary>Where a hybrid attack stopped (see <see cref="HybridRunner"/> for the invariant).</summary>
public sealed class HybridResumePoint
{
    public int Length { get; set; }
    public long BaseCount { get; set; }
    /// <summary>Every base word below this is done (hashcat's side).</summary>
    public long Lo { get; set; }
    /// <summary>The built-in engine's unfinished batch [BatchLo, BatchHi); every base word from BatchHi up is done.</summary>
    public long BatchLo { get; set; }
    public long BatchHi { get; set; }
    /// <summary>Mask box (-1: no batch) and prefix index, or box 0 and the sorted dictionary candidate ordinal.</summary>
    public int Box { get; set; } = -1;
    public long BoxPrefix { get; set; }
    public string? DictionaryFingerprint { get; set; }
    public long LeftoverBytes { get; set; }
    public long LeftoverCount { get; set; }
    public long LeftoverLo { get; set; }
}

/// <summary>The GPU side: hashcat on a range of base words of one mask length or file dictionary.</summary>
public interface IGpuRange
{
    /// <summary>hashcat's base word count for this length's mask arguments, or null if it cannot run them.</summary>
    Task<long?> KeyspaceAsync(IReadOnlyList<string> maskArgs, CancellationToken ct);

    /// <summary>
    /// Runs base words [skip, skip + count). Status updates go to <paramref name="onStatus"/>. Cancelling
    /// <paramref name="stop"/> stops it gracefully; the result then says how far it got.
    /// </summary>
    Task<GpuRangeResult> RunAsync(HashcatOrder order, long skip, long count, IReadOnlyCollection<int> exclude,
        Action<HashcatStatus> onStatus, CancellationToken stop);
}

public sealed class GpuRangeResult
{
    public RunOutcome Outcome { get; init; }
    /// <summary>Every base word from the run's skip up to this one (exclusive) is done.</summary>
    public long DoneUpTo { get; init; }
    public List<string> Passwords { get; init; } = new();
    public List<string> RawPasswords { get; init; } = new();
    public string? Error { get; init; }
    public bool RecheckFromStart { get; init; }
}

/// <summary>
/// Hybrid CPU + GPU masks and file dictionaries: hashcat and the built-in CPU engine run
/// at the same time. Masks use disjoint parts of the keyspace.
///
/// Mask lengths run one after another; a dictionary is one interval with rules as its amplifier.
/// Candidates are numbered as hashcat numbers them
/// (<see cref="HashcatOrder"/>: base words, each with all amplifier characters). hashcat takes base
/// words from the bottom (--skip/--limit), the built-in engine takes batches from the top, so the
/// remaining work is always one interval [Lo, Top) plus at most one unfinished CPU batch. The first
/// split follows the measured (or remembered) speeds of both sides. When the CPU runs out of work
/// while hashcat still has a long way to go, hashcat is stopped at its restore point and the rest is
/// split again; when hashcat finishes first, it starts again on what the CPU has not taken. A found
/// password on either side stops both. If hashcat fails, the CPU takes everything that is left; if the
/// CPU engine fails, hashcat does.
/// Dictionaries give hashcat its predicted share while the CPU works down from the top,
/// prefetching its next batch. The CPU can continue below hashcat's limit, so their ranges may
/// overlap. A remainder only starts hashcat again when it is worth several startups. Work stops when
/// hashcat's completed frontier meets the CPU's committed frontier, without a hashcat restart.
/// Candidates unsupported by the CPU are saved as exact expanded bytes and checked by hashcat
/// afterwards, without applying the original rules again. The checkpoint includes that file's
/// committed byte length and restore cursor; an uncommitted suffix is truncated on resume.
/// </summary>
public sealed class HybridRunner
{
    public event Action<HashcatStatus>? StatusReceived;
    public event Action<string>? OutputLine;
    public event Action<string>? Warning;

    /// <summary>Known devices (for thread planning and the integrated GPU check); null in tests.</summary>
    public IReadOnlyList<BackendDevice>? Devices { get; init; }

    // Tuning, adjustable by tests.
    /// <summary>
    /// Seconds a hashcat start costs (process start, kernel load, self-test, autotune) when nothing
    /// was measured yet. Each run measures it (time to its first speed report); on an Apple M1 Pro
    /// it is about 40 s for PDF R6, so restarts are only worth it for long remaining work.
    /// </summary>
    internal double HashcatStartupSeconds { get; init; } = 15;
    private double _startup;
    /// <summary>Seconds of CPU work per batch taken from the top.</summary>
    internal double BatchSeconds { get; init; } = 3;
    internal TimeSpan Tick { get; init; } = TimeSpan.FromSeconds(1);
    /// <summary>Starting estimates (candidates per second); 0 = remembered or derived.</summary>
    internal double InitialGpuSpeed { get; init; }
    internal double InitialCpuSpeed { get; init; }
    internal bool ForceGpu { get; init; }
    internal int? ThreadsOverride { get; init; }

    public static string RestoreFile(string dir, string session) => Path.Combine(dir, session + ".hybrid.json");
    internal static string LeftoverFile(string dir, string session) => Path.Combine(dir, session + ".hybrid-leftovers.txt");

    /// <summary>
    /// The step runs hybrid when a GPU is used, hybrid mode and the built-in engine are on, the strategy
    /// lets the CPU work next to the GPUs, and the built-in engine could run the step on its own.
    /// </summary>
    public static HybridPlan? Plan(int mode, string hashLines, PreparedAttack attack, Settings settings,
        IReadOnlyList<BackendDevice>? devices, VolumeCredentials? credentials = null, ZipPartialTarget? partial = null, bool resumeDictionary = false)
    {
        if (mode == 9400 && !Kernels.Office2007Kernel.NativeFast) return null;
        if (settings.PerformanceChoice?.Engine is "cpu" or "gpu") return null;
        if (!settings.HybridCpuGpu || settings.Strategy is not (DeviceStrategy.GpuOnly or DeviceStrategy.GpuAndCpu)) return null;
        var gpus = HashcatRunner.ActiveGpus(settings, devices);
        if (gpus.Count == 0) return null;
        // Shared power and memory made these kernels slower over complete jobs on integrated GPUs.
        if (mode is 9400 or 13600 or 22000 && gpus.All(d => d.IsIntegratedGpu)
            && settings.PerformanceChoice?.Engine != "hybrid" && !settings.PerformanceStrategyExplicit) return null;
        bool cpuAddsTooLittle = settings.PerformanceChoice?.Engine != "hybrid" && CpuAddsTooLittle(settings, devices, mode);
        if (mode is 9400 or 13000 or 12500 or 10700 or 13600 or 22000 or 29331 && settings.UseNativeCpuEngine && credentials is null
            && partial is null && attack.Stdin is null && string.IsNullOrWhiteSpace(settings.ExtraArguments)
            && !hashLines.Trim().Contains('\n') && DictionaryAttack.Parse(attack.Args) is { } dictionary
            && NativeKernels.TryCreate(mode, hashLines.Trim()) is { } kernel)
            return cpuAddsTooLittle && !resumeDictionary ? null : new HybridPlan(kernel, null) { Dictionary = dictionary };
        if (cpuAddsTooLittle) return null;
        if (NativeRunner.Plan(mode, hashLines, attack, settings, devices, ignoreGpu: true, credentials, partial) is not { } p) return null;
        // Every length must fit in 64 bits (hashcat's counters) and in hashcat's eight custom charsets.
        for (int l = p.Space.MinLength; l <= p.Space.MaxLength; l++)
        {
            if (p.Space.Keyspace(l) > long.MaxValue) return null;
            if (HashcatOrder.MaskArgs(HashcatOrder.SortedPositions(p.Space, l)) is null) return null;
        }
        return new HybridPlan(p.Kernel, p.Space);
    }

    /// <summary>
    /// True when every GPU in use is integrated (Apple silicon, a processor's own graphics) and the
    /// last hybrid attack on this mode measured the CPU at less than a quarter of hashcat's speed.
    /// Integrated GPUs share the processor's power budget and memory, so a busy CPU slows them:
    /// RAR 3 on an M1 Pro ran 8,000-11,000/s on the GPU next to the CPU engine instead of
    /// 11,500-14,000/s alone, while the CPU added about 1,700/s. hashcat then runs alone.
    /// </summary>
    public static bool CpuAddsTooLittle(Settings s, IReadOnlyList<BackendDevice>? devices, int mode)
    {
        if (s.PerformanceStrategyExplicit) return false;
        var gpus = HashcatRunner.ActiveGpus(s, devices);
        if (gpus.Count == 0 || !gpus.All(d => d.IsIntegratedGpu)) return false;
        return s.CpuSpeedByMode.TryGetValue(mode, out var cpu) && s.GpuSpeedByMode.TryGetValue(mode, out var gpu)
               && cpu > 0 && gpu > 0 && cpu < 0.25 * gpu;
    }

    /// <summary>
    /// CPU threads for the built-in engine: the thread limit from Preferences, minus one per GPU that
    /// hashcat is feeding (its host thread needs a core), unless the strategy asks for every thread.
    /// </summary>
    public static int CpuThreads(Settings s, IReadOnlyList<BackendDevice>? devices, bool hashcatRunning, IReadOnlyCollection<int>? excluded = null)
    {
        if (s.MaxCpuThreads == 0 && s.PerformanceChoice is { Engine: "hybrid", Threads: > 0 } choice)
            return Math.Clamp(choice.Threads, 1, Environment.ProcessorCount);
        if (!hashcatRunning && s.MaxCpuThreads == 0 && s.CpuPerformanceChoice is { Threads: > 0 } cpuChoice)
            return Math.Clamp(cpuChoice.Threads, 1, Environment.ProcessorCount);
        int total = s.MaxCpuThreads > 0 ? Math.Min(s.MaxCpuThreads, Environment.ProcessorCount) : Environment.ProcessorCount;
        if (!hashcatRunning || s.Strategy == DeviceStrategy.GpuAndCpu) return Math.Max(1, total);
        int gpus = Math.Max(1, HashcatRunner.ActiveGpus(s, devices).Count(d => excluded?.Contains(d.Id) != true));
        return Math.Max(1, total - gpus);
    }

    /// <summary>Runs a hybrid step with hashcat as the GPU side.</summary>
    public async Task<RunResult> RunAsync(HybridPlan plan, string hashLine, RunRequest r, HashcatTool tool, CancellationToken ct)
    {
        var runner = new HashcatRunner(tool) { KnownDevices = Devices, FalsePositives = FalsePositives };
        runner.OutputLine += l => OutputLine?.Invoke(l);
        GuardEvents?.Invoke(runner);
        if (plan.Dictionary is { } dictionary && !await dictionary.PrepareAsync(tool, r.Mode, ct))
        {
            if (ct.IsCancellationRequested) return new RunResult { Outcome = RunOutcome.Aborted, ExitCode = 2 };
            if (r.Restore && File.Exists(RestoreFile(r.SessionDir, r.SessionName)))
                return new RunResult { Outcome = RunOutcome.Error, ExitCode = -1,
                    Error = "The dictionary keyspace no longer matches this hybrid checkpoint. Start a new session." };
            Warning?.Invoke("The dictionary keyspace could not be bounded for the CPU engine; hashcat runs this step alone.");
            runner.StatusReceived += s => StatusReceived?.Invoke(s);
            return await runner.RunAsync(r, ct);
        }
        var gpu = new HashcatRange(tool, runner, r, plan.Dictionary is null ? OrderedMarkov.Ensure(r.SessionDir) : null);
        return await RunAsync(plan, hashLine, r, gpu, ct);
    }

    /// <summary>Hits rejected by the confirmation check on either side, over all runs of this runner (a session).</summary>
    internal FalsePositiveLog FalsePositives => _falsePositives ??= new FalsePositiveLog(l => OutputLine?.Invoke(l));
    private FalsePositiveLog? _falsePositives;

    /// <summary>Lets the caller subscribe to the temperature guard events of the hashcat runner used.</summary>
    public Action<HashcatRunner>? GuardEvents { get; init; }

    internal async Task<RunResult> RunAsync(HybridPlan plan, string hashLine, RunRequest r, IGpuRange gpu, CancellationToken ct)
    {
        var s = r.Settings;
        if (r.Mode == 29331) NativeKernels.ConfigureWhirlpool(s);
        NativeKernels.ResetCpuPath(r.Mode);
        string restoreFile = RestoreFile(r.SessionDir, r.SessionName);
        HybridResumePoint? resume = null;
        if (r.Restore && File.Exists(restoreFile))
            try { resume = JsonSerializer.Deserialize<HybridResumePoint>(await File.ReadAllTextAsync(restoreFile, CancellationToken.None)); }
            catch (JsonException) when (plan.Dictionary is not null)
            { return new RunResult { Outcome = RunOutcome.Error, Error = "The dictionary hybrid checkpoint is invalid. Start a new session.", ExitCode = -1 }; }
            catch (JsonException) { }

        var space = plan.Space;
        if (r.Restore && plan.Dictionary is { } restoredDictionary && (resume is null || resume.Length != 0
            || resume.BaseCount != restoredDictionary.BaseCount || resume.Lo < 0 || resume.Lo > resume.BatchLo
            || resume.BatchLo > resume.BatchHi || resume.BatchHi > resume.BaseCount || resume.BoxPrefix < 0
            || resume.LeftoverBytes < 0 || resume.LeftoverCount < 0 || resume.LeftoverLo < 0 || resume.LeftoverLo > resume.LeftoverCount
            || resume.BoxPrefix > (resume.BatchHi - resume.BatchLo) * restoredDictionary.AmplifierCount
            || (resume.BatchLo < resume.BatchHi ? resume.Box != 0 : resume.Box != -1 || resume.BoxPrefix != 0)))
            return new RunResult { Outcome = RunOutcome.Error, Error = "The dictionary hybrid checkpoint is invalid. Start a new session.", ExitCode = -1 };
        if (resume is not null && plan.Dictionary is { } dictionary && resume.DictionaryFingerprint != dictionary.Fingerprint)
            return new RunResult { Outcome = RunOutcome.Error, Error = "The dictionary or rules changed since this hybrid checkpoint. Start a new session.", ExitCode = -1 };
        if (plan.Dictionary is not null && resume is { LeftoverCount: > 0 } && (!File.Exists(LeftoverFile(r.SessionDir, r.SessionName))
            || new FileInfo(LeftoverFile(r.SessionDir, r.SessionName)).Length < resume.LeftoverBytes))
            return new RunResult { Outcome = RunOutcome.Error, Error = "The deferred dictionary candidates are missing or incomplete.", ExitCode = -1 };
        int minLength = space?.MinLength ?? 0, maxLength = space?.MaxLength ?? 0;
        int threads = ThreadsOverride ?? CpuThreads(s, Devices, true);
        double cpuSpeed = InitialCpuSpeed > 0 ? InitialCpuSpeed
            : s.CpuSpeedByMode.TryGetValue(r.Mode, out var known) && known > 0 ? known : plan.Kernel.SpeedHint * threads;
        double gpuSpeed = InitialGpuSpeed > 0 ? InitialGpuSpeed : s.GpuSpeedByMode.GetValueOrDefault(r.Mode);
        _startup = InitialGpuSpeed > 0 || InitialCpuSpeed > 0 ? HashcatStartupSeconds
            : s.GpuStartupByMode.TryGetValue(r.Mode, out var st) && st > 0 ? st : HashcatStartupSeconds;
        var excluded = new HashSet<int>();
        OutputLine?.Invoke($"Hybrid CPU + GPU: hashcat on the GPUs, built-in CPU engine ({plan.Kernel.Name}) on {threads} thread(s), " +
                           (plan.Dictionary is not null ? "dictionary and rules" : $"lengths {minLength}-{maxLength}") + (resume is not null ? ", resuming" : ""));
        DebugLog.Info($"Hybrid: mode {r.Mode}, kernel {plan.Kernel.Name}, threads {threads}, cpu est {cpuSpeed:F0}/s, gpu est {gpuSpeed:F0}/s, " +
                      $"lengths {minLength}-{maxLength}, resume {resume?.Length}:{resume?.Lo}:{resume?.BatchLo}:{resume?.BatchHi}:{resume?.Box}:{resume?.BoxPrefix}");

        var proc = Process.GetCurrentProcess();
        ProcessPriorityClass? previous = null;
        if (NativeRunner.LowersProcessPriority)
            try { previous = proc.PriorityClass; proc.PriorityClass = NativeRunner.ProcessClassFor(s.Priority); }
            catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception or PlatformNotSupportedException) { }
        HashcatStatus? last = null;
        bool gpuAlive = true;
        try
        {
            int startLen = Math.Max(minLength, resume?.Length ?? minLength);
            for (int len = startLen; len <= maxLength; len++)
            {
                if (len > plan.Kernel.MaxPasswordLength) break;
                var sorted = space is not null ? HashcatOrder.SortedPositions(space, len) : [];
                HashcatOrder? order = plan.Dictionary is { } dict ? new HashcatOrder(dict) : null;
                // A length the CPU finishes before hashcat would be up and running stays on the CPU.
                bool worthGpu = gpuAlive && (ForceGpu || (double)(order?.Candidates ?? (long)space!.Keyspace(len)) / cpuSpeed > 2 * _startup);
                if (worthGpu && plan.Dictionary is null)
                {
                    long? baseCount = await gpu.KeyspaceAsync(HashcatOrder.MaskArgs(sorted)!, ct);
                    order = baseCount is { } bc ? HashcatOrder.FromKeyspace(sorted, bc) : null;
                    if (order is null)
                    {
                        if (ct.IsCancellationRequested) return Stopped(last);
                        Warning?.Invoke($"hashcat's keyspace for length {len} could not be matched; this length runs on the CPU only.");
                    }
                }
                bool gpuUsable = gpuAlive && order is not null;
                // A short remainder may now run on the CPU alone; keep the checkpoint's numbering.
                if (order is null && resume is not null && resume.Length == len && plan.Dictionary is null)
                    order = HashcatOrder.FromKeyspace(sorted, resume.BaseCount);
                order ??= HashcatOrder.WithAmplifier(sorted, len);
                var lr = resume is not null && resume.Length == len && resume.BaseCount == order.BaseCount ? resume : null;
                var job = new LengthJob(this, plan.Kernel, order, len, r, gpu, gpuUsable, lr, cpuSpeed, gpuSpeed, excluded);
                var outcome = await job.RunAsync(ct);
                last = job.LastStatus ?? last;
                cpuSpeed = job.CpuSpeed;
                gpuSpeed = job.GpuSpeed;
                if (job.GpuFailed) gpuAlive = false;
                // Remembered for the next attack's first split, once measured for a while (not a warm-up).
                if (job.GpuSpeedMeasured && job.GpuSamples >= 5) s.GpuSpeedByMode[r.Mode] = gpuSpeed;
                if (job.CpuSpeedMeasured && job.CpuSamples >= 10) s.CpuSpeedByMode[r.Mode] = cpuSpeed;
                if (job.StartupMeasured) s.GpuStartupByMode[r.Mode] = _startup;
                switch (outcome)
                {
                    case LengthOutcome.Found:
                        TryDelete(restoreFile);
                        if (plan.Dictionary is not null) TryDelete(LeftoverFile(r.SessionDir, r.SessionName));
                        var pw = job.FoundByCpu is { } cpuPw ? [await NativeRunner.RecordFoundAsync(s, NativeRunner.MatchedHashLine(plan.Kernel, hashLine, cpuPw), cpuPw, r.Mode == 9400 || r.ConfirmPassword is not null || plan.Dictionary is not null ? r.PasswordCachePath ?? s.PotfilePath : null)] : job.FoundByGpu;
                        if (r.Mode == 9400 || plan.Dictionary is not null)
                        {
                            if (job.FoundByCpu is { } bytes) pw = [DictionaryPlain(bytes)];
                            else if (job.FoundByGpuRaw.Count > 0) pw = job.FoundByGpuRaw.Select(raw => DictionaryPlain(PasswordConfirmation.PlainBytes(raw))).ToList();
                        }
                        OutputLine?.Invoke(job.FoundByCpu is not null ? "Found by the built-in CPU engine." : "Found by hashcat.");
                        return new RunResult { Outcome = RunOutcome.Cracked, ExitCode = 0, Passwords = pw, LastStatus = last };
                    case LengthOutcome.Stopped:
                        await File.WriteAllTextAsync(restoreFile, JsonSerializer.Serialize(job.ResumePoint()), CancellationToken.None);
                        return Stopped(last);
                    case LengthOutcome.Failed:
                        if (plan.Dictionary is not null)
                            await File.WriteAllTextAsync(restoreFile, JsonSerializer.Serialize(job.ResumePoint()), CancellationToken.None);
                        else TryDelete(restoreFile);
                        return new RunResult { Outcome = RunOutcome.Error, ExitCode = -1,
                            Error = plan.Dictionary is not null ? "The dictionary attack could not finish. Its checkpoint was retained for resume."
                                : "Both hashcat and the built-in CPU engine failed.", LastStatus = last };
                }
            }
            TryDelete(restoreFile);
            if (plan.Dictionary is not null) TryDelete(LeftoverFile(r.SessionDir, r.SessionName));
            return new RunResult { Outcome = RunOutcome.Exhausted, ExitCode = 1, LastStatus = last };
        }
        finally
        {
            if (previous is { } pc)
                try { proc.PriorityClass = pc; } catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception) { }
        }

        static RunResult Stopped(HashcatStatus? last) => new() { Outcome = RunOutcome.Aborted, ExitCode = 2, LastStatus = last };
    }

    private static void TryDelete(string f) { try { File.Delete(f); } catch (IOException) { } }

    internal static string DictionaryPlain(byte[] password)
    {
        try
        {
            string text = new UTF8Encoding(false, true).GetString(password);
            if (!text.Any(char.IsControl) && !(text.StartsWith("$HEX[", StringComparison.Ordinal) && text.EndsWith(']'))) return text;
        }
        catch (DecoderFallbackException) { }
        return PasswordConfirmation.HexPlain(password);
    }

    private enum LengthOutcome { Exhausted, Found, Stopped, Failed }

    /// <summary>One length: the two engines and the split between them.</summary>
    private sealed class LengthJob
    {
        private readonly HybridRunner _owner;
        private readonly NativeKernel _kernel;
        private readonly HashcatOrder _order;
        private readonly int _len;
        private readonly RunRequest _r;
        private readonly IGpuRange _gpu;
        private readonly HashSet<int> _excluded;
        private readonly object _lock = new();
        private readonly long _n, _a;

        // Remaining work: [_lo, _top) plus the CPU batch [_top, _doneFrom); [0, _lo) and [_doneFrom, N) are done.
        private long _lo, _top, _doneFrom;
        private long _hcEnd;              // hashcat's current range is [_lo, _hcEnd); == _lo when it is not running
        private bool _hcRunning, _hcReported, _gpuDead, _cpuDead, _finish;
        private bool _gpuUsable;
        private long _hcProgress;         // candidates done in the current hashcat run
        private long _hcLive;             // hashcat's latest restore point in the current run
        private long _batchDone;          // candidates done in the CPU batch
        private int _box = -1;            // CPU: current box of the batch
        private long _boxPrefix;          // CPU: resume prefix in that box (on stop)
        private HybridResumePoint? _pending;
        private List<DeviceSpeed> _gpuDevices = new();
        private DateTime _gpuStatusAt;
        private int _rebalances, _gpuStatuses;
        private bool _rebalanceRequested;
        private bool _correctedThisRun;
        private readonly SemaphoreSlim _work = new(0);
        private readonly ManualResetEventSlim _decided = new(false);   // the first hashcat decision is made
        private readonly CancellationTokenSource _found = new();
        private readonly CancellationTokenSource _dictionaryDone = new();
        private CancellationTokenSource? _rebalance;
        private FileStream? _leftovers;
        private long _leftoverCount, _leftoverBytes, _leftoverLo, _leftoverProgress, _cpuHashed;
        private bool _leftoverRunning;
        private bool _cpuHashing;
        private int _cpuThreads;

        public double CpuSpeed { get; private set; }
        public double GpuSpeed { get; private set; }
        public bool GpuSpeedMeasured { get; private set; }
        public bool CpuSpeedMeasured { get; private set; }
        public int CpuSamples { get; private set; }
        public int GpuSamples { get { lock (_lock) return _gpuStatuses; } }
        public bool StartupMeasured { get; private set; }
        private Stopwatch? _hcStarted;
        public bool GpuFailed { get { lock (_lock) return _gpuDead; } }
        public byte[]? FoundByCpu { get; private set; }
        public List<string> FoundByGpu { get; private set; } = new();
        public List<string> FoundByGpuRaw { get; private set; } = new();
        public HashcatStatus? LastStatus { get; private set; }
        private readonly long _resumedFrom;
        private readonly long _started = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

        public LengthJob(HybridRunner owner, NativeKernel kernel, HashcatOrder order, int len, RunRequest r, IGpuRange gpu, bool gpuUsable,
            HybridResumePoint? resume, double cpuSpeed, double gpuSpeed, HashSet<int> excluded)
        {
            _owner = owner; _kernel = kernel; _order = order; _len = len; _r = r; _gpu = gpu; _gpuUsable = gpuUsable; _excluded = excluded;
            _n = order.BaseCount;
            _a = order.AmplifierCount;
            if (order.Dictionary is not null)
            {
                _leftoverCount = resume?.LeftoverCount ?? 0;
                _leftoverBytes = resume?.LeftoverBytes ?? 0;
                _leftoverLo = resume?.LeftoverLo ?? 0;
                string path = LeftoverFile(r.SessionDir, r.SessionName);
                if (File.Exists(path))
                    using (var file = new FileStream(path, FileMode.Open, FileAccess.Write, FileShare.Read)) file.SetLength(_leftoverBytes);
            }
            CpuSpeed = Math.Max(1, cpuSpeed);
            GpuSpeed = gpuSpeed;
            _lo = 0; _top = _n; _doneFrom = _n;
            if (resume is not null)
            {
                _lo = Math.Clamp(resume.Lo, 0, _n);
                _doneFrom = Math.Clamp(resume.BatchHi, _lo, _n);
                _top = Math.Clamp(resume.BatchLo, _lo, _doneFrom);
                if (resume.Box >= 0 && _top < _doneFrom)
                {
                    _pending = resume;
                    _box = resume.Box;
                    _boxPrefix = resume.BoxPrefix;
                    if (_order.Dictionary is not null)
                    {
                        _batchDone = resume.BoxPrefix;
                    }
                    else
                    {
                        var boxes = _order.Boxes(_top, _doneFrom);
                        _batchDone = boxes.Take(resume.Box).Sum(b => (long)b.Keyspace(_len));
                        if (resume.Box < boxes.Count) _batchDone += resume.BoxPrefix * boxes[resume.Box].Positions[_len - 1].Length;
                    }
                }
                else _top = _doneFrom;
            }
            _hcEnd = _lo;
            _resumedFrom = DoneCandidates();
        }

        public HybridResumePoint ResumePoint()
        {
            lock (_lock)
                return new HybridResumePoint
                {
                    Length = _len, BaseCount = _n, Lo = _lo, BatchLo = _top, BatchHi = _doneFrom,
                    Box = _top < _doneFrom ? Math.Max(0, _box) : -1, BoxPrefix = _top < _doneFrom ? _boxPrefix : 0,
                    DictionaryFingerprint = _order.Dictionary?.Fingerprint,
                    LeftoverCount = _leftoverCount, LeftoverBytes = _leftoverBytes, LeftoverLo = _leftoverLo,
                };
        }

        private long DoneCandidates()
        {
            lock (_lock)
                return Math.Max(0, checked(_lo * _a + Math.Min(_hcProgress, (_hcEnd - _lo) * _a) + (_n - _doneFrom) * _a + _batchDone)
                    - (_order.Dictionary is null ? 0 : _leftoverCount - _leftoverLo - _leftoverProgress));
        }

        private int Threads(bool hashcatRunning)
        {
            lock (_lock)
            {
                int n = _owner.ThreadsOverride ?? CpuThreads(_r.Settings, _owner.Devices, hashcatRunning, _excluded);
                // While hashcat starts (self-test, autotune) it needs the processor: with every core busy
                // its start took 60-70 s instead of a few seconds on an M1 Pro (RAR 3).
                return _hcRunning && !_hcReported ? Math.Max(1, n / 2) : n;
            }
        }

        public async Task<LengthOutcome> RunAsync(CancellationToken ct)
        {
            using var stopOrFound = CancellationTokenSource.CreateLinkedTokenSource(ct, _found.Token, _dictionaryDone.Token);
            var cpu = Task.Factory.StartNew(() => CpuLoop(stopOrFound.Token), TaskCreationOptions.LongRunning);
            Task<GpuRangeResult>? gpuRun = null;
            long runSkip = 0;
            long lastCpuDone = DoneCpu();
            var lastTick = Stopwatch.StartNew();

            while (true)
            {
                if (gpuRun is null && !ct.IsCancellationRequested && !_found.IsCancellationRequested)
                {
                    long skip = 0, count = 0;
                    bool drained = false;
                    lock (_lock)
                    {
                        if (_gpuUsable && !_gpuDead && _top > _lo)
                        {
                            long x = _cpuDead ? _top : SplitPoint();
                            double cpuAlone = (double)(_top - _lo) * _a / CpuSpeed;
                            double startupCost = _order.Dictionary is not null ? 4 : 2;
                            if (x > _lo && (_owner.ForceGpu || _cpuDead || cpuAlone > startupCost * _owner._startup))
                            {
                                skip = _lo; count = x - _lo;
                                _hcEnd = x; _hcRunning = true; _hcReported = false; _hcProgress = 0; _hcLive = _lo;
                                _hcStarted = Stopwatch.StartNew();
                                _correctedThisRun = false; _gpuStatuses = 0;
                            }
                        }
                        drained = !_hcRunning && _top <= _lo && _top == _doneFrom && _pending is null;
                        if (!_hcRunning && _cpuDead && (_top > _lo || _doneFrom > _top) && (_gpuDead || !_gpuUsable)) drained = true;   // nobody left
                    }
                    _decided.Set();
                    if (count > 0)
                    {
                        runSkip = skip;
                        _rebalance?.Dispose();
                        _rebalance = CancellationTokenSource.CreateLinkedTokenSource(stopOrFound.Token);
                        List<int> exclude;
                        lock (_lock) { exclude = _excluded.ToList(); _rebalanceRequested = false; }
                        _work.Release();   // the CPU's floor moved
                        DebugLog.Info($"Hybrid length {_len}: hashcat base words [{skip}, {skip + count}) of {_n}, CPU from {_top} down");
                        gpuRun = _gpu.RunAsync(_order, skip, count, exclude, OnGpuStatus, _rebalance.Token);
                    }
                    else if (drained) break;
                }

                var waits = new List<Task> { Task.Delay(_owner.Tick, CancellationToken.None), cpu };
                if (gpuRun is not null) waits.Add(gpuRun);
                await Task.WhenAny(waits);

                if (gpuRun is { IsCompleted: true })
                {
                    var res = await gpuRun;
                    gpuRun = null;
                    HandleGpuResult(res, runSkip, ct);
                }

                // Speeds and status.
                double dt = lastTick.Elapsed.TotalSeconds;
                if (dt >= Math.Min(0.5, 5 * _owner.Tick.TotalSeconds))
                {
                    long cpuDone = DoneCpu();
                    if (cpuDone > lastCpuDone && !CpuIdle())
                    {
                        double sample = (cpuDone - lastCpuDone) / dt;
                        CpuSpeed = CpuSpeedMeasured ? 0.7 * CpuSpeed + 0.3 * sample : sample;
                        CpuSpeedMeasured = true;
                        CpuSamples++;
                    }
                    lastCpuDone = cpuDone;
                    lastTick.Restart();
                    Emit();
                }

                if (ct.IsCancellationRequested || _found.IsCancellationRequested || _dictionaryDone.IsCancellationRequested)
                {
                    _rebalance?.Cancel();
                    if (gpuRun is not null)
                    {
                        var stopping = Stopwatch.StartNew();
                        DebugLog.Info("Hybrid waiting for hashcat to stop");
                        HandleGpuResult(await gpuRun, runSkip, ct); gpuRun = null;
                        DebugLog.Info($"Hybrid hashcat stop wait: {stopping.Elapsed.TotalSeconds:F3} s");
                    }
                    break;
                }
                if (gpuRun is not null) MaybeRebalance();
                if (cpu.IsCompleted && !_cpuDead && !_finish)
                {
                    // The CPU loop only ends early on an error (it sets _cpuDead) or a stop/find.
                    lock (_lock) _cpuDead = true;
                }
            }

            lock (_lock) _finish = true;
            _work.Release();
            await cpu;
            if (_leftovers is not null) { _leftovers.Flush(true); _leftovers.Dispose(); _leftovers = null; }
            if (_dictionaryDone.IsCancellationRequested)
                lock (_lock) { _lo = _top = _doneFrom = _n; _batchDone = 0; _hcEnd = _lo; _pending = null; }
            _rebalance?.Dispose();
            Emit();
            if (FoundByCpu is not null || FoundByGpu.Count > 0) return LengthOutcome.Found;
            if (ct.IsCancellationRequested) return LengthOutcome.Stopped;
            lock (_lock)
                if (_lo < _top || _top < _doneFrom) return LengthOutcome.Failed;   // both engines failed
            if (_order.Dictionary is not null && _leftoverLo < _leftoverCount) return await RunLeftoversAsync(ct);
            return LengthOutcome.Exhausted;
        }

        private long DoneCpu() { lock (_lock) return _order.Dictionary is not null ? _cpuHashed : (_n - _doneFrom) * _a + _batchDone; }

        private bool CpuIdle() { lock (_lock) return _top == _doneFrom && _pending is null; }

        /// <summary>The end of hashcat's next range: both sides should finish together, hashcat after its start-up.</summary>
        private long SplitPoint()
        {
            double work = (double)(_top - _lo) * _a;
            double sg = GpuSpeed > 0 ? GpuSpeed : CpuSpeed * 4;   // unknown GPU: corrected once hashcat reports
            double t = (work + sg * _owner._startup) / (CpuSpeed + sg);
            double gpuCandidates = sg * Math.Max(0, t - _owner._startup);
            long x = _lo + (long)Math.Min(_top - _lo, Math.Floor(gpuCandidates / _a));
            if (x <= _lo) return _lo;
            if (x >= _top) return _top;
            // A boundary between values of the last character (or else on a coarse digit) keeps the
            // CPU's boxes large.
            long unit = _order.LastPositionUnit;
            if (UnitIsSmall() && _top - _lo >= 4 * unit)
            {
                long rounded = (x + unit / 2) / unit * unit;
                return Math.Clamp(rounded, _lo, _top);
            }
            return Math.Max(_lo + 1, _order.AlignDown(x, Math.Max(1, (x - _lo) / 64), _lo));
        }

        /// <summary>One value of the last character is at most a minute of CPU work.</summary>
        private bool UnitIsSmall() => _order.LastPositionUnit > 1 && (double)_order.LastPositionUnit * _a / CpuSpeed <= 60;

        private void OnGpuStatus(HashcatStatus st)
        {
            lock (_lock)
            {
                if (!_hcRunning) return;
                if (st.Status == 3 && !_hcReported && _hcStarted is { } sw)
                {
                    // Start-up cost of this run: from launch to its first speed report.
                    double measured = sw.Elapsed.TotalSeconds;
                    _owner._startup = StartupMeasured ? 0.5 * _owner._startup + 0.5 * measured : measured;
                    StartupMeasured = true;
                    DebugLog.Info($"Hybrid GPU first status: startup {measured:F3} s, range [{_lo}, {_hcEnd}), speed {st.TotalSpeed:F0}/s");
                }
                if (st.Status == 3) { _hcReported = true; _gpuStatuses++; }
                _hcProgress = Math.Max(0, st.ProgressDone);
                if (st.RestorePoint >= _lo && st.RestorePoint <= _hcEnd) _hcLive = Math.Max(_hcLive, st.RestorePoint);
                _gpuDevices = st.Devices.Where(d => !d.Type.Contains("CPU", StringComparison.OrdinalIgnoreCase)).ToList();
                _gpuStatusAt = DateTime.UtcNow;
                double speed = st.TotalSpeed;
                if (st.Status == 3 && speed > 0)
                {
                    GpuSpeed = GpuSpeedMeasured ? 0.7 * GpuSpeed + 0.3 * speed : speed;
                    GpuSpeedMeasured = true;
                }
            }
            if (_order.Dictionary is not null && _hcLive >= _doneFrom)
            {
                DebugLog.Info($"Hybrid dictionary fronts met: GPU {_hcLive}, CPU {_doneFrom}");
                _dictionaryDone.Cancel();
            }
            CheckIntegratedGpus(st);
        }

        /// <summary>
        /// An integrated GPU next to a discrete one costs a CPU thread (hashcat's host thread) and shares
        /// the processor's power budget. When it is slower than that thread on the built-in engine, the
        /// next hashcat runs leave it out and the thread goes back to the CPU engine.
        /// </summary>
        private void CheckIntegratedGpus(HashcatStatus st)
        {
            var known = _owner.Devices;
            if (known is null || st.Status != 3 || _gpuStatuses < 3 || _r.Settings.DeviceSelectionExplicit
                || _r.Settings.PerformanceStrategyExplicit || _r.Settings.DisabledDeviceKeys.Count > 0 || _r.Settings.DisabledDevices.Count > 0) return;
            var active = HashcatRunner.ActiveGpus(_r.Settings, known);
            if (!active.Any(d => !d.IsIntegratedGpu)) return;
            double perThread = CpuSpeed / Math.Max(1, Threads(true));
            foreach (var dev in st.Devices)
            {
                var k = known.FirstOrDefault(d => d.Id == dev.Id);
                if (k is not { IsIntegratedGpu: true } || dev.Speed <= 0 || dev.Speed >= perThread) continue;
                lock (_lock) if (!_excluded.Add(dev.Id)) continue;
                _owner.Warning?.Invoke($"{k.Name} (integrated GPU) tests {dev.Speed:N0}/s, less than the CPU thread it ties up ({perThread:N0}/s); " +
                                       "the next hashcat runs leave it out and the built-in engine gets that thread.");
            }
        }

        private void HandleGpuResult(GpuRangeResult res, long runSkip, CancellationToken ct)
        {
            lock (_lock)
            {
                long end = _hcEnd;
                if (res.RecheckFromStart) _hcLive = runSkip;
                _hcRunning = false;
                _hcProgress = 0;
                switch (res.Outcome)
                {
                    case RunOutcome.Cracked:
                        FoundByGpu = res.Passwords;
                        FoundByGpuRaw = res.RawPasswords;
                        _lo = Math.Clamp(res.DoneUpTo, runSkip, end);
                        _found.Cancel();
                        break;
                    case RunOutcome.Exhausted:
                        _lo = end;
                        if (_order.Dictionary is not null && end >= _doneFrom) _dictionaryDone.Cancel();
                        break;
                    case RunOutcome.Aborted:
                        _lo = Math.Clamp(res.DoneUpTo, runSkip, end);
                        // Not stopped by us: hashcat quit on its own (for example "no devices"), do not loop.
                        if (!_rebalanceRequested && !ct.IsCancellationRequested && !_found.IsCancellationRequested && !_dictionaryDone.IsCancellationRequested) _gpuDead = true;
                        break;
                    default:
                        _gpuDead = true;
                        _lo = Math.Clamp(Math.Max(res.DoneUpTo, _hcLive), runSkip, end);
                        break;
                }
                // The CPU may already have taken base words from above the old range end only; never below.
                _lo = Math.Min(_lo, _top);
                _hcEnd = _lo;
            }
            if (res.Outcome == RunOutcome.Error && !ct.IsCancellationRequested)
                _owner.Warning?.Invoke("hashcat stopped with an error; the built-in CPU engine takes over the rest of this step. " + (res.Error ?? ""));
            _work.Release();
        }

        /// <summary>
        /// Stops hashcat early (at its restore point) when the split is clearly off: the CPU has nothing
        /// left while hashcat still needs a long time, or, once hashcat's speed is known, it would finish
        /// much later than the CPU. The next run gets a fresh split.
        /// </summary>
        private void MaybeRebalance()
        {
            if (_order.Dictionary is not null) return;
            bool stop = false;
            string why = "";
            lock (_lock)
            {
                if (!_hcRunning || !_hcReported || _cpuDead || _rebalances >= 6 || GpuSpeed <= 0) return;
                double gpuLeft = (double)(_hcEnd - _hcLive) * _a / GpuSpeed;
                double restart = 3 * _owner._startup;
                bool cpuIdle = _top <= _hcEnd && _top == _doneFrom && _pending is null;
                double cpuLeft = ((double)(_top - _hcEnd) * _a + Math.Max(0, (_doneFrom - _top) * _a - _batchDone)) / CpuSpeed;
                if (cpuIdle && gpuLeft > restart)
                {
                    stop = true;
                    why = $"CPU finished its part, hashcat has about {gpuLeft:F0} s left";
                }
                else if (!_correctedThisRun && _gpuStatuses >= 3)
                {
                    _correctedThisRun = true;
                    if (gpuLeft - cpuLeft > 5 * _owner._startup)
                    {
                        stop = true;
                        why = $"hashcat would need {gpuLeft:F0} s, the CPU {cpuLeft:F0} s";
                    }
                }
                if (stop) { _rebalances++; _rebalanceRequested = true; }
            }
            if (!stop) return;
            DebugLog.Info($"Hybrid length {_len}: rebalancing ({why})");
            _owner.OutputLine?.Invoke($"Rebalancing CPU and GPU work: {why}.");
            _rebalance?.Cancel();
        }

        private void Emit()
        {
            HashcatStatus st;
            lock (_lock)
            {
                var devices = new List<DeviceSpeed>();
                if (_hcRunning && DateTime.UtcNow - _gpuStatusAt < TimeSpan.FromSeconds(10)) devices.AddRange(_gpuDevices);
                devices.Add(new DeviceSpeed { Id = 0, Name = $"CPU (built-in engine, {NativeKernels.CpuPath(_r.Mode, actualOnly: true)}, {_cpuThreads} threads)", Type = "CPU",
                    Speed = CpuIdle() || _order.Dictionary is not null && !_cpuHashing ? 0 : CpuSpeed });
                st = new HashcatStatus
                {
                    Status = 3,
                    MaskLength = _order.Dictionary is null ? _len : null,
                    GuessBase = _order.Dictionary is not null ? _leftoverRunning ? "deferred dictionary candidates" : "dictionary" : "",
                    ProgressDone = Math.Min(DoneCandidates(), _n * _a),
                    ProgressTotal = _n * _a,
                    ResumedFrom = _resumedFrom,
                    RestorePoint = _lo,
                    TimeStart = _started,
                    TotalHashes = 1,
                    Devices = devices,
                };
            }
            LastStatus = st;
            _owner.StatusReceived?.Invoke(st);
        }

        // ------------------------------------------------------------ CPU side

        private void CpuLoop(CancellationToken stop)
        {
            try { _decided.Wait(TimeSpan.FromSeconds(5), stop); } catch (OperationCanceledException) { return; }
            using var exportStop = CancellationTokenSource.CreateLinkedTokenSource(stop);
            Task<List<byte[]>>? prefetched = null;
            long fetchLo = 0, fetchHi = 0;
            try
            {
                Stopwatch? idle = null;
                while (!stop.IsCancellationRequested)
                {
                    long lo, hi;
                    int box0;
                    long prefix0;
                    bool hashcatRunning;
                    lock (_lock)
                    {
                        if (_finish) return;
                        hashcatRunning = _hcRunning;
                        if (_pending is { } p)
                        {
                            lo = _top; hi = _doneFrom; box0 = p.Box; prefix0 = p.BoxPrefix;
                            _pending = null;
                        }
                        else
                        {
                            long floor = _hcRunning ? _order.Dictionary is not null ? _hcLive : _hcEnd : _lo;
                            if (_top <= floor) { lo = hi = 0; box0 = -1; prefix0 = 0; }
                            else
                            {
                                long size = Math.Max(1, (long)(CpuSpeed * _owner.BatchSeconds / _a));
                                if (_order.Dictionary is not null) size = Math.Max(1, DictionaryAttack.MaxBatchCandidates / _a);
                                // Whole values of the last character when one takes at most a minute.
                                long unit = _order.LastPositionUnit;
                                bool starting = _hcRunning && !_hcReported;   // short batches until hashcat is up
                                if (!starting && unit > size && UnitIsSmall() && _top - floor >= unit) size = unit;
                                hi = _top;
                                lo = prefetched is not null && fetchHi == hi ? fetchLo : _order.AlignDown(hi - size, size, floor);
                                if (lo >= hi) lo = Math.Max(floor, hi - 1);
                                _top = lo;
                                box0 = 0; prefix0 = 0;
                            }
                        }
                        if (_order.Dictionary is not null) _batchDone = prefix0;
                        else if (box0 == 0 && prefix0 == 0) _batchDone = 0;
                        if (box0 >= 0) { _box = box0; _boxPrefix = prefix0; }
                    }
                    if (box0 < 0)
                    {
                        if (_order.Dictionary is not null && _doneFrom <= (_hcRunning ? _hcLive : _lo)) { _dictionaryDone.Cancel(); return; }
                        if (idle is null) { idle = Stopwatch.StartNew(); DebugLog.Info("Hybrid CPU waiting at GPU boundary"); }
                        _work.Wait(200);
                        continue;
                    }
                    if (idle is not null) { DebugLog.Info($"Hybrid CPU boundary wait ended after {idle.Elapsed.TotalSeconds:F3} s"); idle = null; }
                    bool completed;
                    if (_order.Dictionary is { } dictionary)
                    {
                        var waiting = Stopwatch.StartNew();
                        DebugLog.Info($"Hybrid CPU export wait: base words [{lo}, {hi}), prefetched {prefetched is not null}");
                        var candidates = (prefetched is not null && fetchLo == lo && fetchHi == hi ? prefetched
                            : dictionary.ReadCandidates(lo, hi - lo, exportStop.Token)).GetAwaiter().GetResult();
                        prefetched = null;
                        DebugLog.Info($"Hybrid CPU export ready: [{lo}, {hi}), {candidates.Count} candidates, {waiting.Elapsed.TotalSeconds:F3} s");
                        long floor;
                        lock (_lock) floor = _hcRunning ? _hcLive : _lo;
                        fetchHi = lo;
                        fetchLo = Math.Max(floor, lo - Math.Max(1, DictionaryAttack.MaxBatchCandidates / _a));
                        if (fetchHi > fetchLo && !stop.IsCancellationRequested)
                            prefetched = dictionary.ReadCandidates(fetchLo, fetchHi - fetchLo, exportStop.Token);
                        completed = RunDictionaryBatch(dictionary, lo, hi, prefix0, hashcatRunning, stop, candidates);
                    }
                    else completed = RunBatch(lo, hi, box0, prefix0, hashcatRunning, stop);
                    if (!completed) return;
                    lock (_lock)
                    {
                        _doneFrom = lo;
                        _batchDone = 0;
                        _box = -1;
                        if (_order.Dictionary is not null && _doneFrom <= (_hcRunning ? _hcLive : _lo)) _dictionaryDone.Cancel();
                    }
                }
            }
            catch (OperationCanceledException) when (stop.IsCancellationRequested) { }
            catch (Exception ex)
            {
                DebugLog.Warn("Hybrid CPU engine failed: " + ex);
                lock (_lock)
                {
                    _cpuDead = true;
                    _top = _doneFrom;   // its unfinished batch goes back to hashcat
                    _batchDone = 0;
                    _box = -1;
                    _pending = null;
                }
                _owner.Warning?.Invoke("The built-in CPU engine failed (" + ex.Message + "); hashcat takes over the rest of this step.");
            }
            finally
            {
                lock (_lock) _cpuHashing = false;
                exportStop.Cancel();
                if (prefetched is not null)
                    try { prefetched.GetAwaiter().GetResult(); } catch (Exception) { }
                DebugLog.Info("Hybrid CPU stopped");
            }
        }

        private bool RunDictionaryBatch(DictionaryAttack dictionary, long lo, long hi, long from, bool hashcatRunning, CancellationToken stop, List<byte[]>? prepared = null)
        {
            var candidates = prepared ?? dictionary.ReadCandidates(lo, hi - lo, stop).GetAwaiter().GetResult();
            bool Verify(ReadOnlySpan<byte> password) => _kernel is Kernels.Rar5Kernel rar5 && password.Length > rar5.MaxPasswordLength
                ? rar5.VerifyDictionaryPassword(password) : _kernel.Verify(password);
            // Deterministic grouping fills vector lanes and makes the saved ordinal independent of stdout delivery order.
            candidates.Sort((a, b) => a.Length != b.Length ? a.Length.CompareTo(b.Length) : a.AsSpan().SequenceCompareTo(b));
            if (from < 0 || from > candidates.Count) throw new InvalidOperationException("Invalid dictionary batch checkpoint.");
            int next = (int)from;
            long done = from;
            long hashed = 0;
            var gate = new object();
            int threads = Threads(hashcatRunning);
            var hashing = Stopwatch.StartNew();
            lock (_lock) { _cpuHashing = true; _cpuThreads = threads; }
            DebugLog.Info($"Hybrid CPU hashing: [{lo}, {hi}), {threads} threads, ordinal {from}");
            Parallel.For(0, threads, new ParallelOptions { MaxDegreeOfParallelism = threads }, _ =>
            {
                var worker = _kernel.CreateWorker();
                while (true)
                {
                    int begin, end, length;
                    lock (gate)
                    {
                        if (stop.IsCancellationRequested || next >= candidates.Count) return;
                        begin = next;
                        length = candidates[begin].Length;
                        end = begin + 1;
                        bool supported = _kernel.SupportsDictionaryPassword(candidates[begin]);
                        while (end < candidates.Count && end - begin < 64 && candidates[end].Length == length
                            && _kernel.SupportsDictionaryPassword(candidates[end]) == supported) end++;
                        next = end;
                    }
                    if (!_kernel.SupportsDictionaryPassword(candidates[begin]))
                    {
                        // WPA rejects these final byte lengths on both engines; no GPU replay is needed.
                        if (_r.Mode != 22000)
                            for (int i = begin; i < end; i++) AppendLeftover(candidates[i]);
                        Interlocked.Add(ref done, end - begin);
                        lock (_lock) _batchDone = done;
                        continue;
                    }
                    var packed = new byte[(end - begin) * length];
                    for (int i = begin; i < end; i++) candidates[i].CopyTo(packed, (i - begin) * length);
                    int offset = 0;
                    while (offset < end - begin)
                    {
                        int hit;
                        if (length == 0 || length > _kernel.MaxPasswordLength)
                        {
                            hit = -1;
                            for (int i = offset; i < end - begin; i++)
                                if (Verify(candidates[begin + i])) { hit = i - offset; break; }
                        }
                        else hit = worker.SearchPasswords(packed.AsSpan(offset * length), length, end - begin - offset);
                        if (hit < 0) break;
                        var pw = candidates[begin + offset + hit];
                        if (Verify(pw))
                        {
                            if (_r.ConfirmPassword is null || _r.ConfirmPassword(pw))
                            {
                                lock (_lock) FoundByCpu ??= pw;
                                _found.Cancel();
                                return;
                            }
                            _owner.FalsePositives.Rejected(pw.Length, "the built-in CPU engine");
                        }
                        offset += hit + 1;
                    }
                    Interlocked.Add(ref done, end - begin);
                    Interlocked.Add(ref hashed, end - begin);
                    lock (_lock) { _batchDone = done; _cpuHashed += end - begin; }
                }
            });
            // In-flight groups finish before saving. All claimed ordinals are complete, with no holes to replay.
            lock (_lock) { _box = 0; _boxPrefix = next; _batchDone = done; }
            lock (_lock) _cpuHashing = false;
            _leftovers?.Flush(true);
            DebugLog.Info($"Hybrid CPU hashed: [{lo}, {hi}), {hashed} candidates, {threads} threads, {hashing.Elapsed.TotalSeconds:F3} s, {hashed / Math.Max(.000001, hashing.Elapsed.TotalSeconds):F0}/s");
            if (FoundByCpu is not null) return false;
            return next == candidates.Count;
        }

        private void AppendLeftover(byte[] password)
        {
            byte[] line = Encoding.ASCII.GetBytes(PasswordConfirmation.HexPlain(password) + "\n");
            lock (_lock)
            {
                _leftovers ??= new FileStream(LeftoverFile(_r.SessionDir, _r.SessionName), FileMode.OpenOrCreate, FileAccess.Write, FileShare.Read);
                _leftovers.Position = _leftoverBytes;
                _leftovers.Write(line);
                _leftoverBytes = _leftovers.Position;
                _leftoverCount++;
            }
        }

        private async Task<LengthOutcome> RunLeftoversAsync(CancellationToken ct)
        {
            string path = LeftoverFile(_r.SessionDir, _r.SessionName);
            // These are already rule-expanded byte strings; applying the original rules again would change the candidates.
            var dictionary = new DictionaryAttack(["-a", "0", path]) { BaseCount = _leftoverCount, AmplifierCount = 1 };
            var order = new HashcatOrder(dictionary);
            _owner.OutputLine?.Invoke($"Checking {_leftoverCount - _leftoverLo:N0} passwords outside the CPU kernel's limits with hashcat.");
            DebugLog.Info($"Hybrid deferred GPU start: {_leftoverCount - _leftoverLo} expanded candidates, cursor {_leftoverLo}");
            _leftoverRunning = true;
            _hcRunning = true;
            _gpuDevices = [];
            _gpuStatusAt = DateTime.MinValue;
            var started = Stopwatch.StartNew();
            bool reported = false;
            var result = await _gpu.RunAsync(order, _leftoverLo, _leftoverCount - _leftoverLo, _excluded, status =>
            {
                if (!reported)
                {
                    reported = true;
                    DebugLog.Info($"Hybrid deferred GPU first status: startup {started.Elapsed.TotalSeconds:F3} s");
                }
                lock (_lock)
                {
                    _leftoverProgress = Math.Clamp(status.ProgressDone, 0, _leftoverCount - _leftoverLo);
                    _gpuDevices = status.Devices;
                    _gpuStatusAt = DateTime.UtcNow;
                }
                Emit();
            }, ct);
            _hcRunning = false;
            _leftoverProgress = 0;
            _leftoverLo = result.Outcome == RunOutcome.Exhausted ? _leftoverCount : Math.Clamp(result.DoneUpTo, _leftoverLo, _leftoverCount);
            DebugLog.Info($"Hybrid deferred GPU stopped: {result.Outcome}, cursor {_leftoverLo}/{_leftoverCount}");
            if (result.Outcome == RunOutcome.Cracked)
            {
                FoundByGpu = result.Passwords;
                FoundByGpuRaw = result.RawPasswords;
                return LengthOutcome.Found;
            }
            Emit();
            return result.Outcome == RunOutcome.Exhausted ? LengthOutcome.Exhausted
                : ct.IsCancellationRequested ? LengthOutcome.Stopped : LengthOutcome.Failed;
        }

        /// <summary>Runs one batch; false when stopped or found (resume position recorded).</summary>
        private bool RunBatch(long lo, long hi, int box0, long prefix0, bool hashcatRunning, CancellationToken stop)
        {
            if (_order.Dictionary is { } dictionary) return RunDictionaryBatch(dictionary, lo, hi, prefix0, hashcatRunning, stop);
            var boxes = _order.Boxes(lo, hi);
            long before = 0;
            for (int b = 0; b < box0 && b < boxes.Count; b++) before += (long)boxes[b].Keyspace(_len);
            for (int b = box0; b < boxes.Count; b++)
            {
                var box = boxes[b];
                long boxBefore = before;
                int threads = Threads(hashcatRunning);
                var engine = new NativeEngine(_kernel, box)
                {
                    Threads = threads,
                    Priority = NativeRunner.ThreadPriorityFor(_r.Settings.Priority),
                    ProgressInterval = TimeSpan.FromMilliseconds(500),
                    Confirm = _r.ConfirmPassword,
                    Rejected = pw => _owner.FalsePositives.Rejected(pw.Length, "the built-in CPU engine"),
                };
                engine.Progress += p => { lock (_lock) _batchDone = boxBefore + p.Done; };
                var resumeAt = b == box0 && prefix0 > 0 ? new NativeResumePoint { Length = _len, PrefixIndex = prefix0 } : null;
                lock (_lock) { _box = b; _boxPrefix = prefix0; _cpuThreads = threads; }
                var res = engine.Run(resumeAt, stop);
                switch (res.Outcome)
                {
                    case NativeOutcome.Found:
                        lock (_lock) FoundByCpu ??= res.Password;
                        _found.Cancel();
                        return false;
                    case NativeOutcome.Stopped:
                        lock (_lock)
                        {
                            _box = b; _boxPrefix = res.ResumeAt?.PrefixIndex ?? 0;
                            _batchDone = boxBefore + _boxPrefix * box.Positions[_len - 1].Length;
                        }
                        return false;
                }
                before += (long)box.Keyspace(_len);
                lock (_lock) _batchDone = before;
            }
            return true;
        }
    }

    /// <summary>The real GPU side: one hashcat process per range, numbered with the ordered Markov table.</summary>
    private sealed class HashcatRange(HashcatTool tool, HashcatRunner runner, RunRequest template, string? markovPath) : IGpuRange
    {
        public Task<long?> KeyspaceAsync(IReadOnlyList<string> maskArgs, CancellationToken ct)
            => tool.KeyspaceAsync(template.Mode, maskArgs, ct, template.UseOptimizedKernel);

        public async Task<GpuRangeResult> RunAsync(HashcatOrder order, long skip, long count, IReadOnlyCollection<int> exclude,
            Action<HashcatStatus> onStatus, CancellationToken stop)
        {
            var attack = new PreparedAttack { Description = $"length {order.Length}, base words {skip}-{skip + count - 1}", Keyspace = new BigInteger(count) * order.AmplifierCount };
            attack.Args.AddRange(order.AttackArgs());
            if (skip > 0) attack.Args.AddRange(["--skip", skip.ToString()]);
            attack.Args.AddRange(["--limit", count.ToString()]);
            if (markovPath is not null) attack.Args.AddRange(["--markov-hcstat2", markovPath]);
            var req = template with { Attack = attack, Restore = false, GpuOnly = true,
                UseOptimizedKernel = order.Dictionary is null && template.UseOptimizedKernel, ExcludeDevices = exclude.Count > 0 ? exclude : null };
            HashcatStatus? lastSeen = null;
            Action<HashcatStatus> h = st => { lastSeen = st; onStatus(st); };
            runner.StatusReceived += h;
            RunResult res;
            try { res = await runner.RunAsync(req, stop); }
            finally { runner.StatusReceived -= h; }

            var rawPasswords = res.RawPasswords;
            if (order.Dictionary is not null && req.ConfirmPassword is null && File.Exists(HashcatRunner.OutFile(req.SessionDir, req.SessionName)))
            {
                rawPasswords = new List<string>();
                // A leading UTF-8 BOM belongs to the password, not the outfile encoding.
                using var output = new StreamReader(HashcatRunner.OutFile(req.SessionDir, req.SessionName), new UTF8Encoding(false), detectEncodingFromByteOrderMarks: false);
                while (output.ReadLine() is { } line) rawPasswords.Add(line);
            }

            string restore = HashcatRunner.RestoreFile(req.SessionDir, req.SessionName);
            long done = res.RecheckFromStart ? skip : res.Outcome switch
            {
                RunOutcome.Exhausted => skip + count,
                _ => ReadRestorePoint(restore) ?? (res.LastStatus ?? lastSeen)?.RestorePoint ?? skip,
            };
            try { File.Delete(restore); } catch (IOException) { }
            return new GpuRangeResult
            {
                Outcome = res.Outcome,
                DoneUpTo = Math.Clamp(done, skip, skip + count),
                Passwords = res.Passwords,
                RawPasswords = rawPasswords,
                Error = res.Error,
                RecheckFromStart = res.RecheckFromStart,
            };
        }
    }

    /// <summary>
    /// words_cur from a hashcat .restore file (restore_data_t: int version, char cwd[256], u32
    /// dicts_pos, u32 masks_pos, u64 words_cur at offset 272), or null.
    /// </summary>
    public static long? ReadRestorePoint(string file)
    {
        try
        {
            if (!File.Exists(file)) return null;
            var b = File.ReadAllBytes(file);
            if (b.Length < 280) return null;
            ulong v = BitConverter.ToUInt64(b, 272);
            return v <= long.MaxValue ? (long)v : null;
        }
        catch (IOException) { return null; }
        catch (UnauthorizedAccessException) { return null; }
    }
}
