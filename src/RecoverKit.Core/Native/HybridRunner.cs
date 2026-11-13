using System.Diagnostics;
using System.Numerics;
using System.Text.Json;
using RecoverKit.Core.Attacks;
using RecoverKit.Core.Formats;
using RecoverKit.Core.Hashcat;

namespace RecoverKit.Core.Native;

/// <summary>A step the hybrid runner can take: the built-in kernel and the whole mask.</summary>
public sealed record HybridPlan(NativeKernel Kernel, MaskSpace Space);

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
    /// <summary>Box of the batch to continue with, and the prefix index inside it (-1: no batch).</summary>
    public int Box { get; set; } = -1;
    public long BoxPrefix { get; set; }
}

/// <summary>The GPU side of a hybrid attack: hashcat on a range of base words of one length.</summary>
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
    public string? Error { get; init; }
}

/// <summary>
/// Hybrid CPU + GPU brute-force: hashcat runs on the GPUs and the built-in CPU engine on the same
/// mask at the same time, on disjoint parts of the keyspace.
///
/// Lengths run one after another. Within a length, candidates are numbered as hashcat numbers them
/// (<see cref="HashcatOrder"/>: base words, each with all amplifier characters). hashcat takes base
/// words from the bottom (--skip/--limit), the built-in engine takes batches from the top, so the
/// remaining work is always one interval [Lo, Top) plus at most one unfinished CPU batch. The first
/// split follows the measured (or remembered) speeds of both sides. When the CPU runs out of work
/// while hashcat still has a long way to go, hashcat is stopped at its restore point and the rest is
/// split again; when hashcat finishes first, it starts again on what the CPU has not taken. A found
/// password on either side stops both. If hashcat fails, the CPU takes everything that is left; if the
/// CPU engine fails, hashcat does.
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
    internal int? ThreadsOverride { get; init; }

    public static string RestoreFile(string dir, string session) => Path.Combine(dir, session + ".hybrid.json");

    /// <summary>
    /// The step runs hybrid when a GPU is used, hybrid mode and the built-in engine are on, the strategy
    /// lets the CPU work next to the GPUs, and the built-in engine could run the step on its own.
    /// </summary>
    public static HybridPlan? Plan(int mode, string hashLines, PreparedAttack attack, Settings settings,
        IReadOnlyList<BackendDevice>? devices, VolumeCredentials? credentials = null, ZipPartialTarget? partial = null)
    {
        if (settings.PerformanceChoice?.Engine is "cpu" or "gpu") return null;
        if (!settings.HybridCpuGpu || settings.Strategy is not (DeviceStrategy.GpuOnly or DeviceStrategy.GpuAndCpu)) return null;
        if (HashcatRunner.ActiveGpus(settings, devices).Count == 0) return null;
        if (settings.PerformanceChoice?.Engine != "hybrid" && CpuAddsTooLittle(settings, devices, mode)) return null;
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
    public Task<RunResult> RunAsync(HybridPlan plan, string hashLine, RunRequest r, HashcatTool tool, CancellationToken ct)
    {
        var runner = new HashcatRunner(tool) { KnownDevices = Devices, FalsePositives = FalsePositives };
        runner.OutputLine += l => OutputLine?.Invoke(l);
        GuardEvents?.Invoke(runner);
        var gpu = new HashcatRange(tool, runner, r, OrderedMarkov.Ensure(r.SessionDir));
        return RunAsync(plan, hashLine, r, gpu, ct);
    }

    /// <summary>Hits rejected by the confirmation check on either side, over all runs of this runner (a session).</summary>
    internal FalsePositiveLog FalsePositives => _falsePositives ??= new FalsePositiveLog(l => OutputLine?.Invoke(l));
    private FalsePositiveLog? _falsePositives;

    /// <summary>Lets the caller subscribe to the temperature guard events of the hashcat runner used.</summary>
    public Action<HashcatRunner>? GuardEvents { get; init; }

    internal async Task<RunResult> RunAsync(HybridPlan plan, string hashLine, RunRequest r, IGpuRange gpu, CancellationToken ct)
    {
        var s = r.Settings;
        string restoreFile = RestoreFile(r.SessionDir, r.SessionName);
        HybridResumePoint? resume = null;
        if (r.Restore && File.Exists(restoreFile))
            try { resume = JsonSerializer.Deserialize<HybridResumePoint>(await File.ReadAllTextAsync(restoreFile, CancellationToken.None)); }
            catch (JsonException) { }

        var space = plan.Space;
        int threads = ThreadsOverride ?? CpuThreads(s, Devices, true);
        double cpuSpeed = InitialCpuSpeed > 0 ? InitialCpuSpeed
            : s.CpuSpeedByMode.TryGetValue(r.Mode, out var known) && known > 0 ? known : plan.Kernel.SpeedHint * threads;
        double gpuSpeed = InitialGpuSpeed > 0 ? InitialGpuSpeed : s.GpuSpeedByMode.GetValueOrDefault(r.Mode);
        _startup = InitialGpuSpeed > 0 || InitialCpuSpeed > 0 ? HashcatStartupSeconds
            : s.GpuStartupByMode.TryGetValue(r.Mode, out var st) && st > 0 ? st : HashcatStartupSeconds;
        var excluded = new HashSet<int>();
        OutputLine?.Invoke($"Hybrid CPU + GPU: hashcat on the GPUs, built-in CPU engine ({plan.Kernel.Name}) on {threads} thread(s), " +
                           $"lengths {space.MinLength}-{space.MaxLength}" + (resume is not null ? $", resuming at length {resume.Length}" : ""));
        DebugLog.Info($"Hybrid: mode {r.Mode}, kernel {plan.Kernel.Name}, threads {threads}, cpu est {cpuSpeed:F0}/s, gpu est {gpuSpeed:F0}/s, " +
                      $"lengths {space.MinLength}-{space.MaxLength}, resume {resume?.Length}:{resume?.Lo}:{resume?.BatchLo}:{resume?.BatchHi}:{resume?.Box}:{resume?.BoxPrefix}");

        var proc = Process.GetCurrentProcess();
        ProcessPriorityClass? previous = null;
        if (NativeRunner.LowersProcessPriority)
            try { previous = proc.PriorityClass; proc.PriorityClass = NativeRunner.ProcessClassFor(s.Priority); }
            catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception or PlatformNotSupportedException) { }
        HashcatStatus? last = null;
        bool gpuAlive = true;
        try
        {
            int startLen = Math.Max(space.MinLength, resume?.Length ?? space.MinLength);
            for (int len = startLen; len <= space.MaxLength; len++)
            {
                if (len > plan.Kernel.MaxPasswordLength) break;
                var sorted = HashcatOrder.SortedPositions(space, len);
                HashcatOrder? order = null;
                // A length the CPU finishes before hashcat would be up and running stays on the CPU.
                bool worthGpu = gpuAlive && (double)space.Keyspace(len) / cpuSpeed > 2 * _startup;
                if (worthGpu)
                {
                    long? baseCount = await gpu.KeyspaceAsync(HashcatOrder.MaskArgs(sorted)!, ct);
                    order = baseCount is { } bc ? HashcatOrder.FromKeyspace(sorted, bc) : null;
                    if (order is null)
                    {
                        if (ct.IsCancellationRequested) return Stopped(last);
                        Warning?.Invoke($"hashcat's keyspace for length {len} could not be matched; this length runs on the CPU only.");
                    }
                }
                bool gpuUsable = order is not null;
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
                        var pw = job.FoundByCpu is { } cpuPw ? [await NativeRunner.RecordFoundAsync(s, hashLine, cpuPw, r.ConfirmPassword is not null ? r.PasswordCachePath ?? s.PotfilePath : null)] : job.FoundByGpu;
                        OutputLine?.Invoke(job.FoundByCpu is not null ? "Found by the built-in CPU engine." : "Found by hashcat.");
                        return new RunResult { Outcome = RunOutcome.Cracked, ExitCode = 0, Passwords = pw, LastStatus = last };
                    case LengthOutcome.Stopped:
                        await File.WriteAllTextAsync(restoreFile, JsonSerializer.Serialize(job.ResumePoint()), CancellationToken.None);
                        return Stopped(last);
                    case LengthOutcome.Failed:
                        TryDelete(restoreFile);
                        return new RunResult { Outcome = RunOutcome.Error, ExitCode = -1, Error = "Both hashcat and the built-in CPU engine failed.", LastStatus = last };
                }
            }
            TryDelete(restoreFile);
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
        private CancellationTokenSource? _rebalance;

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
        public HashcatStatus? LastStatus { get; private set; }
        private readonly long _resumedFrom;
        private readonly long _started = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

        public LengthJob(HybridRunner owner, NativeKernel kernel, HashcatOrder order, int len, RunRequest r, IGpuRange gpu, bool gpuUsable,
            HybridResumePoint? resume, double cpuSpeed, double gpuSpeed, HashSet<int> excluded)
        {
            _owner = owner; _kernel = kernel; _order = order; _len = len; _r = r; _gpu = gpu; _gpuUsable = gpuUsable; _excluded = excluded;
            _n = order.BaseCount;
            _a = order.AmplifierCount;
            CpuSpeed = Math.Max(1, cpuSpeed);
            GpuSpeed = gpuSpeed;
            _lo = 0; _top = _n; _doneFrom = _n;
            if (resume is not null)
            {
                _lo = Math.Clamp(resume.Lo, 0, _n);
                _doneFrom = Math.Clamp(resume.BatchHi, _lo, _n);
                _top = Math.Clamp(resume.BatchLo, _lo, _doneFrom);
                if (resume.Box >= 0 && _top < _doneFrom) _pending = resume;
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
                };
        }

        private long DoneCandidates()
        {
            lock (_lock)
                return checked(_lo * _a + Math.Min(_hcProgress, (_hcEnd - _lo) * _a) + (_n - _doneFrom) * _a + _batchDone);
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
            using var stopOrFound = CancellationTokenSource.CreateLinkedTokenSource(ct, _found.Token);
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
                            if (x > _lo && (_cpuDead || cpuAlone > 2 * _owner._startup))
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

                if (ct.IsCancellationRequested || _found.IsCancellationRequested)
                {
                    _rebalance?.Cancel();
                    if (gpuRun is not null) { HandleGpuResult(await gpuRun, runSkip, ct); gpuRun = null; }
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
            _rebalance?.Dispose();
            Emit();
            if (FoundByCpu is not null || FoundByGpu.Count > 0) return LengthOutcome.Found;
            if (ct.IsCancellationRequested) return LengthOutcome.Stopped;
            lock (_lock)
                if (_lo < _top || _top < _doneFrom) return LengthOutcome.Failed;   // both engines failed
            return LengthOutcome.Exhausted;
        }

        private long DoneCpu() { lock (_lock) return (_n - _doneFrom) * _a + _batchDone; }

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
            if (known is null || st.Status != 3 || _gpuStatuses < 3) return;
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
                _hcRunning = false;
                _hcProgress = 0;
                switch (res.Outcome)
                {
                    case RunOutcome.Cracked:
                        FoundByGpu = res.Passwords;
                        _lo = Math.Clamp(res.DoneUpTo, runSkip, end);
                        _found.Cancel();
                        break;
                    case RunOutcome.Exhausted:
                        _lo = end;
                        break;
                    case RunOutcome.Aborted:
                        _lo = Math.Clamp(res.DoneUpTo, runSkip, end);
                        // Not stopped by us: hashcat quit on its own (for example "no devices"), do not loop.
                        if (!_rebalanceRequested && !ct.IsCancellationRequested && !_found.IsCancellationRequested) _gpuDead = true;
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
                devices.Add(new DeviceSpeed { Id = 0, Name = "CPU (built-in engine)", Type = "CPU", Speed = CpuIdle() ? 0 : CpuSpeed });
                st = new HashcatStatus
                {
                    Status = 3,
                    MaskLength = _len,
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
            try
            {
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
                            long floor = _hcRunning ? _hcEnd : _lo;
                            if (_top <= floor) { lo = hi = 0; box0 = -1; prefix0 = 0; }
                            else
                            {
                                long size = Math.Max(1, (long)(CpuSpeed * _owner.BatchSeconds / _a));
                                // Whole values of the last character when one takes at most a minute.
                                long unit = _order.LastPositionUnit;
                                bool starting = _hcRunning && !_hcReported;   // short batches until hashcat is up
                                if (!starting && unit > size && UnitIsSmall() && _top - floor >= unit) size = unit;
                                hi = _top;
                                lo = _order.AlignDown(hi - size, size, floor);
                                if (lo >= hi) lo = Math.Max(floor, hi - 1);
                                _top = lo;
                                box0 = 0; prefix0 = 0;
                            }
                        }
                        _batchDone = 0;
                        if (box0 >= 0) { _box = box0; _boxPrefix = prefix0; }
                    }
                    if (box0 < 0)
                    {
                        _work.Wait(200);
                        continue;
                    }
                    if (!RunBatch(lo, hi, box0, prefix0, hashcatRunning, stop)) return;
                    lock (_lock)
                    {
                        _doneFrom = lo;
                        _batchDone = 0;
                        _box = -1;
                    }
                }
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
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
        }

        /// <summary>Runs one batch; false when stopped or found (resume position recorded).</summary>
        private bool RunBatch(long lo, long hi, int box0, long prefix0, bool hashcatRunning, CancellationToken stop)
        {
            var boxes = _order.Boxes(lo, hi);
            long before = 0;
            for (int b = 0; b < box0 && b < boxes.Count; b++) before += (long)boxes[b].Keyspace(_len);
            for (int b = box0; b < boxes.Count; b++)
            {
                var box = boxes[b];
                long boxBefore = before;
                var engine = new NativeEngine(_kernel, box)
                {
                    Threads = Threads(hashcatRunning),
                    Priority = NativeRunner.ThreadPriorityFor(_r.Settings.Priority),
                    ProgressInterval = TimeSpan.FromMilliseconds(500),
                    Confirm = _r.ConfirmPassword,
                    Rejected = pw => _owner.FalsePositives.Rejected(pw.Length, "the built-in CPU engine"),
                };
                engine.Progress += p => { lock (_lock) _batchDone = boxBefore + p.Done; };
                var resumeAt = b == box0 && prefix0 > 0 ? new NativeResumePoint { Length = _len, PrefixIndex = prefix0 } : null;
                lock (_lock) { _box = b; _boxPrefix = prefix0; }
                var res = engine.Run(resumeAt, stop);
                switch (res.Outcome)
                {
                    case NativeOutcome.Found:
                        lock (_lock) FoundByCpu ??= res.Password;
                        _found.Cancel();
                        return false;
                    case NativeOutcome.Stopped:
                        lock (_lock) { _box = b; _boxPrefix = res.ResumeAt?.PrefixIndex ?? 0; }
                        return false;
                }
                before += (long)box.Keyspace(_len);
                lock (_lock) _batchDone = before;
            }
            return true;
        }
    }

    /// <summary>The real GPU side: one hashcat process per range, numbered with the ordered Markov table.</summary>
    private sealed class HashcatRange(HashcatTool tool, HashcatRunner runner, RunRequest template, string markovPath) : IGpuRange
    {
        public Task<long?> KeyspaceAsync(IReadOnlyList<string> maskArgs, CancellationToken ct)
            => tool.KeyspaceAsync(template.Mode, maskArgs, ct, template.UseOptimizedKernel);

        public async Task<GpuRangeResult> RunAsync(HashcatOrder order, long skip, long count, IReadOnlyCollection<int> exclude,
            Action<HashcatStatus> onStatus, CancellationToken stop)
        {
            var attack = new PreparedAttack { Description = $"length {order.Length}, base words {skip}-{skip + count - 1}", Keyspace = new BigInteger(count) * order.AmplifierCount };
            attack.Args.AddRange(order.HashcatMaskArgs()!);
            if (skip > 0) attack.Args.AddRange(["--skip", skip.ToString()]);
            attack.Args.AddRange(["--limit", count.ToString(), "--markov-hcstat2", markovPath]);
            var req = template with { Attack = attack, Restore = false, GpuOnly = true, ExcludeDevices = exclude.Count > 0 ? exclude : null };
            HashcatStatus? lastSeen = null;
            Action<HashcatStatus> h = st => { lastSeen = st; onStatus(st); };
            runner.StatusReceived += h;
            RunResult res;
            try { res = await runner.RunAsync(req, stop); }
            finally { runner.StatusReceived -= h; }

            string restore = HashcatRunner.RestoreFile(req.SessionDir, req.SessionName);
            long done = res.Outcome switch
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
                Error = res.Error,
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
