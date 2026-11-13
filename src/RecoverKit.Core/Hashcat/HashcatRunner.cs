using System.Diagnostics;
using System.Runtime.InteropServices;
using RecoverKit.Core.Attacks;
using RecoverKit.Core.Formats;

namespace RecoverKit.Core.Hashcat;

public enum RunOutcome { Cracked, Exhausted, Aborted, Error }

public sealed record RunRequest
{
    public required int Mode { get; init; }
    public required string HashFile { get; init; }
    public required PreparedAttack Attack { get; init; }
    public required string SessionName { get; init; }
    public required string SessionDir { get; init; }
    public bool Restore { get; init; }
    public Settings Settings { get; init; } = new();
    public bool UseOptimizedKernel { get; init; }
    public VolumeCredentials? VolumeCredentials { get; init; }
    public string? PasswordCachePath { get; init; }
    /// <summary>GPU temperature guard / load limit for this run; null when off or no GPU is used.</summary>
    public ThermalGuard? Guard { get; init; }
    /// <summary>Hybrid attacks: hashcat runs on the GPUs only, the built-in engine has the processor.</summary>
    public bool GpuOnly { get; init; }
    /// <summary>Device ids to leave out of this run (an integrated GPU slower than the CPU thread it costs).</summary>
    public IReadOnlyCollection<int>? ExcludeDevices { get; init; }
}

public sealed class RunResult
{
    public RunOutcome Outcome { get; init; }
    public int ExitCode { get; init; }
    public List<string> Passwords { get; init; } = new();
    /// <summary>Plaintexts exactly as hashcat wrote them ($HEX[..] kept), for binary results such as RC4 keys.</summary>
    public List<string> RawPasswords { get; init; } = new();
    public string? Error { get; init; }
    public HashcatStatus? LastStatus { get; init; }
}

/// <summary>
/// Runs one hashcat attack as a child process, streams --status-json updates,
/// optionally feeds candidates through stdin, and stops it gracefully
/// (Ctrl+C on Windows, SIGINT elsewhere) so the .restore file stays usable.
/// </summary>
public sealed class HashcatRunner(HashcatTool tool)
{
    public event Action<HashcatStatus>? StatusReceived;
    public event Action<string>? OutputLine;
    /// <summary>The temperature guard paused or resumed hashcat.</summary>
    public event Action<ThermalEvent>? Thermal;
    /// <summary>Guard messages for the session log (pauses and resumes).</summary>
    public event Action<string>? GuardMessage;
    /// <summary>Where the guard reads temperatures while hashcat is suspended; defaults to <see cref="GpuTemperature.External"/>.</summary>
    public ITemperatureSource? TemperatureSource
    {
        get => _sourceSet ? _source : GpuTemperature.External;
        set { _source = value; _sourceSet = true; }
    }
    private ITemperatureSource? _source;
    private bool _sourceSet;

    public static string RestoreFile(string dir, string session) => Path.Combine(dir, session + ".restore");
    public static string OutFile(string dir, string session) => Path.Combine(dir, session + ".out");

    public List<string> BuildArguments(RunRequest r)
    {
        string restore = RestoreFile(r.SessionDir, r.SessionName);
        if (r.Restore)
            return ["--session", r.SessionName, "--restore", "--restore-file-path", restore];

        var s = r.Settings;
        var a = new List<string> { "-m", r.Mode.ToString(), r.HashFile };
        a.AddRange(r.Attack.Args);
        if (r.VolumeCredentials is { } credentials) a.AddRange(credentials.Arguments);
        a.AddRange(["--session", r.SessionName, "--restore-file-path", restore]);
        a.AddRange(["--status", "--status-json", "--status-timer", "2", "--quiet"]);
        a.AddRange(["-o", OutFile(r.SessionDir, r.SessionName), "--outfile-format", "2"]);
        if (s.DontUsePasswordCache) a.Add("--potfile-disable");
        else a.AddRange(["--potfile-path", r.PasswordCachePath ?? s.PotfilePath]);
        a.AddRange(["-w", Math.Clamp(s.Workload, 1, 4).ToString()]);
        a.AddRange(DeviceArguments(s, KnownDevices, r.GpuOnly, r.ExcludeDevices));
        if (r.UseOptimizedKernel) a.Add("-O");
        if (r.Attack.Stdin is not null) a.AddRange(["--stdin-timeout-abort", "600"]);
        if (!string.IsNullOrWhiteSpace(s.ExtraArguments))
            a.AddRange(s.ExtraArguments.Split(' ', StringSplitOptions.RemoveEmptyEntries));
        a.AddRange(HwmonArguments(s, r.Guard));
        return a;
    }

    /// <summary>
    /// With the temperature guard on, hashcat's own emergency stop is set a bit above the guard
    /// limit (limit + 10, at most 100 °C) so a stuck guard cannot overheat the GPU. Left alone when
    /// the user passes their own --hwmon-* option (for example --hwmon-disable) as an extra argument.
    /// </summary>
    public static List<string> HwmonArguments(Settings s, ThermalGuard? guard)
    {
        if (guard is not { TemperatureGuard: true }) return [];
        if (s.ExtraArguments.Contains("--hwmon", StringComparison.OrdinalIgnoreCase)) return [];
        return ["--hwmon-temp-abort", ThermalGuard.AbortTemperature(guard.Limit).ToString()];
    }

    /// <summary>The guard for a hashcat run with these settings, or null when it is off or hashcat uses no GPU.</summary>
    public static ThermalGuard? GuardFor(Settings s, IReadOnlyList<BackendDevice>? known)
        => UsesGpu(s, known) ? ThermalGuard.FromSettings(s) : null;

    /// <summary>Whether hashcat runs with these settings can use a GPU (unknown devices count as yes).</summary>
    public static bool UsesGpu(Settings s, IReadOnlyList<BackendDevice>? known)
        => s.Strategy != DeviceStrategy.CpuOnly && (known is not { Count: > 0 } || known.Any(d => d.IsGpu));

    /// <summary>
    /// -d / -D arguments derived from the GPU configuration and CPU/GPU strategy. Every GPU hashcat
    /// can use runs (discrete and integrated, each physical device once: aliases stay skipped) unless
    /// the user unchecked it. <paramref name="gpuOnly"/> keeps the processor out of hashcat because the
    /// built-in CPU engine is using it (hybrid attacks); <paramref name="exclude"/> leaves further
    /// devices out for this run.
    /// </summary>
    public static List<string> DeviceArguments(Settings s, IReadOnlyList<BackendDevice>? known, bool gpuOnly = false,
        IReadOnlyCollection<int>? exclude = null)
    {
        var a = new List<string>();
        // With no GPU among the detected devices the GPU-first strategies fall back to the processor,
        // instead of failing with "no devices found".
        bool noGpu = known is not null && known.Count > 0 && !known.Any(d => d.IsGpu);
        bool cpuDevice = known?.Any(d => !d.IsSkippedAlias && d.Type.Contains("CPU", StringComparison.OrdinalIgnoreCase)) == true;
        if (gpuOnly && !noGpu) a.AddRange(["-D", "2"]);
        else
            switch (s.Strategy)
            {
                case DeviceStrategy.GpuAndCpu: a.AddRange(["-D", "1,2"]); break;
                // hashcat reaches the processor only through OpenCL; skipping the GPU-only CUDA and HIP
                // interfaces keeps a half-installed GPU runtime (for example AMD HIP without its compiler
                // library) from aborting a CPU-only run.
                case DeviceStrategy.CpuOnly: a.AddRange(["-D", "1", "--backend-ignore-cuda", "--backend-ignore-hip"]); break;
                case DeviceStrategy.FastGpu: a.AddRange(["-D", noGpu ? "1" : "2"]); break;
                default:
                    if (noGpu) a.AddRange(["-D", "1"]);
                    else if (s.HashcatCpuWithGpu && cpuDevice) a.AddRange(["-D", "1,2"]);
                    break;
            }
        bool anyOff = s.DisabledDeviceKeys.Count > 0 || s.DisabledDevices.Count > 0 || exclude is { Count: > 0 };
        if (anyOff && known is not null)
        {
            var enabled = known.Where(d => !d.IsSkippedAlias && !IsDisabled(s, d) && exclude?.Contains(d.Id) != true).Select(d => d.Id).ToList();
            if (enabled.Count > 0) a.AddRange(["-d", string.Join(',', enabled)]);
        }
        return a;
    }

    /// <summary>Whether the user unchecked this device (by its stable key; ids only for older settings files).</summary>
    public static bool IsDisabled(Settings s, BackendDevice d)
        => s.DisabledDeviceKeys.Count > 0 ? s.DisabledDeviceKeys.Contains(d.Key) : s.DisabledDevices.Contains(d.Id);

    /// <summary>The GPUs hashcat will run on with these settings (not skipped as an alias, not unchecked).</summary>
    public static List<BackendDevice> ActiveGpus(Settings s, IReadOnlyList<BackendDevice>? known)
        => known is null ? [] : known.Where(d => d.IsGpu && !d.IsSkippedAlias && !IsDisabled(s, d)).ToList();

    /// <summary>
    /// True when the "Don't use GPU threads" strategy is chosen but hashcat sees no CPU device
    /// (Apple Silicon: Apple's OpenCL and Metal expose only the GPU), so -D 1 finds nothing.
    /// </summary>
    /// <summary>Start of the error text when "CPU only" is chosen but hashcat sees no processor device (Windows, Linux).</summary>
    public const string NoCpuDeviceMessage =
        "\"CPU only\" is selected, but hashcat has no processor (CPU) device: it needs a CPU OpenCL runtime for that. " +
        "Install it with Tools > Download CPU runtime, or choose a GPU strategy in Preferences. " +
        "The built-in CPU engine still runs ZIP, Office 97-2003, PDF and RAR 3.x without it.";

    public static bool NoCpuDevice(Settings s, IReadOnlyList<BackendDevice>? known)
        => s.Strategy == DeviceStrategy.CpuOnly && known is { Count: > 0 } &&
           !known.Any(d => d.Type.Contains("CPU", StringComparison.OrdinalIgnoreCase));

    /// <summary>hashcat skipped the mode on every device (Apple GPUs refuse a few modes).</summary>
    public static bool IsGpuRefusal(string? error, int mode)
        => OperatingSystem.IsMacOS() && error?.Contains($"Skipping (hash-mode {mode})", StringComparison.Ordinal) == true;

    public IReadOnlyList<BackendDevice>? KnownDevices { get; set; }

    public async Task<RunResult> RunAsync(RunRequest r, CancellationToken ct)
    {
        r.VolumeCredentials?.ValidateUnchanged();
        var args = BuildArguments(r);
        string outFile = OutFile(r.SessionDir, r.SessionName);
        if (!r.Restore && File.Exists(outFile)) File.Delete(outFile);
        OutputLine?.Invoke("hashcat " + string.Join(' ', args.Select(Quote)));

        bool useStdin = r.Attack.Stdin is not null && !r.Restore;
        var psi = tool.StartInfo(args, useStdin);
        int logId = DebugLog.ProcessStart(psi, $"attack run, mode {r.Mode}, restore={r.Restore}, stdin generator={useStdin}, priority={r.Settings.Priority}");
        var sw = Stopwatch.StartNew();
        using var p = new Process { StartInfo = psi, EnableRaisingEvents = true };
        HashcatStatus? last = null;
        var tail = new Queue<string>();
        ThermalController? guard = null;

        p.OutputDataReceived += (_, e) =>
        {
            if (e.Data is null) return;
            DebugLog.ProcessOutput(logId, "stdout", e.Data);
            var st = HashcatStatus.TryParse(e.Data);
            if (st is not null)
            {
                last = st;
                GpuTemperature.Record(st);
                StatusReceived?.Invoke(guard?.Adjust(st) ?? st);
                return;
            }
            Remember(tail, e.Data);
            if (e.Data.Length > 0) OutputLine?.Invoke(e.Data);
        };
        p.ErrorDataReceived += (_, e) =>
        {
            if (string.IsNullOrEmpty(e.Data)) return;
            DebugLog.ProcessOutput(logId, "stderr", e.Data);
            Remember(tail, e.Data);
            OutputLine?.Invoke(e.Data);
        };

        p.Start();
        TrySetPriority(p, r.Settings.Priority);
        if (r.Guard is { Active: true } g)
        {
            var source = TemperatureSource;
            guard = new ThermalController(g, p, source, m => GuardMessage?.Invoke(m), e => Thermal?.Invoke(e), s => StatusReceived?.Invoke(s));
            if (g.TemperatureGuard && source is null)
                DebugLog.Info("Temperature guard: no external temperature source, relying on hashcat's status");
        }
        p.BeginOutputReadLine();
        p.BeginErrorReadLine();

        using var pumpCts = new CancellationTokenSource();
        Task pump = Task.CompletedTask;
        if (useStdin)
        {
            var source = r.Attack.Stdin!;
            var stdin = p.StandardInput.BaseStream;
            pump = Task.Run(() =>
            {
                try { Generators.Pump(source(), stdin, pumpCts.Token); }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                {
                    OutputLine?.Invoke("Candidate generator failed: " + ex.Message);
                    try { stdin.Close(); } catch (IOException) { }
                }
            });
        }

        bool stopped = false;
        using (ct.Register(() => { stopped = true; guard?.BeforeStop(); pumpCts.Cancel(); _ = StopAsync(p); }))
        {
            await p.WaitForExitAsync(CancellationToken.None);
        }
        guard?.Dispose();
        pumpCts.Cancel();
        try { await pump.WaitAsync(TimeSpan.FromSeconds(5)); } catch (TimeoutException) { }
        p.WaitForExit(); // flush async output handlers

        int code = p.ExitCode;
        DebugLog.ProcessExit(logId, code, sw.Elapsed);
        if (stopped) DebugLog.Info($"#{logId} was stopped by the user");
        var raw = File.Exists(outFile)
            ? File.ReadAllLines(outFile).Distinct().ToList()
            : new List<string>();
        var passwords = raw.Select(p => HashcatTool.DecodePlain(p, r.VolumeCredentials)).Distinct().ToList();

        RunOutcome outcome = code switch
        {
            0 => RunOutcome.Cracked,
            1 => RunOutcome.Exhausted,
            2 or 3 or 4 or 5 => RunOutcome.Aborted,
            _ => stopped ? RunOutcome.Aborted : RunOutcome.Error,
        };
        if (outcome == RunOutcome.Cracked && passwords.Count == 0 && !r.Settings.DontUsePasswordCache)
            passwords = await tool.ShowAsync(r.Mode, r.HashFile, r.PasswordCachePath ?? r.Settings.PotfilePath, r.VolumeCredentials);
        if (stopped && outcome != RunOutcome.Cracked) outcome = RunOutcome.Aborted;

        string? error = outcome == RunOutcome.Error
            ? string.Join(Environment.NewLine, tail.Where(l => !l.StartsWith('{')).TakeLast(12))
            : null;
        if (outcome == RunOutcome.Error && string.IsNullOrWhiteSpace(error)) error = $"hashcat exited with code {code}.";
        if (outcome == RunOutcome.Error && NoCpuDevice(r.Settings, KnownDevices))
            error = (OperatingSystem.IsMacOS()
                ? "hashcat has no processor (CPU) device on this computer: Apple Silicon Macs expose only the GPU to hashcat. " +
                  "Choose a GPU strategy in Preferences (the built-in CPU engine still runs the formats it supports).\n"
                : NoCpuDeviceMessage + "\n") + error;
        // hashcat refuses some modes on Apple GPUs (e.g. 17200 PKZIP: no 'goto' in Metal, OpenCL compiler hang).
        else if (outcome == RunOutcome.Error && IsGpuRefusal(error, r.Mode))
            error = $"hashcat cannot run hash mode {r.Mode} on the Apple GPU (a known Metal/OpenCL runtime limitation). " +
                    "If the built-in CPU engine supports this format, choose \"Don't use GPU threads\" in Preferences to use it.\n" + error;

        return new RunResult { Outcome = outcome, ExitCode = code, Passwords = passwords, RawPasswords = raw, Error = error, LastStatus = last };
    }

    private static void Remember(Queue<string> q, string line)
    {
        lock (q)
        {
            q.Enqueue(line);
            while (q.Count > 60) q.Dequeue();
        }
    }

    private static string Quote(string a) => a.Contains(' ') ? $"\"{a}\"" : a;

    private static void TrySetPriority(Process p, ProcessPriority pr)
    {
        // As for the built-in engine (see NativeRunner.LowersProcessPriority): on macOS a niced hashcat
        // loses its GPU-feeding thread to the built-in engine in hybrid attacks (measured on an M1 Pro:
        // PDF R6 on the GPU fell from 9,600 to 2,500/s), and the GPU itself does not care about nice.
        if (!Native.NativeRunner.LowersProcessPriority) return;
        try
        {
            p.PriorityClass = pr switch
            {
                ProcessPriority.Idle => ProcessPriorityClass.Idle,
                ProcessPriority.BelowNormal => ProcessPriorityClass.BelowNormal,
                ProcessPriority.High => ProcessPriorityClass.High,
                _ => ProcessPriorityClass.Normal,
            };
        }
        catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception or PlatformNotSupportedException) { }
    }

    // ---------------------------------------------------------------- graceful stop

    private static async Task StopAsync(Process p)
    {
        try
        {
            if (p.HasExited) return;
            if (OperatingSystem.IsWindows()) SendCtrlC(p.Id);
            else Process.Start("kill", ["-INT", p.Id.ToString()])?.WaitForExit(2000);
            for (int i = 0; i < 100 && !p.HasExited; i++) await Task.Delay(100);
            if (!p.HasExited) p.Kill(true);
        }
        catch (InvalidOperationException) { }
        catch (System.ComponentModel.Win32Exception) { }
    }

    private static readonly object CtrlLock = new();

    private static void SendCtrlC(int pid)
    {
        lock (CtrlLock)
        {
            // Attach to hashcat's (hidden) console and raise Ctrl+C there, ignoring it ourselves.
            FreeConsole();
            if (!AttachConsole((uint)pid)) return;
            SetConsoleCtrlHandler(IntPtr.Zero, true);
            GenerateConsoleCtrlEvent(0, 0);
            Thread.Sleep(300);
            FreeConsole();
            SetConsoleCtrlHandler(IntPtr.Zero, false);
        }
    }

    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool AttachConsole(uint dwProcessId);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool FreeConsole();
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool SetConsoleCtrlHandler(IntPtr handler, bool add);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool GenerateConsoleCtrlEvent(uint ctrlEvent, uint processGroupId);
}
