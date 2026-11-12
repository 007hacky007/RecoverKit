using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;

namespace RecoverKit.Core.Hashcat;

/// <summary>Power limits of one NVIDIA GPU as nvidia-smi reports them (watts).</summary>
public sealed record GpuPowerInfo(int Index, string Name, double MinWatts, double MaxWatts, double DefaultWatts, double CurrentWatts)
{
    public int MinAllowed => (int)Math.Ceiling(MinWatts);
    public int MaxAllowed => (int)Math.Floor(MaxWatts);
    public bool Allows(int watts) => watts >= MinAllowed && watts <= MaxAllowed;
}

/// <summary>One GPU whose power limit an attack wants to change.</summary>
public sealed record PowerTarget(int Index, string Name, int Watts, double CurrentWatts);

/// <summary>The user's answer to the explanation shown before the administrator prompt.</summary>
public enum ElevationChoice { Continue, WithoutPowerLimit, Cancel }

/// <summary>What RecoverKit asks the user before it requests administrator rights for a power limit.</summary>
public sealed class PowerLimitRequest
{
    public required IReadOnlyList<PowerTarget> Targets { get; init; }

    public static string Watts(double w) => w.ToString("0.##", CultureInfo.InvariantCulture) + " W";

    /// <summary>The explanation shown by the GUI dialog and the CLI before the system prompt.</summary>
    public string Explanation
    {
        get
        {
            string chosen = string.Join(", ", Targets.Select(t => $"{Watts(t.Watts)} for {t.Name}"));
            string restored = string.Join(" and ", Targets.Select(t => Watts(t.CurrentWatts)));
            string prompt = OperatingSystem.IsWindows() ? "Windows will now ask for permission."
                : "Your system will now ask for an administrator password.";
            return $"Administrator rights are needed to set the GPU power limit you chose ({chosen}). {prompt} " +
                   $"Only the power limit is changed, and it is restored to {restored} when the attack ends. " +
                   "RecoverKit itself keeps running without administrator rights.";
        }
    }
}

/// <summary>NVIDIA power limits through nvidia-smi (Windows and Linux; querying needs no admin rights).</summary>
public static class NvidiaPower
{
    public static readonly string[] QueryArgs =
        ["--query-gpu=index,name,power.min_limit,power.max_limit,power.default_limit,power.limit", "--format=csv,noheader,nounits"];

    public static bool PlatformSupported => OperatingSystem.IsWindows() || OperatingSystem.IsLinux();

    /// <summary>
    /// Parses lines like "0, NVIDIA GeForce RTX 4070, 100.00, 200.00, 200.00, 200.00". GPUs whose
    /// limits read "[N/A]" (no power management, e.g. many laptops) are left out.
    /// </summary>
    public static List<GpuPowerInfo> Parse(string csv)
    {
        var list = new List<GpuPowerInfo>();
        foreach (var line in csv.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var f = line.Split(',').Select(x => x.Trim()).ToArray();
            if (f.Length < 6 || !int.TryParse(f[0], NumberStyles.None, CultureInfo.InvariantCulture, out int index)) continue;
            var n = f[^4..].Select(x => double.TryParse(x, NumberStyles.Float, CultureInfo.InvariantCulture, out var v) ? v : double.NaN).ToArray();
            if (n.Any(v => double.IsNaN(v) || v <= 0) || n[0] > n[1]) continue;
            list.Add(new GpuPowerInfo(index, string.Join(",", f[1..^4]), n[0], n[1], n[2], n[3]));
        }
        return list;
    }

    public static List<GpuPowerInfo> Query(NvidiaSmi smi)
    {
        var (code, output) = smi.Run(QueryArgs);
        return code == 0 ? Parse(output) : [];
    }

    /// <summary>NVIDIA GPUs with an adjustable power limit, or an empty list (also on macOS).</summary>
    public static Task<List<GpuPowerInfo>> QueryAsync() => Task.Run(() =>
    {
        if (!PlatformSupported || NvidiaSmi.Locate() is not { } exe) return new List<GpuPowerInfo>();
        return Query(new NvidiaSmi(exe));
    });

    /// <summary>The GPUs whose limit the settings change (skipping those already at the chosen value), or null.</summary>
    public static PowerLimitRequest? BuildRequest(Settings s, IReadOnlyList<GpuPowerInfo> gpus)
    {
        if (!s.GpuPowerLimit) return null;
        var targets = new List<PowerTarget>();
        foreach (var g in gpus)
        {
            if (!s.GpuPowerWatts.TryGetValue(g.Index, out int w) || !g.Allows(w)) continue;
            if (Math.Abs(g.CurrentWatts - w) < 0.5) continue;
            targets.Add(new PowerTarget(g.Index, g.Name, w, g.CurrentWatts));
        }
        return targets.Count == 0 ? null : new PowerLimitRequest { Targets = targets };
    }
}

/// <summary>
/// The elevated helper: "power-helper --pid P --gpu I --watts W [--gpu I --watts W ...]". It runs only
/// the trusted nvidia-smi with integers checked against the limits nvidia-smi itself reports,
/// remembers the current limits, sets the requested ones, waits until RecoverKit (process P) exits
/// or asks it to stop, then restores the remembered limits.
/// </summary>
public static class PowerHelper
{
    public const string Command = "power-helper";
    public const int MaxTargets = 16;

    public const int ExitOk = 0, ExitBadArguments = 2, ExitNoNvidiaSmi = 3, ExitRefused = 4, ExitFailed = 5, ExitNoParent = 6;

    public sealed record Arguments(int ParentPid, IReadOnlyList<(int Gpu, int Watts)> Targets, bool Simulate);

    /// <summary>Strict parsing: only the known options, integers in sane ranges, no duplicates.</summary>
    public static Arguments Parse(IReadOnlyList<string> args)
    {
        if (args.Count == 0 || args[0] != Command) throw new ArgumentException("not a power-helper command line");
        int pid = 0;
        var targets = new List<(int, int)>();
        int? gpu = null;
        bool simulate = false;
        for (int i = 1; i < args.Count; i++)
        {
            string a = args[i];
            if (a == "--simulate" && SimulationAllowed) { simulate = true; continue; }
            if (i + 1 >= args.Count) throw new ArgumentException($"{a} needs a value");
            int v = Int(args[++i], a);
            switch (a)
            {
                case "--pid" when pid == 0 && v > 0: pid = v; break;
                case "--gpu" when gpu is null && v is >= 0 and < 64: gpu = v; break;
                case "--watts" when gpu is not null && v is >= 1 and <= 5000:
                    if (targets.Any(t => t.Item1 == gpu)) throw new ArgumentException($"GPU {gpu} given twice");
                    targets.Add((gpu.Value, v));
                    gpu = null;
                    break;
                default: throw new ArgumentException($"unexpected {a} {v}");
            }
        }
        if (pid == 0 || gpu is not null || targets.Count is 0 or > MaxTargets) throw new ArgumentException("incomplete power-helper command line");
        return new Arguments(pid, targets, simulate);
    }

    private static int Int(string s, string option)
        => s.Length is > 0 and <= 9 && s.All(char.IsAsciiDigit) ? int.Parse(s, CultureInfo.InvariantCulture)
            : throw new ArgumentException($"{option} needs a whole number");

    /// <summary>Simulation (no nvidia-smi calls) exists only in debug builds, for testing the elevation flow.</summary>
    public static bool SimulationAllowed =>
#if DEBUG
        true;
#else
        false;
#endif

    public static List<string> CommandLine(int parentPid, IEnumerable<PowerTarget> targets, bool simulate = false)
    {
        var a = new List<string> { Command, "--pid", parentPid.ToString(CultureInfo.InvariantCulture) };
        foreach (var t in targets)
            a.AddRange(["--gpu", t.Index.ToString(CultureInfo.InvariantCulture), "--watts", t.Watts.ToString(CultureInfo.InvariantCulture)]);
        if (simulate) a.Add("--simulate");
        return a;
    }

    /// <summary>
    /// Checks every target against the limits nvidia-smi reports, then sets them. Returns the
    /// original limits to restore. On any failure the GPUs already changed are restored and an
    /// exception is thrown.
    /// </summary>
    public static List<(int Gpu, double Original)> Apply(NvidiaSmi smi, IReadOnlyList<(int Gpu, int Watts)> targets)
    {
        var gpus = NvidiaPower.Query(smi);
        foreach (var (gpu, watts) in targets)
        {
            var info = gpus.FirstOrDefault(g => g.Index == gpu)
                       ?? throw new InvalidOperationException($"GPU {gpu} has no adjustable power limit.");
            if (!info.Allows(watts))
                throw new InvalidOperationException($"{watts} W is outside {info.MinAllowed}-{info.MaxAllowed} W for GPU {gpu}.");
        }
        var done = new List<(int, double)>();
        foreach (var (gpu, watts) in targets)
        {
            double original = gpus.First(g => g.Index == gpu).CurrentWatts;
            if (!SetLimit(smi, gpu, watts))
            {
                Restore(smi, done);
                throw new InvalidOperationException($"nvidia-smi could not set {watts} W on GPU {gpu}.");
            }
            done.Add((gpu, original));
        }
        return done;
    }

    public static void Restore(NvidiaSmi smi, IEnumerable<(int Gpu, double Original)> originals)
    {
        foreach (var (gpu, original) in originals) SetLimit(smi, gpu, original);
    }

    private static bool SetLimit(NvidiaSmi smi, int gpu, double watts)
        => smi.Run(["-i", gpu.ToString(CultureInfo.InvariantCulture), "-pl", watts.ToString("0.##", CultureInfo.InvariantCulture)]).Code == 0;

    /// <summary>Windows: names of the events RecoverKit creates and the helper opens (derived from the PID only).</summary>
    public static string StopEventName(int parentPid) => $@"Local\RecoverKit.PowerLimit.{parentPid}.Stop";
    public static string AppliedEventName(int parentPid) => $@"Local\RecoverKit.PowerLimit.{parentPid}.Applied";

    /// <summary>Entry point of the elevated helper process. Returns the exit code.</summary>
    public static int Run(string[] argv)
    {
        Arguments a;
        try { a = Parse(argv); }
        catch (ArgumentException ex) { Console.WriteLine("error: " + ex.Message); return ExitBadArguments; }

        Process parent;
        try { parent = Process.GetProcessById(a.ParentPid); }
        catch (ArgumentException) { Console.WriteLine("error: RecoverKit is not running"); return ExitNoParent; }

        NvidiaSmi smi;
        if (a.Simulate) smi = SimulatedSmi(a.Targets);
        else if (NvidiaSmi.Locate() is { } exe) smi = new NvidiaSmi(exe);
        else { Console.WriteLine("error: nvidia-smi not found"); return ExitNoNvidiaSmi; }

        EventWaitHandle? stop = null, applied = null;
        if (OperatingSystem.IsWindows())
        {
            if (!EventWaitHandle.TryOpenExisting(StopEventName(a.ParentPid), out stop) ||
                !EventWaitHandle.TryOpenExisting(AppliedEventName(a.ParentPid), out applied))
            {
                Console.WriteLine("error: RecoverKit did not start this helper");
                return ExitNoParent;
            }
        }

        List<(int Gpu, double Original)> originals;
        try { originals = Apply(smi, a.Targets); }
        catch (InvalidOperationException ex) { Console.WriteLine("error: " + ex.Message); return ex.Message.Contains("outside") ? ExitRefused : ExitFailed; }

        int restored = 0;
        void RestoreOnce()
        {
            if (Interlocked.Exchange(ref restored, 1) == 0) Restore(smi, originals);
        }
        AppDomain.CurrentDomain.ProcessExit += (_, _) => RestoreOnce();
        Console.CancelKeyPress += (_, e) => { e.Cancel = true; stop?.Set(); };
        using var term = OperatingSystem.IsWindows() ? null : PosixSignalRegistration.Create(PosixSignal.SIGTERM, c => { c.Cancel = true; RestoreOnce(); Environment.Exit(ExitOk); });
        using var hup = OperatingSystem.IsWindows() ? null : PosixSignalRegistration.Create(PosixSignal.SIGHUP, c => { c.Cancel = true; RestoreOnce(); Environment.Exit(ExitOk); });

        applied?.Set();
        Console.WriteLine("applied");
        Console.Out.Flush();

        // Stop when RecoverKit exits (also after a crash) or asks: the event on Windows, stdin closing elsewhere.
        var parentExit = parent.WaitForExitAsync();
        Task stopAsked = stop is not null
            ? Task.Run(() => stop.WaitOne())
            : Task.Run(() => { try { while (Console.In.ReadLine() is not null) { } } catch (IOException) { } });
        Task.WaitAny(parentExit, stopAsked);
        RestoreOnce();
        Console.WriteLine("restored");
        return ExitOk;
    }

    /// <summary>Debug builds only: a pretend nvidia-smi so the elevation flow can be tested without an NVIDIA GPU.</summary>
    private static NvidiaSmi SimulatedSmi(IReadOnlyList<(int Gpu, int Watts)> targets)
    {
        string log = Path.Combine(Path.GetTempPath(), "recoverkit-power-simulation.log");
        var limits = targets.ToDictionary(t => t.Gpu, _ => 200.0);
        return new NvidiaSmi("simulated", (_, args) =>
        {
            File.AppendAllText(log, $"{DateTime.Now:O} nvidia-smi {string.Join(' ', args)}{Environment.NewLine}");
            if (args[0].StartsWith("--query-gpu", StringComparison.Ordinal))
                return (0, string.Concat(limits.Select(l => $"{l.Key}, Simulated GPU, 100.00, 250.00, 200.00, {l.Value:0.00}\n")));
            limits[int.Parse(args[1], CultureInfo.InvariantCulture)] = double.Parse(args[3], CultureInfo.InvariantCulture);
            return (0, "");
        });
    }
}

/// <summary>A running elevated helper; disposing it restores the original limits.</summary>
public sealed class PowerLimitSession : IDisposable
{
    private readonly Process? _process;
    private readonly EventWaitHandle? _stop;
    private readonly IDisposable[] _owned;

    internal PowerLimitSession(Process? process, EventWaitHandle? stop, params IDisposable[] owned)
    {
        _process = process;
        _stop = stop;
        _owned = owned;
    }

    public void Dispose()
    {
        try
        {
            if (_stop is not null) _stop.Set();
            else if (_process is { HasExited: false }) _process.StandardInput.Close();
            _process?.WaitForExit(15_000);
        }
        catch (Exception ex) when (ex is InvalidOperationException or IOException) { DebugLog.Warn("Power limit helper: " + ex.Message); }
        foreach (var d in _owned) d.Dispose();
        _process?.Dispose();
    }
}

/// <summary>Starts the elevated helper: UAC ("runas") on Windows, pkexec on Linux.</summary>
public static class PowerLimiter
{
    /// <summary>Debug builds: RECOVERKIT_POWER_SIMULATE=1 pretends an NVIDIA GPU exists and the helper changes nothing.</summary>
    public static bool Simulate => PowerHelper.SimulationAllowed && Environment.GetEnvironmentVariable("RECOVERKIT_POWER_SIMULATE") == "1";

    /// <summary>The GPUs with an adjustable limit (simulated in debug builds when asked to).</summary>
    public static Task<List<GpuPowerInfo>> QueryAsync()
        => Simulate ? Task.FromResult(new List<GpuPowerInfo> { new(0, "Simulated GPU", 100, 250, 200, 200) }) : NvidiaPower.QueryAsync();

    /// <summary>Asks the system for administrator rights and applies the limits. Returns the session, or null and the reason.</summary>
    public static async Task<(PowerLimitSession? Session, string? Error)> StartAsync(PowerLimitRequest request, CancellationToken ct)
    {
        string? exe = Environment.ProcessPath;
        if (exe is null || Path.GetFileNameWithoutExtension(exe).Equals("dotnet", StringComparison.OrdinalIgnoreCase))
            return (null, "the power limit helper needs RecoverKit's own executable");
        var args = PowerHelper.CommandLine(Environment.ProcessId, request.Targets, Simulate);
        if (OperatingSystem.IsWindows()) return await StartWindowsAsync(exe, args, ct);
        if (OperatingSystem.IsLinux()) return await StartLinuxAsync(exe, args, ct);
        return (null, "GPU power limits are not supported on this system");
    }

    private static async Task<(PowerLimitSession?, string?)> StartWindowsAsync(string exe, List<string> args, CancellationToken ct)
    {
        int pid = Environment.ProcessId;
        var stop = new EventWaitHandle(false, EventResetMode.ManualReset, PowerHelper.StopEventName(pid));
        var applied = new EventWaitHandle(false, EventResetMode.ManualReset, PowerHelper.AppliedEventName(pid));
        Process? p;
        try
        {
            var psi = new ProcessStartInfo(exe) { UseShellExecute = true, Verb = "runas", WindowStyle = ProcessWindowStyle.Hidden };
            foreach (var a in args) psi.ArgumentList.Add(a);
            p = Process.Start(psi);
        }
        catch (System.ComponentModel.Win32Exception ex)
        {
            stop.Dispose(); applied.Dispose();
            return (null, ex.NativeErrorCode == 1223 ? "administrator rights were not granted" : ex.Message);
        }
        if (p is null) { stop.Dispose(); applied.Dispose(); return (null, "the helper did not start"); }
        var exited = p.WaitForExitAsync(ct);
        var ok = Task.Run(() => applied.WaitOne(TimeSpan.FromSeconds(60)), ct);
        await Task.WhenAny(exited, ok);
        if (ok.IsCompletedSuccessfully && ok.Result && !p.HasExited)
        {
            applied.Dispose();
            return (new PowerLimitSession(p, stop), null);
        }
        stop.Set();
        string error = p.HasExited ? HelperError(p.ExitCode) : "the helper did not respond";
        p.Dispose(); stop.Dispose(); applied.Dispose();
        return (null, error);
    }

    private static async Task<(PowerLimitSession?, string?)> StartLinuxAsync(string exe, List<string> args, CancellationToken ct)
    {
        const string pkexec = "/usr/bin/pkexec";
        if (!File.Exists(pkexec)) return (null, "pkexec is not installed");
        var psi = new ProcessStartInfo(pkexec) { UseShellExecute = false, RedirectStandardInput = true, RedirectStandardOutput = true };
        psi.ArgumentList.Add(exe);
        foreach (var a in args) psi.ArgumentList.Add(a);
        var p = Process.Start(psi)!;
        string? line;
        string last = "";
        while ((line = await p.StandardOutput.ReadLineAsync(ct)) is not null)
        {
            if (line == "applied") return (new PowerLimitSession(p, null), null);
            last = line;
        }
        await p.WaitForExitAsync(ct);
        int code = p.ExitCode;
        p.Dispose();
        return (null, code is 126 or 127 ? "administrator rights were not granted" : last.StartsWith("error: ") ? last[7..] : HelperError(code));
    }

    public static string HelperError(int code) => code switch
    {
        PowerHelper.ExitNoNvidiaSmi => "nvidia-smi was not found",
        PowerHelper.ExitRefused => "the chosen power limit is outside the range the GPU allows",
        PowerHelper.ExitFailed => "nvidia-smi could not change the power limit",
        PowerHelper.ExitBadArguments => "the helper was started with invalid arguments",
        PowerHelper.ExitNoParent => "the helper could not reach RecoverKit",
        _ => $"the helper exited with code {code}",
    };
}
