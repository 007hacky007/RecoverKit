using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text.Json;
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
    /// <summary>
    /// Second check for found passwords (<see cref="HashTarget.ConfirmPassword"/>). hashcat then runs with
    /// --keep-guessing and without its potfile; RecoverKit reads its outfile while it runs, stops it at the
    /// first confirmed password and caches only that one.
    /// </summary>
    public Func<byte[], bool>? ConfirmPassword { get; init; }
    /// <summary>The target needs RecoverKit's ZIP kernel to check a partial encrypted entry.</summary>
    public bool RequiresPartialZipKernel { get; init; }
    public ZipCheckBytesTarget? ZipCheckBytes { get; init; }
    internal string? CacheHashFile { get; init; }
    internal Func<bool>? ZipFilterReplayPending { get; init; }
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
    public bool RecheckFromStart { get; init; }
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

    /// <summary>
    /// hashcat's major version, for the restore arguments; read from <c>--version</c> on first use.
    /// Tests set it directly.
    /// </summary>
    public int HashcatMajorVersion
    {
        get => _major ??= tool.MajorVersion;
        set => _major = value;
    }
    private int? _major;

    /// <summary>
    /// Command line for a run. Resuming: hashcat 7 re-ran the command line stored in the .restore file
    /// (<c>--restore</c>). hashcat 8 no longer does (CVE-2026-68766; <c>--restore</c> only prints it): the
    /// same command line is given again with <c>--restore-position</c>, which takes only the position
    /// from the file. The request carries the same attack, so the arguments are rebuilt from it.
    /// </summary>
    public List<string> BuildArguments(RunRequest r)
    {
        string restore = RestoreFile(r.SessionDir, r.SessionName);
        if (r.Restore && HashcatMajorVersion is > 0 and < 8)
            return ["--session", r.SessionName, "--restore", "--restore-file-path", restore];

        var s = r.Settings;
        var a = new List<string> { "-m", r.Mode.ToString(), r.HashFile };
        a.AddRange(r.Attack.Args);
        if (r.VolumeCredentials is { } credentials) a.AddRange(credentials.Arguments);
        a.AddRange(["--session", r.SessionName, "--restore-file-path", restore]);
        a.AddRange(["--status", "--status-json", "--status-timer", "2", "--quiet"]);
        a.AddRange(["-o", OutFile(r.SessionDir, r.SessionName), "--outfile-format", "2"]);
        // With a confirmation check hashcat must not stop at (or cache) a password that only passes the
        // hash: it keeps guessing, and RecoverKit caches the confirmed one itself.
        if (r.ConfirmPassword is not null) a.AddRange(["--keep-guessing", "--potfile-disable"]);
        else if (s.DontUsePasswordCache) a.Add("--potfile-disable");
        else a.AddRange(["--potfile-path", r.PasswordCachePath ?? s.PotfilePath]);
        a.AddRange(["-w", Math.Clamp(s.Workload, 1, 4).ToString()]);
        a.AddRange(MustAvoidAppleOpenCl(r.Mode, OperatingSystem.IsMacOS())
            ? MetalOnlyArguments(s, KnownDevices, r.GpuOnly, r.ExcludeDevices)
            : DeviceArguments(s, KnownDevices, r.GpuOnly, r.ExcludeDevices, preferMetal: r.ConfirmPassword is not null && OperatingSystem.IsMacOS()));
        if (r.UseOptimizedKernel) a.Add("-O");
        if (r.Attack.Stdin is not null) a.AddRange(["--stdin-timeout-abort", "600"]);
        if (!string.IsNullOrWhiteSpace(s.ExtraArguments))
            // The persisted, length-checked decision owns -O, including on resume.
            a.AddRange(s.ExtraArguments.Split(' ', StringSplitOptions.RemoveEmptyEntries)
                .Where(x => x is not ("-O" or "--optimized-kernel-enable")));
        a.AddRange(HwmonArguments(s, r.Guard));
        if (r.Restore) a.Add("--restore-position");
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
    /// <remarks>
    /// <paramref name="preferMetal"/> (macOS, runs with --keep-guessing): each GPU runs through its Metal
    /// device instead of the OpenCL alias hashcat picks by default. With Apple's OpenCL, hashcat 8 never
    /// clears a hash's "shown" flag after a hit (its clEnqueueFillBuffer reset has no effect), so with
    /// --keep-guessing it reports nothing after the first hit: on an M1 Pro a run that found a false
    /// positive missed the real password later in the same run, on OpenCL with both hashcat's kernel
    /// and RecoverKit's, while Metal reported both.
    /// </remarks>
    public static List<string> DeviceArguments(Settings s, IReadOnlyList<BackendDevice>? known, bool gpuOnly = false,
        IReadOnlyCollection<int>? exclude = null, bool preferMetal = false)
    {
        var a = new List<string>();
        // With no GPU among the detected devices the GPU-first strategies fall back to the processor,
        // instead of failing with "no devices found".
        bool noGpu = known is { Count: > 0 } && !known.Any(d => d.IsGpu && !d.IsSkippedAlias && !IsDisabled(s, d) && exclude?.Contains(d.Id) != true);
        bool cpuDevice = known?.Any(d => !d.IsSkippedAlias && d.Type.Contains("CPU", StringComparison.OrdinalIgnoreCase)) == true;
        if (gpuOnly && !noGpu) a.AddRange(["-D", "2"]);
        else
            switch (s.Strategy)
            {
                case DeviceStrategy.GpuAndCpu: a.AddRange(["-D", noGpu ? "1" : "1,2"]); break;
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
        var measuredKeys = (s.PerformanceChoice?.DeviceKeys is { Count: > 0 } executionKeys ? executionKeys : s.GpuPerformanceChoice?.DeviceKeys);
        if (measuredKeys is { Count: > 0 } && known is not null)
        {
            var selected = known.Where(d => d.IsGpu && measuredKeys.Contains(d.Key) && !IsDisabled(s, d) && exclude?.Contains(d.Id) != true).ToList();
            if (selected.Count > 0) { a.AddRange(["-d", string.Join(',', selected.Select(d => d.Id))]); AddBackendIgnores(); return a; }
        }
        bool anyOff = s.DisabledDeviceKeys.Count > 0 || s.DisabledDevices.Count > 0 || exclude is { Count: > 0 };
        if (preferMetal && known is not null && known.Any(d => d.IsMetal && d.IsSkippedAlias && d.AliasOf is int))
        {
            var ids = new List<int>();
            bool gpuTypesOnly = a.Count >= 2 && a[^2] == "-D" && a[^1] == "2";
            foreach (var d in known.Where(d => !d.IsSkippedAlias && !IsDisabled(s, d) && (d.IsGpu || !gpuTypesOnly)))
            {
                var metal = d.IsGpu && !d.IsMetal ? known.FirstOrDefault(m => m.IsMetal && m.AliasOf == d.Id) : null;
                if (exclude?.Contains(d.Id) == true || (metal is not null && exclude?.Contains(metal.Id) == true)) continue;
                ids.Add(metal?.Id ?? d.Id);
            }
            if (ids.Count > 0)
            {
                a.AddRange(["-d", string.Join(',', ids)]);
                AddBackendIgnores();
                return a;
            }
        }
        if (anyOff && known is not null)
        {
            var enabled = known.Where(d => !d.IsSkippedAlias && !IsDisabled(s, d) && exclude?.Contains(d.Id) != true).Select(d => d.Id).ToList();
            if (enabled.Count > 0) a.AddRange(["-d", string.Join(',', enabled)]);
        }
        AddBackendIgnores();
        return a;

        void AddBackendIgnores()
        {
            if (known is not { Count: > 0 }) return;
            var enabled = known.Where(d => d.IsGpu && !d.IsSkippedAlias && !IsDisabled(s, d) && exclude?.Contains(d.Id) != true).ToList();
            bool cpuOnly = s.Strategy == DeviceStrategy.CpuOnly && !gpuOnly;
            // An unidentified GPU might still need either backend. Its aliases can supply the vendor.
            IEnumerable<BackendDevice> WithAliases(BackendDevice device)
                => new[] { device }.Concat(known.Where(alias => alias.AliasOf == device.Id));
            var enabledWithAliases = enabled.SelectMany(WithAliases).ToList();
            bool unknown = enabled.Any(d => !WithAliases(d).Any(device => device.Backend is "CUDA" or "HIP" or "Metal" ||
                    HasVendor(device, "NVIDIA") || HasVendor(device, "AMD") || HasVendor(device, "Advanced Micro Devices") ||
                    HasVendor(device, "Intel") || HasVendor(device, "Apple")));
            bool ignoreCuda = cpuOnly || !unknown && !enabledWithAliases.Any(d => d.Backend == "CUDA" || HasVendor(d, "NVIDIA"));
            bool ignoreHip = cpuOnly || !unknown && !enabledWithAliases.Any(d => d.Backend == "HIP" || HasVendor(d, "AMD") || HasVendor(d, "Advanced Micro Devices"));
            if (ignoreCuda && !a.Contains("--backend-ignore-cuda")) a.Add("--backend-ignore-cuda");
            if (ignoreHip && !a.Contains("--backend-ignore-hip")) a.Add("--backend-ignore-hip");
            int selection = a.IndexOf("-d");
            if (selection < 0) return;
            var removed = known.Where(d => ignoreCuda && d.Backend == "CUDA" || ignoreHip && d.Backend == "HIP").ToList();
            // Backend ignores remove devices before hashcat assigns ids, shifting later -d selections.
            a[selection + 1] = string.Join(',', a[selection + 1].Split(',').Select(int.Parse)
                .Where(id => !removed.Any(d => d.Id == id))
                .Select(id => id - removed.Count(d => d.Id < id)));
        }
    }

    private static bool HasVendor(BackendDevice d, string vendor)
        => d.Vendor.Contains(vendor, StringComparison.OrdinalIgnoreCase) || d.Name.Contains(vendor, StringComparison.OrdinalIgnoreCase);

    /// <summary>Whether the user unchecked this device (by its stable key; ids only for older settings files).</summary>
    public static bool IsDisabled(Settings s, BackendDevice d)
        => s.DisabledDeviceKeys.Count > 0 ? s.DisabledDeviceKeys.Contains(d.Key) : s.DisabledDevices.Contains(d.Id);

    /// <summary>The GPUs hashcat will run on with these settings (not skipped as an alias, not unchecked).</summary>
    /// <summary>
    /// On macOS hashcat never runs a format on Apple's OpenCL. On an idle M1 Pro hashcat 8.0.0 ended
    /// wordlist attacks without the password and without an error on the OpenCL device with the pure
    /// kernel: RAR 3 in 3 of 33 runs, PDF 1.7 Level 8 in 6 of 17. The Metal device found the password
    /// in every run of every format measured. A format where Metal misses a password goes into
    /// <see cref="MetalMisses"/> and is decided on its own measurements.
    /// </summary>
    public static bool MustAvoidAppleOpenCl(int mode, bool isMacOS) => isMacOS && !MetalMisses.Contains(mode);

    /// <summary>Modes where hashcat on Metal missed a password; none so far.</summary>
    internal static readonly IReadOnlySet<int> MetalMisses = new HashSet<int>();

    /// <summary>
    /// Device arguments that keep hashcat off OpenCL: every selected GPU is replaced by its Metal
    /// device and the OpenCL interface is not opened, so a GPU without a Metal device makes hashcat
    /// stop with an error instead of skipping candidates. The "don't use GPUs" strategy is left as it
    /// is, because hashcat reaches the processor only through OpenCL.
    /// </summary>
    public static List<string> MetalOnlyArguments(Settings s, IReadOnlyList<BackendDevice>? known, bool gpuOnly = false,
        IReadOnlyCollection<int>? exclude = null)
    {
        var a = DeviceArguments(s, known, gpuOnly, exclude, preferMetal: true);
        if (s.Strategy == DeviceStrategy.CpuOnly) return a;
        int at = a.IndexOf("-d");
        if (at >= 0 && at + 1 < a.Count && known is not null)
            a[at + 1] = string.Join(',', a[at + 1].Split(',').Select(text =>
            {
                if (!int.TryParse(text, out int id) || known.FirstOrDefault(k => k.Id == id) is not { IsGpu: true, IsMetal: false } d) return text;
                return known.FirstOrDefault(m => m.IsMetal && (m.AliasOf == d.Id || d.AliasOf == m.Id))?.Id.ToString() ?? text;
            }).Distinct());
        a.Add("--backend-ignore-opencl");
        return a;
    }

    /// <summary>GPU-only device arguments for <paramref name="mode"/>: Metal only on macOS, as in a recovery run.</summary>
    internal static List<string> GpuArguments(Settings s, IReadOnlyList<BackendDevice>? known, int mode, IReadOnlyCollection<int>? exclude = null)
        => MustAvoidAppleOpenCl(mode, OperatingSystem.IsMacOS())
            ? MetalOnlyArguments(s, known, gpuOnly: true, exclude)
            : DeviceArguments(s, known, gpuOnly: true, exclude, preferMetal: OperatingSystem.IsMacOS());

    public static List<BackendDevice> ActiveGpus(Settings s, IReadOnlyList<BackendDevice>? known)
    {
        if (known is null) return [];
        var measured = s.PerformanceChoice?.DeviceKeys is { Count: > 0 } executionKeys ? executionKeys : s.GpuPerformanceChoice?.DeviceKeys;
        return known.Where(d => d.IsGpu && !IsDisabled(s, d) && (measured is { Count: > 0 } ? measured.Contains(d.Key) : !d.IsSkippedAlias)).ToList();
    }

    /// <summary>
    /// True when the "Don't use GPU threads" strategy is chosen but hashcat sees no CPU device
    /// (Apple Silicon: Apple's OpenCL and Metal expose only the GPU), so -D 1 finds nothing.
    /// </summary>
    /// <summary>Start of the error text when "CPU only" is chosen but hashcat sees no processor device (Windows, Linux).</summary>
    public const string NoCpuDeviceMessage =
        "\"CPU only\" is selected, but hashcat has no processor (CPU) device: it needs a CPU OpenCL runtime for that. " +
        "Install it with Tools > Dependencies, or choose a GPU strategy in Preferences. " +
        "The built-in CPU engine still runs ZIP, Office 97-2003, PDF and RAR 3.x without it.";

    public static bool NoCpuDevice(Settings s, IReadOnlyList<BackendDevice>? known)
        => s.Strategy == DeviceStrategy.CpuOnly && known is { Count: > 0 } &&
           !known.Any(d => d.Type.Contains("CPU", StringComparison.OrdinalIgnoreCase));

    /// <summary>hashcat skipped the mode on every device (Apple GPUs refuse a few modes).</summary>
    public static bool IsGpuRefusal(string? error, int mode)
        => OperatingSystem.IsMacOS() && error?.Contains($"Skipping (hash-mode {mode})", StringComparison.Ordinal) == true;

    public IReadOnlyList<BackendDevice>? KnownDevices { get; set; }

    /// <summary>Hits rejected by the confirmation check, over all runs of this runner (a session); shared in hybrid runs.</summary>
    public FalsePositiveLog FalsePositives
    {
        get => _falsePositives ??= new FalsePositiveLog(l => OutputLine?.Invoke(l));
        set => _falsePositives = value;
    }
    private FalsePositiveLog? _falsePositives;

    /// <summary>How often the outfile is read for new hits when a confirmation check is set.</summary>
    internal TimeSpan OutfilePollInterval { get; set; } = TimeSpan.FromMilliseconds(500);

    /// <summary>The last attack mode on the rebuilt command line, including user arguments.</summary>
    internal static int EffectiveAttackMode(PreparedAttack attack, string? extraArguments)
    {
        var args = attack.Args.Concat((extraArguments ?? "").Split(' ', StringSplitOptions.RemoveEmptyEntries)).ToList();
        int mode = 0;
        for (int i = 0; i < args.Count; i++)
        {
            string? value = args[i] switch
            {
                "-a" or "--attack-mode" => ++i < args.Count ? args[i] : "",
                var arg when arg.StartsWith("--attack-mode=", StringComparison.Ordinal) => arg[14..],
                var arg when arg.StartsWith("-a", StringComparison.Ordinal) && arg.Length > 2 => arg[2..],
                _ => null,
            };
            if (value is not null) mode = int.TryParse(value, out int parsed) ? parsed : -1;
        }
        return mode;
    }

    public async Task<RunResult> RunAsync(RunRequest r, CancellationToken ct)
    {
        r.VolumeCredentials?.ValidateUnchanged();
        if (r.ZipCheckBytes is { } filter)
            return await RunCheckBytesAsync(r, filter, ct);
        int attackMode = EffectiveAttackMode(r.Attack, r.Settings.ExtraArguments);
        bool kernelsReady = HashcatKernels.EnsureFor(tool, r.Mode, attackMode);
        if (r.RequiresPartialZipKernel && !kernelsReady)
            return new RunResult { Outcome = RunOutcome.Error, Error = "This partial ZIP target requires RecoverKit's ZIP kernel and a supported dictionary or mask attack. Check the hashcat installation and kernel settings." };
        using var zipProfile = HashcatKernels.ApplyProfile(tool, r.Mode, r.RequiresPartialZipKernel ? null : r.Settings.ZipGpuPerformanceChoice?.Variant);
        string outFile = OutFile(r.SessionDir, r.SessionName);
        if (!r.Restore && File.Exists(outFile)) File.Delete(outFile);
        var confirm = r.ConfirmPassword is { } cf ? new OutfileConfirmer(outFile, cf, FalsePositives) : null;
        long progress = 0;
        string restoreFile = RestoreFile(r.SessionDir, r.SessionName);
        if (!r.Restore && File.Exists(restoreFile)) File.Delete(restoreFile);
        long checkpoint = Native.HybridRunner.ReadRestorePoint(restoreFile) ?? 0;
        int retries = 0;
        int cudaHintShown = 0;
        void Output(string line)
        {
            if (!HashcatOutput.IsCudaCompilerAdvice(line)) OutputLine?.Invoke(line);
            if (HashcatOutput.NeedsCudaCompilerHint(line) && Interlocked.Exchange(ref cudaHintShown, 1) == 0)
                OutputLine?.Invoke("NVIDIA OpenCL fallback: use Tools > Dependencies to enable CUDA.");
        }
        while (true)
        {
            if (ct.IsCancellationRequested) return new RunResult { Outcome = RunOutcome.Aborted };
            var result = await RunAttemptAsync(r, confirm, Output, ct);
            if (result.Outcome != RunOutcome.Error || ct.IsCancellationRequested || !HashcatOutput.IsTransientFailure(result.Error)) return result;
            long nextProgress = result.LastStatus?.ProgressDone ?? 0;
            long nextCheckpoint = Native.HybridRunner.ReadRestorePoint(RestoreFile(r.SessionDir, r.SessionName)) ?? 0;
            if (nextProgress > progress || nextCheckpoint > checkpoint) retries = 0;
            progress = Math.Max(progress, nextProgress);
            checkpoint = Math.Max(checkpoint, nextCheckpoint);
            if (retries >= 3) return result;
            retries++;
            bool restore = r.Attack.Stdin is null && File.Exists(restoreFile);
            OutputLine?.Invoke("The GPU stopped with an error; " +
                (restore ? "resuming from the last checkpoint" : r.Attack.Stdin is not null
                    ? "restarting this step because the candidate generator cannot resume"
                    : "restarting this step because no checkpoint was saved") + $" (retry {retries} of 3).");
            try { await Task.Delay(TimeSpan.FromMilliseconds(100), ct); }
            catch (OperationCanceledException) { return new RunResult { Outcome = RunOutcome.Aborted, LastStatus = result.LastStatus }; }
            r = r with { Restore = restore };
        }
    }

    public static string ZipFilterStateFile(string directory, string session) => Path.Combine(directory, session + ".zip-filter.json");

    private sealed class ZipFilterState
    {
        public string Phase { get; set; } = "headers";
        public string HashLines { get; set; } = "";
    }

    private async Task<RunResult> RunCheckBytesAsync(RunRequest r, ZipCheckBytesTarget filter, CancellationToken ct)
    {
        string stateFile = ZipFilterStateFile(r.SessionDir, r.SessionName);
        string hash = Path.Combine(r.SessionDir, r.SessionName + ".headers.hash");
        string restore = RestoreFile(r.SessionDir, r.SessionName);
        var state = new ZipFilterState { HashLines = filter.HashLines };
        if (File.Exists(stateFile))
        {
            try { state = JsonSerializer.Deserialize<ZipFilterState>(File.ReadAllText(stateFile)) ?? new() { Phase = "replay" }; }
            catch (JsonException) { state.Phase = "replay"; }
        }
        if (!r.Restore && state.Phase == "headers") state.HashLines = filter.HashLines;
        void Save()
        {
            File.WriteAllText(stateFile + ".tmp", JsonSerializer.Serialize(state));
            File.Move(stateFile + ".tmp", stateFile, true);
        }
        bool finished = false;
        try
        {
            if (state.Phase == "headers")
            {
                if (!r.Restore) File.Delete(restore);
                if (r.ExcludeDevices is { Count: > 0 } && KnownDevices is { } known && !r.Restore)
                {
                    var profile = await Diagnostics.PerformanceCalibration.EnsureZipAsync(tool, r.Settings, known, r.Mode,
                        PasswordConfirmation.FirstHashLine(r.HashFile), filter, message => OutputLine?.Invoke(message), ct, r.ExcludeDevices);
                    if (!ZipCheckBytesTarget.IsFaster(profile, r.Settings, known, r.Mode, r.ExcludeDevices)) state.Phase = "replay";
                }
                if (r.GpuOnly && state.Phase == "headers")
                {
                    // Hybrid ranges count base words; switching modes must preserve the amplifier split.
                    var original = await tool.KeyspaceAsync(r.Mode, r.Attack.Args, ct, r.UseOptimizedKernel);
                    var headers = await tool.KeyspaceAsync(17230, r.Attack.Args, ct);
                    if (original is null || headers != original) state.Phase = "replay";
                }
                if (state.Phase == "headers")
                {
                    Save();
                    File.WriteAllText(hash, state.HashLines + "\n");
                    bool Confirm(byte[] password)
                    {
                        if (filter.ConfirmPassword(password)) return true;
                        if (state.Phase != "replay")
                        {
                            state.Phase = "replay";
                            Save(); // Persist before allowing a checkpoint to outlive the rejected hit.
                        }
                        return false;
                    }
                    OutputLine?.Invoke("ZIP check bytes on the GPU, full entry confirmation on the CPU (mode 17230).");
                    var result = await RunAsync(r with
                    {
                        Mode = 17230, HashFile = hash, UseOptimizedKernel = false, RequiresPartialZipKernel = false,
                        ZipCheckBytes = null, ConfirmPassword = Confirm, CacheHashFile = r.HashFile,
                        ZipFilterReplayPending = () => state.Phase == "replay",
                    }, ct);
                    if (result.Outcome == RunOutcome.Cracked || state.Phase == "headers")
                    {
                        finished = result.Outcome is RunOutcome.Cracked or RunOutcome.Exhausted;
                        return result;
                    }
                    if (result.Outcome == RunOutcome.Aborted || ct.IsCancellationRequested)
                        return new RunResult { Outcome = RunOutcome.Aborted, RecheckFromStart = true,
                            LastStatus = result.LastStatus?.With(restorePoint: 0) ?? new() };
                    OutputLine?.Invoke("A ZIP header hit was rejected; rechecking this assigned range on the original entry.");
                }
            }
            if (state.Phase != "original")
            {
                File.Delete(restore); // A header checkpoint is not an original-entry checkpoint.
                state.Phase = "original";
                Save();
                r = r with { Restore = false };
            }
            var replay = await RunAsync(r with { ZipCheckBytes = null }, ct);
            finished = replay.Outcome is RunOutcome.Cracked or RunOutcome.Exhausted;
            if (replay.Outcome == RunOutcome.Error)
                return new RunResult { Outcome = replay.Outcome, Error = replay.Error, ExitCode = replay.ExitCode,
                    LastStatus = replay.LastStatus, RecheckFromStart = true };
            return replay;
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            bool recheck = state.Phase == "replay";
            return new RunResult { Outcome = RunOutcome.Aborted, RecheckFromStart = recheck,
                LastStatus = new() { RestorePoint = recheck ? 0 : Native.HybridRunner.ReadRestorePoint(restore) ?? 0 } };
        }
        finally
        {
            if (finished)
                foreach (string file in new[] { hash, stateFile })
                    try { File.Delete(file); } catch (IOException) { }
        }
    }

    private Dictionary<int, int> OriginalDeviceIds(IReadOnlyList<string> args)
    {
        if (KnownDevices is not { Count: > 0 } known) return [];
        var removed = known.Where(d => args.Contains("--backend-ignore-" + d.Backend.ToLowerInvariant())).ToList();
        if (removed.Count == 0) return [];
        return known.Where(d => !removed.Contains(d))
            .ToDictionary(d => d.Id - removed.Count(skipped => skipped.Id < d.Id), d => d.Id);
    }

    private async Task<RunResult> RunAttemptAsync(RunRequest r, OutfileConfirmer? confirm, Action<string> output, CancellationToken ct)
    {
        var args = BuildArguments(r);
        // Older hashcat restores its saved command line, whose device settings come from this request.
        var originalIds = OriginalDeviceIds(r.Restore && HashcatMajorVersion is > 0 and < 8
            ? BuildArguments(r with { Restore = false }) : args);
        string outFile = OutFile(r.SessionDir, r.SessionName);
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
                // Every consumer, including the guard and hybrid scheduler, uses the discovery ids.
                if (originalIds.Count > 0)
                    st = st.With(st.Devices.Select(d => originalIds.TryGetValue(d.Id, out int id)
                        ? new DeviceSpeed
                        {
                            Id = id, Name = d.Name, Type = d.Type, Speed = d.Speed,
                            Temperature = d.Temperature, Utilization = d.Utilization,
                        } : d).ToList());
                if (r.ZipFilterReplayPending?.Invoke() == true) st = st.With(restorePoint: 0);
                last = st;
                GpuTemperature.Record(st);
                StatusReceived?.Invoke(guard?.Adjust(st) ?? st);
                return;
            }
            Remember(tail, e.Data);
            if (e.Data.Length > 0) output(e.Data);
        };
        p.ErrorDataReceived += (_, e) =>
        {
            if (string.IsNullOrEmpty(e.Data)) return;
            DebugLog.ProcessOutput(logId, "stderr", e.Data);
            Remember(tail, e.Data);
            output(e.Data);
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
        // Confirmation check: hashcat keeps guessing; each hit it writes to the outfile is checked here
        // and the first confirmed one stops it.
        using var tailCts = new CancellationTokenSource();
        Task outfileTail = Task.CompletedTask;
        if (confirm is not null)
            outfileTail = Task.Run(async () =>
            {
                while (!tailCts.IsCancellationRequested && !p.HasExited)
                {
                    try { await Task.Delay(OutfilePollInterval, tailCts.Token); } catch (OperationCanceledException) { break; }
                    if (confirm.Poll(final: false))
                    {
                        DebugLog.Info($"#{logId}: confirmed password found, stopping hashcat");
                        guard?.BeforeStop();
                        pumpCts.Cancel();
                        await StopAsync(p);
                        break;
                    }
                }
            });
        using (ct.Register(() => { stopped = true; guard?.BeforeStop(); pumpCts.Cancel(); _ = StopAsync(p); }))
        {
            await p.WaitForExitAsync(CancellationToken.None);
        }
        tailCts.Cancel();
        await outfileTail;
        guard?.Dispose();
        pumpCts.Cancel();
        try { await pump.WaitAsync(TimeSpan.FromSeconds(5)); } catch (TimeoutException) { }
        p.WaitForExit(); // flush async output handlers

        int code = p.ExitCode;
        DebugLog.ProcessExit(logId, code, sw.Elapsed);
        if (stopped) DebugLog.Info($"#{logId} was stopped by the user");
        List<string> raw;
        if (confirm is not null)
        {
            // Only a confirmed hit counts; the outfile's other lines are false positives.
            confirm.Poll(final: true);
            raw = confirm.Confirmed is { } c ? [c] : [];
        }
        else
            raw = File.Exists(outFile)
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
        if (confirm is not null)
        {
            // hashcat's own verdict does not count: it ended on its own without a confirmed hit (exhausted),
            // or RecoverKit stopped it at one (cracked).
            if (confirm.Confirmed is not null) outcome = RunOutcome.Cracked;
            else if (outcome == RunOutcome.Cracked) outcome = RunOutcome.Exhausted;
            if (confirm.Confirmed is { } plain && !r.Settings.DontUsePasswordCache)
                await PasswordConfirmation.AppendAsync(r.PasswordCachePath ?? r.Settings.PotfilePath,
                    PasswordConfirmation.FirstHashLine(r.CacheHashFile ?? r.HashFile), PasswordConfirmation.PlainBytes(plain));
        }
        else if (outcome == RunOutcome.Cracked && passwords.Count == 0 && !r.Settings.DontUsePasswordCache)
            passwords = await tool.ShowAsync(r.Mode, r.HashFile, r.PasswordCachePath ?? r.Settings.PotfilePath, r.VolumeCredentials);
        if (stopped && outcome != RunOutcome.Cracked) outcome = RunOutcome.Aborted;

        string? error = outcome == RunOutcome.Error ? HashcatOutput.FailureMessage(tail, code) : null;
        if (outcome == RunOutcome.Error && NoCpuDevice(r.Settings, KnownDevices))
            error = (OperatingSystem.IsMacOS()
                ? "hashcat has no processor (CPU) device on this computer: Apple Silicon Macs expose only the GPU to hashcat. " +
                  "Choose a GPU strategy in Preferences (the built-in CPU engine still runs the formats it supports).\n"
                : NoCpuDeviceMessage + "\n") + error;
        // hashcat refuses some modes on Apple GPUs (hashcat 7 did so for 17200 PKZIP: no goto in Metal, OpenCL compiler hang).
        else if (outcome == RunOutcome.Error && IsGpuRefusal(error, r.Mode))
            error = $"hashcat cannot run hash mode {r.Mode} on the Apple GPU (a known Metal/OpenCL runtime limitation). " +
                    "If the built-in CPU engine supports this format, choose \"Don't use GPU threads\" in Preferences to use it.\n" + error;

        return new RunResult { Outcome = outcome, ExitCode = code, Passwords = passwords, RawPasswords = raw, Error = error, LastStatus = last };
    }

    /// <summary>
    /// Reads the lines hashcat appends to its outfile (format 2: one plaintext per line) and checks each
    /// with the confirmation function until one passes.
    /// </summary>
    internal sealed class OutfileConfirmer(string path, Func<byte[], bool> confirm, FalsePositiveLog log)
    {
        private long _offset;
        private readonly List<byte> _partial = new();
        private readonly HashSet<string> _seen = new();

        /// <summary>The first confirmed plaintext, as hashcat wrote it ($HEX[...] kept).</summary>
        public string? Confirmed { get; private set; }

        /// <summary>Checks new complete lines (and with <paramref name="final"/> an unterminated last one); true once confirmed.</summary>
        public bool Poll(bool final)
        {
            if (Confirmed is not null) return true;
            byte[] chunk;
            try
            {
                if (!File.Exists(path)) return false;
                using var f = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                if (f.Length < _offset) _offset = 0;    // replaced
                f.Position = _offset;
                chunk = new byte[f.Length - _offset];
                int n = 0;
                while (n < chunk.Length && f.Read(chunk, n, chunk.Length - n) is var k and > 0) n += k;
                if (n < chunk.Length) Array.Resize(ref chunk, n);
                _offset += n;
            }
            catch (IOException) { return false; }
            catch (UnauthorizedAccessException) { return false; }

            foreach (var b in chunk)
            {
                if (b != (byte)'\n') { _partial.Add(b); continue; }
                if (Check()) return true;
            }
            return final && _partial.Count > 0 && Check();
        }

        private bool Check()
        {
            int len = _partial.Count;
            if (len > 0 && _partial[len - 1] == (byte)'\r') len--;
            string line = System.Text.Encoding.UTF8.GetString(_partial.ToArray(), 0, len);
            _partial.Clear();
            if (!_seen.Add(line)) return false;   // an empty line is an empty password
            var pw = PasswordConfirmation.PlainBytes(line);
            if (confirm(pw)) { Confirmed = line; return true; }
            log.Rejected(pw.Length, "hashcat");
            return false;
        }
    }

    private static void Remember(Queue<string> q, string line)
    {
        if (HashcatOutput.IsStartupAdvice(line) || string.IsNullOrWhiteSpace(line)) return;
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
