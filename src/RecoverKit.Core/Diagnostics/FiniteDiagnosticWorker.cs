using System.Diagnostics;
using System.Globalization;
using System.Text.Json;
using System.Runtime.InteropServices;
using RecoverKit.Core.Attacks;
using RecoverKit.Core.Hashcat;
using RecoverKit.Core.Native;

namespace RecoverKit.Core.Diagnostics;

/// <summary>Finite synthetic jobs run separately so a native failure preserves the main report.</summary>
public static class FiniteDiagnosticWorker
{
    public const string Command = "--rk-finite-diagnostic-worker";

    public sealed class Result
    {
        public bool Correct { get; set; }
        public double Speed { get; set; }
        public double ElapsedSeconds { get; set; }
        public string? Error { get; set; }
        public Dictionary<string, string> Details { get; set; } = new();
    }

    internal sealed class WorkerRequest
    {
        public string EngineExe { get; set; } = "";
        public int Mode { get; set; }
        public int Count { get; set; }
        public int Length { get; set; }
        public int Limit { get; set; }
        public WorkerLimits Limits { get; set; } = new();
        public List<WorkerDevice> Devices { get; set; } = [];
    }

    internal sealed class WorkerLimits
    {
        public ProcessPriority Priority { get; set; }
        public int Workload { get; set; }
        public bool OptimizedKernels { get; set; }
        public bool GpuTempGuard { get; set; }
        public int GpuTempLimit { get; set; }
        public int GpuTempHysteresis { get; set; }
        public int GpuDutyPercent { get; set; }
        public bool GpuPowerLimit { get; set; }
        public Dictionary<int, int> GpuPowerWatts { get; set; } = new();
    }

    internal sealed class WorkerDevice
    {
        public int Id { get; set; }
        public int? AliasOf { get; set; }
        public string Key { get; set; } = "";
        public string Name { get; set; } = "";
        public string Backend { get; set; } = "";
        public string BackendVersion { get; set; } = "";
        public string DriverVersion { get; set; } = "";
        public string Type { get; set; } = "";
        public string Vendor { get; set; } = "";
        public bool Unified { get; set; }
        public bool IsSkippedAlias { get; set; }
        public BackendDevice ToDevice() => new()
        {
            Id = Id, AliasOf = AliasOf, Key = Key, Name = Name, Backend = Backend, BackendVersion = BackendVersion,
            DriverVersion = DriverVersion, Type = Type, Vendor = Vendor, Unified = Unified, IsSkippedAlias = IsSkippedAlias,
        };
    }

    internal static WorkerRequest BuildRequest(string engineExe, Settings settings, IReadOnlyList<BackendDevice> group, int mode, int count, int length, int limit) => new()
    {
        EngineExe = engineExe, Mode = mode, Count = count, Length = length, Limit = limit,
        Limits = new()
        {
            Priority = settings.Priority, Workload = settings.Workload, OptimizedKernels = settings.OptimizedKernels,
            GpuTempGuard = settings.GpuTempGuard, GpuTempLimit = settings.GpuTempLimit, GpuTempHysteresis = settings.GpuTempHysteresis,
            GpuDutyPercent = settings.GpuDutyPercent, GpuPowerLimit = settings.GpuPowerLimit, GpuPowerWatts = new(settings.GpuPowerWatts),
        },
        Devices = group.Select(d => new WorkerDevice
        {
            Id = d.Id, AliasOf = d.AliasOf, Key = d.Key, Name = d.Name, Backend = d.Backend, BackendVersion = d.BackendVersion,
            DriverVersion = d.DriverVersion, Type = d.Type, Vendor = d.Vendor, Unified = d.Unified, IsSkippedAlias = d.IsSkippedAlias,
        }).ToList(),
    };

    public static async Task<Result> ExecuteAsync(HashcatTool tool, Settings settings, IReadOnlyList<BackendDevice> group,
        int mode, int count, int length, int limit, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        string? directory = null;
        try
        {
            directory = Directory.CreateTempSubdirectory("rk-finite-worker-").FullName;
            string requestFile = Path.Combine(directory, "request.json"), resultFile = Path.Combine(directory, "result.json");
            await File.WriteAllTextAsync(requestFile, JsonSerializer.Serialize(BuildRequest(tool.Exe, settings, group, mode, count, length, limit)), ct);
            var start = CpuDiagnosticWorker.SelfStartInfo();
            start.Environment["RECOVERKIT_HOME"] = directory;
            start.ArgumentList.Add(Command);
            start.ArgumentList.Add(requestFile);
            start.ArgumentList.Add(resultFile);
            var process = await CpuDiagnosticWorker.RunJsonProcessAsync(start, resultFile, TimeSpan.FromMinutes(3), ct, isolatedProcessGroup: true);
            return process.Error is not null ? Failed(process.Error) : ReadResult(process.ExitCode, process.Json);
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException or System.ComponentModel.Win32Exception)
        { return Failed($"Finite diagnostic worker could not start ({ex.GetType().Name})."); }
        finally
        {
            if (directory is not null)
                try { Directory.Delete(directory, true); } catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
        }
    }

    public static int Run(string[] args)
    {
        if (args.Length != 3 || args[0] != Command) return 2;
        Result result;
        try
        {
            ProtectChildProcesses();
            if (new FileInfo(args[1]).Length > 1_000_000) return 2;
            var request = JsonSerializer.Deserialize<WorkerRequest>(File.ReadAllText(args[1]));
            result = request is null ? Failed("Finite diagnostic request is invalid.") : RunJobAsync(request, Path.GetDirectoryName(Path.GetFullPath(args[1]))!).GetAwaiter().GetResult();
        }
        catch (Exception ex) { result = Failed($"Finite diagnostic worker failed ({ex.GetType().Name})."); }
        try { File.WriteAllText(args[2], JsonSerializer.Serialize(result)); return 0; }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return 3; }
    }

    private static async Task<Result> RunJobAsync(WorkerRequest value, string directory)
    {
        if (value.Mode is not (13000 or 17210) || value.Length is < 1 or > 10 || value.Count < -1
            || value.Count > Environment.ProcessorCount || value.Limit < 1 || value.Limit > Environment.ProcessorCount
            || value.Count > value.Limit || value.Limits is null || value.Devices is null)
            return Failed("Finite diagnostic request is invalid.");
        var devices = value.Devices.Select(d => d.ToDevice()).ToList();
        if (value.Count >= 0 && (devices.Count == 0 || devices.Any(d => !d.IsGpu || d.IsSkippedAlias)))
            return Failed("Finite diagnostic request has no eligible GPU group.");
        var limits = value.Limits;
        var settings = new Settings
        {
            Priority = limits.Priority, Workload = limits.Workload, OptimizedKernels = limits.OptimizedKernels,
            GpuTempGuard = limits.GpuTempGuard, GpuTempLimit = limits.GpuTempLimit, GpuTempHysteresis = limits.GpuTempHysteresis,
            GpuDutyPercent = limits.GpuDutyPercent, GpuPowerLimit = limits.GpuPowerLimit, GpuPowerWatts = limits.GpuPowerWatts,
            DontUsePasswordCache = true, SessionsDir = directory, MaxCpuThreads = value.Limit,
            Strategy = value.Count < 0 ? DeviceStrategy.CpuOnly : DeviceStrategy.GpuOnly,
            // Force -d even when this finite job uses only a subset of the available GPUs.
            DisabledDevices = [-1],
        };
        string hash = NativeKernels.BenchmarkHashes[value.Mode];
        DebugLog.RegisterHashes(hash);
        var kernel = NativeKernels.TryCreate(value.Mode, hash);
        if (value.Count != 0)
        {
            if (kernel is null) return Failed("Built-in CPU kernel is unavailable.");
            var check = value.Mode == 17210 ? CpuDiagnostics.CheckZipVariant(PerformanceProfiles.DefaultZipVariant()) : CpuDiagnostics.CheckKernel(value.Mode);
            if (!check.Passed) return Failed("Finite diagnostic CPU correctness check failed: " + DiagnosticHtml.Scrub(check.Error ?? "incorrect result"));
        }
        var tool = HashcatTool.Locate(value.EngineExe) ?? throw new InvalidOperationException("Isolated GPU engine unavailable.");
        tool.MaxCpuThreads = value.Limit;
        var maskArgs = new[] { "-a", "3", "-1", "ABCDEFGHIJKLMN", string.Concat(Enumerable.Repeat("?1", value.Length)) };
        var space = MaskSpace.FromHashcatArgs(maskArgs)!;
        var attack = new PreparedAttack { Description = "Synthetic finite diagnostics job", Keyspace = space.Keyspace(value.Length) };
        attack.Args.AddRange(maskArgs);
        string hashFile = Path.Combine(directory, "synthetic.hash");
        await File.WriteAllTextAsync(hashFile, hash + "\n");
        bool optimized = value.Count >= 0 && settings.OptimizedKernels && (await tool.ModeInfoAsync(value.Mode))?.HasOptimizedKernel == true;
        var run = new RunRequest
        {
            Mode = value.Mode, HashFile = hashFile, Attack = attack, SessionName = "finite-" + Guid.NewGuid().ToString("N"), SessionDir = directory,
            Settings = settings, Guard = HashcatRunner.GuardFor(settings, devices), UseOptimizedKernel = optimized,
        };
        using var timeout = new CancellationTokenSource(TimeSpan.FromMinutes(3));
        var timer = Stopwatch.StartNew();
        RunResult completed;
        if (value.Count < 0) completed = await new NativeRunner().RunAsync(kernel!, space, hash, run, timeout.Token);
        else if (value.Count == 0) completed = await new HashcatRunner(tool) { KnownDevices = devices }.RunAsync(run, timeout.Token);
        else completed = await new HybridRunner { Devices = devices, ThreadsOverride = value.Count }.RunAsync(new HybridPlan(kernel!, space), hash, run, tool, timeout.Token);
        bool correct = completed.Outcome == RunOutcome.Exhausted;
        var result = new Result
        {
            Correct = correct, Speed = correct ? (double)space.Keyspace(value.Length) / timer.Elapsed.TotalSeconds : 0,
            ElapsedSeconds = timer.Elapsed.TotalSeconds,
            Error = correct ? null : $"Finite job did not exhaust the synthetic keyspace ({completed.Outcome}); not eligible for selection.",
            Details = new() { ["Optimized"] = optimized.ToString(), ["Isolation"] = "Finite job ran in a separate process.", ["GPU temperature guard"] = (run.Guard?.TemperatureGuard ?? false).ToString(), ["GPU duty percent"] = limits.GpuDutyPercent.ToString(CultureInfo.InvariantCulture), ["Configured power limit"] = limits.GpuPowerLimit.ToString() },
        };
        if (completed.LastStatus is { } status)
            foreach (var device in status.Devices)
                result.Details[$"Engine speed {device.Id} {(device.Type is "GPU" or "CPU" ? device.Type : "device")}"] = device.Speed.ToString("F2", CultureInfo.InvariantCulture);
        return result;
    }

    internal static Result ReadResult(int exitCode, string json)
    {
        if (exitCode != 0) return Failed($"Finite diagnostic worker terminated (exit {exitCode}); result is ineligible.");
        try
        {
            var result = JsonSerializer.Deserialize<Result>(json);
            if (result is null || !double.IsFinite(result.Speed) || result.Speed < 0 || !double.IsFinite(result.ElapsedSeconds) || result.ElapsedSeconds < 0
                || result.Correct && (result.Speed <= 0 || result.ElapsedSeconds <= 0 || result.Error is not null)) return Failed("Finite diagnostic worker returned an invalid result.");
            if (!result.Correct && result.Error is null) return Failed("Finite diagnostic worker returned no completed result.");
            result.Details ??= new();
            return result;
        }
        catch (JsonException) { return Failed("Finite diagnostic worker returned invalid JSON."); }
    }

    // A native fault must not leave hashcat working after its diagnostic worker has exited.
    private static IntPtr _job;
    private static void ProtectChildProcesses()
    {
        if (!OperatingSystem.IsWindows())
        {
            if (SetProcessGroup(0, 0) != 0 && GetProcessGroup() != Environment.ProcessId)
                throw new InvalidOperationException("Cannot isolate diagnostic child processes.");
            return;
        }
        _job = CreateJobObject(IntPtr.Zero, null);
        if (_job == IntPtr.Zero) throw new InvalidOperationException("Cannot create diagnostic process job.");
        var limits = new JobLimits { Basic = new BasicLimits { Flags = 0x2000 } };
        if (!SetInformationJobObject(_job, 9, ref limits, (uint)Marshal.SizeOf<JobLimits>()) || !AssignProcessToJobObject(_job, GetCurrentProcess()))
        {
            CloseHandle(_job);
            _job = IntPtr.Zero;
            throw new InvalidOperationException("Cannot protect diagnostic child processes.");
        }
        // Keep the handle open for this short-lived process. The OS closes it on exit or native fault.
    }

    internal static void StopProcessGroup(int pid)
    {
        if (!OperatingSystem.IsWindows()) KillProcessGroup(-pid, 9);
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct BasicLimits
    {
        public long ProcessTime, JobTime;
        public uint Flags;
        public UIntPtr MinimumWorkingSet, MaximumWorkingSet;
        public uint ActiveProcessLimit;
        public UIntPtr Affinity;
        public uint PriorityClass, SchedulingClass;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IoCounters { public ulong ReadOperations, WriteOperations, OtherOperations, ReadBytes, WriteBytes, OtherBytes; }

    [StructLayout(LayoutKind.Sequential)]
    private struct JobLimits
    {
        public BasicLimits Basic;
        public IoCounters Io;
        public UIntPtr ProcessMemory, JobMemory, PeakProcessMemory, PeakJobMemory;
    }

    [DllImport("libc", EntryPoint = "setpgid", SetLastError = true)]
    private static extern int SetProcessGroup(int pid, int group);
    [DllImport("libc", EntryPoint = "getpgrp")]
    private static extern int GetProcessGroup();
    [DllImport("libc", EntryPoint = "kill", SetLastError = true)]
    private static extern int KillProcessGroup(int pid, int signal);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreateJobObject(IntPtr attributes, string? name);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetInformationJobObject(IntPtr job, int infoClass, ref JobLimits limits, uint size);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);
    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();
    [DllImport("kernel32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr handle);

    private static Result Failed(string message) => new() { Error = message };
}
