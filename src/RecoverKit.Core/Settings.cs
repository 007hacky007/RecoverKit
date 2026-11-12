using System.Text.Json;
using System.Text.Json.Serialization;

namespace RecoverKit.Core;

/// <summary>
/// The four CPU/GPU strategies, in dropdown order. Stored by name, so the order can
/// match the UI without breaking older settings files.
/// </summary>
public enum DeviceStrategy
{
    GpuOnly,      // "Keep one CPU thread free for each GPU": GPUs; the CPU when no GPU exists
    FastGpu,      // "Avoid the CPU whenever a GPU can run": same device choice, CPU only as a fallback
    GpuAndCpu,    // "Use maximum number of CPU threads": -D 1,2
    CpuOnly,      // "Don't use GPU threads": -D 1
}

public enum ProcessPriority { Idle, BelowNormal, Normal, High }

/// <summary>User preferences, stored as JSON in the per-user application data folder.</summary>
public sealed class Settings
{
    public string? HashcatPath { get; set; }
    public int Workload { get; set; } = 3;                    // hashcat -w 1..4 ("lag free display" .. "performance")
    public List<int> DisabledDevices { get; set; } = new();   // hashcat backend device ids the user unchecked (older settings)
    /// <summary>
    /// <see cref="Hashcat.BackendDevice.Key"/> of the devices the user unchecked. Preferred over
    /// <see cref="DisabledDevices"/>: ids shift when a driver adds or removes a backend, which could
    /// leave the wrong GPU out.
    /// </summary>
    public List<string> DisabledDeviceKeys { get; set; } = new();
    public DeviceStrategy Strategy { get; set; } = DeviceStrategy.GpuOnly;
    public ProcessPriority Priority { get; set; } = ProcessPriority.Idle;   // the recommended default
    public int MaxCpuThreads { get; set; }                    // OpenCL CPU worker threads; 0 = one per logical processor
    public bool PreventScreensaver { get; set; } = true;
    public bool OptimizedKernels { get; set; } = true;
    public bool UseNativeCpuEngine { get; set; } = true;      // built-in CPU kernels when no GPU is used
    /// <summary>
    /// With a GPU, run the built-in CPU engine at the same time as hashcat on another part of the
    /// keyspace (brute-force and mask attacks on formats with a built-in kernel).
    /// </summary>
    public bool HybridCpuGpu { get; set; } = true;
    /// <summary>
    /// For formats without a built-in kernel, also give hashcat the processor as an OpenCL device next
    /// to the GPUs (needs a CPU OpenCL runtime; usually adds little).
    /// </summary>
    public bool HashcatCpuWithGpu { get; set; }
    public string ExtraArguments { get; set; } = "";

    // GPU temperature guard and load limit (all off by default)
    public bool GpuTempGuard { get; set; }                    // pause hashcat when the hottest GPU reaches the limit
    public int GpuTempLimit { get; set; } = 85;               // °C, 60..100
    public int GpuTempHysteresis { get; set; } = 10;          // °C, 3..30: resume at or below limit - hysteresis
    public int GpuDutyPercent { get; set; } = 100;            // share of time the GPU works (100 = always); rests in between
    public bool GpuPowerLimit { get; set; }                   // NVIDIA power limit during attacks (asks for admin rights per attack)
    public Dictionary<int, int> GpuPowerWatts { get; set; } = new();   // nvidia-smi GPU index -> watts

    public bool UseExternalScenarioFile { get; set; }
    public string? ExternalScenarioFile { get; set; }
    public string? DataPath { get; set; }
    public string? DefaultDictionary { get; set; }
    public string? ExecuteOnSuccess { get; set; }
    public string? ExecuteOnFail { get; set; }

    public bool DontUsePasswordCache { get; set; }
    public bool DontUseKeyCache { get; set; }
    public bool ReduceOutput { get; set; }
    public bool DebugLogIncludeHashes { get; set; }          // off: extracted hashes are masked in the debug log

    // Key search and rainbow tables
    public string? RainbowTablesPath { get; set; }
    public bool AutoDecrypt { get; set; }

    /// <summary>Try Stay's fast key search on compatible ZipCrypto archives before password attacks.</summary>
    public bool TryStayZipAttack { get; set; } = true;
    public string DecryptSuffix { get; set; } = "_decrypted";

    public Dictionary<int, double> SpeedByMode { get; set; } = new();
    /// <summary>hashcat's own speed (GPUs only) in hybrid attacks, to split the next one.</summary>
    public Dictionary<int, double> GpuSpeedByMode { get; set; } = new();
    /// <summary>The built-in engine's speed next to hashcat in hybrid attacks.</summary>
    public Dictionary<int, double> CpuSpeedByMode { get; set; } = new();
    /// <summary>Seconds hashcat needs to start a hybrid run of this mode (until its first speed report).</summary>
    public Dictionary<int, double> GpuStartupByMode { get; set; } = new();
    public string? LastOpenedDirectory { get; set; }
    public string? LastDictionaryDirectory { get; set; }
    public int[]? WindowBounds { get; set; }

    [JsonIgnore] public static string AppDataDir { get; } = InitAppData();

    [JsonIgnore] public string PotfilePath => Path.Combine(AppDataDir, "recovered.potfile");
    [JsonIgnore] public string VolumePasswordCacheDir => Directory.CreateDirectory(Path.Combine(AppDataDir, "volume-passwords")).FullName;
    [JsonIgnore] public string KeyCachePath { get; set; } = Path.Combine(AppDataDir, "keys.cache");
    [JsonIgnore] public string SessionsDir { get; set; } = Directory.CreateDirectory(Path.Combine(AppDataDir, "sessions")).FullName;

    private static string FilePath => Path.Combine(AppDataDir, "settings.json");

    /// <summary>
    /// True when the data folder was redirected by RECOVERKIT_HOME or the portable marker, so logs
    /// stay next to the other data instead of the platform's standard log folder.
    /// </summary>
    [JsonIgnore] public static bool IsRelocated { get; private set; }

    /// <summary>
    /// Settings, potfile and sessions live in %APPDATA%\RecoverKit on Windows, ~/.config/RecoverKit
    /// on Linux and ~/Library/Application Support/RecoverKit on macOS, unless RECOVERKIT_HOME is set
    /// or a file named "portable" exists next to the executable (then .\userdata is used).
    /// </summary>
    private static string InitAppData()
    {
        var env = Environment.GetEnvironmentVariable("RECOVERKIT_HOME");
        var portable = File.Exists(Path.Combine(AppContext.BaseDirectory, "portable"));
        IsRelocated = !string.IsNullOrWhiteSpace(env) || portable;
        var dir = !string.IsNullOrWhiteSpace(env) ? env
            : portable ? Path.Combine(AppContext.BaseDirectory, "userdata")
            : Path.Combine(DefaultDataRoot(), "RecoverKit");
        Directory.CreateDirectory(dir);
        return dir;
    }

    /// <summary>The per-user application data root of this platform.</summary>
    private static string DefaultDataRoot()
    {
        // .NET maps ApplicationData to ~/.config on macOS; Apple's convention is Application Support.
        if (OperatingSystem.IsMacOS())
            return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Library", "Application Support");
        return Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
    }

    private static readonly JsonSerializerOptions Json = new() { WriteIndented = true, Converters = { new JsonStringEnumConverter() } };

    public static Settings Load()
    {
        try
        {
            if (File.Exists(FilePath))
                return JsonSerializer.Deserialize<Settings>(File.ReadAllText(FilePath), Json) ?? new Settings();
        }
        catch (JsonException) { /* fall back to defaults */ }
        return new Settings();
    }

    public void Save()
    {
        var tmp = FilePath + ".tmp";
        File.WriteAllText(tmp, JsonSerializer.Serialize(this, Json));
        File.Move(tmp, FilePath, overwrite: true);
    }

    public double SpeedFor(int mode, double fallback = 10000) => SpeedByMode.TryGetValue(mode, out var s) && s > 0 ? s : fallback;
}
