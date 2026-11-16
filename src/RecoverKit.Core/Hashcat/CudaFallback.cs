using System.Reflection;
using System.Text.Json;

namespace RecoverKit.Core.Hashcat;

/// <summary>
/// Runs NVIDIA GPUs through OpenCL instead of CUDA after a CUDA kernel failed to build on this PC (for
/// example a CUDA Toolkit newer than the driver). Remembered until the NVIDIA driver or RecoverKit
/// changes. An explicit NVIDIA backend preference overrides this automatic fallback.
/// </summary>
public static class CudaFallback
{
    private sealed record State(string Key, string Reason, DateTime When);

    internal static string FilePath { get; set; } = Path.Combine(Settings.AppDataDir, "cuda-fallback.json");

    private static State? _cached;
    private static bool _loaded;
    private static readonly object Gate = new();

    /// <summary>The NVIDIA driver version (from hashcat's OpenCL device list) and RecoverKit's version, or null without an NVIDIA CUDA device.</summary>
    internal static string? KeyFor(IReadOnlyList<BackendDevice>? known)
    {
        if (known is null || !known.Any(d => d.Backend == "CUDA")) return null;
        string driver = known.FirstOrDefault(d => d.DriverVersion.Length > 0 &&
            (d.Vendor.Contains("NVIDIA", StringComparison.OrdinalIgnoreCase) || d.Name.Contains("NVIDIA", StringComparison.OrdinalIgnoreCase)))?.DriverVersion ?? "?";
        string app = typeof(CudaFallback).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion ?? "?";
        return $"driver {driver}; RecoverKit {app}";
    }

    private static State? Load()
    {
        lock (Gate)
        {
            if (_loaded) return _cached;
            _loaded = true;
            try { _cached = File.Exists(FilePath) ? JsonSerializer.Deserialize<State>(File.ReadAllText(FilePath)) : null; }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException) { _cached = null; }
            return _cached;
        }
    }

    /// <summary>True when NVIDIA GPUs run through OpenCL on this PC with these devices.</summary>
    public static bool IsActive(IReadOnlyList<BackendDevice>? known)
        => KeyFor(known) is { } key && Load() is { } state && state.Key == key;

    /// <summary>Why CUDA is off, for the dependencies page and logs, or null.</summary>
    public static string? Reason(IReadOnlyList<BackendDevice>? known) => IsActive(known) ? Load()!.Reason : null;

    public static void Activate(IReadOnlyList<BackendDevice>? known, string reason)
    {
        if (KeyFor(known) is not { } key) return;
        var state = new State(key, reason, DateTime.UtcNow);
        lock (Gate)
        {
            _cached = state;
            _loaded = true;
            try
            {
                File.WriteAllText(FilePath + ".tmp", JsonSerializer.Serialize(state));
                File.Move(FilePath + ".tmp", FilePath, true);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { DebugLog.Warn("Could not save the CUDA fallback: " + ex.Message); }
        }
        DebugLog.Warn($"CUDA fallback active ({key}): {reason}");
    }

    /// <summary>Tries CUDA again (after RecoverKit's own CUDA compiler was installed).</summary>
    public static void Clear()
    {
        lock (Gate)
        {
            _cached = null;
            _loaded = true;
            try { File.Delete(FilePath); } catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
        }
    }

    internal static void ResetForTests(string path)
    {
        lock (Gate) { FilePath = path; _cached = null; _loaded = false; }
    }

    /// <summary>The OpenCL device that is the same GPU as a CUDA device, or null.</summary>
    internal static BackendDevice? OpenClTwin(BackendDevice cuda, IReadOnlyList<BackendDevice> known)
        => known.FirstOrDefault(o => o.Backend == "OpenCL" && (o.AliasOf == cuda.Id || cuda.AliasOf == o.Id));
}
