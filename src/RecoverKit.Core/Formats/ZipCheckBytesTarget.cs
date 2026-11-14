using System.Text.Json;
using RecoverKit.Core.Diagnostics;
using RecoverKit.Core.Hashcat;

namespace RecoverKit.Core.Formats;

/// <summary>A GPU header filter over the same entries and checks used by CPU confirmation.</summary>
public sealed record ZipCheckBytesTarget(string HashLines, Func<byte[], bool> ConfirmPassword)
{
    // Eight one-byte entries give 64 nominal bits. CRC/time alternatives reduce that to at least
    // 56 effective bits (8 * 7): at 100 billion/s and 0.1 s/launch, at most 1e10/2^56 = 1.4e-7
    // false hits/launch, versus 0.29 for five such entries. Four verified old two-byte entries
    // give 64 effective bits. An observed rejected hit still requires replay of its assigned range.
    internal const int MinimumCheckBits = 64;
    internal const int MaximumEntries = 8;

    internal static IReadOnlyList<BackendDevice> ActiveDevices(Settings settings, IReadOnlyList<BackendDevice> devices, IReadOnlyCollection<int>? exclude = null)
    {
        var args = HashcatRunner.GpuArguments(settings, devices, 17230, exclude);
        int selection = args.IndexOf("-d");
        if (selection < 0) return HashcatRunner.ActiveGpus(settings, devices).Where(d => exclude?.Contains(d.Id) != true).ToList();
        var ids = args[selection + 1].Split(',').Where(s => s.Length > 0).Select(int.Parse).ToHashSet();
        var removed = devices.Where(d => args.Contains("--backend-ignore-" + d.Backend.ToLowerInvariant())).ToList();
        return devices.Where(d => d.IsGpu && !removed.Contains(d) && ids.Contains(d.Id - removed.Count(old => old.Id < d.Id))).ToList();
    }

    internal static List<PerformanceDecision> Rates(PerformanceProfile profile, Settings settings, IReadOnlyList<BackendDevice> devices, IReadOnlyCollection<int>? exclude = null)
    {
        var keys = ActiveDevices(settings, devices, exclude).Select(d => d.Key).Order(StringComparer.Ordinal).ToArray();
        if (keys.Length == 0) return [];
        string policy = PerformanceProfiles.PolicyFingerprint(settings, "zip");
        // Probes run the GPU alone; enabling the hybrid CPU does not change the measured device set.
        var alternate = JsonSerializer.Deserialize<Settings>(JsonSerializer.Serialize(settings))!;
        alternate.HybridCpuGpu = !settings.HybridCpuGpu;
        string alternatePolicy = PerformanceProfiles.PolicyFingerprint(alternate, "zip");
        return profile.Decisions.Where(d => d.Domain is "zip" or "zip-filter"
            && d.DeviceKeys.Order(StringComparer.Ordinal).SequenceEqual(keys)
            && (d.Policy.Length == 0 || d.Policy == policy || d.Policy == alternatePolicy)).ToList();
    }

    internal static bool HasMeasurements(PerformanceProfile profile, Settings settings, IReadOnlyList<BackendDevice> devices, int mode, IReadOnlyCollection<int>? exclude = null)
    {
        var rows = Rates(profile, settings, devices, exclude);
        return rows.Any(r => r.Mode == mode && r.Speed > 0 && double.IsFinite(r.Speed))
            && rows.Any(r => r.Mode == 17230 && r.Speed > 0 && double.IsFinite(r.Speed));
    }

    /// <summary>No measurements means no filter. Require a 5% gain for the exact active GPU set.</summary>
    public static bool IsFaster(PerformanceProfile profile, Settings settings, IReadOnlyList<BackendDevice> devices, int mode, IReadOnlyCollection<int>? exclude = null)
    {
        if (!string.IsNullOrWhiteSpace(settings.ExtraArguments) || settings.Strategy == DeviceStrategy.CpuOnly || settings.HashcatCpuWithGpu) return false;
        var rows = Rates(profile, settings, devices, exclude);
        var automatic = rows.Where(d => d.Domain == "zip-filter").ToList();
        if (automatic.Any(d => d.Mode == mode) && automatic.Any(d => d.Mode == 17230)) rows = automatic;
        rows = rows.Where(d => double.IsFinite(d.Speed) && d.Speed > 0).ToList();
        double baseline = rows.Where(d => d.Mode == mode).Select(d => d.Speed).DefaultIfEmpty().Max();
        double filter = rows.Where(d => d.Mode == 17230).Select(d => d.Speed).DefaultIfEmpty().Min();
        return baseline > 0 && filter > baseline * 1.05;
    }
}
