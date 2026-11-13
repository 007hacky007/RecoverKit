using RecoverKit.Core.Hashcat;

namespace RecoverKit.Core.Diagnostics;

public static class HybridBenchmarkDevices
{
    public static List<List<BackendDevice>> Groups(Settings settings, IReadOnlyList<BackendDevice> devices,
        int mode, IEnumerable<DiagnosticMeasurement> measurements, PerformanceProfile? previous = null)
    {
        var active = HashcatRunner.ActiveGpus(settings, devices)
            .GroupBy(d => GpuProfileSelection.FamilyKey(d.Key, devices)).Select(family => family.First()).ToList();
        var rows = measurements.Where(row => row.Section == "gpu" && row.Mode == mode).ToList();
        var groups = new List<List<BackendDevice>>();
        bool mixed = active.Any(d => d.IsIntegratedGpu) && active.Any(d => !d.IsIntegratedGpu);
        var discreteFamilies = active.Where(d => !d.IsIntegratedGpu).Select(d => GpuProfileSelection.FamilyKey(d.Key, devices)).ToHashSet();

        void Add(IEnumerable<BackendDevice> candidates)
        {
            var group = candidates.Where(d => !HashcatRunner.IsDisabled(settings, d)).ToList();
            var keys = group.Select(d => d.Key).Order(StringComparer.Ordinal);
            if (group.Count == 0 || groups.Any(existing => existing.Select(d => d.Key).Order(StringComparer.Ordinal).SequenceEqual(keys))) return;
            groups.Add(group.Select(ForceAlias).ToList());
        }

        Add(active);
        if (mixed) Add(active.Where(d => !d.IsIntegratedGpu));
        var preferred = new List<BackendDevice>();
        foreach (var current in active)
        {
            string family = GpuProfileSelection.FamilyKey(current.Key, devices);
            var allowed = devices.Where(d => d.IsGpu && !HashcatRunner.IsDisabled(settings, d)
                && GpuProfileSelection.FamilyKey(d.Key, devices) == family).ToList();
            PerformanceDecision? choice = null;
            if (rows.Count > 0)
            {
                var comparable = rows.Where(row => allowed.Any(d => d.Key == row.DeviceKey)).ToList();
                var baseline = comparable.FirstOrDefault(row => bool.TryParse(row.Details.GetValueOrDefault("Default"), out bool marked) && marked);
                if (baseline is { Correct: true, Error: null, Speed: > 0 } && double.IsFinite(baseline.Speed))
                    choice = PerformanceProfiles.Choose(comparable, baseline.Variant);
            }
            else if (previous is not null)
                choice = previous.Decisions.Where(d => d.Domain == "gpu" && d.Mode == mode && d.Scope == family
                        && d.DeviceKeys.Count == 1 && allowed.Any(device => device.Key == d.DeviceKeys[0]))
                    .OrderByDescending(d => d.Margin).FirstOrDefault(d => PerformanceProfiles.Apply(d, settings, devices) is not null);

            var winner = choice is { Margin: >= .05, DeviceKeys.Count: 1 }
                ? allowed.FirstOrDefault(d => d.Key == choice.DeviceKeys[0]) : null;
            preferred.Add(winner ?? current);
        }
        Add(preferred);
        if (mixed) Add(preferred.Where(d => discreteFamilies.Contains(GpuProfileSelection.FamilyKey(d.Key, devices))));
        return groups;
    }

    // Explicit device selection must keep a chosen alias enabled in finite hashcat workers.
    private static BackendDevice ForceAlias(BackendDevice device) => !device.IsSkippedAlias ? device : new()
    {
        Id = device.Id,
        AliasOf = device.AliasOf,
        Backend = device.Backend,
        BackendVersion = device.BackendVersion,
        DriverVersion = device.DriverVersion,
        Type = device.Type,
        Vendor = device.Vendor,
        Name = device.Name,
        Processors = device.Processors,
        ClockMhz = device.ClockMhz,
        MemoryMb = device.MemoryMb,
        Unified = device.Unified,
        Key = device.Key,
        IsSkippedAlias = false,
    };
}
