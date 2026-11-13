using RecoverKit.Core.Hashcat;

namespace RecoverKit.Core.Diagnostics;

public static class GpuProfileSelection
{
    public static string FamilyKey(string deviceKey, IReadOnlyList<BackendDevice> devices)
    {
        var start = devices.FirstOrDefault(d => d.Key == deviceKey);
        if (start is null) return deviceKey;
        var ids = new HashSet<int> { start.Id };
        var pending = new Queue<int>();
        pending.Enqueue(start.Id);
        while (pending.TryDequeue(out int id))
            foreach (var device in devices)
            {
                int? neighbor = device.Id == id ? device.AliasOf : device.AliasOf == id ? device.Id : null;
                if (neighbor is int next && ids.Add(next)) pending.Enqueue(next);
            }
        return devices.Where(d => ids.Contains(d.Id)).Select(d => d.Key).Order(StringComparer.Ordinal).First();
    }

    public static PerformanceDecision? ForAttack(PerformanceProfile profile, Settings settings,
        IReadOnlyList<BackendDevice> devices, int mode, int length)
    {
        var selected = new List<string>();
        var reasons = new List<string>();
        bool? optimized = null;
        foreach (var family in HashcatRunner.ActiveGpus(settings, devices).GroupBy(d => FamilyKey(d.Key, devices)))
        {
            var current = family.First();
            var choice = profile.Decisions
                .Where(d => d.Domain == "gpu" && d.Scope == family.Key && d.Mode == mode )
                .OrderByDescending(d => d.Length == length).ThenByDescending(d => d.Margin)
                .FirstOrDefault(d => d.DeviceKeys.Count == 1 && devices.Any(device => device.IsGpu
                    && device.Key == d.DeviceKeys[0] && FamilyKey(device.Key, devices) == family.Key)
                    && PerformanceProfiles.Apply(d, settings, devices) is not null);
            if (choice is not null)
            {
                current = devices.First(d => d.Key == choice.DeviceKeys[0]);
                reasons.Add($"{current.Name}: {current.Backend}");
            }
            selected.Add(current.Key);
            bool useOptimized = settings.OptimizedKernels && choice?.Optimized != false;
            // One hashcat process has one kernel flag, including GPUs without measurements.
            if (optimized is bool previous && previous != useOptimized) return null;
            optimized = useOptimized;
        }
        return reasons.Count == 0 ? null : new PerformanceDecision
        {
            Domain = "gpu", Mode = mode, Length = length, Engine = "gpu", Variant = "measured",
            DeviceKeys = selected, Optimized = optimized,
            Reason = "measured backends: " + string.Join("; ", reasons),
        };
    }
}
