using System.Runtime.Intrinsics;
using RecoverKit.Core.Native;

namespace RecoverKit.Core.Diagnostics;

/// <summary>The same variant registry serves diagnostics, calibration and measured attack choices.</summary>
public static class KernelVariants
{
    public sealed record Variant(string Name, bool Supported);
    private sealed record Registration(string Name, Func<bool> Supported, Func<IDisposable?> Select);

    private static readonly Registration[] NativeAndManaged =
    [
        new("default", () => true, () => null),
        new("managed", () => RkNative.Available && Vector256.IsHardwareAccelerated, SelectManaged),
    ];

    // A new format with existing native and managed paths needs one registration.
    private static readonly IReadOnlyDictionary<int, Registration[]> Registry = new Dictionary<int, Registration[]>
    {
        [9700] = NativeAndManaged,
        [9800] = NativeAndManaged,
        [10400] = NativeAndManaged,
        [10500] = NativeAndManaged,
        [10510] = NativeAndManaged,
        [12500] = NativeAndManaged,
    };

    public static IReadOnlyList<Variant> ForMode(int mode)
    {
        mode = Math.Abs(mode);
        if (mode is 17200 or 17210)
            return CpuDiagnostics.Variants.Select(v => new Variant(v.Name, v.Supported)).ToArray();
        if (Registry.TryGetValue(mode, out var registrations))
            return registrations.Select(v => new Variant(v.Name, v.Supported())).ToArray();
        return [new("default", NativeKernels.Supports(mode))];
    }

    public static bool Supported(int mode, string variant) => ForMode(mode).Any(v => v.Name == variant && v.Supported);

    public static IDisposable? Select(int mode, string variant)
    {
        mode = Math.Abs(mode);
        if (!Supported(mode, variant)) return null;
        if (mode is 17200 or 17210) return CpuDiagnostics.UseZipVariant(variant);
        return Registry.TryGetValue(mode, out var registrations) ? registrations.First(v => v.Name == variant).Select() : null;
    }

    internal static IDisposable SelectManaged() => new NativeSelection();

    private sealed class NativeSelection : IDisposable
    {
        private readonly bool _saved = RkNative.Disabled;
        private bool _disposed;
        public NativeSelection() => RkNative.Disabled = true;
        public void Dispose()
        {
            if (_disposed) return;
            RkNative.Disabled = _saved;
            _disposed = true;
        }
    }
}
