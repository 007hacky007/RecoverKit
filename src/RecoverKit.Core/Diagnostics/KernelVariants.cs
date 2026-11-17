using System.Runtime.Intrinsics;
using RecoverKit.Core.Native;
using RecoverKit.Core.Native.Kernels;

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
        [9400] = Office2007Variants,
        [9700] = NativeAndManaged,
        [9800] = NativeAndManaged,
        [10400] = NativeAndManaged,
        [10500] = NativeAndManaged,
        [10510] = NativeAndManaged,
        [12500] = [.. NativeAndManaged, .. WideVariants],
        [13000] = [new("default", () => true, () => null), .. WideVariants],
        [13600] = Pbkdf2Sha1Variants,
        [22000] = Pbkdf2Sha1Variants,
        [29331] = [new("default", () => true, () => null),
            // Compared only where an AVX-512 path exists; elsewhere "scalar" is the default path itself.
            new("scalar", () => WideSupported("avx512", RkNative.Available, RkNative.Features), () => new FeatureSelection()),
            new("avx512", () => WideSupported("avx512", RkNative.Available, RkNative.Features), () => new WhirlpoolSelection())],
    };

    private static Registration[] WideVariants =>
    [
        new("avx2", () => WideSupported("avx2", RkNative.Available, RkNative.Features), () => new FeatureSelection()),
        new("avx512", () => WideSupported("avx512", RkNative.Available, RkNative.Features), () => null),
    ];

    private static Registration[] Office2007Variants =>
    [
        new("default", () => true, () => null),
        new("scalar", () => RkNative.Available, () => new Office2007Selection(0)),
        new("avx2", () => WideSupported("avx2", RkNative.Available, RkNative.Features), () => new Office2007Selection(RkNative.Feature.Avx2)),
        new("avx512", () => WideSupported("avx512", RkNative.Available, RkNative.Features), () => new Office2007Selection(RkNative.Feature.Avx512 | RkNative.Feature.Avx2)),
        new("sha-ni", () => RkNative.Available && RkNative.Features.HasFlag(RkNative.Feature.ShaNi), () => new Office2007Selection(RkNative.Feature.ShaNi)),
        new("neon", () => RkNative.Available && RkNative.Features.HasFlag(RkNative.Feature.Neon), () => new Office2007Selection(RkNative.Feature.Neon)),
        new("arm-sha1", () => RkNative.Available && RkNative.Features.HasFlag(RkNative.Feature.ArmSha1), () => new Office2007Selection(RkNative.Feature.ArmSha1 | RkNative.Feature.Neon)),
    ];

    private sealed class Office2007Selection : IDisposable
    {
        private readonly RkNative.Feature _saved = RkNative.Features;
        public Office2007Selection(RkNative.Feature selected)
        {
            const RkNative.Feature paths = RkNative.Feature.Avx2 | RkNative.Feature.Avx512 | RkNative.Feature.ShaNi | RkNative.Feature.Neon | RkNative.Feature.ArmSha1;
            RkNative.LimitFeatures(_saved & (~paths | selected));
        }
        public void Dispose() => RkNative.LimitFeatures(_saved);
    }

    private static Registration[] Pbkdf2Sha1Variants =>
    [
        new("default", () => true, () => null),
        new("scalar", () => RkNative.Available, () => new Sha1Selection(0)),
        new("avx2", () => WideSupported("avx2", RkNative.Available, RkNative.Features), () => new Sha1Selection(RkNative.Feature.Avx2)),
        new("avx512", () => WideSupported("avx512", RkNative.Available, RkNative.Features), () => new Sha1Selection(RkNative.Feature.Avx512 | RkNative.Feature.Avx2)),
        new("neon", () => RkNative.Available && RkNative.Features.HasFlag(RkNative.Feature.Neon), () => new Sha1Selection(RkNative.Feature.Neon)),
        new("arm-sha1", () => RkNative.Available && RkNative.Features.HasFlag(RkNative.Feature.ArmSha1), () => new Sha1Selection(RkNative.Feature.ArmSha1 | RkNative.Feature.Neon)),
    ];

    private static Registration[] Pbkdf2Sha512Variants =>
    [
        new("default", () => true, () => null),
        new("managed", () => true, SelectManaged),
        new("scalar", () => RkNative.Available, () => new Sha512Selection(0)),
        new("avx2", () => WideSupported("avx2", RkNative.Available, RkNative.Features), () => new Sha512Selection(RkNative.Feature.Avx2)),
        new("avx512", () => WideSupported("avx512", RkNative.Available, RkNative.Features), () => new Sha512Selection(RkNative.Feature.Avx512 | RkNative.Feature.Avx2)),
        new("neon", () => RkNative.Available && RkNative.Features.HasFlag(RkNative.Feature.Neon), () => new Sha512Selection(RkNative.Feature.Neon)),
        new("arm-sha512", () => RkNative.Available && RkNative.Features.HasFlag(RkNative.Feature.ArmSha512), () => new Sha512Selection(RkNative.Feature.ArmSha512 | RkNative.Feature.Neon)),
    ];

    private sealed class Sha512Selection : IDisposable
    {
        private readonly RkNative.Feature _saved = RkNative.Features;
        public Sha512Selection(RkNative.Feature selected)
        {
            const RkNative.Feature paths = RkNative.Feature.Avx2 | RkNative.Feature.Avx512 | RkNative.Feature.Neon | RkNative.Feature.ArmSha512;
            RkNative.LimitFeatures(_saved & (~paths | selected));
        }
        public void Dispose() => RkNative.LimitFeatures(_saved);
    }

    private sealed class Sha1Selection : IDisposable
    {
        private readonly RkNative.Feature _saved = RkNative.Features;
        public Sha1Selection(RkNative.Feature selected)
        {
            const RkNative.Feature paths = RkNative.Feature.Avx2 | RkNative.Feature.Avx512 | RkNative.Feature.Neon | RkNative.Feature.ArmSha1;
            RkNative.LimitFeatures(_saved & (~paths | selected));
        }
        public void Dispose() => RkNative.LimitFeatures(_saved);
    }

    internal static bool WideSupported(string variant, bool available, RkNative.Feature features) => available && variant switch
    {
        "avx2" => features.HasFlag(RkNative.Feature.Avx2),
        "avx512" => features.HasFlag(RkNative.Feature.Avx512),
        _ => false,
    };

    private sealed class WhirlpoolSelection : IDisposable
    {
        private readonly bool _saved = RkNative.WhirlpoolAvx512Enabled;
        public WhirlpoolSelection() => RkNative.WhirlpoolAvx512Enabled = true;
        public void Dispose() => RkNative.WhirlpoolAvx512Enabled = _saved;
    }

    private sealed class FeatureSelection : IDisposable
    {
        private readonly RkNative.Feature _saved = RkNative.Features;
        public FeatureSelection() => RkNative.LimitFeatures(_saved & ~RkNative.Feature.Avx512);
        public void Dispose() => RkNative.LimitFeatures(_saved);
    }

    public static IReadOnlyList<Variant> ForMode(int mode)
    {
        mode = Math.Abs(mode);
        if (mode is 17200 or 17210)
            return CpuDiagnostics.Variants.Select(v => new Variant(v.Name, v.Supported)).ToArray();
        if (TrueCryptSha512Kernel.SupportsMode(mode))
            return Pbkdf2Sha512Variants.Select(v => new Variant(v.Name, v.Supported())).ToArray();
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
        if (TrueCryptSha512Kernel.SupportsMode(mode)) return Pbkdf2Sha512Variants.First(v => v.Name == variant).Select();
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
