using System.Diagnostics;
using RecoverKit.Core.Formats;
using RecoverKit.Core.Native;
using RecoverKit.Core.Native.Kernels;

namespace RecoverKit.Core.Diagnostics;

/// <summary>CPU correctness gates and repeated timings, shared by detailed and automatic measurements.</summary>
public static class CpuDiagnostics
{
    public sealed record ZipVariant(string Name, int Selector)
    {
        public bool Supported => Selector <= 0 || RkNative.Available && RkNative.ZipPath(Selector) == Selector;
    }
    public sealed record CorrectnessResult(bool Passed, int Cases, string? Error = null);
    internal sealed record HeaderCase(byte[] Header, byte Check1, byte Check2, uint Key0, uint Key1, uint Key2, byte[] Last);

    // Registration is shared by diagnostics and performance-profile selection.
    public static IReadOnlyList<ZipVariant> Variants { get; } =
    [
        new("managed-scalar", -2), new("managed", -1), new("scalar", 1), new("avx2", 3),
        new("avx512", 4), new("neon", 2), new("arm-crc", 5),
    ];

    public static CorrectnessResult CheckZipVariant(string name)
    {
        var variant = Variants.FirstOrDefault(v => v.Name == name && v.Supported);
        return variant is null ? new(false, 0, "ZIP variant is not supported.") : CheckZipPath(variant.Selector);
    }

    public static IDisposable UseZipVariant(string name)
    {
        var variant = Variants.FirstOrDefault(v => v.Name == name && v.Supported)
            ?? throw new ArgumentException("ZIP variant is not supported.", nameof(name));
        return new ZipSelection(variant.Selector);
    }

    private sealed class ZipSelection : IDisposable
    {
        private readonly int _saved = ZipCryptoNative.RequestedPath;
        private bool _disposed;
        public ZipSelection(int selector) => ZipCryptoNative.RequestedPath = selector;
        public void Dispose()
        {
            if (_disposed) return;
            ZipCryptoNative.RequestedPath = _saved;
            _disposed = true;
        }
    }

    public static async Task RunAsync(Action<DiagnosticMeasurement> add, Action<string> progress, CancellationToken ct, Settings? settings = null)
    {
        ct.ThrowIfCancellationRequested();
        int limit = settings?.MaxCpuThreads is > 0 ? settings.MaxCpuThreads : Environment.ProcessorCount;
        int[] counts = new[] { SystemFacts.PhysicalCores(), Environment.ProcessorCount }.Select(n => Math.Min(n, limit)).Distinct().Order().ToArray();
        foreach (int mode in NativeKernels.BenchmarkHashes.Keys)
        {
            ct.ThrowIfCancellationRequested();
            foreach (var variant in KernelVariants.ForMode(mode))
            {
                if (!variant.Supported) continue;
                progress($"Mode {mode}: checking {variant.Name}");
                var check = await CpuDiagnosticWorker.CheckAsync(mode, variant.Name, ct);
                if (!check.Passed)
                {
                    add(new DiagnosticMeasurement { Section = "cpu", Step = "Correctness FAIL", Mode = Math.Abs(mode), Engine = "cpu", Variant = variant.Name,
                        Correct = false, Error = check.Error, Target = Target(mode), Length = 7 });
                    continue;
                }
                bool failed = false;
                foreach (int threads in counts)
                {
                    if (failed) break;
                    for (int repeat = 1; repeat <= 2; repeat++)
                    {
                        ct.ThrowIfCancellationRequested();
                        progress($"Mode {mode}, {variant.Name}, {threads} workers, repeat {repeat}/2");
                        var result = await CpuDiagnosticWorker.MeasureAsync(mode, variant.Name, threads, settings?.Priority ?? ProcessPriority.Normal, repeat, ct);
                        add(new DiagnosticMeasurement
                        {
                            Section = "cpu", Step = result.Check.Passed ? "Correctness PASS; timed" : "Worker failed; variant skipped", Mode = Math.Abs(mode),
                            Engine = "cpu", Variant = variant.Name, Threads = threads, Repeat = repeat, Correct = result.Check.Passed, Speed = result.Speed,
                            Error = result.Error ?? result.Check.Error ?? (result.Speed <= 0 ? "No CPU benchmark rate was reported." : null),
                            ElapsedSeconds = result.ElapsedSeconds, Target = Target(mode), Length = 7,
                            Details = new() { ["correctness cases"] = result.Check.Cases.ToString(), ["mask charset"] = "upper-case, digits, special characters", ["actual path"] = result.ActualPath,
                                ["Isolation"] = "Separate process for each correctness check and timing sample." },
                        });
                        if (!result.Check.Passed) { failed = true; break; }
                    }
                }
            }
        }
    }

    private static string Target(int mode) => mode switch
    {
        17200 => "synthetic ZIP deflated 1 KB text fixture",
        17210 => "native ZIP stored 29-byte fixture",
        -17210 => "published ZIP stored 453-byte fixture",
        10700 => "RecoverKit synthetic PDF R6 fixture",
        _ => $"native published example mode {mode}",
    };

    internal static (CorrectnessResult Check, double Speed) CheckThenMeasure(Func<CorrectnessResult> check, Func<double> measure)
    {
        var result = check();
        return (result, result.Passed ? measure() : 0);
    }

    public static CorrectnessResult CheckKernel(int mode)
    {
        try
        {
            var kernel = NativeKernels.TryCreate(mode, NativeKernels.BenchmarkHashes[mode]);
            if (kernel is null) return new(false, 0, "Kernel is not supported by this CPU or native library.");
            byte[] known = mode == 10700 ? "Qz7#Kp2"u8.ToArray() : "hashcat"u8.ToArray();
            // The 40-bit PDF password-search fixture is deliberately artificial, so validate its
            // candidate filter against the scalar verifier rather than claiming a known password.
            if (mode != 10510 && !kernel.Verify(known)) return new(false, 1, "Known vector was rejected by the reference verifier.");
            var worker = kernel.CreateWorker();
            byte[] prefix = known[..^1];
            byte[] last = [(byte)(known[^1] ^ 1), known[^1], (byte)(known[^1] ^ 2)];
            int want = -1;
            for (int i = 0; i < last.Length; i++)
            {
                byte[] candidate = [.. prefix, last[i]];
                if (kernel.Verify(candidate)) { want = i; break; }
            }
            if (worker.Search(prefix, last) != want) return new(false, 4, "Search differs from the reference verifier.");
            prefix[0] ^= 1;
            want = -1;
            for (int i = 0; i < last.Length; i++)
                if (kernel.Verify([.. prefix, last[i]])) { want = i; break; }
            if (worker.Search(prefix, last) != want) return new(false, 7, "Search differs after a prefix change.");
            return new(true, 7);
        }
        catch (Exception ex) { return new(false, 0, ex.Message); }
    }

    internal static CorrectnessResult CheckZipPath(int path, Func<HeaderCase, int[]>? nativeSearch = null)
    {
        int saved = ZipCryptoNative.RequestedPath;
        int cases = 0;
        try
        {
            if (path > 0 && nativeSearch is null && (!RkNative.Available || RkNative.ZipPath(path) != path))
                return new(false, 0, "Requested ZIP path is not supported.");
            var rng = new Random(17210512);
            if (path > 0)
            {
                foreach (int n in new[] { 0, 1, 3, 4, 7, 8, 15, 16, 17, 31, 32, 47, 48, 49, 63, 64, 65, 127, 255, 256 })
                for (int trial = 0; trial < 8; trial++)
                {
                    byte[] header = new byte[12], last = new byte[n];
                    rng.NextBytes(header); rng.NextBytes(last);
                    uint a = (uint)rng.NextInt64(1L << 32), b = (uint)rng.NextInt64(1L << 32), c = (uint)rng.NextInt64(1L << 32);
                    byte c1 = (byte)rng.Next(256), c2 = trial % 2 == 0 ? c1 : (byte)rng.Next(256);
                    // Force a known survivor in half the nonempty headers, including SIMD tails.
                    if (n > 0 && trial % 2 == 0) c1 = HeaderByte(header, a, b, c, last[^1]);
                    var input = new HeaderCase(header, c1, c2, a, b, c, last);
                    int[] expected = Enumerable.Range(0, n).Where(i => { byte p = HeaderByte(header, a, b, c, last[i]); return p == c1 || p == c2; }).ToArray();
                    int[] actual = nativeSearch is null ? NativeHits(input, path) : nativeSearch(input);
                    cases++;
                    if (!actual.SequenceEqual(expected)) return new(false, cases, "Native header survivor indices/count differ from managed scalar reference.");
                }
            }
            foreach (bool deflate in new[] { false, true })
            foreach (bool descriptor in new[] { false, true })
            foreach (int checkBytes in new[] { 1, 2 })
            foreach (int length in new[] { 1, 2, 7, 31, 64 })
            {
                byte[] password = new byte[length]; rng.NextBytes(password);
                var target = ZipCryptoSample.Extract(ZipCryptoSample.Archive([new("synthetic.dat", ZipCryptoSample.Text(96, rng), deflate, descriptor)], password, rng));
                string hash = target.HashLines.Replace("$pkzip2$1*1*", $"$pkzip2$1*{checkBytes}*");
                if (checkBytes == 2 && descriptor)
                {
                    var fields = hash.Split('*'); fields[11] = fields[12]; hash = string.Join('*', fields);
                }
                var kernel = ZipCryptoKernel.TryParse(hash)!;
                if (!kernel.Verify(password)) return new(false, cases, "Generated known ZIP vector did not verify.");
                byte[] last = Enumerable.Range(0, 256).Select(i => (byte)i).ToArray();
                byte[] prefix = password[..^1];
                ZipCryptoNative.RequestedPath = -2;
                int expected = kernel.CreateWorker().Search(prefix, last);
                ZipCryptoNative.RequestedPath = path;
                var worker = kernel.CreateWorker();
                cases++;
                if (expected != password[^1] || worker.Search(prefix, last) != expected || worker.Search(prefix, last) != expected)
                    return new(false, cases, "ZIP search differs from the managed scalar known-vector result.");
                if (prefix.Length > 0)
                {
                    prefix[^1] ^= 1;
                    ZipCryptoNative.RequestedPath = -2;
                    int miss = kernel.CreateWorker().Search(prefix, last);
                    ZipCryptoNative.RequestedPath = path;
                    cases++;
                    if (worker.Search(prefix, last) != miss || worker.SearchBatch([.. prefix, .. password[..^1]], 2, last) != 256 + expected)
                        return new(false, cases, "ZIP search differs after prefix changes or in a batch.");
                }
            }
            var knownKernel = ZipCryptoKernel.TryParse(NativeKernels.BenchmarkHashes[17210])!;
            ZipCryptoNative.RequestedPath = path;
            cases++;
            if (knownKernel.CreateWorker().Search("zq"u8, "xyz789"u8) != 3)
                return new(false, cases, "Published stored ZIP vector was not recovered.");
            return new(true, cases);
        }
        catch (Exception ex) { return new(false, cases, ex.Message); }
        finally { ZipCryptoNative.RequestedPath = saved; }
    }

    private static unsafe int[] NativeHits(HeaderCase input, int path)
    {
        var hits = new int[input.Last.Length + 1];
        fixed (byte* h = input.Header, last = input.Last)
        fixed (int* output = hits)
        {
            int count = RkNative.ZipSearch(h, input.Check1, input.Check2, input.Key0, input.Key1, input.Key2, last, input.Last.Length, output, input.Last.Length, path);
            if (count < 0 || count > input.Last.Length) throw new InvalidOperationException("Invalid native survivor count.");
            if (RkNative.ZipSearch(h, input.Check1, input.Check2, input.Key0, input.Key1, input.Key2, last, input.Last.Length, output, 0, path) != count)
                throw new InvalidOperationException("Native survivor count depends on output capacity.");
            return hits[..count];
        }
    }

    private static byte HeaderByte(byte[] header, uint a, uint b, uint c, byte last)
    {
        void Step(byte value)
        {
            a = (a >> 8) ^ ZipCryptoKernel.Crc[(byte)(a ^ value)];
            b = unchecked((b + (byte)a) * 134775813u + 1);
            c = (c >> 8) ^ ZipCryptoKernel.Crc[(byte)(c ^ (b >> 24))];
        }
        Step(last);
        byte plain = 0;
        foreach (byte encrypted in header)
        {
            uint t = (c | 2) & 0xffff;
            plain = (byte)(encrypted ^ (byte)((t * (t ^ 1)) >> 8));
            Step(plain);
        }
        return plain;
    }
}
