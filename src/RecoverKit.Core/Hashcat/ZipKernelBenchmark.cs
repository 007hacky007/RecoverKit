using System.Text;
using RecoverKit.Core.Formats;
using RecoverKit.Core.Diagnostics;

namespace RecoverKit.Core.Hashcat;

/// <summary>
/// Compares hashcat's own ZipCrypto kernels with RecoverKit's replacements (<see cref="HashcatKernels"/>)
/// on every device, with live brute-force attacks on generated archives of different entry sizes
/// (recoverkit-cli bench-zip). The cost of hashcat's kernels grows with the size of the attacked entry,
/// so one figure (hashcat -b uses a 453-byte entry) does not describe them.
/// </summary>
public sealed class ZipKernelBenchmark(HashcatTool tool)
{
    public sealed record Sample(string Label, int Mode, string HashLine);

    /// <summary>Speeds in H/s: hashcat's kernel, RecoverKit's, and RecoverKit's with the amplifier key cache (0 when not measured).</summary>
    public sealed record Row(BackendDevice Device, Sample Sample, double Original, double Replacement, double AmpCache);

    /// <summary>
    /// Also measure RecoverKit's kernel with RK_AMP_CACHE 1 (the key states after the amplifier's
    /// characters cached in 12 KB of local memory), which did not help on the Apple M1 Pro.
    /// </summary>
    public bool WithAmpCache { get; init; } = true;

    /// <summary>Seconds each attack runs (after start-up and autotune).</summary>
    public int Seconds { get; init; } = 10;
    public ProcessPriority? Priority { get; init; }
    internal bool Optimized { get; init; }
    internal bool BoundedTuning { get; init; }

    /// <summary>The brute-force mask: eight printable characters, far more than any run gets through.</summary>
    internal string? Charset1 { get; init; }
    public string Mask { get; init; } = "?a?a?a?a?a?a?a?a";

    public event Action<string>? Progress;

    /// <summary>Entries: a 17-byte stored file, hashcat's own benchmark size, and larger stored and deflated files.</summary>
    public static List<Sample> DefaultSamples()
    {
        var rng = new Random(20261112);
        // The password is not in the mask, so every run tests candidates for the whole time.
        var pw = "Benché-not-in-mask"u8.ToArray();
        Sample Make(string label, int length, bool deflate)
        {
            var content = deflate ? ZipCryptoSample.Text(length, rng) : RandomBytes(length, rng);
            var t = ZipCryptoSample.Extract(ZipCryptoSample.Archive([new ZipCryptoSample.Entry("bench.dat", content, deflate)], pw, rng));
            return new Sample(label, t.Modes[0], t.HashLines);
        }
        return
        [
            Make("stored, 17 bytes", 17, false),
            Make("stored, 453 bytes (as hashcat -b)", 453, false),
            Make("stored, 4 KB", 4096, false),
            Make("deflated, 1 KB text", 1024, true),
            Make("deflated, 16 KB text", 16384, true),
        ];
    }

    private static byte[] RandomBytes(int n, Random rng)
    {
        var b = new byte[n];
        rng.NextBytes(b);
        return b;
    }

    /// <summary>
    /// Runs every sample on every device (each alias too, so CUDA, OpenCL and Metal show separately),
    /// first with hashcat's kernels and then with RecoverKit's. RecoverKit's kernels are in place again
    /// afterwards. Returns no rows when this hashcat cannot take the replacement kernels.
    /// </summary>
    public async Task<List<Row>> RunAsync(IReadOnlyList<BackendDevice> devices, IReadOnlyList<Sample> samples, CancellationToken ct)
    {
        var rows = new List<Row>();
        if (HashcatKernels.Inspect(tool.Directory) == HashcatKernels.State.Unsupported) return rows;
        var dir = Directory.CreateTempSubdirectory("rk-bench-zip").FullName;
        try
        {
            foreach (var dev in devices)
            {
                foreach (var s in samples)
                {
                    ct.ThrowIfCancellationRequested();
                    var file = Path.Combine(dir, $"{s.Mode}-{rows.Count}.hash");
                    DebugLog.RegisterHashes(s.HashLine);
                    await File.WriteAllTextAsync(file, s.HashLine + "\n", ct);
                    HashcatKernels.Restore(tool.Directory);
                    Progress?.Invoke($"Device #{dev.Id}, {s.Label}: hashcat's kernel ...");
                    double original = await SpeedAsync(s.Mode, file, dev.Id, ct);
                    HashcatKernels.Install(tool.Directory);
                    Progress?.Invoke($"Device #{dev.Id}, {s.Label}: RecoverKit's kernel ...");
                    double replacement = await SpeedAsync(s.Mode, file, dev.Id, ct);
                    double ampCache = 0;
                    if (WithAmpCache)
                    {
                        var include = Path.Combine(tool.Directory, "OpenCL", HashcatKernels.IncludeFile);
                        File.WriteAllText(include, HashcatKernels.Sources[HashcatKernels.IncludeFile].Replace("#define RK_AMP_CACHE 0", "#define RK_AMP_CACHE 1"));
                        Progress?.Invoke($"Device #{dev.Id}, {s.Label}: RecoverKit's kernel with the amplifier cache ...");
                        ampCache = await SpeedAsync(s.Mode, file, dev.Id, ct);
                        HashcatKernels.Install(tool.Directory);
                    }
                    rows.Add(new Row(dev, s, original, replacement, ampCache));
                }
            }
        }
        finally
        {
            HashcatKernels.Install(tool.Directory);
            try { Directory.Delete(dir, true); } catch (IOException) { }
        }
        return rows;
    }

    internal async Task<double> MeasureAsync(Sample sample, BackendDevice device, string variant, CancellationToken ct)
    {
        var directory = Directory.CreateTempSubdirectory("rk-zip-sample-").FullName;
        try
        {
            string file = Path.Combine(directory, "synthetic.hash");
            DebugLog.RegisterHashes(sample.HashLine);
            await File.WriteAllTextAsync(file, sample.HashLine + "\n", ct);
            HashcatKernels.EnsureFor(tool, sample.Mode);
            using var selection = HashcatKernels.ApplyProfile(tool, sample.Mode, variant);
            using var tuning = BoundedTuning ? DiagnosticGpuTuning.Apply(tool, [device]) : null;
            return await SpeedAsync(sample.Mode, file, device.Id, ct);
        }
        finally { Directory.Delete(directory, true); }
    }

    /// <summary>Median speed (H/s) over the status updates of one run, the first two (warm-up) left out.</summary>
    private async Task<double> SpeedAsync(int mode, string hashFile, int device, CancellationToken ct)
    {
        var args = new List<string>
        {
            "-m", mode.ToString(), "-a", "3", hashFile, Mask, "-d", device.ToString(),
            "--runtime", Seconds.ToString(), "--status", "--status-json", "--status-timer", "1",
            // ZipCrypto has false positives: about one candidate in 2^39 passes the check byte and the
            // CRC-32 of a stored entry (one of the 8-character runs here hit one). Keep going after it.
            "--keep-guessing", "--potfile-disable", "--restore-disable", "--logfile-disable", "--session", "rk-bench-zip", "--quiet",
        };
        if (Charset1 is not null) args.AddRange(["-1", Charset1]);
        if (Optimized) args.Add("-O");
        var (code, o, e) = await tool.RunAsync(args, TimeSpan.FromSeconds(Seconds + 600), ct: ct, priority: Priority, redactOutput: true);
        double speed = ParseSpeed(code, o);
        if (speed > 0) return speed;
        var why = (o + "\n" + e).Split('\n').Select(l => l.Trim()).Where(l => l.Length > 0 && !l.StartsWith('{')).TakeLast(3);
        Progress?.Invoke($"  no valid speed reported (exit {code}): " + string.Join(" / ", why));
        return 0;
    }

    internal static double ParseSpeed(int exitCode, string output)
    {
        // Runtime expiry (4) is normal here; errors or a manual stop invalidate earlier samples.
        if (exitCode is not (0 or 1 or 4)) return 0;
        var speeds = output.Split('\n').Select(l => HashcatStatus.TryParse(l.Trim())).OfType<HashcatStatus>()
            .Where(st => st.Status == 3).Select(st => st.TotalSpeed).Where(v => v > 0 && double.IsFinite(v)).ToList();
        if (speeds.Count == 0) return 0;
        var tail = speeds.Count > 3 ? speeds.Skip(2).ToList() : speeds;
        tail.Sort();
        return tail[tail.Count / 2];
    }

    /// <summary>The result table as printed by recoverkit-cli bench-zip.</summary>
    public static string Format(IEnumerable<Row> rows)
    {
        var sb = new StringBuilder();
        foreach (var g in rows.GroupBy(r => r.Device.Id))
        {
            var d = g.First().Device;
            sb.AppendLine($"Device #{d.Id}: {d.Name} ({d.Backend}{(d.BackendVersion.Length > 0 ? " " + d.BackendVersion : "")})");
            bool nc = g.Any(r => r.AmpCache > 0);
            sb.AppendLine($"  {"entry",-36} {"hashcat",14} {"RecoverKit",14} {"gain",7}" + (nc ? $" {"amp cache",14}" : ""));
            foreach (var r in g)
            {
                string gain = r.Original > 0 && r.Replacement > 0 ? $"{r.Replacement / r.Original:F2}x" : "-";
                sb.AppendLine($"  {r.Sample.Label,-36} {Mhs(r.Original),14} {Mhs(r.Replacement),14} {gain,7}" + (nc ? $" {Mhs(r.AmpCache),14}" : ""));
            }
        }
        return sb.ToString();
    }

    private static string Mhs(double hs) => hs > 0 ? (hs / 1e6).ToString("N1") + " MH/s" : "failed";
}
