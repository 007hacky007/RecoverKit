using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;
using RecoverKit.Core.Diagnostics;
using RecoverKit.Core.Native;

namespace RecoverKit.Core.Hashcat;

/// <summary>Paired live-mask and -b measurements in a disposable engine copy, including every backend alias.</summary>
public sealed partial class PdfKernelBenchmark(HashcatTool tool)
{
    public int Seconds { get; init; } = 10;
    public int Runs { get; init; } = 3;
    public int Workload { get; init; } = 3;
    public IReadOnlyList<string> Tuning { get; init; } = [];
    public event Action<string>? Progress;

    public sealed record Trial(double Speed, string Launch);
    public sealed record Row(BackendDevice Device, int Mode, bool Benchmark, List<Trial> Original, List<Trial> Replacement);

    public async Task<List<Row>> RunAsync(NvidiaBackend backend, IReadOnlySet<int>? deviceIds, CancellationToken ct)
    {
        if (Seconds < 3 || Runs < 1 || Workload is < 1 or > 4) throw new ArgumentOutOfRangeException(nameof(Seconds));
        if (PdfHashcatKernels.ExplicitlyDisabled) throw new InvalidOperationException("Unset RECOVERKIT_HASHCAT_PDF_KERNELS before comparing PDF kernels.");
        string directory = Directory.CreateTempSubdirectory("rk-bench-pdf-").FullName;
        try
        {
            Progress?.Invoke("Preparing isolated hashcat engine ...");
            await Task.Run(() => PrepareEngine(tool.Directory, directory, ct), ct);
            var local = HashcatTool.ForExe(Path.Combine(directory, Path.GetFileName(tool.Exe)));
            if (!PdfHashcatKernels.Supported(directory)) throw new InvalidOperationException("PDF replacements require hashcat 8.0.0's original kernel sources.");
            if (HashcatKernels.Hash(File.ReadAllText(Path.Combine(directory, "OpenCL", "m10510-pure.cl"))) != "fac9fab82e1a3f84796890ff2cf77d1cb7ef149b31835c8e0a27249b53780b3b")
                throw new InvalidOperationException("The 10510 control needs hashcat 8.0.0's original kernel source.");
            var (versionCode, version, versionError) = await local.RunAsync(["--version"], TimeSpan.FromMinutes(5), ct: ct);
            if (versionCode != 0) throw new InvalidOperationException("Cannot start isolated hashcat: " + versionError);
            Progress?.Invoke("hashcat " + version.Trim());
            var devices = await local.DevicesAsync(ct);
            var selected = SelectDevices(devices, backend, deviceIds);
            var rows = new List<Row>();
            foreach (var device in selected)
            {
                Progress?.Invoke($"Device #{device.Id}: {device.Name} ({device.Backend} {device.BackendVersion}, driver {device.DriverVersion})");
                foreach (int mode in new[] { 10500, 10510 })
                {
                    string hash = Path.Combine(directory, mode + ".hash");
                    await File.WriteAllTextAsync(hash, NativeKernels.BenchmarkHashes[mode] + "\n", ct);
                    foreach (bool benchmark in new[] { false, true })
                    {
                        var row = new Row(device, mode, benchmark, [], []);
                        for (int run = 0; run < Runs; run++)
                        {
                            // Reverse each pair on alternate runs to reduce order/temperature bias.
                            foreach (bool replacement in run % 2 == 0 ? new[] { false, true } : new[] { true, false })
                            {
                                if (replacement)
                                {
                                    if (!PdfHashcatKernels.Install(directory)) throw new InvalidOperationException("Could not install the PDF replacement sources.");
                                }
                                else PdfHashcatKernels.Restore(directory);
                                var args = new List<string> { "-m", mode.ToString(), "-d", device.Id.ToString(), "-w", Workload.ToString() };
                                args.AddRange(Tuning);
                                if (benchmark) args.Add("-b");
                                else args.AddRange(["-a", "3", hash, "-1", "?u?d?s", "?1?1?1?1?1?1?1", "--runtime", Seconds.ToString(),
                                    "--status", "--status-timer", "1", "--potfile-disable", "--restore-disable", "--logfile-disable", "--session", "rk-bench-pdf", "--keep-guessing"]);
                                string label = $"{device.Backend} {mode} {(benchmark ? "-b" : "live")} {(replacement ? mode == 10510 ? "stock control" : "RecoverKit" : "hashcat")} {run + 1}/{Runs}";
                                Progress?.Invoke(label + " ...");
                                var (code, stdout, stderr) = await local.RunAsync(args, TimeSpan.FromMinutes(10), ct: ct, redactOutput: true);
                                double speed = ParseSpeed(code, stdout, benchmark);
                                if (speed <= 0) throw new InvalidOperationException(label + $" failed (exit {code}): " + (stdout + "\n" + stderr)[^Math.Min(2000, stdout.Length + stderr.Length + 1)..]);
                                string launch = SpeedLine().Matches(stdout).LastOrDefault()?.Groups[3].Value ?? "";
                                var trial = new Trial(speed, launch.Trim());
                                (replacement ? row.Replacement : row.Original).Add(trial);
                                Progress?.Invoke(FormattableString.Invariant($"  {speed:F0} H/s, {trial.Launch}"));
                            }
                        }
                        rows.Add(row);
                    }
                }
            }
            return rows;
        }
        finally { Directory.Delete(directory, true); }
    }

    internal static List<BackendDevice> SelectDevices(IReadOnlyList<BackendDevice> devices, NvidiaBackend backend, IReadOnlySet<int>? deviceIds)
    {
        var requested = devices.Where(d => d.IsGpu && (deviceIds is null || deviceIds.Contains(d.Id))).ToList();
        var selected = requested.Where(d => backend == NvidiaBackend.Automatic || !IsNvidia(d) || d.Backend == (backend == NvidiaBackend.Cuda ? "CUDA" : "OpenCL")).ToList();
        if (selected.Count == 0) throw new InvalidOperationException("No GPU matches the selected device and backend.");
        if (backend != NvidiaBackend.Automatic && requested.Any(IsNvidia) && !selected.Any(IsNvidia))
            throw new InvalidOperationException("The requested NVIDIA backend is unavailable.");
        return selected;
    }

    internal static void PrepareEngine(string source, string destination, CancellationToken ct)
    {
        DetailedBenchmarkRunner.CopyEngine(source, destination, ct);
        // Avoid loading hundreds of modules again on macOS. Hashcat validates this metadata cache
        // against every module's size and timestamp before using it; kernel caches stay isolated.
        foreach (string name in new[] { "module_options.so.cache", "module_options.dll.cache" })
        {
            string path = Path.Combine(source, "cache", name);
            if (!File.Exists(path)) continue;
            Directory.CreateDirectory(Path.Combine(destination, "cache"));
            File.Copy(path, Path.Combine(destination, "cache", name));
        }
    }

    private static bool IsNvidia(BackendDevice device) => device.Backend == "CUDA" || device.Vendor.Contains("NVIDIA", StringComparison.OrdinalIgnoreCase) || device.Name.Contains("NVIDIA", StringComparison.OrdinalIgnoreCase);

    [GeneratedRegex(@"Speed\.#\d+\.+:\s*([\d.]+)\s*([kMGT]?)H/s[^\r\n]*?@ ([^\r\n]+)")]
    private static partial Regex SpeedLine();

    internal static double ParseSpeed(int exitCode, string output, bool benchmark)
    {
        if (benchmark ? exitCode != 0 : exitCode is not (0 or 1 or 4)) return 0;
        var values = SpeedLine().Matches(output).Select(m => double.Parse(m.Groups[1].Value, CultureInfo.InvariantCulture)
            * (m.Groups[2].Value switch { "k" => 1e3, "M" => 1e6, "G" => 1e9, "T" => 1e12, _ => 1 })).ToList();
        return Median(!benchmark && values.Count > 3 ? values.Skip(2) : values);
    }

    internal static double Median(IEnumerable<double> values)
    {
        var sorted = values.Order().ToArray();
        if (sorted.Length == 0) return 0;
        int mid = sorted.Length / 2;
        return sorted.Length % 2 == 0 ? (sorted[mid - 1] + sorted[mid]) / 2 : sorted[mid];
    }

    public static string Format(IEnumerable<Row> rows)
    {
        var text = new StringBuilder("PDF R3 GPU kernels; live mask: -1 ?u?d?s ?1?1?1?1?1?1?1\nSpeeds in H/s; medians of successful runs. 10510 runs stock kernels in both columns as a control.\n");
        foreach (var row in rows)
        {
            double original = Median(row.Original.Select(t => t.Speed)), replacement = Median(row.Replacement.Select(t => t.Speed));
            text.AppendLine(FormattableString.Invariant($"#{row.Device.Id} {row.Device.Name} {row.Device.Backend}, {row.Mode} {(row.Benchmark ? "-b" : "live")}: hashcat {original:F0}, RecoverKit {replacement:F0}, gain {replacement / original:F3}x"));
            foreach (var (label, trials) in new[] { ("hashcat", row.Original), ("RecoverKit", row.Replacement) })
                foreach (var trial in trials) text.AppendLine(FormattableString.Invariant($"  {label}: {trial.Speed:F0} H/s; {trial.Launch}"));
        }
        return text.ToString();
    }
}
