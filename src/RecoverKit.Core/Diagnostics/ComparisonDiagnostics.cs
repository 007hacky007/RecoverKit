using System.Diagnostics;
using RecoverKit.Core.Hashcat;

namespace RecoverKit.Core.Diagnostics;

public sealed partial class DetailedBenchmarkRunner
{
    private static List<ZipKernelBenchmark.Sample> ComparisonZipSamples() => BenchmarkTestFiles.Create().Where(f => f.Format == "ZIP / ZipCrypto")
        .Select(f => new ZipKernelBenchmark.Sample(ZipLabel(f.FileName), f.Mode, f.Hash)).Append(ZipKernelBenchmark.CheckBytesSample()).ToList();

    private static string ZipLabel(string file)
    {
        string size = file.Contains("small") ? "17 bytes" : file.Contains("453b") ? "453 bytes" : file.Contains("4kb") ? "4 KB" : file.Contains("16kb") ? "16 KB" : "1 KB";
        string check = file.Contains("check2") ? "check2" : file.Contains("check1") ? "check1" : file.Contains("crc-time") ? "crc-time" : "crc";
        return $"{(file.Contains("stored") ? "stored" : "deflated")}, {size}, {check}";
    }

    private static Dictionary<string, string> ComparisonDetails(ZipKernelBenchmark.Sample sample)
    {
        if (sample.Mode == 17230) return new() { ["Attack"] = BenchmarkTestFiles.Attack, ["Optimized"] = "False", ["Correctness"] = "Header filter checked against full CPU verification" };
        var file = BenchmarkTestFiles.Create().First(f => f.Hash == sample.HashLine);
        return new() { ["Test file"] = file.FileName, ["Attack"] = BenchmarkTestFiles.Attack, ["Optimized"] = "False", ["Correctness"] = "GPU match set checked against scalar verification for this entry type" };
    }

    private async Task<DiagnosticMeasurement> MeasureComparisonAsync(HashcatTool local, BackendDevice device, BenchmarkTestFiles.TestFile file,
        string variant, int repeat, CancellationToken ct)
    {
        var timer = Stopwatch.StartNew();
        bool optimized = settings.OptimizedKernels && (await local.ModeInfoAsync(file.Mode, 3, ct))?.HasOptimizedKernel == true;
        double speed = await new ZipKernelBenchmark(local) { Seconds = Thorough ? Math.Max(3, Seconds) : 3, Mask = BenchmarkTestFiles.Mask,
            Charset1 = BenchmarkTestFiles.Charset, Optimized = optimized, Priority = settings.Priority, BoundedTuning = !Thorough }
            .MeasureAsync(new(file.FileName, file.Mode, file.Hash), device, variant, ct);
        return new() { Section = "comparison", Step = file.FileName, Mode = file.Mode, Target = file.FileName, Length = 7,
            Engine = "gpu", Variant = variant, DeviceKey = device.Key, Backend = device.Backend, Speed = speed, Correct = speed > 0, Repeat = repeat,
            ElapsedSeconds = timer.Elapsed.TotalSeconds, Error = speed > 0 ? null : "No valid comparison rate reported",
            Details = new() { ["Test file"] = file.FileName, ["Attack"] = BenchmarkTestFiles.Attack, ["Optimized"] = optimized.ToString(), ["Metric"] = "Live candidates/second on the exported target, excluding startup" } };
    }

    private void AddComparisonSteps(DiagnosticPlan plan, HashcatTool local, DiagnosticReport report, CancellationToken ct)
    {
        foreach (var file in BenchmarkTestFiles.Create())
            plan.Add("gpu", "Comparison file " + file.FileName, 10, async () =>
            {
                var device = HashcatRunner.ActiveGpus(settings, devices).First();
                report.Measurements.Add(await MeasureComparisonAsync(local, device, file, "replacement", 1, ct));
            });
    }
}
