using System.Text;
using RecoverKit.Core.Formats;
using RecoverKit.Core.Hashcat;
using RecoverKit.Core.Native.Kernels;

namespace RecoverKit.Core.Diagnostics;

internal static class GpuZipCorrectness
{
    public static async Task<bool> CheckAsync(HashcatTool tool, BackendDevice device, ZipKernelBenchmark.Sample sample, string variant, CancellationToken ct)
        => await CheckAsync(tool, device, new[] { sample }, variant, ct);

    public static async Task<bool> CheckAsync(HashcatTool tool, BackendDevice device, IReadOnlyList<ZipKernelBenchmark.Sample> samples, string variant, CancellationToken ct)
    {
        var rng = new Random(90127);
        var hashes = new List<string>();
        var expected = new SortedSet<string>(StringComparer.Ordinal);
        foreach (var sample in samples)
        {
            int size = sample.Label.StartsWith("stored, 17 ", StringComparison.Ordinal) ? 17
                : sample.Label.Contains("453", StringComparison.Ordinal) ? 453
                : sample.Label.Contains("4 KB", StringComparison.Ordinal) ? 4096
                : sample.Label.Contains("16 KB", StringComparison.Ordinal) ? 16384 : 1024;
            bool deflate = sample.Mode == 17200;
            var bytes = deflate ? ZipCryptoSample.Text(size, rng) : new byte[size];
            if (!deflate) rng.NextBytes(bytes);
            var target = ZipCryptoSample.Extract(ZipCryptoSample.Archive([new ZipCryptoSample.Entry("synthetic.dat", bytes, deflate)], "ABCDABCD"u8.ToArray(), rng));
            DebugLog.RegisterHashes(target.HashLines);
            var reference = ZipCryptoKernel.TryParse(target.HashLines)!;
            hashes.Add(target.HashLines);
            foreach (char a in "ABCD")
            foreach (char b in "ABCD")
            {
                string candidate = $"{a}{b}CDABCD";
                if (reference.Verify(Encoding.ASCII.GetBytes(candidate))) expected.Add(target.HashLines + ":" + candidate);
            }
        }
        if (expected.Count != samples.Count) return false;
        var dir = Directory.CreateTempSubdirectory("rk-gpu-correctness-").FullName;
        try
        {
            if (variant == "hashcat") HashcatKernels.Restore(tool.Directory);
            else
            {
                if (!HashcatKernels.Install(tool.Directory)) return false;
                if (variant == "amplifier-cache")
                    await File.WriteAllTextAsync(Path.Combine(tool.Directory, "OpenCL", HashcatKernels.IncludeFile), HashcatKernels.Sources[HashcatKernels.IncludeFile].Replace("#define RK_AMP_CACHE 0", "#define RK_AMP_CACHE 1"), ct);
            }
            string hash = Path.Combine(dir, "fixture.hash"), output = Path.Combine(dir, "matches.out");
            await File.WriteAllTextAsync(hash, string.Join("\n", hashes) + "\n", ct);
            var (code, _, _) = await tool.RunAsync(["-m", samples[0].Mode.ToString(), "-a", "3", hash, "?1?1CDABCD", "-1", "ABCD", "-d", device.Id.ToString(), "--keep-guessing", "--quiet", "--potfile-disable", "--restore-disable", "--logfile-disable", "--session", "rk-gpu-correctness", "-o", output, "--outfile-format", "1,2"], TimeSpan.FromMinutes(3), ct: ct, redactOutput: true);
            if (code is not (0 or 1)) return false;
            var actual = File.Exists(output) ? File.ReadAllLines(output).Where(s => s.Length > 0) : [];
            return expected.SetEquals(actual);
        }
        finally
        {
            HashcatKernels.Install(tool.Directory);
            try { Directory.Delete(dir, true); } catch (IOException) { }
        }
    }
}
