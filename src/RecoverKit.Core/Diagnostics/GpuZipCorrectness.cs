using System.Text;
using RecoverKit.Core.Formats;
using RecoverKit.Core.Hashcat;
using RecoverKit.Core.Native.Kernels;

namespace RecoverKit.Core.Diagnostics;

internal static class GpuZipCorrectness
{
    public static async Task<bool> CheckAsync(HashcatTool tool, BackendDevice device, ZipKernelBenchmark.Sample sample, string variant, CancellationToken ct)
    {
        var rng = new Random(90127);
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
        var expected = new SortedSet<string>(StringComparer.Ordinal);
        foreach (char a in "ABCD")
        foreach (char b in "ABCD")
        {
            string candidate = $"{a}{b}CDABCD";
            if (reference.Verify(Encoding.ASCII.GetBytes(candidate))) expected.Add(candidate);
        }
        if (expected.Count == 0) return false;
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
            await File.WriteAllTextAsync(hash, target.HashLines + "\n", ct);
            var (code, _, _) = await tool.RunAsync(["-m", sample.Mode.ToString(), "-a", "3", hash, "?1?1CDABCD", "-1", "ABCD", "-d", device.Id.ToString(), "--keep-guessing", "--quiet", "--potfile-disable", "--restore-disable", "--logfile-disable", "--session", "rk-gpu-correctness", "-o", output, "--outfile-format", "2"], TimeSpan.FromMinutes(3), ct: ct);
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
