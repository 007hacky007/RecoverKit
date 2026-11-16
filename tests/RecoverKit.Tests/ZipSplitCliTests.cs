using System.Diagnostics;
using Xunit;
using Xunit.Abstractions;

namespace RecoverKit.Tests;

public sealed class SplitZipHashcatTheoryAttribute : TheoryAttribute
{
    public SplitZipHashcatTheoryAttribute()
    {
        if (string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("RECOVERKIT_TEST_HASHCAT")))
            Skip = "Set RECOVERKIT_TEST_HASHCAT to a private hashcat 8.0.0 copy.";
    }
}

[Trait("Category", "Slow")]
[Collection("NativeFeatures")]
public sealed class ZipSplitCliTests(ITestOutputHelper output)
{
    [SplitZipHashcatTheory]
    [InlineData("infozip.z01")]
    [InlineData("infozip64.zip")]
    [InlineData("7zip-aes.zip.002")]
    public async Task CliRecoversThePasswordWithHashcat(string fixture)
    {
        var root = new DirectoryInfo(AppContext.BaseDirectory);
        while (root is not null && !File.Exists(Path.Combine(root.FullName, "RecoverKit.sln"))) root = root.Parent;
        Assert.NotNull(root);
        string configuration = new DirectoryInfo(AppContext.BaseDirectory).Parent!.Name;
        string cli = Path.Combine(root.FullName, "src", "RecoverKit.Cli", "bin", configuration, "net10.0", "recoverkit-cli.dll");
        Assert.True(File.Exists(cli), "Build RecoverKit.sln before running CLI integration tests.");
        string home = Directory.CreateTempSubdirectory("rk-split-cli-").FullName;
        try
        {
            var start = new ProcessStartInfo("dotnet") { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false };
            foreach (string arg in new[] { cli, "crack", Path.Combine(AppContext.BaseDirectory, "Fixtures", "ZipSplit", fixture),
                "--hcmask", "?d", "--hashcat", Environment.GetEnvironmentVariable("RECOVERKIT_TEST_HASHCAT")!,
                "--strategy", "GpuOnly", "--no-hybrid", "--no-potfile", "--no-stay", "--new", "--stop-after", "150" })
                start.ArgumentList.Add(arg);
            start.Environment["RECOVERKIT_HOME"] = home;
            using var process = Process.Start(start)!;
            using var timeout = new CancellationTokenSource(TimeSpan.FromMinutes(4));
            var stdout = process.StandardOutput.ReadToEndAsync(timeout.Token);
            var stderr = process.StandardError.ReadToEndAsync(timeout.Token);
            try { await process.WaitForExitAsync(timeout.Token); }
            finally { if (!process.HasExited) process.Kill(entireProcessTree: true); }
            string text = await stdout + await stderr;
            output.WriteLine(text);
            Assert.Equal(0, process.ExitCode);
            Assert.Contains("v8.0.0", text);
            Assert.Contains("PASSWORD: 7", text);
            Assert.Contains("[Info] hashcat -m", text);
        }
        finally { Directory.Delete(home, true); }
    }
}
