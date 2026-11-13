using System.Text;
using Xunit;
using RecoverKit.Core;
using RecoverKit.Core.Attacks;
using RecoverKit.Core.Formats;
using RecoverKit.Core.Hashcat;
using RecoverKit.Core.Native.Kernels;

namespace RecoverKit.Tests;

/// <summary>RecoverKit's hashcat ZIP kernels: installation, hashcat 8 arguments, sample archives.</summary>
public class ZipGpuKernelTests
{
    private sealed class TempDir : IDisposable
    {
        public string Path { get; } = Directory.CreateTempSubdirectory("rk-zipk").FullName;
        public void Dispose()
        {
            try { Directory.Delete(Path, true); } catch (IOException) { }
        }
    }

    [Fact]
    public void KernelSourcesAreEmbeddedAndEveryReplacedFileHasAKnownOriginal()
    {
        Assert.True(HashcatKernels.Sources.ContainsKey(HashcatKernels.IncludeFile));
        var files = HashcatKernels.KernelFiles.ToList();
        Assert.Equal(["m17200_a0-pure.cl", "m17200_a3-pure.cl", "m17210_a0-pure.cl", "m17210_a3-pure.cl"], files);
        foreach (var f in files)
        {
            Assert.True(HashcatKernels.Originals.ContainsKey(f), f);
            Assert.Contains("inc_rk_zipcrypto.cl", HashcatKernels.Sources[f]);
            Assert.Contains(f.Contains("_a3") ? "inc_rk_zip_a3.cl" : "inc_rk_zip_a0.cl", HashcatKernels.Sources[f]);
            Assert.DoesNotContain('\r', HashcatKernels.Sources[f]);
        }
        // hashcat 8 checksums every non-kernel file of OpenCL/ into its cache key, and on Windows
        // hands NVRTC only files named inc_*: the includes must keep that prefix.
        Assert.All(HashcatKernels.IncludeFiles, f => Assert.StartsWith("inc_rk_", f));
        // The settings the benchmark and the tests rewrite.
        Assert.Contains("#define RK_AMP_CACHE 0", HashcatKernels.Sources[HashcatKernels.IncludeFile]);
        Assert.Matches(@"#define RK_QUEUE \d+", HashcatKernels.Sources[HashcatKernels.IncludeFile]);
    }

    private static (string Dir, Dictionary<string, string> Originals) FakeHashcat(string root, bool crlf = false)
    {
        var ocl = Directory.CreateDirectory(Path.Combine(root, "OpenCL")).FullName;
        var originals = new Dictionary<string, string>();
        foreach (var f in HashcatKernels.KernelFiles)
        {
            var text = $"// hashcat original {f}\nKERNEL_FQ void x () {{ }}\n";
            originals[f] = HashcatKernels.Hash(text);
            File.WriteAllText(Path.Combine(ocl, f), crlf ? text.Replace("\n", "\r\n") : text);
        }
        return (root, originals);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]   // the Windows release ships CRLF sources
    public void InstallReplacesKnownOriginalsKeepsThemAndRestorePutsThemBack(bool crlf)
    {
        using var t = new TempDir();
        var (dir, originals) = FakeHashcat(t.Path, crlf);
        var ocl = Path.Combine(dir, "OpenCL");
        var before = HashcatKernels.KernelFiles.ToDictionary(f => f, f => File.ReadAllText(Path.Combine(ocl, f)));

        Assert.Equal(HashcatKernels.State.Original, HashcatKernels.Inspect(dir, originals));
        Assert.True(HashcatKernels.Install(dir, originals));
        Assert.Equal(HashcatKernels.State.Installed, HashcatKernels.Inspect(dir, originals));
        foreach (var f in HashcatKernels.KernelFiles)
        {
            Assert.Equal(HashcatKernels.Sources[f], File.ReadAllText(Path.Combine(ocl, f)));
            Assert.Equal(before[f], File.ReadAllText(Path.Combine(ocl, f + HashcatKernels.OriginalSuffix)));
        }
        foreach (var f in HashcatKernels.IncludeFiles)
            Assert.Equal(HashcatKernels.Sources[f], File.ReadAllText(Path.Combine(ocl, f)));
        Assert.Empty(Directory.GetFiles(ocl, "*.rk-tmp"));

        // Installing again changes nothing; restoring brings hashcat's files back.
        Assert.True(HashcatKernels.Install(dir, originals));
        Assert.True(HashcatKernels.Restore(dir));
        foreach (var f in HashcatKernels.KernelFiles) Assert.Equal(before[f], File.ReadAllText(Path.Combine(ocl, f)));
        Assert.Equal(HashcatKernels.State.Original, HashcatKernels.Inspect(dir, originals));
    }

    [Fact]
    public void KernelsOfAnEarlierRecoverKitAreUpdated()
    {
        using var t = new TempDir();
        var (dir, originals) = FakeHashcat(t.Path);
        Assert.True(HashcatKernels.Install(dir, originals));
        var f = HashcatKernels.KernelFiles.First();
        var path = Path.Combine(dir, "OpenCL", f);
        File.WriteAllText(path, "/* " + HashcatKernels.Marker + " 8.0.0, an older version */\n");
        File.WriteAllText(Path.Combine(dir, "OpenCL", HashcatKernels.IncludeFile), "// older include\n");

        Assert.Equal(HashcatKernels.State.Original, HashcatKernels.Inspect(dir, originals));
        Assert.True(HashcatKernels.Install(dir, originals));
        Assert.Equal(HashcatKernels.State.Installed, HashcatKernels.Inspect(dir, originals));
        Assert.Equal(HashcatKernels.Sources[f], File.ReadAllText(path));

        // Without hashcat's original beside it, a marked file is not touched.
        File.WriteAllText(path, "/* " + HashcatKernels.Marker + " */\n");
        File.Delete(path + HashcatKernels.OriginalSuffix);
        Assert.Equal(HashcatKernels.State.Unsupported, HashcatKernels.Inspect(dir, originals));
    }

    [Fact]
    public void OtherHashcatVersionsAreLeftAlone()
    {
        using var t = new TempDir();
        var (dir, originals) = FakeHashcat(t.Path);
        var f = HashcatKernels.KernelFiles.First();
        var path = Path.Combine(dir, "OpenCL", f);
        File.WriteAllText(path, "// hashcat 7.1.2 kernel\n");

        Assert.Equal(HashcatKernels.State.Unsupported, HashcatKernels.Inspect(dir, originals));
        Assert.False(HashcatKernels.Install(dir, originals));
        Assert.Equal("// hashcat 7.1.2 kernel\n", File.ReadAllText(path));
        Assert.False(File.Exists(path + HashcatKernels.OriginalSuffix));
        Assert.False(File.Exists(Path.Combine(dir, "OpenCL", HashcatKernels.IncludeFile)));
        // A folder without kernels at all is not hashcat 8 either.
        Assert.Equal(HashcatKernels.State.Unsupported, HashcatKernels.Inspect(t.Path + "-missing"));
    }

    private static RunRequest Request(bool restore) => new()
    {
        Mode = 17210, HashFile = "h.hash", SessionName = "s", SessionDir = Path.GetTempPath(), Restore = restore,
        Attack = new PreparedAttack { Description = "t", Args = { "-a", "3", "?l?l?l" } },
    };

    [Fact]
    public void ResumingUsesRestorePositionWithHashcat8AndRestoreWithHashcat7()
    {
        using var t = new TempDir();
        string exe = Path.Combine(t.Path, OperatingSystem.IsWindows() ? "hashcat.exe" : "hashcat");
        File.WriteAllText(exe, "");
        var runner = new HashcatRunner(HashcatTool.Locate(exe, t.Path, t.Path)!) { HashcatMajorVersion = 8 };

        var fresh = runner.BuildArguments(Request(false));
        var resumed = runner.BuildArguments(Request(true));
        Assert.DoesNotContain("--restore-position", fresh);
        Assert.DoesNotContain("--restore", resumed);
        Assert.Equal([.. fresh, "--restore-position"], resumed);
        Assert.Equal(HashcatRunner.RestoreFile(Path.GetTempPath(), "s"), resumed[resumed.IndexOf("--restore-file-path") + 1]);

        runner.HashcatMajorVersion = 7;
        Assert.Equal(["--session", "s", "--restore", "--restore-file-path", HashcatRunner.RestoreFile(Path.GetTempPath(), "s")],
            runner.BuildArguments(Request(true)));
    }

    [Theory]
    [InlineData("v8.0.0\n", 8)]
    [InlineData("v7.1.2", 7)]
    [InlineData("v6.2.6-851-g6716447df", 6)]
    [InlineData("", 0)]
    public void MajorVersionIsReadFromVersionOutput(string output, int major)
        => Assert.Equal(major, HashcatTool.ParseMajorVersion(output));

    [Fact]
    public void AnOlderManagedCopyGivesWayToThePinnedVersion()
    {
        using var t = new TempDir();
        string name = OperatingSystem.IsWindows() ? "hashcat.exe" : "hashcat";
        var engines = Directory.CreateDirectory(Path.Combine(t.Path, "engines")).FullName;
        var old = Path.Combine(Directory.CreateDirectory(Path.Combine(engines, "hashcat-7.1.2")).FullName, name);
        File.WriteAllText(old, "");
        Assert.True(HashcatTool.IsOlderManagedCopy(old, engines));
        Assert.False(HashcatTool.IsOlderManagedCopy(Path.Combine(t.Path, "elsewhere", name), engines));

        // Only the old copy: it is still used (hashcat works, it is just older).
        var app = Directory.CreateDirectory(Path.Combine(t.Path, "app")).FullName;
        Assert.Equal(old, HashcatTool.Locate(old, app, engines)!.Exe);

        var pinned = Path.Combine(Directory.CreateDirectory(Path.Combine(engines, "hashcat-" + HashcatInstaller.Version)).FullName, name);
        File.WriteAllText(pinned, "");
        Assert.False(HashcatTool.IsOlderManagedCopy(pinned, engines));
        Assert.Equal(pinned, HashcatTool.Locate(old, app, engines)!.Exe);
    }

    [Fact]
    public void Hashcat8RuntimeCacheIsNotCopiedFromABundle()
    {
        using var t = new TempDir();
        var bundle = Directory.CreateDirectory(Path.Combine(t.Path, "bundle")).FullName;
        string name = OperatingSystem.IsWindows() ? "hashcat.exe" : "hashcat";
        File.WriteAllText(Path.Combine(bundle, name), "");
        File.WriteAllText(Path.Combine(bundle, HashcatInstaller.BundleStampFile), HashcatInstaller.Version + "-1\n");
        Directory.CreateDirectory(Path.Combine(bundle, "cache", "kernels"));
        File.WriteAllText(Path.Combine(bundle, "cache", "kernels", "m17210.kernel"), "x");
        Directory.CreateDirectory(Path.Combine(bundle, "feeds"));
        File.WriteAllText(Path.Combine(bundle, "feeds", "feed_stdin.so"), "x");
        var inst = new HashcatInstaller(Path.Combine(t.Path, "engines"));
        inst.CopyBundle(bundle, null, default);
        Assert.True(File.Exists(Path.Combine(inst.ExpectedDirectory, "feeds", "feed_stdin.so")));
        Assert.False(Directory.Exists(Path.Combine(inst.ExpectedDirectory, "cache")));
    }

    [Theory]
    [InlineData(17, false, false)]
    [InlineData(1, false, true)]
    [InlineData(700, true, false)]
    [InlineData(3000, true, true)]
    public void SampleArchivesExtractToHashesTheCpuEngineConfirms(int length, bool deflate, bool descriptor)
    {
        var rng = new Random(length);
        var pw = Encoding.UTF8.GetBytes("pw" + length);
        var content = deflate ? ZipCryptoSample.Text(length, rng) : Enumerable.Range(0, length).Select(i => (byte)rng.Next(256)).ToArray();
        var zip = ZipCryptoSample.Archive([new ZipCryptoSample.Entry("a.bin", content, deflate, descriptor)], pw, rng);
        var target = ZipCryptoSample.Extract(zip);
        Assert.Equal(deflate ? 17200 : 17210, target.Modes[0]);
        var k = ZipCryptoKernel.TryParse(target.HashLines)!;
        Assert.True(k.Verify(pw));
        Assert.False(k.Verify(Encoding.UTF8.GetBytes("pw" + (length + 1))));
    }
}
