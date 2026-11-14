using RecoverKit.Core.Hashcat;
using Xunit;

namespace RecoverKit.Tests;

/// <summary>The hashcat folder shipped beside the executable (Windows layout) is only a copy source.</summary>
public class BundledHashcatTests
{
    private static (string App, string Bundle, string Engines) MakeApp(string root, string stamp)
    {
        var app = Directory.CreateDirectory(System.IO.Path.Combine(root, "app")).FullName;
        var bundle = Directory.CreateDirectory(System.IO.Path.Combine(app, "hashcat")).FullName;
        File.WriteAllText(System.IO.Path.Combine(bundle, HashcatInstaller.ExeName), "#!/bin/sh\necho v8.0.0\n");
        File.WriteAllText(System.IO.Path.Combine(bundle, HashcatInstaller.BundleStampFile), stamp + "\n");
        if (!OperatingSystem.IsWindows())
            File.SetUnixFileMode(System.IO.Path.Combine(bundle, HashcatInstaller.ExeName),
                UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        return (app, bundle, System.IO.Path.Combine(root, "engines"));
    }

    [Fact]
    public void BundleIsFoundBesideTheExecutable()
    {
        using var t = new TempDir();
        var (app, bundle, _) = MakeApp(t.Path, "8.0.0-1");
        Assert.Equal(System.IO.Path.GetFullPath(bundle), HashcatInstaller.FindBundle(app));

        File.Delete(System.IO.Path.Combine(bundle, HashcatInstaller.BundleStampFile));
        Assert.Null(HashcatInstaller.FindBundle(app));
    }

    [Fact]
    public void LocateNeverRunsTheCopyBesideTheExecutable()
    {
        using var t = new TempDir();
        var (app, bundle, engines) = MakeApp(t.Path, "8.0.0-1");
        var before = HashcatTool.Locate(null, app, engines);
        Assert.True(before is null || !before.Exe.StartsWith(bundle, StringComparison.Ordinal));

        Assert.True(new HashcatInstaller(engines).TryInstallBundledHere(bundle, null, default));
        var tool = HashcatTool.Locate(null, app, engines);
        Assert.NotNull(tool);
        Assert.Equal(System.IO.Path.Combine(engines, "hashcat-8.0.0", HashcatInstaller.ExeName), tool!.Exe);
    }

    [Fact]
    public void PortableVersionRunsTheBundleInPlace()
    {
        using var t = new TempDir();
        var (app, bundle, engines) = MakeApp(t.Path, "8.0.0-1");
        var tool = HashcatTool.Locate(null, app, engines, portable: true);
        Assert.Equal(System.IO.Path.Combine(bundle, HashcatInstaller.ExeName), tool!.Exe);
        Assert.False(Directory.Exists(engines));

        // A path an earlier RecoverKit saved for its own older copy gives way to the bundle.
        var old = Directory.CreateDirectory(System.IO.Path.Combine(engines, "hashcat-7.1.2")).FullName;
        var oldExe = System.IO.Path.Combine(old, HashcatInstaller.ExeName);
        File.WriteAllText(oldExe, "old");
        Assert.Equal(System.IO.Path.Combine(bundle, HashcatInstaller.ExeName), HashcatTool.Locate(oldExe, app, engines, portable: true)!.Exe);
        // A hashcat of the user's own, chosen in Preferences, still wins.
        var own = System.IO.Path.Combine(t.Path, HashcatInstaller.ExeName);
        File.WriteAllText(own, "own");
        Assert.Equal(own, HashcatTool.Locate(own, app, engines, portable: true)!.Exe);
    }

    [Fact]
    public void TimeoutsSayWhatToCheck()
    {
        Assert.Contains("antivirus", HashcatTool.StartTimeoutMessage(@"C:\RecoverKit\hashcat", TimeSpan.FromSeconds(20)), StringComparison.OrdinalIgnoreCase);
        Assert.Contains(@"C:\RecoverKit\hashcat", HashcatTool.StartTimeoutMessage(@"C:\RecoverKit\hashcat", TimeSpan.FromSeconds(20)));
        Assert.Contains("hashcat -I", HashcatTool.DevicesTimeoutMessage(TimeSpan.FromSeconds(90)));
    }

    [Fact]
    public void UnstampedEnginesCopyIsReplacedByTheBundle()
    {
        using var t = new TempDir();
        var (_, bundle, engines) = MakeApp(t.Path, "8.0.0-1");
        var inst = new HashcatInstaller(engines);
        var dir = Directory.CreateDirectory(System.IO.Path.Combine(engines, "hashcat-8.0.0")).FullName;
        File.WriteAllText(System.IO.Path.Combine(dir, HashcatInstaller.ExeName), "old");

        Assert.True(inst.BundleNeedsInstall(bundle));
        Assert.True(inst.TryInstallBundledHere(bundle, null, default));
        Assert.Equal("8.0.0-1", HashcatInstaller.ReadStamp(dir));
    }

    [Fact]
    public void ConfiguredOldManagedCopyGivesWayToTheBundleOnWindowsLayout()
    {
        using var t = new TempDir();
        var (app, bundle, engines) = MakeApp(t.Path, "8.0.0-1");
        var oldDir = Directory.CreateDirectory(System.IO.Path.Combine(engines, "hashcat-7.1.2")).FullName;
        var old = System.IO.Path.Combine(oldDir, HashcatInstaller.ExeName);
        File.WriteAllText(old, "old");

        Assert.True(new HashcatInstaller(engines).TryInstallBundledHere(bundle, null, default));
        var tool = HashcatTool.Locate(old, app, engines);
        Assert.Equal(System.IO.Path.Combine(engines, "hashcat-8.0.0", HashcatInstaller.ExeName), tool!.Exe);
    }

    [Fact]
    public async Task InstallWithoutBundleExplainsWhatToDo()
    {
        using var t = new TempDir();
        var inst = new HashcatInstaller(System.IO.Path.Combine(t.Path, "engines"));
        var ex = await Assert.ThrowsAsync<InstallException>(() => inst.InstallAsync());
        Assert.Equal(HashcatInstaller.NoBundleMessage, ex.Message);
    }

    private sealed class TempDir : IDisposable
    {
        public string Path { get; } = Directory.CreateTempSubdirectory("rk-bundle").FullName;
        public void Dispose()
        {
            try { Directory.Delete(Path, true); } catch (IOException) { }
        }
    }

    [Fact]
    public void WindowsBuildPinsTheSameHashcatAsTheApp()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(System.IO.Path.Combine(dir.FullName, "RecoverKit.sln")))
            dir = dir.Parent;
        Assert.NotNull(dir);

        var script = File.ReadAllText(System.IO.Path.Combine(dir!.FullName, "installer", "build.ps1"));
        Assert.Contains("$HashcatVersion = '" + HashcatInstaller.Version + "'", script);
        Assert.Contains("9fa86e1bfd5dd898d3c83aa38a67b08db1ba5d2f5252dffa2af44a8c62585f49", script);
    }
}
