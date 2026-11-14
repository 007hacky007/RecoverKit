using RecoverKit.Core.Dependencies;
using RecoverKit.Core.Hashcat;
using Xunit;

namespace RecoverKit.Tests;

public class HashcatRepairTests
{
    private sealed class TempDir : IDisposable
    {
        public string Path { get; } = Directory.CreateTempSubdirectory("rk-repair").FullName;
        public void Dispose()
        {
            try { Directory.Delete(Path, true); } catch (IOException) { }
        }
    }

    private static string MakeBundle(string root)
    {
        var bundle = Directory.CreateDirectory(System.IO.Path.Combine(root, "app", "hashcat")).FullName;
        File.WriteAllText(System.IO.Path.Combine(bundle, HashcatInstaller.ExeName), "exe");
        File.WriteAllText(System.IO.Path.Combine(bundle, HashcatInstaller.BundleStampFile), "8.0.0-1\n");
        return bundle;
    }

    private static HashcatRepair.Environment Env(string root, string bundle, Func<string, bool> starts, List<string> stopped, bool inPlace = false)
        => new(System.IO.Path.Combine(root, "engines", "hashcat-8.0.0", HashcatInstaller.ExeName))
        {
            Bundle = bundle, InPlace = inPlace, Engines = new HashcatInstaller(System.IO.Path.Combine(root, "engines")),
            Alternatives = [System.IO.Path.Combine(root, "alt1"), System.IO.Path.Combine(root, "alt2")],
            Starts = (exe, _) => Task.FromResult(starts(exe)),
            StopProcesses = stopped.Add,
            Current = path => path,
        };

    [Fact]
    public async Task AFreshCopyThatStartsIsKept()
    {
        using var t = new TempDir();
        var bundle = MakeBundle(t.Path);
        var stopped = new List<string>();
        var exe = await HashcatRepair.RepairAsync(Env(t.Path, bundle, _ => true, stopped), null, default);
        Assert.Equal(System.IO.Path.Combine(t.Path, "engines", "hashcat-8.0.0", HashcatInstaller.ExeName), exe);
        Assert.Equal([System.IO.Path.Combine(t.Path, "engines", "hashcat-8.0.0")], stopped);
        Assert.Equal("8.0.0-1", HashcatInstaller.ReadStamp(System.IO.Path.GetDirectoryName(exe)!));
    }

    [Fact]
    public async Task AHeldFolderMovesHashcatElsewhere()
    {
        using var t = new TempDir();
        var bundle = MakeBundle(t.Path);
        var exe = await HashcatRepair.RepairAsync(Env(t.Path, bundle, e => !e.Contains("engines") && !e.Contains("alt1"), []), null, default);
        Assert.Equal(System.IO.Path.Combine(t.Path, "alt2", "hashcat-8.0.0", HashcatInstaller.ExeName), exe);
        Assert.True(File.Exists(exe));
    }

    [Fact]
    public async Task ABlockedBundleTellsTheUserWhereToLook()
    {
        using var t = new TempDir();
        var bundle = MakeBundle(t.Path);
        var ex = await Assert.ThrowsAsync<InstallException>(() => HashcatRepair.RepairAsync(Env(t.Path, bundle, _ => false, []), null, default));
        Assert.Contains("Protection history", ex.Message);
        Assert.False(Directory.Exists(System.IO.Path.Combine(t.Path, "alt1")));
    }

    [Fact]
    public async Task ThePortableVersionKeepsItsBundleWhenItStarts()
    {
        using var t = new TempDir();
        var bundle = MakeBundle(t.Path);
        var exe = await HashcatRepair.RepairAsync(Env(t.Path, bundle, _ => true, [], inPlace: true), null, default);
        Assert.Equal(System.IO.Path.Combine(bundle, HashcatInstaller.ExeName), exe);
        Assert.False(Directory.Exists(System.IO.Path.Combine(t.Path, "engines")));
    }

    [Fact]
    public void AStartTimeoutOfRecoverKitsCopyOffersRepair()
    {
        var facts = new MachineFacts
        {
            IsWindows = true, HashcatExe = @"C:\Users\u\AppData\Roaming\RecoverKit\engines\hashcat-8.0.0\hashcat.exe",
            HashcatIsManaged = true, BundleAvailable = true, HashcatError = "hashcat did not start within 20 s.", HashcatStartTimedOut = true,
        };
        var row = DependencyCheck.Evaluate(facts).Single(i => i.Id == DependencyId.Hashcat);
        Assert.Equal(DependencyAction.RepairHashcat, row.Action);
        Assert.Equal(Light.Red, row.Light);
        // A device listing that hangs is a driver problem: a repair of hashcat would not help.
        var hang = DependencyCheck.Evaluate(facts with { HashcatStartTimedOut = false }).Single(i => i.Id == DependencyId.Hashcat);
        Assert.NotEqual(DependencyAction.RepairHashcat, hang.Action);
    }
}
