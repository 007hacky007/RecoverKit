using System.IO.Compression;
using RecoverKit.Core;
using RecoverKit.Core.Attacks;
using RecoverKit.Core.Attacks.Stay;
using RecoverKit.Core.Formats;
using RecoverKit.Tests.Stay;
using Xunit;

namespace RecoverKit.Tests.Stay;

public class StayZipStepTests
{
    private static Settings IsolatedSettings()
        => new()
        {
            KeyCachePath = Path.Combine(Path.GetTempPath(), $"staykeys-{Guid.NewGuid():N}.cache"),
            SessionsDir = Directory.CreateDirectory(Path.Combine(Path.GetTempPath(), $"staysess-{Guid.NewGuid():N}")).FullName,
        };

    private static (string Path, HashTarget Target) ZipTarget(int files, uint seed = 0x5d3f8a21)
        => StayTestZip.ExtractToTemp(StayTestZip.MakeZip(files, seed));

    [Fact]
    public async Task Step_recovers_caches_and_decrypts()
    {
        var (path, target) = ZipTarget(5);
        var settings = IsolatedSettings();
        try
        {
            var logs = new List<(LogKind Kind, string Message)>();
            var outcome = await StayZipStep.RunAsync(target, path, settings, (k, m) => logs.Add((k, m)), CancellationToken.None);

            Assert.NotNull(outcome.Keys);
            Assert.NotNull(outcome.DecryptedCopy);
            Assert.True(File.Exists(outcome.DecryptedCopy));
            using var opened = ZipFile.OpenRead(outcome.DecryptedCopy!);
            Assert.Equal(5, opened.Entries.Count);
            Assert.False(outcome.Incompatible);

            // second run: served from the key cache, no attack progress
            var logs2 = new List<(LogKind Kind, string Message)>();
            var outcome2 = await StayZipStep.RunAsync(target, path, settings, (k, m) => logs2.Add((k, m)), CancellationToken.None);
            Assert.Equal(outcome.Keys, outcome2.Keys);
            Assert.Contains(logs2, l => l.Message.Contains("key cache", StringComparison.OrdinalIgnoreCase));
            Assert.DoesNotContain(logs2, l => l.Message.Contains("Fast key search: "));
        }
        finally { Cleanup(path, settings); }
    }

    [Fact]
    public async Task Step_incompatible_archive_continues()
    {
        var (path, target) = ZipTarget(3);
        var settings = IsolatedSettings();
        try
        {
            var logs = new List<(LogKind Kind, string Message)>();
            var outcome = await StayZipStep.RunAsync(target, path, settings, (k, m) => logs.Add((k, m)), CancellationToken.None);

            Assert.Null(outcome.Keys);
            Assert.Null(outcome.DecryptedCopy);
            Assert.True(outcome.Incompatible);
            Assert.Contains(logs, l => l.Message.Contains("not compatible", StringComparison.OrdinalIgnoreCase));
        }
        finally { Cleanup(path, settings); }
    }

    [Fact]
    public async Task Step_skips_copy_when_output_exists()
    {
        var (path, target) = ZipTarget(5, 0x77c1a2b3);
        var settings = IsolatedSettings();
        try
        {
            var existing = ZipStayDecryptor.OutputPathFor(path, settings);
            await File.WriteAllTextAsync(existing, "keep me");

            var logs = new List<(LogKind Kind, string Message)>();
            var outcome = await StayZipStep.RunAsync(target, path, settings, (k, m) => logs.Add((k, m)), CancellationToken.None);

            Assert.NotNull(outcome.Keys);                                   // the attack still ran and succeeded
            Assert.Null(outcome.DecryptedCopy);                             // but no copy was written
            Assert.Equal("keep me", await File.ReadAllTextAsync(existing));
            Assert.Contains(logs, l => l.Message.Contains("already exists", StringComparison.OrdinalIgnoreCase));
        }
        finally { Cleanup(path, settings); }
    }

    [Fact]
    public async Task Session_runs_stay_step_and_reports_recovered_keys()
    {
        var (path, target) = ZipTarget(5, 0x2b4d6f81);
        var settings = IsolatedSettings();
        settings.DontUsePasswordCache = true;   // the stub hashcat cannot run; skip the potfile lookup
        var fakeHashcat = Path.Combine(Path.GetTempPath(), "hashcat");
        await File.WriteAllTextAsync(fakeHashcat, "stub");
        var tool = RecoverKit.Core.Hashcat.HashcatTool.Locate(fakeHashcat, Path.GetTempPath(), Path.GetTempPath());
        Assert.NotNull(tool);
        try
        {
            var session = new RecoverySession(tool!, settings);
            var logs = new List<(LogKind Kind, string Message)>();
            session.Log += (k, m) => logs.Add((k, m));

            var steps = new List<AttackSpec> { new() { Kind = AttackKind.StayZip } };
            var result = await session.RunAsync(target, path, steps, null, CancellationToken.None);

            Assert.Equal(SessionOutcome.KeyRecovered, result.Outcome);
            Assert.NotNull(result.Key);
            Assert.NotNull(result.DecryptedCopy);
            Assert.True(File.Exists(result.DecryptedCopy!));
            Assert.DoesNotContain(logs, l => l.Message.Contains(result.Key!, StringComparison.Ordinal));   // keys never logged

            // disabled: the step is skipped and the session reports a plain NotFound
            settings.TryStayZipAttack = false;
            var result2 = await session.RunAsync(target, path, steps, null, CancellationToken.None);
            Assert.Equal(SessionOutcome.NotFound, result2.Outcome);
            Assert.Null(result2.Key);
        }
        finally
        {
            Cleanup(path, settings);
            File.Delete(fakeHashcat);
            File.Delete(ZipStayDecryptor.OutputPathFor(path, settings));
        }
    }

    private static void Cleanup(string path, Settings settings)
    {
        File.Delete(path);
        try { File.Delete(ZipStayDecryptor.OutputPathFor(path, settings)); } catch { }
        try { File.Delete(settings.KeyCachePath); } catch { }
        try { Directory.Delete(settings.SessionsDir, true); } catch { }
    }
}
