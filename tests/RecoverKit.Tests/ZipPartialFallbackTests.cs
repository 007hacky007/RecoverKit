using RecoverKit.Core;
using RecoverKit.Core.Attacks;
using RecoverKit.Core.Formats;
using RecoverKit.Core.Hashcat;
using Xunit;

namespace RecoverKit.Tests;

public sealed class ZipPartialFallbackTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("rk-partial-fallback").FullName;
    public void Dispose() => Directory.Delete(_dir, true);

    private async Task<SessionResult> Run(bool deflate, AttackSpec attack, bool native = true, bool kernels = false,
        Action<HashTarget>? configure = null, SessionState? resume = null, CancellationToken ct = default, bool gpuRefusal = false)
    {
        var data = new byte[330_000];
        new Random(74).NextBytes(data);
        string archive = Path.Combine(_dir, "sample.zip");
        File.WriteAllBytes(archive, ZipCryptoSample.Archive([new("large.bin", data, deflate)], "ab1"u8, new Random(8)));
        var detection = new Detection { FilePath = archive };
        using (var stream = File.OpenRead(archive)) ZipExtractor.Extract(stream, detection);
        configure?.Invoke(detection.Target!);
        // This file cannot execute. Any accidental hashcat invocation makes the test fail.
        string exe = Path.Combine(_dir, OperatingSystem.IsWindows() ? "hashcat.exe" : "hashcat");
        File.WriteAllText(exe, "not an executable");
        if (gpuRefusal && !OperatingSystem.IsWindows())
        {
            File.WriteAllText(exe, "#!/usr/bin/env python3\nimport sys\n" +
                "if '--version' in sys.argv: print('v8.0.0'); sys.exit(0)\n" +
                "print('Skipping (hash-mode 17200)')\nsys.exit(255)\n");
            File.SetUnixFileMode(exe, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        }
        var tool = HashcatTool.Locate(exe, _dir, _dir)!;
        if (kernels)
        {
            Directory.CreateDirectory(Path.Combine(_dir, "OpenCL"));
            foreach (var (name, source) in HashcatKernels.Sources)
                File.WriteAllText(Path.Combine(_dir, "OpenCL", name), source);
        }
        var settings = new Settings
        {
            SessionsDir = _dir, DontUsePasswordCache = true, UseNativeCpuEngine = native,
            MaxCpuThreads = 1,
        };
        var session = new RecoverySession(tool, settings)
        {
            Devices = [new BackendDevice { Id = 1, Type = "GPU", Vendor = "Apple", Backend = "Metal" }],
        };
        return await session.RunAsync(detection.Target!, archive, [attack], resume, ct);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task WithoutReplacementKernelsMaskUsesOnlyTheCpu(bool deflate)
    {
        var result = await Run(deflate, new AttackSpec { Kind = AttackKind.Mask, HashcatMask = "ab?d" });
        Assert.Equal(SessionOutcome.Found, result.Outcome);
        Assert.Equal(["ab1"], result.Passwords);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task WithoutReplacementKernelsPlainDictionaryUsesOnlyTheCpu(bool deflate)
    {
        string dict = Path.Combine(_dir, "words.txt");
        File.WriteAllText(dict, "wrong\nab1\nother\n");
        var result = await Run(deflate, new AttackSpec { Kind = AttackKind.Dictionary, Dictionaries = [dict, null, null, null] });
        Assert.Equal(SessionOutcome.Found, result.Outcome);
        Assert.Equal(["ab1"], result.Passwords);
    }

    [Fact]
    public async Task WithoutReplacementKernelsDisabledCpuFailsClearly()
    {
        var result = await Run(true, new AttackSpec { Kind = AttackKind.Mask, HashcatMask = "ab?d" }, native: false);
        Assert.Equal(SessionOutcome.Error, result.Outcome);
        Assert.Contains("built-in CPU engine", result.Error);
    }

    [Fact]
    public async Task WrongDictionaryFinishesWithoutAFalseResult()
    {
        string dict = Path.Combine(_dir, "words.txt");
        File.WriteAllText(dict, "wrong\nanother\n");
        var result = await Run(false, new AttackSpec { Kind = AttackKind.Dictionary, Dictionaries = [dict, null, null, null] });
        Assert.Equal(SessionOutcome.NotFound, result.Outcome);
        Assert.Empty(result.Passwords);
    }

    [Fact]
    public async Task StoredPartialUsesCpuEvenWithReplacementKernels()
    {
        var result = await Run(false, new AttackSpec { Kind = AttackKind.Mask, HashcatMask = "ab?d" }, kernels: true);
        Assert.Equal(SessionOutcome.Found, result.Outcome);
    }

    [Fact]
    public async Task UnsupportedCpuDictionaryRulesFailBeforeStartingHashcat()
    {
        string dict = Path.Combine(_dir, "words.txt");
        string rules = Path.Combine(_dir, "custom.rule");
        File.WriteAllText(dict, "ab1\n");
        File.WriteAllText(rules, ":\n");
        var result = await Run(true, new AttackSpec
        {
            Kind = AttackKind.Dictionary, Dictionaries = [dict, null, null, null],
            Rules = RulesPreset.CustomFile, RulesFile = rules,
        });
        Assert.Equal(SessionOutcome.Error, result.Outcome);
        Assert.Contains("without rules", result.Error);
    }

    [Fact]
    public async Task CpuDictionaryDecodesHexAndConvertedWords()
    {
        string dict = Path.Combine(_dir, "words.txt");
        File.WriteAllText(dict, "wrong\n$HEX[616231]\n", System.Text.Encoding.Unicode);
        var result = await Run(false, new AttackSpec { Kind = AttackKind.Dictionary, Dictionaries = [dict, null, null, null] });
        Assert.Equal(SessionOutcome.Found, result.Outcome);
        Assert.Equal(["ab1"], result.Passwords);
    }

    [Fact]
    public async Task ConvertedCpuDictionaryResumesAfterTheLastTestedWord()
    {
        string dict = Path.Combine(_dir, "words.txt");
        File.WriteAllText(dict, "wrong\nab1\nother\n", System.Text.Encoding.Unicode);
        var attack = new AttackSpec { Kind = AttackKind.Dictionary, Dictionaries = [dict, null, null, null] };
        using var stop = new CancellationTokenSource();
        HashTarget? target = null;
        var first = await Run(false, attack, configure: t =>
        {
            target = t;
            t.ConfirmPassword = _ => { stop.Cancel(); return false; };
        }, ct: stop.Token);
        Assert.Equal(SessionOutcome.Stopped, first.Outcome);
        var saved = SessionState.Load(new Settings { SessionsDir = _dir }, target!);
        Assert.NotNull(saved);
        Assert.True(saved.Restorable);
        var checkedWords = new List<string>();
        var resumed = await Run(false, attack, configure: t =>
        {
            var confirm = t.ConfirmPassword!;
            t.ConfirmPassword = bytes => { checkedWords.Add(System.Text.Encoding.UTF8.GetString(bytes)); return confirm(bytes); };
        }, resume: saved);
        Assert.Equal(SessionOutcome.Found, resumed.Outcome);
        Assert.Equal(["ab1"], checkedWords);
    }

    [Fact]
    public async Task AppleGpuRefusalAlsoFallsBackForPartialDictionaries()
    {
        if (!OperatingSystem.IsMacOS()) return;
        string dict = Path.Combine(_dir, "words.txt");
        File.WriteAllText(dict, "wrong\nab1\n");
        var result = await Run(true, new AttackSpec { Kind = AttackKind.Dictionary, Dictionaries = [dict, null, null, null] },
            kernels: true, gpuRefusal: true);
        Assert.Equal(SessionOutcome.Found, result.Outcome);
        Assert.Equal(["ab1"], result.Passwords);
    }
}
