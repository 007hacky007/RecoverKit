using System.Text.Json.Nodes;
using RecoverKit.Core;
using RecoverKit.Core.Attacks;
using RecoverKit.Core.Formats;
using RecoverKit.Core.Hashcat;
using Xunit;

namespace RecoverKit.Tests;

public class OptimizedKernelTests
{
    private const string Pure = """
        {"12500":{"name":"RAR3-hp","slow_hash":true,"kernel_type":["pure","optimized"],"password_len_max":128}}
        """;
    private const string Optimized = """
        {"12500":{"name":"RAR3-hp","kernel_type_filter":["optimized"],"attack_mode_filter":3,"password_len_max":20,"benchmark_mask":"?l?l?l?l?l","benchmark_charset1":"N/A"}}
        """;

    private static PreparedAttack Mask(int length) => new() { Description = "test", Args = { "-a", "3", new string('a', length) } };

    [Theory]
    [InlineData(19, true)]
    [InlineData(20, true)]
    [InlineData(21, false)]
    public void UsesTheReportedLimitForMasks(int length, bool expected)
        => Assert.Equal(expected, RecoverySession.CanUseOptimizedKernel(HashcatTool.ParseModeInfo(12500, Pure, Optimized), Mask(length)));

    [Theory]
    [InlineData(null)]
    [InlineData("{}")]
    [InlineData("not json")]
    [InlineData("{\"12500\":{\"password_len_max\":20}}")]
    [InlineData("{\"12500\":{\"kernel_type_filter\":[\"pure\"],\"password_len_max\":128}}")]
    [InlineData("{\"12500\":{\"kernel_type_filter\":[\"optimized\"],\"password_len_max\":0}}")]
    [InlineData("{\"12500\":{\"kernel_type_filter\":[\"optimized\"],\"password_len_max\":\"20\"}}")]
    public void UnknownOrUnselectedOptimizedLimitUsesPure(string? optimized)
    {
        var info = HashcatTool.ParseModeInfo(12500, Pure, optimized);
        Assert.Equal(128, info.PasswordLenMax);
        Assert.False(RecoverySession.CanUseOptimizedKernel(info, Mask(1)));
        Assert.False(RecoverySession.CanUseOptimizedKernel(null, Mask(1)));
    }

    [Fact]
    public void MeasuresThePreparedAttackIncludingIncrementAndUtf8()
    {
        var info = HashcatTool.ParseModeInfo(12500, Pure, Optimized);
        var target = new HashTarget { FormatId = "TEST", FormatName = "test", Protection = "test", Modes = [12500], HashLines = "test" };
        var brute = new AttackSpec { MaxLength = 21 };
        Assert.False(RecoverySession.CanUseOptimizedKernel(info, AttackPlanner.Prepare(brute, target, new())));
        brute.Mask = new string('a', 20) + "?";
        brute.MaxLength = 1;
        Assert.False(RecoverySession.CanUseOptimizedKernel(info, AttackPlanner.Prepare(brute, target, new())));
        brute.Mask = new string('a', 18) + "é?"; // 21 UTF-8 bytes in hashcat's hex mask
        Assert.False(RecoverySession.CanUseOptimizedKernel(info, AttackPlanner.Prepare(brute, target, new())));
        var increment = Mask(21);
        increment.Args.InsertRange(2, ["-i", "--increment-min", "1", "--increment-max", "20"]);
        Assert.True(RecoverySession.CanUseOptimizedKernel(info, increment));
        Assert.False(RecoverySession.CanUseOptimizedKernel(info, new PreparedAttack { Description = "words", Args = { "-a", "0", "words", "-r", "rules" } }));
        var streamed = Mask(1);
        streamed.Stdin = () => ["a"];
        Assert.False(RecoverySession.CanUseOptimizedKernel(info, streamed));
    }

    [Theory]
    [InlineData(true, false)]
    [InlineData(false, true)]
    [InlineData(null, true)]
    public async Task ResumeUsesSavedChoiceWithoutQueryingChangedSettings(bool? saved, bool enabled)
    {
        using var t = new TempDir();
        string exe = Path.Combine(t.Path, "missing-engine");
        File.WriteAllText(exe, "");
        var tool = HashcatTool.Locate(exe, t.Path, t.Path)!;
        Assert.Equal(saved ?? false, await RecoverySession.SelectOptimizedKernelAsync(tool, 12500, Mask(21), enabled, restore: true, savedChoice: saved));
    }

    [Theory]
    [InlineData(true, false)]
    [InlineData(false, false)]
    [InlineData(true, true)]
    [InlineData(false, true)]
    public async Task SessionSavesChoiceBeforeRunAndHonoursItOnResume(bool enabled, bool keySearch)
    {
        if (OperatingSystem.IsWindows()) return;
        using var t = new TempDir();
        int mode = keySearch ? 9710 : 12500;
        var tool = FakeTool(t.Path, mode);
        var settings = new Settings { SessionsDir = t.Path, DontUsePasswordCache = true, DontUseKeyCache = true, UseNativeCpuEngine = false, OptimizedKernels = enabled };
        var target = new HashTarget { FormatId = keySearch ? "972K" : "TEST", FormatName = "test", Protection = "test", Modes = [mode], HashLines = "test" };
        var session = new RecoverySession(tool, settings);
        var attack = new AttackSpec { Kind = keySearch ? AttackKind.KeySearch : AttackKind.Mask, HashcatMask = "?d?d?d" };
        Assert.Equal(SessionOutcome.Stopped, (await session.RunAsync(target, "fixture", [attack], null, default)).Outcome);
        var state = SessionState.Load(settings, target)!;
        Assert.Equal(enabled, state.UseOptimizedKernel);
        Assert.Equal(enabled, JsonNode.Parse(File.ReadAllText(Path.Combine(t.Path, "state-at-start.json")))!["UseOptimizedKernel"]!.GetValue<bool>());
        Assert.Equal(enabled, File.ReadAllLines(Path.Combine(t.Path, "run.args")).Contains("-O"));
        settings.OptimizedKernels = !enabled;
        Assert.Equal(SessionOutcome.Stopped, (await session.RunAsync(target, "fixture", [], state, default)).Outcome);
        var args = File.ReadAllLines(Path.Combine(t.Path, "run.args"));
        Assert.Contains("--restore-position", args);
        Assert.Equal(enabled, args.Contains("-O"));

        // An actual pre-field JSON file must keep the old pure-kernel resume behavior.
        string path = SessionState.PathFor(settings, state.Key);
        var json = JsonNode.Parse(File.ReadAllText(path))!;
        json.AsObject().Remove("UseOptimizedKernel");
        File.WriteAllText(path, json.ToJsonString());
        state = SessionState.Load(settings, target)!;
        Assert.Null(state.UseOptimizedKernel);
        settings.OptimizedKernels = true;
        Assert.Equal(SessionOutcome.Stopped, (await session.RunAsync(target, "fixture", [], state, default)).Outcome);
        Assert.DoesNotContain("-O", File.ReadAllLines(Path.Combine(t.Path, "run.args")));
    }

    [Fact]
    public async Task LookupQueriesSelectedMaskKernelAndCachesPerVersion()
    {
        if (OperatingSystem.IsWindows()) return;
        using var t = new TempDir();
        var tool = FakeTool(t.Path);
        Assert.Equal(20, (await tool.ModeInfoAsync(12500, 3))!.OptimizedPasswordLenMax);
        File.WriteAllText(Path.Combine(t.Path, "optimized.json"), Optimized.Replace(":20", ":18"));
        Assert.Equal(20, (await tool.ModeInfoAsync(12500, 3))!.OptimizedPasswordLenMax);
        File.WriteAllText(Path.Combine(t.Path, "version"), "v8.0.1");
        Assert.Equal(18, (await tool.ModeInfoAsync(12500, 3))!.OptimizedPasswordLenMax);
        File.WriteAllText(Path.Combine(t.Path, "version"), "v8.0.2");
        File.WriteAllText(Path.Combine(t.Path, "fail-info"), "");
        Assert.Null(await tool.ModeInfoAsync(12500, 3));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task BenchmarkUsesTheSameDecisionWithoutHashcat8ForcingOptimized(bool enabled)
    {
        if (OperatingSystem.IsWindows()) return;
        using var t = new TempDir();
        var tool = FakeTool(t.Path);
        await tool.BenchmarkAsync(12500, [], default, enabled);
        var args = File.ReadAllLines(Path.Combine(t.Path, "run.args"));
        Assert.Contains("-B", args);
        Assert.Equal(enabled, args.Contains("-O"));
    }

    [Fact]
    public void ExtraArgumentsCannotOverrideTheSavedKernelChoice()
    {
        using var t = new TempDir();
        string exe = Path.Combine(t.Path, "hashcat");
        File.WriteAllText(exe, "");
        var runner = new HashcatRunner(HashcatTool.Locate(exe, t.Path, t.Path)!) { HashcatMajorVersion = 8 };
        var args = runner.BuildArguments(new RunRequest
        {
            Mode = 12500, HashFile = "fixture.hash", SessionName = "test", SessionDir = t.Path, Attack = Mask(21), Restore = true,
            Settings = new Settings { ExtraArguments = "-O --optimized-kernel-enable --force" },
        });
        Assert.DoesNotContain("-O", args);
        Assert.DoesNotContain("--optimized-kernel-enable", args);
        Assert.Contains("--force", args);
    }

    private static HashcatTool FakeTool(string dir, int mode = 12500)
    {
        File.WriteAllText(Path.Combine(dir, "pure.json"), Pure.Replace("12500", mode.ToString()));
        File.WriteAllText(Path.Combine(dir, "optimized.json"), Optimized.Replace("12500", mode.ToString()));
        File.WriteAllText(Path.Combine(dir, "version"), "v8.0.0");
        string exe = Path.Combine(dir, "hashcat");
        File.WriteAllText(exe, """
            #!/bin/sh
            if [ "$1" = "--version" ]; then cat version; exit; fi
            case " $* " in
              *" --hash-info "*)
                test -f fail-info && exit 1
                case " $* " in
                  *" -O "*)
                    case " $* " in *" --hash-info --hash-info "*" -a 3 "*) cat optimized.json;; *) exit 1;; esac;;
                  *) cat pure.json;;
                esac
                exit;;
            esac
            printf '%s\n' "$@" > run.args
            for state in *.session.json; do test -f "$state" && cp "$state" state-at-start.json; done
            while [ "$#" -gt 0 ]; do
              if [ "$1" = "--restore-file-path" ]; then shift; touch "$1"; fi
              shift
            done
            exit 2
            """);
        if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(exe, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        return HashcatTool.Locate(exe, dir, dir)!;
    }

    private sealed class TempDir : IDisposable
    {
        public string Path { get; } = Directory.CreateTempSubdirectory("rk-optimized").FullName;
        public void Dispose() => Directory.Delete(Path, true);
    }
}
