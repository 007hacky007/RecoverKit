using System.Text;
using RecoverKit.Core;
using RecoverKit.Core.Attacks;
using RecoverKit.Core.Hashcat;
using Xunit;

namespace RecoverKit.Tests;

public sealed class HashcatFailureTests : IDisposable
{
    [Theory]
    [InlineData("Syntax error in mask: ?z")]
    [InlineData("error: syntax error", "clBuildProgram(): CL_BUILD_PROGRAM_FAILURE")]
    public void SyntaxErrorsAreNotReportedAsUnreadableHashes(params string[] lines)
    {
        string error = HashcatOutput.FailureMessage(lines, 255);
        Assert.DoesNotContain("read the hash", error);
        if (lines.Length > 1) Assert.Contains("compile the attack kernel", error);
        Assert.False(HashcatOutput.IsTransientFailure(string.Join('\n', lines)));
    }

    private readonly string _dir = Path.Combine(Path.GetTempPath(), "rk-failure-" + Guid.NewGuid().ToString("N"));
    private const string MetalFailure = "hc_mtl4_commit_and_wait(): Metal 4 command buffer failed, The operation couldn't be completed. (MTL4CommandQueueErrorDomain error 1.).";
    private const string Startup = "Failed to initialize the AMD main driver HIP runtime library. Please install the AMD HIP SDK.\nFailed to initialize AMD HIP RTC library. Please install the AMD HIP SDK.\nDevice #1: CUDA SDK Toolkit not installed or incorrectly installed... Falling back to OpenCL runtime.";

    public HashcatFailureTests() => Directory.CreateDirectory(_dir);
    public void Dispose() { try { Directory.Delete(_dir, true); } catch (IOException) { } }

    private RunRequest Request(Func<byte[], bool>? confirm = null) => new()
    {
        Mode = 0, HashFile = Path.Combine(_dir, "h.hash"), SessionDir = _dir, SessionName = "failure",
        Attack = new PreparedAttack { Description = "mask", Args = { "-a", "3", "?l?l?l?l" } },
        Settings = new Settings { DontUsePasswordCache = true }, ConfirmPassword = confirm,
    };

    private HashcatRunner? Runner(string body)
    {
        if (OperatingSystem.IsWindows()) return null;
        string script = Path.Combine(_dir, "hashcat");
        File.WriteAllText(script, "#!/usr/bin/env python3\n" + "import sys, os, json, struct\n" +
            "args = sys.argv[1:]\n" +
            "state = os.path.join(os.path.dirname(__file__), 'attempts.json')\n" +
            "attempts = json.load(open(state)) if os.path.exists(state) else []\n" +
            "attempts.append(args)\njson.dump(attempts, open(state, 'w'))\n" +
            "attempt = len(attempts)\n" +
            "restore = args[args.index('--restore-file-path') + 1]\n" +
            "out = args[args.index('-o') + 1]\n" + body + "\n");
        File.SetUnixFileMode(script, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        return new HashcatRunner(HashcatTool.Locate(script)!) { HashcatMajorVersion = 8 };
    }

    private string[][] Attempts() => System.Text.Json.JsonSerializer.Deserialize<string[][]>(File.ReadAllText(Path.Combine(_dir, "attempts.json")))!;
    private static string Py(string value) => System.Text.Json.JsonSerializer.Serialize(value);

    [Fact]
    public async Task StartupWarningsDoNotReplaceTheActualFatalReason()
    {
        if (Runner($"print('No hashes loaded.')\nprint({Py(Startup)}, file=sys.stderr)\nsys.exit(255)") is not { } runner) return;
        var output = new List<string>();
        runner.OutputLine += line => { lock (output) output.Add(line); };
        var result = await runner.RunAsync(Request(), CancellationToken.None);
        Assert.Equal(RunOutcome.Error, result.Outcome);
        Assert.Contains("hash", result.Error!, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("HIP", result.Error!);
        Assert.DoesNotContain("CUDA SDK", result.Error!);
        Assert.Contains(output, l => l.Contains("HIP RTC"));
        Assert.Single(Attempts());
    }

    [Theory]
    [InlineData(MetalFailure)]
    [InlineData("clEnqueueNDRangeKernel(): CL_OUT_OF_RESOURCES")]
    [InlineData("cuLaunchKernel(): CUDA_ERROR_LAUNCH_FAILED")]
    [InlineData("hipLaunchKernel(): hipErrorLaunchFailure")]
    [InlineData("hipCtxSynchronize(): hipErrorUnknown")]
    public async Task TransientBackendFailureRestartsAndExhaustsNormally(string error)
    {
        if (Runner($"if attempt == 1:\n    print({Py(error)}, file=sys.stderr)\n    sys.exit(255)\nsys.exit(1)") is not { } runner) return;
        var result = await runner.RunAsync(Request(), CancellationToken.None);
        Assert.Equal(RunOutcome.Exhausted, result.Outcome);
        Assert.Equal(2, Attempts().Length);
    }

    [Fact]
    public async Task ThreeRetriesWithoutProgressStopWithTheBackendReason()
    {
        if (Runner($"print({Py(MetalFailure)}, file=sys.stderr)\nsys.exit(255)") is not { } runner) return;
        var output = new List<string>();
        runner.OutputLine += line => { lock (output) output.Add(line); };
        var result = await runner.RunAsync(Request(), CancellationToken.None);
        Assert.Equal(RunOutcome.Error, result.Outcome);
        Assert.Equal(4, Attempts().Length);
        Assert.Equal(new[]
        {
            "The GPU stopped with an error; restarting this step because no checkpoint was saved (retry 1 of 3).",
            "The GPU stopped with an error; restarting this step because no checkpoint was saved (retry 2 of 3).",
            "The GPU stopped with an error; restarting this step because no checkpoint was saved (retry 3 of 3).",
        }, output.Where(line => line.Contains("(retry ")));
        Assert.StartsWith("The GPU", result.Error);
        Assert.Contains("Metal 4 command buffer failed", result.Error);
    }

    [Fact]
    public async Task RetryRestoresCheckpointAndRejectsFalseHitsBeforeConfirming()
    {
        if (Runner($"""
            if attempt == 1:
                with open(out, 'a') as f: f.write('wrong\n')
                checkpoint = bytearray(300)
                struct.pack_into('<Q', checkpoint, 272, 40)
                open(restore, 'wb').write(checkpoint)
                print({Py(MetalFailure)}, file=sys.stderr)
                sys.exit(255)
            if '--restore-position' not in args: sys.exit(254)
            with open(out, 'a') as f: f.write('wrong\n$HEX[7265616c]\n')
            sys.exit(255)
            """) is not { } runner) return;
        var output = new List<string>();
        runner.OutputLine += line => { lock (output) output.Add(line); };
        var result = await runner.RunAsync(Request(pw => Encoding.ASCII.GetString(pw) == "real"), CancellationToken.None);
        Assert.Equal(RunOutcome.Cracked, result.Outcome);
        Assert.Equal(["real"], result.Passwords);
        Assert.Equal(2, Attempts().Length);
        Assert.Contains("The GPU stopped with an error; resuming from the last checkpoint (retry 1 of 3).", output);
        Assert.All(Attempts(), args => Assert.Contains("--keep-guessing", args));
        Assert.Equal(1, runner.FalsePositives.Count);
    }

    [Fact]
    public async Task CancellationDuringRetryPauseDoesNotRestart()
    {
        if (Runner($"print({Py(MetalFailure)}, file=sys.stderr)\nsys.exit(255)") is not { } runner) return;
        using var stop = new CancellationTokenSource();
        runner.OutputLine += line => { if (line.Contains("(retry ", StringComparison.OrdinalIgnoreCase)) stop.Cancel(); };
        var result = await runner.RunAsync(Request(), stop.Token);
        Assert.Equal(RunOutcome.Aborted, result.Outcome);
        Assert.Single(Attempts());
    }

    [Theory]
    [InlineData("No hashes loaded.", "read the hash for this file")]
    [InlineData("* Device #1: Self-test failed.", "self-test failed")]
    [InlineData("clBuildProgram(): CL_BUILD_PROGRAM_FAILURE", "compile")]
    [InlineData("* Device #1: Not enough allocatable device memory or free host memory for mapping.", "allocate")]
    [InlineData("No devices left.", "usable compute device")]
    [InlineData("cuLaunchKernel(): CUDA_ERROR_INVALID_VALUE", "could not complete")]
    [InlineData("hipLaunchKernel(): hipErrorInvalidValue", "could not complete")]
    public async Task FatalFailuresDoNotRetry(string error, string reason)
    {
        if (Runner($"print({Py(error)}, file=sys.stderr)\nsys.exit(255)") is not { } runner) return;
        var result = await runner.RunAsync(Request(), CancellationToken.None);
        Assert.Equal(RunOutcome.Error, result.Outcome);
        Assert.Contains(reason, result.Error!, StringComparison.OrdinalIgnoreCase);
        Assert.Contains(error, result.Error!);
        Assert.Single(Attempts());
    }

    [Fact]
    public async Task StartupAdviceCannotEvictTheFatalReasonFromTheTail()
    {
        if (Runner($"print('No hashes loaded.', flush=True)\nprint({Py(Startup)} * 30, file=sys.stderr)\nsys.exit(255)") is not { } runner) return;
        var result = await runner.RunAsync(Request(), CancellationToken.None);
        Assert.Contains("No hashes loaded.", result.Error!);
        Assert.DoesNotContain("HIP", result.Error!);
    }

    [Fact]
    public async Task NvidiaOpenClFallbackGetsOneCompilerHintAcrossRetries()
    {
        string advice = Startup + "\nThe NVIDIA RTC library that hashcat compiles its kernels with comes with the CUDA Toolkit.\n" +
            "Install the Windows build of it from https://developer.nvidia.com/cuda-downloads, choosing\n" +
            "Windows and the version of it you are on. The GPU driver on its own does not carry it.\n" +
            "Running hashcat inside WSL2 reaches CUDA as well, using the Linux build of hashcat and the\n" +
            "Linux CUDA Toolkit installed inside it. No NVIDIA GPU driver is installed inside WSL2 itself.\n" +
            "For all details: https://docs.nvidia.com/cuda/wsl-user-guide/index.html";
        if (Runner($"print({Py(advice)}, file=sys.stderr)\nif attempt == 1:\n    print({Py(MetalFailure)}, file=sys.stderr)\n    sys.exit(255)\nsys.exit(1)") is not { } runner) return;
        var output = new List<string>();
        runner.OutputLine += line => { lock (output) output.Add(line); };
        var result = await runner.RunAsync(Request(), CancellationToken.None);
        Assert.Equal(RunOutcome.Exhausted, result.Outcome);
        Assert.Single(output, line => line.Contains("Tools > Download NVIDIA CUDA compiler"));
        Assert.DoesNotContain(output, line => line.Contains("WSL", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(output, line => line.Contains("CUDA SDK Toolkit"));
        Assert.DoesNotContain(output, line => line.Contains("cuda-downloads"));
        Assert.DoesNotContain(output, line => line.Contains("The NVIDIA RTC library"));
    }

    [Fact]
    public async Task SelfTestFailureTakesPriorityOverTransientAndNoDevicesMessages()
    {
        if (Runner($"print({Py(MetalFailure)}, file=sys.stderr)\nprint('* Device #1: Self-test failed.', file=sys.stderr)\nprint('No devices left.', file=sys.stderr)\nsys.exit(255)") is not { } runner) return;
        var result = await runner.RunAsync(Request(), CancellationToken.None);
        Assert.StartsWith("hashcat's kernel self-test failed.", result.Error!);
        Assert.Single(Attempts());
    }

    [Fact]
    public async Task ConfirmedPasswordWinsOverBackendFailureWithoutRetry()
    {
        if (Runner($"open(out, 'a').write('real\\n')\nprint({Py(MetalFailure)}, file=sys.stderr)\nsys.exit(255)") is not { } runner) return;
        var result = await runner.RunAsync(Request(pw => Encoding.ASCII.GetString(pw) == "real"), CancellationToken.None);
        Assert.Equal(RunOutcome.Cracked, result.Outcome);
        Assert.Equal(["real"], result.Passwords);
        Assert.Null(result.Error);
        Assert.Single(Attempts());
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(3)]
    public async Task PartialTargetNeverStartsWithoutItsReplacementKernel(int attackMode)
    {
        if (Runner("sys.exit(1)") is not { } runner) return;
        var request = Request() with { Mode = 17210, RequiresPartialZipKernel = true };
        request.Attack.Args[1] = attackMode.ToString();
        var result = await runner.RunAsync(request, CancellationToken.None);
        Assert.Equal(RunOutcome.Error, result.Outcome);
        Assert.Contains("partial", result.Error!, StringComparison.OrdinalIgnoreCase);
        Assert.False(File.Exists(Path.Combine(_dir, "attempts.json")));
    }

    [Fact]
    public async Task FreshAttackNeverResumesAStaleCheckpoint()
    {
        if (Runner($"if '--restore-position' in args: sys.exit(254)\nif attempt == 1:\n    print({Py(MetalFailure)}, file=sys.stderr)\n    sys.exit(255)\nsys.exit(1)") is not { } runner) return;
        var old = new byte[300];
        BitConverter.GetBytes(900L).CopyTo(old, 272);
        File.WriteAllBytes(HashcatRunner.RestoreFile(_dir, "failure"), old);
        var result = await runner.RunAsync(Request(), CancellationToken.None);
        Assert.Equal(RunOutcome.Exhausted, result.Outcome);
        Assert.All(Attempts(), args => Assert.DoesNotContain("--restore-position", args));
    }

    [Fact]
    public void FatalClassificationSurvivesDetailTruncation()
    {
        var output = new[] { "No hashes loaded." }.Concat(Enumerable.Repeat(MetalFailure, 15));
        string message = HashcatOutput.FailureMessage(output, 255);
        Assert.StartsWith("hashcat could not read the hash for this file", message);
        Assert.False(HashcatOutput.IsTransientFailure(message));
        Assert.Contains("No hashes loaded.", message);
    }

    [Theory]
    [InlineData("Successfully initialized the NVIDIA main driver CUDA runtime library.")]
    [InlineData("Failed to initialize NVIDIA RTC library.")]
    [InlineData("The NVIDIA RTC library that hashcat compiles its kernels with comes with the CUDA Toolkit.")]
    [InlineData("Install the Windows build of it from https://developer.nvidia.com/cuda-downloads, choosing")]
    [InlineData("Windows and the version of it you are on. The GPU driver on its own does not carry it.")]
    [InlineData("Running hashcat inside WSL2 reaches CUDA as well, using the Linux build of hashcat and the")]
    [InlineData("Linux CUDA Toolkit installed inside it. No NVIDIA GPU driver is installed inside WSL2 itself.")]
    [InlineData("For all details: https://docs.nvidia.com/cuda/wsl-user-guide/index.html")]
    [InlineData("Failed to initialize AMD HIP RTC library.")]
    [InlineData("* Device #1: Metal 4 setup failed, command queue is not available. Using Metal 3.")]
    public void OptionalStartupOutputIsInformational(string line)
    {
        Assert.True(HashcatOutput.IsStartupAdvice(line));
        Assert.DoesNotContain(line, HashcatOutput.FailureMessage([line, "No hashes loaded."], 255));
    }

    [Theory]
    [InlineData("-a 1", 1)]
    [InlineData("-a1", 1)]
    [InlineData("--attack-mode 1", 1)]
    [InlineData("--attack-mode=1", 1)]
    [InlineData("--attack-mode=3", 3)]
    [InlineData("--attack-mode=invalid", -1)]
    public void EffectiveAttackModeIncludesExtraArguments(string extra, int expected)
    {
        var request = Request();
        Assert.Equal(expected, HashcatRunner.EffectiveAttackMode(request.Attack, extra));
    }

    [Theory]
    [InlineData("-a 1")]
    [InlineData("-a1")]
    [InlineData("--attack-mode 1")]
    [InlineData("--attack-mode=1")]
    public async Task PartialGuardChecksTheEffectiveAttackMode(string extra)
    {
        if (Runner("sys.exit(1)") is not { } runner) return;
        string kernels = Directory.CreateDirectory(Path.Combine(_dir, "OpenCL")).FullName;
        foreach (var source in HashcatKernels.Sources) File.WriteAllText(Path.Combine(kernels, source.Key), source.Value);
        var request = Request() with { Mode = 17210, RequiresPartialZipKernel = true, Settings = new Settings { ExtraArguments = extra } };
        var result = await runner.RunAsync(request, CancellationToken.None);
        Assert.Equal(RunOutcome.Error, result.Outcome);
        Assert.False(File.Exists(Path.Combine(_dir, "attempts.json")));
    }

    [Fact]
    public async Task StdinRetryReplaysTheGeneratorInsteadOfResumingACheckpoint()
    {
        if (Runner($$"""
            if '--restore-position' in args: sys.exit(254)
            if sys.stdin.read() != 'candidate\n': sys.exit(253)
            if attempt == 1:
                checkpoint = bytearray(300)
                struct.pack_into('<Q', checkpoint, 272, 40)
                open(restore, 'wb').write(checkpoint)
                print({{Py(MetalFailure)}}, file=sys.stderr)
                sys.exit(255)
            sys.exit(1)
            """) is not { } runner) return;
        var request = Request() with { Attack = new PreparedAttack { Description = "generator", Args = { "-a", "0" }, Stdin = () => ["candidate"] } };
        var result = await runner.RunAsync(request, CancellationToken.None);
        Assert.Equal(RunOutcome.Exhausted, result.Outcome);
        Assert.Equal(2, Attempts().Length);
    }

    [Fact]
    public async Task ProgressResetsTheConsecutiveFailureBudget()
    {
        if (Runner($$"""
            print(json.dumps({'status': 3, 'progress': [100 if attempt >= 3 else 0, 1000]}))
            print({{Py(MetalFailure)}}, file=sys.stderr)
            sys.exit(255)
            """) is not { } runner) return;
        var result = await runner.RunAsync(Request(), CancellationToken.None);
        Assert.Equal(RunOutcome.Error, result.Outcome);
        Assert.Equal(6, Attempts().Length);
    }
}
