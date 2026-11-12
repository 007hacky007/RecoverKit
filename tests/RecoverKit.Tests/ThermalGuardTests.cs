using System.Diagnostics;
using RecoverKit.Core;
using RecoverKit.Core.Attacks;
using RecoverKit.Core.Hashcat;
using Xunit;

namespace RecoverKit.Tests;

public class ThermalGuardTests
{
    private static readonly DateTime T0 = new(2026, 1, 1, 12, 0, 0, DateTimeKind.Utc);
    private static DateTime At(double seconds) => T0.AddSeconds(seconds);

    [Fact]
    public void PausesAtTheLimitAndResumesOnlyBelowTheHysteresis()
    {
        var g = new ThermalGuard(true, 85, 10);
        Assert.Equal(GuardAction.None, g.Observe(84, At(0)));
        Assert.Equal(GuardAction.Pause, g.Observe(85, At(2)));
        Assert.Equal(PauseReason.Thermal, g.Reason);
        Assert.Equal(GuardAction.None, g.Observe(86, At(4)));
        Assert.Equal(GuardAction.None, g.Observe(80, At(6)));
        Assert.Equal(GuardAction.None, g.Observe(76, At(8)));     // still above 75
        Assert.Equal(GuardAction.Resume, g.Observe(75, At(10)));
        Assert.False(g.Paused);
        Assert.Equal(GuardAction.None, g.Observe(84, At(12)));    // no flapping just under the limit
        Assert.Equal(TimeSpan.FromSeconds(8), g.PausedTotal);
    }

    [Fact]
    public void MissingTemperaturesNeverPauseOrResume()
    {
        var g = new ThermalGuard(true, 80, 5) { BlindCooldown = TimeSpan.FromSeconds(90) };
        Assert.Equal(GuardAction.None, g.Observe(-1, At(0)));
        Assert.Equal(GuardAction.None, g.Tick(At(500)));
        Assert.Equal(GuardAction.Pause, g.Observe(81, At(501)));
        Assert.Equal(GuardAction.None, g.Observe(-1, At(530)));
        Assert.Equal(81, g.Temperature);                           // unknown readings do not overwrite the last one
    }

    [Fact]
    public void ResumesBlindAfterTheCooldownWhenNoReadingArrivesWhilePaused()
    {
        var g = new ThermalGuard(true, 80, 5) { BlindCooldown = TimeSpan.FromSeconds(90) };
        g.Observe(82, At(0));
        Assert.Equal(GuardAction.None, g.Tick(At(89)));
        Assert.Equal(GuardAction.Resume, g.Tick(At(90)));
        Assert.Equal(GuardAction.Pause, g.Observe(83, At(92)));     // still hot: pause again
    }

    [Fact]
    public void ReadingsWhilePausedPostponeTheBlindResume()
    {
        var g = new ThermalGuard(true, 80, 5) { BlindCooldown = TimeSpan.FromSeconds(90) };
        g.Observe(82, At(0));
        g.Observe(79, At(80));
        Assert.Equal(GuardAction.None, g.Tick(At(100)));
        Assert.Equal(GuardAction.Resume, g.Tick(At(170)));
    }

    [Fact]
    public void HottestGpuCountsAndCpusAndUnknownsAreIgnored()
    {
        var devices = new List<DeviceSpeed>
        {
            new() { Id = 1, Type = "GPU", Temperature = 70 },
            new() { Id = 2, Type = "GPU", Temperature = 88 },
            new() { Id = 3, Type = "CPU", Temperature = 95 },
            new() { Id = 4, Type = "GPU", Temperature = -1 },
        };
        Assert.Equal(88, ThermalGuard.Hottest(devices));
        Assert.Equal(-1, ThermalGuard.Hottest([new DeviceSpeed { Type = "GPU" }]));
        var g = new ThermalGuard(true, 85, 10);
        Assert.Equal(GuardAction.Pause, g.Observe(ThermalGuard.Hottest(devices), At(0)));
    }

    [Fact]
    public void DutyCycleAlternatesWorkAndRest()
    {
        var g = new ThermalGuard(false, 85, 10, dutyPercent: 25, dutyPeriod: TimeSpan.FromSeconds(20));
        Assert.Equal(GuardAction.None, g.Tick(At(0)));
        Assert.Equal(GuardAction.None, g.Tick(At(4)));
        Assert.Equal(GuardAction.Pause, g.Tick(At(5)));
        Assert.Equal(PauseReason.LoadLimit, g.Reason);
        Assert.Equal(GuardAction.None, g.Tick(At(19)));
        Assert.Equal(GuardAction.Resume, g.Tick(At(20)));
        Assert.Equal(GuardAction.Pause, g.Tick(At(25)));
        Assert.Equal(GuardAction.None, g.Observe(99, At(26)));      // temperature guard off: readings do nothing
    }

    [Fact]
    public void HeatDuringALoadRestTurnsItIntoAThermalPause()
    {
        var g = new ThermalGuard(true, 80, 10, dutyPercent: 50, dutyPeriod: TimeSpan.FromSeconds(20));
        g.Tick(At(0));
        Assert.Equal(GuardAction.Pause, g.Tick(At(10)));
        Assert.Equal(GuardAction.None, g.Observe(82, At(11)));
        Assert.Equal(PauseReason.Thermal, g.Reason);
        Assert.Equal(GuardAction.None, g.Tick(At(25)));            // the rest is over, but it is still hot
        Assert.Equal(GuardAction.Resume, g.Observe(70, At(30)));
    }

    [Fact]
    public void LimitsAreClamped()
    {
        var g = new ThermalGuard(true, 30, 100);
        Assert.Equal(ThermalGuard.MinLimit, g.Limit);
        Assert.Equal(ThermalGuard.MaxHysteresis, g.Hysteresis);
        Assert.Equal(95, ThermalGuard.AbortTemperature(85));
        Assert.Equal(100, ThermalGuard.AbortTemperature(98));
    }

    [Fact]
    public void GuardIsOffByDefaultAndForCpuOnlyRuns()
    {
        Assert.Null(HashcatRunner.GuardFor(new Settings(), null));
        var on = new Settings { GpuTempGuard = true };
        Assert.NotNull(HashcatRunner.GuardFor(on, null));
        Assert.Null(HashcatRunner.GuardFor(new Settings { GpuTempGuard = true, Strategy = DeviceStrategy.CpuOnly }, null));
        Assert.Null(HashcatRunner.GuardFor(on, [new BackendDevice { Id = 1, Type = "CPU" }]));
        Assert.NotNull(HashcatRunner.GuardFor(new Settings { GpuDutyPercent = 50 }, null));
    }

    private static RunRequest Request(Settings s, ThermalGuard? guard) => new()
    {
        Mode = 0, HashFile = "h", SessionName = "s", SessionDir = "/tmp", Settings = s, Guard = guard,
        Attack = new PreparedAttack { Description = "t" },
    };

    [Fact]
    public void ArgumentsAddHashcatsTemperatureAbortOnlyWithTheGuard()
    {
        string dir = Directory.CreateTempSubdirectory("rk-thermal").FullName;
        string exe = Path.Combine(dir, OperatingSystem.IsWindows() ? "hashcat.exe" : "hashcat");
        File.WriteAllText(exe, "");
        var runner = new HashcatRunner(HashcatTool.Locate(exe, dir, dir)!);
        var off = runner.BuildArguments(Request(new Settings(), null));
        Assert.DoesNotContain("--hwmon-temp-abort", off);
        Assert.Equal("3", off[off.IndexOf("-w") + 1]);

        var s = new Settings { GpuTempGuard = true, GpuTempLimit = 80, Workload = 1 };
        var on = runner.BuildArguments(Request(s, HashcatRunner.GuardFor(s, null)));
        Assert.Equal("90", on[on.IndexOf("--hwmon-temp-abort") + 1]);
        Assert.Equal("1", on[on.IndexOf("-w") + 1]);

        var own = new Settings { GpuTempGuard = true, ExtraArguments = "--hwmon-disable" };
        Assert.DoesNotContain("--hwmon-temp-abort", runner.BuildArguments(Request(own, HashcatRunner.GuardFor(own, null))));

        var load = new Settings { GpuDutyPercent = 50 };
        Assert.DoesNotContain("--hwmon-temp-abort", runner.BuildArguments(Request(load, HashcatRunner.GuardFor(load, null))));
    }

    [Fact]
    public void NvidiaSmiOutputParsesToTheHottestGpu()
    {
        Assert.Equal(71, NvidiaSmi.ParseHottest("54\n71\n[N/A]\n"));
        Assert.Equal(-1, NvidiaSmi.ParseHottest("[N/A]\r\n"));
        Assert.Equal(-1, NvidiaSmi.ParseHottest(""));
        var smi = new NvidiaSmi("nvidia-smi", (_, args) => (0, args[0].Contains("temperature") ? "48\n63\n" : ""));
        Assert.Equal(63, new NvidiaTemperature(smi).ReadHottest());
        Assert.Equal(-1, new NvidiaTemperature(new NvidiaSmi("x", (_, _) => (9, "63"))).ReadHottest());
    }

    [Fact]
    public void AppleSensorNamesSelectDieAndGpuSensors()
    {
        Assert.True(AppleSiliconSensors.IsGpuOrDie("PMU tdie4"));
        Assert.True(AppleSiliconSensors.IsGpuOrDie("PMU TP2g"));
        Assert.False(AppleSiliconSensors.IsGpuOrDie("PMU TP1s"));
        Assert.False(AppleSiliconSensors.IsGpuOrDie("gas gauge battery"));
        Assert.False(AppleSiliconSensors.IsGpuOrDie("NAND CH0 temp"));
    }

    [Fact]
    public void SuspendStopsAProcessAndResumeLetsItContinue()
    {
        if (OperatingSystem.IsWindows()) return;
        var psi = new ProcessStartInfo("/bin/sh", ["-c", "while true; do echo x; sleep 0.05; done"]) { RedirectStandardOutput = true, UseShellExecute = false };
        using var p = Process.Start(psi)!;
        int lines = 0;
        p.OutputDataReceived += (_, e) => { if (e.Data is not null) Interlocked.Increment(ref lines); };
        p.BeginOutputReadLine();
        try
        {
            Thread.Sleep(400);
            Assert.True(ProcessSuspend.Suspend(p));
            Thread.Sleep(300);
            int frozen = Volatile.Read(ref lines);
            Thread.Sleep(600);
            Assert.Equal(frozen, Volatile.Read(ref lines));
            Assert.True(ProcessSuspend.Resume(p));
            Thread.Sleep(600);
            Assert.True(Volatile.Read(ref lines) > frozen);
        }
        finally { p.Kill(true); }
    }

    [Fact]
    public void SettingsDefaultToOff()
    {
        var s = new Settings();
        Assert.False(s.GpuTempGuard);
        Assert.Equal(85, s.GpuTempLimit);
        Assert.Equal(10, s.GpuTempHysteresis);
        Assert.Equal(100, s.GpuDutyPercent);
        Assert.Null(ThermalGuard.FromSettings(s));
    }
}
