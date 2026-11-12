namespace RecoverKit.Core.Hashcat;

/// <summary>What the attack runner should do with hashcat after a guard decision.</summary>
public enum GuardAction { None, Pause, Resume }

/// <summary>Why the attack is paused (a thermal pause outranks a load-limit rest).</summary>
public enum PauseReason { None, Thermal, LoadLimit }

/// <summary>
/// Pure decision logic of the GPU temperature guard and the GPU load limit, free of processes and
/// clocks so it can be unit tested: the caller feeds temperatures and the current time and carries
/// out the returned action (pause or resume hashcat).
/// </summary>
/// <remarks>
/// Temperature guard: pause when the hottest GPU reaches <see cref="Limit"/>, resume when it is at or
/// below <see cref="ResumeBelow"/> (limit minus hysteresis). Readings below zero mean "unknown" and
/// never change the state. When no reading arrives while paused (no temperature source works while
/// hashcat is stopped), the guard resumes after <see cref="BlindCooldown"/> so the next reading can
/// decide again, instead of staying paused forever.
/// Load limit: with <see cref="DutyPercent"/> below 100 the GPU works that share of every
/// <see cref="DutyPeriod"/> and rests for the rest of it.
/// </remarks>
public sealed class ThermalGuard
{
    public const int MinLimit = 60, MaxLimit = 100, MinHysteresis = 3, MaxHysteresis = 30;

    public bool TemperatureGuard { get; }
    public int Limit { get; }
    public int Hysteresis { get; }
    public int ResumeBelow => Limit - Hysteresis;
    public int DutyPercent { get; }
    public TimeSpan DutyPeriod { get; }
    public TimeSpan BlindCooldown { get; init; } = TimeSpan.FromSeconds(90);

    /// <summary>
    /// One work + rest cycle of the load limit. Long, because the GPU finishes the work already
    /// queued (measured: about 5 s on an M1 Pro) before it idles after a pause.
    /// </summary>
    public static readonly TimeSpan DefaultDutyPeriod = TimeSpan.FromSeconds(60);

    public PauseReason Reason { get; private set; }
    public bool Paused => Reason != PauseReason.None;
    /// <summary>Hottest GPU temperature last seen, -1 when none is known.</summary>
    public int Temperature { get; private set; } = -1;
    /// <summary>Total time spent paused, so speed and ETA can leave it out.</summary>
    public TimeSpan PausedTotal { get; private set; }

    private DateTime _pausedAt;
    private DateTime _lastReading = DateTime.MinValue;
    private DateTime _phaseStart = DateTime.MinValue;

    public ThermalGuard(bool temperatureGuard, int limit, int hysteresis, int dutyPercent = 100, TimeSpan? dutyPeriod = null)
    {
        TemperatureGuard = temperatureGuard;
        Limit = Math.Clamp(limit, MinLimit, MaxLimit);
        Hysteresis = Math.Clamp(hysteresis, MinHysteresis, MaxHysteresis);
        DutyPercent = Math.Clamp(dutyPercent, 10, 100);
        DutyPeriod = dutyPeriod ?? DefaultDutyPeriod;
    }

    public static ThermalGuard? FromSettings(Settings s, TimeSpan? dutyPeriod = null)
        => s.GpuTempGuard || s.GpuDutyPercent < 100
            ? new ThermalGuard(s.GpuTempGuard, s.GpuTempLimit, s.GpuTempHysteresis, s.GpuDutyPercent, dutyPeriod)
            : null;

    /// <summary>Whether anything is limited at all.</summary>
    public bool Active => TemperatureGuard || DutyPercent < 100;

    /// <summary>hashcat's own emergency stop (--hwmon-temp-abort) a bit above the guard, so a stuck guard cannot overheat the GPU.</summary>
    public static int AbortTemperature(int limit) => Math.Min(100, Math.Clamp(limit, MinLimit, MaxLimit) + 10);

    /// <summary>Hottest temperature among GPU devices that report one, or -1.</summary>
    public static int Hottest(IEnumerable<DeviceSpeed> devices)
        => devices.Where(d => d.Temperature >= 0 && !d.Type.Contains("CPU", StringComparison.OrdinalIgnoreCase))
                  .Select(d => d.Temperature).DefaultIfEmpty(-1).Max();

    /// <summary>Feed a temperature reading (or -1 for none) at time <paramref name="now"/>.</summary>
    public GuardAction Observe(int temperature, DateTime now)
    {
        if (temperature >= 0)
        {
            Temperature = temperature;
            _lastReading = now;
        }
        return Tick(now, temperature >= 0);
    }

    /// <summary>Time passes without a new reading.</summary>
    public GuardAction Tick(DateTime now) => Tick(now, false);

    private GuardAction Tick(DateTime now, bool fresh)
    {
        if (_phaseStart == DateTime.MinValue) _phaseStart = now;

        if (TemperatureGuard)
        {
            if (Reason == PauseReason.Thermal)
            {
                bool cooled = fresh && Temperature <= ResumeBelow;
                // No reading for a while (the temperature source went quiet while paused): try again.
                bool blind = now - (_lastReading > _pausedAt ? _lastReading : _pausedAt) >= BlindCooldown;
                if (!cooled && !blind) return GuardAction.None;
                return ResumeFrom(now);
            }
            if (fresh && Temperature >= Limit)
            {
                if (Reason == PauseReason.LoadLimit) { Reason = PauseReason.Thermal; return GuardAction.None; }
                return PauseFor(PauseReason.Thermal, now);
            }
        }

        if (DutyPercent < 100)
        {
            var work = TimeSpan.FromTicks(DutyPeriod.Ticks * DutyPercent / 100);
            var rest = DutyPeriod - work;
            if (Reason == PauseReason.None && now - _phaseStart >= work) return PauseFor(PauseReason.LoadLimit, now);
            if (Reason == PauseReason.LoadLimit && now - _phaseStart >= rest) return ResumeFrom(now);
        }
        return GuardAction.None;
    }

    private GuardAction PauseFor(PauseReason reason, DateTime now)
    {
        Reason = reason;
        _pausedAt = now;
        _phaseStart = now;
        return GuardAction.Pause;
    }

    private GuardAction ResumeFrom(DateTime now)
    {
        PausedTotal += now - _pausedAt;
        Reason = PauseReason.None;
        _phaseStart = now;
        return GuardAction.Resume;
    }
}
