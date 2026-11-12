using System.Diagnostics;

namespace RecoverKit.Core.Hashcat;

/// <summary>
/// Applies a <see cref="ThermalGuard"/> to one running hashcat process: reads temperatures (hashcat's
/// status, or the external source while hashcat is suspended or reports none), suspends and resumes
/// the process, reports pauses, and adjusts the status it passes on so pauses do not spoil the
/// average speed and ETA.
/// </summary>
internal sealed class ThermalController : IDisposable
{
    private readonly ThermalGuard _g;
    private readonly Process _p;
    private readonly ITemperatureSource? _external;
    private readonly Action<string> _log;
    private readonly Action<ThermalEvent> _thermal;
    private readonly Action<HashcatStatus> _emit;
    private readonly object _lock = new();
    private readonly CancellationTokenSource _cts = new();
    private readonly Task _loop;

    private bool _suspended, _stopping, _announced;
    private int _statusTemp = -1, _externalTemp = -1;
    private DateTime _statusAt, _usedStatusAt, _probeAt, _thermalSince, _holdUntil;
    private double _thermalPausedSeconds;
    private HashcatStatus? _last;
    private Dictionary<int, double> _running = new(), _held = new();

    public static readonly TimeSpan ProbeInterval = TimeSpan.FromSeconds(2);

    public ThermalController(ThermalGuard guard, Process p, ITemperatureSource? external,
        Action<string> log, Action<ThermalEvent> thermal, Action<HashcatStatus> emit)
    {
        _g = guard;
        _p = p;
        _external = external;
        _log = log;
        _thermal = thermal;
        _emit = emit;
        _loop = Task.Run(LoopAsync);
    }

    /// <summary>Records the temperature of a hashcat status and returns the status to pass on.</summary>
    public HashcatStatus Adjust(HashcatStatus st)
    {
        lock (_lock)
        {
            var now = DateTime.UtcNow;
            int hot = ThermalGuard.Hottest(st.Devices);
            if (hot >= 0) { _statusTemp = hot; _statusAt = now; }
            if (st.Status == 3 && !_suspended) _running = st.Devices.ToDictionary(d => d.Id, d => d.Speed);
            double duty = _g.DutyPercent / 100.0;
            bool hold = now < _holdUntil;
            var devices = st.Devices.Select(d =>
            {
                // Apple Silicon: hashcat reports no temperature, the chip sensors do.
                int? temp = d.Temperature < 0 && _externalTemp >= 0 && IsGpu(d) ? _externalTemp : null;
                double speed = d.Speed;
                // hashcat averages its speed over a window that includes the suspended time: show the
                // speed from before the pause until hashcat's own figure catches up again.
                if (hold && _held.TryGetValue(d.Id, out var before) && speed < before * 0.9) speed = before;
                else _held.Remove(d.Id);
                return d.With(speed: speed * duty, temperature: temp);
            }).ToList();
            var adjusted = st.With(devices, status: _suspended && _announced ? 4 : null,   // load-limit rests are not shown as pauses
                timeStart: st.TimeStart > 0 ? st.TimeStart + (long)ThermalPausedSeconds(now) : null);
            _last = st;   // raw, so a repeated Adjust of it is not adjusted twice
            return adjusted;
        }
    }

    /// <summary>The user stops the attack: resume first so hashcat can handle the stop and write its restore file.</summary>
    public void BeforeStop()
    {
        lock (_lock)
        {
            _stopping = true;
            if (_suspended) { ProcessSuspend.Resume(_p); _suspended = false; }
        }
    }

    private double ThermalPausedSeconds(DateTime now)
        => _thermalPausedSeconds + (_announced && _suspended ? (now - _thermalSince).TotalSeconds : 0);

    private static bool IsGpu(DeviceSpeed d) => !d.Type.Contains("CPU", StringComparison.OrdinalIgnoreCase);

    private async Task LoopAsync()
    {
        try
        {
            while (!_cts.IsCancellationRequested)
            {
                await Task.Delay(1000, _cts.Token);
                var now = DateTime.UtcNow;
                int fresh = -1;
                bool probed = false;
                lock (_lock)
                {
                    if (_stopping) return;
                    if (!_suspended && _statusAt > _usedStatusAt && _statusTemp >= 0) { fresh = _statusTemp; _usedStatusAt = _statusAt; }
                }
                // The external source covers hashcat being suspended and GPUs hashcat reports no temperature for.
                if (fresh < 0 && _external is not null && now - _probeAt >= ProbeInterval)
                {
                    _probeAt = now;
                    fresh = _external.ReadHottest();
                    probed = true;
                }
                lock (_lock)
                {
                    if (_stopping || _p.HasExited) return;
                    if (probed) _externalTemp = fresh;
                    var action = fresh >= 0 ? _g.Observe(fresh, now) : _g.Tick(now);
                    Act(action, now);
                    if (_suspended && _announced && probed && _last is { } last) _emit(Adjust(last));   // keep the paused display current
                }
            }
        }
        catch (OperationCanceledException) { }
        catch (InvalidOperationException) { }
    }

    private void Act(GuardAction action, DateTime now)
    {
        if (action == GuardAction.Pause)
        {
            if (!ProcessSuspend.Suspend(_p)) { _log("Could not pause hashcat; hashcat's own temperature abort still applies."); return; }
            _suspended = true;
            _held = new Dictionary<int, double>(_running);
        }
        if (_g.Reason == PauseReason.Thermal && !_announced)
        {
            _announced = true;
            _thermalSince = now;
            _log($"GPU at {_g.Temperature} °C: paused until it cools to {_g.ResumeBelow} °C.");
            _thermal(new ThermalEvent(ThermalState.Paused, _g.Temperature, _g.Limit, _g.ResumeBelow));
        }
        if (_announced && action == GuardAction.Pause && _last is { } last) _emit(Adjust(last));
        if (action != GuardAction.Resume) return;

        ProcessSuspend.Resume(_p);
        _suspended = false;
        _holdUntil = now.AddMinutes(3);
        if (!_announced) return;
        _thermalPausedSeconds += (now - _thermalSince).TotalSeconds;
        _announced = false;
        bool measured = _g.Temperature >= 0 && _g.Temperature <= _g.ResumeBelow;
        _log(measured
            ? $"GPU cooled to {_g.Temperature} °C: resumed."
            : $"No GPU temperature while paused: resumed after {_g.BlindCooldown.TotalSeconds:N0} s to measure again.");
        _thermal(new ThermalEvent(ThermalState.Normal, _g.Temperature, _g.Limit, _g.ResumeBelow));
    }

    public void Dispose()
    {
        _cts.Cancel();
        try { _loop.Wait(TimeSpan.FromSeconds(3)); } catch (AggregateException) { }
        lock (_lock)
        {
            _stopping = true;
            if (_suspended) { ProcessSuspend.Resume(_p); _suspended = false; }
            if (_announced)
            {
                _announced = false;
                _thermal(new ThermalEvent(ThermalState.Normal, _g.Temperature, _g.Limit, _g.ResumeBelow));
            }
        }
        _cts.Dispose();
    }
}
