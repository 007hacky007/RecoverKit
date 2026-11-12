namespace RecoverKit.Core.Hashcat;

/// <summary>What the GPU temperature guard is doing right now.</summary>
public enum ThermalState
{
    /// <summary>Running normally (or the guard is off).</summary>
    Normal,
    /// <summary>Cracking is paused until the hottest GPU cools below <see cref="ThermalEvent.ResumeBelow"/>.</summary>
    Paused,
}

/// <summary>
/// Raised by <see cref="RecoverySession.Thermal"/> when the guard pauses or resumes an attack.
/// Temperature is the hottest GPU in degrees Celsius, or -1 when hashcat does not report one.
/// </summary>
public sealed record ThermalEvent(ThermalState State, int Temperature, int Limit, int ResumeBelow);
