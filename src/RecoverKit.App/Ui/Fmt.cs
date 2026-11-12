using System.Globalization;
using System.Numerics;
using RecoverKit.Core.Formats;

namespace RecoverKit.App.Ui;

internal static class Fmt
{
    private static readonly NumberFormatInfo Spaced = new() { NumberGroupSeparator = " ", NumberDecimalDigits = 0 };

    public static string Count(BigInteger n) => n.ToString("N0", Spaced);
    public static string Count(long n) => n.ToString("N0", Spaced);

    public static string Speed(double hps) => hps switch
    {
        <= 0 => "n/a",
        < 1e4 => $"{hps:N0} p/s",
        < 1e6 => $"{hps / 1e3:N1} k p/s",
        < 1e9 => $"{hps / 1e6:N2} M p/s",
        _ => $"{hps / 1e9:N2} G p/s",
    };

    public static string Duration(double seconds)
    {
        if (double.IsNaN(seconds) || seconds < 0) return "n/a";
        if (seconds > 1e4 * 365.25 * 86400) return "practically never";
        long s = (long)Math.Ceiling(seconds);
        if (s < 60) return $"{s}s";
        if (s < 3600) return $"{s / 60}m {s % 60}s";
        if (s < 86400) return $"{s / 3600}h {s % 3600 / 60}m";
        if (s < 365L * 86400) return $"{s / 86400}d {s % 86400 / 3600}h";
        return $"{s / (365L * 86400)}y {s % (365L * 86400) / 86400}d";
    }

    public static string Duration(BigInteger candidates, double speed)
        => speed <= 0 ? "n/a" : candidates > new BigInteger(1e30) ? "practically never" : Duration((double)candidates / speed);

    public static string SpeedClass(SpeedClass c) => c switch
    {
        Core.Formats.SpeedClass.Instant => "Instant",
        Core.Formats.SpeedClass.VeryFast => "Very fast",
        Core.Formats.SpeedClass.Fast => "Fast",
        Core.Formats.SpeedClass.Medium => "Medium",
        Core.Formats.SpeedClass.Slow => "Slow",
        _ => "Very slow",
    };
}
