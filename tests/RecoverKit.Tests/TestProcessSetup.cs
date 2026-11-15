using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace RecoverKit.Tests;

internal static partial class TestProcessSetup
{
    private const uint FailCriticalErrors = 0x0001, NoGpFaultErrorBox = 0x0002, NoOpenFileErrorBox = 0x8000;

    // Tests start placeholder hashcat.exe files that are not programs. Without this, Windows can show a
    // modal "Unsupported 16-Bit Application" box from CreateProcess, which blocks the test forever.
    [ModuleInitializer]
    internal static void SuppressWindowsErrorDialogs()
    {
        if (OperatingSystem.IsWindows()) SetErrorMode(FailCriticalErrors | NoGpFaultErrorBox | NoOpenFileErrorBox);
    }

    [LibraryImport("kernel32.dll")]
    private static partial uint SetErrorMode(uint mode);
}
