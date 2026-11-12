using System.Diagnostics;
using System.Runtime.InteropServices;
using Avalonia.Input;
using RecoverKit.Core;

namespace RecoverKit.App.Ui;

/// <summary>Operating-system specifics: shortcuts, opening files and folders, sleep prevention, CPU name.</summary>
internal static partial class Platform
{
    public static bool IsMac => OperatingSystem.IsMacOS();

    /// <summary>Cmd on macOS, Ctrl elsewhere.</summary>
    public static KeyModifiers Cmd => IsMac ? KeyModifiers.Meta : KeyModifiers.Control;

    /// <summary>"Cmd+O" / "Ctrl+O" for help texts.</summary>
    public static string Shortcut(string key) => (IsMac ? "Cmd+" : "Ctrl+") + key;

    /// <summary>"x64" / "arm64".</summary>
    public static string Arch => RuntimeInformation.ProcessArchitecture switch
    {
        Architecture.X64 => "x64",
        Architecture.Arm64 => "arm64",
        var a => a.ToString().ToLowerInvariant(),
    };

    /// <summary>Opens a document, folder or https link with the system's default handler.</summary>
    public static void Shell(string target) => Process.Start(new ProcessStartInfo(target) { UseShellExecute = true })?.Dispose();

    /// <summary>Shows a file selected in Explorer / Finder, or opens its folder elsewhere.</summary>
    public static void Reveal(string file)
    {
        if (OperatingSystem.IsWindows()) Process.Start(new ProcessStartInfo("explorer.exe") { ArgumentList = { "/select," + file } })?.Dispose();
        else if (IsMac) Process.Start(new ProcessStartInfo("open") { ArgumentList = { "-R", file } })?.Dispose();
        else Shell(Path.GetDirectoryName(file) ?? ".");
    }

    // ------------------------------------------------------------------ keep awake

    private static Process? _caffeinate;

    /// <summary>Keeps the system and display awake while an attack runs.</summary>
    public static void KeepAwake(bool on)
    {
        try
        {
            if (OperatingSystem.IsWindows())
            {
                const uint Continuous = 0x80000000, System = 0x00000001, Display = 0x00000002;
                SetThreadExecutionState(on ? Continuous | System | Display : Continuous);
            }
            else if (IsMac)
            {
                if (on && _caffeinate is null)
                    _caffeinate = Process.Start(new ProcessStartInfo("/usr/bin/caffeinate")
                    {
                        ArgumentList = { "-di", "-w", Environment.ProcessId.ToString() }, UseShellExecute = false, CreateNoWindow = true,
                    });
                else if (!on && _caffeinate is { } p)
                {
                    _caffeinate = null;
                    try { if (!p.HasExited) p.Kill(); } catch (InvalidOperationException) { }
                    p.Dispose();
                }
            }
        }
        catch (Exception ex) when (ex is EntryPointNotFoundException or DllNotFoundException or System.ComponentModel.Win32Exception)
        {
            DebugLog.Warn("Keep awake: " + ex.Message);
        }
    }

    [LibraryImport("kernel32.dll")]
    private static partial uint SetThreadExecutionState(uint esFlags);

    // ------------------------------------------------------------------ CPU

    public static string CpuName()
    {
        try
        {
            if (OperatingSystem.IsWindows())
            {
                using var k = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"HARDWARE\DESCRIPTION\System\CentralProcessor\0");
                return (k?.GetValue("ProcessorNameString") as string)?.Trim() ?? "unknown";
            }
            if (IsMac)
            {
                using var p = Process.Start(new ProcessStartInfo("/usr/sbin/sysctl") { ArgumentList = { "-n", "machdep.cpu.brand_string" }, RedirectStandardOutput = true, UseShellExecute = false });
                var s = p?.StandardOutput.ReadToEnd().Trim();
                p?.WaitForExit(2000);
                return string.IsNullOrEmpty(s) ? "unknown" : s;
            }
            var model = File.ReadLines("/proc/cpuinfo").FirstOrDefault(l => l.StartsWith("model name", StringComparison.Ordinal));
            return model?.Split(':', 2)[1].Trim() ?? "unknown";
        }
        catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException or IOException or System.ComponentModel.Win32Exception)
        {
            return "unknown";
        }
    }

    /// <summary>Vector and crypto instruction sets the .NET runtime reports for this CPU.</summary>
    public static string CpuFeatures()
    {
        var f = new List<string>();
        if (System.Runtime.Intrinsics.X86.Sse2.IsSupported) f.Add("SSE2");
        if (System.Runtime.Intrinsics.X86.Avx.IsSupported) f.Add("AVX");
        if (System.Runtime.Intrinsics.X86.Avx2.IsSupported) f.Add("AVX2");
        if (System.Runtime.Intrinsics.X86.Avx512F.IsSupported) f.Add("AVX-512");
        if (System.Runtime.Intrinsics.X86.Aes.IsSupported) f.Add("AES-NI");
        if (System.Runtime.Intrinsics.Arm.AdvSimd.IsSupported) f.Add("NEON");
        if (System.Runtime.Intrinsics.Arm.Aes.IsSupported) f.Add("AES");
        if (System.Runtime.Intrinsics.Arm.Sha1.IsSupported) f.Add("SHA1");
        if (System.Runtime.Intrinsics.Arm.Sha256.IsSupported) f.Add("SHA256");
        return string.Join(' ', f);
    }
}
