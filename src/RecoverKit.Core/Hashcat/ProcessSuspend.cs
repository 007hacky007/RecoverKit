using System.Diagnostics;
using System.Runtime.InteropServices;

namespace RecoverKit.Core.Hashcat;

/// <summary>
/// Suspends and resumes a whole process: SIGSTOP / SIGCONT on macOS and Linux, NtSuspendProcess /
/// NtResumeProcess on Windows (what Task Manager's "Suspend" uses). hashcat stops queueing GPU work,
/// the kernel already submitted finishes and the GPU idles within seconds; nothing is lost, the
/// attack simply continues where it was. See docs/DEVELOPERS.md for why this beats hashcat's own
/// 'p' key (it only pauses between batches, minutes apart for slow hashes) and a checkpoint restart.
/// </summary>
public static class ProcessSuspend
{
    public static bool Suspend(Process p) => Signal(p, suspend: true);
    public static bool Resume(Process p) => Signal(p, suspend: false);

    private static bool Signal(Process p, bool suspend)
    {
        try
        {
            if (p.HasExited) return false;
            if (OperatingSystem.IsWindows())
                return (suspend ? NtSuspendProcess(p.Handle) : NtResumeProcess(p.Handle)) == 0;
            return kill(p.Id, suspend ? SigStop() : SigCont()) == 0;
        }
        catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception or EntryPointNotFoundException or DllNotFoundException)
        {
            DebugLog.Warn($"{(suspend ? "Suspend" : "Resume")} failed: {ex.Message}");
            return false;
        }
    }

    // Signal numbers differ: macOS/BSD 17/19, Linux 19/18.
    private static int SigStop() => OperatingSystem.IsLinux() ? 19 : 17;
    private static int SigCont() => OperatingSystem.IsLinux() ? 18 : 19;

    [DllImport("libc", SetLastError = true)] private static extern int kill(int pid, int sig);
    [DllImport("ntdll.dll")] private static extern int NtSuspendProcess(IntPtr process);
    [DllImport("ntdll.dll")] private static extern int NtResumeProcess(IntPtr process);
}
