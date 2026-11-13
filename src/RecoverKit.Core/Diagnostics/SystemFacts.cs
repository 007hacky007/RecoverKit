using System.Diagnostics;
using System.Runtime.InteropServices;

namespace RecoverKit.Core.Diagnostics;

/// <summary>Hardware facts that contain no host name, serial number or user identifier.</summary>
public static class SystemFacts
{
    public static string CpuName()
    {
        if (OperatingSystem.IsMacOS()) return Read("/usr/sbin/sysctl", "-n", "machdep.cpu.brand_string").Trim() is { Length: > 0 } name ? name : "Apple CPU";
        if (OperatingSystem.IsWindows())
            return Microsoft.Win32.Registry.GetValue(@"HKEY_LOCAL_MACHINE\HARDWARE\DESCRIPTION\System\CentralProcessor\0", "ProcessorNameString", null)?.ToString()?.Trim() ?? "CPU";
        try { return File.ReadLines("/proc/cpuinfo").FirstOrDefault(l => l.StartsWith("model name", StringComparison.Ordinal))?.Split(':', 2)[1].Trim() ?? "CPU"; }
        catch (IOException) { return "CPU"; }
    }

    public static int PhysicalCores()
    {
        if (OperatingSystem.IsMacOS() && int.TryParse(Read("/usr/sbin/sysctl", "-n", "hw.physicalcpu").Trim(), out var mac))
            return Math.Clamp(mac, 1, Environment.ProcessorCount);
        if (OperatingSystem.IsWindows())
        {
            uint size = 0;
            GetLogicalProcessorInformationEx(0, IntPtr.Zero, ref size);
            if (size > 0 && size < 1_000_000)
            {
                var buffer = Marshal.AllocHGlobal((int)size);
                try
                {
                    if (GetLogicalProcessorInformationEx(0, buffer, ref size))
                    {
                        int count = 0;
                        for (int offset = 0; offset + 8 <= size;)
                        {
                            int entrySize = Marshal.ReadInt32(buffer, offset + 4);
                            if (entrySize < 8 || offset + entrySize > size) break;
                            if (Marshal.ReadInt32(buffer, offset) == 0) count++;
                            offset += entrySize;
                        }
                        if (count > 0) return Math.Clamp(count, 1, Environment.ProcessorCount);
                    }
                }
                finally { Marshal.FreeHGlobal(buffer); }
            }
        }
        if (OperatingSystem.IsLinux())
        {
            try
            {
                var pairs = File.ReadAllText("/proc/cpuinfo").Split("\n\n", StringSplitOptions.RemoveEmptyEntries)
                    .Select(block => block.Split('\n').Where(l => l.StartsWith("physical id", StringComparison.Ordinal) || l.StartsWith("core id", StringComparison.Ordinal)).ToArray())
                    .Where(p => p.Length == 2).Select(p => string.Join('|', p)).Distinct().Count();
                if (pairs > 0) return Math.Clamp(pairs, 1, Environment.ProcessorCount);
            }
            catch (IOException) { }
        }
        return Environment.ProcessorCount;
    }

    public static long RamBytes()
    {
        if (OperatingSystem.IsMacOS() && long.TryParse(Read("/usr/sbin/sysctl", "-n", "hw.memsize").Trim(), out var mac)) return mac;
        if (OperatingSystem.IsWindows())
        {
            var status = new MemoryStatus { Length = (uint)Marshal.SizeOf<MemoryStatus>() };
            if (GlobalMemoryStatusEx(ref status)) return (long)status.TotalPhysical;
        }
        if (OperatingSystem.IsLinux())
        {
            try
            {
                var value = File.ReadLines("/proc/meminfo").First(l => l.StartsWith("MemTotal:", StringComparison.Ordinal)).Split(' ', StringSplitOptions.RemoveEmptyEntries)[1];
                if (long.TryParse(value, out var kb)) return kb * 1024;
            }
            catch (IOException) { }
        }
        return GC.GetGCMemoryInfo().TotalAvailableMemoryBytes;
    }

    private static string Read(string file, params string[] args)
    {
        try
        {
            var info = new ProcessStartInfo(file) { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false, CreateNoWindow = true };
            foreach (string arg in args) info.ArgumentList.Add(arg);
            using var process = Process.Start(info);
            if (process is null) return "";
            var output = process.StandardOutput.ReadToEndAsync();
            if (!process.WaitForExit(2000)) { process.Kill(entireProcessTree: true); return ""; }
            return output.GetAwaiter().GetResult();
        }
        catch (Exception ex) when (ex is IOException or InvalidOperationException or System.ComponentModel.Win32Exception) { return ""; }
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetLogicalProcessorInformationEx(int relationship, IntPtr buffer, ref uint length);

    [StructLayout(LayoutKind.Sequential)]
    private struct MemoryStatus
    {
        public uint Length, Load;
        public ulong TotalPhysical, AvailablePhysical, TotalPageFile, AvailablePageFile, TotalVirtual, AvailableVirtual, AvailableExtendedVirtual;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GlobalMemoryStatusEx(ref MemoryStatus status);
}
