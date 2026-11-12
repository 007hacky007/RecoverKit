using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace RecoverKit.Core.Hashcat;

/// <summary>A way to read the GPU temperature that works while hashcat is paused or not running.</summary>
public interface ITemperatureSource
{
    /// <summary>Short description for the UI, e.g. "nvidia-smi" or "Apple chip sensors".</summary>
    string Name { get; }
    /// <summary>The hottest GPU in degrees Celsius, or -1 when it cannot be read right now.</summary>
    int ReadHottest();
}

/// <summary>
/// GPU temperature sources. hashcat reports temperatures in its status (NVML for NVIDIA, ADL or sysfs
/// for AMD, SMC on Intel Macs) but not on Apple Silicon, and not at all while it is stopped, so the
/// guard also uses an external source when one exists: nvidia-smi (NVIDIA, no admin rights needed)
/// or the Apple Silicon die sensors (IOKit HID, no admin rights needed).
/// </summary>
public static class GpuTemperature
{
    private static readonly Lazy<ITemperatureSource?> _external = new(Detect);

    /// <summary>The external source for this computer, or null when there is none.</summary>
    public static ITemperatureSource? External => _external.Value;

    /// <summary>Hottest GPU temperature hashcat reported during this run of the app, -1 if none.</summary>
    public static int LastReported { get; private set; } = -1;

    /// <summary>True once hashcat ran on a GPU and reported no temperature for it.</summary>
    public static bool HashcatReportsNone { get; private set; }

    internal static void Record(HashcatStatus s)
    {
        var gpus = s.Devices.Where(d => !d.Type.Contains("CPU", StringComparison.OrdinalIgnoreCase)).ToList();
        if (gpus.Count == 0 || s.Status != 3) return;
        int t = ThermalGuard.Hottest(gpus);
        if (t >= 0) { LastReported = t; HashcatReportsNone = false; }
        else if (LastReported < 0) HashcatReportsNone = true;
    }

    /// <summary>Best current reading: the external source, else what hashcat last reported (-1 if unknown).</summary>
    public static int Current()
    {
        int t = External?.ReadHottest() ?? -1;
        return t >= 0 ? t : LastReported;
    }

    private static ITemperatureSource? Detect()
    {
        try
        {
            if (OperatingSystem.IsMacOS() && RuntimeInformation.ProcessArchitecture == Architecture.Arm64)
            {
                var apple = new AppleSiliconSensors();
                if (apple.ReadHottest() >= 0) return apple;
            }
            if (NvidiaSmi.Locate() is { } smi)
            {
                var nv = new NvidiaTemperature(new NvidiaSmi(smi));
                if (nv.ReadHottest() >= 0) return nv;
            }
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException or InvalidOperationException or System.ComponentModel.Win32Exception or IOException)
        {
            DebugLog.Warn("GPU temperature source: " + ex.Message);
        }
        return null;
    }
}

/// <summary>Temperatures through nvidia-smi (all NVIDIA GPUs; the hottest counts).</summary>
public sealed class NvidiaTemperature(NvidiaSmi smi) : ITemperatureSource
{
    public string Name => "nvidia-smi";

    public int ReadHottest()
    {
        var (code, output) = smi.Run(["--query-gpu=temperature.gpu", "--format=csv,noheader,nounits"]);
        return code == 0 ? NvidiaSmi.ParseHottest(output) : -1;
    }
}

/// <summary>
/// Runs nvidia-smi. The process runner can be replaced for tests. Only a fixed, trusted executable
/// path is ever used (see <see cref="Locate"/>).
/// </summary>
public sealed class NvidiaSmi(string exe, Func<string, IReadOnlyList<string>, (int Code, string Output)>? runner = null)
{
    public string Exe { get; } = exe;
    private readonly Func<string, IReadOnlyList<string>, (int, string)> _run = runner ?? RunProcess;

    public (int Code, string Output) Run(IReadOnlyList<string> args) => _run(Exe, args);

    /// <summary>The trusted nvidia-smi locations of the NVIDIA driver, or null when it is not installed.</summary>
    public static string? Locate()
    {
        foreach (var p in TrustedPaths())
            if (File.Exists(p)) return p;
        return null;
    }

    public static IEnumerable<string> TrustedPaths()
    {
        if (OperatingSystem.IsWindows())
        {
            yield return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "nvidia-smi.exe");
            yield return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "NVIDIA Corporation", "NVSMI", "nvidia-smi.exe");
        }
        else if (OperatingSystem.IsLinux())
        {
            yield return "/usr/bin/nvidia-smi";
            yield return "/usr/local/bin/nvidia-smi";
        }
    }

    /// <summary>The hottest value of "temperature.gpu" CSV lines; "[N/A]" and junk are skipped.</summary>
    public static int ParseHottest(string csv)
    {
        int best = -1;
        foreach (var line in csv.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            if (int.TryParse(line, out int t) && t is >= 0 and < 150) best = Math.Max(best, t);
        return best;
    }

    private static (int, string) RunProcess(string exe, IReadOnlyList<string> args)
    {
        var psi = new ProcessStartInfo(exe) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
        foreach (var a in args) psi.ArgumentList.Add(a);
        try
        {
            using var p = Process.Start(psi)!;
            var o = p.StandardOutput.ReadToEndAsync();
            if (!p.WaitForExit(10_000)) { try { p.Kill(true); } catch (InvalidOperationException) { } return (-1, ""); }
            return (p.ExitCode, o.Result);
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException) { return (-1, ""); }
    }
}

/// <summary>
/// Apple Silicon die temperatures through the IOKit HID event system (the sensors Activity-style
/// tools read, no administrator rights needed). The GPU shares the die, so the hottest die and GPU
/// sensor ("PMU tdie*", "PMU TP*g") stands for the GPU. hashcat itself reports -1 on these Macs.
/// </summary>
public sealed class AppleSiliconSensors : ITemperatureSource
{
    public string Name => "Apple chip sensors";

    private const string IOKit = "/System/Library/Frameworks/IOKit.framework/IOKit";
    private const string CF = "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation";
    private const uint Utf8 = 0x08000100;
    private const long TemperatureEvent = 15;
    private const int TemperatureField = 15 << 16;

    private readonly object _lock = new();
    private IntPtr _client;
    private IntPtr _services;

    public int ReadHottest()
    {
        lock (_lock)
        {
            if (_services == IntPtr.Zero && !Open()) return -1;
            double best = -1;
            IntPtr productKey = CFStringCreateWithCString(IntPtr.Zero, "Product", Utf8);
            try
            {
                long n = CFArrayGetCount(_services);
                var buf = new byte[128];
                for (long i = 0; i < n; i++)
                {
                    IntPtr svc = CFArrayGetValueAtIndex(_services, i);
                    IntPtr name = IOHIDServiceClientCopyProperty(svc, productKey);
                    if (name == IntPtr.Zero) continue;
                    string product = "";
                    if (CFGetTypeID(name) == CFStringGetTypeID() && CFStringGetCString(name, buf, buf.Length, Utf8))
                        product = Encoding.UTF8.GetString(buf, 0, Array.IndexOf(buf, (byte)0) is var z and >= 0 ? z : buf.Length);
                    CFRelease(name);
                    if (!IsGpuOrDie(product)) continue;
                    IntPtr ev = IOHIDServiceClientCopyEvent(svc, TemperatureEvent, 0, 0);
                    if (ev == IntPtr.Zero) continue;
                    double t = IOHIDEventGetFloatValue(ev, TemperatureField);
                    CFRelease(ev);
                    if (t is > 0 and < 150) best = Math.Max(best, t);
                }
            }
            finally { CFRelease(productKey); }
            return best < 0 ? -1 : (int)Math.Round(best);
        }
    }

    /// <summary>"PMU tdie3" (die) and "PMU TP2g" (GPU) sensors; battery, NAND and the rest are ignored.</summary>
    public static bool IsGpuOrDie(string product)
        => product.StartsWith("PMU tdie", StringComparison.Ordinal)
           || (product.StartsWith("PMU TP", StringComparison.Ordinal) && product.EndsWith('g'));

    private bool Open()
    {
        _client = IOHIDEventSystemClientCreate(IntPtr.Zero);
        if (_client == IntPtr.Zero) return false;
        var cf = NativeLibrary.Load(CF);
        IntPtr keyCallbacks = NativeLibrary.GetExport(cf, "kCFTypeDictionaryKeyCallBacks");
        IntPtr valueCallbacks = NativeLibrary.GetExport(cf, "kCFTypeDictionaryValueCallBacks");
        int page = 0xff00, usage = 5;   // Apple vendor page, temperature sensors
        IntPtr[] keys = [CFStringCreateWithCString(IntPtr.Zero, "PrimaryUsagePage", Utf8), CFStringCreateWithCString(IntPtr.Zero, "PrimaryUsage", Utf8)];
        IntPtr[] values = [CFNumberCreate(IntPtr.Zero, 9, ref page), CFNumberCreate(IntPtr.Zero, 9, ref usage)];
        IntPtr match = CFDictionaryCreate(IntPtr.Zero, keys, values, 2, keyCallbacks, valueCallbacks);
        IOHIDEventSystemClientSetMatching(_client, match);
        foreach (var p in keys.Concat(values).Append(match)) CFRelease(p);
        _services = IOHIDEventSystemClientCopyServices(_client);
        return _services != IntPtr.Zero;
    }

    [DllImport(IOKit)] private static extern IntPtr IOHIDEventSystemClientCreate(IntPtr allocator);
    [DllImport(IOKit)] private static extern int IOHIDEventSystemClientSetMatching(IntPtr client, IntPtr matching);
    [DllImport(IOKit)] private static extern IntPtr IOHIDEventSystemClientCopyServices(IntPtr client);
    [DllImport(IOKit)] private static extern IntPtr IOHIDServiceClientCopyEvent(IntPtr service, long type, int options, long timestamp);
    [DllImport(IOKit)] private static extern IntPtr IOHIDServiceClientCopyProperty(IntPtr service, IntPtr key);
    [DllImport(IOKit)] private static extern double IOHIDEventGetFloatValue(IntPtr ev, int field);
    [DllImport(CF)] private static extern IntPtr CFStringCreateWithCString(IntPtr allocator, string s, uint encoding);
    [DllImport(CF)] private static extern bool CFStringGetCString(IntPtr s, byte[] buffer, long size, uint encoding);
    [DllImport(CF)] private static extern IntPtr CFNumberCreate(IntPtr allocator, long type, ref int value);
    [DllImport(CF)] private static extern IntPtr CFDictionaryCreate(IntPtr allocator, IntPtr[] keys, IntPtr[] values, long count, IntPtr keyCallbacks, IntPtr valueCallbacks);
    [DllImport(CF)] private static extern long CFArrayGetCount(IntPtr array);
    [DllImport(CF)] private static extern IntPtr CFArrayGetValueAtIndex(IntPtr array, long index);
    [DllImport(CF)] private static extern ulong CFGetTypeID(IntPtr cf);
    [DllImport(CF)] private static extern ulong CFStringGetTypeID();
    [DllImport(CF)] private static extern void CFRelease(IntPtr cf);
}
