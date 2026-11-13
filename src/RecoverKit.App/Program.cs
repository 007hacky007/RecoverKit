using Avalonia;
using RecoverKit.App.Views;
using RecoverKit.Core;

namespace RecoverKit.App;

internal static class Program
{
    [STAThread]
    private static int Main(string[] args)
    {
        if (args.Length > 0 && args[0] == Core.Diagnostics.FiniteDiagnosticWorker.Command) return Core.Diagnostics.FiniteDiagnosticWorker.Run(args);
        if (args.Length > 0 && args[0] == Core.Diagnostics.CpuDiagnosticWorker.Command) return Core.Diagnostics.CpuDiagnosticWorker.Run(args);
        // The elevated NVIDIA power limit helper: no window, no log (see PowerLimiter).
        if (args.Length > 0 && args[0] == Core.Hashcat.PowerHelper.Command) return Core.Hashcat.PowerHelper.Run(args);
        DebugLog.Start(MainWindow.AppName, MainWindow.AppVersion, args);
        AppDomain.CurrentDomain.UnhandledException += (_, e) =>
        {
            if (e.ExceptionObject is Exception ex) DebugLog.Error("Unhandled exception (terminating=" + e.IsTerminating + ")", ex);
            if (e.IsTerminating) DebugLog.Stop();
        };
        TaskScheduler.UnobservedTaskException += (_, e) => DebugLog.Error("Unobserved task exception", e.Exception);

        // Finder passes -psn_... on old systems; only real files are opened.
        App.FileToOpen = args.FirstOrDefault(File.Exists);
        try { return BuildAvaloniaApp().StartWithClassicDesktopLifetime(args); }
        finally { DebugLog.Stop(); }
    }

    // Also used by the Avalonia designer.
    public static AppBuilder BuildAvaloniaApp() => AppBuilder.Configure<App>()
        .UsePlatformDetect()
        .LogToTrace();
}
