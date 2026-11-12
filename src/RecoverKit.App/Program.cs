using Avalonia;
using RecoverKit.App.Views;
using RecoverKit.Core;

namespace RecoverKit.App;

internal static class Program
{
    [STAThread]
    private static int Main(string[] args)
    {
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
