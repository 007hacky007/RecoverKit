using RecoverKit.App.Forms;
using RecoverKit.Core;

namespace RecoverKit.App;

internal static class Program
{
    [STAThread]
    private static void Main(string[] args)
    {
        DebugLog.Start(MainForm.AppName, MainForm.AppVersion, args);
        AppDomain.CurrentDomain.UnhandledException += (_, e) =>
        {
            if (e.ExceptionObject is Exception ex) DebugLog.Error("Unhandled exception (terminating=" + e.IsTerminating + ")", ex);
            if (e.IsTerminating) DebugLog.Stop();
        };
        TaskScheduler.UnobservedTaskException += (_, e) => DebugLog.Error("Unobserved task exception", e.Exception);

        ApplicationConfiguration.Initialize();
        Application.SetUnhandledExceptionMode(UnhandledExceptionMode.CatchException);
        Application.ThreadException += (_, e) =>
        {
            DebugLog.Error("UI thread exception", e.Exception);
            MessageBox.Show(e.Exception.Message + "\r\n\r\nDetails are in the debug log: " + DebugLog.CurrentFile,
                "RecoverKit", MessageBoxButtons.OK, MessageBoxIcon.Error);
        };
        try { Application.Run(new MainForm(args.FirstOrDefault(File.Exists))); }
        finally { DebugLog.Stop(); }
    }
}
