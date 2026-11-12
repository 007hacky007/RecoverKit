using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Input;
using Avalonia.Platform.Storage;
using Avalonia.Styling;
using Avalonia.Themes.Fluent;
using Avalonia.Threading;
using RecoverKit.App.Ui;
using RecoverKit.App.Views;
using RecoverKit.Core;

namespace RecoverKit.App;

public sealed class App : Application
{
    /// <summary>File given on the command line (Windows "Open with", drag onto the exe).</summary>
    public static string? FileToOpen { get; set; }

    public override void Initialize()
    {
        Name = MainWindow.AppName;
        RequestedThemeVariant = ThemeVariant.Default;   // follow the system's light/dark setting
#if DEBUG
        if (Snapshots.Theme is "light") RequestedThemeVariant = ThemeVariant.Light;
        else if (Snapshots.Theme is "dark") RequestedThemeVariant = ThemeVariant.Dark;
#endif
        Styles.Add(new FluentTheme());
        Styles.Add(Ui.Styles.App());
    }

    public override void OnFrameworkInitializationCompleted()
    {
        Dispatcher.UIThread.UnhandledException += (_, e) =>
        {
            DebugLog.Error("UI thread exception", e.Exception);
            e.Handled = true;
            if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime { MainWindow: { } w })
                _ = Msg.Show(w, e.Exception.Message + "\n\nDetails are in the debug log: " + DebugLog.CurrentFile, MainWindow.AppName, MsgButtons.Ok, MsgIcon.Error);
        };

        if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
        {
            var main = new MainWindow(FileToOpen);
            desktop.MainWindow = main;
            desktop.ShutdownMode = ShutdownMode.OnMainWindowClose;
            if (OperatingSystem.IsMacOS()) NativeMenu.SetMenu(this, AppMenu(main));
#if DEBUG
            if (Snapshots.Dir is { } snapDir) main.Opened += (_, _) => _ = Snapshots.RunAsync(main, snapDir);
#endif

            // macOS: files opened from Finder or dropped on the Dock icon arrive as activation events.
            if (this.TryGetFeature<IActivatableLifetime>() is { } activatable)
                activatable.Activated += (_, e) =>
                {
                    if (e is FileActivatedEventArgs fa && fa.Files.FirstOrDefault()?.TryGetLocalPath() is { } path)
                        Dispatcher.UIThread.Post(() => main.OpenFromShell(path));
                };
        }
        base.OnFrameworkInitializationCompleted();
    }

    /// <summary>The macOS application menu: About, Settings and update check (Quit and Hide are added by Avalonia).</summary>
    private static NativeMenu AppMenu(MainWindow main)
    {
        var m = new NativeMenu();
        m.Items.Add(Item($"About {MainWindow.AppName}", main.ShowAbout));
        m.Items.Add(Item("Check for Updates...", () => _ = main.CheckForUpdatesAsync()));
        m.Items.Add(new NativeMenuItemSeparator());
        m.Items.Add(Item("Settings...", () => main.ShowPreferences(0), new KeyGesture(Key.OemComma, KeyModifiers.Meta)));
        return m;
    }

    private static NativeMenuItem Item(string header, Action a, KeyGesture? gesture = null)
    {
        var i = new NativeMenuItem(header) { Gesture = gesture };
        i.Click += (_, _) => a();
        return i;
    }
}
