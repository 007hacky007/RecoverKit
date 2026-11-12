#if DEBUG
using Avalonia;
using Avalonia.Controls;
using Avalonia.Media.Imaging;
using Avalonia.Threading;
using RecoverKit.App.Views;
using RecoverKit.Core;
using RecoverKit.Core.Attacks;
using RecoverKit.Core.Formats;

namespace RecoverKit.App.Ui;

/// <summary>
/// Debug builds only: RECOVERKIT_SNAPSHOTS=&lt;dir&gt; renders every window and wizard page to PNG
/// (client area, no OS frame) and exits. Used to check layouts without clicking through the app.
/// RECOVERKIT_SNAPSHOT_THEME=light|dark forces a theme; RECOVERKIT_SNAPSHOT_ONLY=main limits the run
/// to the main window and wizard/found dialog states.
/// </summary>
internal static class Snapshots
{
    public static string? Dir => Environment.GetEnvironmentVariable("RECOVERKIT_SNAPSHOTS");
    public static string? Theme => Environment.GetEnvironmentVariable("RECOVERKIT_SNAPSHOT_THEME");
    private static bool OnlyMain => Environment.GetEnvironmentVariable("RECOVERKIT_SNAPSHOT_ONLY") == "main";

    /// <summary>A Word document as the detector would report it, for the loaded-file states.</summary>
    internal static Detection FakeDetection()
    {
        var d = new Detection { FilePath = "/Users/example/Documents/Quarterly-report.docx", TypeName = "MS Office 2007 document" };
        d.Add("Application", "Microsoft Word");
        d.Target = new HashTarget
        {
            FormatId = "OF07", FormatName = "MS Office 2007 document", Protection = "AES-128, SHA-1, 50000 iterations", Modes = [9400],
            HashLines = "", Speed = SpeedClass.Slow, Utf16Password = true,
        };
        return d;
    }

    public static async Task RunAsync(MainWindow main, string dir)
    {
        Directory.CreateDirectory(dir);
        main.Width = 700;
        main.Height = 600;
        await Task.Delay(2500);   // hashcat detection
        await Save(main, Path.Combine(dir, "main-empty.png"));
        main.DebugShowDetection(FakeDetection());
        await Save(main, Path.Combine(dir, "main-loaded.png"));
        await main.DebugStatesAsync(async name => await Save(main, Path.Combine(dir, $"main-{name}.png")));
        if (Environment.GetEnvironmentVariable("RECOVERKIT_SNAPSHOT_REAL") is { Length: > 0 } real)
        {
            await main.DebugRealRunAsync(real,
            [
                new AttackSpec { Kind = AttackKind.Mask, HashcatMask = "?d?d?d?d?d?d?d" },
                new AttackSpec { Kind = AttackKind.BruteForce, Smalls = true, Digits = true, MinLength = 1, MaxLength = 4 },
            ], async name => await Save(main, Path.Combine(dir, $"main-{name}.png")));
            Environment.Exit(0);
        }

        var settings = Settings.Load();
        if (!OnlyMain)
        {
            var target = new HashTarget
            {
                FormatId = "PDF6", FormatName = "Adobe PDF 2.0", Protection = "AES-256 (revision 6)", Modes = [10700], HashLines = "", MaxPasswordLength = 127,
            };
            var ctx = new PlannerContext { DataPath = settings.DataPath, DefaultDictionary = settings.DefaultDictionary };
            var wiz = new WizardWindow(target, "/Users/example/Documents/Report-2024.pdf", ScenarioParser.LoadDefault(), settings, ctx);
            wiz.Show(main);
            for (int i = 0; i < WizardWindow.DebugPageNames.Length; i++)
            {
                wiz.DebugShow(i);
                await Save(wiz, Path.Combine(dir, $"wizard-{WizardWindow.DebugPageNames[i]}.png"));
            }
            wiz.Close();
            for (int tab = 0; tab < 5; tab++)
            {
                var p = new PreferencesWindow(settings, null, [], tab);
                p.Show(main);
                await Save(p, Path.Combine(dir, $"prefs-{tab}.png"));
                p.Close();
            }
            foreach (var (name, w) in new (string, Window)[] { ("openas", new OpenAsWindow(settings)) })
            {
                w.Show(main);
                await Save(w, Path.Combine(dir, name + ".png"));
                w.Close();
            }
            var msg = Msg.Show(main, "An attack is running. Stop it and exit?\n(It can be continued later.)", "RecoverKit", MsgButtons.YesNo, MsgIcon.Question);
            await Task.Delay(800);
            var top = ((Avalonia.Controls.ApplicationLifetimes.IClassicDesktopStyleApplicationLifetime)Application.Current!.ApplicationLifetime!).Windows.Last();
            await Save(top, Path.Combine(dir, "msg.png"));
            top.Close();
            await msg;
        }
        Environment.Exit(0);
    }

    internal static async Task Save(Window w, string path)
    {
        await Task.Delay(700);
        await Dispatcher.UIThread.InvokeAsync(() => { }, DispatcherPriority.Render);
        var size = new PixelSize((int)(w.ClientSize.Width * 2), (int)(w.ClientSize.Height * 2));
        using var bmp = new RenderTargetBitmap(size, new Vector(192, 192));
        bmp.Render(w);
        bmp.Save(path);
    }
}
#endif
