using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.Shapes;
using Avalonia.Layout;
using Avalonia.Media;

namespace RecoverKit.App.Ui;

public enum MsgButtons { Ok, YesNo, YesNoCancel }
public enum MsgIcon { None, Info, Question, Warning, Error }
public enum MsgResult { None, Ok, Yes, No, Cancel }

/// <summary>A minimal modal message box (Avalonia has none built in).</summary>
internal static class Msg
{
    public static Task<MsgResult> Info(Window owner, string text, string? title = null) => Show(owner, text, title ?? Views.MainWindow.AppName, MsgButtons.Ok, MsgIcon.Info);
    public static Task<MsgResult> Warn(Window owner, string text, string? title = null) => Show(owner, text, title ?? Views.MainWindow.AppName, MsgButtons.Ok, MsgIcon.Warning);
    public static Task<MsgResult> Error(Window owner, string text, string? title = null) => Show(owner, text, title ?? Views.MainWindow.AppName, MsgButtons.Ok, MsgIcon.Error);

    public static async Task<bool> Ask(Window owner, string text, string? title = null, MsgIcon icon = MsgIcon.Question)
        => await Show(owner, text, title ?? Views.MainWindow.AppName, MsgButtons.YesNo, icon) == MsgResult.Yes;

    public static async Task<MsgResult> Show(Window owner, string text, string title, MsgButtons buttons, MsgIcon icon)
    {
        var w = new Window
        {
            Title = title, SizeToContent = SizeToContent.WidthAndHeight, CanResize = false, CanMinimize = false, CanMaximize = false,
            WindowStartupLocation = WindowStartupLocation.CenterOwner, ShowInTaskbar = false, MinWidth = 320,
        };
        var result = MsgResult.None;
        Button B(string t, MsgResult r, bool def = false, bool cancel = false) =>
            L.Button(t, () => { result = r; w.Close(); }, 84, def, cancel);

        Control[] btns = buttons switch
        {
            MsgButtons.YesNo => [B("Yes", MsgResult.Yes, def: true), B("No", MsgResult.No, cancel: true)],
            MsgButtons.YesNoCancel => [B("Yes", MsgResult.Yes, def: true), B("No", MsgResult.No), B("Cancel", MsgResult.Cancel, cancel: true)],
            _ => [B("OK", MsgResult.Ok, def: true, cancel: true)],
        };
        // macOS puts the default button on the right.
        if (OperatingSystem.IsMacOS()) Array.Reverse(btns);

        var body = new DockPanel { Margin = new Thickness(20, 18, 20, 14) };
        if (IconFor(icon) is { } glyph)
        {
            glyph.Margin = new Thickness(0, 0, 14, 0);
            glyph.VerticalAlignment = VerticalAlignment.Top;
            DockPanel.SetDock(glyph, Dock.Left);
            body.Children.Add(glyph);
        }
        body.Children.Add(new SelectableTextBlock { Text = text.Replace("\r\n", "\n"), TextWrapping = TextWrapping.Wrap, MaxWidth = 440, VerticalAlignment = VerticalAlignment.Center });

        var root = new DockPanel();
        var footer = L.Footer(btns);
        DockPanel.SetDock(footer, Dock.Bottom);
        root.Children.Add(footer);
        root.Children.Add(body);
        w.Content = root;
        w.Closed += (_, _) => { if (result == MsgResult.None) result = buttons == MsgButtons.Ok ? MsgResult.Ok : buttons == MsgButtons.YesNo ? MsgResult.No : MsgResult.Cancel; };

        await ShowModal(w, owner);
        return result;
    }

    /// <summary>ShowDialog, or a plain window when the owner is not on screen yet (it cannot own a modal then).</summary>
    public static async Task ShowModal(Window w, Window? owner)
    {
        if (owner is { IsVisible: true }) { await w.ShowDialog(owner); return; }
        var done = new TaskCompletionSource();
        w.Closed += (_, _) => done.TrySetResult();
        w.WindowStartupLocation = WindowStartupLocation.CenterScreen;
        w.Show();
        await done.Task;
    }

    private static Control? IconFor(MsgIcon icon)
    {
        (uint color, string glyph) = icon switch
        {
            MsgIcon.Info => (0xFF0A62C9u, "i"),
            MsgIcon.Question => (0xFF0A62C9u, "?"),
            MsgIcon.Warning => (0xFFE09000u, "!"),
            MsgIcon.Error => (0xFFD13438u, "×"),
            _ => (0u, ""),
        };
        if (glyph.Length == 0) return null;
        var g = new Grid { Width = 34, Height = 34 };
        g.Children.Add(new Ellipse { Fill = new SolidColorBrush(Color.FromUInt32(color)) });
        g.Children.Add(new TextBlock
        {
            Text = glyph, Foreground = Brushes.White, FontWeight = FontWeight.Bold, FontSize = 20,
            HorizontalAlignment = HorizontalAlignment.Center, VerticalAlignment = VerticalAlignment.Center,
        });
        return g;
    }
}
