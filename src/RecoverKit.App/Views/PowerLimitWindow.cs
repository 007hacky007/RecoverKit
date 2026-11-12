using Avalonia;
using Avalonia.Controls;
using Avalonia.Layout;
using Avalonia.Media;
using RecoverKit.App.Ui;
using RecoverKit.Core.Hashcat;

namespace RecoverKit.App.Views;

/// <summary>
/// Explains why administrator rights are needed before the system's UAC or password prompt for
/// the NVIDIA power limit appears. Wire it to <see cref="Core.RecoverySession.ConfirmElevation"/>:
/// <c>session.ConfirmElevation = r =&gt; PowerLimitWindow.AskAsync(this, r);</c>
/// </summary>
public static class PowerLimitWindow
{
    public static async Task<ElevationChoice> AskAsync(Window owner, PowerLimitRequest request)
    {
        var w = new Window
        {
            Title = "GPU power limit", SizeToContent = SizeToContent.WidthAndHeight, CanResize = false, CanMinimize = false,
            CanMaximize = false, WindowStartupLocation = WindowStartupLocation.CenterOwner, ShowInTaskbar = false, MinWidth = 360,
            Icon = owner.Icon,
        };
        var choice = ElevationChoice.Cancel;
        Button B(string text, ElevationChoice c, double width, bool def = false, bool cancel = false)
            => L.Button(text, () => { choice = c; w.Close(); }, width, def, cancel);
        Control[] buttons =
        [
            B("Continue", ElevationChoice.Continue, 90, def: true),
            B("Run without power limit", ElevationChoice.WithoutPowerLimit, 180),
            B("Cancel", ElevationChoice.Cancel, 90, cancel: true),
        ];
        if (OperatingSystem.IsMacOS()) Array.Reverse(buttons);

        var text = new SelectableTextBlock { Text = request.Explanation, TextWrapping = TextWrapping.Wrap, MaxWidth = 460 };
        var note = L.Text("If you decline, the attack runs without the power limit.", dim: true, wrap: true);
        note.MaxWidth = 460;
        var body = new StackPanel { Spacing = 10, Margin = new Thickness(20, 18, 20, 14), Children = { text, note } };
        var root = new DockPanel();
        var footer = L.Footer(buttons);
        DockPanel.SetDock(footer, Dock.Bottom);
        root.Children.Add(footer);
        root.Children.Add(body);
        w.Content = root;
        await Msg.ShowModal(w, owner);
        return choice;
    }
}
