using Avalonia;
using Avalonia.Controls;
using Avalonia.Media;

namespace RecoverKit.App.Ui;

/// <summary>The drop zone frame: a dashed rounded outline, solid accent with a soft fill while a file is dragged over.</summary>
internal sealed class DropFrame : Decorator
{
    public static readonly StyledProperty<bool> ActiveProperty = AvaloniaProperty.Register<DropFrame, bool>(nameof(Active));

    static DropFrame() => AffectsRender<DropFrame>(ActiveProperty);

    public bool Active { get => GetValue(ActiveProperty); set => SetValue(ActiveProperty, value); }

    public override void Render(DrawingContext ctx)
    {
        double th = Active ? 2 : 1.5;
        var r = new Rect(Bounds.Size).Deflate(th / 2);
        if (Active)
        {
            ctx.DrawRectangle(Palette.AccentSoftBrush, new Pen(Palette.AccentBrush, th), r, 12, 12);
            // A soft inner glow, as in the design study.
            ctx.DrawRectangle(null, new Pen(Palette.AccentSoftBrush, 4), r.Deflate(3), 9, 9);
        }
        else ctx.DrawRectangle(Brushes.Transparent, new Pen(Palette.DashBrush, th) { DashStyle = new DashStyle([4, 3], 0) }, r, 12, 12);
    }
}
