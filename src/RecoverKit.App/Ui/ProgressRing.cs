using Avalonia;
using Avalonia.Controls;
using Avalonia.Media;

namespace RecoverKit.App.Ui;

/// <summary>A circular progress indicator: a faint track and an arc from 12 o'clock, clockwise.</summary>
internal sealed class ProgressRing : Control
{
    public static readonly StyledProperty<double> ValueProperty = AvaloniaProperty.Register<ProgressRing, double>(nameof(Value));
    public static readonly StyledProperty<IBrush?> FillProperty = AvaloniaProperty.Register<ProgressRing, IBrush?>(nameof(Fill));
    public static readonly StyledProperty<IBrush?> TrackProperty = AvaloniaProperty.Register<ProgressRing, IBrush?>(nameof(Track));
    public static readonly StyledProperty<double> ThicknessProperty = AvaloniaProperty.Register<ProgressRing, double>(nameof(Thickness), 9);

    static ProgressRing() => AffectsRender<ProgressRing>(ValueProperty, FillProperty, TrackProperty, ThicknessProperty);

    public ProgressRing()
    {
        Fill = Palette.AccentBrush;
        Track = Palette.TrackBrush;
        if (!Platform.ReduceMotion)
            Transitions = [new Avalonia.Animation.DoubleTransition { Property = ValueProperty, Duration = TimeSpan.FromMilliseconds(450) }];
    }

    /// <summary>0..1.</summary>
    public double Value { get => GetValue(ValueProperty); set => SetValue(ValueProperty, value); }
    public IBrush? Fill { get => GetValue(FillProperty); set => SetValue(FillProperty, value); }
    public IBrush? Track { get => GetValue(TrackProperty); set => SetValue(TrackProperty, value); }
    public double Thickness { get => GetValue(ThicknessProperty); set => SetValue(ThicknessProperty, value); }

    /// <summary>Jumps to a value without the smoothing transition.</summary>
    public void Snap(double value)
    {
        var t = Transitions;
        Transitions = null;
        Value = value;
        Transitions = t;
    }

    public override void Render(DrawingContext ctx)
    {
        double size = Math.Min(Bounds.Width, Bounds.Height);
        double th = Thickness;
        double radius = (size - th) / 2;
        if (radius <= 0) return;
        var c = new Point(Bounds.Width / 2, Bounds.Height / 2);
        ctx.DrawEllipse(null, new Pen(Track, th), c, radius, radius);

        double v = Math.Clamp(Value, 0, 1);
        if (v <= 0.001) return;
        var pen = new Pen(Fill, th) { LineCap = PenLineCap.Round };
        if (v >= 0.9995) { ctx.DrawEllipse(null, pen, c, radius, radius); return; }

        double a = v * Math.PI * 2;
        var start = new Point(c.X, c.Y - radius);
        var end = new Point(c.X + radius * Math.Sin(a), c.Y - radius * Math.Cos(a));
        var g = new StreamGeometry();
        using (var s = g.Open())
        {
            s.BeginFigure(start, false);
            s.ArcTo(end, new Size(radius, radius), 0, v > 0.5, SweepDirection.Clockwise);
            s.EndFigure(false);
        }
        ctx.DrawGeometry(null, pen, g);
    }
}
