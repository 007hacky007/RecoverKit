using Avalonia;
using Avalonia.Animation;
using Avalonia.Animation.Easings;
using Avalonia.Controls;
using Avalonia.Media;
using Avalonia.Styling;

namespace RecoverKit.App.Ui;

/// <summary>A green circle with a check mark that draws itself once (<see cref="Play"/>).</summary>
internal sealed class CheckMark : Control
{
    public static readonly StyledProperty<double> ProgressProperty = AvaloniaProperty.Register<CheckMark, double>(nameof(Progress), 1);

    static CheckMark() => AffectsRender<CheckMark>(ProgressProperty);

    // The check in a 54x54 box: (16,28) -> (23,35) -> (38,20).
    private static readonly Point A = new(16, 28), B = new(23, 35), C = new(38, 20);

    public CheckMark() => Width = Height = 54;

    /// <summary>0..1: how much of the check is drawn.</summary>
    public double Progress { get => GetValue(ProgressProperty); set => SetValue(ProgressProperty, value); }

    /// <summary>Draws the check from nothing (or shows it at once when motion is reduced).</summary>
    public async void Play()
    {
        if (Platform.ReduceMotion) { Progress = 1; return; }
        Progress = 0;
        var anim = new Animation
        {
            Duration = TimeSpan.FromMilliseconds(500), Delay = TimeSpan.FromMilliseconds(150), Easing = new CubicEaseOut(),
            FillMode = FillMode.Forward,
            Children =
            {
                new KeyFrame { Cue = new Cue(0), Setters = { new Setter(ProgressProperty, 0.0) } },
                new KeyFrame { Cue = new Cue(1), Setters = { new Setter(ProgressProperty, 1.0) } },
            },
        };
        await anim.RunAsync(this);
        Progress = 1;
    }

    public override void Render(DrawingContext ctx)
    {
        double s = Math.Min(Bounds.Width, Bounds.Height) / 54;
        using var _ = ctx.PushTransform(Matrix.CreateScale(s, s));
        var good = Palette.GoodBrush;
        var color = (good as ISolidColorBrush)?.Color ?? Colors.Green;
        ctx.DrawEllipse(new SolidColorBrush(color, 0.14), new Pen(good, 2), new Point(27, 27), 25, 25);

        double l1 = Dist(A, B), l2 = Dist(B, C), len = (l1 + l2) * Math.Clamp(Progress, 0, 1);
        if (len <= 0.01) return;
        var g = new StreamGeometry();
        using (var c = g.Open())
        {
            c.BeginFigure(A, false);
            if (len <= l1) c.LineTo(Lerp(A, B, len / l1));
            else { c.LineTo(B); c.LineTo(Lerp(B, C, (len - l1) / l2)); }
            c.EndFigure(false);
        }
        ctx.DrawGeometry(null, new Pen(good, 3) { LineCap = PenLineCap.Round, LineJoin = PenLineJoin.Round }, g);
    }

    private static double Dist(Point a, Point b) => Math.Sqrt((a.X - b.X) * (a.X - b.X) + (a.Y - b.Y) * (a.Y - b.Y));
    private static Point Lerp(Point a, Point b, double t) => new(a.X + (b.X - a.X) * t, a.Y + (b.Y - a.Y) * t);
}
