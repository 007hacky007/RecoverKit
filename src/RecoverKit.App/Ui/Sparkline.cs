using Avalonia;
using Avalonia.Controls;
using Avalonia.Media;

namespace RecoverKit.App.Ui;

/// <summary>
/// Speed over the last <see cref="Window"/>: a line with a soft area under it, a faint middle grid line
/// and a dot on the latest sample. The newest sample is at the right edge.
/// </summary>
internal sealed class Sparkline : Control
{
    public static readonly StyledProperty<IBrush?> LineProperty = AvaloniaProperty.Register<Sparkline, IBrush?>(nameof(Line));

    static Sparkline() => AffectsRender<Sparkline>(LineProperty);

    private readonly List<(DateTime At, double Value)> _samples = new();

    public TimeSpan Window { get; init; } = TimeSpan.FromSeconds(60);

    public Sparkline()
    {
        Line = Palette.AccentBrush;
        Height = 54;
    }

    public IBrush? Line { get => GetValue(LineProperty); set => SetValue(LineProperty, value); }

    public int Count => _samples.Count;

    public void Add(double value, DateTime? at = null)
    {
        var t = at ?? DateTime.UtcNow;
        _samples.Add((t, Math.Max(0, value)));
        var cut = t - Window;
        int old = _samples.FindIndex(s => s.At >= cut);
        if (old > 1) _samples.RemoveRange(0, old - 1);   // keep one sample left of the window so the line reaches the edge
        InvalidateVisual();
    }

    public void Clear()
    {
        _samples.Clear();
        InvalidateVisual();
    }

    public override void Render(DrawingContext ctx)
    {
        var r = new Rect(Bounds.Size);
        var grid = new Pen(Palette.ChipBrush, 1);
        ctx.DrawLine(grid, new Point(0, Math.Round(r.Height / 2) + 0.5), new Point(r.Width, Math.Round(r.Height / 2) + 0.5));
        if (_samples.Count == 0 || r.Width < 4) return;

        double max = _samples.Max(s => s.Value), min = _samples.Min(s => s.Value);
        // Scale to the data, but never zoom in so far that noise of a few percent looks like a cliff.
        double span = Math.Max(max - min, max * 0.25);
        double lo = Math.Max(0, (max + min) / 2 - span * 0.6), hi = lo + span * 1.2;
        if (hi <= lo) hi = lo + 1;
        var now = _samples[^1].At;
        double top = 4, bottom = r.Height - 3;
        Point P((DateTime At, double Value) s) => new(
            Math.Clamp((1 - (now - s.At).TotalSeconds / Window.TotalSeconds) * (r.Width - 4), 0, r.Width - 4),
            bottom - (s.Value - lo) / (hi - lo) * (bottom - top));
        var pts = _samples.Select(P).ToList();
        if (pts.Count == 1) pts.Insert(0, new Point(Math.Max(0, pts[0].X - 1), pts[0].Y));

        var line = new StreamGeometry();
        using (var g = line.Open())
        {
            g.BeginFigure(pts[0], false);
            foreach (var p in pts.Skip(1)) g.LineTo(p);
            g.EndFigure(false);
        }
        var area = new StreamGeometry();
        using (var g = area.Open())
        {
            g.BeginFigure(new Point(pts[0].X, r.Height), true);
            foreach (var p in pts) g.LineTo(p);
            g.LineTo(new Point(pts[^1].X, r.Height));
            g.EndFigure(true);
        }
        var color = (Line as ISolidColorBrush)?.Color ?? Palette.AccentColor;
        ctx.DrawGeometry(new SolidColorBrush(color, 0.16), null, area);
        ctx.DrawGeometry(null, new Pen(Line, 1.6) { LineJoin = PenLineJoin.Round, LineCap = PenLineCap.Round }, line);
        ctx.DrawEllipse(Line, null, pts[^1], 3, 3);
    }
}
