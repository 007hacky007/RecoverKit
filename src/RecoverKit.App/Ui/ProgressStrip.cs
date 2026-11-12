using Avalonia;
using Avalonia.Controls;
using Avalonia.Media;
using Avalonia.Threading;

namespace RecoverKit.App.Ui;

/// <summary>
/// A rounded 8 px progress bar. While <see cref="Sheen"/> is on, a soft highlight sweeps over the filled
/// part (off when the system asks for reduced motion).
/// </summary>
internal sealed class ProgressStrip : Control
{
    public static readonly StyledProperty<double> ValueProperty = AvaloniaProperty.Register<ProgressStrip, double>(nameof(Value));
    public static readonly StyledProperty<IBrush?> FillProperty = AvaloniaProperty.Register<ProgressStrip, IBrush?>(nameof(Fill));
    public static readonly StyledProperty<IBrush?> TrackProperty = AvaloniaProperty.Register<ProgressStrip, IBrush?>(nameof(Track));
    public static readonly StyledProperty<bool> SheenProperty = AvaloniaProperty.Register<ProgressStrip, bool>(nameof(Sheen));

    static ProgressStrip() => AffectsRender<ProgressStrip>(ValueProperty, FillProperty, TrackProperty, SheenProperty);

    private DispatcherTimer? _timer;
    private readonly DateTime _t0 = DateTime.UtcNow;

    public ProgressStrip()
    {
        Height = 8;
        Fill = Palette.AccentBrush;
        Track = Palette.TrackBrush;
        if (!Platform.ReduceMotion)
            Transitions = [new Avalonia.Animation.DoubleTransition { Property = ValueProperty, Duration = TimeSpan.FromMilliseconds(450) }];
    }

    /// <summary>0..1.</summary>
    public double Value { get => GetValue(ValueProperty); set => SetValue(ValueProperty, value); }
    public IBrush? Fill { get => GetValue(FillProperty); set => SetValue(FillProperty, value); }
    public IBrush? Track { get => GetValue(TrackProperty); set => SetValue(TrackProperty, value); }
    public bool Sheen { get => GetValue(SheenProperty); set => SetValue(SheenProperty, value); }

    /// <summary>Jumps to a value without the smoothing transition (resets, new steps).</summary>
    public void Snap(double value)
    {
        var t = Transitions;
        Transitions = null;
        Value = value;
        Transitions = t;
    }

    protected override void OnPropertyChanged(AvaloniaPropertyChangedEventArgs change)
    {
        base.OnPropertyChanged(change);
        if (change.Property == SheenProperty || change.Property == IsVisibleProperty) UpdateTimer();
    }

    private bool _attached;

    protected override void OnAttachedToVisualTree(VisualTreeAttachmentEventArgs e) { base.OnAttachedToVisualTree(e); _attached = true; UpdateTimer(); }
    protected override void OnDetachedFromVisualTree(VisualTreeAttachmentEventArgs e) { base.OnDetachedFromVisualTree(e); _attached = false; UpdateTimer(); }

    private void UpdateTimer()
    {
        bool on = Sheen && IsVisible && !Platform.ReduceMotion && _attached;
        if (on)
        {
            _timer ??= new DispatcherTimer(TimeSpan.FromMilliseconds(33), DispatcherPriority.Render, (_, _) => InvalidateVisual());
            _timer.Start();
        }
        else _timer?.Stop();
    }

    public override void Render(DrawingContext ctx)
    {
        var r = new Rect(Bounds.Size);
        double radius = r.Height / 2;
        ctx.DrawRectangle(Track, null, r, radius, radius);
        double w = Math.Clamp(Value, 0, 1) * r.Width;
        if (w <= 0.5) return;
        var fill = new Rect(0, 0, Math.Max(w, r.Height), r.Height);
        ctx.DrawRectangle(Fill, null, fill, radius, radius);
        if (!Sheen || Platform.ReduceMotion) return;

        // A 1.8 s sweep from left to right across the whole bar, clipped to the filled part.
        double phase = (DateTime.UtcNow - _t0).TotalSeconds % 1.8 / 1.8;
        double band = Math.Max(60, r.Width * 0.25);
        double x = -band + phase * (r.Width + band * 2);
        var sheen = new LinearGradientBrush
        {
            StartPoint = new RelativePoint(x, 0, RelativeUnit.Absolute),
            EndPoint = new RelativePoint(x + band, 0, RelativeUnit.Absolute),
            GradientStops =
            {
                new GradientStop(Color.FromArgb(0, 255, 255, 255), 0),
                new GradientStop(Color.FromArgb(72, 255, 255, 255), 0.5),
                new GradientStop(Color.FromArgb(0, 255, 255, 255), 1),
            },
        };
        using (ctx.PushClip(new RoundedRect(fill, radius)))
            ctx.DrawRectangle(sheen, null, fill);
    }
}
