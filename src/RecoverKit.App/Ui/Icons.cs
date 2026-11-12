using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.Documents;
using Avalonia.Media;

namespace RecoverKit.App.Ui;

/// <summary>
/// Monochrome line icons (24x24 strokes, like the toolbar of the design study). They paint with the
/// inherited text foreground, so they follow the button state (hover, accent, disabled) and the theme.
/// </summary>
internal static class Icons
{
    public const string OpenData = "M3,7 H9 L11,9 H21 V18 A2,2 0 0 1 19,20 H5 A2,2 0 0 1 3,18 Z M12,17 V12 M9.5,14.5 L12,12 L14.5,14.5";
    public const string StartData = "M8,5.5 V18.5 L18,12 Z";
    public const string StopData = "M8.5,6.5 H15.5 A2,2 0 0 1 17.5,8.5 V15.5 A2,2 0 0 1 15.5,17.5 H8.5 A2,2 0 0 1 6.5,15.5 V8.5 A2,2 0 0 1 8.5,6.5 Z";
    public const string BenchData = "M4,19 V9 M9,19 V5 M14,19 V12 M19,19 V8";
    public const string HelpData = "M21,12 A9,9 0 1 1 3,12 A9,9 0 1 1 21,12 Z M9.5,9.5 A2.5,2.5 0 1 1 13,11.8 C12.4,12.1 12,12.6 12,13.3 V13.7 M12,17 H12.01";
    public const string LockData = "M7,10 H17 A2,2 0 0 1 19,12 V18 A2,2 0 0 1 17,20 H7 A2,2 0 0 1 5,18 V12 A2,2 0 0 1 7,10 Z M8,10 V7 A4,4 0 0 1 16,7 V10 M12,14 V16";
    public const string CheckData = "M5,12.5 L9.5,17 L19,7.5";

    /// <summary>A gear outline: eight rounded teeth around a ring with a hole.</summary>
    public static string GearData
    {
        get
        {
            var sb = new System.Text.StringBuilder();
            const int teeth = 8;
            for (int i = 0; i < teeth * 4; i++)
            {
                double a = (i - 0.5) * Math.PI * 2 / (teeth * 4);
                double r = (i % 4) is 0 or 1 ? 9.6 : 7.4;
                sb.Append(i == 0 ? 'M' : 'L').Append(FormattableString.Invariant($"{12 + r * Math.Cos(a):0.##},{12 + r * Math.Sin(a):0.##} "));
            }
            sb.Append("Z M15,12 A3,3 0 1 1 9,12 A3,3 0 1 1 15,12 Z");
            return sb.ToString();
        }
    }

    public static LineIcon Open(double size = 20) => new(OpenData, size);
    public static LineIcon Start(double size = 20) => new(StartData, size);
    public static LineIcon Stop(double size = 20) => new(StopData, size);
    public static LineIcon Bench(double size = 20) => new(BenchData, size);
    public static LineIcon Gear(double size = 20) => new(GearData, size);
    public static LineIcon Help(double size = 20) => new(HelpData, size);
    public static LineIcon Lock(double size = 44) => new(LockData, size, 1.4);
    public static LineIcon Check(double size = 20) => new(CheckData, size, 2.4);

    /// <summary>The window icon, from the embedded multi-resolution .ico.</summary>
    public static WindowIcon? AppIcon()
    {
        using var s = typeof(Icons).Assembly.GetManifestResourceStream("RecoverKit.App.Icon.ico");
        return s is null ? null : new WindowIcon(s);
    }
}

/// <summary>Strokes a 24x24 path geometry scaled to its size, in <see cref="Brush"/> or the inherited foreground.</summary>
internal sealed class LineIcon : Control
{
    public static readonly StyledProperty<IBrush?> BrushProperty = AvaloniaProperty.Register<LineIcon, IBrush?>(nameof(Brush));

    static LineIcon() => AffectsRender<LineIcon>(BrushProperty, TextElement.ForegroundProperty);

    private readonly Geometry _geometry;
    private readonly double _thickness;

    public LineIcon(string data, double size, double thickness = 1.7)
    {
        _geometry = Geometry.Parse(data);
        _thickness = thickness;
        Width = Height = size;
    }

    /// <summary>Overrides the inherited foreground.</summary>
    public IBrush? Brush { get => GetValue(BrushProperty); set => SetValue(BrushProperty, value); }

    public override void Render(DrawingContext context)
    {
        var brush = Brush ?? GetValue(TextElement.ForegroundProperty) ?? Palette.ForegroundBrush;
        double scale = Math.Min(Bounds.Width, Bounds.Height) / 24;
        var pen = new Pen(brush, _thickness) { LineCap = PenLineCap.Round, LineJoin = PenLineJoin.Round };
        using (context.PushTransform(Matrix.CreateScale(scale, scale)))
            context.DrawGeometry(null, pen, _geometry);
    }
}
