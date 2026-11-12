using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.Shapes;
using Avalonia.Media;

namespace RecoverKit.App.Ui;

/// <summary>Toolbar and window icons, drawn as vectors on a 32x32 canvas so they stay sharp at any scale.</summary>
internal static class Icons
{
    private static Color C(uint argb) => Color.FromUInt32(argb);

    private static Viewbox Box(double size, params Control[] shapes)
    {
        var canvas = new Canvas { Width = 32, Height = 32 };
        foreach (var s in shapes) canvas.Children.Add(s);
        return new Viewbox { Width = size, Height = size, Child = canvas };
    }

    private static LinearGradientBrush Vertical(uint top, uint bottom) => new()
    {
        StartPoint = new RelativePoint(0.5, 0, RelativeUnit.Relative), EndPoint = new RelativePoint(0.5, 1, RelativeUnit.Relative),
        GradientStops = { new GradientStop(C(top), 0), new GradientStop(C(bottom), 1) },
    };

    private static Avalonia.Controls.Shapes.Path P(string data, IBrush? fill, IBrush? stroke = null, double thickness = 1)
        => new() { Data = Geometry.Parse(data), Fill = fill, Stroke = stroke, StrokeThickness = thickness };

    public static Control Open(double size) => Box(size,
        P("M2,9 H28 V28 H2 Z M2,6 H13 V11 H2 Z", Vertical(0xFFFFD678, 0xFFE6961E)),
        P("M4,14 H30 L27,28 H2 Z", new SolidColorBrush(C(0xFFFABE46))),
        P("M16,2 L24,11 H19.5 V22 H12.5 V11 H8 Z", new SolidColorBrush(C(0xFF28A03C)), new SolidColorBrush(C(0xFF146E28))));

    private static Control Disc(double size, uint light, uint dark, Control glyph)
    {
        var fill = new RadialGradientBrush
        {
            Center = new RelativePoint(0.38, 0.3, RelativeUnit.Relative), GradientOrigin = new RelativePoint(0.38, 0.3, RelativeUnit.Relative),
            RadiusX = new RelativeScalar(0.75, RelativeUnit.Relative), RadiusY = new RelativeScalar(0.75, RelativeUnit.Relative),
            GradientStops = { new GradientStop(C(light), 0), new GradientStop(C(dark), 1) },
        };
        var shadow = new Ellipse { Width = 27, Height = 27, Fill = new SolidColorBrush(C(0x3C000000)) };
        Canvas.SetLeft(shadow, 3); Canvas.SetTop(shadow, 4);
        var disc = new Ellipse { Width = 27, Height = 27, Fill = fill, Stroke = new SolidColorBrush(C(0xFF5A5A5A)), StrokeThickness = 1.2 };
        Canvas.SetLeft(disc, 2); Canvas.SetTop(disc, 2);
        return Box(size, shadow, disc, glyph);
    }

    public static Control Start(double size, bool enabled = true) => Disc(size,
        enabled ? 0xFF8CE678 : 0xFFDCDCDC, enabled ? 0xFF1E8C28 : 0xFF8C8C8C,
        P("M12.5,9 L22,15.5 L12.5,22 Z", Brushes.White));

    public static Control Stop(double size, bool enabled = true) => Disc(size,
        enabled ? 0xFF969696 : 0xFFDCDCDC, enabled ? 0xFF323232 : 0xFF8C8C8C,
        P("M11,11 H20.5 V20.5 H11 Z", Brushes.White));

    public static Control Gear(double size)
    {
        const int teeth = 8;
        var sb = new System.Text.StringBuilder();
        for (int i = 0; i < teeth * 4; i++)
        {
            double a = i * Math.PI * 2 / (teeth * 4);
            double r = (i % 4) is 0 or 1 ? 14.5 : 11;
            sb.Append(i == 0 ? 'M' : 'L').Append(FormattableString.Invariant($"{16 + r * Math.Cos(a):0.##},{16 + r * Math.Sin(a):0.##} "));
        }
        sb.Append("Z M21,16 A5,5 0 1 0 11,16 A5,5 0 1 0 21,16 Z");
        var fill = new LinearGradientBrush
        {
            StartPoint = new RelativePoint(0, 0, RelativeUnit.Relative), EndPoint = new RelativePoint(1, 1, RelativeUnit.Relative),
            GradientStops = { new GradientStop(C(0xFFFFB43C), 0), new GradientStop(C(0xFFDC640A), 1) },
        };
        var path = P("F0 " + sb, fill, new SolidColorBrush(C(0xFFA04600)));
        return Box(size, path);
    }

    public static Control Help(double size)
    {
        var page = P("M6,2 H20 L26,8 V30 H6 Z", Vertical(0xFFFFFFFF, 0xFFDCE6F5), new SolidColorBrush(C(0xFF5A6E8C)), 1.2);
        var fold = P("M20,2 V8 H26", null, new SolidColorBrush(C(0xFF5A6E8C)), 1.2);
        var q = new TextBlock { Text = "?", FontSize = 17, FontWeight = FontWeight.Bold, Foreground = new SolidColorBrush(C(0xFF1E5AC8)) };
        Canvas.SetLeft(q, 11); Canvas.SetTop(q, 7);
        return Box(size, page, fold, q);
    }

    /// <summary>The window icon, from the embedded multi-resolution .ico.</summary>
    public static WindowIcon? AppIcon()
    {
        using var s = typeof(Icons).Assembly.GetManifestResourceStream("RecoverKit.App.Icon.ico");
        return s is null ? null : new WindowIcon(s);
    }
}
