using System.Drawing.Drawing2D;

namespace RecoverKit.App.Ui;

/// <summary>Toolbar and window icons, drawn at runtime so no binary assets are needed.</summary>
internal static class Icons
{
    private static Bitmap Canvas(int size, out Graphics g)
    {
        var b = new Bitmap(size, size);
        g = Graphics.FromImage(b);
        g.SmoothingMode = SmoothingMode.AntiAlias;
        g.ScaleTransform(size / 32f, size / 32f);
        return b;
    }

    public static Bitmap Open(int size)
    {
        var b = Canvas(size, out var g);
        using (g)
        {
            using var back = new LinearGradientBrush(new Rectangle(2, 6, 28, 22), Color.FromArgb(255, 214, 120), Color.FromArgb(230, 150, 30), 90f);
            g.FillRectangle(back, 2, 9, 26, 19);
            g.FillRectangle(back, 2, 6, 11, 5);
            using var front = new SolidBrush(Color.FromArgb(250, 190, 70));
            g.FillPolygon(front, [new PointF(4, 14), new PointF(30, 14), new PointF(27, 28), new PointF(2, 28)]);
            using var arrow = new SolidBrush(Color.FromArgb(40, 160, 60));
            g.FillPolygon(arrow, [new PointF(16, 2), new PointF(24, 11), new PointF(19.5f, 11), new PointF(19.5f, 22), new PointF(12.5f, 22), new PointF(12.5f, 11), new PointF(8, 11)]);
            using var pen = new Pen(Color.FromArgb(20, 110, 40), 1);
            g.DrawPolygon(pen, [new PointF(16, 2), new PointF(24, 11), new PointF(19.5f, 11), new PointF(19.5f, 22), new PointF(12.5f, 22), new PointF(12.5f, 11), new PointF(8, 11)]);
        }
        return b;
    }

    private static Bitmap Disc(int size, Color light, Color dark, Action<Graphics> glyph)
    {
        var b = Canvas(size, out var g);
        using (g)
        {
            using var shadow = new SolidBrush(Color.FromArgb(60, 0, 0, 0));
            g.FillEllipse(shadow, 3, 4, 27, 27);
            using var path = new GraphicsPath();
            path.AddEllipse(2, 2, 27, 27);
            using var fill = new PathGradientBrush(path) { CenterColor = light, SurroundColors = [dark], CenterPoint = new PointF(12, 10) };
            g.FillPath(fill, path);
            using var rim = new Pen(Color.FromArgb(90, 90, 90), 1.2f);
            g.DrawEllipse(rim, 2, 2, 27, 27);
            glyph(g);
        }
        return b;
    }

    public static Bitmap Start(int size, bool enabled = true) => Disc(size,
        enabled ? Color.FromArgb(140, 230, 120) : Color.Gainsboro, enabled ? Color.FromArgb(30, 140, 40) : Color.Gray,
        g => g.FillPolygon(Brushes.White, [new PointF(12.5f, 9), new PointF(22, 15.5f), new PointF(12.5f, 22)]));

    public static Bitmap Stop(int size, bool enabled = true) => Disc(size,
        enabled ? Color.FromArgb(150, 150, 150) : Color.Gainsboro, enabled ? Color.FromArgb(50, 50, 50) : Color.Gray,
        g => g.FillRectangle(Brushes.White, 11, 11, 9.5f, 9.5f));

    public static Bitmap Gear(int size)
    {
        var b = Canvas(size, out var g);
        using (g)
        {
            using var path = new GraphicsPath();
            const int teeth = 8;
            var pts = new List<PointF>();
            for (int i = 0; i < teeth * 4; i++)
            {
                double a = i * Math.PI * 2 / (teeth * 4);
                float r = (i % 4) is 0 or 1 ? 14.5f : 11f;
                pts.Add(new PointF(16 + r * (float)Math.Cos(a), 16 + r * (float)Math.Sin(a)));
            }
            path.AddPolygon(pts.ToArray());
            path.AddEllipse(11, 11, 10, 10);
            using var fill = new LinearGradientBrush(new Rectangle(0, 0, 32, 32), Color.FromArgb(255, 180, 60), Color.FromArgb(220, 100, 10), 60f);
            g.FillPath(fill, path);
            using var pen = new Pen(Color.FromArgb(160, 70, 0), 1);
            g.DrawPath(pen, path);
        }
        return b;
    }

    public static Bitmap Help(int size)
    {
        var b = Canvas(size, out var g);
        using (g)
        {
            var page = new[] { new PointF(6, 2), new PointF(20, 2), new PointF(26, 8), new PointF(26, 30), new PointF(6, 30) };
            using var fill = new LinearGradientBrush(new Rectangle(0, 0, 32, 32), Color.White, Color.FromArgb(220, 230, 245), 90f);
            g.FillPolygon(fill, page);
            using var pen = new Pen(Color.FromArgb(90, 110, 140), 1.2f);
            g.DrawPolygon(pen, page);
            g.DrawLines(pen, [new PointF(20, 2), new PointF(20, 8), new PointF(26, 8)]);
            using var font = new Font("Segoe UI", 15f, FontStyle.Bold, GraphicsUnit.Pixel);
            using var blue = new SolidBrush(Color.FromArgb(30, 90, 200));
            g.DrawString("?", font, blue, 10, 9);
        }
        return b;
    }

    private static Icon? _appIcon;

    /// <summary>
    /// The application icon, loaded from the embedded multi-resolution .ico so window, taskbar and
    /// Alt-Tab renderings stay crisp at every size. Falls back to a drawn padlock if the resource
    /// is missing. Cached because it owns an unmanaged handle for the process lifetime.
    /// </summary>
    public static Icon AppIcon()
    {
        if (_appIcon != null) return _appIcon;
        var asm = typeof(Icons).Assembly;
        using var s = asm.GetManifestResourceStream("RecoverKit.App.Icon.ico");
        if (s != null) return _appIcon = new Icon(s);
        return _appIcon = DrawnAppIcon();
    }

    private static Icon DrawnAppIcon()
    {
        var b = Canvas(32, out var g);
        using (g)
        {
            using var bg = new LinearGradientBrush(new Rectangle(0, 0, 32, 32), Color.FromArgb(40, 120, 220), Color.FromArgb(15, 60, 140), 90f);
            using var rr = Rounded(new RectangleF(1, 1, 30, 30), 6);
            g.FillPath(bg, rr);
            using var white = new Pen(Color.White, 3f);
            g.DrawArc(white, 10, 5, 12, 14, 180, 180);
            g.DrawLine(white, 10, 12, 10, 15);
            g.DrawLine(white, 22, 12, 22, 15);
            g.FillRectangle(Brushes.White, 7, 14, 18, 13);
            using var hole = new SolidBrush(Color.FromArgb(20, 70, 160));
            g.FillEllipse(hole, 14, 17, 4, 4);
            g.FillRectangle(hole, 15, 20, 2, 4);
        }
        return Icon.FromHandle(b.GetHicon());
    }

    private static GraphicsPath Rounded(RectangleF r, float rad)
    {
        var p = new GraphicsPath();
        p.AddArc(r.X, r.Y, rad * 2, rad * 2, 180, 90);
        p.AddArc(r.Right - rad * 2, r.Y, rad * 2, rad * 2, 270, 90);
        p.AddArc(r.Right - rad * 2, r.Bottom - rad * 2, rad * 2, rad * 2, 0, 90);
        p.AddArc(r.X, r.Bottom - rad * 2, rad * 2, rad * 2, 90, 90);
        p.CloseFigure();
        return p;
    }
}
