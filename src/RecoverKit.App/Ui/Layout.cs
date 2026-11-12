using Avalonia;
using Avalonia.Controls;
using Avalonia.Layout;
using Avalonia.Media;
using Avalonia.Styling;

namespace RecoverKit.App.Ui;

/// <summary>Small builders that keep the code-only views short (no XAML).</summary>
internal static class L
{
    /// <summary>A grid with the given column definitions (e.g. "38*,22*,22*,18*"); rows are added on demand.</summary>
    public static Grid Grid(string columns, double rowSpacing = 6, double columnSpacing = 8)
        => new() { ColumnDefinitions = new ColumnDefinitions(columns), RowSpacing = rowSpacing, ColumnSpacing = columnSpacing };

    /// <summary>Places <paramref name="c"/> in the grid, adding Auto rows as needed.</summary>
    public static T Put<T>(this Grid g, T c, int row, int col, int colSpan = 1, int rowSpan = 1) where T : Control
    {
        while (g.RowDefinitions.Count < row + rowSpan) g.RowDefinitions.Add(new RowDefinition(GridLength.Auto));
        Avalonia.Controls.Grid.SetRow(c, row);
        Avalonia.Controls.Grid.SetColumn(c, col);
        Avalonia.Controls.Grid.SetColumnSpan(c, colSpan);
        Avalonia.Controls.Grid.SetRowSpan(c, rowSpan);
        g.Children.Add(c);
        return c;
    }

    public static TextBlock Text(string s, bool dim = false, bool bold = false, bool wrap = false, double size = 0)
    {
        var t = new TextBlock { Text = s, VerticalAlignment = VerticalAlignment.Center, TextWrapping = wrap ? TextWrapping.Wrap : TextWrapping.NoWrap };
        if (dim) t.Foreground = Palette.DimBrush;
        if (bold) t.FontWeight = FontWeight.SemiBold;
        if (size > 0) t.FontSize = size;
        return t;
    }

    public static Button Button(string text, Action click, double minWidth = 84, bool isDefault = false, bool isCancel = false)
    {
        var b = new Button { Content = text, MinWidth = minWidth, IsDefault = isDefault, IsCancel = isCancel, HorizontalContentAlignment = HorizontalAlignment.Center };
        if (isDefault) b.Classes.Add("accent");
        b.Click += (_, _) => click();
        return b;
    }

    public static StackPanel Row(params Control[] children)
    {
        var p = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 8 };
        foreach (var c in children) p.Children.Add(c);
        return p;
    }

    public static StackPanel Column(double spacing, params Control[] children)
    {
        var p = new StackPanel { Orientation = Orientation.Vertical, Spacing = spacing };
        foreach (var c in children) p.Children.Add(c);
        return p;
    }

    /// <summary>A titled group (WinForms GroupBox).</summary>
    public static Control Group(string title, Control content)
    {
        var body = new Border
        {
            BorderBrush = Palette.LineBrush, BorderThickness = new Thickness(1), CornerRadius = new CornerRadius(6),
            Padding = new Thickness(12, 10), Child = content,
        };
        if (title.Length == 0) return body;
        return Column(4, Text(title, bold: true), body);
    }

    /// <summary>Right-aligned dialog buttons in a footer band.</summary>
    public static Border Footer(params Control[] buttons)
    {
        var row = Row(buttons);
        row.HorizontalAlignment = HorizontalAlignment.Right;
        return new Border { Padding = new Thickness(16, 12), Background = Palette.BandBrush, BorderBrush = Palette.LineBrush, BorderThickness = new Thickness(0, 1, 0, 0), Child = row };
    }

    public static NumericUpDown Number(int min, int max, int value, double width = 130) => new()
    {
        Minimum = min, Maximum = max, Value = Math.Clamp(value, min, max), Increment = 1, FormatString = "0", MinWidth = width,
        ParsingNumberStyle = System.Globalization.NumberStyles.Integer, HorizontalAlignment = HorizontalAlignment.Left,
    };

    public static int IntValue(this NumericUpDown n) => (int)(n.Value ?? n.Minimum);
}

/// <summary>App-wide style tweaks on top of the Fluent theme.</summary>
internal static class Styles
{
    public static readonly FontFamily Mono = new("Menlo, SF Mono, Consolas, Cascadia Mono, monospace");

    /// <summary>Digits of equal width, so counters do not jitter while they change.</summary>
    public static FontFeatureCollection TabularDigits => [FontFeature.Parse("tnum")];

    public static Avalonia.Styling.Styles App()
    {
        var s = new Avalonia.Styling.Styles();
        s.Add(new Style(x => x.OfType<Window>()) { Setters = { new Setter(Avalonia.Controls.Primitives.TemplatedControl.FontSizeProperty, 13.0), new Setter(Avalonia.Controls.Primitives.TemplatedControl.BackgroundProperty, Palette.WindowBrush) } });
        // Toolbar buttons: flat with a rounded hover plate; Start uses the accent class when it is the next step.
        s.Add(new Style(x => x.OfType<Button>().Class("tool"))
        {
            Setters = { new Setter(Avalonia.Controls.Primitives.TemplatedControl.CornerRadiusProperty, new CornerRadius(7)) },
        });
        s.Add(new Style(x => x.OfType<Button>().Class("tool").Not(y => y.Class("accent")))
        {
            Setters =
            {
                new Setter(Avalonia.Controls.Primitives.TemplatedControl.BackgroundProperty, Brushes.Transparent),
                new Setter(Avalonia.Controls.Primitives.TemplatedControl.BorderThicknessProperty, new Thickness(0)),
            },
        });
        s.Add(new Style(x => x.OfType<Button>().Class("tool").Class(":disabled").Template().OfType<Avalonia.Controls.Presenters.ContentPresenter>())
        {
            Setters =
            {
                new Setter(Avalonia.Controls.Presenters.ContentPresenter.BackgroundProperty, Brushes.Transparent),
                new Setter(Visual.OpacityProperty, 0.45),
            },
        });
        return s;
    }
}
