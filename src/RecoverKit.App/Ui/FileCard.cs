using Avalonia;
using Avalonia.Controls;
using Avalonia.Layout;
using Avalonia.Media;
using RecoverKit.Core.Formats;

namespace RecoverKit.App.Ui;

/// <summary>The opened file at a glance: a format tile, the file name, type and protection, and a status badge.</summary>
internal sealed class FileCard : Border
{
    public enum BadgeKind { Neutral, Accent, Good, Warn, Bad }

    private readonly Border _tile = new() { Width = 34, Height = 40, CornerRadius = new CornerRadius(5), VerticalAlignment = VerticalAlignment.Center };
    private readonly TextBlock _tileText = new() { FontWeight = FontWeight.Bold, Foreground = Brushes.White, HorizontalAlignment = HorizontalAlignment.Center, VerticalAlignment = VerticalAlignment.Center };
    private readonly TextBlock _name = new() { FontWeight = FontWeight.SemiBold, TextTrimming = TextTrimming.CharacterEllipsis };
    private readonly TextBlock _sub = new() { FontSize = 12, TextTrimming = TextTrimming.CharacterEllipsis };
    private readonly Border _badge = new() { CornerRadius = new CornerRadius(999), Padding = new Thickness(8, 3), VerticalAlignment = VerticalAlignment.Center };
    private readonly TextBlock _badgeText = new() { FontSize = 11 };

    public FileCard()
    {
        Padding = new Thickness(16, 12);
        Background = Palette.FileCardBrush;
        BorderBrush = Palette.LineBrush;
        BorderThickness = new Thickness(0, 0, 0, 1);
        _sub.Foreground = Palette.DimBrush;
        _tile.Child = _tileText;
        _badge.Child = _badgeText;
        var text = new StackPanel { Spacing = 1, VerticalAlignment = VerticalAlignment.Center, Children = { _name, _sub } };
        var row = new DockPanel();
        DockPanel.SetDock(_tile, Dock.Left);
        DockPanel.SetDock(_badge, Dock.Right);
        _tile.Margin = new Thickness(0, 0, 12, 0);
        _badge.Margin = new Thickness(12, 0, 0, 0);
        row.Children.Add(_tile);
        row.Children.Add(_badge);
        row.Children.Add(text);
        Child = row;
    }

    public void Show(Detection det)
    {
        var (label, color) = TileFor(det);
        _tileText.Text = label;
        _tileText.FontSize = label.Length switch { 1 => 14, 2 => 12, 3 => 10.5, _ => 9 };
        _tile.Background = new SolidColorBrush(Color.FromUInt32(color));
        _name.Text = Path.GetFileName(det.FilePath);
        ToolTip.SetTip(_name, det.FilePath);
        var parts = new List<string> { det.TypeName };
        if (det.Target is { } t)
        {
            if (t.Protection.Length > 0 && t.Protection != det.TypeName) parts.Add(t.Protection);
            if (t.Modes.Count > 0) parts.Add("hashcat mode " + string.Join(", ", t.Modes));
            SetBadge(Fmt.SpeedClass(t.Speed) + " to recover", BadgeKind.Neutral);
        }
        else SetBadge("Not protected", BadgeKind.Warn);
        _sub.Text = string.Join("  ·  ", parts.Where(p => p.Length > 0));
        ToolTip.SetTip(_sub, _sub.Text);
    }

    public void SetBadge(string? text, BadgeKind kind = BadgeKind.Neutral)
    {
        _badge.IsVisible = !string.IsNullOrEmpty(text);
        _badgeText.Text = text;
        (_badge.Background, _badgeText.Foreground) = kind switch
        {
            BadgeKind.Accent => (Palette.AccentSoftBrush, Palette.StepBrush),
            BadgeKind.Good => (Palette.GoodSoftBrush, Palette.SuccessBrush),
            BadgeKind.Warn => (Palette.WarnSoftBrush, Palette.WarningBrush),
            BadgeKind.Bad => (Palette.BadSoftBrush, Palette.BadTextBrush),
            _ => (Palette.ChipBrush, Palette.DimBrush),
        };
    }

    /// <summary>A short label and colour for the file's format (Office colours for Word, Excel and PowerPoint).</summary>
    internal static (string Label, uint Color) TileFor(Detection det)
    {
        var name = Path.GetFileName(det.FilePath);
        var ext = Path.GetExtension(det.FilePath).TrimStart('.').ToLowerInvariant();
        string type = det.TypeName;
        if (ext is "doc" or "docx" or "docm" or "dot" or "dotx" || type.Contains("Word", StringComparison.OrdinalIgnoreCase)) return ("W", 0xFF2B5797);
        if (ext is "xls" or "xlsx" or "xlsm" or "xlsb" || type.Contains("Excel", StringComparison.OrdinalIgnoreCase)) return ("X", 0xFF217346);
        if (ext is "ppt" or "pptx" or "pptm" || type.Contains("PowerPoint", StringComparison.OrdinalIgnoreCase)) return ("P", 0xFFB7472A);
        if (ext == "pdf" || det.Target?.FormatId.StartsWith("PDF", StringComparison.Ordinal) == true) return ("PDF", 0xFFC4302B);
        if (ext.StartsWith("od", StringComparison.Ordinal) || ext.StartsWith("sx", StringComparison.Ordinal)) return ("OD", 0xFF1E7FA8);
        if (ext is "zip" or "zipx") return ("ZIP", 0xFF7A5AA6);
        if (ext == "rar") return ("RAR", 0xFF8A4FB0);
        if (ext is "22000" or "hccapx" or "hccap" || det.Target?.FormatId == "WPAH") return ("WiFi", 0xFF0F8A7E);
        if (name.Equals("Manifest.plist", StringComparison.OrdinalIgnoreCase) || ext == "plist") return ("iOS", 0xFF5B6575);
        if (ext == "ipd") return ("BB", 0xFF3A3F47);
        if (ext == "exe") return ("EXE", 0xFF5B6575);
        if (type.Contains("VeraCrypt", StringComparison.OrdinalIgnoreCase)) return ("VC", 0xFF2E6B4F);
        if (type.Contains("TrueCrypt", StringComparison.OrdinalIgnoreCase)) return ("TC", 0xFF2E6B4F);
        var e = ext.Length is > 0 and <= 4 ? ext.ToUpperInvariant() : "#";
        return (e, 0xFF5B6575);
    }
}
