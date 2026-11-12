using Avalonia;
using Avalonia.Media;
using Avalonia.Styling;

namespace RecoverKit.App.Ui;

/// <summary>
/// Colours for log text and chrome, picked for the theme that is active when the text is written
/// (light or dark, following the system).
/// </summary>
internal static class Palette
{
    public static bool Dark => Application.Current?.ActualThemeVariant == ThemeVariant.Dark;

    private static IBrush B(uint light, uint dark) => new SolidColorBrush(Color.FromUInt32(Dark ? dark : light));

    public static IBrush StepBrush => B(0xFF0046AA, 0xFF7DB2FF);
    public static IBrush WarningBrush => B(0xFFB05A00, 0xFFF2B35B);
    public static IBrush ErrorBrush => B(0xFFC80000, 0xFFFF7B72);
    public static IBrush SuccessBrush => B(0xFF007A00, 0xFF62D47E);
    public static IBrush DimBrush => B(0xFF5F6670, 0xFFA3AAB5);
    public static IBrush LinkBrush => B(0xFF0A62C9, 0xFF7DB2FF);
    public static IBrush TitleBrush => B(0xFF003399, 0xFF8FBBFF);
    public static IBrush LineBrush => B(0x33000000, 0x33FFFFFF);
    public static IBrush BandBrush => B(0x0A000000, 0x0FFFFFFF);
    public static IBrush PaneBrush => B(0xFFFFFFFF, 0xFF1E1F22);
    public static IBrush WindowBrush => B(0xFFF3F3F3, 0xFF2A2B2F);
}
