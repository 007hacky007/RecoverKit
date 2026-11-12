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

    // Main window surfaces and live attack view.
    public static IBrush ForegroundBrush => B(0xFF1B1E24, 0xFFE9EAED);
    public static IBrush AccentBrush => B(0xFF0A6CF0, 0xFF2F86FF);
    public static IBrush AccentSoftBrush => B(0x1A0A6CF0, 0x2E2F86FF);
    public static IBrush AccentHoverBrush => B(0x0F0A6CF0, 0x0F2F86FF);
    public static IBrush GoodBrush => B(0xFF1E9E55, 0xFF62D47E);
    public static IBrush GoodSoftBrush => B(0x1A1E9E55, 0x1A62D47E);
    public static IBrush GoodBorderBrush => B(0x591E9E55, 0x5962D47E);
    public static IBrush WarnBrush => B(0xFFD98A00, 0xFFF2B35B);
    public static IBrush WarnSoftBrush => B(0x1FD98A00, 0x21F2B35B);
    public static IBrush WarnBorderBrush => B(0x66D98A00, 0x59F2B35B);
    public static IBrush BadTextBrush => B(0xFFC62828, 0xFFFF9A92);
    public static IBrush BadSoftBrush => B(0x1AC62828, 0x24FF7B72);
    public static IBrush TrackBrush => B(0x14000000, 0x14FFFFFF);
    public static IBrush ChipBrush => B(0x0D000000, 0x0FFFFFFF);
    public static IBrush DashBrush => B(0x40000000, 0x2EFFFFFF);
    public static IBrush InsetBrush => B(0x08000000, 0x40000000);
    public static IBrush CardBrush => B(0xFFFFFFFF, 0x08FFFFFF);
    public static IBrush CardHoverBrush => B(0x08000000, 0x0FFFFFFF);
    public static IBrush ToastBrush => B(0xFF2F3136, 0xFF3A3B40);
    public static IBrush StatusBandBrush => B(0xFFEBECEF, 0xFF313236);
    public static IBrush FileCardBrush => B(0x05000000, 0x05FFFFFF);

    public static Color AccentColor => Color.FromUInt32(Dark ? 0xFF2F86FFu : 0xFF0A6CF0u);
}
