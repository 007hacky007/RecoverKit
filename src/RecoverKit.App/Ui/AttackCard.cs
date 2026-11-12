using Avalonia;
using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Layout;
using Avalonia.Media;

namespace RecoverKit.App.Ui;

/// <summary>
/// A selectable card for the wizard's attack choice: title, an optional time estimate badge and a
/// one-line description, plus optional extra content (the scenario list). Works like a radio button:
/// click or Space selects, the arrow keys move between cards of the same <see cref="AttackCardGroup"/>.
/// </summary>
internal sealed class AttackCard : Border
{
    private readonly TextBlock _badge = new() { FontSize = 11, FontWeight = FontWeight.Medium, VerticalAlignment = VerticalAlignment.Center };
    private readonly Border _badgeBox = new() { CornerRadius = new CornerRadius(999), Padding = new Thickness(7, 2), IsVisible = false, VerticalAlignment = VerticalAlignment.Center };
    private bool _selected, _hover;

    public AttackCardGroup Group { get; }
    public object Value { get; }

    public AttackCard(AttackCardGroup group, object value, string title, string description, Control? extra = null)
    {
        Group = group;
        Value = value;
        Focusable = true;
        IsTabStop = false;
        Cursor = new Cursor(StandardCursorType.Hand);
        CornerRadius = new CornerRadius(10);
        Padding = new Thickness(14, 11);
        BorderThickness = new Thickness(1);
        _badgeBox.Child = _badge;
        var head = new DockPanel();
        DockPanel.SetDock(_badgeBox, Dock.Right);
        _badgeBox.Margin = new Thickness(8, 0, 0, 0);
        head.Children.Add(_badgeBox);
        head.Children.Add(new TextBlock { Text = title, FontWeight = FontWeight.SemiBold, TextTrimming = TextTrimming.CharacterEllipsis, VerticalAlignment = VerticalAlignment.Center });
        var desc = new TextBlock { Text = description, FontSize = 12, Foreground = Palette.DimBrush, TextWrapping = TextWrapping.Wrap };
        var body = new StackPanel { Spacing = 4, Children = { head, desc } };
        if (extra is not null) { extra.Margin = new Thickness(0, 4, 0, 0); body.Children.Add(extra); }
        Child = body;
        Avalonia.Automation.AutomationProperties.SetName(this, title);
        Avalonia.Automation.AutomationProperties.SetHelpText(this, description);

        // Clicks on the scenario list inside the card select the card too.
        AddHandler(PointerPressedEvent, (_, _) => { Group.Select(this); if (!IsKeyboardFocusWithin) Focus(); }, Avalonia.Interactivity.RoutingStrategies.Bubble, handledEventsToo: true);
        PointerEntered += (_, _) => { _hover = true; Paint(); };
        PointerExited += (_, _) => { _hover = false; Paint(); };
        GotFocus += (_, _) => Paint();
        LostFocus += (_, _) => Paint();
        KeyDown += OnKeyDown;
        group.Add(this);
        Paint();
    }

    public bool IsSelected
    {
        get => _selected;
        set { _selected = value; IsTabStop = value; Paint(); }
    }

    /// <summary>Shows an estimate badge (green under an hour, amber under a day, red otherwise) or hides it.</summary>
    public void SetBadge(string? text, double seconds = 0, string? tip = null)
    {
        _badgeBox.IsVisible = text is not null;
        _badge.Text = text;
        ToolTip.SetTip(_badgeBox, tip);
        (_badgeBox.Background, _badge.Foreground) = seconds < 3600 ? (Palette.GoodSoftBrush, Palette.SuccessBrush)
            : seconds < 86400 ? (Palette.WarnSoftBrush, Palette.WarningBrush)
            : (Palette.BadSoftBrush, Palette.BadTextBrush);
    }

    private void OnKeyDown(object? sender, KeyEventArgs e)
    {
        if (!ReferenceEquals(e.Source, this)) return;   // keys for the scenario list stay there
        switch (e.Key)
        {
            case Key.Space: Group.Select(this); e.Handled = true; break;
            case Key.Left: e.Handled = Group.Move(this, -1, 0); break;
            case Key.Right: e.Handled = Group.Move(this, 1, 0); break;
            case Key.Up: e.Handled = Group.Move(this, 0, -1); break;
            case Key.Down: e.Handled = Group.Move(this, 0, 1); break;
        }
    }

    private void Paint()
    {
        bool focus = IsFocused;
        Background = _selected ? Palette.AccentSoftBrush : _hover ? Palette.CardHoverBrush : Palette.CardBrush;
        BorderBrush = _selected || focus ? Palette.AccentBrush : Palette.LineBrush;
        // Selected and keyboard focus both get the 2 px accent outline; the fill tells selection apart.
        bool strong = _selected || focus;
        BorderThickness = new Thickness(strong ? 2 : 1);
        Padding = new Thickness(strong ? 13 : 14, strong ? 10 : 11);
    }
}

/// <summary>The cards of one choice, laid out in a grid of <see cref="Columns"/> columns (cards may span both).</summary>
internal sealed class AttackCardGroup(int columns)
{
    private readonly List<AttackCard> _cards = new();

    public int Columns { get; } = columns;
    public AttackCard? Selected { get; private set; }
    public event Action<AttackCard>? SelectionChanged;

    internal void Add(AttackCard c) => _cards.Add(c);

    public void Select(AttackCard c)
    {
        if (ReferenceEquals(Selected, c)) return;
        foreach (var x in _cards) x.IsSelected = ReferenceEquals(x, c);
        Selected = c;
        SelectionChanged?.Invoke(c);
    }

    /// <summary>Arrow keys: moves selection and focus within the grid. False at the edge.</summary>
    public bool Move(AttackCard from, int dx, int dy)
    {
        int i = _cards.IndexOf(from);
        int row = Grid.GetRow(from), col = Grid.GetColumn(from);
        AttackCard? target = null;
        if (dy == 0)
        {
            int j = i + dx;
            if (j >= 0 && j < _cards.Count) target = _cards[j];
        }
        else
        {
            target = _cards.Where(c => Grid.GetRow(c) == row + dy)
                           .OrderBy(c => Math.Abs(Grid.GetColumn(c) - col)).FirstOrDefault();
        }
        if (target is null) return false;
        Select(target);
        target.Focus(NavigationMethod.Directional);
        return true;
    }
}
