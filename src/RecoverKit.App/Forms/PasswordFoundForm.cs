namespace RecoverKit.App.Forms;

/// <summary>Shows recovered password(s) with a copy button.</summary>
public sealed class PasswordFoundForm : Form
{
    public PasswordFoundForm(IReadOnlyList<string> passwords)
    {
        Text = "Password found";
        Font = new Font("Segoe UI", 9f);
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = MinimizeBox = false;
        ShowInTaskbar = false;
        StartPosition = FormStartPosition.CenterParent;
        ClientSize = new Size(420, 170);

        var t = new TableLayoutPanel { Dock = DockStyle.Fill, Padding = new Padding(16), ColumnCount = 1, RowCount = 3 };
        t.Controls.Add(new Label { Text = "The password was successfully recovered:", AutoSize = true });
        var box = new TextBox
        {
            ReadOnly = true, Dock = DockStyle.Fill, Font = new Font("Consolas", 14f, FontStyle.Bold),
            Text = string.Join(Environment.NewLine, passwords.Select(p => p.Length == 0 ? "(empty password)" : p)),
            Multiline = passwords.Count > 1, ScrollBars = passwords.Count > 1 ? ScrollBars.Vertical : ScrollBars.None, Height = 40,
        };
        t.Controls.Add(box);
        var buttons = new FlowLayoutPanel { Dock = DockStyle.Fill, FlowDirection = FlowDirection.RightToLeft };
        var ok = new Button { Text = "OK", DialogResult = DialogResult.OK, Width = 80 };
        var copy = new Button { Text = "&Copy", Width = 80 };
        copy.Click += (_, _) => { if (passwords.Count > 0) Clipboard.SetText(passwords[0]); };
        buttons.Controls.Add(ok);
        buttons.Controls.Add(copy);
        t.Controls.Add(buttons);
        Controls.Add(t);
        AcceptButton = ok;
    }
}
