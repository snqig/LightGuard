using System.Drawing.Drawing2D;

namespace LightGuard.UI.Controls;

/// <summary>
/// 侧边栏导航按钮 - Fluent 风格
/// </summary>
public class SidebarButton : Control
{
    private bool _isActive;
    private bool _isHovered;
    private readonly string _icon;

    public event Action? NavClicked;

    public string NavKey { get; }

    /// <summary>是否禁用（非管理员灰化的高危功能入口）。禁用时不响应悬停/点击。</summary>
    public bool Disabled { get; set; }

    public bool IsActive
    {
        get => _isActive;
        set { _isActive = value; Invalidate(); }
    }

    public SidebarButton(string text, string icon, string navKey)
    {
        _icon = icon;
        NavKey = navKey;
        Text = text;
        Size = new Size(180, 40);
        Cursor = Cursors.Hand;
        DoubleBuffered = true;
        Font = Theme.BodyFont;
    }

    protected override void OnMouseEnter(EventArgs e)
    {
        if (Disabled) return;
        _isHovered = true; Invalidate();
    }

    protected override void OnMouseLeave(EventArgs e) { _isHovered = false; Invalidate(); }

    protected override void OnClick(EventArgs e)
    {
        base.OnClick(e);
        if (Disabled) return;
        NavClicked?.Invoke();
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        var g = e.Graphics;
        g.SmoothingMode = SmoothingMode.AntiAlias;
        g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.ClearTypeGridFit;

        // P1-4 DPI 适配：手绘文字按当前 DPI 放大，避免高分屏下偏小
        using var iconFont = Theme.DpiFont(Theme.HeaderFont, this);
        using var textFont = Theme.DpiFont(Font, this);

        // 禁用态：灰色背景 + 全灰文字，不响应激活/悬停视觉
        if (Disabled)
        {
            using var disabledBgBrush = new SolidBrush(Theme.DisabledBg);
            Theme.FillRoundedRect(g, disabledBgBrush, ClientRectangle, 4);
            using var disabledIconBrush = new SolidBrush(Theme.TextTertiary);
            var disabledIconRect = new Rectangle(16, 0, 24, Height);
            Theme.DrawCenteredText(g, _icon, iconFont, disabledIconBrush, disabledIconRect);
            using var disabledTextBrush = new SolidBrush(Theme.TextTertiary);
            Theme.DrawLeftText(g, Text + "  🔒", textFont, disabledTextBrush, new Rectangle(44, 0, Width - 52, Height), 0);
            return;
        }

        // 背景
        if (_isActive)
        {
            using var brush = new SolidBrush(Theme.AccentLight);
            Theme.FillRoundedRect(g, brush, ClientRectangle, 4);
        }
        else if (_isHovered)
        {
            using var brush = new SolidBrush(Theme.CardHover);
            Theme.FillRoundedRect(g, brush, ClientRectangle, 4);
        }

        // 左侧强调条
        if (_isActive)
        {
            using var pen = new Pen(Theme.Accent, 3);
            g.DrawLine(pen, 3, 10, 3, Height - 10);
        }

        // 图标（简单Unicode符号）
        using var iconBrush = new SolidBrush(_isActive ? Theme.Accent : Theme.TextSecondary);
        var iconRect = new Rectangle(16, 0, 24, Height);
        Theme.DrawCenteredText(g, _icon, iconFont, iconBrush, iconRect);

        // 文字
        using var textBrush = new SolidBrush(_isActive ? Theme.TextPrimary : Theme.TextSecondary);
        Theme.DrawLeftText(g, Text, textFont, textBrush, new Rectangle(44, 0, Width - 52, Height), 0);
    }
}

/// <summary>
/// 开关切换控件 - Fluent Toggle 风格
/// </summary>
public class ToggleSwitch : Control
{
    private bool _isOn;
    private bool _isHovered;

    public event Action<bool>? Toggled;

    public bool IsOn
    {
        get => _isOn;
        set
        {
            if (_isOn != value)
            {
                _isOn = value;
                Toggled?.Invoke(_isOn);
                Invalidate();
            }
            else { _isOn = value; Invalidate(); }
        }
    }

    public ToggleSwitch()
    {
        Size = new Size(Theme.ToggleWidth, Theme.ToggleHeight);
        Cursor = Cursors.Hand;
        DoubleBuffered = true;
    }

    protected override void OnMouseEnter(EventArgs e) { _isHovered = true; Invalidate(); }
    protected override void OnMouseLeave(EventArgs e) { _isHovered = false; Invalidate(); }

    protected override void OnClick(EventArgs e)
    {
        IsOn = !_isOn;
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        var g = e.Graphics;
        g.SmoothingMode = SmoothingMode.AntiAlias;

        var rect = new Rectangle(0, 0, Width - 1, Height - 1);
        var radius = Height / 2;

        // 轨道
        Color trackColor = _isOn ? Theme.Accent : (_isHovered ? Theme.CardHover : Theme.Border);
        using var trackBrush = new SolidBrush(trackColor);
        Theme.FillRoundedRect(g, trackBrush, rect, radius);

        // 滑块
        int knobSize = Height - 6;
        int knobX = _isOn ? Width - knobSize - 3 : 3;
        var knobRect = new Rectangle(knobX, 3, knobSize, knobSize);
        using var knobBrush = new SolidBrush(Theme.TextPrimary);
        g.FillEllipse(knobBrush, knobRect);
    }
}

/// <summary>
/// 强调色按钮 - Fluent Button 风格
/// </summary>
public class AccentButton : Control
{
    private bool _isHovered;
    private bool _isPressed;
    private bool _isEnabled = true;

    public new event Action? Click;

    public new bool Enabled
    {
        get => _isEnabled;
        set { _isEnabled = value; Invalidate(); }
    }

    public AccentButton()
    {
        Size = new Size(120, 36);
        Cursor = Cursors.Hand;
        DoubleBuffered = true;
        Font = Theme.ButtonFont;
    }

    protected override void OnMouseEnter(EventArgs e) { _isHovered = true; Invalidate(); }
    protected override void OnMouseLeave(EventArgs e) { _isHovered = false; _isPressed = false; Invalidate(); }
    protected override void OnMouseDown(MouseEventArgs e) { _isPressed = true; Invalidate(); }
    protected override void OnMouseUp(MouseEventArgs e) { _isPressed = false; Invalidate(); }

    protected override void OnClick(EventArgs e)
    {
        if (_isEnabled) Click?.Invoke();
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        var g = e.Graphics;
        g.SmoothingMode = SmoothingMode.AntiAlias;
        g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.ClearTypeGridFit;

        Color bgColor;
        if (!_isEnabled)
            bgColor = Theme.Border;
        else if (_isPressed)
            bgColor = Color.FromArgb(0, 90, 170);
        else if (_isHovered)
            bgColor = Theme.AccentHover;
        else
            bgColor = Theme.Accent;

        using var brush = new SolidBrush(bgColor);
        Theme.FillRoundedRect(g, brush, ClientRectangle, Theme.ButtonRadius);

        // 文字（P1-4 DPI 适配：手绘文字按当前 DPI 放大）
        using var textFont = Theme.DpiFont(Font, this);
        using var textBrush = new SolidBrush(Color.White);
        Theme.DrawCenteredText(g, Text, textFont, textBrush, ClientRectangle);
    }
}

/// <summary>
/// 模块卡片控件 - 显示模块状态和开关
/// </summary>
public class ModuleCard : Panel
{
    private bool _isHovered;
    private readonly ToggleSwitch _toggle;
    private readonly Label _titleLabel;
    private readonly Label _descLabel;
    private readonly Label _statusLabel;

    public event Action<bool>? ToggleChanged;

    public string ModuleId { get; }
    public string ModuleName { get; }
    public string ModuleDesc { get; }
    public bool ModuleEnabled
    {
        get => _toggle.IsOn;
        set => _toggle.IsOn = value;
    }

    public ModuleCard(string id, string name, string desc, string status, bool enabled)
    {
        ModuleId = id;
        ModuleName = name;
        ModuleDesc = desc;

        Size = new Size(360, 90);
        BackColor = Color.Transparent;
        DoubleBuffered = true;
        Cursor = Cursors.Hand;

        _titleLabel = new Label
        {
            Text = name,
            Font = Theme.HeaderFont,
            ForeColor = Theme.TextPrimary,
            Location = new Point(16, 12),
            Size = new Size(260, 22),
            BackColor = Color.Transparent
        };
        Controls.Add(_titleLabel);

        _descLabel = new Label
        {
            Text = desc,
            Font = Theme.SmallFont,
            ForeColor = Theme.TextSecondary,
            Location = new Point(16, 36),
            Size = new Size(280, 18),
            BackColor = Color.Transparent
        };
        Controls.Add(_descLabel);

        _statusLabel = new Label
        {
            Text = status,
            Font = Theme.SmallFont,
            ForeColor = enabled ? Theme.Success : Theme.TextTertiary,
            Location = new Point(16, 58),
            Size = new Size(200, 16),
            BackColor = Color.Transparent
        };
        Controls.Add(_statusLabel);

        _toggle = new ToggleSwitch
        {
            Location = new Point(Width - 52, 35)
        };
        _toggle.IsOn = enabled;
        _toggle.Toggled += (on) => ToggleChanged?.Invoke(on);
        Controls.Add(_toggle);
    }

    public void UpdateStatus(string status, bool enabled)
    {
        _statusLabel.Text = status;
        _statusLabel.ForeColor = enabled ? Theme.Success : Theme.TextTertiary;
        _toggle.IsOn = enabled;
    }

    protected override void OnMouseEnter(EventArgs e) { _isHovered = true; Invalidate(); }
    protected override void OnMouseLeave(EventArgs e) { _isHovered = false; Invalidate(); }

    protected override void OnPaint(PaintEventArgs e)
    {
        var g = e.Graphics;
        g.SmoothingMode = SmoothingMode.AntiAlias;

        var bgColor = _isHovered ? Theme.CardHover : Theme.CardBg;
        using var brush = new SolidBrush(bgColor);
        Theme.FillRoundedRect(g, brush, ClientRectangle, Theme.CardRadius);

        using var borderPen = new Pen(Theme.Border, 1);
        Theme.DrawRoundedBorder(g, borderPen, ClientRectangle, Theme.CardRadius);
    }
}

/// <summary>
/// 信息卡片 - 用于展示统计信息、系统状态等
/// </summary>
public class InfoCard : Panel
{
    private bool _isHovered;

    public InfoCard(string title, string value, string? subtitle = null)
    {
        Size = new Size(170, 80);
        BackColor = Color.Transparent;
        DoubleBuffered = true;

        var titleLabel = new Label
        {
            Text = title,
            Font = Theme.SmallFont,
            ForeColor = Theme.TextSecondary,
            Location = new Point(12, 8),
            Size = new Size(Width - 24, 18),
            BackColor = Color.Transparent
        };
        Controls.Add(titleLabel);

        var valueLabel = new Label
        {
            Text = value,
            Font = new Font("Microsoft YaHei UI", 20F, FontStyle.Bold, GraphicsUnit.Pixel),
            ForeColor = Theme.Accent,
            Location = new Point(12, 28),
            Size = new Size(Width - 24, 28),
            BackColor = Color.Transparent
        };
        Controls.Add(valueLabel);

        if (subtitle != null)
        {
            var subLabel = new Label
            {
                Text = subtitle,
                Font = Theme.SmallFont,
                ForeColor = Theme.TextTertiary,
                Location = new Point(12, 58),
                Size = new Size(Width - 24, 16),
                BackColor = Color.Transparent
            };
            Controls.Add(subLabel);
        }
    }

    protected override void OnMouseEnter(EventArgs e) { _isHovered = true; Invalidate(); }
    protected override void OnMouseLeave(EventArgs e) { _isHovered = false; Invalidate(); }

    protected override void OnPaint(PaintEventArgs e)
    {
        var g = e.Graphics;
        g.SmoothingMode = SmoothingMode.AntiAlias;

        var bgColor = _isHovered ? Theme.CardHover : Theme.CardBg;
        using var brush = new SolidBrush(bgColor);
        Theme.FillRoundedRect(g, brush, ClientRectangle, Theme.CardRadius);

        using var borderPen = new Pen(Theme.Border, 1);
        Theme.DrawRoundedBorder(g, borderPen, ClientRectangle, Theme.CardRadius);
    }
}

/// <summary>
/// 分组面板 - 带标题的区域容器
/// </summary>
public class GroupPanel : Panel
{
    private readonly Label _titleLabel;

    public string GroupTitle
    {
        get => _titleLabel.Text;
        set => _titleLabel.Text = value;
    }

    public GroupPanel(string title)
    {
        BackColor = Color.Transparent;
        DoubleBuffered = true;
        Padding = new Padding(0, 28, 0, 0);

        _titleLabel = new Label
        {
            Text = title,
            Font = Theme.HeaderFont,
            ForeColor = Theme.TextPrimary,
            Location = new Point(0, 0),
            Size = new Size(400, 24),
            BackColor = Color.Transparent
        };
        Controls.Add(_titleLabel);
    }
}
