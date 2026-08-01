using System.Drawing.Drawing2D;
using LightGuard.Core;

namespace LightGuard.UI.Pages;

/// <summary>
/// 页面基类 - 所有内容页面的父类
/// 提供标题、滚动、主题适配等公共功能
/// </summary>
public abstract class Page : Panel
{
    protected readonly AppState AppState;
    protected readonly Label TitleLabel;
    protected readonly Label SubtitleLabel;
    protected readonly Panel ScrollContent;

    protected Page(AppState appState, string title, string subtitle = "")
    {
        AppState = appState;
        DoubleBuffered = true;
        BackColor = Theme.Background;

        // 标题
        TitleLabel = new Label
        {
            Text = title,
            Font = Theme.TitleFont,
            ForeColor = Theme.TextPrimary,
            Location = new Point(24, 16),
            Size = new Size(600, 28),
            BackColor = Color.Transparent
        };
        Controls.Add(TitleLabel);

        // 副标题
        SubtitleLabel = new Label
        {
            Text = subtitle,
            Font = Theme.SmallFont,
            ForeColor = Theme.TextSecondary,
            Location = new Point(24, 46),
            Size = new Size(600, 18),
            BackColor = Color.Transparent
        };
        Controls.Add(SubtitleLabel);

        // 可滚动内容区
        ScrollContent = new Panel
        {
            Location = new Point(24, 76),
            Size = new Size(Width - 48, Height - 100),
            BackColor = Color.Transparent,
            AutoScroll = true
        };
        Controls.Add(ScrollContent);

        Resize += (s, e) =>
        {
            ScrollContent.Size = new Size(Width - 48, Height - 100);
            OnResized();
        };
    }

    /// <summary>页面被导航到时调用</summary>
    public virtual void OnShown() { }

    /// <summary>窗口大小变化时调用</summary>
    protected virtual void OnResized() { }

    /// <summary>刷新页面数据</summary>
    public virtual void RefreshData() { }

    /// <summary>创建一个带圆角背景的卡片面板</summary>
    protected Panel CreateCard(int x, int y, int width, int height)
    {
        var card = new Panel
        {
            Location = new Point(x, y),
            Size = new Size(width, height),
            BackColor = Color.Transparent
        };
        // 通过反射启用双缓冲（DoubleBuffered 是受保护成员，无法直接在 Panel 实例上设置）
        typeof(Control).GetProperty("DoubleBuffered",
            System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)
            ?.SetValue(card, true, null);
        card.Paint += (s, e) =>
        {
            var g = e.Graphics;
            g.SmoothingMode = SmoothingMode.AntiAlias;
            using var brush = new SolidBrush(Theme.CardBg);
            Theme.FillRoundedRect(g, brush, card.ClientRectangle, Theme.CardRadius);
            using var pen = new Pen(Theme.Border, 1);
            Theme.DrawRoundedBorder(g, pen, card.ClientRectangle, Theme.CardRadius);
        };
        ScrollContent.Controls.Add(card);
        return card;
    }

    /// <summary>创建分区标题</summary>
    protected Label CreateSectionTitle(string text, int x, int y)
    {
        var label = new Label
        {
            Text = text,
            Font = Theme.HeaderFont,
            ForeColor = Theme.TextPrimary,
            Location = new Point(x, y),
            Size = new Size(400, 24),
            BackColor = Color.Transparent
        };
        ScrollContent.Controls.Add(label);
        return label;
    }
}
