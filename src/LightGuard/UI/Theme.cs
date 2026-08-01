using System.Drawing.Drawing2D;
using LightGuard.Core;

namespace LightGuard.UI;

/// <summary>
/// 全局主题系统 - Win11 现代 Fluent 风格
/// 支持高配(深色+Mica)和低配(浅色极简)双模式
/// </summary>
public static class Theme
{
    // ===== 深色主题（高配默认） =====
    public static class Dark
    {
        public static readonly Color Background = Color.FromArgb(32, 32, 32);        // #202020
        public static readonly Color SidebarBg = Color.FromArgb(28, 28, 28);          // #1C1C1C
        public static readonly Color CardBg = Color.FromArgb(45, 45, 45);             // #2D2D2D
        public static readonly Color CardHover = Color.FromArgb(55, 55, 55);          // #373737
        public static readonly Color Border = Color.FromArgb(60, 60, 60);             // #3C3C3C
        public static readonly Color Accent = Color.FromArgb(0, 120, 212);            // #0078D4
        public static readonly Color AccentHover = Color.FromArgb(20, 140, 232);      // #148CE8
        public static readonly Color AccentLight = Color.FromArgb(0, 120, 212, 40);   // 半透明强调
        public static readonly Color TextPrimary = Color.FromArgb(255, 255, 255);     // #FFFFFF
        public static readonly Color TextSecondary = Color.FromArgb(180, 180, 180);   // #B4B4B4
        public static readonly Color TextTertiary = Color.FromArgb(120, 120, 120);    // #787878
        public static readonly Color Success = Color.FromArgb(76, 175, 80);           // #4CAF50
        public static readonly Color Warning = Color.FromArgb(255, 152, 0);           // #FF9800
        public static readonly Color Error = Color.FromArgb(244, 67, 54);             // #F44336
        public static readonly Color TitleBar = Color.FromArgb(24, 24, 24);           // #181818
    }

    // ===== 浅色主题（低配） =====
    public static class Light
    {
        public static readonly Color Background = Color.FromArgb(243, 243, 243);      // #F3F3F3
        public static readonly Color SidebarBg = Color.FromArgb(238, 238, 238);       // #EEEEEE
        public static readonly Color CardBg = Color.FromArgb(255, 255, 255);          // #FFFFFF
        public static readonly Color CardHover = Color.FromArgb(245, 245, 245);       // #F5F5F5
        public static readonly Color Border = Color.FromArgb(224, 224, 224);          // #E0E0E0
        public static readonly Color Accent = Color.FromArgb(0, 120, 212);            // #0078D4
        public static readonly Color AccentHover = Color.FromArgb(20, 140, 232);      // #148CE8
        public static readonly Color AccentLight = Color.FromArgb(0, 120, 212, 30);
        public static readonly Color TextPrimary = Color.FromArgb(32, 32, 32);        // #202020
        public static readonly Color TextSecondary = Color.FromArgb(96, 96, 96);      // #606060
        public static readonly Color TextTertiary = Color.FromArgb(140, 140, 140);    // #8C8C8C
        public static readonly Color Success = Color.FromArgb(46, 125, 50);           // #2E7D32
        public static readonly Color Warning = Color.FromArgb(230, 81, 0);            // #E65100
        public static readonly Color Error = Color.FromArgb(183, 28, 28);             // #B71C1C
        public static readonly Color TitleBar = Color.FromArgb(248, 248, 248);        // #F8F8F8
    }

    // ===== 当前主题（运行时切换） =====
    private static bool _isDark = true;
    private static bool _autoFollowSystem = true;

    public static bool IsDark
    {
        get => _isDark;
        set { _isDark = value; ThemeChanged?.Invoke(); }
    }

    /// <summary>是否自动跟随系统主题</summary>
    public static bool AutoFollowSystem
    {
        get => _autoFollowSystem;
        set
        {
            _autoFollowSystem = value;
            if (value) SyncWithSystem();
        }
    }

    /// <summary>
    /// 检测 Windows 系统当前是否为深色模式
    /// 读取注册表 HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize\AppsUseLightTheme
    /// 0 = 深色, 1 = 浅色
    /// </summary>
    public static bool IsSystemDarkMode()
    {
        try
        {
            using var key = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(
                @"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize");
            if (key != null)
            {
                var value = key.GetValue("AppsUseLightTheme");
                if (value is int i)
                    return i == 0; // 0=深色, 1=浅色
            }
        }
        catch { }
        return true; // 默认深色
    }

    /// <summary>
    /// 同步主题与系统设置
    /// </summary>
    public static void SyncWithSystem()
    {
        _isDark = IsSystemDarkMode();
        ThemeChanged?.Invoke();
    }

    public static event Action? ThemeChanged;

    // 便捷访问
    public static Color Background => _isDark ? Dark.Background : Light.Background;
    public static Color SidebarBg => _isDark ? Dark.SidebarBg : Light.SidebarBg;
    public static Color CardBg => _isDark ? Dark.CardBg : Light.CardBg;
    public static Color CardHover => _isDark ? Dark.CardHover : Light.CardHover;
    public static Color Border => _isDark ? Dark.Border : Light.Border;
    public static Color Accent => Dark.Accent;
    public static Color AccentHover => Dark.AccentHover;
    public static Color AccentLight => _isDark ? Dark.AccentLight : Light.AccentLight;
    public static Color TextPrimary => _isDark ? Dark.TextPrimary : Light.TextPrimary;
    public static Color TextSecondary => _isDark ? Dark.TextSecondary : Light.TextSecondary;
    public static Color TextTertiary => _isDark ? Dark.TextTertiary : Light.TextTertiary;
    public static Color Success => _isDark ? Dark.Success : Light.Success;
    public static Color Warning => _isDark ? Dark.Warning : Light.Warning;
    public static Color Error => _isDark ? Dark.Error : Light.Error;
    public static Color TitleBar => _isDark ? Dark.TitleBar : Light.TitleBar;

    // ===== 字体 =====
    private static Font? _titleFont;
    private static Font? _headerFont;
    private static Font? _bodyFont;
    private static Font? _smallFont;
    private static Font? _buttonFont;

    public static Font TitleFont => _titleFont ??= new Font("Microsoft YaHei UI", 18F, FontStyle.Bold, GraphicsUnit.Pixel);
    public static Font HeaderFont => _headerFont ??= new Font("Microsoft YaHei UI", 14F, FontStyle.Bold, GraphicsUnit.Pixel);
    public static Font BodyFont => _bodyFont ??= new Font("Microsoft YaHei UI", 12F, FontStyle.Regular, GraphicsUnit.Pixel);
    public static Font SmallFont => _smallFont ??= new Font("Microsoft YaHei UI", 10F, FontStyle.Regular, GraphicsUnit.Pixel);
    public static Font ButtonFont => _buttonFont ??= new Font("Microsoft YaHei UI", 12F, FontStyle.Regular, GraphicsUnit.Pixel);

    // ===== 尺寸 =====
    public const int SidebarWidth = 200;
    public const int TitleBarHeight = 40;
    public const int CardRadius = 8;
    public const int ButtonRadius = 6;
    public const int ToggleWidth = 40;
    public const int ToggleHeight = 20;

    // ===== 绘图辅助 =====

    /// <summary>
    /// 绘制圆角矩形路径
    /// </summary>
    public static GraphicsPath CreateRoundedRect(Rectangle rect, int radius)
    {
        var path = new GraphicsPath();
        int d = radius * 2;

        if (d > rect.Width) d = rect.Width;
        if (d > rect.Height) d = rect.Height;

        path.AddArc(rect.X, rect.Y, d, d, 180, 90);
        path.AddArc(rect.Right - d, rect.Y, d, d, 270, 90);
        path.AddArc(rect.Right - d, rect.Bottom - d, d, d, 0, 90);
        path.AddArc(rect.X, rect.Bottom - d, d, d, 90, 90);
        path.CloseFigure();

        return path;
    }

    /// <summary>
    /// 绘制圆角矩形填充
    /// </summary>
    public static void FillRoundedRect(Graphics g, Brush brush, Rectangle rect, int radius)
    {
        using var path = CreateRoundedRect(rect, radius);
        g.FillPath(brush, path);
    }

    /// <summary>
    /// 绘制圆角矩形边框
    /// </summary>
    public static void DrawRoundedBorder(Graphics g, Pen pen, Rectangle rect, int radius)
    {
        using var path = CreateRoundedRect(rect, radius);
        g.DrawPath(pen, path);
    }

    /// <summary>
    /// 文本居中绘制
    /// </summary>
    public static void DrawCenteredText(Graphics g, string text, Font font, Brush brush, Rectangle rect)
    {
        var sf = new StringFormat
        {
            Alignment = StringAlignment.Center,
            LineAlignment = StringAlignment.Center
        };
        g.DrawString(text, font, brush, rect, sf);
    }

    /// <summary>
    /// 左对齐文本（垂直居中）
    /// </summary>
    public static void DrawLeftText(Graphics g, string text, Font font, Brush brush, Rectangle rect, int padding = 12)
    {
        var sf = new StringFormat
        {
            Alignment = StringAlignment.Near,
            LineAlignment = StringAlignment.Center,
            Trimming = StringTrimming.EllipsisCharacter
        };
        var textRect = new Rectangle(rect.X + padding, rect.Y, rect.Width - padding * 2, rect.Height);
        g.DrawString(text, font, brush, textRect, sf);
    }

    /// <summary>
    /// 根据UI模式初始化主题，自动跟随系统深浅色
    /// </summary>
    public static void InitFromMode(UiMode mode)
    {
        // 始终跟随系统深浅色主题
        _isDark = IsSystemDarkMode();
    }
}
