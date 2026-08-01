using System.Drawing.Drawing2D;
using System.Runtime.InteropServices;
using LightGuard.Core;
using LightGuard.Native;
using LightGuard.UI.Controls;
using LightGuard.UI.Pages;

namespace LightGuard.UI;

/// <summary>
/// 主窗口 - Win11 Fluent 风格无边框窗口
/// 左侧导航栏 + 右侧内容区
/// </summary>
public class MainForm : Form
{
    private readonly AppState _appState;

    // 窗口控件
    private Panel? _titleBar;
    private Panel? _sidebar;
    private Panel? _contentArea;
    private Label? _titleLabel;
    private Button? _minBtn;
    private Button? _maxBtn;
    private Button? _closeBtn;

    // 导航
    private readonly List<SidebarButton> _navButtons = new();
    private readonly Dictionary<string, Page> _pages = new();
    private string _currentPage = "dashboard";

    // 系统托盘
    private NotifyIcon? _trayIcon;

    // 拖拽
    private bool _isDragging;
    private Point _dragOffset;

    // 标题栏按钮区域
    private const int HTCLIENT = 1;
    private const int HTCAPTION = 2;
    private const int HTMINBUTTON = 8;
    private const int HTMAXBUTTON = 9;
    private const int HTCLOSE = 20;

    public MainForm(AppState appState)
    {
        _appState = appState;

        // 窗口基本设置
        FormBorderStyle = FormBorderStyle.None;
        Text = "LightGuard V2.0";
        StartPosition = FormStartPosition.CenterScreen;
        MinimumSize = new Size(900, 600);
        Size = new Size(1000, 680);
        BackColor = Theme.Background;
        DoubleBuffered = true;
        ShowInTaskbar = true;

        // 初始化主题
        Theme.InitFromMode(_appState.UiMode);

        // 初始化组件
        InitializeComponent();
        CreatePages();
        ApplyMicaEffect();

        // 注册模块
        _appState.RegisterModules();

        // 导航到默认页面
        NavigateTo("dashboard");

        // 设置托盘
        SetupTrayIcon();

        // 首次运行引导
        if (!_appState.Config.FirstRunCompleted)
        {
            BeginInvoke(async () =>
            {
                await Task.Delay(500);
                ShowOnboarding();
            });
        }
    }

    private void InitializeComponent()
    {
        // ===== 标题栏 =====
        _titleBar = new Panel
        {
            Dock = DockStyle.Top,
            Height = Theme.TitleBarHeight,
            BackColor = Theme.TitleBar
        };
        Controls.Add(_titleBar);

        _titleLabel = new Label
        {
            Text = "  LightGuard V2.0  -  超低资源全能安全防护",
            Font = Theme.BodyFont,
            ForeColor = Theme.TextPrimary,
            Location = new Point(12, 0),
            Size = new Size(500, Theme.TitleBarHeight),
            BackColor = Color.Transparent
        };
        _titleBar.Controls.Add(_titleLabel);

        // 窗口控制按钮
        _minBtn = CreateTitleButton("—", HTMINBUTTON);
        _minBtn.Location = new Point(Width - 130, 0);
        _minBtn.Click += (s, e) => WindowState = FormWindowState.Minimized;

        _maxBtn = CreateTitleButton("□", HTMAXBUTTON);
        _maxBtn.Location = new Point(Width - 90, 0);
        _maxBtn.Click += (s, e) =>
        {
            WindowState = WindowState == FormWindowState.Maximized
                ? FormWindowState.Normal : FormWindowState.Maximized;
        };

        _closeBtn = CreateTitleButton("✕", HTCLOSE);
        _closeBtn.Location = new Point(Width - 45, 0);
        _closeBtn.Click += (s, e) => Close();
        _closeBtn.BackColor = Color.FromArgb(196, 43, 28); // 关闭按钮悬停红色

        _titleBar.Controls.AddRange(new Control[] { _minBtn, _maxBtn, _closeBtn });

        // 标题栏双击最大化
        _titleBar.DoubleClick += (s, e) =>
        {
            WindowState = WindowState == FormWindowState.Maximized
                ? FormWindowState.Normal : FormWindowState.Maximized;
        };

        // 拖拽移动
        _titleBar.MouseDown += OnTitleBarMouseDown;
        _titleBar.MouseMove += OnTitleBarMouseMove;
        _titleBar.MouseUp += OnTitleBarMouseUp;

        // ===== 侧边栏 =====
        _sidebar = new Panel
        {
            Dock = DockStyle.Left,
            Width = Theme.SidebarWidth,
            BackColor = Theme.SidebarBg
        };
        Controls.Add(_sidebar);

        // Logo
        var logoLabel = new Label
        {
            Text = "🛡 LightGuard",
            Font = Theme.TitleFont,
            ForeColor = Theme.Accent,
            Location = new Point(16, 12),
            Size = new Size(Theme.SidebarWidth - 32, 30),
            BackColor = Color.Transparent
        };
        _sidebar.Controls.Add(logoLabel);

        var versionLabel = new Label
        {
            Text = "V2.0 终极完整版",
            Font = Theme.SmallFont,
            ForeColor = Theme.TextTertiary,
            Location = new Point(16, 44),
            Size = new Size(Theme.SidebarWidth - 32, 18),
            BackColor = Color.Transparent
        };
        _sidebar.Controls.Add(versionLabel);

        // 导航按钮
        var navItems = new[]
        {
            ("仪表盘", "📊", "dashboard"),
            ("隐私加固", "🔒", "privacy"),
            ("流氓净化", "🧹", "cleanup"),
            ("防火墙", "🌐", "firewall"),
            ("勒索防护", "🦠", "ransomware"),
            ("加密备份", "💾", "backup"),
            ("自动更新", "🔄", "update"),
            ("设置", "⚙", "settings"),
        };

        int navY = 80;
        foreach (var (text, icon, key) in navItems)
        {
            var btn = new SidebarButton(text, icon, key)
            {
                Location = new Point(10, navY),
                Size = new Size(Theme.SidebarWidth - 20, 38)
            };
            btn.NavClicked += () => NavigateTo(key);
            _navButtons.Add(btn);
            _sidebar.Controls.Add(btn);
            navY += 42;
        }

        // 底部状态
        var statusLabel = new Label
        {
            Text = "● 全自动防护中",
            Font = Theme.SmallFont,
            ForeColor = Theme.Success,
            Location = new Point(16, Height - 50),
            Size = new Size(Theme.SidebarWidth - 32, 18),
            BackColor = Color.Transparent
        };
        _sidebar.Controls.Add(statusLabel);
        _sidebar.Resize += (s, e) => statusLabel.Location = new Point(16, _sidebar.Height - 50);

        // ===== 内容区 =====
        _contentArea = new Panel
        {
            Dock = DockStyle.Fill,
            BackColor = Theme.Background
        };
        Controls.Add(_contentArea);
        _contentArea.BringToFront();
    }

    private Button CreateTitleButton(string text, int tag)
    {
        var btn = new Button
        {
            Text = text,
            Size = new Size(45, Theme.TitleBarHeight),
            FlatStyle = FlatStyle.Flat,
            Font = new Font("Segoe UI", 10F, GraphicsUnit.Pixel),
            ForeColor = Theme.TextPrimary,
            BackColor = Theme.TitleBar,
            TextAlign = ContentAlignment.MiddleCenter,
            Tag = tag
        };
        btn.FlatAppearance.BorderSize = 0;
        btn.MouseEnter += (s, e) => btn.BackColor = Theme.CardHover;
        btn.MouseLeave += (s, e) => btn.BackColor = Theme.TitleBar;
        return btn;
    }

    private void CreatePages()
    {
        _pages["dashboard"] = new DashboardPage(_appState);
        _pages["privacy"] = new PrivacyPage(_appState);
        _pages["cleanup"] = new CleanupPage(_appState);
        _pages["firewall"] = new FirewallPage(_appState);
        _pages["ransomware"] = new RansomwarePage(_appState);
        _pages["backup"] = new BackupPage(_appState);
        _pages["update"] = new UpdatePage(_appState);
        _pages["settings"] = new SettingsPage(_appState);

        foreach (var page in _pages.Values)
        {
            page.Dock = DockStyle.Fill;
            page.BackColor = Theme.Background;
            _contentArea!.Controls.Add(page);
            page.Visible = false;
        }
    }

    public void NavigateTo(string key)
    {
        if (!_pages.ContainsKey(key)) return;

        foreach (var page in _pages.Values)
            page.Visible = false;

        _pages[key].Visible = true;
        _pages[key].Invalidate();

        foreach (var btn in _navButtons)
            btn.IsActive = btn.NavKey == key;

        _currentPage = key;
    }

    private void ApplyMicaEffect()
    {
        if (_appState.UiMode != UiMode.Modern || !_appState.Hardware.IsWin11)
            return;

        try
        {
            Win32.EnableMica(Handle);
            Win32.EnableDarkMode(Handle);
            Win32.EnableRoundedCorners(Handle);
        }
        catch { }
    }

    private void SetupTrayIcon()
    {
        _trayIcon = new NotifyIcon
        {
            Text = "LightGuard V2.0 - 全自动安全防护",
            Visible = true,
            Icon = SystemIcons.Shield
        };

        var menu = new ContextMenuStrip();
        menu.Items.Add("打开主界面", null, (s, e) =>
        {
            Show();
            WindowState = FormWindowState.Normal;
        });
        menu.Items.Add("立即维护", null, async (s, e) =>
        {
            await _appState.Scheduler.TriggerMaintenanceAsync();
        });
        menu.Items.Add("-");
        menu.Items.Add("退出", null, (s, e) =>
        {
            _trayIcon.Visible = false;
            Application.Exit();
        });

        _trayIcon.ContextMenuStrip = menu;
        _trayIcon.DoubleClick += (s, e) =>
        {
            Show();
            WindowState = FormWindowState.Normal;
        };
    }

    private void ShowOnboarding()
    {
        var form = new OnboardingForm(_appState);
        form.ShowDialog(this);
        _appState.Config.FirstRunCompleted = true;
        ConfigManager.Save(_appState.Config);
    }

    #region 窗口拖拽

    private void OnTitleBarMouseDown(object? sender, MouseEventArgs e)
    {
        if (e.Button == MouseButtons.Left)
        {
            _isDragging = true;
            _dragOffset = e.Location;
        }
    }

    private void OnTitleBarMouseMove(object? sender, MouseEventArgs e)
    {
        if (_isDragging && WindowState != FormWindowState.Maximized)
        {
            var screenPos = PointToScreen(e.Location);
            Location = new Point(screenPos.X - _dragOffset.X, screenPos.Y - _dragOffset.Y);
        }
    }

    private void OnTitleBarMouseUp(object? sender, MouseEventArgs e)
    {
        _isDragging = false;
    }

    #endregion

    #region 窗口重绘

    protected override void OnResize(EventArgs e)
    {
        base.OnResize(e);
        if (_minBtn != null) _minBtn.Location = new Point(Width - 130, 0);
        if (_maxBtn != null) _maxBtn.Location = new Point(Width - 90, 0);
        if (_closeBtn != null) _closeBtn.Location = new Point(Width - 45, 0);
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        base.OnPaint(e);
        // 窗口边框
        using var pen = new Pen(Theme.Border, 1);
        e.Graphics.DrawRectangle(pen, 0, 0, Width - 1, Height - 1);
    }

    protected override void WndProc(ref Message m)
    {
        const int WM_NCHITTEST = 0x0084;

        if (m.Msg == WM_NCHITTEST)
        {
            // 让窗口边缘可调整大小
            var pos = PointToClient(new Point((int)m.LParam & 0xFFFF, (int)m.LParam >> 16));
            const int resizeArea = 6;

            if (pos.X <= resizeArea) { m.Result = (IntPtr)10; return; }
            if (pos.X >= Width - resizeArea) { m.Result = (IntPtr)11; return; }
            if (pos.Y <= resizeArea) { m.Result = (IntPtr)12; return; }
            if (pos.Y >= Height - resizeArea) { m.Result = (IntPtr)15; return; }
        }

        base.WndProc(ref m);
    }

    #endregion

    protected override void OnFormClosing(FormClosingEventArgs e)
    {
        if (e.CloseReason == CloseReason.UserClosing && _trayIcon != null)
        {
            e.Cancel = true;
            Hide();
            _trayIcon.ShowBalloonTip(2000, "LightGuard", "程序已最小化到系统托盘，继续后台防护中。", ToolTipIcon.Info);
            return;
        }

        _appState.Dispose();
        _trayIcon?.Dispose();
        base.OnFormClosing(e);
    }
}
