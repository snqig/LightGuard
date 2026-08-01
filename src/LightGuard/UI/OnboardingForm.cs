using System.Drawing.Drawing2D;
using LightGuard.Core;
using LightGuard.UI.Controls;

namespace LightGuard.UI;

/// <summary>
/// 首次运行引导窗体
/// 分3步引导用户：欢迎介绍、硬件检测结果、场景模式选择
/// 现代 UI 风格，圆角窗口，模态对话框
/// </summary>
public class OnboardingForm : Form
{
    private readonly AppState _appState;
    private int _currentStep = 0;
    private SceneMode _selectedScene = SceneMode.Home;

    // 布局常量
    private const int FormWidth = 600;
    private const int FormHeight = 480;
    private const int CornerRadius = 12;

    // 控件
    private Panel? _contentPanel;
    private Label? _stepIndicatorLabel;
    private AccentButton? _prevBtn;
    private AccentButton? _nextBtn;
    private Label? _closeBtn;

    // 步骤3场景选择面板
    private readonly List<Panel> _scenePanels = new();

    // 拖拽
    private bool _isDragging;
    private Point _dragOffset;

    public OnboardingForm(AppState appState)
    {
        _appState = appState;

        // 窗口基本设置
        FormBorderStyle = FormBorderStyle.None;
        StartPosition = FormStartPosition.CenterParent;
        Size = new Size(FormWidth, FormHeight);
        BackColor = Theme.Background;
        DoubleBuffered = true;
        ShowInTaskbar = false;
        MaximizeBox = false;
        MinimizeBox = false;

        // 默认场景选择
        _selectedScene = _appState.Config.CurrentScene;

        InitializeComponent();
        ShowStep(0);
    }

    /// <summary>初始化界面组件</summary>
    private void InitializeComponent()
    {
        // ===== 顶部标题栏区域 =====
        var titlePanel = new Panel
        {
            Location = new Point(0, 0),
            Size = new Size(FormWidth, 50),
            BackColor = Color.Transparent
        };
        titlePanel.Paint += (s, e) =>
        {
            var g = e.Graphics;
            g.SmoothingMode = SmoothingMode.AntiAlias;

            // 标题文字
            using var titleBrush = new SolidBrush(Theme.Accent);
            g.DrawString("LightGuard V2.0", Theme.TitleFont, titleBrush, new PointF(24, 12));

            // 副标题
            using var subBrush = new SolidBrush(Theme.TextTertiary);
            g.DrawString("首次运行引导", Theme.SmallFont, subBrush, new PointF(200, 20));
        };
        Controls.Add(titlePanel);

        // 关闭按钮
        _closeBtn = new Label
        {
            Text = "✕",
            Font = new Font("Segoe UI", 11F, GraphicsUnit.Pixel),
            ForeColor = Theme.TextSecondary,
            Location = new Point(FormWidth - 36, 14),
            Size = new Size(24, 24),
            BackColor = Color.Transparent,
            Cursor = Cursors.Hand,
            TextAlign = ContentAlignment.MiddleCenter
        };
        _closeBtn.MouseEnter += (s, e) => _closeBtn.ForeColor = Theme.Error;
        _closeBtn.MouseLeave += (s, e) => _closeBtn.ForeColor = Theme.TextSecondary;
        _closeBtn.Click += (s, e) => Close();
        Controls.Add(_closeBtn);

        // 标题栏拖拽
        titlePanel.MouseDown += (s, e) =>
        {
            if (e.Button == MouseButtons.Left)
            {
                _isDragging = true;
                _dragOffset = e.Location;
            }
        };
        titlePanel.MouseMove += (s, e) =>
        {
            if (_isDragging)
            {
                var screenPos = PointToScreen(e.Location);
                Location = new Point(screenPos.X - _dragOffset.X, screenPos.Y - _dragOffset.Y);
            }
        };
        titlePanel.MouseUp += (s, e) => _isDragging = false;

        // ===== 步骤指示器 =====
        _stepIndicatorLabel = new Label
        {
            Font = Theme.HeaderFont,
            ForeColor = Theme.TextPrimary,
            Location = new Point(24, 56),
            Size = new Size(FormWidth - 48, 28),
            BackColor = Color.Transparent
        };
        Controls.Add(_stepIndicatorLabel);

        // 分割线
        var separatorPanel = new Panel
        {
            Location = new Point(24, 90),
            Size = new Size(FormWidth - 48, 1),
            BackColor = Theme.Border
        };
        Controls.Add(separatorPanel);

        // ===== 内容区 =====
        _contentPanel = new Panel
        {
            Location = new Point(24, 100),
            Size = new Size(FormWidth - 48, FormHeight - 170),
            BackColor = Color.Transparent
        };
        Controls.Add(_contentPanel);

        // ===== 底部导航按钮 =====
        _prevBtn = new AccentButton
        {
            Text = "上一步",
            Location = new Point(24, FormHeight - 56),
            Size = new Size(100, 36),
            Enabled = false
        };
        _prevBtn.Click += () =>
        {
            if (_currentStep > 0)
            {
                _currentStep--;
                ShowStep(_currentStep);
            }
        };
        Controls.Add(_prevBtn);

        _nextBtn = new AccentButton
        {
            Text = "下一步",
            Location = new Point(FormWidth - 124, FormHeight - 56),
            Size = new Size(100, 36)
        };
        _nextBtn.Click += () =>
        {
            if (_currentStep < 2)
            {
                _currentStep++;
                ShowStep(_currentStep);
            }
            else
            {
                // 完成引导
                CompleteOnboarding();
            }
        };
        Controls.Add(_nextBtn);
    }

    /// <summary>显示指定步骤</summary>
    private void ShowStep(int step)
    {
        _contentPanel!.Controls.Clear();
        _scenePanels.Clear();

        // 更新步骤指示器
        var stepTitles = new[] { "步骤 1/3 - 欢迎使用", "步骤 2/3 - 硬件检测", "步骤 3/3 - 选择场景" };
        _stepIndicatorLabel!.Text = stepTitles[step];

        // 更新按钮状态
        _prevBtn!.Enabled = step > 0;
        _nextBtn!.Text = step < 2 ? "下一步" : "完成";

        // 构建对应步骤内容
        switch (step)
        {
            case 0: BuildStep1Welcome(); break;
            case 1: BuildStep2Hardware(); break;
            case 2: BuildStep3Scene(); break;
        }
    }

    /// <summary>步骤1：欢迎与功能介绍</summary>
    private void BuildStep1Welcome()
    {
        int y = 10;

        // 欢迎标题
        var welcomeLabel = new Label
        {
            Text = "欢迎使用 LightGuard V2.0",
            Font = new Font("Microsoft YaHei UI", 16F, FontStyle.Bold, GraphicsUnit.Pixel),
            ForeColor = Theme.Accent,
            Location = new Point(0, y),
            Size = new Size(_contentPanel!.Width, 28),
            BackColor = Color.Transparent
        };
        _contentPanel.Controls.Add(welcomeLabel);
        y += 40;

        // 副标题
        var subTitleLabel = new Label
        {
            Text = "超低资源全能安全防护软件",
            Font = Theme.BodyFont,
            ForeColor = Theme.TextSecondary,
            Location = new Point(0, y),
            Size = new Size(_contentPanel.Width, 22),
            BackColor = Color.Transparent
        };
        _contentPanel.Controls.Add(subTitleLabel);
        y += 36;

        // 功能介绍
        var features = new[]
        {
            ("🔒", "系统隐私加固", "一键关闭 Windows 遥测、广告 ID、后台应用与锁屏广告"),
            ("🧹", "流氓软件净化", "一键净化 WPS、360、Edge、2345 等弹窗广告与后台流氓行为"),
            ("🌐", "防火墙管理", "原生高级防火墙、智能拦截流氓软件偷流量、Defender 智能兼容"),
            ("🦠", "勒索病毒防护", "四层终极防护：多源病毒库、双引擎扫描、VSS卷影副本、实时监控"),
            ("💾", "加密智能备份", "AES256加密、NTFS增量、伪装备份防勒索、NAS/WebDAV云端备份"),
            ("🔄", "自动更新", "三层全自动无感更新：软件本体、杀毒引擎、病毒库+流氓规则库")
        };

        foreach (var (icon, title, desc) in features)
        {
            var featurePanel = new Panel
            {
                Location = new Point(0, y),
                Size = new Size(_contentPanel.Width, 38),
                BackColor = Color.Transparent
            };

            var iconLabel = new Label
            {
                Text = icon,
                Font = new Font("Microsoft YaHei UI", 14F, GraphicsUnit.Pixel),
                ForeColor = Theme.TextPrimary,
                Location = new Point(0, 4),
                Size = new Size(28, 28),
                BackColor = Color.Transparent,
                TextAlign = ContentAlignment.MiddleCenter
            };
            featurePanel.Controls.Add(iconLabel);

            var titleLabel = new Label
            {
                Text = title,
                Font = Theme.BodyFont,
                ForeColor = Theme.TextPrimary,
                Location = new Point(32, 2),
                Size = new Size(120, 18),
                BackColor = Color.Transparent
            };
            featurePanel.Controls.Add(titleLabel);

            var descLabel = new Label
            {
                Text = desc,
                Font = Theme.SmallFont,
                ForeColor = Theme.TextSecondary,
                Location = new Point(32, 20),
                Size = new Size(_contentPanel.Width - 40, 16),
                BackColor = Color.Transparent
            };
            featurePanel.Controls.Add(descLabel);

            _contentPanel.Controls.Add(featurePanel);
            y += 42;
        }
    }

    /// <summary>步骤2：硬件检测结果</summary>
    private void BuildStep2Hardware()
    {
        int y = 10;

        var hw = _appState.Hardware;

        // 标题
        var titleLabel = new Label
        {
            Text = "硬件检测结果",
            Font = Theme.HeaderFont,
            ForeColor = Theme.TextPrimary,
            Location = new Point(0, y),
            Size = new Size(_contentPanel!.Width, 24),
            BackColor = Color.Transparent
        };
        _contentPanel.Controls.Add(titleLabel);
        y += 36;

        // 硬件信息条目
        var items = new[]
        {
            ("处理器", $"{hw.CpuName}（{hw.CpuCores}核 {hw.CpuLogicalCores}线程）"),
            ("内存", $"{hw.TotalMemoryMb} MB（可用 {hw.AvailableMemoryMb} MB）"),
            ("显卡", hw.GpuName),
            ("系统", $"{hw.OsVersion}（Build {hw.OsBuildNumber}）"),
            ("屏幕", $"{hw.ScreenWidth}×{hw.ScreenHeight} @ {hw.ScreenDpi}DPI（{hw.ScreenScale:F0}%）"),
            ("硬盘", hw.HasSsd ? "SSD 固态硬盘" : "HDD 机械硬盘"),
            ("电源", hw.IsBatteryPowered ? $"电池供电（{hw.BatteryLevel}%）" : "外接电源")
        };

        foreach (var (key, value) in items)
        {
            var keyLabel = new Label
            {
                Text = key,
                Font = Theme.BodyFont,
                ForeColor = Theme.TextSecondary,
                Location = new Point(0, y),
                Size = new Size(80, 22),
                BackColor = Color.Transparent
            };
            _contentPanel.Controls.Add(keyLabel);

            var valueLabel = new Label
            {
                Text = value,
                Font = Theme.BodyFont,
                ForeColor = Theme.TextPrimary,
                Location = new Point(90, y),
                Size = new Size(_contentPanel.Width - 90, 22),
                BackColor = Color.Transparent
            };
            _contentPanel.Controls.Add(valueLabel);

            y += 28;
        }

        y += 16;

        // 配置等级
        var levelPanel = new Panel
        {
            Location = new Point(0, y),
            Size = new Size(_contentPanel.Width, 60),
            BackColor = Color.Transparent
        };
        levelPanel.Paint += (s, e) =>
        {
            var g = e.Graphics;
            g.SmoothingMode = SmoothingMode.AntiAlias;

            // 背景卡片
            var cardRect = new Rectangle(0, 0, levelPanel.Width, 50);
            using var cardBrush = new SolidBrush(Theme.CardBg);
            Theme.FillRoundedRect(g, cardBrush, cardRect, Theme.CardRadius);
            using var borderPen = new Pen(Theme.Border, 1);
            Theme.DrawRoundedBorder(g, borderPen, cardRect, Theme.CardRadius);

            // 等级文字
            var levelText = hw.IsHighEnd ? "高配电脑" : "低配电脑";
            var levelColor = hw.IsHighEnd ? Theme.Success : Theme.Warning;
            var recommendText = hw.IsHighEnd
                ? "已检测到高配硬件，将启用全部现代 UI 特效与深度防护功能。"
                : "已检测到低配硬件，将自动切换到极简模式以节省系统资源。";

            using var levelBrush = new SolidBrush(levelColor);
            var levelFont = new Font("Microsoft YaHei UI", 14F, FontStyle.Bold, GraphicsUnit.Pixel);
            g.DrawString(levelText, levelFont, levelBrush, new PointF(16, 8));

            using var recBrush = new SolidBrush(Theme.TextSecondary);
            g.DrawString(recommendText, Theme.SmallFont, recBrush, new PointF(16, 30));
        };
        _contentPanel.Controls.Add(levelPanel);
    }

    /// <summary>步骤3：场景模式选择</summary>
    private void BuildStep3Scene()
    {
        int y = 10;

        // 标题
        var titleLabel = new Label
        {
            Text = "选择您的使用场景",
            Font = Theme.HeaderFont,
            ForeColor = Theme.TextPrimary,
            Location = new Point(0, y),
            Size = new Size(_contentPanel!.Width, 24),
            BackColor = Color.Transparent
        };
        _contentPanel.Controls.Add(titleLabel);
        y += 30;

        // 说明
        var descLabel = new Label
        {
            Text = "不同场景将自动调整防护策略，您可以在设置中随时更改。",
            Font = Theme.SmallFont,
            ForeColor = Theme.TextSecondary,
            Location = new Point(0, y),
            Size = new Size(_contentPanel.Width, 20),
            BackColor = Color.Transparent
        };
        _contentPanel.Controls.Add(descLabel);
        y += 32;

        // 场景选项
        var scenes = new[]
        {
            (SceneMode.Home, "🏠 家用纯净", "关闭遥测广告，保留常用软件，轻量防护", "适合日常家用电脑，兼顾安全与流畅"),
            (SceneMode.Office, "🏢 办公防勒索", "强化勒索防护与备份，拦截广告弹窗", "适合办公电脑，保护重要文档数据安全"),
            (SceneMode.Performance, "⚡ 老旧流畅", "关闭非必要后台服务，极致省资源", "适合老旧低配电脑，优先保证运行速度")
        };

        foreach (var (mode, name, shortDesc, longDesc) in scenes)
        {
            var panel = CreateScenePanel(mode, name, shortDesc, longDesc, y);
            _scenePanels.Add(panel);
            _contentPanel.Controls.Add(panel);
            y += 72;
        }

        // 更新选中状态
        UpdateSceneSelection();
    }

    /// <summary>创建场景选择面板</summary>
    private Panel CreateScenePanel(SceneMode mode, string name, string shortDesc, string longDesc, int y)
    {
        var panel = new Panel
        {
            Location = new Point(0, y),
            Size = new Size(_contentPanel!.Width, 64),
            BackColor = Color.Transparent,
            Cursor = Cursors.Hand,
            Tag = mode
        };

        // 名称
        var nameLabel = new Label
        {
            Text = name,
            Font = Theme.HeaderFont,
            ForeColor = Theme.TextPrimary,
            Location = new Point(16, 6),
            Size = new Size(200, 22),
            BackColor = Color.Transparent
        };
        panel.Controls.Add(nameLabel);

        // 短描述
        var shortLabel = new Label
        {
            Text = shortDesc,
            Font = Theme.SmallFont,
            ForeColor = Theme.TextSecondary,
            Location = new Point(16, 28),
            Size = new Size(panel.Width - 80, 16),
            BackColor = Color.Transparent
        };
        panel.Controls.Add(shortLabel);

        // 长描述
        var longLabel = new Label
        {
            Text = longDesc,
            Font = Theme.SmallFont,
            ForeColor = Theme.TextTertiary,
            Location = new Point(16, 44),
            Size = new Size(panel.Width - 80, 16),
            BackColor = Color.Transparent
        };
        panel.Controls.Add(longLabel);

        // 选中指示器（圆点）
        var indicator = new Label
        {
            Location = new Point(panel.Width - 36, 24),
            Size = new Size(20, 20),
            BackColor = Color.Transparent,
            Tag = "indicator"
        };
        indicator.Paint += (s, e) =>
        {
            var g = e.Graphics;
            g.SmoothingMode = SmoothingMode.AntiAlias;
            bool selected = _selectedScene == mode;
            int cx = 10, cy = 10, r = 8;

            // 外圈
            using var outerPen = new Pen(selected ? Theme.Accent : Theme.Border, 2);
            g.DrawEllipse(outerPen, cx - r, cy - r, r * 2, r * 2);

            // 内圈（选中时填充）
            if (selected)
            {
                using var innerBrush = new SolidBrush(Theme.Accent);
                g.FillEllipse(innerBrush, cx - 4, cy - 4, 8, 8);
            }
        };
        panel.Controls.Add(indicator);

        // 点击选择
        panel.Click += (s, e) =>
        {
            _selectedScene = mode;
            UpdateSceneSelection();
        };
        foreach (Control c in panel.Controls)
        {
            c.Click += (s, e) =>
            {
                _selectedScene = mode;
                UpdateSceneSelection();
            };
        }

        // 自定义绘制（边框）
        panel.Paint += (s, e) =>
        {
            var g = e.Graphics;
            g.SmoothingMode = SmoothingMode.AntiAlias;
            bool selected = _selectedScene == mode;

            var cardRect = new Rectangle(0, 0, panel.Width - 1, panel.Height - 1);
            using var bgBrush = new SolidBrush(selected ? Theme.AccentLight : Theme.CardBg);
            Theme.FillRoundedRect(g, bgBrush, cardRect, Theme.CardRadius);

            using var borderPen = new Pen(selected ? Theme.Accent : Theme.Border, selected ? 2 : 1);
            Theme.DrawRoundedBorder(g, borderPen, cardRect, Theme.CardRadius);
        };

        return panel;
    }

    /// <summary>更新场景选择面板的视觉效果</summary>
    private void UpdateSceneSelection()
    {
        foreach (var panel in _scenePanels)
        {
            panel.Invalidate();
            foreach (Control c in panel.Controls)
            {
                if (c is Label lbl && lbl.Tag is string tag && tag == "indicator")
                {
                    lbl.Invalidate();
                }
            }
        }
    }

    /// <summary>完成引导</summary>
    private void CompleteOnboarding()
    {
        // 保存场景模式
        _appState.Config.CurrentScene = _selectedScene;

        // 根据场景模式设置 UI 模式
        if (_selectedScene == SceneMode.Performance)
        {
            _appState.SwitchUiMode(UiMode.Minimal);
            Theme.InitFromMode(UiMode.Minimal);
        }
        else
        {
            _appState.SwitchUiMode(_appState.Hardware.IsHighEnd ? UiMode.Modern : UiMode.Minimal);
            Theme.InitFromMode(_appState.Hardware.IsHighEnd ? UiMode.Modern : UiMode.Minimal);
        }

        ConfigManager.Save(_appState.Config);

        var sceneText = _selectedScene switch
        {
            SceneMode.Home => "家用纯净",
            SceneMode.Office => "办公防勒索",
            SceneMode.Performance => "老旧流畅",
            _ => _selectedScene.ToString()
        };

        MessageBoxHelper.Info($"引导完成！已为您设置为「{sceneText}」模式。\n\nLightGuard 将在后台全自动保护您的电脑。");

        DialogResult = DialogResult.OK;
        Close();
    }

    /// <summary>应用圆角窗口区域</summary>
    protected override void OnLoad(EventArgs e)
    {
        base.OnLoad(e);
        ApplyRoundedRegion();
    }

    private void ApplyRoundedRegion()
    {
        using var path = Theme.CreateRoundedRect(new Rectangle(0, 0, Width, Height), CornerRadius);
        Region = new Region(path);
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        base.OnPaint(e);
        var g = e.Graphics;
        g.SmoothingMode = SmoothingMode.AntiAlias;

        // 窗口边框
        var rect = new Rectangle(0, 0, Width - 1, Height - 1);
        using var borderPen = new Pen(Theme.Border, 1);
        Theme.DrawRoundedBorder(g, borderPen, rect, CornerRadius);
    }
}
