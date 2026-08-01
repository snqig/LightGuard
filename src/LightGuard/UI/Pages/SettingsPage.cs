using System.Diagnostics;
using System.Text.Json;
using LightGuard.Core;
using LightGuard.UI.Controls;

namespace LightGuard.UI.Pages;

/// <summary>
/// 设置页面
/// 提供UI模式切换、场景模式切换、后台调度、主题切换、配置管理、关于信息等功能
/// </summary>
public class SettingsPage : Page
{
    private AccentButton? _modernBtn;
    private AccentButton? _minimalBtn;
    private AccentButton? _homeBtn;
    private AccentButton? _officeBtn;
    private AccentButton? _perfBtn;
    private AccentButton? _darkBtn;
    private AccentButton? _lightBtn;
    private ToggleSwitch? _schedulingToggle;
    private ComboBox? _maintenanceHourCombo;
    private AccentButton? _exportBtn;
    private AccentButton? _importBtn;
    private AccentButton? _openConfigDirBtn;
    private AccentButton? _openLogBtn;

    public SettingsPage(AppState appState) : base(appState, "设置", "界面模式、场景模式、后台调度、主题、配置管理与关于信息")
    {
    }

    public override void OnShown()
    {
        BuildContent();
    }

    /// <summary>构建页面内容</summary>
    private void BuildContent()
    {
        ScrollContent.Controls.Clear();

        int y = 0;

        // ===== 界面设置 =====
        CreateSectionTitle("界面设置", 0, y);
        y += 30;

        var uiCard = CreateCard(0, y, ContentWidth, 110);

        // UI 模式切换
        var uiModeLabel = new Label
        {
            Text = "UI 模式：",
            Font = Theme.BodyFont,
            ForeColor = Theme.TextSecondary,
            Location = new Point(16, 12),
            Size = new Size(80, 22),
            BackColor = Color.Transparent
        };
        uiCard.Controls.Add(uiModeLabel);

        _modernBtn = new AccentButton
        {
            Text = "高配 Modern",
            Location = new Point(100, 10),
            Size = new Size(130, 36)
        };
        _modernBtn.Click += () => SwitchUiMode(UiMode.Modern);
        uiCard.Controls.Add(_modernBtn);

        _minimalBtn = new AccentButton
        {
            Text = "低配 Minimal",
            Location = new Point(236, 10),
            Size = new Size(130, 36)
        };
        _minimalBtn.Click += () => SwitchUiMode(UiMode.Minimal);
        uiCard.Controls.Add(_minimalBtn);

        var uiModeDescLabel = new Label
        {
            Text = AppState.UiMode == UiMode.Modern
                ? "当前：高配模式（Mica云母、圆角、渐变、阴影）"
                : "当前：低配模式（纯矩形极简、无特效）",
            Font = Theme.SmallFont,
            ForeColor = Theme.TextTertiary,
            Location = new Point(376, 18),
            Size = new Size(320, 20),
            BackColor = Color.Transparent
        };
        uiCard.Controls.Add(uiModeDescLabel);

        // 深色/浅色主题切换
        var themeLabel = new Label
        {
            Text = "主题色彩：",
            Font = Theme.BodyFont,
            ForeColor = Theme.TextSecondary,
            Location = new Point(16, 58),
            Size = new Size(80, 22),
            BackColor = Color.Transparent
        };
        uiCard.Controls.Add(themeLabel);

        _darkBtn = new AccentButton
        {
            Text = "深色主题",
            Location = new Point(100, 56),
            Size = new Size(130, 36)
        };
        _darkBtn.Click += () => SwitchTheme(true);
        uiCard.Controls.Add(_darkBtn);

        _lightBtn = new AccentButton
        {
            Text = "浅色主题",
            Location = new Point(236, 56),
            Size = new Size(130, 36)
        };
        _lightBtn.Click += () => SwitchTheme(false);
        uiCard.Controls.Add(_lightBtn);

        var themeDescLabel = new Label
        {
            Text = Theme.IsDark ? "当前：深色主题" : "当前：浅色主题",
            Font = Theme.SmallFont,
            ForeColor = Theme.TextTertiary,
            Location = new Point(376, 64),
            Size = new Size(320, 20),
            BackColor = Color.Transparent
        };
        uiCard.Controls.Add(themeDescLabel);

        y += 130;

        // ===== 场景模式 =====
        CreateSectionTitle("场景模式", 0, y);
        y += 30;

        var sceneCard = CreateCard(0, y, ContentWidth, 80);

        var sceneDescLabel = new Label
        {
            Text = "选择场景模式以自动调整各模块的防护策略：",
            Font = Theme.SmallFont,
            ForeColor = Theme.TextSecondary,
            Location = new Point(16, 10),
            Size = new Size(688, 20),
            BackColor = Color.Transparent
        };
        sceneCard.Controls.Add(sceneDescLabel);

        _homeBtn = new AccentButton
        {
            Text = "家用纯净",
            Location = new Point(16, 36),
            Size = new Size(200, 36)
        };
        _homeBtn.Click += () => SwitchScene(SceneMode.Home);
        sceneCard.Controls.Add(_homeBtn);

        _officeBtn = new AccentButton
        {
            Text = "办公防勒索",
            Location = new Point(226, 36),
            Size = new Size(200, 36)
        };
        _officeBtn.Click += () => SwitchScene(SceneMode.Office);
        sceneCard.Controls.Add(_officeBtn);

        _perfBtn = new AccentButton
        {
            Text = "老旧流畅",
            Location = new Point(436, 36),
            Size = new Size(200, 36)
        };
        _perfBtn.Click += () => SwitchScene(SceneMode.Performance);
        sceneCard.Controls.Add(_perfBtn);

        y += 100;

        // ===== 调度设置 =====
        CreateSectionTitle("调度设置", 0, y);
        y += 30;

        var schedCard = CreateCard(0, y, ContentWidth, 110);

        // 后台调度开关
        var schedLabel = new Label
        {
            Text = "后台调度：",
            Font = Theme.BodyFont,
            ForeColor = Theme.TextSecondary,
            Location = new Point(16, 12),
            Size = new Size(100, 22),
            BackColor = Color.Transparent
        };
        schedCard.Controls.Add(schedLabel);

        _schedulingToggle = new ToggleSwitch
        {
            Location = new Point(116, 14),
            IsOn = AppState.Config.BackgroundSchedulingEnabled
        };
        _schedulingToggle.Toggled += (on) =>
        {
            AppState.Config.BackgroundSchedulingEnabled = on;
            ConfigManager.Save(AppState.Config);
            MessageBoxHelper.Info(on ? "已开启后台调度。" : "已关闭后台调度。");
        };
        schedCard.Controls.Add(_schedulingToggle);

        var schedDescLabel = new Label
        {
            Text = "开启后将在后台自动执行定时维护、备份、更新等任务",
            Font = Theme.SmallFont,
            ForeColor = Theme.TextTertiary,
            Location = new Point(170, 14),
            Size = new Size(400, 20),
            BackColor = Color.Transparent
        };
        schedCard.Controls.Add(schedDescLabel);

        // 自动维护时间
        var maintLabel = new Label
        {
            Text = "自动维护时间：",
            Font = Theme.BodyFont,
            ForeColor = Theme.TextSecondary,
            Location = new Point(16, 52),
            Size = new Size(100, 22),
            BackColor = Color.Transparent
        };
        schedCard.Controls.Add(maintLabel);

        _maintenanceHourCombo = new ComboBox
        {
            Location = new Point(116, 50),
            Size = new Size(140, 24),
            FlatStyle = FlatStyle.Flat,
            Font = Theme.BodyFont,
            DropDownStyle = ComboBoxStyle.DropDownList
        };
        for (int h = 0; h < 24; h++)
        {
            _maintenanceHourCombo.Items.Add($"{h:D2}:00");
        }
        _maintenanceHourCombo.SelectedIndex = AppState.Config.AutoMaintenanceHour;
        _maintenanceHourCombo.SelectedIndexChanged += (s, e) =>
        {
            AppState.Config.AutoMaintenanceHour = _maintenanceHourCombo.SelectedIndex;
            ConfigManager.Save(AppState.Config);
        };
        schedCard.Controls.Add(_maintenanceHourCombo);

        var maintDescLabel = new Label
        {
            Text = "每天在此时间自动执行隐私优化、净化、备份等维护任务",
            Font = Theme.SmallFont,
            ForeColor = Theme.TextTertiary,
            Location = new Point(270, 52),
            Size = new Size(400, 20),
            BackColor = Color.Transparent
        };
        schedCard.Controls.Add(maintDescLabel);

        var currentSceneLabel = new Label
        {
            Text = $"当前场景：{GetSceneText(AppState.Config.CurrentScene)}",
            Font = Theme.SmallFont,
            ForeColor = Theme.TextTertiary,
            Location = new Point(16, 84),
            Size = new Size(400, 20),
            BackColor = Color.Transparent
        };
        schedCard.Controls.Add(currentSceneLabel);

        y += 130;

        // ===== 配置管理 =====
        CreateSectionTitle("配置管理", 0, y);
        y += 30;

        var configCard = CreateCard(0, y, ContentWidth, 60);

        _exportBtn = new AccentButton
        {
            Text = "导出配置",
            Location = new Point(16, 12),
            Size = new Size(120, 36)
        };
        _exportBtn.Click += () => ExportConfig();
        configCard.Controls.Add(_exportBtn);

        _importBtn = new AccentButton
        {
            Text = "导入配置",
            Location = new Point(146, 12),
            Size = new Size(120, 36)
        };
        _importBtn.Click += () => ImportConfig();
        configCard.Controls.Add(_importBtn);

        _openConfigDirBtn = new AccentButton
        {
            Text = "打开配置目录",
            Location = new Point(276, 12),
            Size = new Size(130, 36)
        };
        _openConfigDirBtn.Click += () => OpenConfigDir();
        configCard.Controls.Add(_openConfigDirBtn);

        _openLogBtn = new AccentButton
        {
            Text = "检查日志",
            Location = new Point(416, 12),
            Size = new Size(120, 36)
        };
        _openLogBtn.Click += () => OpenLogDir();
        configCard.Controls.Add(_openLogBtn);

        y += 80;

        // ===== 关于 =====
        CreateSectionTitle("关于", 0, y);
        y += 30;

        var aboutCard = CreateCard(0, y, ContentWidth, 160);

        var version = System.Reflection.Assembly.GetExecutingAssembly().GetName().Version;
        var versionText = version != null ? $"V{version.Major}.{version.Minor}.{version.Build}" : "V2.0.0";

        var aboutTitleLabel = new Label
        {
            Text = "LightGuard V2.0 终极完整版",
            Font = Theme.HeaderFont,
            ForeColor = Theme.Accent,
            Location = new Point(16, 12),
            Size = new Size(400, 24),
            BackColor = Color.Transparent
        };
        aboutCard.Controls.Add(aboutTitleLabel);

        var aboutVersionLabel = new Label
        {
            Text = $"软件版本：{versionText}",
            Font = Theme.BodyFont,
            ForeColor = Theme.TextSecondary,
            Location = new Point(16, 40),
            Size = new Size(400, 22),
            BackColor = Color.Transparent
        };
        aboutCard.Controls.Add(aboutVersionLabel);

        var aboutDescLabel = new Label
        {
            Text = "超低资源全能安全防护软件，集隐私加固、流氓净化、防火墙、\n勒索防护、加密备份、自动更新于一体。",
            Font = Theme.SmallFont,
            ForeColor = Theme.TextTertiary,
            Location = new Point(16, 66),
            Size = new Size(688, 36),
            BackColor = Color.Transparent
        };
        aboutCard.Controls.Add(aboutDescLabel);

        var hw = AppState.Hardware;
        var hwLabel = new Label
        {
            Text = $"硬件：{hw.CpuName} | {hw.TotalMemoryMb}MB 内存 | {hw.GpuName}\n" +
                   $"系统：{hw.OsVersion} (Build {hw.OsBuildNumber}) | {(hw.IsHighEnd ? "高配电脑" : "低配电脑")} | {(hw.HasSsd ? "SSD" : "HDD")}",
            Font = Theme.SmallFont,
            ForeColor = Theme.TextTertiary,
            Location = new Point(16, 104),
            Size = new Size(688, 36),
            BackColor = Color.Transparent
        };
        aboutCard.Controls.Add(hwLabel);

        var configDirLabel = new Label
        {
            Text = $"配置目录：{ConfigManager.GetConfigDir()}",
            Font = Theme.SmallFont,
            ForeColor = Theme.TextTertiary,
            Location = new Point(16, 140),
            Size = new Size(688, 18),
            BackColor = Color.Transparent
        };
        aboutCard.Controls.Add(configDirLabel);

        y += 180;
    }

    /// <summary>切换 UI 模式</summary>
    private void SwitchUiMode(UiMode mode)
    {
        if (AppState.UiMode == mode)
        {
            MessageBoxHelper.Info($"当前已是{GetUiModeText(mode)}。");
            return;
        }

        AppState.SwitchUiMode(mode);
        Theme.InitFromMode(mode);
        ConfigManager.Save(AppState.Config);

        MessageBoxHelper.Info($"已切换到{GetUiModeText(mode)}，重启程序后完全生效。");
        BuildContent();
    }

    /// <summary>切换主题</summary>
    private void SwitchTheme(bool dark)
    {
        if (Theme.IsDark == dark)
        {
            MessageBoxHelper.Info($"当前已是{(dark ? "深色" : "浅色")}主题。");
            return;
        }

        Theme.IsDark = dark;
        MessageBoxHelper.Info($"已切换到{(dark ? "深色" : "浅色")}主题，重启程序后完全生效。");
        BuildContent();
    }

    /// <summary>切换场景模式</summary>
    private void SwitchScene(SceneMode mode)
    {
        if (AppState.Config.CurrentScene == mode)
        {
            MessageBoxHelper.Info($"当前已是{GetSceneText(mode)}。");
            return;
        }

        AppState.Config.CurrentScene = mode;
        ConfigManager.Save(AppState.Config);

        var desc = mode switch
        {
            SceneMode.Home => "家用纯净模式：关闭遥测广告，保留常用软件，轻量防护。",
            SceneMode.Office => "办公防勒索模式：强化勒索防护与备份，拦截广告弹窗。",
            SceneMode.Performance => "老旧流畅模式：关闭非必要后台服务，极致省资源。",
            _ => ""
        };

        MessageBoxHelper.Info($"已切换到{GetSceneText(mode)}。\n\n{desc}");
        BuildContent();
    }

    /// <summary>导出配置到文件</summary>
    private void ExportConfig()
    {
        using var dialog = new SaveFileDialog
        {
            Title = "导出配置",
            Filter = "配置文件|*.json|所有文件|*.*",
            FileName = $"LightGuard_config_{DateTime.Now:yyyyMMdd_HHmmss}.json"
        };

        if (dialog.ShowDialog() != DialogResult.OK)
            return;

        try
        {
            var json = JsonSerializer.Serialize(AppState.Config, new JsonSerializerOptions
            {
                WriteIndented = true,
                DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull
            });
            File.WriteAllText(dialog.FileName, json);
            MessageBoxHelper.Info($"配置已导出到：\n{dialog.FileName}");
        }
        catch (Exception ex)
        {
            MessageBoxHelper.Error($"导出配置失败：{ex.Message}");
        }
    }

    /// <summary>从文件导入配置</summary>
    private void ImportConfig()
    {
        using var dialog = new OpenFileDialog
        {
            Title = "导入配置",
            Filter = "配置文件|*.json|所有文件|*.*"
        };

        if (dialog.ShowDialog() != DialogResult.OK)
            return;

        if (!MessageBoxHelper.Confirm("导入配置将覆盖当前设置，确定继续吗？"))
            return;

        try
        {
            var json = File.ReadAllText(dialog.FileName);
            var config = JsonSerializer.Deserialize<AppConfig>(json);
            if (config == null)
            {
                MessageBoxHelper.Error("配置文件格式无效。");
                return;
            }

            // 复制配置内容到当前 AppState
            var currentConfig = AppState.Config;
            currentConfig.UiMode = config.UiMode;
            currentConfig.CurrentScene = config.CurrentScene;
            currentConfig.BackgroundSchedulingEnabled = config.BackgroundSchedulingEnabled;
            currentConfig.AutoMaintenanceHour = config.AutoMaintenanceHour;
            currentConfig.ModuleEnabled = config.ModuleEnabled;
            currentConfig.Backup = config.Backup;
            currentConfig.Update = config.Update;
            currentConfig.Firewall = config.Firewall;
            currentConfig.Privacy = config.Privacy;
            currentConfig.Cleanup = config.Cleanup;

            ConfigManager.Save(currentConfig);
            MessageBoxHelper.Info("配置导入成功，重启程序后完全生效。");
            BuildContent();
        }
        catch (Exception ex)
        {
            MessageBoxHelper.Error($"导入配置失败：{ex.Message}");
        }
    }

    /// <summary>打开配置目录</summary>
    private void OpenConfigDir()
    {
        try
        {
            Process.Start(new ProcessStartInfo
            {
                FileName = "explorer.exe",
                Arguments = $"\"{ConfigManager.GetConfigDir()}\"",
                UseShellExecute = true
            });
        }
        catch (Exception ex)
        {
            MessageBoxHelper.Error($"无法打开配置目录：{ex.Message}");
        }
    }

    /// <summary>打开日志目录</summary>
    private void OpenLogDir()
    {
        try
        {
            var logDir = ConfigManager.GetLogDir();
            if (!Directory.Exists(logDir) || !Directory.EnumerateFiles(logDir).Any())
            {
                MessageBoxHelper.Info("暂无日志文件。日志将在程序运行后自动生成。");
                return;
            }

            Process.Start(new ProcessStartInfo
            {
                FileName = "explorer.exe",
                Arguments = $"\"{logDir}\"",
                UseShellExecute = true
            });
        }
        catch (Exception ex)
        {
            MessageBoxHelper.Error($"无法打开日志目录：{ex.Message}");
        }
    }

    /// <summary>获取 UI 模式显示文本</summary>
    private static string GetUiModeText(UiMode mode) => mode switch
    {
        UiMode.Modern => "高配 Modern 模式",
        UiMode.Minimal => "低配 Minimal 模式",
        _ => mode.ToString()
    };

    /// <summary>获取场景模式显示文本</summary>
    private static string GetSceneText(SceneMode mode) => mode switch
    {
        SceneMode.Home => "家用纯净",
        SceneMode.Office => "办公防勒索",
        SceneMode.Performance => "老旧流畅",
        _ => mode.ToString()
    };

    public override void RefreshData()
    {
        BuildContent();
    }
}
