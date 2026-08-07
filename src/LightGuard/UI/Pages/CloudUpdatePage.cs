using System.Drawing.Drawing2D;
using LightGuard.Core;
using LightGuard.Core.CloudUpdate;
using LightGuard.Modules;
using LightGuard.UI.Controls;

namespace LightGuard.UI.Pages;

/// <summary>
/// 云端规则更新页面
/// RSA 签名校验的云端规则自动增量更新系统界面
/// 包含三个标签页：更新概览、规则管理、更新历史
/// </summary>
public class CloudUpdatePage : Page
{
    private CloudUpdateModule? _module;
    private CloudUpdateClient? _client;
    private RuleUpdateScheduler? _scheduler;

    // 标签页相关
    private readonly string[] _tabNames = { "更新概览", "规则管理", "更新历史" };
    private int _currentTab;
    private readonly List<Panel> _tabButtons = new();
    private Panel? _tabContentArea;

    // 概览页控件
    private Label? _statusLabel;
    private Label? _lastCheckLabel;
    private Label? _lastUpdateLabel;
    private Label? _totalChecksLabel;
    private Label? _totalUpdatesLabel;
    private ComboBox? _channelCombo;
    private ComboBox? _intervalCombo;
    private AccentButton? _checkBtn;
    private ToggleSwitch? _autoUpdateToggle;
    private Label? _progressLabel;

    // 规则管理页控件
    private AccentButton? _updateAllBtn;
    private Panel? _progressBarPanel;
    private Label? _ruleProgressLabel;
    private bool _isUpdating;

    public CloudUpdatePage(AppState appState)
        : base(appState, "云端规则更新", "RSA 签名校验 · 自动增量更新")
    {
    }

    public override void OnShown()
    {
        _module = AppState.Modules.GetModule("cloud-update") as CloudUpdateModule;
        _client = _module?.Client;
        _scheduler = _module?.Scheduler;
        BuildContent();
    }

    /// <summary>构建页面内容</summary>
    private void BuildContent()
    {
        ScrollContent.Controls.Clear();
        _tabButtons.Clear();

        int y = 0;

        // ===== 标签栏 =====
        var tabBar = new Panel
        {
            Location = new Point(0, y),
            Size = new Size(ContentWidth, 40),
            BackColor = Color.Transparent
        };
        ScrollContent.Controls.Add(tabBar);

        int tabX = 0;
        for (int i = 0; i < _tabNames.Length; i++)
        {
            var tabBtn = new Panel
            {
                Location = new Point(tabX, 0),
                Size = new Size(110, 36),
                BackColor = Color.Transparent,
                Cursor = Cursors.Hand,
                Tag = i
            };
            var tabIndex = i;
            tabBtn.Click += (s, e) => SwitchTab(tabIndex);
            tabBtn.Paint += (s, e) =>
            {
                var g = e.Graphics;
                g.SmoothingMode = SmoothingMode.AntiAlias;
                var isActive = (int)(s as Control)!.Tag! == _currentTab;
                if (isActive)
                {
                    using var brush = new SolidBrush(Theme.AccentLight);
                    Theme.FillRoundedRect(g, brush, new Rectangle(0, 0, tabBtn.Width, tabBtn.Height), 4);
                    using var pen = new Pen(Theme.Accent, 2);
                    g.DrawLine(pen, 8, tabBtn.Height - 2, tabBtn.Width - 8, tabBtn.Height - 2);
                }
                var font = isActive ? Theme.HeaderFont : Theme.BodyFont;
                var color = isActive ? Theme.Accent : Theme.TextSecondary;
                Theme.DrawCenteredText(g, _tabNames[tabIndex], font, new SolidBrush(color),
                    new Rectangle(0, 0, tabBtn.Width, tabBtn.Height));
            };
            tabBar.Controls.Add(tabBtn);
            _tabButtons.Add(tabBtn);
            tabX += 116;
        }

        y += 46;

        // ===== 标签内容区 =====
        _tabContentArea = new Panel
        {
            Location = new Point(0, y),
            Size = new Size(ContentWidth, Height - 160),
            BackColor = Color.Transparent
        };
        ScrollContent.Controls.Add(_tabContentArea);

        RenderCurrentTab();
    }

    /// <summary>切换标签页</summary>
    private void SwitchTab(int index)
    {
        _currentTab = index;
        foreach (var btn in _tabButtons)
            btn.Invalidate();
        RenderCurrentTab();
    }

    /// <summary>渲染当前标签页内容</summary>
    private void RenderCurrentTab()
    {
        if (_tabContentArea == null) return;
        _tabContentArea.Controls.Clear();

        switch (_currentTab)
        {
            case 0:
                RenderOverviewTab();
                break;
            case 1:
                RenderRuleManagementTab();
                break;
            case 2:
                RenderHistoryTab();
                break;
        }
    }

    // ==================== 标签页 1: 更新概览 ====================

    private void RenderOverviewTab()
    {
        if (_tabContentArea == null) return;
        int y = 0;
        int w = _tabContentArea.Width;

        // ===== 调度器状态卡片 =====
        CreateTabSectionTitle("调度器状态", 0, y);
        y += 30;

        var statusCard = CreateTabCard(0, y, w, 150);
        var status = _scheduler?.GetStatus() ?? new UpdateSchedulerStatus();

        _statusLabel = CreateStatusLabel("运行状态：", status.IsRunning ? "运行中" : "已停止",
            status.IsRunning ? Theme.Success : Theme.TextTertiary, 16, 12, statusCard);
        _lastCheckLabel = CreateStatusLabel("最后检查：",
            status.LastCheckTime?.ToString("yyyy-MM-dd HH:mm:ss") ?? "从未",
            Theme.TextSecondary, 16, 38, statusCard);
        _lastUpdateLabel = CreateStatusLabel("最后更新：",
            status.LastUpdateTime?.ToString("yyyy-MM-dd HH:mm:ss") ?? "从未",
            Theme.TextSecondary, 300, 38, statusCard);
        _totalChecksLabel = CreateStatusLabel("累计检查：", $"{status.TotalChecks} 次",
            Theme.TextSecondary, 16, 64, statusCard);
        _totalUpdatesLabel = CreateStatusLabel("累计更新：", $"{status.TotalUpdatesApplied} 次",
            Theme.TextSecondary, 300, 64, statusCard);

        if (!string.IsNullOrEmpty(status.LastError))
        {
            var errorLabel = new Label
            {
                Text = $"最后错误: {status.LastError}",
                Font = Theme.SmallFont,
                ForeColor = Theme.Error,
                Location = new Point(16, 96),
                Size = new Size(w - 32, 40),
                BackColor = Color.Transparent
            };
            statusCard.Controls.Add(errorLabel);
        }

        y += 170;

        // ===== 更新设置卡片 =====
        CreateTabSectionTitle("更新设置", 0, y);
        y += 30;

        var settingsCard = CreateTabCard(0, y, w, 200);

        // 更新通道
        var channelLabel = new Label
        {
            Text = "更新通道：",
            Font = Theme.BodyFont,
            ForeColor = Theme.TextSecondary,
            Location = new Point(16, 14),
            Size = new Size(100, 22),
            BackColor = Color.Transparent
        };
        settingsCard.Controls.Add(channelLabel);

        _channelCombo = new ComboBox
        {
            Location = new Point(120, 12),
            Size = new Size(160, 24),
            FlatStyle = FlatStyle.Flat,
            Font = Theme.BodyFont,
            DropDownStyle = ComboBoxStyle.DropDownList
        };
        _channelCombo.Items.AddRange(new object[] { "稳定版 (Stable)", "测试版 (Beta)", "每夜版 (Nightly)" });
        var currentChannel = AppState.Config.CloudUpdate.Channel?.ToLowerInvariant();
        _channelCombo.SelectedIndex = currentChannel switch
        {
            "beta" => 1,
            "nightly" => 2,
            _ => 0
        };
        _channelCombo.SelectedIndexChanged += (s, e) =>
        {
            var channel = _channelCombo.SelectedIndex switch
            {
                1 => "Beta",
                2 => "Nightly",
                _ => "Stable"
            };
            AppState.Config.CloudUpdate.Channel = channel;
            ConfigManager.Save(AppState.Config);
            if (_scheduler != null)
            {
                _scheduler.Channel = channel.ToLowerInvariant() switch
                {
                    "beta" => UpdateChannel.Beta,
                    "nightly" => UpdateChannel.Nightly,
                    _ => UpdateChannel.Stable
                };
            }
        };
        settingsCard.Controls.Add(_channelCombo);

        var channelDesc = new Label
        {
            Text = "稳定版经过完整测试；测试版可预览新功能；每夜版最新但不稳定",
            Font = Theme.SmallFont,
            ForeColor = Theme.TextTertiary,
            Location = new Point(290, 14),
            Size = new Size(400, 20),
            BackColor = Color.Transparent
        };
        settingsCard.Controls.Add(channelDesc);

        // 检查间隔
        var intervalLabel = new Label
        {
            Text = "检查间隔：",
            Font = Theme.BodyFont,
            ForeColor = Theme.TextSecondary,
            Location = new Point(16, 48),
            Size = new Size(100, 22),
            BackColor = Color.Transparent
        };
        settingsCard.Controls.Add(intervalLabel);

        _intervalCombo = new ComboBox
        {
            Location = new Point(120, 46),
            Size = new Size(160, 24),
            FlatStyle = FlatStyle.Flat,
            Font = Theme.BodyFont,
            DropDownStyle = ComboBoxStyle.DropDownList
        };
        _intervalCombo.Items.AddRange(new object[] { "每 6 小时", "每 12 小时", "每天", "每 3 天", "每周" });
        var intervalHours = AppState.Config.CloudUpdate.CheckIntervalHours;
        _intervalCombo.SelectedIndex = intervalHours switch
        {
            6 => 0,
            12 => 1,
            24 => 2,
            72 => 3,
            168 => 4,
            _ => 1
        };
        _intervalCombo.SelectedIndexChanged += (s, e) =>
        {
            var hours = _intervalCombo.SelectedIndex switch
            {
                0 => 6,
                1 => 12,
                2 => 24,
                3 => 72,
                4 => 168,
                _ => 12
            };
            AppState.Config.CloudUpdate.CheckIntervalHours = hours;
            ConfigManager.Save(AppState.Config);
            if (_scheduler != null)
            {
                _scheduler.CheckInterval = TimeSpan.FromHours(hours);
            }
        };
        settingsCard.Controls.Add(_intervalCombo);

        // 自动更新开关
        var autoLabel = new Label
        {
            Text = "自动更新：",
            Font = Theme.BodyFont,
            ForeColor = Theme.TextSecondary,
            Location = new Point(16, 86),
            Size = new Size(100, 22),
            BackColor = Color.Transparent
        };
        settingsCard.Controls.Add(autoLabel);

        _autoUpdateToggle = new ToggleSwitch
        {
            Location = new Point(120, 88),
            IsOn = AppState.Config.CloudUpdate.AutoApply
        };
        _autoUpdateToggle.Toggled += (on) =>
        {
            AppState.Config.CloudUpdate.AutoApply = on;
            AppState.Config.CloudUpdate.Enabled = on;
            ConfigManager.Save(AppState.Config);
            if (_scheduler != null)
            {
                _scheduler.AutoApply = on;
            }
        };
        settingsCard.Controls.Add(_autoUpdateToggle);

        var autoDesc = new Label
        {
            Text = "开启后定时自动检查并应用规则更新（需 RSA 签名校验通过）",
            Font = Theme.SmallFont,
            ForeColor = Theme.TextTertiary,
            Location = new Point(170, 88),
            Size = new Size(400, 20),
            BackColor = Color.Transparent
        };
        settingsCard.Controls.Add(autoDesc);

        // 服务器地址
        var serverLabel = new Label
        {
            Text = "服务器：",
            Font = Theme.BodyFont,
            ForeColor = Theme.TextSecondary,
            Location = new Point(16, 122),
            Size = new Size(100, 22),
            BackColor = Color.Transparent
        };
        settingsCard.Controls.Add(serverLabel);

        var serverUrlLabel = new Label
        {
            Text = AppState.Config.CloudUpdate.ServerUrl,
            Font = Theme.SmallFont,
            ForeColor = Theme.TextTertiary,
            Location = new Point(120, 122),
            Size = new Size(500, 20),
            BackColor = Color.Transparent
        };
        settingsCard.Controls.Add(serverUrlLabel);

        // RSA 公钥信息
        var rsaLabel = new Label
        {
            Text = "RSA-2048 公钥已内置，所有更新包均经过 SHA256 + RSA 双重校验",
            Font = Theme.SmallFont,
            ForeColor = Theme.Success,
            Location = new Point(16, 152),
            Size = new Size(w - 32, 20),
            BackColor = Color.Transparent
        };
        settingsCard.Controls.Add(rsaLabel);

        y += 220;

        // ===== 操作区 =====
        CreateTabSectionTitle("手动操作", 0, y);
        y += 30;

        var actionCard = CreateTabCard(0, y, w, 60);

        _checkBtn = new AccentButton
        {
            Text = "立即检查更新",
            Location = new Point(16, 12),
            Size = new Size(160, 36)
        };
        _checkBtn.Click += () => _ = StartCheckAllUpdatesAsync();
        actionCard.Controls.Add(_checkBtn);

        _progressLabel = new Label
        {
            Text = "就绪",
            Font = Theme.BodyFont,
            ForeColor = Theme.TextSecondary,
            Location = new Point(190, 18),
            Size = new Size(400, 22),
            BackColor = Color.Transparent
        };
        actionCard.Controls.Add(_progressLabel);
    }

    // ==================== 标签页 2: 规则管理 ====================

    private void RenderRuleManagementTab()
    {
        if (_tabContentArea == null) return;
        int y = 0;
        int w = _tabContentArea.Width;

        // ===== 操作栏 =====
        var actionCard = CreateTabCard(0, y, w, 56);

        _updateAllBtn = new AccentButton
        {
            Text = "全部更新",
            Location = new Point(16, 10),
            Size = new Size(120, 36)
        };
        _updateAllBtn.Click += () => _ = StartUpdateAllAsync();
        actionCard.Controls.Add(_updateAllBtn);

        _ruleProgressLabel = new Label
        {
            Text = "",
            Font = Theme.BodyFont,
            ForeColor = Theme.TextSecondary,
            Location = new Point(150, 18),
            Size = new Size(400, 22),
            BackColor = Color.Transparent
        };
        actionCard.Controls.Add(_ruleProgressLabel);

        y += 66;

        // ===== 进度条 =====
        _progressBarPanel = new Panel
        {
            Location = new Point(0, y),
            Size = new Size(w, 8),
            BackColor = Color.Transparent
        };
        _progressBarPanel.Paint += (s, e) =>
        {
            var g = e.Graphics;
            g.SmoothingMode = SmoothingMode.AntiAlias;
            // 背景
            using var bgBrush = new SolidBrush(Theme.Border);
            Theme.FillRoundedRect(g, bgBrush, new Rectangle(0, 2, w, 4), 2);
            // 进度
            var progressWidth = (int)(w * _currentProgress);
            if (progressWidth > 0)
            {
                using var pBrush = new SolidBrush(Theme.Accent);
                Theme.FillRoundedRect(g, pBrush, new Rectangle(0, 2, progressWidth, 4), 2);
            }
        };
        _tabContentArea.Controls.Add(_progressBarPanel);
        y += 18;

        // ===== 规则列表表头 =====
        CreateTabSectionTitle("规则列表", 0, y);
        y += 30;

        var headerCard = CreateTabCard(0, y, w, 30);
        var headers = new[] { "规则名称", "当前版本", "最新版本", "状态", "操作" };
        var xPositions = new[] { 8, 200, 320, 440, 560 };
        var widths = new[] { 186, 114, 114, 114, 120 };

        for (int i = 0; i < headers.Length; i++)
        {
            var hLabel = new Label
            {
                Text = headers[i],
                Font = Theme.SmallFont,
                ForeColor = Theme.TextSecondary,
                Location = new Point(xPositions[i], 5),
                Size = new Size(widths[i], 20),
                BackColor = Color.Transparent
            };
            headerCard.Controls.Add(hLabel);
        }
        y += 36;

        // ===== 规则行 =====
        foreach (RuleType rt in Enum.GetValues<RuleType>())
        {
            var ruleCard = CreateTabCard(0, y, w, 32);

            var currentVersion = _client?.GetLocalVersion(rt) ?? "0.0.0";
            var displayName = CloudUpdateClient.GetRuleDisplayName(rt);

            var nameLabels = new[]
            {
                displayName,
                currentVersion,
                "—",
                "未知",
                ""
            };

            for (int i = 0; i < 4; i++)
            {
                var vLabel = new Label
                {
                    Text = nameLabels[i],
                    Font = Theme.SmallFont,
                    ForeColor = Theme.TextPrimary,
                    Location = new Point(xPositions[i], 6),
                    Size = new Size(widths[i], 20),
                    BackColor = Color.Transparent,
                    Tag = rt
                };
                ruleCard.Controls.Add(vLabel);
            }

            // 更新按钮
            var updateBtn = new AccentButton
            {
                Text = "更新",
                Location = new Point(xPositions[4], 0),
                Size = new Size(80, 28),
                Font = Theme.SmallFont
            };
            var ruleType = rt;
            updateBtn.Click += () => _ = StartUpdateSingleAsync(ruleType, updateBtn);
            ruleCard.Controls.Add(updateBtn);

            y += 38;
        }

        y += 20;

        // 规则说明
        var descCard = CreateTabCard(0, y, w, 90);
        var descText = new Label
        {
            Text = "规则说明：\n" +
                   "  YARA 勒索规则库 - 用于勒索病毒行为特征匹配\n" +
                   "  广告拦截规则库 - 阻止广告和流氓软件\n" +
                   "  解密工具索引 - 勒索解密工具版本索引\n" +
                   "  病毒特征数据库 - ClamAV 病毒特征库",
            Font = Theme.SmallFont,
            ForeColor = Theme.TextSecondary,
            Location = new Point(16, 10),
            Size = new Size(w - 32, 72),
            BackColor = Color.Transparent
        };
        descCard.Controls.Add(descText);
    }

    // ==================== 标签页 3: 更新历史 ====================

    private void RenderHistoryTab()
    {
        if (_tabContentArea == null) return;
        int y = 0;
        int w = _tabContentArea.Width;

        // ===== 操作栏 =====
        var actionCard = CreateTabCard(0, y, w, 56);

        var exportBtn = new AccentButton
        {
            Text = "导出历史",
            Location = new Point(16, 10),
            Size = new Size(120, 36)
        };
        exportBtn.Click += () =>
        {
            if (_scheduler == null) return;
            using var dialog = new SaveFileDialog
            {
                Title = "导出更新历史",
                Filter = "CSV 文件|*.csv",
                FileName = $"cloud_update_history_{DateTime.Now:yyyyMMdd}.csv"
            };
            if (dialog.ShowDialog() == DialogResult.OK)
            {
                if (_scheduler.ExportHistoryToCsv(dialog.FileName))
                    MessageBoxHelper.Info($"更新历史已导出到:\n{dialog.FileName}");
                else
                    MessageBoxHelper.Error("导出失败，请查看日志");
            }
        };
        actionCard.Controls.Add(exportBtn);

        var historyCountLabel = new Label
        {
            Text = $"共 {_scheduler?.GetHistory(0).Count ?? 0} 条记录",
            Font = Theme.BodyFont,
            ForeColor = Theme.TextSecondary,
            Location = new Point(150, 18),
            Size = new Size(200, 22),
            BackColor = Color.Transparent
        };
        actionCard.Controls.Add(historyCountLabel);

        y += 66;

        // ===== 历史列表表头 =====
        var headerCard = CreateTabCard(0, y, w, 30);
        var headers = new[] { "时间", "规则类型", "旧版本", "新版本", "状态" };
        var xPositions = new[] { 8, 180, 330, 440, 550 };
        var widths = new[] { 166, 144, 104, 104, 130 };

        for (int i = 0; i < headers.Length; i++)
        {
            var hLabel = new Label
            {
                Text = headers[i],
                Font = Theme.SmallFont,
                ForeColor = Theme.TextSecondary,
                Location = new Point(xPositions[i], 5),
                Size = new Size(widths[i], 20),
                BackColor = Color.Transparent
            };
            headerCard.Controls.Add(hLabel);
        }
        y += 36;

        // ===== 历史记录列表 =====
        var history = _scheduler?.GetHistory(50) ?? new List<UpdateHistoryEntry>();

        if (history.Count == 0)
        {
            var emptyLabel = new Label
            {
                Text = "暂无更新历史记录",
                Font = Theme.BodyFont,
                ForeColor = Theme.TextTertiary,
                Location = new Point(0, y + 20),
                Size = new Size(w, 24),
                BackColor = Color.Transparent,
                TextAlign = ContentAlignment.MiddleCenter
            };
            _tabContentArea.Controls.Add(emptyLabel);
            return;
        }

        foreach (var entry in history)
        {
            var entryCard = CreateTabCard(0, y, w, 28);

            var values = new[]
            {
                entry.Timestamp.ToString("yyyy-MM-dd HH:mm"),
                CloudUpdateClient.GetRuleDisplayName(entry.RuleType),
                entry.OldVersion,
                entry.NewVersion,
                entry.Success ? "成功" : "失败"
            };

            for (int i = 0; i < values.Length; i++)
            {
                var vLabel = new Label
                {
                    Text = values[i],
                    Font = Theme.SmallFont,
                    ForeColor = i == 4
                        ? (entry.Success ? Theme.Success : Theme.Error)
                        : Theme.TextPrimary,
                    Location = new Point(xPositions[i], 4),
                    Size = new Size(widths[i], 20),
                    BackColor = Color.Transparent
                };
                entryCard.Controls.Add(vLabel);
            }

            y += 34;
        }
    }

    // ==================== 交互逻辑 ====================

    private double _currentProgress;

    /// <summary>开始检查所有更新</summary>
    private async Task StartCheckAllUpdatesAsync()
    {
        if (_isUpdating || _client == null) return;
        _isUpdating = true;
        if (_checkBtn != null) _checkBtn.Enabled = false;
        if (_progressLabel != null)
        {
            _progressLabel.Text = "正在检查所有规则更新...";
            _progressLabel.ForeColor = Theme.Warning;
        }

        _currentProgress = 0.05;
        _progressBarPanel?.Invalidate();

        try
        {
            // 订阅进度事件
            _client.ProgressChanged += OnProgressChanged;

            var results = await _client.CheckAllUpdatesAsync();

            _client.ProgressChanged -= OnProgressChanged;

            _currentProgress = 1.0;
            _progressBarPanel?.Invalidate();

            var updateCount = results.Count(r => r.HasUpdate);
            if (_progressLabel != null)
            {
                _progressLabel.Text = updateCount > 0
                    ? $"检查完成，发现 {updateCount} 个可用更新"
                    : "检查完成，所有规则均为最新版本";
                _progressLabel.ForeColor = updateCount > 0 ? Theme.Warning : Theme.Success;
            }

            // 如果有更新，切换到规则管理标签
            if (updateCount > 0)
            {
                await Task.Delay(800);
                SwitchTab(1);
            }
        }
        catch (Exception ex)
        {
            if (_progressLabel != null)
            {
                _progressLabel.Text = $"检查失败: {ex.Message}";
                _progressLabel.ForeColor = Theme.Error;
            }
        }
        finally
        {
            _isUpdating = false;
            if (_checkBtn != null) _checkBtn.Enabled = true;
        }
    }

    /// <summary>开始更新所有规则</summary>
    private async Task StartUpdateAllAsync()
    {
        if (_isUpdating || _scheduler == null) return;
        _isUpdating = true;
        if (_updateAllBtn != null) _updateAllBtn.Enabled = false;

        _currentProgress = 0.0;
        _progressBarPanel?.Invalidate();

        try
        {
            var results = await _scheduler.CheckAndApplyAllAsync();

            _currentProgress = 1.0;
            _progressBarPanel?.Invalidate();

            var successCount = results.Count(r => r.Success);
            if (_ruleProgressLabel != null)
            {
                _ruleProgressLabel.Text = results.Count == 0
                    ? "所有规则均为最新版本"
                    : $"更新完成：成功 {successCount} / {results.Count} 项";
                _ruleProgressLabel.ForeColor = successCount == results.Count
                    ? Theme.Success
                    : (successCount > 0 ? Theme.Warning : Theme.Error);
            }

            // 刷新页面
            await Task.Delay(800);
            RenderCurrentTab();
        }
        catch (Exception ex)
        {
            if (_ruleProgressLabel != null)
            {
                _ruleProgressLabel.Text = $"更新失败: {ex.Message}";
                _ruleProgressLabel.ForeColor = Theme.Error;
            }
        }
        finally
        {
            _isUpdating = false;
            if (_updateAllBtn != null) _updateAllBtn.Enabled = true;
        }
    }

    /// <summary>更新单个规则</summary>
    private async Task StartUpdateSingleAsync(RuleType ruleType, AccentButton btn)
    {
        if (_isUpdating || _scheduler == null) return;
        _isUpdating = true;
        btn.Enabled = false;
        btn.Text = "更新中...";

        if (_ruleProgressLabel != null)
        {
            _ruleProgressLabel.Text = $"正在更新 {CloudUpdateClient.GetRuleDisplayName(ruleType)}...";
            _ruleProgressLabel.ForeColor = Theme.Warning;
        }

        _currentProgress = 0.1;
        _progressBarPanel?.Invalidate();

        try
        {
            var success = await _scheduler.CheckAndApplyAsync(ruleType);

            _currentProgress = 1.0;
            _progressBarPanel?.Invalidate();

            if (_ruleProgressLabel != null)
            {
                _ruleProgressLabel.Text = success
                    ? $"{CloudUpdateClient.GetRuleDisplayName(ruleType)} 更新成功"
                    : $"{CloudUpdateClient.GetRuleDisplayName(ruleType)} 无可用更新或更新失败";
                _ruleProgressLabel.ForeColor = success ? Theme.Success : Theme.Warning;
            }

            await Task.Delay(800);
            RenderCurrentTab();
        }
        catch (Exception ex)
        {
            if (_ruleProgressLabel != null)
            {
                _ruleProgressLabel.Text = $"更新失败: {ex.Message}";
                _ruleProgressLabel.ForeColor = Theme.Error;
            }
        }
        finally
        {
            _isUpdating = false;
        }
    }

    /// <summary>进度事件处理</summary>
    private void OnProgressChanged(UpdateProgress progress)
    {
        _currentProgress = progress.PercentComplete / 100.0;
        _progressBarPanel?.Invalidate();
        if (_progressLabel != null && progress.IsRunning)
        {
            _progressLabel.Text = $"[{progress.PercentComplete:F0}%] {progress.CurrentFile}";
            _progressLabel.ForeColor = Theme.Warning;
        }
    }

    // ==================== UI 辅助方法 ====================

    /// <summary>创建标签内容区内的分区标题</summary>
    private void CreateTabSectionTitle(string text, int x, int y)
    {
        if (_tabContentArea == null) return;
        var label = new Label
        {
            Text = text,
            Font = Theme.HeaderFont,
            ForeColor = Theme.TextPrimary,
            Location = new Point(x, y),
            Size = new Size(400, 24),
            BackColor = Color.Transparent
        };
        _tabContentArea.Controls.Add(label);
    }

    /// <summary>创建标签内容区内的卡片</summary>
    private Panel CreateTabCard(int x, int y, int width, int height)
    {
        if (_tabContentArea == null) return new Panel();
        var card = new Panel
        {
            Location = new Point(x, y),
            Size = new Size(width, height),
            BackColor = Color.Transparent
        };
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
        _tabContentArea.Controls.Add(card);
        return card;
    }

    /// <summary>创建状态标签（左标题 + 右值）</summary>
    private Label CreateStatusLabel(string title, string value, Color valueColor, int x, int y, Control parent)
    {
        var label = new Label
        {
            Text = $"{title}{value}",
            Font = Theme.BodyFont,
            ForeColor = valueColor,
            Location = new Point(x, y),
            Size = new Size(280, 22),
            BackColor = Color.Transparent
        };
        parent.Controls.Add(label);
        return label;
    }

    // ==================== 页面基类回调 ====================

    public override void RefreshData()
    {
        BuildContent();
    }
}
