using System.Drawing.Drawing2D;
using System.Diagnostics;
using LightGuard.Core;
using LightGuard.Defender;
using LightGuard.Modules;
using LightGuard.Security;
using LightGuard.UI.Controls;

// 消歧义：LightGuard.Modules 命名空间已存在同名 DefenderStatusInfo（FirewallModule 双杀检测用），
// 此处显式绑定到本模块所在的 LightGuard.Defender.DefenderStatusInfo。
using DefenderStatusInfo = LightGuard.Defender.DefenderStatusInfo;

namespace LightGuard.UI.Pages;

/// <summary>
/// Defender 按需查杀页面（P0-4）
/// 四标签页：扫描概览 / 按需扫描 / 扫描历史 / 策略配置
/// 扫描在后台线程执行，通过 ProgressChanged 实时回传进度，不阻塞 UI。
/// </summary>
public class DefenderScanPage : Page
{
    private DefenderScanModule? _module;
    private DefenderScannerHelper? _scanner;
    private DefenderScannerHelper? _subscribedScanner;

    // 标签页
    private Panel? _tabBar;
    private readonly List<TabButton> _tabButtons = new();
    private Panel? _overviewPanel;
    private Panel? _scanPanel;
    private Panel? _historyPanel;
    private Panel? _policyPanel;
    private int _activeTab;

    // 扫描页控件
    private Label? _pathLabel;
    private ProgressBar? _progressBar;
    private Label? _progressStatusLabel;
    private AccentButton? _cancelBtn;
    private ListView? _threatListView;
    private Label? _resultSummaryLabel;
    private CancellationTokenSource? _cts;
    private bool _isScanning;

    // 概览页控件
    private Label? _statusDetailLabel;

    // 策略页控件
    private ComboBox? _priorityCombo;
    private ComboBox? _remediationCombo;
    private ToggleSwitch? _autoScanBeforeBackupToggle;

    // P1-5 调度策略控件
    private ToggleSwitch? _scheduleToggle;
    private ComboBox? _scanTimeCombo;
    private ComboBox? _scheduleTypeCombo;
    private ToggleSwitch? _autoSigToggle;
    private ComboBox? _sigMaxAgeCombo;
    private ToggleSwitch? _alertThreatToggle;
    private ToggleSwitch? _alertProtectionToggle;

    // 历史页威胁清单
    private ListView? _threatListLv;

    // 策略状态（持久化到 AppConfig）
    private ProcessPriorityClass _scanPriority = ProcessPriorityClass.Normal;
    private ThreatAction _remediationAction = ThreatAction.Quarantine;
    private bool _autoScanBeforeBackup = true;

    // P1-5 调度策略状态（持久化到 AppConfig.Defender）
    private bool _scheduleEnabled = true;
    private string _scanTime = "02:30";
    private string _scheduleScanType = "QuickScan";
    private bool _autoUpdateSignatures = true;
    private int _sigMaxAgeDays = 3;
    private bool _alertOnThreat = true;
    private bool _alertOnProtectionDisabled = true;

    private const int TabBarHeight = 38;

    public DefenderScanPage(AppState appState)
        : base(appState, "Defender 按需查杀", "Microsoft Defender 智能调度引擎")
    {
    }

    public override void OnShown()
    {
        _module = AppState.Modules.GetModule("defender-scan") as DefenderScanModule;
        LoadPolicyFromConfig();
        AttachScanner();
        BuildContent();
        CheckDefenderCompatibility();
    }

    /// <summary>从配置加载扫描策略（P1-5：优先级/处置动作/调度/告警全量持久化）</summary>
    private void LoadPolicyFromConfig()
    {
        _autoScanBeforeBackup = AppState.Config.Backup.ScanBeforeBackup;

        var cfg = AppState.Config.Defender;
        _scanPriority = cfg.ScanPriority == 1 ? ProcessPriorityClass.BelowNormal : ProcessPriorityClass.Normal;
        _remediationAction = cfg.ThreatAction switch
        {
            "Remove" => ThreatAction.Remove,
            "Allow" => ThreatAction.Allow,
            "None" => ThreatAction.None,
            _ => ThreatAction.Quarantine
        };
        _scheduleEnabled = cfg.ScheduleEnabled;
        _scanTime = string.IsNullOrWhiteSpace(cfg.ScanTime) ? "02:30" : cfg.ScanTime;
        _scheduleScanType = string.IsNullOrWhiteSpace(cfg.ScheduleScanType) ? "QuickScan" : cfg.ScheduleScanType;
        _autoUpdateSignatures = cfg.AutoUpdateSignatures;
        _sigMaxAgeDays = cfg.SignatureMaxAgeDays > 0 ? cfg.SignatureMaxAgeDays : 3;
        _alertOnThreat = cfg.AlertOnThreat;
        _alertOnProtectionDisabled = cfg.AlertOnProtectionDisabled;
    }

    /// <summary>保存调度/告警策略到 AppConfig.Defender 并落盘（P1-5）。</summary>
    private void SaveDefenderPolicy()
    {
        var cfg = AppState.Config.Defender;
        cfg.ScanPriority = _scanPriority == ProcessPriorityClass.BelowNormal ? 1 : 0;
        cfg.ThreatAction = _remediationAction switch
        {
            ThreatAction.Remove => "Remove",
            ThreatAction.Allow => "Allow",
            ThreatAction.None => "None",
            _ => "Quarantine"
        };
        cfg.ScheduleEnabled = _scheduleEnabled;
        cfg.ScanTime = _scanTime;
        cfg.ScheduleScanType = _scheduleScanType;
        cfg.AutoUpdateSignatures = _autoUpdateSignatures;
        cfg.SignatureMaxAgeDays = _sigMaxAgeDays;
        cfg.AlertOnThreat = _alertOnThreat;
        cfg.AlertOnProtectionDisabled = _alertOnProtectionDisabled;
        ConfigManager.Save(AppState.Config);
        ErrorReporter.Log("[Defender] 扫描/调度策略已保存到配置");
    }

    /// <summary>
    /// 兼容性检查：第三方杀毒导致 Defender 禁用时，置灰扫描按钮并提示。
    /// </summary>
    private void CheckDefenderCompatibility()
    {
        bool available = DefenderIntegrationService.IsAvailable(out var reason, out var detailed);
        if (available) return;

        ErrorReporter.Log($"Defender 兼容性检查：{detailed}", "WARN");
        if (_scanPanel == null) return;

        foreach (Control c in _scanPanel.Controls)
        {
            if (c is AccentButton ab && ab.Text is "单文件扫描" or "目录扫描" or "快速扫描" or "全盘扫描")
                ab.Enabled = false;
        }

        if (_progressStatusLabel != null)
        {
            _progressStatusLabel.Text = $"⚠ {reason}";
            _progressStatusLabel.ForeColor = Theme.Warning;
        }
    }

    /// <summary>订阅扫描助手的进度事件（模块可能被重新启用，需切换订阅对象）</summary>
    private void AttachScanner()
    {
        var current = _module?.Scanner;
        if (ReferenceEquals(current, _subscribedScanner))
            return;

        if (_subscribedScanner != null)
            _subscribedScanner.ProgressChanged -= OnScanProgress;

        _scanner = current;
        if (_scanner != null)
        {
            _scanner.ScanPriority = _scanPriority;
            _scanner.ProgressChanged += OnScanProgress;
        }
        _subscribedScanner = _scanner;
    }

    /// <summary>构建整个页面（标签栏 + 四个标签面板）</summary>
    private void BuildContent()
    {
        ScrollContent.Controls.Clear();
        _tabButtons.Clear();

        int y = 0;

        // ===== 标签栏 =====
        _tabBar = new Panel
        {
            Location = new Point(0, y),
            Size = new Size(ContentWidth, TabBarHeight),
            BackColor = Color.Transparent
        };
        typeof(Control).GetProperty("DoubleBuffered",
            System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)
            ?.SetValue(_tabBar, true, null);
        ScrollContent.Controls.Add(_tabBar);

        var tabTitles = new[] { "扫描概览", "按需扫描", "扫描历史", "策略配置" };
        int tabX = 0;
        foreach (var title in tabTitles)
        {
            var btn = new TabButton(title)
            {
                Location = new Point(tabX, 0),
                Size = new Size(130, TabBarHeight)
            };
            btn.Activated += () => SwitchTab(_tabButtons.IndexOf(btn));
            _tabBar.Controls.Add(btn);
            _tabButtons.Add(btn);
            tabX += 130;
        }

        y += TabBarHeight + 8;

        // ===== 四个标签面板（同一位置，仅显示一个） =====
        _overviewPanel = new Panel
        {
            Location = new Point(0, y),
            Size = new Size(ContentWidth, 600),
            BackColor = Color.Transparent
        };
        _scanPanel = new Panel
        {
            Location = new Point(0, y),
            Size = new Size(ContentWidth, 600),
            BackColor = Color.Transparent
        };
        _historyPanel = new Panel
        {
            Location = new Point(0, y),
            Size = new Size(ContentWidth, 600),
            BackColor = Color.Transparent
        };
        _policyPanel = new Panel
        {
            Location = new Point(0, y),
            Size = new Size(ContentWidth, 600),
            BackColor = Color.Transparent
        };
        ScrollContent.Controls.Add(_overviewPanel);
        ScrollContent.Controls.Add(_scanPanel);
        ScrollContent.Controls.Add(_historyPanel);
        ScrollContent.Controls.Add(_policyPanel);

        BuildOverviewTab();
        BuildScanTab();
        BuildHistoryTab();
        BuildPolicyTab();

        SwitchTab(_activeTab);
    }

    // ==================== 标签切换 ====================

    private void SwitchTab(int index)
    {
        if (index < 0 || index >= _tabButtons.Count) return;
        _activeTab = index;

        for (int i = 0; i < _tabButtons.Count; i++)
            _tabButtons[i].IsActive = i == index;

        if (_overviewPanel != null) _overviewPanel.Visible = index == 0;
        if (_scanPanel != null) _scanPanel.Visible = index == 1;
        if (_historyPanel != null) _historyPanel.Visible = index == 2;
        if (_policyPanel != null) _policyPanel.Visible = index == 3;

        if (index == 0) RefreshOverview();
        if (index == 2) RefreshHistory();
    }

    // ==================== 概览标签 ====================

    private void BuildOverviewTab()
    {
        if (_overviewPanel == null) return;
        _overviewPanel.Controls.Clear();

        int y = 0;

        // 健康状态卡片
        var healthCard = CreateCardIn(_overviewPanel, 0, y, ContentWidth, 70);

        _statusDetailLabel = new Label
        {
            Text = "正在获取 Defender 状态...",
            Font = Theme.BodyFont,
            ForeColor = Theme.TextSecondary,
            Location = new Point(16, 12),
            Size = new Size(ContentWidth - 220, 46),
            BackColor = Color.Transparent
        };
        healthCard.Controls.Add(_statusDetailLabel);

        var refreshBtn = new AccentButton
        {
            Text = "刷新状态",
            Location = new Point(ContentWidth - 190, 18),
            Size = new Size(80, 34)
        };
        refreshBtn.Click += () => RefreshOverview();
        healthCard.Controls.Add(refreshBtn);

        var updateSigBtn = new AccentButton
        {
            Text = "更新病毒库",
            Location = new Point(ContentWidth - 100, 18),
            Size = new Size(86, 34)
        };
        updateSigBtn.Click += async () =>
        {
            updateSigBtn.Enabled = false;
            MessageBoxHelper.Info("正在更新 Defender 病毒库签名...");
            if (_module != null)
                await _module.UpdateSignaturesAsync();
            updateSigBtn.Enabled = true;
            MessageBoxHelper.Info("病毒库更新流程已完成。");
            RefreshOverview();
        };
        healthCard.Controls.Add(updateSigBtn);

        y += 90;

        // 详细信息卡片
        CreateSectionTitleIn(_overviewPanel, "引擎与病毒库信息", 0, y);
        y += 30;

        var detailCard = CreateCardIn(_overviewPanel, 0, y, ContentWidth, 180);
        // 表头
        var headers = new[] { "项目", "状态 / 版本" };
        var rows = new[]
        {
            ("实时保护", ""),
            ("反病毒引擎", ""),
            ("反间谍软件", ""),
            ("病毒库版本", ""),
            ("病毒库最后更新", ""),
            ("引擎版本", ""),
            ("产品版本", "")
        };

        int ry = 10;
        var nameLabels = new Label[rows.Length];
        var valueLabels = new Label[rows.Length];
        for (int i = 0; i < rows.Length; i++)
        {
            nameLabels[i] = new Label
            {
                Text = rows[i].Item1,
                Font = Theme.BodyFont,
                ForeColor = Theme.TextSecondary,
                Location = new Point(16, ry),
                Size = new Size(160, 22),
                BackColor = Color.Transparent
            };
            detailCard.Controls.Add(nameLabels[i]);

            valueLabels[i] = new Label
            {
                Text = "—",
                Font = Theme.BodyFont,
                ForeColor = Theme.TextPrimary,
                Location = new Point(180, ry),
                Size = new Size(ContentWidth - 200, 22),
                BackColor = Color.Transparent
            };
            detailCard.Controls.Add(valueLabels[i]);
            ry += 24;
        }

        // 缓存值标签引用到面板 Tag 以便刷新
        _overviewPanel.Tag = valueLabels;

        y += 200;
    }

    /// <summary>刷新概览数据</summary>
    private void RefreshOverview()
    {
        if (_module == null || _statusDetailLabel == null) return;

        DefenderStatusInfo status;
        try
        {
            status = Task.Run(() => _module.GetDefenderStatus()).Result;
        }
        catch
        {
            status = new DefenderStatusInfo { ErrorMessage = "状态查询失败" };
        }

        // 健康摘要
        var healthText = status.IsValid
            ? (status.IsHealthy ? "● 健康 - Defender 运行正常" : "● 需关注 - 请检查实时保护或病毒库")
            : $"● 未知 - {status.ErrorMessage}";
        _statusDetailLabel.Text = healthText;
        _statusDetailLabel.ForeColor = status.IsHealthy ? Theme.Success : (status.IsValid ? Theme.Warning : Theme.Error);

        // 详细信息
        if (_overviewPanel?.Tag is Label[] valueLabels && valueLabels.Length >= 7)
        {
            valueLabels[0].Text = status.RealTimeProtectionEnabled ? "已启用" : "未启用";
            valueLabels[0].ForeColor = status.RealTimeProtectionEnabled ? Theme.Success : Theme.Error;
            valueLabels[1].Text = status.AntivirusEnabled ? "已启用" : "未启用";
            valueLabels[1].ForeColor = status.AntivirusEnabled ? Theme.Success : Theme.Error;
            valueLabels[2].Text = status.AntispywareEnabled ? "已启用" : "未启用";
            valueLabels[2].ForeColor = status.AntispywareEnabled ? Theme.Success : Theme.Error;
            valueLabels[3].Text = string.IsNullOrEmpty(status.SignatureVersion) ? "未知" : status.SignatureVersion;
            valueLabels[4].Text = status.SignatureLastUpdated == default
                ? "从未"
                : status.SignatureLastUpdated.ToString("yyyy-MM-dd HH:mm");
            valueLabels[5].Text = string.IsNullOrEmpty(status.EngineVersion) ? "未知" : status.EngineVersion;
            valueLabels[6].Text = string.IsNullOrEmpty(status.ProductVersion) ? "未知" : status.ProductVersion;
        }
    }

    // ==================== 按需扫描标签 ====================

    private void BuildScanTab()
    {
        if (_scanPanel == null) return;
        _scanPanel.Controls.Clear();

        int y = 0;

        CreateSectionTitleIn(_scanPanel, "扫描目标", 0, y);
        y += 30;

        // 路径展示
        var pathCard = CreateCardIn(_scanPanel, 0, y, ContentWidth, 56);
        _pathLabel = new Label
        {
            Text = "（单文件/目录扫描请点击下方按钮选择目标）",
            Font = Theme.BodyFont,
            ForeColor = Theme.TextTertiary,
            Location = new Point(16, 16),
            Size = new Size(ContentWidth - 32, 24),
            BackColor = Color.Transparent,
            AutoEllipsis = true
        };
        pathCard.Controls.Add(_pathLabel);
        y += 76;

        // 四个扫描按钮
        CreateSectionTitleIn(_scanPanel, "扫描操作", 0, y);
        y += 30;

        var opCard = CreateCardIn(_scanPanel, 0, y, ContentWidth, 60);

        var fileBtn = new AccentButton
        {
            Text = "单文件扫描",
            Location = new Point(16, 12),
            Size = new Size(130, 36)
        };
        fileBtn.Click += () => StartScan(DefenderScanType.SingleFile);
        opCard.Controls.Add(fileBtn);

        var dirBtn = new AccentButton
        {
            Text = "目录扫描",
            Location = new Point(156, 12),
            Size = new Size(120, 36)
        };
        dirBtn.Click += () => StartScan(DefenderScanType.Directory);
        opCard.Controls.Add(dirBtn);

        var quickBtn = new AccentButton
        {
            Text = "快速扫描",
            Location = new Point(286, 12),
            Size = new Size(120, 36)
        };
        quickBtn.Click += () => StartScan(DefenderScanType.QuickScan);
        opCard.Controls.Add(quickBtn);

        var fullBtn = new AccentButton
        {
            Text = "全盘扫描",
            Location = new Point(416, 12),
            Size = new Size(120, 36)
        };
        fullBtn.Click += () => StartScan(DefenderScanType.FullScan);
        opCard.Controls.Add(fullBtn);

        y += 80;

        // 进度区
        CreateSectionTitleIn(_scanPanel, "扫描进度", 0, y);
        y += 30;

        var progressCard = CreateCardIn(_scanPanel, 0, y, ContentWidth, 84);

        _progressBar = new ProgressBar
        {
            Location = new Point(16, 14),
            Size = new Size(ContentWidth - 130, 18),
            Style = ProgressBarStyle.Continuous,
            Minimum = 0,
            Maximum = 100,
            Value = 0
        };
        progressCard.Controls.Add(_progressBar);

        _cancelBtn = new AccentButton
        {
            Text = "取消",
            Location = new Point(ContentWidth - 100, 8),
            Size = new Size(84, 32),
            Enabled = false
        };
        _cancelBtn.Click += () => CancelScan();
        progressCard.Controls.Add(_cancelBtn);

        _progressStatusLabel = new Label
        {
            Text = "就绪",
            Font = Theme.BodyFont,
            ForeColor = Theme.TextSecondary,
            Location = new Point(16, 44),
            Size = new Size(ContentWidth - 32, 30),
            BackColor = Color.Transparent,
            AutoEllipsis = true
        };
        progressCard.Controls.Add(_progressStatusLabel);

        y += 104;

        // 结果区
        CreateSectionTitleIn(_scanPanel, "扫描结果", 0, y);
        y += 30;

        var resultCard = CreateCardIn(_scanPanel, 0, y, ContentWidth, 200);

        _resultSummaryLabel = new Label
        {
            Text = "尚未执行扫描",
            Font = Theme.BodyFont,
            ForeColor = Theme.TextTertiary,
            Location = new Point(16, 12),
            Size = new Size(ContentWidth - 32, 24),
            BackColor = Color.Transparent
        };
        resultCard.Controls.Add(_resultSummaryLabel);

        _threatListView = new ListView
        {
            Location = new Point(16, 42),
            Size = new Size(ContentWidth - 32, 146),
            View = View.Details,
            FullRowSelect = true,
            Font = Theme.SmallFont,
            BackColor = Theme.CardBg,
            ForeColor = Theme.TextPrimary,
            BorderStyle = BorderStyle.None
        };
        _threatListView.Columns.Add("威胁名称", 220);
        _threatListView.Columns.Add("文件路径", 300);
        _threatListView.Columns.Add("严重等级", 80);
        _threatListView.Columns.Add("处置", 80);
        resultCard.Controls.Add(_threatListView);

        y += 220;
    }

    // ==================== 扫描历史标签 ====================

    private void BuildHistoryTab()
    {
        if (_historyPanel == null) return;
        _historyPanel.Controls.Clear();

        int y = 0;

        var headerCard = CreateCardIn(_historyPanel, 0, y, ContentWidth, 44);

        var title = new Label
        {
            Text = "扫描历史记录",
            Font = Theme.HeaderFont,
            ForeColor = Theme.TextPrimary,
            Location = new Point(16, 12),
            Size = new Size(300, 24),
            BackColor = Color.Transparent
        };
        headerCard.Controls.Add(title);

        var clearBtn = new AccentButton
        {
            Text = "清空历史",
            Location = new Point(ContentWidth - 110, 6),
            Size = new Size(94, 32)
        };
        clearBtn.Click += () =>
        {
            _module?.ClearHistory();
            RefreshHistory();
            MessageBoxHelper.Info("已清空扫描历史。");
        };
        headerCard.Controls.Add(clearBtn);

        y += 54;

        var listCard = CreateCardIn(_historyPanel, 0, y, ContentWidth, 420);

        var lv = new ListView
        {
            Location = new Point(8, 8),
            Size = new Size(ContentWidth - 16, 404),
            View = View.Details,
            FullRowSelect = true,
            GridLines = true,
            Font = Theme.SmallFont,
            BackColor = Theme.CardBg,
            ForeColor = Theme.TextPrimary,
            BorderStyle = BorderStyle.None
        };
        lv.Columns.Add("完成时间", 150);
        lv.Columns.Add("扫描类型", 90);
        lv.Columns.Add("威胁数", 60);
        lv.Columns.Add("耗时", 90);
        lv.Columns.Add("扫描项", 70);
        lv.Columns.Add("状态", 200);
        listCard.Controls.Add(lv);

        _historyPanel.Tag = lv;

        y += 440;

        // ===== P1-5：累计威胁清单（跨重启持久化）+ 事后处置 =====
        var threatHeader = CreateCardIn(_historyPanel, 0, y, ContentWidth, 44);

        var threatTitle = new Label
        {
            Text = "威胁清单（累计，跨重启保留）",
            Font = Theme.HeaderFont,
            ForeColor = Theme.TextPrimary,
            Location = new Point(16, 12),
            Size = new Size(300, 24),
            BackColor = Color.Transparent
        };
        threatHeader.Controls.Add(threatTitle);

        y += 54;

        var threatCard = CreateCardIn(_historyPanel, 0, y, ContentWidth, 250);

        // 处置按钮行
        var quarantineBtn = new AccentButton
        {
            Text = "隔离所选",
            Location = new Point(12, 10),
            Size = new Size(88, 28)
        };
        quarantineBtn.Click += () => HandleSelectedThreats(ThreatAction.Quarantine);
        threatCard.Controls.Add(quarantineBtn);

        var deleteBtn = new AccentButton
        {
            Text = "删除所选",
            Location = new Point(108, 10),
            Size = new Size(88, 28)
        };
        deleteBtn.Click += () => HandleSelectedThreats(ThreatAction.Remove);
        threatCard.Controls.Add(deleteBtn);

        var allowBtn = new AccentButton
        {
            Text = "允许所选",
            Location = new Point(204, 10),
            Size = new Size(88, 28)
        };
        allowBtn.Click += () => HandleSelectedThreats(ThreatAction.Allow);
        threatCard.Controls.Add(allowBtn);

        var quarantineMgmtBtn = new AccentButton
        {
            Text = "恢复隔离区",
            Location = new Point(ContentWidth - 120, 10),
            Size = new Size(104, 28)
        };
        quarantineMgmtBtn.Click += () =>
        {
            using var dialog = new QuarantineManageDialog();
            dialog.ShowDialog(this);
            RefreshThreatList();
        };
        threatCard.Controls.Add(quarantineMgmtBtn);

        var threatLv = new ListView
        {
            Location = new Point(8, 44),
            Size = new Size(ContentWidth - 16, 196),
            View = View.Details,
            FullRowSelect = true,
            GridLines = true,
            Font = Theme.SmallFont,
            BackColor = Theme.CardBg,
            ForeColor = Theme.TextPrimary,
            BorderStyle = BorderStyle.None
        };
        threatLv.Columns.Add("威胁名称", 180);
        threatLv.Columns.Add("文件路径", 320);
        threatLv.Columns.Add("严重等级", 80);
        threatLv.Columns.Add("处置", 90);
        threatLv.Columns.Add("发现时间", 130);
        threatCard.Controls.Add(threatLv);

        _threatListLv = threatLv;

        RefreshThreatList();
    }

    /// <summary>刷新威胁清单列表（持久化数据源）。</summary>
    private void RefreshThreatList()
    {
        if (_threatListLv == null) return;
        _threatListLv.Items.Clear();

        if (_module == null) return;

        var threats = _module.GetThreatList();
        for (int i = threats.Count - 1; i >= 0; i--)
        {
            var t = threats[i];
            var item = new ListViewItem(t.ThreatName);
            item.SubItems.Add(t.FilePath);
            item.SubItems.Add(t.Severity.ToString());
            item.SubItems.Add(t.ActionTaken.ToString());
            item.SubItems.Add(t.DetectedAt.ToString("yyyy-MM-dd HH:mm"));
            item.ForeColor = t.Severity >= ThreatSeverity.High ? Theme.Error : Theme.Warning;
            _threatListLv.Items.Add(item);
        }
    }

    /// <summary>
    /// 对威胁清单选中项执行事后处置（P1-5）：
    /// 隔离 = AES 加密移入隔离区并删除原文件；删除 = 直接删除；允许 = 仅记录放行。
    /// 处置结果回写模块威胁状态并持久化。
    /// </summary>
    private void HandleSelectedThreats(ThreatAction action)
    {
        if (_threatListLv == null || _module == null) return;
        if (_threatListLv.SelectedItems.Count == 0)
        {
            MessageBoxHelper.Warn("请先在威胁清单中选择要处置的条目。");
            return;
        }

        int ok = 0, fail = 0;
        foreach (ListViewItem item in _threatListLv.SelectedItems)
        {
            var threatName = item.Text;
            var filePath = item.SubItems.Count > 1 ? item.SubItems[1].Text : "";

            bool success = false;
            try
            {
                switch (action)
                {
                    case ThreatAction.Quarantine:
                        if (!string.IsNullOrEmpty(filePath) && File.Exists(filePath))
                        {
                            using var qm = new QuarantineManager();
                            success = !string.IsNullOrEmpty(qm.QuarantineFile(filePath, "Defender 威胁处置", threatName));
                        }
                        else success = true; // 文件已不存在则视为已处置
                        break;
                    case ThreatAction.Remove:
                        if (!string.IsNullOrEmpty(filePath) && File.Exists(filePath))
                        {
                            File.Delete(filePath);
                            success = true;
                        }
                        else success = true;
                        break;
                    case ThreatAction.Allow:
                        success = true;
                        break;
                }

                if (success)
                {
                    _module.UpdateThreatAction(threatName, filePath, action);
                    ok++;
                }
                else fail++;
            }
            catch (Exception ex)
            {
                fail++;
                ErrorReporter.Report(ex, $"Defender 威胁处置失败: {threatName} @ {filePath}");
            }
        }

        AuditLogSystem.Log(fail > 0 ? LogLevel.Warning : LogLevel.Info, LogCategory.DefenderScan,
            $"Defender 威胁处置：{action}",
            $"成功 {ok} 个 / 失败 {fail} 个");

        if (fail > 0)
            MessageBoxHelper.Warn($"处置完成：成功 {ok} 个，失败 {fail} 个。");
        else
            MessageBoxHelper.Info($"已对 {ok} 个威胁执行「{action}」处置。");

        RefreshThreatList();
    }

    /// <summary>刷新历史列表</summary>
    private void RefreshHistory()
    {
        if (_historyPanel?.Tag is not ListView lv) return;
        lv.Items.Clear();

        if (_module == null) return;

        var history = _module.GetScanHistory();
        // 倒序显示（最新在前）
        for (int i = history.Count - 1; i >= 0; i--)
        {
            var r = history[i];
            var item = new ListViewItem(r.CompletedAt.ToString("yyyy-MM-dd HH:mm:ss"));
            item.SubItems.Add(TypeName(r.ScanType));
            item.SubItems.Add(r.ThreatsFound.ToString());
            item.SubItems.Add(FormatDuration(r.ScanDuration));
            item.SubItems.Add(r.ScannedItems.ToString());
            item.SubItems.Add(r.Success
                ? (r.ThreatsFound > 0 ? $"发现 {r.ThreatsFound} 个威胁" : "干净")
                : $"失败: {r.ErrorMessage}");

            item.ForeColor = !r.Success
                ? Theme.Error
                : (r.ThreatsFound > 0 ? Theme.Warning : Theme.Success);
            lv.Items.Add(item);
        }
    }

    // ==================== 策略配置标签 ====================

    private void BuildPolicyTab()
    {
        if (_policyPanel == null) return;
        _policyPanel.Controls.Clear();

        int y = 0;

        CreateSectionTitleIn(_policyPanel, "扫描策略", 0, y);
        y += 30;

        var card = CreateCardIn(_policyPanel, 0, y, ContentWidth, 200);

        // 扫描优先级
        var prioLabel = new Label
        {
            Text = "扫描优先级：",
            Font = Theme.BodyFont,
            ForeColor = Theme.TextSecondary,
            Location = new Point(16, 16),
            Size = new Size(120, 22),
            BackColor = Color.Transparent
        };
        card.Controls.Add(prioLabel);

        _priorityCombo = new ComboBox
        {
            Location = new Point(140, 14),
            Size = new Size(180, 24),
            FlatStyle = FlatStyle.Flat,
            Font = Theme.BodyFont,
            DropDownStyle = ComboBoxStyle.DropDownList
        };
        _priorityCombo.Items.AddRange(new object[] { "正常（默认）", "低（不影响前台）" });
        _priorityCombo.SelectedIndex = _scanPriority == ProcessPriorityClass.BelowNormal ? 1 : 0;
        _priorityCombo.SelectedIndexChanged += (s, e) =>
        {
            _scanPriority = _priorityCombo.SelectedIndex == 1
                ? ProcessPriorityClass.BelowNormal
                : ProcessPriorityClass.Normal;
            if (_scanner != null) _scanner.ScanPriority = _scanPriority;
            SaveDefenderPolicy();
            ErrorReporter.Log($"Defender 扫描优先级已设置为 {_scanPriority}（已持久化）");
        };
        card.Controls.Add(_priorityCombo);

        var prioDesc = new Label
        {
            Text = "低优先级适合后台静默扫描，避免影响日常使用",
            Font = Theme.SmallFont,
            ForeColor = Theme.TextTertiary,
            Location = new Point(330, 16),
            Size = new Size(360, 22),
            BackColor = Color.Transparent
        };
        card.Controls.Add(prioDesc);

        // 处置动作
        var remLabel = new Label
        {
            Text = "处置动作：",
            Font = Theme.BodyFont,
            ForeColor = Theme.TextSecondary,
            Location = new Point(16, 56),
            Size = new Size(120, 22),
            BackColor = Color.Transparent
        };
        card.Controls.Add(remLabel);

        _remediationCombo = new ComboBox
        {
            Location = new Point(140, 54),
            Size = new Size(180, 24),
            FlatStyle = FlatStyle.Flat,
            Font = Theme.BodyFont,
            DropDownStyle = ComboBoxStyle.DropDownList
        };
        // 处置动作：隔离/删除/允许/不处置（None 与配置项一一对应，保证显示与实际一致）
        _remediationCombo.Items.AddRange(new object[] { "隔离（推荐）", "删除", "允许", "不处置（仅告警）" });
        _remediationCombo.SelectedIndex = _remediationAction switch
        {
            ThreatAction.Remove => 1,
            ThreatAction.Allow => 2,
            ThreatAction.None => 3,
            _ => 0
        };
        _remediationCombo.SelectedIndexChanged += (s, e) =>
        {
            _remediationAction = _remediationCombo.SelectedIndex switch
            {
                1 => ThreatAction.Remove,
                2 => ThreatAction.Allow,
                3 => ThreatAction.None,
                _ => ThreatAction.Quarantine
            };
            SaveDefenderPolicy();
            ErrorReporter.Log($"Defender 处置动作已设置为 {_remediationAction}（已持久化）");
        };
        card.Controls.Add(_remediationCombo);

        var remDesc = new Label
        {
            Text = "按需扫描默认仅检测（-DisableRemediation），发现威胁后按此策略处置",
            Font = Theme.SmallFont,
            ForeColor = Theme.TextTertiary,
            Location = new Point(330, 56),
            Size = new Size(380, 22),
            BackColor = Color.Transparent
        };
        card.Controls.Add(remDesc);

        // 备份前自动查杀
        var autoLabel = new Label
        {
            Text = "备份前自动查杀：",
            Font = Theme.BodyFont,
            ForeColor = Theme.TextSecondary,
            Location = new Point(16, 100),
            Size = new Size(130, 22),
            BackColor = Color.Transparent
        };
        card.Controls.Add(autoLabel);

        _autoScanBeforeBackupToggle = new ToggleSwitch
        {
            Location = new Point(150, 102),
            IsOn = _autoScanBeforeBackup
        };
        _autoScanBeforeBackupToggle.Toggled += (on) =>
        {
            _autoScanBeforeBackup = on;
            AppState.Config.Backup.ScanBeforeBackup = on;
            ConfigManager.Save(AppState.Config);
            ErrorReporter.Log($"备份前自动查杀: {(on ? "开" : "关")}（已持久化）");
        };
        card.Controls.Add(_autoScanBeforeBackupToggle);

        var autoDesc = new Label
        {
            Text = "开启后将在每次加密备份前对源目录执行一次 Defender 快速查杀",
            Font = Theme.SmallFont,
            ForeColor = Theme.TextTertiary,
            Location = new Point(210, 100),
            Size = new Size(420, 22),
            BackColor = Color.Transparent
        };
        card.Controls.Add(autoDesc);

        // 提示
        var tipLabel = new Label
        {
            Text = "提示：策略已持久化保存；第三方杀毒导致 Defender 禁用时，扫描按钮将自动置灰。",
            Font = Theme.SmallFont,
            ForeColor = Theme.TextTertiary,
            Location = new Point(16, 150),
            Size = new Size(ContentWidth - 32, 30),
            BackColor = Color.Transparent
        };
        card.Controls.Add(tipLabel);

        y += 220;

        // ===== P1-5：每日调度与保护监控配置 =====
        CreateSectionTitleIn(_policyPanel, "每日调度与保护监控", 0, y);
        y += 30;

        var schedCard = CreateCardIn(_policyPanel, 0, y, ContentWidth, 300);

        int colX1 = 16, colX2 = 140, colX3 = 330;
        int rowY = 16, rowGap = 44;

        // 定时扫描开关
        var schedLabel = new Label
        {
            Text = "每日定时扫描：",
            Font = Theme.BodyFont,
            ForeColor = Theme.TextSecondary,
            Location = new Point(colX1, rowY),
            Size = new Size(120, 22),
            BackColor = Color.Transparent
        };
        schedCard.Controls.Add(schedLabel);

        _scheduleToggle = new ToggleSwitch
        {
            Location = new Point(colX2, rowY + 2),
            IsOn = _scheduleEnabled
        };
        _scheduleToggle.Toggled += (on) =>
        {
            _scheduleEnabled = on;
            SaveDefenderPolicy();
            ErrorReporter.Log($"Defender 每日定时扫描: {(on ? "开" : "关")}（已持久化）");
        };
        schedCard.Controls.Add(_scheduleToggle);

        var schedDesc = new Label
        {
            Text = "开启后每天到设定时间自动执行一次快速/全盘扫描，结果记入历史",
            Font = Theme.SmallFont,
            ForeColor = Theme.TextTertiary,
            Location = new Point(colX3, rowY),
            Size = new Size(ContentWidth - colX3 - 20, 22),
            BackColor = Color.Transparent
        };
        schedCard.Controls.Add(schedDesc);
        rowY += rowGap;

        // 扫描时间
        var timeLabel = new Label
        {
            Text = "扫描时间：",
            Font = Theme.BodyFont,
            ForeColor = Theme.TextSecondary,
            Location = new Point(colX1, rowY),
            Size = new Size(120, 22),
            BackColor = Color.Transparent
        };
        schedCard.Controls.Add(timeLabel);

        _scanTimeCombo = new ComboBox
        {
            Location = new Point(colX2, rowY - 2),
            Size = new Size(180, 24),
            FlatStyle = FlatStyle.Flat,
            Font = Theme.BodyFont,
            DropDownStyle = ComboBoxStyle.DropDownList
        };
        // 预设常用时间；若配置值不在预设列表（如自定义 05:00），动态加入并选中，
        // 保证 UI 显示与实际配置一致（否则会错误回退到 02:30）
        _scanTimeCombo.Items.AddRange(new object[] { "01:00", "02:00", "02:30", "03:00", "04:00", "12:00", "22:00", "23:00" });
        if (!_scanTimeCombo.Items.Contains(_scanTime))
            _scanTimeCombo.Items.Add(_scanTime);
        _scanTimeCombo.SelectedItem = _scanTime;
        _scanTimeCombo.SelectedIndexChanged += (s, e) =>
        {
            if (_scanTimeCombo.SelectedItem is string t)
            {
                _scanTime = t;
                SaveDefenderPolicy();
                ErrorReporter.Log($"Defender 定时扫描时间已设置为 {_scanTime}（已持久化）");
            }
        };
        schedCard.Controls.Add(_scanTimeCombo);

        var timeDesc = new Label
        {
            Text = "建议选择非工作时段（如凌晨），避免影响日常使用",
            Font = Theme.SmallFont,
            ForeColor = Theme.TextTertiary,
            Location = new Point(colX3, rowY),
            Size = new Size(360, 22),
            BackColor = Color.Transparent
        };
        schedCard.Controls.Add(timeDesc);
        rowY += rowGap;

        // 定时扫描类型
        var typeLabel = new Label
        {
            Text = "定时扫描类型：",
            Font = Theme.BodyFont,
            ForeColor = Theme.TextSecondary,
            Location = new Point(colX1, rowY),
            Size = new Size(120, 22),
            BackColor = Color.Transparent
        };
        schedCard.Controls.Add(typeLabel);

        _scheduleTypeCombo = new ComboBox
        {
            Location = new Point(colX2, rowY - 2),
            Size = new Size(180, 24),
            FlatStyle = FlatStyle.Flat,
            Font = Theme.BodyFont,
            DropDownStyle = ComboBoxStyle.DropDownList
        };
        _scheduleTypeCombo.Items.AddRange(new object[] { "快速扫描", "全盘扫描" });
        _scheduleTypeCombo.SelectedIndex =
            string.Equals(_scheduleScanType, "FullScan", StringComparison.OrdinalIgnoreCase) ? 1 : 0;
        _scheduleTypeCombo.SelectedIndexChanged += (s, e) =>
        {
            _scheduleScanType = _scheduleTypeCombo.SelectedIndex == 1 ? "FullScan" : "QuickScan";
            SaveDefenderPolicy();
            ErrorReporter.Log($"Defender 定时扫描类型已设置为 {_scheduleScanType}（已持久化）");
        };
        schedCard.Controls.Add(_scheduleTypeCombo);

        var typeDesc = new Label
        {
            Text = "全盘扫描耗时较长，建议在空闲时段启用",
            Font = Theme.SmallFont,
            ForeColor = Theme.TextTertiary,
            Location = new Point(colX3, rowY),
            Size = new Size(360, 22),
            BackColor = Color.Transparent
        };
        schedCard.Controls.Add(typeDesc);
        rowY += rowGap;

        // 病毒库自动更新
        var sigLabel = new Label
        {
            Text = "病毒库自动更新：",
            Font = Theme.BodyFont,
            ForeColor = Theme.TextSecondary,
            Location = new Point(colX1, rowY),
            Size = new Size(130, 22),
            BackColor = Color.Transparent
        };
        schedCard.Controls.Add(sigLabel);

        _autoSigToggle = new ToggleSwitch
        {
            Location = new Point(colX2, rowY + 2),
            IsOn = _autoUpdateSignatures
        };
        _autoSigToggle.Toggled += (on) =>
        {
            _autoUpdateSignatures = on;
            SaveDefenderPolicy();
            ErrorReporter.Log($"Defender 病毒库自动更新: {(on ? "开" : "关")}（已持久化）");
        };
        schedCard.Controls.Add(_autoSigToggle);

        // 过期天数
        var ageLabel = new Label
        {
            Text = "过期天数：",
            Font = Theme.BodyFont,
            ForeColor = Theme.TextSecondary,
            Location = new Point(colX3 - 40, rowY),
            Size = new Size(90, 22),
            BackColor = Color.Transparent
        };
        schedCard.Controls.Add(ageLabel);

        _sigMaxAgeCombo = new ComboBox
        {
            Location = new Point(colX3 + 60, rowY - 2),
            Size = new Size(90, 24),
            FlatStyle = FlatStyle.Flat,
            Font = Theme.BodyFont,
            DropDownStyle = ComboBoxStyle.DropDownList
        };
        // 过期天数：预设 1/3/7/14；若配置为其他值（如 5），动态加入并选中，保证显示与实际一致
        _sigMaxAgeCombo.Items.AddRange(new object[] { "1 天", "3 天", "7 天", "14 天" });
        if (!_sigMaxAgeCombo.Items.Contains($"{_sigMaxAgeDays} 天"))
            _sigMaxAgeCombo.Items.Add($"{_sigMaxAgeDays} 天");
        _sigMaxAgeCombo.SelectedItem = $"{_sigMaxAgeDays} 天";
        _sigMaxAgeCombo.SelectedIndexChanged += (s, e) =>
        {
            _sigMaxAgeDays = _sigMaxAgeCombo.SelectedIndex switch { 0 => 1, 2 => 7, 3 => 14, _ => 3 };
            SaveDefenderPolicy();
            ErrorReporter.Log($"Defender 病毒库过期天数阈值已设置为 {_sigMaxAgeDays} 天（已持久化）");
        };
        schedCard.Controls.Add(_sigMaxAgeCombo);
        rowY += rowGap;

        // 威胁告警
        var alertLabel = new Label
        {
            Text = "威胁 Webhook 告警：",
            Font = Theme.BodyFont,
            ForeColor = Theme.TextSecondary,
            Location = new Point(colX1, rowY),
            Size = new Size(130, 22),
            BackColor = Color.Transparent
        };
        schedCard.Controls.Add(alertLabel);

        _alertThreatToggle = new ToggleSwitch
        {
            Location = new Point(colX2, rowY + 2),
            IsOn = _alertOnThreat
        };
        _alertThreatToggle.Toggled += (on) =>
        {
            _alertOnThreat = on;
            SaveDefenderPolicy();
            ErrorReporter.Log($"Defender 威胁 Webhook 告警: {(on ? "开" : "关")}（已持久化）");
        };
        schedCard.Controls.Add(_alertThreatToggle);

        var alertDesc = new Label
        {
            Text = "发现威胁时经钉钉/企微 Webhook 外发告警（需在设置中配置 Webhook）",
            Font = Theme.SmallFont,
            ForeColor = Theme.TextTertiary,
            Location = new Point(colX3, rowY),
            Size = new Size(ContentWidth - colX3 - 20, 22),
            BackColor = Color.Transparent
        };
        schedCard.Controls.Add(alertDesc);
        rowY += rowGap;

        // 保护关闭告警
        var protLabel = new Label
        {
            Text = "保护异常告警：",
            Font = Theme.BodyFont,
            ForeColor = Theme.TextSecondary,
            Location = new Point(colX1, rowY),
            Size = new Size(130, 22),
            BackColor = Color.Transparent
        };
        schedCard.Controls.Add(protLabel);

        _alertProtectionToggle = new ToggleSwitch
        {
            Location = new Point(colX2, rowY + 2),
            IsOn = _alertOnProtectionDisabled
        };
        _alertProtectionToggle.Toggled += (on) =>
        {
            _alertOnProtectionDisabled = on;
            SaveDefenderPolicy();
            ErrorReporter.Log($"Defender 实时保护异常告警: {(on ? "开" : "关")}（已持久化）");
        };
        schedCard.Controls.Add(_alertProtectionToggle);

        var protDesc = new Label
        {
            Text = "实时保护被关闭 / 引擎健康异常时 Webhook 告警（每日限流一次）",
            Font = Theme.SmallFont,
            ForeColor = Theme.TextTertiary,
            Location = new Point(colX3, rowY),
            Size = new Size(ContentWidth - colX3 - 20, 22),
            BackColor = Color.Transparent
        };
        schedCard.Controls.Add(protDesc);

        y += 320;
    }

    // ==================== 扫描执行 ====================

    /// <summary>启动一次扫描</summary>
    private async void StartScan(DefenderScanType type)
    {
        AttachScanner();
        if (_scanner == null)
        {
            MessageBoxHelper.Warn("Defender 查杀模块未启用，请先在设置中启用该模块。");
            return;
        }
        if (_isScanning)
        {
            MessageBoxHelper.Warn("已有扫描正在运行，请等待完成或取消后再试。");
            return;
        }

        string? targetPath = null;

        // 文件 / 目录扫描需先选择目标
        if (type == DefenderScanType.SingleFile)
        {
            using var dlg = new OpenFileDialog
            {
                Title = "选择要扫描的文件",
                Filter = "所有文件|*.*"
            };
            if (dlg.ShowDialog() != DialogResult.OK)
                return;
            targetPath = dlg.FileName;
        }
        else if (type == DefenderScanType.Directory)
        {
            using var dlg = new FolderBrowserDialog
            {
                Description = "选择要扫描的目录",
                UseDescriptionForTitle = true
            };
            if (dlg.ShowDialog() != DialogResult.OK)
                return;
            targetPath = dlg.SelectedPath;
        }

        if (_pathLabel != null)
        {
            _pathLabel.Text = targetPath != null
                ? $"目标：{targetPath}"
                : type switch
                {
                    DefenderScanType.QuickScan => "目标：快速扫描（系统关键区域）",
                    DefenderScanType.FullScan => "目标：全盘扫描（所有磁盘）",
                    _ => "目标：—"
                };
            _pathLabel.ForeColor = Theme.TextPrimary;
        }

        _isScanning = true;
        SetScanButtonsEnabled(false);
        if (_cancelBtn != null) _cancelBtn.Enabled = true;

        if (_progressBar != null)
        {
            _progressBar.Style = ProgressBarStyle.Marquee;
            _progressBar.Value = 0;
        }
        if (_progressStatusLabel != null)
        {
            _progressStatusLabel.Text = $"正在执行{TypeName(type)}，请稍候...";
            _progressStatusLabel.ForeColor = Theme.Warning;
        }
        if (_threatListView != null) _threatListView.Items.Clear();
        if (_resultSummaryLabel != null)
        {
            _resultSummaryLabel.Text = "扫描进行中...";
            _resultSummaryLabel.ForeColor = Theme.Warning;
        }

        _cts = new CancellationTokenSource();

        DefenderScanResult result;
        var ct = _cts.Token;
        try
        {
            result = type switch
            {
                DefenderScanType.SingleFile => await _scanner.ScanFileAsync(targetPath!, ct),
                DefenderScanType.Directory => await _scanner.ScanDirectoryAsync(targetPath!, ct),
                DefenderScanType.QuickScan => await _scanner.QuickScanAsync(ct),
                DefenderScanType.FullScan => await _scanner.FullScanAsync(ct),
                _ => new DefenderScanResult { Success = false, ErrorMessage = "未知扫描类型" }
            };
        }
        catch (OperationCanceledException)
        {
            result = new DefenderScanResult
            {
                ScanType = type,
                Success = false,
                ErrorMessage = "已取消",
                TargetPath = targetPath
            };
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, "Defender 扫描异常");
            result = new DefenderScanResult
            {
                ScanType = type,
                Success = false,
                ErrorMessage = ex.Message,
                TargetPath = targetPath
            };
        }
        finally
        {
            _cts?.Dispose();
            _cts = null;
            _isScanning = false;
            SetScanButtonsEnabled(true);
            if (_cancelBtn != null) _cancelBtn.Enabled = false;
        }

        OnScanCompleted(result);
    }

    /// <summary>扫描完成处理</summary>
    private void OnScanCompleted(DefenderScanResult result)
    {
        if (_progressBar != null)
        {
            _progressBar.Style = ProgressBarStyle.Continuous;
            _progressBar.Value = 100;
        }

        if (_progressStatusLabel != null)
        {
            _progressStatusLabel.Text = result.Success ? "扫描完成" : $"扫描结束：{result.ErrorMessage}";
            _progressStatusLabel.ForeColor = result.Success ? Theme.Success : Theme.Error;
        }

        if (_resultSummaryLabel != null)
        {
            if (!result.Success)
            {
                _resultSummaryLabel.Text = $"扫描失败：{result.ErrorMessage}";
                _resultSummaryLabel.ForeColor = Theme.Error;
            }
            else if (result.ThreatsFound == 0)
            {
                _resultSummaryLabel.Text =
                    $"扫描完成，未发现威胁。耗时 {FormatDuration(result.ScanDuration)} | 扫描项 {result.ScannedItems}";
                _resultSummaryLabel.ForeColor = Theme.Success;
            }
            else
            {
                _resultSummaryLabel.Text =
                    $"发现 {result.ThreatsFound} 个威胁！耗时 {FormatDuration(result.ScanDuration)} | 扫描项 {result.ScannedItems}";
                _resultSummaryLabel.ForeColor = Theme.Error;
            }
        }

        // 填充威胁列表
        if (_threatListView != null)
        {
            _threatListView.Items.Clear();
            foreach (var t in result.Threats)
            {
                var item = new ListViewItem(t.ThreatName);
                item.SubItems.Add(t.FilePath);
                item.SubItems.Add(t.Severity.ToString());
                item.SubItems.Add(t.ActionTaken.ToString());
                item.ForeColor = t.Severity >= ThreatSeverity.High ? Theme.Error : Theme.Warning;
                _threatListView.Items.Add(item);
            }
        }

        // 记录到模块历史
        _module?.RecordScan(result);

        // P1-5：扫描完成后刷新持久化威胁清单（历史页）
        RefreshThreatList();

        // P1-6：扫描事件完整写入审计日志（支持报表导出）
        AuditLogSystem.Log(
            !result.Success ? LogLevel.Error : (result.ThreatsFound > 0 ? LogLevel.Critical : LogLevel.Info),
            LogCategory.DefenderScan,
            $"Defender 扫描{(result.Success ? "完成" : "失败")}：{(result.Success ? (result.ThreatsFound > 0 ? $"发现 {result.ThreatsFound} 个威胁" : "未发现威胁") : result.ErrorMessage)}",
            $"类型={TypeName(result.ScanType)} 目标={result.TargetPath ?? "—"} 耗时={FormatDuration(result.ScanDuration)} 扫描项={result.ScannedItems}");

        // 服务器适配：关闭桌面弹窗，仅留存日志记录
        if (DistributionProfile.IsServerEdition)
            return;

        if (result.Success && result.ThreatsFound > 0)
            MessageBoxHelper.Warn($"扫描完成，发现 {result.ThreatsFound} 个威胁，请查看结果列表。");
        else if (result.Success)
            MessageBoxHelper.Info("扫描完成，未发现威胁。");
    }

    /// <summary>进度回调（后台线程 -> UI 线程）</summary>
    private void OnScanProgress(DefenderScanProgress p)
    {
        if (IsDisposed || !IsHandleCreated) return;
        try
        {
            if (InvokeRequired)
                BeginInvoke(() => ApplyProgress(p));
            else
                ApplyProgress(p);
        }
        catch
        {
            // 窗口句柄可能已释放
        }
    }

    private void ApplyProgress(DefenderScanProgress p)
    {
        if (_progressBar != null && p.IsRunning && _progressBar.Style != ProgressBarStyle.Marquee)
            _progressBar.Style = ProgressBarStyle.Marquee;

        if (_progressStatusLabel != null)
        {
            var file = string.IsNullOrEmpty(p.CurrentFile) ? "" : $" | 当前: {Truncate(p.CurrentFile, 50)}";
            _progressStatusLabel.Text =
                $"{(p.IsRunning ? "扫描中" : "已结束")} | 已扫描 {p.FilesScanned} 项 | 发现威胁 {p.ThreatsFound}{file}";
            _progressStatusLabel.ForeColor = p.IsRunning ? Theme.Warning : Theme.Success;
        }
    }

    /// <summary>取消当前扫描</summary>
    private void CancelScan()
    {
        try
        {
            _cts?.Cancel();
            if (_progressStatusLabel != null)
            {
                _progressStatusLabel.Text = "正在取消扫描...";
                _progressStatusLabel.ForeColor = Theme.Warning;
            }
        }
        catch { }
    }

    /// <summary>设置四个扫描按钮可用状态</summary>
    private void SetScanButtonsEnabled(bool enabled)
    {
        if (_scanPanel == null) return;
        foreach (Control c in _scanPanel.Controls)
        {
            if (c is AccentButton ab && ab.Text is "单文件扫描" or "目录扫描" or "快速扫描" or "全盘扫描")
                ab.Enabled = enabled;
        }
    }

    // ==================== 辅助 ====================

    /// <summary>在指定父面板内创建带圆角的卡片</summary>
    private Panel CreateCardIn(Panel parent, int x, int y, int width, int height)
    {
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
        parent.Controls.Add(card);
        return card;
    }

    /// <summary>在指定父面板内创建分区标题</summary>
    private Label CreateSectionTitleIn(Panel parent, string text, int x, int y)
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
        parent.Controls.Add(label);
        return label;
    }

    private static string TypeName(DefenderScanType type) => type switch
    {
        DefenderScanType.SingleFile => "单文件扫描",
        DefenderScanType.Directory => "目录扫描",
        DefenderScanType.QuickScan => "快速扫描",
        DefenderScanType.FullScan => "全盘扫描",
        _ => "扫描"
    };

    private static string FormatDuration(TimeSpan ts)
    {
        if (ts.TotalSeconds < 60) return $"{ts.TotalSeconds:F1}s";
        if (ts.TotalMinutes < 60) return $"{(int)ts.TotalMinutes}m{ts.Seconds}s";
        return $"{(int)ts.TotalHours}h{(int)ts.TotalMinutes % 60}m";
    }

    private static string Truncate(string text, int maxLen)
    {
        if (string.IsNullOrEmpty(text)) return "";
        return text.Length <= maxLen ? text : "..." + text[^maxLen..];
    }

    public override void RefreshData()
    {
        AttachScanner();
        BuildContent();
    }
}

// ============================================================================
// 自定义标签按钮控件
// ============================================================================

/// <summary>
/// 标签页按钮 - Fluent 风格，激活时底部显示强调色下划线
/// </summary>
internal sealed class TabButton : Control
{
    private bool _isActive;
    private bool _isHovered;

    public event Action? Activated;

    public bool IsActive
    {
        get => _isActive;
        set { _isActive = value; Invalidate(); }
    }

    public TabButton(string text)
    {
        Text = text;
        Size = new Size(120, 36);
        Cursor = Cursors.Hand;
        DoubleBuffered = true;
        Font = Theme.BodyFont;
    }

    protected override void OnMouseEnter(EventArgs e) { _isHovered = true; Invalidate(); }
    protected override void OnMouseLeave(EventArgs e) { _isHovered = false; Invalidate(); }

    protected override void OnClick(EventArgs e)
    {
        base.OnClick(e);
        Activated?.Invoke();
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        var g = e.Graphics;
        g.SmoothingMode = SmoothingMode.AntiAlias;
        g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.ClearTypeGridFit;

        // 文字
        var textColor = _isActive ? Theme.TextPrimary : (_isHovered ? Theme.TextPrimary : Theme.TextSecondary);
        using var textBrush = new SolidBrush(textColor);
        var sf = new StringFormat
        {
            Alignment = StringAlignment.Center,
            LineAlignment = StringAlignment.Center
        };
        g.DrawString(Text, _isActive ? Theme.HeaderFont : Font, textBrush, ClientRectangle, sf);

        // 激活时底部下划线
        if (_isActive)
        {
            using var pen = new Pen(Theme.Accent, 3);
            int w = 40;
            int x = (Width - w) / 2;
            g.DrawLine(pen, x, Height - 3, x + w, Height - 3);
        }
    }
}
