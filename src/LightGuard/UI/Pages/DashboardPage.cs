using System.Drawing.Drawing2D;
using System.Diagnostics;
using LightGuard.Core;
using LightGuard.Core.Interfaces;
using LightGuard.UI.Controls;

namespace LightGuard.UI.Pages;

/// <summary>
/// 仪表盘页面 - 系统概览、模块状态、快速操作
/// </summary>
public class DashboardPage : Page
{
    private List<InfoCard> _infoCards = new();
    private List<ModuleCard> _moduleCards = new();
    private System.Windows.Forms.Timer? _refreshTimer;

    public DashboardPage(AppState appState) : base(appState, "仪表盘", "系统安全状态总览")
    {
    }

    public override void OnShown()
    {
        BuildContent();
        StartRefreshTimer();
    }

    private void BuildContent()
    {
        ScrollContent.Controls.Clear();
        _infoCards.Clear();
        _moduleCards.Clear();

        int y = 0;

        // ===== 系统信息卡片行 =====
        var hw = AppState.Hardware;
        var memUsed = hw.TotalMemoryMb - hw.AvailableMemoryMb;
        var memPercent = hw.TotalMemoryMb > 0 ? (int)(memUsed * 100 / hw.TotalMemoryMb) : 0;

        var procMem = Process.GetCurrentProcess().WorkingSet64 / (1024 * 1024);

        _infoCards.Add(new InfoCard("防护状态", "已启用", "全自动运行中"));
        _infoCards.Add(new InfoCard("系统内存", $"{memPercent}%", $"{memUsed}MB / {hw.TotalMemoryMb}MB"));
        _infoCards.Add(new InfoCard("程序占用", $"{procMem}MB", "超低资源占用"));
        _infoCards.Add(new InfoCard("CPU 核心", $"{hw.CpuCores}核", $"{hw.CpuLogicalCores}线程"));

        for (int i = 0; i < _infoCards.Count; i++)
        {
            _infoCards[i].Location = new Point(i * 184, y);
            ScrollContent.Controls.Add(_infoCards[i]);
        }

        y += 100;

        // ===== 硬件信息区 =====
        CreateSectionTitle("硬件信息", 0, y);
        y += 30;

        var hwCard = CreateCard(0, y, ContentWidth, 130);
        var hwLabels = new[]
        {
            $"处理器：{hw.CpuName}",
            $"显卡：{hw.GpuName}",
            $"系统：{hw.OsVersion} (Build {hw.OsBuildNumber})",
            $"内存：{hw.TotalMemoryMb}MB {(hw.HasSsd ? "| SSD" : "| HDD")}",
            $"分辨率：{hw.ScreenWidth}×{hw.ScreenHeight} ({hw.ScreenDpi}DPI)",
            $"配置等级：{(hw.IsHighEnd ? "高配 - 现代UI模式" : "低配 - 极简模式")}"
        };

        for (int i = 0; i < hwLabels.Length; i++)
        {
            var label = new Label
            {
                Text = hwLabels[i],
                Font = Theme.BodyFont,
                ForeColor = Theme.TextSecondary,
                Location = new Point(16, 12 + i * 19),
                Size = new Size(688, 18),
                BackColor = Color.Transparent
            };
            hwCard.Controls.Add(label);
        }

        y += 150;

        // ===== 模块状态区 =====
        CreateSectionTitle("功能模块", 0, y);
        y += 30;

        var modules = AppState.Modules.AllModules;
        int cardX = 0;
        int cardY = y;

        foreach (var module in modules)
        {
            var status = module.GetStatus();
            var enabled = AppState.Config.IsModuleEnabled(module.Id);
            var statusText = status switch
            {
                ModuleStatus.Running => "● 运行中",
                ModuleStatus.Stopped => "○ 已停止",
                ModuleStatus.Disabled => "○ 已禁用",
                ModuleStatus.Initializing => "◌ 初始化中",
                ModuleStatus.Error => "✕ 错误",
                _ => "○ 未知"
            };

            var card = new ModuleCard(module.Id, module.DisplayName, module.Description, statusText, enabled)
            {
                Location = new Point(cardX, cardY)
            };
            card.ToggleChanged += async (on) =>
            {
                await AppState.Modules.ToggleModuleAsync(module.Id, on);
                RefreshData();
            };
            _moduleCards.Add(card);
            ScrollContent.Controls.Add(card);

            cardX += 376;
            if (cardX >= ContentWidth)
            {
                cardX = 0;
                cardY += 100;
            }
        }

        y = cardY + (cardX > 0 ? 100 : 0) + 20;

        // ===== 快速操作区 =====
        CreateSectionTitle("快速操作", 0, y);
        y += 30;

        var actionCard = CreateCard(0, y, ContentWidth, 60);

        var scanBtn = new AccentButton
        {
            Text = "快速扫描",
            Location = new Point(16, 12),
            Size = new Size(100, 36)
        };
        scanBtn.Click += async () =>
        {
            var ransomwareModule = AppState.Modules.GetModule("ransomware") as Modules.RansomwareModule;
            if (ransomwareModule != null)
            {
                MessageBoxHelper.Info("开始快速扫描...");
                await Task.Run(() => ransomwareModule.QuickScan());
            }
        };
        actionCard.Controls.Add(scanBtn);

        var backupBtn = new AccentButton
        {
            Text = "立即备份",
            Location = new Point(126, 12),
            Size = new Size(100, 36)
        };
        backupBtn.Click += async () =>
        {
            var backupModule = AppState.Modules.GetModule("backup") as Modules.BackupModule;
            if (backupModule != null)
            {
                MessageBoxHelper.Info("开始备份...");
                await Task.Run(() => backupModule.BackupNow());
            }
        };
        actionCard.Controls.Add(backupBtn);

        var maintainBtn = new AccentButton
        {
            Text = "立即维护",
            Location = new Point(236, 12),
            Size = new Size(100, 36)
        };
        maintainBtn.Click += async () =>
        {
            await AppState.Scheduler.TriggerMaintenanceAsync();
            MessageBoxHelper.Info("维护任务已执行完成。");
        };
        actionCard.Controls.Add(maintainBtn);

        var optimizeBtn = new AccentButton
        {
            Text = "一键优化",
            Location = new Point(346, 12),
            Size = new Size(100, 36)
        };
        optimizeBtn.Click += async () =>
        {
            var privacyModule = AppState.Modules.GetModule("privacy") as Modules.PrivacyModule;
            var cleanupModule = AppState.Modules.GetModule("cleanup") as Modules.CleanupModule;
            if (privacyModule != null)
                await Task.Run(() => privacyModule.ApplyOptimization());
            if (cleanupModule != null)
                await Task.Run(() => cleanupModule.ApplyCleanup(AppState.Config.CurrentScene));
            MessageBoxHelper.Info("一键优化完成！隐私加固和流氓净化已应用。");
        };
        actionCard.Controls.Add(optimizeBtn);
    }

    private void StartRefreshTimer()
    {
        _refreshTimer?.Dispose();
        _refreshTimer = new System.Windows.Forms.Timer
        {
            Interval = 5000 // 每5秒刷新
        };
        _refreshTimer.Tick += (s, e) => RefreshData();
        _refreshTimer.Start();
    }

    public override void RefreshData()
    {
        // 更新内存信息卡片
        if (_infoCards.Count >= 2)
        {
            var hw = AppState.Hardware;
            var availMem = HardwareDetector.GetAvailableMemoryMb();
            var usedMem = hw.TotalMemoryMb - availMem;
            var percent = hw.TotalMemoryMb > 0 ? (int)(usedMem * 100 / hw.TotalMemoryMb) : 0;

            // 更新第二个卡片（内存）
            var memCard = _infoCards[1];
            var controls = memCard.Controls.OfType<Label>().ToList();
            if (controls.Count >= 2)
            {
                controls[1].Text = $"{percent}%";
                if (controls.Count >= 3)
                    controls[2].Text = $"{usedMem}MB / {hw.TotalMemoryMb}MB";
            }
        }

        // 更新程序占用
        if (_infoCards.Count >= 3)
        {
            var procMem = Process.GetCurrentProcess().WorkingSet64 / (1024 * 1024);
            var memCard = _infoCards[2];
            var controls = memCard.Controls.OfType<Label>().ToList();
            if (controls.Count >= 2)
            {
                controls[1].Text = $"{procMem}MB";
            }
        }

        // 更新模块状态
        foreach (var card in _moduleCards)
        {
            var module = AppState.Modules.GetModule(card.ModuleId);
            if (module != null)
            {
                var status = module.GetStatus();
                var enabled = AppState.Config.IsModuleEnabled(module.Id);
                var statusText = status switch
                {
                    ModuleStatus.Running => "● 运行中",
                    ModuleStatus.Stopped => "○ 已停止",
                    ModuleStatus.Disabled => "○ 已禁用",
                    ModuleStatus.Initializing => "◌ 初始化中",
                    ModuleStatus.Error => "✕ 错误",
                    _ => "○ 未知"
                };
                card.UpdateStatus(statusText, enabled);
            }
        }
    }
}
