using LightGuard.Core;
using LightGuard.Modules;
using LightGuard.UI.Controls;

namespace LightGuard.UI.Pages;

/// <summary>
/// 勒索病毒防护页面
/// 提供快速/全盘扫描、VSS快照创建、隔离威胁列表、扫描历史、病毒库状态
/// 扫描在后台线程执行，不阻塞UI
/// </summary>
public class RansomwarePage : Page
{
    private RansomwareModule? _module;
    private Label? _progressLabel;
    private Label? _resultLabel;
    private Label? _dbStatusLabel;
    private AccentButton? _quickScanBtn;
    private AccentButton? _fullScanBtn;
    private AccentButton? _vssBtn;
    private bool _isScanning;

    public RansomwarePage(AppState appState) : base(appState, "勒索病毒防护", "四层终极防护：多源病毒库、双引擎扫描、VSS卷影副本、实时监控")
    {
    }

    public override void OnShown()
    {
        _module = AppState.Modules.GetModule("ransomware") as RansomwareModule;
        BuildContent();
    }

    /// <summary>构建页面内容</summary>
    private void BuildContent()
    {
        ScrollContent.Controls.Clear();

        int y = 0;

        // ===== 病毒库状态区 =====
        CreateSectionTitle("病毒库状态", 0, y);
        y += 30;

        var dbCard = CreateCard(0, y, ContentWidth, 60);
        var sigCount = _module?.GetSignatureCount() ?? 0;
        var lastVirusDb = AppState.Config.Update.LastVirusDbUpdate;

        _dbStatusLabel = new Label
        {
            Text = $"已加载特征：{sigCount} 条    " +
                   $"病毒库最后更新：{(lastVirusDb.HasValue ? lastVirusDb.Value.ToString("yyyy-MM-dd HH:mm") : "从未")}",
            Font = Theme.BodyFont,
            ForeColor = Theme.TextSecondary,
            Location = new Point(16, 18),
            Size = new Size(688, 24),
            BackColor = Color.Transparent
        };
        dbCard.Controls.Add(_dbStatusLabel);
        y += 80;

        // ===== 扫描操作区 =====
        CreateSectionTitle("病毒扫描", 0, y);
        y += 30;

        var scanCard = CreateCard(0, y, ContentWidth, 100);

        _quickScanBtn = new AccentButton
        {
            Text = "快速扫描",
            Location = new Point(16, 12),
            Size = new Size(120, 36)
        };
        _quickScanBtn.Click += () => StartScan(false);
        scanCard.Controls.Add(_quickScanBtn);

        _fullScanBtn = new AccentButton
        {
            Text = "全盘扫描",
            Location = new Point(146, 12),
            Size = new Size(120, 36)
        };
        _fullScanBtn.Click += () => StartScan(true);
        scanCard.Controls.Add(_fullScanBtn);

        _vssBtn = new AccentButton
        {
            Text = "创建VSS快照",
            Location = new Point(276, 12),
            Size = new Size(140, 36)
        };
        _vssBtn.Click += async () =>
        {
            if (_module == null) return;
            _vssBtn.Enabled = false;
            MessageBoxHelper.Info("正在创建 C 盘 VSS 卷影副本，需要管理员权限...");
            var ok = await Task.Run(() => _module.CreateVssSnapshot("C:"));
            _vssBtn.Enabled = true;
            if (ok)
                MessageBoxHelper.Info("VSS 卷影副本创建成功！");
            else
                MessageBoxHelper.Warn("VSS 卷影副本创建失败，请以管理员身份运行。");
        };
        scanCard.Controls.Add(_vssBtn);

        _progressLabel = new Label
        {
            Text = _isScanning ? "正在扫描中，请稍候..." : "就绪",
            Font = Theme.BodyFont,
            ForeColor = _isScanning ? Theme.Warning : Theme.TextSecondary,
            Location = new Point(16, 56),
            Size = new Size(688, 20),
            BackColor = Color.Transparent
        };
        scanCard.Controls.Add(_progressLabel);

        y += 120;

        // ===== 扫描结果区 =====
        CreateSectionTitle("扫描结果", 0, y);
        y += 30;

        var resultCard = CreateCard(0, y, ContentWidth, 50);
        _resultLabel = new Label
        {
            Text = "尚未执行扫描",
            Font = Theme.BodyFont,
            ForeColor = Theme.TextTertiary,
            Location = new Point(16, 14),
            Size = new Size(688, 22),
            BackColor = Color.Transparent
        };
        resultCard.Controls.Add(_resultLabel);
        y += 70;

        // ===== 已隔离威胁列表区 =====
        CreateSectionTitle("已隔离威胁列表", 0, y);
        y += 30;

        if (_module != null)
        {
            var threats = _module.GetThreatList();
            var display = threats.Take(20).ToList();

            if (display.Count == 0)
            {
                var emptyLabel = new Label
                {
                    Text = "暂无已隔离威胁，系统安全。",
                    Font = Theme.BodyFont,
                    ForeColor = Theme.Success,
                    Location = new Point(16, 0),
                    Size = new Size(680, 24),
                    BackColor = Color.Transparent
                };
                ScrollContent.Controls.Add(emptyLabel);
                y += 30;
            }
            else
            {
                // 表头
                var headerCard = CreateCard(0, y, ContentWidth, 28);
                var headers = new[] { "威胁名称", "文件路径", "风险等级", "隔离时间", "已断网" };
                var xPositions = new[] { 8, 180, 440, 530, 620 };
                var widths = new[] { 168, 256, 84, 86, 80 };

                for (int i = 0; i < headers.Length; i++)
                {
                    var hLabel = new Label
                    {
                        Text = headers[i],
                        Font = Theme.SmallFont,
                        ForeColor = Theme.TextSecondary,
                        Location = new Point(xPositions[i], 4),
                        Size = new Size(widths[i], 20),
                        BackColor = Color.Transparent
                    };
                    headerCard.Controls.Add(hLabel);
                }
                y += 34;

                foreach (var threat in display)
                {
                    var threatCard = CreateCard(0, y, ContentWidth, 24);

                    var values = new[]
                    {
                        TruncateText(threat.ThreatName, 24),
                        TruncateText(threat.FilePath, 36),
                        threat.Risk.ToString(),
                        threat.QuarantinedAt.ToString("MM-dd HH:mm"),
                        threat.Blocked ? "是" : "否"
                    };

                    for (int i = 0; i < values.Length; i++)
                    {
                        var vLabel = new Label
                        {
                            Text = values[i],
                            Font = Theme.SmallFont,
                            ForeColor = threat.Risk >= RiskLevel.High ? Theme.Error : Theme.TextSecondary,
                            Location = new Point(xPositions[i], 2),
                            Size = new Size(widths[i], 20),
                            BackColor = Color.Transparent
                        };
                        threatCard.Controls.Add(vLabel);
                    }

                    y += 30;
                }
            }

            y += 10;
        }

        // ===== 扫描历史区 =====
        CreateSectionTitle("扫描历史（最近 20 条）", 0, y);
        y += 30;

        if (_module != null)
        {
            var history = _module.GetScanHistory();
            var display = history.Skip(Math.Max(0, history.Count - 20)).ToList();

            if (display.Count == 0)
            {
                var emptyLabel = new Label
                {
                    Text = "暂无扫描历史记录",
                    Font = Theme.BodyFont,
                    ForeColor = Theme.TextTertiary,
                    Location = new Point(16, 0),
                    Size = new Size(680, 24),
                    BackColor = Color.Transparent
                };
                ScrollContent.Controls.Add(emptyLabel);
                y += 30;
            }
            else
            {
                // 表头
                var headerCard = CreateCard(0, y, ContentWidth, 28);
                var headers = new[] { "扫描时间", "文件路径", "威胁名称", "风险等级" };
                var xPositions = new[] { 8, 160, 460, 600 };
                var widths = new[] { 148, 296, 136, 100 };

                for (int i = 0; i < headers.Length; i++)
                {
                    var hLabel = new Label
                    {
                        Text = headers[i],
                        Font = Theme.SmallFont,
                        ForeColor = Theme.TextSecondary,
                        Location = new Point(xPositions[i], 4),
                        Size = new Size(widths[i], 20),
                        BackColor = Color.Transparent
                    };
                    headerCard.Controls.Add(hLabel);
                }
                y += 34;

                foreach (var entry in display)
                {
                    var entryCard = CreateCard(0, y, ContentWidth, 24);

                    var values = new[]
                    {
                        entry.ScannedAt.ToString("yyyy-MM-dd HH:mm"),
                        TruncateText(entry.FilePath, 40),
                        TruncateText(entry.ThreatName, 18),
                        entry.Risk.ToString()
                    };

                    for (int i = 0; i < values.Length; i++)
                    {
                        var vLabel = new Label
                        {
                            Text = values[i],
                            Font = Theme.SmallFont,
                            ForeColor = entry.Risk >= RiskLevel.High ? Theme.Warning : Theme.TextSecondary,
                            Location = new Point(xPositions[i], 2),
                            Size = new Size(widths[i], 20),
                            BackColor = Color.Transparent
                        };
                        entryCard.Controls.Add(vLabel);
                    }

                    y += 30;
                }
            }

            y += 10;
        }

        y += 20;
    }

    /// <summary>启动扫描（后台线程）</summary>
    private async void StartScan(bool fullScan)
    {
        if (_module == null || _isScanning) return;

        _isScanning = true;
        SetScanButtonsEnabled(false);

        if (_progressLabel != null)
        {
            _progressLabel.Text = fullScan ? "正在执行全盘扫描，可能需要较长时间..." : "正在执行快速扫描...";
            _progressLabel.ForeColor = Theme.Warning;
        }

        var sw = System.Diagnostics.Stopwatch.StartNew();
        var results = await Task.Run(() => fullScan ? _module.FullScan() : _module.QuickScan());
        sw.Stop();

        _isScanning = false;
        SetScanButtonsEnabled(true);

        var totalFiles = results.Count;
        var threatCount = results.Count(r => r.IsMalicious);
        var cleanCount = totalFiles - threatCount;

        if (_progressLabel != null)
        {
            _progressLabel.Text = "扫描完成";
            _progressLabel.ForeColor = Theme.Success;
        }

        if (_resultLabel != null)
        {
            _resultLabel.Text = $"扫描完成！耗时 {sw.Elapsed.TotalSeconds:F1}s | " +
                                $"扫描文件：{totalFiles} | 干净：{cleanCount} | 发现威胁：{threatCount}";
            _resultLabel.ForeColor = threatCount > 0 ? Theme.Error : Theme.Success;
        }

        if (threatCount > 0)
            MessageBoxHelper.Warn($"扫描完成！发现 {threatCount} 个威胁，已自动隔离并断网。");
        else
            MessageBoxHelper.Info($"扫描完成！共扫描 {totalFiles} 个文件，未发现威胁。");

        // 刷新页面显示威胁列表和历史
        BuildContent();
    }

    /// <summary>设置扫描按钮可用状态</summary>
    private void SetScanButtonsEnabled(bool enabled)
    {
        if (_quickScanBtn != null) _quickScanBtn.Enabled = enabled;
        if (_fullScanBtn != null) _fullScanBtn.Enabled = enabled;
    }

    /// <summary>截断过长文本</summary>
    private static string TruncateText(string text, int maxLen)
    {
        if (string.IsNullOrEmpty(text)) return "";
        return text.Length <= maxLen ? text : text.Substring(0, maxLen - 3) + "...";
    }

    public override void RefreshData()
    {
        BuildContent();
    }
}
