// © 2026 落尘（Luochen） 原创开发 - 保留所有权利

using System.Drawing.Drawing2D;
using System.Text;
using LightGuard.Audit;
using LightGuard.Core;
using LightGuard.Defender;
using LightGuard.Modules;
using LightGuard.UI.Controls;

namespace LightGuard.UI.Pages;

/// <summary>
/// 文件服务器访问审计页面
/// <para>四大标签页：审计概览 | 审计记录 | 风险告警 | 策略配置</para>
/// <para>后端引擎：SmbAuditModule + SmbAuditCollector + SmbRiskDetector</para>
/// </summary>
public class FileServerAuditPage : Page
{
    // 模块引用
    private SmbAuditModule? _module;
    private SmbAuditCollector? _collector;
    private SmbRiskDetector? _riskDetector;

    // 标签页
    private int _activeTab; // 0=概览 1=审计记录 2=风险告警 3=策略配置
    private readonly string[] _tabNames = { "审计概览", "审计记录", "风险告警", "策略配置" };
    private List<Panel> _tabButtons = new();

    // 概览控件
    private Label? _statusLabel;
    private Label? _recordCountLabel;
    private Label? _riskCountLabel;
    private Label? _topUserLabel;
    private Label? _topFileLabel;

    // 审计记录控件
    private ComboBox? _filterOpCombo;
    private TextBox? _filterUserBox;
    private TextBox? _filterIpBox;
    private TextBox? _filterPathBox;
    private AccentButton? _searchBtn;
    private AccentButton? _exportCsvBtn;
    private AccentButton? _clearRecordsBtn;

    // 风险告警控件
    private AccentButton? _clearRiskBtn;

    // 策略配置控件
    private AccentButton? _enablePolicyBtn;
    private AccentButton? _queryPolicyBtn;
    private TextBox? _policyStatusBox;

    public FileServerAuditPage(AppState appState) : base(appState,
        "文件服务器访问审计",
        "SMB 共享全行为审计 | NTFS SACL + ETW 双采集 | 批量外泄/凌晨访问/高频删除实时告警")
    {
    }

    public override void OnShown()
    {
        _module = AppState.Modules.GetModule("smb-audit") as SmbAuditModule;
        _collector = _module?.GetCollector();
        _riskDetector = _module?.GetRiskDetector();
        BuildContent();
    }

    /// <summary>构建页面内容</summary>
    private void BuildContent()
    {
        ScrollContent.Controls.Clear();
        _tabButtons.Clear();

        int y = 0;
        int cw = ContentWidth;

        // ===== 标签栏 =====
        var tabBar = CreateCard(0, y, cw, 44);
        int tabW = (cw - 16) / _tabNames.Length;
        for (int i = 0; i < _tabNames.Length; i++)
        {
            var tab = new Panel
            {
                Location = new Point(8 + i * tabW, 6),
                Size = new Size(tabW - 4, 32),
                BackColor = Color.Transparent,
                Cursor = Cursors.Hand,
                Tag = i
            };
            var idx = i;
            tab.Click += (s, e) => { _activeTab = idx; BuildContent(); };
            tab.Paint += (s, e) =>
            {
                var g = e.Graphics;
                g.SmoothingMode = SmoothingMode.AntiAlias;
                var isActive = (int)tab.Tag! == _activeTab;
                using var bg = new SolidBrush(isActive ? Theme.Accent : Theme.CardHover);
                Theme.FillRoundedRect(g, bg, tab.ClientRectangle, 6);
                using var tb = new SolidBrush(isActive ? Color.White : Theme.TextSecondary);
                Theme.DrawCenteredText(g, _tabNames[idx], Theme.BodyFont, tb, tab.ClientRectangle);
            };
            tabBar.Controls.Add(tab);
            _tabButtons.Add(tab);
        }
        y += 54;

        // ===== 根据激活标签构建内容 =====
        switch (_activeTab)
        {
            case 0: BuildOverviewTab(y); break;
            case 1: BuildRecordsTab(y); break;
            case 2: BuildRiskTab(y); break;
            case 3: BuildPolicyTab(y); break;
        }
    }

    #region 标签页1：审计概览

    private void BuildOverviewTab(int y)
    {
        int cw = ContentWidth;

        // ===== 状态卡片区 =====
        CreateSectionTitle("审计状态", 0, y);
        y += 30;

        var isRunning = _module?.IsEnabled ?? false;
        var recordCount = _collector?.GetRecordCount() ?? 0;
        var riskHistory = _module?.GetRiskHistory() ?? new List<SmbRiskEvent>();
        var riskCount = riskHistory.Count;
        var criticalRisks = riskHistory.Count(r => r.Severity >= RiskLevel.Critical);

        // 四列信息卡片
        int cardW = (cw - 24) / 4;
        var cards = new[]
        {
            new { Title = "采集状态", Value = isRunning ? "运行中" : "已停止", Sub = isRunning ? "SACL + ETW 双采集" : "点击策略配置启用", Color = isRunning ? Theme.Success : Theme.TextTertiary },
            new { Title = "审计记录", Value = recordCount.ToString(), Sub = "条 SMB 操作记录", Color = Theme.Accent },
            new { Title = "风险事件", Value = riskCount.ToString(), Sub = $"Critical {criticalRisks} 次", Color = riskCount > 0 ? Theme.Warning : Theme.Success },
            new { Title = "分析窗口", Value = (_riskDetector?.GetWindowRecordCount() ?? 0).ToString(), Sub = "条实时分析中", Color = Theme.TextSecondary }
        };

        for (int i = 0; i < cards.Length; i++)
        {
            var infoCard = new InfoCard(cards[i].Title, cards[i].Value, cards[i].Sub)
            {
                Location = new Point(i * (cardW + 8), y),
                Size = new Size(cardW, 80)
            };
            ScrollContent.Controls.Add(infoCard);
        }
        y += 90;

        // ===== 审计引擎信息 =====
        CreateSectionTitle("采集引擎", 0, y);
        y += 30;

        var engineCard = CreateCard(0, y, cw, 100);
        var engineLines = new[]
        {
            "方案 1：NTFS SACL 安全审核 + 系统安全事件日志（EventLog API 实时订阅）",
            "  · 事件 ID 4624(SMB登录) / 4656(打开句柄) / 4663(读写访问) / 4660(删除) / 4670(权限篡改)",
            "方案 2：ETW Windows 事件追踪（Microsoft-Windows-SmbServer / Kernel-File 实时流式采集）",
            "双采集融合：SACL 日志持久化存储 + ETW 实时告警触发，数据合并去重",
            "风险识别：批量文件外泄(5min/100+文件) / 凌晨访问(22:00-06:00) / 高频删除(1min/10+文件) / 备份目录异常访问"
        };
        for (int i = 0; i < engineLines.Length; i++)
        {
            var line = new Label
            {
                Text = engineLines[i],
                Font = i == 0 || i == 2 ? Theme.BodyFont : Theme.SmallFont,
                ForeColor = i == 0 || i == 2 ? Theme.TextPrimary : Theme.TextSecondary,
                Location = new Point(16, 8 + i * 17),
                Size = new Size(cw - 32, 18),
                BackColor = Color.Transparent
            };
            engineCard.Controls.Add(line);
        }
        y += 110;

        // ===== 最近审计记录（概览） =====
        CreateSectionTitle("最近审计记录（最新 20 条）", 0, y);
        y += 30;

        var recentRecords = _collector?.GetRecentRecords(20) ?? new List<SmbAuditEntry>();
        if (recentRecords.Count == 0)
        {
            var empty = new Label
            {
                Text = isRunning
                    ? "暂无审计记录 — 等待 SMB 共享访问事件..."
                    : "审计模块未启用 — 请到\"策略配置\"标签页一键开启安全审核策略",
                Font = Theme.BodyFont,
                ForeColor = Theme.TextTertiary,
                Location = new Point(16, 0),
                Size = new Size(cw - 32, 24),
                BackColor = Color.Transparent
            };
            ScrollContent.Controls.Add(empty);
            y += 30;
        }
        else
        {
            y = BuildRecordTable(y, recentRecords, cw);
        }

        y += 20;

        // ===== 最近风险事件 =====
        CreateSectionTitle("最近风险事件", 0, y);
        y += 30;

        var recentRisks = riskHistory
            .OrderByDescending(r => r.DetectedAt)
            .Take(10)
            .ToList();

        if (recentRisks.Count == 0)
        {
            var noRisk = new Label
            {
                Text = "暂无风险事件",
                Font = Theme.BodyFont,
                ForeColor = Theme.Success,
                Location = new Point(16, 0),
                Size = new Size(cw - 32, 24),
                BackColor = Color.Transparent
            };
            ScrollContent.Controls.Add(noRisk);
            y += 30;
        }
        else
        {
            y = BuildRiskTable(y, recentRisks, cw);
        }

        y += 20;
    }

    #endregion

    #region 标签页2：审计记录

    private void BuildRecordsTab(int y)
    {
        int cw = ContentWidth;

        // ===== 筛选区 =====
        CreateSectionTitle("筛选条件", 0, y);
        y += 30;

        var filterCard = CreateCard(0, y, cw, 100);

        // 操作类型筛选
        var opLabel = new Label
        {
            Text = "操作类型：",
            Font = Theme.BodyFont,
            ForeColor = Theme.TextSecondary,
            Location = new Point(16, 12),
            Size = new Size(80, 22),
            BackColor = Color.Transparent
        };
        filterCard.Controls.Add(opLabel);

        _filterOpCombo = new ComboBox
        {
            Location = new Point(100, 10),
            Size = new Size(160, 24),
            FlatStyle = FlatStyle.Flat,
            Font = Theme.BodyFont,
            DropDownStyle = ComboBoxStyle.DropDownList
        };
        _filterOpCombo.Items.AddRange(new object[]
        {
            "全部操作", "登录", "读取", "写入", "修改", "删除", "移动", "重命名", "权限篡改", "越权访问"
        });
        _filterOpCombo.SelectedIndex = 0;
        filterCard.Controls.Add(_filterOpCombo);

        // 用户名筛选
        var userLabel = new Label
        {
            Text = "用户名：",
            Font = Theme.BodyFont,
            ForeColor = Theme.TextSecondary,
            Location = new Point(280, 12),
            Size = new Size(60, 22),
            BackColor = Color.Transparent
        };
        filterCard.Controls.Add(userLabel);

        _filterUserBox = new TextBox
        {
            Location = new Point(346, 10),
            Size = new Size(140, 24),
            Font = Theme.BodyFont,
            BackColor = Theme.CardBg,
            ForeColor = Theme.TextPrimary,
            BorderStyle = BorderStyle.FixedSingle,
            PlaceholderText = "模糊搜索用户名"
        };
        filterCard.Controls.Add(_filterUserBox);

        // IP 筛选
        var ipLabel = new Label
        {
            Text = "客户端IP：",
            Font = Theme.BodyFont,
            ForeColor = Theme.TextSecondary,
            Location = new Point(500, 12),
            Size = new Size(70, 22),
            BackColor = Color.Transparent
        };
        filterCard.Controls.Add(ipLabel);

        _filterIpBox = new TextBox
        {
            Location = new Point(576, 10),
            Size = new Size(120, 24),
            Font = Theme.BodyFont,
            BackColor = Theme.CardBg,
            ForeColor = Theme.TextPrimary,
            BorderStyle = BorderStyle.FixedSingle,
            PlaceholderText = "IP 地址"
        };
        filterCard.Controls.Add(_filterIpBox);

        // 文件路径筛选
        var pathLabel = new Label
        {
            Text = "文件路径：",
            Font = Theme.BodyFont,
            ForeColor = Theme.TextSecondary,
            Location = new Point(16, 46),
            Size = new Size(80, 22),
            BackColor = Color.Transparent
        };
        filterCard.Controls.Add(pathLabel);

        _filterPathBox = new TextBox
        {
            Location = new Point(100, 44),
            Size = new Size(380, 24),
            Font = Theme.BodyFont,
            BackColor = Theme.CardBg,
            ForeColor = Theme.TextPrimary,
            BorderStyle = BorderStyle.FixedSingle,
            PlaceholderText = "模糊搜索文件路径或文件名"
        };
        filterCard.Controls.Add(_filterPathBox);

        // 搜索按钮
        _searchBtn = new AccentButton
        {
            Text = "搜索",
            Location = new Point(500, 40),
            Size = new Size(80, 32)
        };
        _searchBtn.Click += () => BuildContent();
        filterCard.Controls.Add(_searchBtn);

        // 导出 CSV 按钮
        _exportCsvBtn = new AccentButton
        {
            Text = "导出 CSV",
            Location = new Point(590, 40),
            Size = new Size(90, 32)
        };
        _exportCsvBtn.Click += ExportRecordsCsv;
        filterCard.Controls.Add(_exportCsvBtn);

        // 清空记录按钮
        _clearRecordsBtn = new AccentButton
        {
            Text = "清空记录",
            Location = new Point(cw - 106, 40),
            Size = new Size(90, 32)
        };
        _clearRecordsBtn.Click += ClearRecords;
        filterCard.Controls.Add(_clearRecordsBtn);

        y += 110;

        // ===== 审计记录列表 =====
        CreateSectionTitle("审计记录列表", 0, y);
        y += 30;

        var allRecords = _collector?.GetRecords() ?? new List<SmbAuditEntry>();
        var filtered = FilterRecords(allRecords);

        if (filtered.Count == 0)
        {
            var empty = new Label
            {
                Text = allRecords.Count == 0
                    ? "暂无审计记录 — 请确保审计模块已启用且服务器有 SMB 共享访问"
                    : "没有匹配筛选条件的记录",
                Font = Theme.BodyFont,
                ForeColor = Theme.TextTertiary,
                Location = new Point(16, 0),
                Size = new Size(cw - 32, 24),
                BackColor = Color.Transparent
            };
            ScrollContent.Controls.Add(empty);
            y += 30;
        }
        else
        {
            // 统计信息
            var statLabel = new Label
            {
                Text = $"共 {allRecords.Count} 条记录，筛选后 {filtered.Count} 条（显示最新 200 条）",
                Font = Theme.SmallFont,
                ForeColor = Theme.TextTertiary,
                Location = new Point(16, 0),
                Size = new Size(cw - 32, 18),
                BackColor = Color.Transparent
            };
            ScrollContent.Controls.Add(statLabel);
            y += 24;

            var display = filtered
                .OrderByDescending(r => r.Time)
                .Take(200)
                .ToList();
            y = BuildRecordTable(y, display, cw);
        }

        y += 20;
    }

    /// <summary>按筛选条件过滤记录</summary>
    private List<SmbAuditEntry> FilterRecords(List<SmbAuditEntry> records)
    {
        var result = records.AsEnumerable();

        // 操作类型筛选
        var opIdx = _filterOpCombo?.SelectedIndex ?? 0;
        if (opIdx > 0)
        {
            var targetOp = opIdx switch
            {
                1 => SmbOperation.Login,
                2 => SmbOperation.Read,
                3 => SmbOperation.Write,
                4 => SmbOperation.Modify,
                5 => SmbOperation.Delete,
                6 => SmbOperation.Move,
                7 => SmbOperation.Rename,
                8 => SmbOperation.PermissionChange,
                9 => SmbOperation.AccessDenied,
                _ => SmbOperation.Login
            };
            result = result.Where(r => r.Operation == targetOp);
        }

        // 用户名筛选
        var userFilter = _filterUserBox?.Text?.Trim();
        if (!string.IsNullOrEmpty(userFilter))
            result = result.Where(r => r.UserName.Contains(userFilter, StringComparison.OrdinalIgnoreCase));

        // IP 筛选
        var ipFilter = _filterIpBox?.Text?.Trim();
        if (!string.IsNullOrEmpty(ipFilter))
            result = result.Where(r => r.ClientIp.Contains(ipFilter, StringComparison.OrdinalIgnoreCase));

        // 路径筛选
        var pathFilter = _filterPathBox?.Text?.Trim();
        if (!string.IsNullOrEmpty(pathFilter))
            result = result.Where(r => r.FilePath.Contains(pathFilter, StringComparison.OrdinalIgnoreCase));

        return result.ToList();
    }

    /// <summary>导出审计记录为 CSV</summary>
    private void ExportRecordsCsv()
    {
        try
        {
            var records = _collector?.GetRecords() ?? new List<SmbAuditEntry>();
            var filtered = FilterRecords(records);
            if (filtered.Count == 0)
            {
                MessageBoxHelper.Warn("没有可导出的审计记录。");
                return;
            }

            using var dlg = new SaveFileDialog
            {
                Title = "导出审计记录",
                Filter = "CSV 文件 (*.csv)|*.csv|所有文件 (*.*)|*.*",
                FileName = $"SMB审计记录_{DateTime.Now:yyyyMMdd_HHmmss}.csv"
            };
            if (dlg.ShowDialog() != DialogResult.OK) return;

            var sb = new StringBuilder();
            sb.Append('\uFEFF'); // UTF-8 BOM
            sb.AppendLine("时间,用户名,客户端IP,主机名,文件路径,操作类型,远程操作,风险标签");
            foreach (var r in filtered.OrderByDescending(x => x.Time))
            {
                sb.Append($"{r.Time:yyyy-MM-dd HH:mm:ss},");
                sb.Append(EscapeCsv(r.UserName));
                sb.Append(',');
                sb.Append(EscapeCsv(r.ClientIp));
                sb.Append(',');
                sb.Append(EscapeCsv(r.HostName));
                sb.Append(',');
                sb.Append(EscapeCsv(r.FilePath));
                sb.Append(',');
                sb.Append(GetOperationName(r.Operation));
                sb.Append(',');
                sb.Append(r.IsRemote ? "远程" : "本地");
                sb.Append(',');
                sb.Append(EscapeCsv(r.RiskTag));
                sb.AppendLine();
            }
            File.WriteAllText(dlg.FileName, sb.ToString(), Encoding.UTF8);
            MessageBoxHelper.Info($"已导出 {filtered.Count} 条审计记录到：\n{dlg.FileName}");
        }
        catch (Exception ex)
        {
            MessageBoxHelper.Error($"导出失败：{ex.Message}");
        }
    }

    /// <summary>清空审计记录</summary>
    private void ClearRecords()
    {
        if (!MessageBoxHelper.Confirm("确认清空所有审计记录？此操作不可撤销。"))
            return;
        _collector?.ClearRecords();
        BuildContent();
    }

    #endregion

    #region 标签页3：风险告警

    private void BuildRiskTab(int y)
    {
        int cw = ContentWidth;

        // ===== 风险统计 =====
        CreateSectionTitle("风险统计", 0, y);
        y += 30;

        var risks = _module?.GetRiskHistory() ?? new List<SmbRiskEvent>();
        var critical = risks.Count(r => r.Severity >= RiskLevel.Critical);
        var high = risks.Count(r => r.Severity == RiskLevel.High);
        var medium = risks.Count(r => r.Severity == RiskLevel.Medium);

        int cardW = (cw - 24) / 4;
        var stats = new[]
        {
            new { Title = "总风险事件", Value = risks.Count.ToString(), Sub = "累计检测", Color = Theme.Accent },
            new { Title = "Critical", Value = critical.ToString(), Sub = "严重风险", Color = Theme.Error },
            new { Title = "High", Value = high.ToString(), Sub = "高危风险", Color = Theme.Warning },
            new { Title = "Medium", Value = medium.ToString(), Sub = "中危风险", Color = Theme.TextSecondary }
        };

        for (int i = 0; i < stats.Length; i++)
        {
            var infoCard = new InfoCard(stats[i].Title, stats[i].Value, stats[i].Sub)
            {
                Location = new Point(i * (cardW + 8), y),
                Size = new Size(cardW, 80)
            };
            ScrollContent.Controls.Add(infoCard);
        }
        y += 90;

        // ===== 风险事件列表 =====
        CreateSectionTitle("风险事件列表", 0, y);
        y += 30;

        // 清空风险记录按钮
        _clearRiskBtn = new AccentButton
        {
            Text = "清空风险记录",
            Location = new Point(cw - 120, y - 28),
            Size = new Size(110, 26)
        };
        _clearRiskBtn.Click += () =>
        {
            if (MessageBoxHelper.Confirm("确认清空所有风险事件记录？"))
            {
                // 风险记录由 RiskDetector 内部管理，无法直接清空
                // 这里仅刷新 UI
                MessageBoxHelper.Info("风险事件记录在模块重启时自动清空。");
            }
        };
        ScrollContent.Controls.Add(_clearRiskBtn);

        var sortedRisks = risks.OrderByDescending(r => r.DetectedAt).Take(100).ToList();
        if (sortedRisks.Count == 0)
        {
            var empty = new Label
            {
                Text = "暂无风险事件 — 系统运行正常",
                Font = Theme.BodyFont,
                ForeColor = Theme.Success,
                Location = new Point(16, 0),
                Size = new Size(cw - 32, 24),
                BackColor = Color.Transparent
            };
            ScrollContent.Controls.Add(empty);
            y += 30;
        }
        else
        {
            y = BuildRiskTable(y, sortedRisks, cw);
        }

        y += 20;

        // ===== 风险类型说明 =====
        CreateSectionTitle("风险类型说明", 0, y);
        y += 30;

        var legendCard = CreateCard(0, y, cw, 90);
        var legends = new[]
        {
            "批量文件外泄：5 分钟内同一用户/IP 远程读取 100+ 文件，疑似数据外传",
            "凌晨非工作时段访问：22:00-06:00 远程访问共享文件，标记为异常",
            "高频删除行为：1 分钟内删除 10+ 文件，疑似勒索软件或恶意删除",
            "备份目录异常访问：有人访问备份/受保护目录，触发勒索防护联动告警（Critical）"
        };
        for (int i = 0; i < legends.Length; i++)
        {
            var line = new Label
            {
                Text = "• " + legends[i],
                Font = Theme.SmallFont,
                ForeColor = Theme.TextSecondary,
                Location = new Point(16, 8 + i * 18),
                Size = new Size(cw - 32, 18),
                BackColor = Color.Transparent
            };
            legendCard.Controls.Add(line);
        }

        y += 100;
    }

    #endregion

    #region 标签页4：策略配置

    private void BuildPolicyTab(int y)
    {
        int cw = ContentWidth;

        // ===== 审计模块开关 =====
        CreateSectionTitle("审计模块开关", 0, y);
        y += 30;

        var moduleCard = CreateCard(0, y, cw, 70);
        var isRunning = _module?.IsEnabled ?? false;

        _statusLabel = new Label
        {
            Text = isRunning
                ? "● 审计模块运行中 — SACL 安全事件日志 + ETW 实时采集已启动"
                : "○ 审计模块已停止 — 点击下方按钮启用",
            Font = Theme.BodyFont,
            ForeColor = isRunning ? Theme.Success : Theme.TextTertiary,
            Location = new Point(16, 12),
            Size = new Size(cw - 200, 22),
            BackColor = Color.Transparent
        };
        moduleCard.Controls.Add(_statusLabel);

        var toggleBtn = new AccentButton
        {
            Text = isRunning ? "停止审计" : "启动审计",
            Location = new Point(cw - 140, 8),
            Size = new Size(120, 32)
        };
        toggleBtn.Click += async () =>
        {
            try
            {
                if (isRunning)
                    await _module!.DisableAsync();
                else
                {
                    await _module!.InitializeAsync();
                    await _module.EnableAsync();
                }
                BuildContent();
            }
            catch (Exception ex)
            {
                MessageBoxHelper.Error($"操作失败：{ex.Message}");
            }
        };
        moduleCard.Controls.Add(toggleBtn);

        var hintLabel = new Label
        {
            Text = "启用审计前，建议先执行\"一键配置安全策略\"以确保系统审核规则已开启",
            Font = Theme.SmallFont,
            ForeColor = Theme.TextTertiary,
            Location = new Point(16, 40),
            Size = new Size(cw - 32, 18),
            BackColor = Color.Transparent
        };
        moduleCard.Controls.Add(hintLabel);

        y += 80;

        // ===== 安全策略配置 =====
        CreateSectionTitle("服务器安全策略配置", 0, y);
        y += 30;

        var policyCard = CreateCard(0, y, cw, 200);

        var policyDesc = new Label
        {
            Text = "一键启用 Windows 安全审核策略，自动配置以下审核子类别：",
            Font = Theme.BodyFont,
            ForeColor = Theme.TextPrimary,
            Location = new Point(16, 12),
            Size = new Size(cw - 32, 22),
            BackColor = Color.Transparent
        };
        policyCard.Controls.Add(policyDesc);

        var policyItems = new[]
        {
            "File System（文件系统）— 成功 + 失败审核",
            "Logon（登录）— 成功 + 失败审核",
            "Logoff（注销）— 成功 + 失败审核",
            "Sensitive Privilege Use（敏感特权使用）— 成功 + 失败审核",
            "Authorization Policy Change（授权策略变更）— 成功 + 失败审核"
        };
        for (int i = 0; i < policyItems.Length; i++)
        {
            var item = new Label
            {
                Text = "  ✓ " + policyItems[i],
                Font = Theme.SmallFont,
                ForeColor = Theme.Success,
                Location = new Point(16, 38 + i * 18),
                Size = new Size(cw - 32, 18),
                BackColor = Color.Transparent
            };
            policyCard.Controls.Add(item);
        }

        // 一键配置按钮
        _enablePolicyBtn = new AccentButton
        {
            Text = "一键配置安全策略",
            Location = new Point(16, 138),
            Size = new Size(160, 32)
        };
        _enablePolicyBtn.Click += () =>
        {
            try
            {
                var success = _module?.ConfigureSecurityPolicy() ?? false;
                if (success)
                    MessageBoxHelper.Info("安全策略配置成功！\n\n已开启文件系统、登录、注销、敏感特权使用、授权策略变更的审核。\n现在可以启动审计模块开始采集。");
                else
                    MessageBoxHelper.Warn("安全策略配置部分失败，请检查管理员权限。\n部分审核子类别可能未成功开启。");
            }
            catch (Exception ex)
            {
                MessageBoxHelper.Error($"配置失败：{ex.Message}");
            }
        };
        policyCard.Controls.Add(_enablePolicyBtn);

        // 查询策略状态按钮
        _queryPolicyBtn = new AccentButton
        {
            Text = "查询当前策略状态",
            Location = new Point(186, 138),
            Size = new Size(160, 32)
        };
        _queryPolicyBtn.Click += () =>
        {
            try
            {
                var status = _collector?.GetAuditPolicyStatus() ?? "采集器未初始化";
                if (_policyStatusBox != null)
                    _policyStatusBox.Text = status;
            }
            catch (Exception ex)
            {
                MessageBoxHelper.Error($"查询失败：{ex.Message}");
            }
        };
        policyCard.Controls.Add(_queryPolicyBtn);

        y += 210;

        // ===== 策略状态输出 =====
        CreateSectionTitle("策略状态输出（auditpol）", 0, y);
        y += 30;

        var statusCard = CreateCard(0, y, cw, 200);
        _policyStatusBox = new TextBox
        {
            Location = new Point(16, 12),
            Size = new Size(cw - 32, 170),
            Font = new Font("Consolas", 9F),
            BackColor = Theme.CardBg,
            ForeColor = Theme.TextSecondary,
            BorderStyle = BorderStyle.FixedSingle,
            Multiline = true,
            ScrollBars = ScrollBars.Vertical,
            ReadOnly = true,
            Text = "点击\"查询当前策略状态\"按钮查看系统审核策略配置..."
        };
        statusCard.Controls.Add(_policyStatusBox);

        y += 210;

        // ===== 采集技术说明 =====
        CreateSectionTitle("采集技术方案说明", 0, y);
        y += 30;

        var techCard = CreateCard(0, y, cw, 160);
        var techLines = new[]
        {
            "方案 1：NTFS SACL 安全审核 + 系统安全事件日志",
            "  · 通过 auditpol 自动配置「审核对象访问」策略",
            "  · EventLog API 实时订阅 Security 日志流（事件 ID 4624/4656/4663/4660/4670）",
            "  · 句柄 HandleID 关联 4656+4663 事件，补全「文件路径 + 操作类型」完整数据",
            "",
            "方案 2：ETW Windows 事件追踪（实时流式采集）",
            "  · 订阅 Microsoft-Windows-SmbServer / Microsoft-Windows-Kernel-File 事件源",
            "  · 高并发场景无延迟、海量操作不丢失记录",
            "  · SACL 日志做持久化存储，ETW 做实时告警触发，二者数据合并去重"
        };
        for (int i = 0; i < techLines.Length; i++)
        {
            var line = new Label
            {
                Text = techLines[i],
                Font = techLines[i].StartsWith("方案") ? Theme.BodyFont : Theme.SmallFont,
                ForeColor = techLines[i].StartsWith("方案") ? Theme.TextPrimary : Theme.TextSecondary,
                Location = new Point(16, 8 + i * 16),
                Size = new Size(cw - 32, 16),
                BackColor = Color.Transparent
            };
            techCard.Controls.Add(line);
        }

        y += 170;
    }

    #endregion

    #region 通用表格构建

    /// <summary>构建审计记录表格</summary>
    private int BuildRecordTable(int y, List<SmbAuditEntry> records, int cw)
    {
        // 表头
        var headerCard = CreateCard(0, y, cw, 28);
        var headers = new[] { "时间", "用户名", "客户端IP", "操作", "文件路径", "风险标签", "来源" };
        var xPos = new[] { 8, 158, 318, 448, 520, 820, 920 };
        var widths = new[] { 146, 156, 126, 66, 296, 96, 80 };
        for (int i = 0; i < headers.Length; i++)
        {
            var h = new Label
            {
                Text = headers[i],
                Font = Theme.SmallFont,
                ForeColor = Theme.TextSecondary,
                Location = new Point(xPos[i], 4),
                Size = new Size(widths[i], 20),
                BackColor = Color.Transparent
            };
            headerCard.Controls.Add(h);
        }
        y += 32;

        foreach (var r in records)
        {
            var itemCard = CreateCard(0, y, cw, 26);
            var vals = new[]
            {
                r.Time.ToString("MM-dd HH:mm:ss"),
                TruncateText(r.UserName, 20),
                r.ClientIp,
                GetOperationName(r.Operation),
                TruncateText(r.FilePath, 40),
                r.RiskTag,
                r.IsRemote ? "远程" : "本地"
            };
            for (int i = 0; i < vals.Length; i++)
            {
                var v = new Label
                {
                    Text = vals[i],
                    Font = Theme.SmallFont,
                    ForeColor = GetRecordForeColor(r, i),
                    Location = new Point(xPos[i], 3),
                    Size = new Size(widths[i], 20),
                    BackColor = Color.Transparent
                };
                itemCard.Controls.Add(v);
            }

            // P1-6：SMB 审计日志右键菜单 — 一键查杀目标文件（Defender 联动）
            var filePath = r.FilePath;
            var ctx = new ContextMenuStrip();
            ctx.Items.Add("🔍 Defender 查杀该文件", null, async (s, e) =>
            {
                if (string.IsNullOrEmpty(filePath))
                {
                    MessageBoxHelper.Warn("该记录无文件路径，无法查杀。");
                    return;
                }
                if (!File.Exists(filePath))
                {
                    MessageBoxHelper.Warn("文件已不存在，可能已被移动或删除。");
                    return;
                }
                await DefenderIntegrationService.ScanPathAsync(filePath, false, "SMB审计联动");
                MessageBoxHelper.Info("Defender 查杀已完成，结果已写入审计日志。");
            });
            ctx.Items.Add("打开所在目录", null, (s, e) =>
            {
                if (string.IsNullOrEmpty(filePath)) return;
                var dir = Path.GetDirectoryName(filePath);
                if (Directory.Exists(dir))
                    System.Diagnostics.Process.Start("explorer.exe", dir);
            });
            itemCard.ContextMenuStrip = ctx;
            foreach (Control child in itemCard.Controls)
                child.ContextMenuStrip = ctx;

            y += 30;
        }
        return y;
    }

    /// <summary>构建风险事件表格</summary>
    private int BuildRiskTable(int y, List<SmbRiskEvent> risks, int cw)
    {
        // 表头
        var headerCard = CreateCard(0, y, cw, 28);
        var headers = new[] { "检测时间", "等级", "风险类型", "标题", "描述" };
        var xPos = new[] { 8, 168, 228, 380, 660 };
        var widths = new[] { 156, 56, 148, 276, cw - 670 };
        for (int i = 0; i < headers.Length; i++)
        {
            var h = new Label
            {
                Text = headers[i],
                Font = Theme.SmallFont,
                ForeColor = Theme.TextSecondary,
                Location = new Point(xPos[i], 4),
                Size = new Size(widths[i], 20),
                BackColor = Color.Transparent
            };
            headerCard.Controls.Add(h);
        }
        y += 32;

        foreach (var r in risks)
        {
            var itemCard = CreateCard(0, y, cw, 44);
            var vals = new[]
            {
                r.DetectedAt.ToString("MM-dd HH:mm:ss"),
                GetSeverityName(r.Severity),
                GetRiskTypeName(r.Type),
                r.Title,
                TruncateText(r.Description, 80)
            };
            for (int i = 0; i < vals.Length; i++)
            {
                var v = new Label
                {
                    Text = vals[i],
                    Font = Theme.SmallFont,
                    ForeColor = i == 1 ? GetSeverityColor(r.Severity) : Theme.TextSecondary,
                    Location = new Point(xPos[i], 4),
                    Size = new Size(widths[i], i == 4 ? 36 : 20),
                    BackColor = Color.Transparent
                };
                itemCard.Controls.Add(v);
            }
            y += 48;
        }
        return y;
    }

    #endregion

    #region 辅助方法

    /// <summary>获取操作类型显示名</summary>
    private static string GetOperationName(SmbOperation op) => op switch
    {
        SmbOperation.Login => "登录",
        SmbOperation.Read => "读取",
        SmbOperation.Write => "写入",
        SmbOperation.Modify => "修改",
        SmbOperation.Delete => "删除",
        SmbOperation.BatchDelete => "批量删除",
        SmbOperation.Move => "移动",
        SmbOperation.Rename => "重命名",
        SmbOperation.PermissionChange => "权限篡改",
        SmbOperation.AccessDenied => "越权访问",
        _ => op.ToString()
    };

    /// <summary>获取风险类型显示名</summary>
    private static string GetRiskTypeName(SmbRiskType type) => type switch
    {
        SmbRiskType.MassExfiltration => "批量外泄",
        SmbRiskType.AfterHoursAccess => "凌晨访问",
        SmbRiskType.HighFrequencyDeletion => "高频删除",
        SmbRiskType.BackupAnomalousAccess => "备份目录访问",
        _ => type.ToString()
    };

    /// <summary>获取严重等级显示名</summary>
    private static string GetSeverityName(RiskLevel level) => level switch
    {
        RiskLevel.Critical => "严重",
        RiskLevel.High => "高危",
        RiskLevel.Medium => "中危",
        RiskLevel.Low => "低危",
        RiskLevel.Clean => "正常",
        _ => level.ToString()
    };

    /// <summary>获取严重等级颜色</summary>
    private static Color GetSeverityColor(RiskLevel level) => level switch
    {
        RiskLevel.Critical => Theme.Error,
        RiskLevel.High => Theme.Warning,
        RiskLevel.Medium => Theme.Accent,
        _ => Theme.TextSecondary
    };

    /// <summary>获取记录字段颜色（风险标签列特殊着色）</summary>
    private static Color GetRecordForeColor(SmbAuditEntry entry, int colIndex)
    {
        if (colIndex == 6) // 来源列
            return entry.IsRemote ? Theme.Warning : Theme.TextTertiary;
        if (colIndex == 5) // 风险标签列
        {
            if (entry.RiskTag.Contains("删除") || entry.RiskTag.Contains("篡改"))
                return Theme.Error;
            if (entry.RiskTag.Contains("失败") || entry.RiskTag.Contains("越权"))
                return Theme.Warning;
        }
        return Theme.TextSecondary;
    }

    /// <summary>截断文本</summary>
    private static string TruncateText(string text, int maxLen)
    {
        if (string.IsNullOrEmpty(text)) return "";
        return text.Length <= maxLen ? text : text.Substring(0, maxLen - 3) + "...";
    }

    /// <summary>CSV 字段转义</summary>
    private static string EscapeCsv(string field)
    {
        if (string.IsNullOrEmpty(field)) return "";
        if (field.Contains(',') || field.Contains('"') || field.Contains('\n'))
            return $"\"{field.Replace("\"", "\"\"")}\"";
        return field;
    }

    public override void RefreshData()
    {
        BuildContent();
    }

    #endregion
}
