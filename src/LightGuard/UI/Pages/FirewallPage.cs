using LightGuard.Core;
using LightGuard.Modules;
using LightGuard.UI.Controls;

namespace LightGuard.UI.Pages;

/// <summary>
/// 防火墙管理页面
/// 显示防火墙状态、网络连接列表、防火墙规则、Windows Defender 状态
/// 支持启用防火墙、检测可疑连接
/// </summary>
public class FirewallPage : Page
{
    private FirewallModule? _module;
    private Label? _firewallStatusLabel;
    private AccentButton? _enableBtn;
    private AccentButton? _detectBtn;

    public FirewallPage(AppState appState) : base(appState, "防火墙管理", "原生高级防火墙、智能拦截流氓软件偷流量、Defender 智能兼容")
    {
    }

    public override void OnShown()
    {
        _module = AppState.Modules.GetModule("firewall") as FirewallModule;
        BuildContent();
    }

    /// <summary>构建页面内容</summary>
    private void BuildContent()
    {
        ScrollContent.Controls.Clear();

        int y = 0;

        // ===== 防火墙状态区 =====
        CreateSectionTitle("防火墙状态", 0, y);
        y += 30;

        var fwEnabled = _module?.IsFirewallEnabled() ?? false;
        var statusCard = CreateCard(0, y, 720, 60);

        _firewallStatusLabel = new Label
        {
            Text = fwEnabled ? "● 防火墙已启用" : "○ 防火墙未启用",
            Font = Theme.HeaderFont,
            ForeColor = fwEnabled ? Theme.Success : Theme.Error,
            Location = new Point(16, 8),
            Size = new Size(300, 24),
            BackColor = Color.Transparent
        };
        statusCard.Controls.Add(_firewallStatusLabel);

        _enableBtn = new AccentButton
        {
            Text = fwEnabled ? "已启用" : "启用防火墙",
            Location = new Point(580, 12),
            Size = new Size(120, 36),
            Enabled = !fwEnabled
        };
        _enableBtn.Click += async () =>
        {
            if (_module == null) return;
            _enableBtn.Enabled = false;
            var ok = await Task.Run(() => _module.EnableFirewall());
            if (ok)
                MessageBoxHelper.Info("Windows 防火墙已成功启用！");
            else
                MessageBoxHelper.Error("启用防火墙失败，请以管理员身份运行。");
            RefreshData();
        };
        statusCard.Controls.Add(_enableBtn);

        y += 80;

        // ===== 快速操作区 =====
        CreateSectionTitle("快速操作", 0, y);
        y += 30;

        var actionCard = CreateCard(0, y, 720, 56);

        _detectBtn = new AccentButton
        {
            Text = "检测可疑连接",
            Location = new Point(16, 10),
            Size = new Size(140, 36)
        };
        _detectBtn.Click += async () =>
        {
            if (_module == null) return;
            _detectBtn.Enabled = false;
            MessageBoxHelper.Info("正在检测可疑网络连接...");
            await Task.Run(() => _module.DetectSuspiciousConnections());
            _detectBtn.Enabled = true;
            MessageBoxHelper.Info("可疑连接检测完成，已自动阻止流氓程序联网。");
            RefreshData();
        };
        actionCard.Controls.Add(_detectBtn);

        y += 76;

        // ===== Windows Defender 状态区 =====
        CreateSectionTitle("Windows Defender 状态", 0, y);
        y += 30;

        if (_module != null)
        {
            var defender = _module.GetDefenderStatus();
            var defenderCard = CreateCard(0, y, 720, 150);

            var defenderLines = new[]
            {
                $"Defender 已安装：{(defender.IsInstalled ? "是" : "否")}",
                $"反间谍软件：{(defender.AntiSpywareEnabled ? "已启用" : "未启用")}",
                $"实时保护：{(defender.RealTimeProtectionEnabled ? "已启用" : "未启用")}",
                $"防病毒：{(defender.AntivirusEnabled ? "已启用" : "未启用")}",
                $"运行模式：{defender.RunningMode}",
                $"引擎版本：{defender.EngineVersion}",
                $"病毒库更新：{(defender.SignatureLastUpdated.HasValue ? defender.SignatureLastUpdated.Value.ToString("yyyy-MM-dd HH:mm") : "未知")}",
                $"双杀冲突检测：{(defender.HasConflict ? "存在冲突（建议关闭 Defender 实时保护）" : "无冲突")}"
            };

            for (int i = 0; i < defenderLines.Length; i++)
            {
                var label = new Label
                {
                    Text = defenderLines[i],
                    Font = Theme.BodyFont,
                    ForeColor = Theme.TextSecondary,
                    Location = new Point(16, 10 + i * 17),
                    Size = new Size(688, 17),
                    BackColor = Color.Transparent
                };
                defenderCard.Controls.Add(label);
            }

            y += 170;
        }

        // ===== 网络连接列表区 =====
        CreateSectionTitle("网络连接列表（前 30 条）", 0, y);
        y += 30;

        if (_module != null)
        {
            var connections = _module.GetNetworkConnections();
            var display = connections.Take(30).ToList();

            if (display.Count == 0)
            {
                var emptyLabel = new Label
                {
                    Text = "暂无网络连接",
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
                var headerCard = CreateCard(0, y, 720, 28);
                var headers = new[] { "协议", "本地地址", "远程地址", "状态", "PID", "进程名" };
                var xPositions = new[] { 8, 60, 220, 380, 480, 540 };
                var widths = new[] { 50, 158, 158, 96, 56, 148 };

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

                foreach (var conn in display)
                {
                    var connCard = CreateCard(0, y, 720, 24);
                    var bgColor = conn.IsSuspicious ? Theme.Warning : Color.Transparent;

                    var values = new[]
                    {
                        conn.Protocol,
                        TruncateText(conn.LocalAddress, 22),
                        TruncateText(conn.ForeignAddress, 22),
                        TruncateText(conn.State, 12),
                        conn.PID.ToString(),
                        TruncateText(conn.ProcessName, 20)
                    };

                    for (int i = 0; i < values.Length; i++)
                    {
                        var vLabel = new Label
                        {
                            Text = values[i],
                            Font = Theme.SmallFont,
                            ForeColor = conn.IsSuspicious ? Theme.Warning : Theme.TextSecondary,
                            Location = new Point(xPositions[i], 2),
                            Size = new Size(widths[i], 20),
                            BackColor = Color.Transparent
                        };
                        connCard.Controls.Add(vLabel);
                    }

                    y += 30;
                }
            }

            y += 10;
        }

        // ===== 防火墙规则列表区 =====
        CreateSectionTitle("防火墙规则列表（前 20 条）", 0, y);
        y += 30;

        if (_module != null)
        {
            var rules = _module.GetFirewallRules();
            var display = rules.Take(20).ToList();

            if (display.Count == 0)
            {
                var emptyLabel = new Label
                {
                    Text = "暂无防火墙规则",
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
                var headerCard = CreateCard(0, y, 720, 28);
                var ruleHeaders = new[] { "规则名称", "启用", "方向", "操作", "程序路径" };
                var ruleXPos = new[] { 8, 360, 420, 500, 560 };
                var ruleWidths = new[] { 350, 56, 76, 76, 148 };

                for (int i = 0; i < ruleHeaders.Length; i++)
                {
                    var hLabel = new Label
                    {
                        Text = ruleHeaders[i],
                        Font = Theme.SmallFont,
                        ForeColor = Theme.TextSecondary,
                        Location = new Point(ruleXPos[i], 4),
                        Size = new Size(ruleWidths[i], 20),
                        BackColor = Color.Transparent
                    };
                    headerCard.Controls.Add(hLabel);
                }
                y += 34;

                foreach (var rule in display)
                {
                    var ruleCard = CreateCard(0, y, 720, 24);

                    var ruleValues = new[]
                    {
                        TruncateText(rule.Name, 48),
                        rule.Enabled ? "是" : "否",
                        rule.Direction,
                        rule.Action,
                        TruncateText(rule.Program, 20)
                    };

                    for (int i = 0; i < ruleValues.Length; i++)
                    {
                        var vLabel = new Label
                        {
                            Text = ruleValues[i],
                            Font = Theme.SmallFont,
                            ForeColor = rule.Action == "Block" ? Theme.Warning : Theme.TextSecondary,
                            Location = new Point(ruleXPos[i], 2),
                            Size = new Size(ruleWidths[i], 20),
                            BackColor = Color.Transparent
                        };
                        ruleCard.Controls.Add(vLabel);
                    }

                    y += 30;
                }
            }

            y += 10;
        }

        y += 20;
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
