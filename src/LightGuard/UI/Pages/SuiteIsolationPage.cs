// © 2026 落尘（Luochen） 原创开发 - 保留所有权利

using LightGuard.Core;
using LightGuard.NetworkIsolation;

namespace LightGuard.UI.Pages;

/// <summary>
/// 商业软件联网隔离页面
/// <para>Adobe / CorelDRAW 等套件的「出站阻断」管理：仅断对外联网，
/// 不阻止程序运行；每套件独立开关，支持刷新规则（升级后 exe 路径变更）与一键清除。</para>
/// </summary>
public sealed class SuiteIsolationPage : Page
{
    private readonly SuiteIsolationService _service = new();
    private readonly Dictionary<string, Label> _statusLabels = new();
    private readonly TextBox _logBox = new();
    private string _logText = "";
    private bool _building;
    private bool _busy;

    public SuiteIsolationPage(AppState appState) : base(appState,
        "商业软件网络隔离",
        "仅阻断商业软件对外联网（上报 / 激活校验 / 更新 / 遥测），不阻止程序运行；软件升级后请点【刷新规则】")
    {
        // 首次运行播种预置套件配置
        if (appState.Config.SuiteIsolation.Suites.Count == 0)
        {
            appState.Config.SuiteIsolation.Suites = SuiteBlockPresets.GetDefaultPresets();
            ConfigManager.Save(appState.Config);
        }
    }

    public override void OnShown() => RefreshData();

    public override void RefreshData()
    {
        _building = true;
        try
        {
            ScrollContent.Controls.Clear();
            _statusLabels.Clear();

            var width = ContentWidth - 16;
            int y = 8;

            // ===== 顶部提示卡 =====
            var tipCard = CreateCard(0, y, width, 88);
            var tip = new Label
            {
                Text = "⚠ 本功能仅阻断软件对外上传、更新、遥测、激活校验网络；不会阻止软件启动运行。\n" +
                       "   软件大版本升级后 exe 路径会变化，请点【刷新规则】更新规则。\n" +
                       "   如果软件出现授权弹窗，属于软件自身逻辑，本地功能不受影响。",
                Font = Theme.SmallFont,
                ForeColor = Theme.TextSecondary,
                Location = new Point(16, 10),
                Size = new Size(width - 32, 68),
                BackColor = Color.Transparent
            };
            tipCard.Controls.Add(tip);
            y += 100;

            // ===== hosts 补充阻断开关（可选增强）=====
            var hostsToggle = new CheckBox
            {
                Text = "附加 Hosts 域名阻断（可选增强，需管理员权限；防止软件借系统进程联网）",
                Font = Theme.BodyFont,
                ForeColor = Theme.TextPrimary,
                Location = new Point(0, y),
                Size = new Size(width, 26),
                Checked = AppState.Config.SuiteIsolation.HostsBlockEnabled,
                BackColor = Color.Transparent
            };
            hostsToggle.CheckedChanged += (s, e) =>
            {
                if (_building) return;
                AppState.Config.SuiteIsolation.HostsBlockEnabled = hostsToggle.Checked;
                ConfigManager.Save(AppState.Config);
                RunBusy(() => hostsToggle.Checked
                    ? ApplyHostsForAll()
                    : RestoreHostsForAll());
            };
            ScrollContent.Controls.Add(hostsToggle);
            y += 34;

            // ===== 各套件卡片 =====
            foreach (var suite in AppState.Config.SuiteIsolation.Suites)
            {
                y += 12;
                var card = CreateCard(0, y, width, 158);
                BuildSuiteCard(card, suite, width);
                y += 170;
            }

            // ===== 操作日志 =====
            y += 12;
            CreateSectionTitle("操作日志", 0, y);
            y += 30;
            _logBox.Location = new Point(0, y);
            _logBox.Size = new Size(width, 220);
            _logBox.Multiline = true;
            _logBox.ReadOnly = true;
            _logBox.ScrollBars = ScrollBars.Vertical;
            _logBox.BackColor = Theme.CardBg;
            _logBox.ForeColor = Theme.TextPrimary;
            _logBox.Font = Theme.SmallFont;
            _logBox.BorderStyle = BorderStyle.None;
            _logBox.Text = _logText;
            ScrollContent.Controls.Add(_logBox);
        }
        finally
        {
            _building = false;
        }
    }

    /// <summary>构建单个套件卡片（名称 / 启用开关 / 状态 / 刷新 / 清除）</summary>
    private void BuildSuiteCard(Panel card, SuiteBlockConfig suite, int width)
    {
        var nameLabel = new Label
        {
            Text = suite.UiName,
            Font = Theme.HeaderFont,
            ForeColor = Theme.TextPrimary,
            Location = new Point(16, 12),
            Size = new Size(width - 32, 24),
            BackColor = Color.Transparent
        };
        card.Controls.Add(nameLabel);

        var enableBox = new CheckBox
        {
            Text = "启用隔离（生成出站阻断规则）",
            Font = Theme.BodyFont,
            ForeColor = Theme.TextSecondary,
            Location = new Point(16, 44),
            Size = new Size(260, 24),
            Checked = suite.Enabled,
            BackColor = Color.Transparent
        };
        enableBox.CheckedChanged += (s, e) =>
        {
            if (_building) return;
            suite.Enabled = enableBox.Checked;
            ConfigManager.Save(AppState.Config);
            RunBusy(() => enableBox.Checked
                ? _service.ApplyRules(suite, Log)
                : _service.ClearRules(suite, Log));
        };
        card.Controls.Add(enableBox);

        var statusLabel = new Label
        {
            Text = $"当前规则：{_service.CountRules(suite)} 条",
            Font = Theme.SmallFont,
            ForeColor = Theme.TextTertiary,
            Location = new Point(16, 76),
            Size = new Size(width - 32, 20),
            BackColor = Color.Transparent
        };
        card.Controls.Add(statusLabel);
        _statusLabels[suite.Id] = statusLabel;

        var refreshBtn = MakeButton("刷新规则", new Point(16, 104), Math.Max(width - 32 - 130 - 12, 120));
        refreshBtn.Click += (s, e) => RunBusy(() => _service.ApplyRules(suite, Log));
        card.Controls.Add(refreshBtn);

        var clearBtn = MakeButton("清除全部规则", new Point(16 + refreshBtn.Width + 12, 104), 130);
        clearBtn.Click += (s, e) => RunBusy(() =>
        {
            _service.ClearRules(suite, Log);
            if (AppState.Config.SuiteIsolation.HostsBlockEnabled)
                _service.RestoreHostsBlock(suite);
            return 0;
        });
        card.Controls.Add(clearBtn);
    }

    /// <summary>创建统一样式的扁平按钮</summary>
    private static Button MakeButton(string text, Point location, int width)
    {
        var btn = new Button
        {
            Text = text,
            Location = location,
            Size = new Size(width, 32),
            FlatStyle = FlatStyle.Flat,
            Font = Theme.BodyFont,
            BackColor = Theme.CardBg,
            ForeColor = Theme.TextPrimary,
            Cursor = Cursors.Hand
        };
        btn.FlatAppearance.BorderColor = Theme.Border;
        return btn;
    }

    private int ApplyHostsForAll()
    {
        int ok = 0;
        foreach (var suite in AppState.Config.SuiteIsolation.Suites)
        {
            Log($"[INFO] 写入 hosts 阻断：{suite.UiName}");
            if (_service.ApplyHostsBlock(suite)) ok++;
        }
        Log(ok > 0 ? $"[INFO] hosts 阻断已应用（{ok} 个套件）" : "[WARN] hosts 写入失败，请以管理员身份运行");
        return ok;
    }

    private int RestoreHostsForAll()
    {
        int ok = 0;
        foreach (var suite in AppState.Config.SuiteIsolation.Suites)
        {
            if (_service.RestoreHostsBlock(suite)) ok++;
        }
        Log($"[INFO] 已清除 hosts 阻断（{ok} 个套件）");
        return ok;
    }

    /// <summary>追加一条操作日志（线程安全：跨线程回 UI 线程）</summary>
    private void Log(string message)
    {
        _logText += message + Environment.NewLine;
        try
        {
            BeginInvoke(() =>
            {
                _logBox.Text = _logText;
                _logBox.SelectionStart = _logBox.TextLength;
                _logBox.ScrollToCaret();
            });
        }
        catch { }
    }

    /// <summary>后台执行套件操作，完成后刷新状态标签；操作进行中拒绝并发</summary>
    private void RunBusy(Func<int> op)
    {
        if (_busy)
        {
            Log("[WARN] 有操作进行中，请稍候...");
            return;
        }
        _busy = true;
        Task.Run(() =>
        {
            try
            {
                op();
                BeginInvoke(() =>
                {
                    foreach (var suite in AppState.Config.SuiteIsolation.Suites)
                    {
                        if (_statusLabels.TryGetValue(suite.Id, out var label))
                            label.Text = $"当前规则：{_service.CountRules(suite)} 条";
                    }
                });
            }
            catch (Exception ex)
            {
                Log($"[ERROR] {ex.Message}");
                ErrorReporter.Report(ex, "[SuiteIsolation] 操作异常");
            }
            finally
            {
                _busy = false;
            }
        });
    }
}
