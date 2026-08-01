using LightGuard.Core;
using LightGuard.Modules;
using LightGuard.UI.Controls;

namespace LightGuard.UI.Pages;

/// <summary>
/// 自动更新页面
/// 显示各组件更新状态，支持检查更新、自动更新开关、更新频率设置、离线导入
/// 更新在后台执行
/// </summary>
public class UpdatePage : Page
{
    private UpdateModule? _module;
    private AccentButton? _checkBtn;
    private AccentButton? _importBtn;
    private ToggleSwitch? _autoUpdateToggle;
    private ComboBox? _intervalCombo;
    private Label? _progressLabel;
    private bool _isUpdating;

    public UpdatePage(AppState appState) : base(appState, "自动更新", "三层全自动无感更新：软件本体、杀毒引擎、病毒库+流氓规则库")
    {
    }

    public override void OnShown()
    {
        _module = AppState.Modules.GetModule("update") as UpdateModule;
        BuildContent();
    }

    /// <summary>构建页面内容</summary>
    private void BuildContent()
    {
        ScrollContent.Controls.Clear();

        int y = 0;

        // ===== 更新操作区 =====
        CreateSectionTitle("更新操作", 0, y);
        y += 30;

        var actionCard = CreateCard(0, y, ContentWidth, 60);

        _checkBtn = new AccentButton
        {
            Text = "检查更新",
            Location = new Point(16, 12),
            Size = new Size(120, 36)
        };
        _checkBtn.Click += () => StartCheckUpdate();
        actionCard.Controls.Add(_checkBtn);

        _importBtn = new AccentButton
        {
            Text = "离线导入",
            Location = new Point(146, 12),
            Size = new Size(120, 36)
        };
        _importBtn.Click += async () =>
        {
            if (_module == null) return;
            using var dialog = new OpenFileDialog
            {
                Title = "选择离线更新包",
                Filter = "更新包文件|*.zip;*.cvd;*.json|所有文件|*.*"
            };
            if (dialog.ShowDialog() != DialogResult.OK)
                return;

            _importBtn.Enabled = false;
            MessageBoxHelper.Info("正在导入离线更新包...");
            var result = await Task.Run(() => _module.ImportUpdateFromFile(dialog.FileName));
            _importBtn.Enabled = true;

            if (result.Success)
                MessageBoxHelper.Info($"离线导入成功！{result.Message}");
            else
                MessageBoxHelper.Error($"离线导入失败：{result.Message}");

            RefreshData();
        };
        actionCard.Controls.Add(_importBtn);

        y += 80;

        // ===== 更新进度区 =====
        CreateSectionTitle("更新进度", 0, y);
        y += 30;

        var progressCard = CreateCard(0, y, ContentWidth, 50);
        _progressLabel = new Label
        {
            Text = _isUpdating ? "正在检查更新，请稍候..." : "就绪",
            Font = Theme.BodyFont,
            ForeColor = _isUpdating ? Theme.Warning : Theme.TextSecondary,
            Location = new Point(16, 14),
            Size = new Size(688, 22),
            BackColor = Color.Transparent
        };
        progressCard.Controls.Add(_progressLabel);
        y += 70;

        // ===== 更新设置区 =====
        CreateSectionTitle("更新设置", 0, y);
        y += 30;

        var settingsCard = CreateCard(0, y, ContentWidth, 110);

        // 自动更新开关
        var autoLabel = new Label
        {
            Text = "自动更新：",
            Font = Theme.BodyFont,
            ForeColor = Theme.TextSecondary,
            Location = new Point(16, 12),
            Size = new Size(100, 22),
            BackColor = Color.Transparent
        };
        settingsCard.Controls.Add(autoLabel);

        _autoUpdateToggle = new ToggleSwitch
        {
            Location = new Point(116, 14),
            IsOn = AppState.Config.Update.AutoUpdate
        };
        _autoUpdateToggle.Toggled += (on) =>
        {
            AppState.Config.Update.AutoUpdate = on;
            ConfigManager.Save(AppState.Config);
            MessageBoxHelper.Info(on ? "已开启自动更新。" : "已关闭自动更新。");
        };
        settingsCard.Controls.Add(_autoUpdateToggle);

        var autoDescLabel = new Label
        {
            Text = "开启后将定时自动检查并更新病毒库和规则库",
            Font = Theme.SmallFont,
            ForeColor = Theme.TextTertiary,
            Location = new Point(170, 14),
            Size = new Size(400, 20),
            BackColor = Color.Transparent
        };
        settingsCard.Controls.Add(autoDescLabel);

        // 检查频率
        var intervalLabel = new Label
        {
            Text = "检查频率：",
            Font = Theme.BodyFont,
            ForeColor = Theme.TextSecondary,
            Location = new Point(16, 50),
            Size = new Size(100, 22),
            BackColor = Color.Transparent
        };
        settingsCard.Controls.Add(intervalLabel);

        _intervalCombo = new ComboBox
        {
            Location = new Point(116, 48),
            Size = new Size(140, 24),
            FlatStyle = FlatStyle.Flat,
            Font = Theme.BodyFont,
            DropDownStyle = ComboBoxStyle.DropDownList
        };
        _intervalCombo.Items.AddRange(new object[] { "每 6 小时", "每 12 小时", "每天", "每 3 天", "每周" });
        var intervalHours = AppState.Config.Update.UpdateCheckIntervalHours;
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
            AppState.Config.Update.UpdateCheckIntervalHours = _intervalCombo.SelectedIndex switch
            {
                0 => 6,
                1 => 12,
                2 => 24,
                3 => 72,
                4 => 168,
                _ => 12
            };
            ConfigManager.Save(AppState.Config);
        };
        settingsCard.Controls.Add(_intervalCombo);

        // 最后更新时间
        var lastUpdateLabel = new Label
        {
            Text = $"病毒库最后更新：{(AppState.Config.Update.LastVirusDbUpdate.HasValue ? AppState.Config.Update.LastVirusDbUpdate.Value.ToString("yyyy-MM-dd HH:mm:ss") : "从未")}    " +
                   $"引擎最后更新：{(AppState.Config.Update.LastEngineUpdate.HasValue ? AppState.Config.Update.LastEngineUpdate.Value.ToString("yyyy-MM-dd HH:mm:ss") : "从未")}",
            Font = Theme.SmallFont,
            ForeColor = Theme.TextTertiary,
            Location = new Point(16, 82),
            Size = new Size(688, 20),
            BackColor = Color.Transparent
        };
        settingsCard.Controls.Add(lastUpdateLabel);

        y += 130;

        // ===== 组件更新状态区 =====
        CreateSectionTitle("组件更新状态", 0, y);
        y += 30;

        if (_module != null)
        {
            var status = _module.GetUpdateStatus();
            var components = new[] { status.AppStatus, status.EngineStatus, status.VirusDbStatus, status.RogueRulesStatus };

            // 表头
            var headerCard = CreateCard(0, y, ContentWidth, 28);
            var headers = new[] { "组件", "当前版本", "最新版本", "状态", "最后更新" };
            var xPositions = new[] { 8, 120, 260, 400, 540 };
            var widths = new[] { 108, 136, 136, 136, 160 };

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

            foreach (var comp in components)
            {
                var compCard = CreateCard(0, y, ContentWidth, 28);

                var values = new[]
                {
                    comp.Component,
                    comp.CurrentVersion,
                    comp.LatestVersion,
                    comp.IsUpToDate ? "已是最新" : "有更新",
                    comp.LastUpdate.HasValue ? comp.LastUpdate.Value.ToString("yyyy-MM-dd HH:mm") : "未更新"
                };

                for (int i = 0; i < values.Length; i++)
                {
                    var vLabel = new Label
                    {
                        Text = values[i],
                        Font = Theme.SmallFont,
                        ForeColor = comp.IsUpToDate ? Theme.Success : Theme.Warning,
                        Location = new Point(xPositions[i], 4),
                        Size = new Size(widths[i], 20),
                        BackColor = Color.Transparent
                    };
                    compCard.Controls.Add(vLabel);
                }

                y += 36;
            }

            // 状态描述
            var summaryLabel = new Label
            {
                Text = status.AllUpToDate ? "所有组件均为最新版本" : "部分组件有可用更新",
                Font = Theme.BodyFont,
                ForeColor = status.AllUpToDate ? Theme.Success : Theme.Warning,
                Location = new Point(0, y),
                Size = new Size(ContentWidth, 22),
                BackColor = Color.Transparent
            };
            ScrollContent.Controls.Add(summaryLabel);
            y += 30;
        }

        y += 20;
    }

    /// <summary>启动更新检查（后台线程）</summary>
    private async void StartCheckUpdate()
    {
        if (_module == null || _isUpdating) return;

        _isUpdating = true;
        if (_checkBtn != null) _checkBtn.Enabled = false;

        if (_progressLabel != null)
        {
            _progressLabel.Text = "正在检查并更新所有组件，请稍候...";
            _progressLabel.ForeColor = Theme.Warning;
        }

        var results = await Task.Run(() => _module.CheckAndUpdateAllAsync());

        _isUpdating = false;
        if (_checkBtn != null) _checkBtn.Enabled = true;

        if (_progressLabel != null)
        {
            _progressLabel.Text = "更新检查完成";
            _progressLabel.ForeColor = Theme.Success;
        }

        // 构建结果摘要
        var sb = new System.Text.StringBuilder();
        sb.AppendLine("更新检查结果：");
        sb.AppendLine();
        foreach (var r in results)
        {
            sb.AppendLine($"【{r.Component}】{(r.Success ? "成功" : "失败")} - {r.Message}");
        }
        MessageBoxHelper.Info(sb.ToString());

        RefreshData();
    }

    public override void RefreshData()
    {
        BuildContent();
    }
}
