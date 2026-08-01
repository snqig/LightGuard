using LightGuard.Core;
using LightGuard.Modules;
using LightGuard.UI.Controls;

namespace LightGuard.UI.Pages;

/// <summary>
/// 流氓软件净化页面
/// 显示净化项列表，支持三模式切换（家用/办公/老旧），一键净化/还原
/// </summary>
public class CleanupPage : Page
{
    private CleanupModule? _module;
    private Label? _lastCleanedLabel;
    private AccentButton? _cleanBtn;
    private AccentButton? _restoreBtn;
    private AccentButton? _homeBtn;
    private AccentButton? _officeBtn;
    private AccentButton? _perfBtn;

    public CleanupPage(AppState appState) : base(appState, "流氓软件净化", "一键净化 WPS、360、Edge、2345 等弹窗广告与后台流氓行为")
    {
    }

    public override void OnShown()
    {
        _module = AppState.Modules.GetModule("cleanup") as CleanupModule;
        BuildContent();
    }

    /// <summary>构建页面内容</summary>
    private void BuildContent()
    {
        ScrollContent.Controls.Clear();

        int y = 0;

        // ===== 状态信息区 =====
        CreateSectionTitle("净化状态", 0, y);
        y += 30;

        var statusCard = CreateCard(0, y, 720, 50);
        _lastCleanedLabel = new Label
        {
            Text = GetLastCleanedText(),
            Font = Theme.BodyFont,
            ForeColor = Theme.TextSecondary,
            Location = new Point(16, 14),
            Size = new Size(680, 22),
            BackColor = Color.Transparent
        };
        statusCard.Controls.Add(_lastCleanedLabel);
        y += 70;

        // ===== 场景模式切换 =====
        CreateSectionTitle("场景模式", 0, y);
        y += 30;

        var modeCard = CreateCard(0, y, 720, 60);
        var modeLabel = new Label
        {
            Text = "选择净化模式：",
            Font = Theme.BodyFont,
            ForeColor = Theme.TextSecondary,
            Location = new Point(16, 16),
            Size = new Size(120, 28),
            BackColor = Color.Transparent
        };
        modeCard.Controls.Add(modeLabel);

        _homeBtn = new AccentButton
        {
            Text = "家用纯净",
            Location = new Point(140, 12),
            Size = new Size(100, 36)
        };
        _homeBtn.Click += () =>
        {
            AppState.Config.CurrentScene = SceneMode.Home;
            ConfigManager.Save(AppState.Config);
            RefreshData();
            MessageBoxHelper.Info("已切换为家用纯净模式。");
        };
        modeCard.Controls.Add(_homeBtn);

        _officeBtn = new AccentButton
        {
            Text = "办公防勒索",
            Location = new Point(250, 12),
            Size = new Size(110, 36)
        };
        _officeBtn.Click += () =>
        {
            AppState.Config.CurrentScene = SceneMode.Office;
            ConfigManager.Save(AppState.Config);
            RefreshData();
            MessageBoxHelper.Info("已切换为办公防勒索模式。");
        };
        modeCard.Controls.Add(_officeBtn);

        _perfBtn = new AccentButton
        {
            Text = "老旧流畅",
            Location = new Point(370, 12),
            Size = new Size(100, 36)
        };
        _perfBtn.Click += () =>
        {
            AppState.Config.CurrentScene = SceneMode.Performance;
            ConfigManager.Save(AppState.Config);
            RefreshData();
            MessageBoxHelper.Info("已切换为老旧流畅模式。");
        };
        modeCard.Controls.Add(_perfBtn);

        y += 80;

        // ===== 操作按钮区 =====
        CreateSectionTitle("快速操作", 0, y);
        y += 30;

        var actionCard = CreateCard(0, y, 720, 60);

        _cleanBtn = new AccentButton
        {
            Text = "一键净化",
            Location = new Point(16, 12),
            Size = new Size(120, 36)
        };
        _cleanBtn.Click += async () =>
        {
            if (_module == null) return;
            _cleanBtn.Enabled = false;
            var mode = AppState.Config.CurrentScene;
            MessageBoxHelper.Info($"开始执行{mode}模式净化，请稍候...");
            var result = await Task.Run(() => _module.ApplyCleanup(mode));
            _cleanBtn.Enabled = true;
            MessageBoxHelper.Info(
                $"净化完成！已净化 {result.CleanedItemIds.Count} 项，跳过 {result.SkippedItemIds.Count} 项。\n备份目录：{result.BackupDir}");
            RefreshData();
        };
        actionCard.Controls.Add(_cleanBtn);

        _restoreBtn = new AccentButton
        {
            Text = "一键还原",
            Location = new Point(146, 12),
            Size = new Size(120, 36)
        };
        _restoreBtn.Click += async () =>
        {
            if (_module == null) return;
            if (!MessageBoxHelper.Confirm("确定要还原所有净化设置吗？将恢复净化前的注册表和 Hosts 状态。"))
                return;
            _restoreBtn.Enabled = false;
            var ok = await Task.Run(() => _module.RestoreCleanup());
            _restoreBtn.Enabled = true;
            if (ok)
                MessageBoxHelper.Info("净化设置已成功还原！");
            else
                MessageBoxHelper.Warn("还原失败，可能未找到备份目录。");
            RefreshData();
        };
        actionCard.Controls.Add(_restoreBtn);

        y += 80;

        // ===== 净化项列表区 =====
        CreateSectionTitle("净化项列表", 0, y);
        y += 30;

        if (_module != null)
        {
            var items = _module.GetCleanupItems();
            var groups = items.GroupBy(i => i.Category).ToList();

            foreach (var group in groups)
            {
                // 分组标题
                var groupLabel = new Label
                {
                    Text = $"【{group.Key}】",
                    Font = Theme.HeaderFont,
                    ForeColor = Theme.Accent,
                    Location = new Point(0, y),
                    Size = new Size(720, 24),
                    BackColor = Color.Transparent
                };
                ScrollContent.Controls.Add(groupLabel);
                y += 28;

                foreach (var item in group)
                {
                    var itemCard = CreateCard(0, y, 720, 70);

                    var nameLabel = new Label
                    {
                        Text = item.Name,
                        Font = Theme.BodyFont,
                        ForeColor = item.Applicable ? Theme.TextPrimary : Theme.TextTertiary,
                        Location = new Point(16, 6),
                        Size = new Size(560, 20),
                        BackColor = Color.Transparent
                    };
                    itemCard.Controls.Add(nameLabel);

                    var descLabel = new Label
                    {
                        Text = item.Description,
                        Font = Theme.SmallFont,
                        ForeColor = Theme.TextTertiary,
                        Location = new Point(16, 28),
                        Size = new Size(560, 18),
                        BackColor = Color.Transparent
                    };
                    itemCard.Controls.Add(descLabel);

                    // 状态行：安装状态 + 净化状态
                    string stateText;
                    Color stateColor;
                    if (!item.Applicable)
                    {
                        stateText = "不适用";
                        stateColor = Theme.TextTertiary;
                    }
                    else if (!item.IsInstalled)
                    {
                        stateText = "未安装";
                        stateColor = Theme.TextTertiary;
                    }
                    else if (item.IsCleaned)
                    {
                        stateText = "已净化";
                        stateColor = Theme.Success;
                    }
                    else
                    {
                        stateText = "待净化";
                        stateColor = Theme.Warning;
                    }

                    var statusLabel = new Label
                    {
                        Text = stateText,
                        Font = Theme.SmallFont,
                        ForeColor = stateColor,
                        Location = new Point(600, 22),
                        Size = new Size(100, 20),
                        BackColor = Color.Transparent,
                        TextAlign = ContentAlignment.MiddleRight
                    };
                    itemCard.Controls.Add(statusLabel);

                    // 安装状态小标签
                    var installLabel = new Label
                    {
                        Text = item.IsInstalled ? "已安装" : "未安装",
                        Font = Theme.SmallFont,
                        ForeColor = item.IsInstalled ? Theme.TextSecondary : Theme.TextTertiary,
                        Location = new Point(16, 48),
                        Size = new Size(200, 16),
                        BackColor = Color.Transparent
                    };
                    itemCard.Controls.Add(installLabel);

                    y += 80;
                }

                y += 8;
            }
        }

        y += 20;
    }

    /// <summary>获取上次净化时间文本</summary>
    private string GetLastCleanedText()
    {
        var last = AppState.Config.Cleanup.LastCleaned;
        var scene = AppState.Config.CurrentScene;
        if (last.HasValue)
            return $"当前模式：{scene}    上次净化时间：{last:yyyy-MM-dd HH:mm:ss}";
        return $"当前模式：{scene}    尚未进行流氓软件净化";
    }

    public override void RefreshData()
    {
        if (_lastCleanedLabel != null)
            _lastCleanedLabel.Text = GetLastCleanedText();

        // 根据当前模式禁用对应按钮
        var currentScene = AppState.Config.CurrentScene;
        if (_homeBtn != null) _homeBtn.Enabled = currentScene != SceneMode.Home;
        if (_officeBtn != null) _officeBtn.Enabled = currentScene != SceneMode.Office;
        if (_perfBtn != null) _perfBtn.Enabled = currentScene != SceneMode.Performance;

        BuildContent();
    }
}
