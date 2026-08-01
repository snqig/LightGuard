using LightGuard.Core;
using LightGuard.Modules;
using LightGuard.UI.Controls;

namespace LightGuard.UI.Pages;

/// <summary>
/// 系统隐私加固页面
/// 显示隐私优化项列表，支持一键优化/还原，家用/办公模式切换
/// </summary>
public class PrivacyPage : Page
{
    private PrivacyModule? _module;
    private Label? _lastOptimizedLabel;
    private AccentButton? _optimizeBtn;
    private AccentButton? _restoreBtn;
    private AccentButton? _homeModeBtn;
    private AccentButton? _officeModeBtn;

    public PrivacyPage(AppState appState) : base(appState, "系统隐私加固", "一键关闭 Windows 遥测、广告 ID、后台应用与锁屏广告")
    {
    }

    public override void OnShown()
    {
        _module = AppState.Modules.GetModule("privacy") as PrivacyModule;
        BuildContent();
    }

    /// <summary>构建页面内容</summary>
    private void BuildContent()
    {
        ScrollContent.Controls.Clear();

        int y = 0;

        // ===== 状态信息区 =====
        CreateSectionTitle("优化状态", 0, y);
        y += 30;

        var statusCard = CreateCard(0, y, ContentWidth, 50);
        _lastOptimizedLabel = new Label
        {
            Text = GetLastOptimizedText(),
            Font = Theme.BodyFont,
            ForeColor = Theme.TextSecondary,
            Location = new Point(16, 14),
            Size = new Size(400, 22),
            BackColor = Color.Transparent
        };
        statusCard.Controls.Add(_lastOptimizedLabel);
        y += 70;

        // ===== 策略模式切换 =====
        CreateSectionTitle("策略模式", 0, y);
        y += 30;

        var modeCard = CreateCard(0, y, ContentWidth, 60);
        var modeLabel = new Label
        {
            Text = "选择适用模板：",
            Font = Theme.BodyFont,
            ForeColor = Theme.TextSecondary,
            Location = new Point(16, 16),
            Size = new Size(120, 28),
            BackColor = Color.Transparent
        };
        modeCard.Controls.Add(modeLabel);

        _homeModeBtn = new AccentButton
        {
            Text = "家用模式",
            Location = new Point(140, 12),
            Size = new Size(100, 36)
        };
        _homeModeBtn.Click += () =>
        {
            _module?.SetPolicyMode(PrivacyPolicyMode.Home);
            RefreshData();
            MessageBoxHelper.Info("已切换为家用模式，已重新加载优化项。");
        };
        modeCard.Controls.Add(_homeModeBtn);

        _officeModeBtn = new AccentButton
        {
            Text = "办公模式",
            Location = new Point(250, 12),
            Size = new Size(100, 36)
        };
        _officeModeBtn.Click += () =>
        {
            _module?.SetPolicyMode(PrivacyPolicyMode.Office);
            RefreshData();
            MessageBoxHelper.Info("已切换为办公模式，已重新加载优化项。");
        };
        modeCard.Controls.Add(_officeModeBtn);

        y += 80;

        // ===== 操作按钮区 =====
        CreateSectionTitle("快速操作", 0, y);
        y += 30;

        var actionCard = CreateCard(0, y, ContentWidth, 60);

        _optimizeBtn = new AccentButton
        {
            Text = "一键优化",
            Location = new Point(16, 12),
            Size = new Size(120, 36)
        };
        _optimizeBtn.Click += async () =>
        {
            if (_module == null) return;
            _optimizeBtn.Enabled = false;
            MessageBoxHelper.Info("开始应用隐私优化，请稍候...");
            var ok = await Task.Run(() => _module.ApplyOptimization());
            _optimizeBtn.Enabled = true;
            if (ok)
                MessageBoxHelper.Info("隐私优化已成功应用！优化前已自动备份注册表。");
            else
                MessageBoxHelper.Warn("隐私优化应用失败，请以管理员身份运行或查看日志。");
            RefreshData();
        };
        actionCard.Controls.Add(_optimizeBtn);

        _restoreBtn = new AccentButton
        {
            Text = "一键还原",
            Location = new Point(146, 12),
            Size = new Size(120, 36)
        };
        _restoreBtn.Click += async () =>
        {
            if (_module == null) return;
            if (!MessageBoxHelper.Confirm("确定要还原隐私优化设置吗？将恢复优化前的注册表状态。"))
                return;
            _restoreBtn.Enabled = false;
            var ok = await Task.Run(() => _module.RestoreOptimization());
            _restoreBtn.Enabled = true;
            if (ok)
                MessageBoxHelper.Info("隐私优化已成功还原！");
            else
                MessageBoxHelper.Warn("还原失败，可能未找到备份目录。");
            RefreshData();
        };
        actionCard.Controls.Add(_restoreBtn);

        y += 80;

        // ===== 优化项列表区 =====
        CreateSectionTitle("隐私优化项", 0, y);
        y += 30;

        if (_module != null)
        {
            var items = _module.GetOptimizationDetails();
            // 按分组归类
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
                    Size = new Size(ContentWidth, 24),
                    BackColor = Color.Transparent
                };
                ScrollContent.Controls.Add(groupLabel);
                y += 28;

                // 分组下每一项
                foreach (var item in group)
                {
                    var itemCard = CreateCard(0, y, ContentWidth, 56);

                    var nameLabel = new Label
                    {
                        Text = item.Name,
                        Font = Theme.BodyFont,
                        ForeColor = Theme.TextPrimary,
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

                    // 状态标签
                    var statusLabel = new Label
                    {
                        Text = item.IsOptimized ? "已优化" : "未优化",
                        Font = Theme.SmallFont,
                        ForeColor = item.IsOptimized ? Theme.Success : Theme.Warning,
                        Location = new Point(620, 18),
                        Size = new Size(80, 20),
                        BackColor = Color.Transparent,
                        TextAlign = ContentAlignment.MiddleRight
                    };
                    itemCard.Controls.Add(statusLabel);

                    y += 66;
                }

                y += 8;
            }
        }

        // 底部留白
        y += 20;
    }

    /// <summary>获取上次优化时间文本</summary>
    private string GetLastOptimizedText()
    {
        var last = AppState.Config.Privacy.LastOptimized;
        var mode = AppState.Config.Privacy.PolicyMode;
        if (last.HasValue)
            return $"当前模式：{mode}    上次优化时间：{last:yyyy-MM-dd HH:mm:ss}";
        return $"当前模式：{mode}    尚未进行隐私优化";
    }

    public override void RefreshData()
    {
        if (_lastOptimizedLabel != null)
            _lastOptimizedLabel.Text = GetLastOptimizedText();

        // 高亮当前模式按钮
        var currentMode = AppState.Config.Privacy.PolicyMode;
        if (_homeModeBtn != null)
            _homeModeBtn.Enabled = currentMode != PrivacyPolicyMode.Home;
        if (_officeModeBtn != null)
            _officeModeBtn.Enabled = currentMode != PrivacyPolicyMode.Office;

        // 重建列表以刷新状态
        BuildContent();
    }
}
