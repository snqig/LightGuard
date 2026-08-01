using LightGuard.Core;
using LightGuard.Core.Interfaces;
using LightGuard.Native;
using Microsoft.Win32;

namespace LightGuard.Modules;

/// <summary>
/// 系统隐私加固模块
/// 一键关闭 Windows 遥测、广告 ID、后台应用、联网搜索、锁屏/开始菜单广告等
/// 支持家用/办公双模板策略，优化前自动备份注册表，支持一键还原
/// 所有注册表操作统一通过 RegistryHelper 完成
/// </summary>
public sealed class PrivacyModule : ModuleBase
{
    public PrivacyModule(AppState appState) : base(appState) { }

    public override string Id => "privacy";
    public override string DisplayName => "系统隐私加固";
    public override string Description => "一键关闭 Windows 遥测、广告 ID、后台应用、联网搜索与锁屏/开始菜单广告，支持家用/办公双模板与一键还原。";
    public override ModuleCategory Category => ModuleCategory.Privacy;
    public override bool RequiresAdmin => true;

    /// <summary>优化项分组：遥测诊断</summary>
    private const string GroupTelemetry = "遥测诊断";
    /// <summary>优化项分组：广告与推荐</summary>
    private const string GroupAds = "广告与推荐";
    /// <summary>优化项分组：隐私限制</summary>
    private const string GroupPrivacy = "隐私限制";

    /// <summary>
    /// 注册表优化操作定义
    /// 描述一项需要设置的注册表值及其期望值
    /// </summary>
    private sealed class RegistryOp
    {
        public string Name { get; set; } = "";
        public string Description { get; set; } = "";
        public string Group { get; set; } = "";
        public RegistryHive Hive { get; set; }
        public string Path { get; set; } = "";
        public string ValueName { get; set; } = "";
        public int ExpectedValue { get; set; }

        /// <summary>办公模式下的覆盖值（为空则与家用一致）</summary>
        public int? OfficeOverride { get; set; }

        /// <summary>家用模式是否适用</summary>
        public bool AppliesHome { get; set; } = true;

        /// <summary>办公模式是否适用</summary>
        public bool AppliesOffice { get; set; } = true;

        public bool Applies(PrivacyPolicyMode mode) =>
            mode == PrivacyPolicyMode.Home ? AppliesHome : AppliesOffice;

        public int ExpectedFor(PrivacyPolicyMode mode) =>
            mode == PrivacyPolicyMode.Office && OfficeOverride.HasValue ? OfficeOverride.Value : ExpectedValue;
    }

    /// <summary>所有隐私优化项定义</summary>
    private static readonly List<RegistryOp> Ops = BuildOps();

    private static List<RegistryOp> BuildOps()
    {
        var list = new List<RegistryOp>();

        // ===== 遥测诊断 =====
        list.Add(new RegistryOp
        {
            Name = "关闭 Windows 遥测",
            Description = "设置 AllowTelemetry=0。家用完全关闭；办公仅保留安全级（=1）以兼顾企业合规。",
            Group = GroupTelemetry,
            Hive = RegistryHive.LocalMachine,
            Path = @"SOFTWARE\Policies\Microsoft\Windows\DataCollection",
            ValueName = "AllowTelemetry",
            ExpectedValue = 0,
            OfficeOverride = 1
        });

        // ===== 广告与推荐 =====
        list.Add(new RegistryOp
        {
            Name = "关闭广告 ID",
            Description = "禁用 Windows 广告标识符，阻止应用基于 ID 跨应用投放广告。",
            Group = GroupAds,
            Hive = RegistryHive.LocalMachine,
            Path = @"SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo",
            ValueName = "Enabled",
            ExpectedValue = 0
        });

        // 锁屏广告：ContentDeliveryManager 下各 Rotating* 值
        list.Add(new RegistryOp
        {
            Name = "关闭锁屏背景广告",
            Description = "禁用锁屏 RotatingScreenOverlay 轮播广告。",
            Group = GroupAds,
            Hive = RegistryHive.CurrentUser,
            Path = @"SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager",
            ValueName = "RotatingScreenOverlayEnabled",
            ExpectedValue = 0
        });
        list.Add(new RegistryOp
        {
            Name = "关闭锁屏画报广告",
            Description = "禁用锁屏 RotatingLockScreenOverlay 画报。",
            Group = GroupAds,
            Hive = RegistryHive.CurrentUser,
            Path = @"SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager",
            ValueName = "RotatingLockScreenOverlayEnabled",
            ExpectedValue = 0
        });

        // 开始菜单推荐：SubscribedContent-* 系列
        list.Add(new RegistryOp
        {
            Name = "关闭开始菜单推荐",
            Description = "禁用 SubscribedContent-338388 开始菜单推荐。",
            Group = GroupAds,
            Hive = RegistryHive.CurrentUser,
            Path = @"SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager",
            ValueName = "SubscribedContent-338388Enabled",
            ExpectedValue = 0
        });
        list.Add(new RegistryOp
        {
            Name = "关闭提示建议",
            Description = "禁用 SubscribedContent-338389 系统提示建议。",
            Group = GroupAds,
            Hive = RegistryHive.CurrentUser,
            Path = @"SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager",
            ValueName = "SubscribedContent-338389Enabled",
            ExpectedValue = 0
        });
        list.Add(new RegistryOp
        {
            Name = "关闭锁屏建议",
            Description = "禁用 SubscribedContent-338393 锁屏建议。",
            Group = GroupAds,
            Hive = RegistryHive.CurrentUser,
            Path = @"SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager",
            ValueName = "SubscribedContent-338393Enabled",
            ExpectedValue = 0
        });
        list.Add(new RegistryOp
        {
            Name = "关闭欢迎体验",
            Description = "禁用 SubscribedContent-353694 欢迎体验提示。",
            Group = GroupAds,
            Hive = RegistryHive.CurrentUser,
            Path = @"SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager",
            ValueName = "SubscribedContent-353694Enabled",
            ExpectedValue = 0
        });
        list.Add(new RegistryOp
        {
            Name = "关闭设置建议",
            Description = "禁用 SubscribedContent-353696 设置页建议。",
            Group = GroupAds,
            Hive = RegistryHive.CurrentUser,
            Path = @"SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager",
            ValueName = "SubscribedContent-353696Enabled",
            ExpectedValue = 0
        });
        list.Add(new RegistryOp
        {
            Name = "关闭静默安装推荐",
            Description = "禁用 SilentInstalledAppsEnabled，阻止系统静默安装推荐应用。",
            Group = GroupAds,
            Hive = RegistryHive.CurrentUser,
            Path = @"SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager",
            ValueName = "SilentInstalledAppsEnabled",
            ExpectedValue = 0
        });
        list.Add(new RegistryOp
        {
            Name = "关闭系统面板建议",
            Description = "禁用 SystemPaneSuggestionsEnabled 系统面板建议。",
            Group = GroupAds,
            Hive = RegistryHive.CurrentUser,
            Path = @"SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager",
            ValueName = "SystemPaneSuggestionsEnabled",
            ExpectedValue = 0
        });

        // 搜索联网
        list.Add(new RegistryOp
        {
            Name = "关闭搜索联网",
            Description = "设置 BingSearchEnabled=0，阻止开始菜单搜索联网。",
            Group = GroupAds,
            Hive = RegistryHive.CurrentUser,
            Path = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Search",
            ValueName = "BingSearchEnabled",
            ExpectedValue = 0
        });
        list.Add(new RegistryOp
        {
            Name = "关闭 Cortana 联网授权",
            Description = "设置 CortanaConsent=0，关闭 Cortana 联网授权。",
            Group = GroupAds,
            Hive = RegistryHive.CurrentUser,
            Path = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Search",
            ValueName = "CortanaConsent",
            ExpectedValue = 0
        });

        // ===== 隐私限制 =====
        list.Add(new RegistryOp
        {
            Name = "关闭后台应用",
            Description = "设置 GlobalUserDisabled=1，禁用 UWP 后台应用。家用关闭；办公保留以兼容企业应用。",
            Group = GroupPrivacy,
            Hive = RegistryHive.CurrentUser,
            Path = @"Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications",
            ValueName = "GlobalUserDisabled",
            ExpectedValue = 1,
            AppliesOffice = false // 办公模式保留后台应用
        });

        return list;
    }

    /// <summary>UI 展示用的优化项</summary>
    public sealed class OptimizationItem
    {
        public string Name { get; set; } = "";
        public string Description { get; set; } = "";
        public string Category { get; set; } = "";
        public string Hive { get; set; } = "";
        public string Path { get; set; } = "";
        public bool IsOptimized { get; set; }
        public PrivacyPolicyMode ApplicableMode { get; set; }
    }

    protected override Task OnInitializeAsync()
    {
        // 预确认备份目录可用，并加载当前策略模式
        _ = ConfigManager.GetBackupDir();
        return Task.CompletedTask;
    }

    protected override Task OnEnableAsync()
    {
        // 模块启用即为就绪，实际优化由用户显式触发 ApplyOptimization
        return Task.CompletedTask;
    }

    protected override Task OnDisableAsync()
    {
        // 禁用模块不会自动还原，避免误操作；用户可显式调用 RestoreOptimization
        return Task.CompletedTask;
    }

    /// <summary>
    /// 一键应用隐私优化
    /// 优化前自动备份注册表到 ConfigManager.GetBackupDir()
    /// </summary>
    /// <returns>是否全部成功</returns>
    public bool ApplyOptimization()
    {
        try
        {
            var mode = AppState.Config.Privacy.PolicyMode;

            // 1. 优化前备份相关注册表项
            var backupDir = BackupRegistry();

            // 2. 逐项应用（通过 RegistryHelper 写入）
            foreach (var op in Ops)
            {
                if (!op.Applies(mode)) continue;
                RegistryHelper.SetValue(op.Hive, op.Path, op.ValueName, op.ExpectedFor(mode));
            }

            // 3. 记录优化时间与备份路径
            AppState.Config.Privacy.LastOptimized = DateTime.Now;
            AppState.Config.Privacy.BackupPath = backupDir;
            ConfigManager.Save(AppState.Config);

            ErrorReporter.Log($"隐私加固已应用（模式={mode}），备份目录={backupDir}");
            return true;
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, "隐私加固应用失败");
            return false;
        }
    }

    /// <summary>
    /// 从最近一次备份一键还原注册表
    /// </summary>
    /// <returns>是否全部还原成功</returns>
    public bool RestoreOptimization()
    {
        try
        {
            var dir = AppState.Config.Privacy.BackupPath;
            if (string.IsNullOrEmpty(dir) || !Directory.Exists(dir))
            {
                ErrorReporter.Log("隐私加固还原失败：未找到备份目录", "WARN");
                return false;
            }

            bool allOk = true;
            foreach (var regFile in Directory.GetFiles(dir, "*.reg"))
            {
                if (!RegistryHelper.RestoreRegistryKey(regFile))
                    allOk = false;
            }

            // 清除优化记录
            AppState.Config.Privacy.LastOptimized = null;
            ConfigManager.Save(AppState.Config);

            ErrorReporter.Log($"隐私加固已还原，备份目录={dir}");
            return allOk;
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, "隐私加固还原失败");
            return false;
        }
    }

    /// <summary>
    /// 获取优化项列表供 UI 显示（含当前是否已优化状态）
    /// </summary>
    public List<OptimizationItem> GetOptimizationDetails()
    {
        var mode = AppState.Config.Privacy.PolicyMode;
        var list = new List<OptimizationItem>();

        foreach (var op in Ops)
        {
            if (!op.Applies(mode)) continue;

            // 通过 RegistryHelper 读取当前值判断是否已优化
            var current = RegistryHelper.GetDWord(op.Hive, op.Path, op.ValueName, -1);
            list.Add(new OptimizationItem
            {
                Name = op.Name,
                Description = op.Description,
                Category = op.Group,
                Hive = op.Hive.ToString(),
                Path = op.Path,
                IsOptimized = current == op.ExpectedFor(mode),
                ApplicableMode = mode
            });
        }

        return list;
    }

    /// <summary>切换策略模板（家用/办公）</summary>
    public void SetPolicyMode(PrivacyPolicyMode mode)
    {
        AppState.Config.Privacy.PolicyMode = mode;
        ConfigManager.Save(AppState.Config);
    }

    /// <summary>
    /// 备份所有涉及的注册表项到带时间戳的子目录
    /// </summary>
    private string BackupRegistry()
    {
        var baseDir = ConfigManager.GetBackupDir();
        var dir = Path.Combine(baseDir, $"privacy_{DateTime.Now:yyyyMMdd_HHmmss}");
        Directory.CreateDirectory(dir);

        // 按 (Hive, Path) 去重备份
        foreach (var g in Ops.GroupBy(o => (o.Hive, o.Path)))
        {
            RegistryHelper.BackupRegistryKey(g.Key.Hive, g.Key.Path, dir);
        }

        File.WriteAllText(Path.Combine(dir, "manifest.txt"),
            $"Privacy backup @ {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
        return dir;
    }

    protected override string GetStatusSummary()
    {
        var cfg = AppState.Config.Privacy;
        if (cfg.LastOptimized.HasValue)
            return $"已加固（{cfg.PolicyMode}）-{cfg.LastOptimized:yyyy-MM-dd HH:mm}";
        return "未加固";
    }
}
