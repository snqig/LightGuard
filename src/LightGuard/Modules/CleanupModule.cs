using LightGuard.Core;
using LightGuard.Core.Interfaces;
using LightGuard.Native;
using Microsoft.Win32;

namespace LightGuard.Modules;

/// <summary>
/// 流氓软件一键净化模块
/// 净化 WPS / 360浏览器 / Edge / 2345 / 压缩软件 / QQ·微信 等弹窗广告与后台流氓行为
/// 支持家用纯净 / 办公防勒索 / 老旧流畅三模式，优化前备份注册表+Hosts+服务，支持单项/全局还原
/// </summary>
public sealed class CleanupModule : ModuleBase
{
    public CleanupModule(AppState appState) : base(appState) { }

    public override string Id => "cleanup";
    public override string DisplayName => "流氓软件净化";
    public override string Description => "一键净化 WPS、360、Edge、2345、压缩软件、QQ/微信等弹窗广告与后台流氓行为，支持三模式与一键还原。";
    public override ModuleCategory Category => ModuleCategory.Cleanup;
    public override bool RequiresAdmin => true;

    // ===== 分类常量 =====
    private const string CatWps = "WPS Office";
    private const string Cat360 = "360浏览器";
    private const string CatEdge = "Microsoft Edge";
    private const string Cat2345 = "2345";
    private const string CatZip = "压缩软件";
    private const string CatIm = "即时通讯";
    private const string CatSys = "系统全局";

    /// <summary>净化动作定义</summary>
    private sealed class CleanupAction
    {
        public string Id { get; set; } = "";
        public string Name { get; set; } = "";
        public string Description { get; set; } = "";
        public string Category { get; set; } = "";

        /// <summary>软件检测关键字（null 表示无需检测，始终适用）</summary>
        public string? SoftwareKeyword { get; set; }

        /// <summary>适用的场景模式</summary>
        public SceneMode[] ApplicableModes { get; set; } = Array.Empty<SceneMode>();

        public bool Applies(SceneMode mode) => Array.IndexOf(ApplicableModes, mode) >= 0;
    }

    /// <summary>所有净化动作</summary>
    private static readonly CleanupAction[] Actions = BuildActions();

    private static CleanupAction[] BuildActions()
    {
        // 场景模式集合
        var all = new[] { SceneMode.Home, SceneMode.Office, SceneMode.Performance };
        var noHome = new[] { SceneMode.Office, SceneMode.Performance };
        var officeOnly = new[] { SceneMode.Office };
        var perfOnly = new[] { SceneMode.Performance };

        return new[]
        {
            // ===== WPS Office =====
            new CleanupAction { Id = "wps_ad",      Name = "WPS广告弹窗净化",            Description = "关闭WPS启动页/文档页广告弹窗", Category = CatWps, SoftwareKeyword = "WPS", ApplicableModes = all },
            new CleanupAction { Id = "wps_cloud",   Name = "禁用WPS云推送",              Description = "关闭WPS云文档自动同步与推送通知", Category = CatWps, SoftwareKeyword = "WPS", ApplicableModes = all },
            new CleanupAction { Id = "wps_update",  Name = "禁用WPS自动更新",            Description = "关闭WPS在线自动更新检查", Category = CatWps, SoftwareKeyword = "WPS", ApplicableModes = noHome },
            new CleanupAction { Id = "wps_data",    Name = "禁用WPS数据收集",            Description = "关闭WPS用户体验数据上报", Category = CatWps, SoftwareKeyword = "WPS", ApplicableModes = all },
            new CleanupAction { Id = "wps_ransom",  Name = "禁用WPS云盘同步（防勒索）",   Description = "办公模式关闭云盘同步，防止勒索病毒加密云端文档", Category = CatWps, SoftwareKeyword = "WPS", ApplicableModes = officeOnly },

            // ===== 360浏览器 =====
            new CleanupAction { Id = "b360_hotpic", Name = "关闭360热点画报",            Description = "禁用360浏览器热点画报弹窗", Category = Cat360, SoftwareKeyword = "360", ApplicableModes = all },
            new CleanupAction { Id = "b360_bgad",   Name = "禁用360后台广告进程",         Description = "阻止360后台静默拉起广告模块", Category = Cat360, SoftwareKeyword = "360", ApplicableModes = all },
            new CleanupAction { Id = "b360_update", Name = "禁用360静默更新",            Description = "关闭360浏览器静默升级", Category = Cat360, SoftwareKeyword = "360", ApplicableModes = noHome },

            // ===== Microsoft Edge =====
            new CleanupAction { Id = "edge_bg",     Name = "禁用Edge后台常驻",           Description = "关闭Edge后台运行模式(BackgroundModeEnabled=0)", Category = CatEdge, SoftwareKeyword = null, ApplicableModes = all },
            new CleanupAction { Id = "edge_preload",Name = "禁用Edge预加载",             Description = "关闭Edge启动预加载以减少内存占用", Category = CatEdge, SoftwareKeyword = null, ApplicableModes = all },
            new CleanupAction { Id = "edge_sleep",  Name = "开启Edge标签休眠",           Description = "启用睡眠标签节省资源(SleepingTabsEnabled=1)", Category = CatEdge, SoftwareKeyword = null, ApplicableModes = all },
            new CleanupAction { Id = "edge_update", Name = "禁用Edge自动更新服务",        Description = "停止并禁用MicrosoftEdgeUpdateService", Category = CatEdge, SoftwareKeyword = null, ApplicableModes = all },

            // ===== 2345 =====
            new CleanupAction { Id = "s2345_ad",    Name = "关闭2345弹窗广告",           Description = "禁用2345系列软件弹窗广告", Category = Cat2345, SoftwareKeyword = "2345", ApplicableModes = all },

            // ===== 压缩软件 =====
            new CleanupAction { Id = "zip_ad",      Name = "关闭压缩软件广告",           Description = "关闭Bandizip/好压等压缩软件广告", Category = CatZip, SoftwareKeyword = null, ApplicableModes = all },

            // ===== 即时通讯 =====
            new CleanupAction { Id = "qq_ad",       Name = "关闭QQ弹窗广告",             Description = "禁用QQ迷你首页/弹窗广告", Category = CatIm, SoftwareKeyword = "QQ", ApplicableModes = all },
            new CleanupAction { Id = "wx_ad",       Name = "关闭微信弹窗广告",           Description = "禁用微信辅助弹窗广告", Category = CatIm, SoftwareKeyword = "WeChat", ApplicableModes = all },

            // ===== 系统全局 =====
            new CleanupAction { Id = "sys_bundle",  Name = "禁止静默捆绑安装",           Description = "禁止系统静默安装推荐/捆绑应用", Category = CatSys, SoftwareKeyword = null, ApplicableModes = all },
            new CleanupAction { Id = "sys_autostart",Name = "清理开机自启动项",          Description = "禁用流氓软件开机自启项", Category = CatSys, SoftwareKeyword = null, ApplicableModes = all },
            new CleanupAction { Id = "sys_hosts",   Name = "Hosts全局广告屏蔽",          Description = "通过Hosts屏蔽常见广告/追踪域名", Category = CatSys, SoftwareKeyword = null, ApplicableModes = all },
            new CleanupAction { Id = "sys_perf",    Name = "极致精简后台服务",           Description = "老旧流畅模式禁用更多非必要后台服务", Category = CatSys, SoftwareKeyword = null, ApplicableModes = perfOnly },
        };
    }

    /// <summary>净化结果</summary>
    public sealed class CleanupResult
    {
        public string BackupDir { get; set; } = "";
        /// <summary>已成功净化的项标识</summary>
        public List<string> CleanedItemIds { get; set; } = new();
        /// <summary>跳过的项标识（软件未安装等）</summary>
        public List<string> SkippedItemIds { get; set; } = new();
    }

    /// <summary>UI 展示用的净化项</summary>
    public sealed class CleanupItem
    {
        public string Id { get; set; } = "";
        public string Name { get; set; } = "";
        public string Description { get; set; } = "";
        public string Category { get; set; } = "";
        /// <summary>对应软件是否已安装</summary>
        public bool IsInstalled { get; set; }
        /// <summary>是否已净化</summary>
        public bool IsCleaned { get; set; }
        /// <summary>在当前场景模式下是否适用</summary>
        public bool Applicable { get; set; }
    }

    protected override Task OnInitializeAsync()
    {
        _ = ConfigManager.GetBackupDir();
        return Task.CompletedTask;
    }

    protected override Task OnEnableAsync() => Task.CompletedTask;

    protected override Task OnDisableAsync() => Task.CompletedTask;

    /// <summary>
    /// 按场景模式一键净化
    /// 优化前备份注册表 + Hosts + 服务配置
    /// </summary>
    public CleanupResult ApplyCleanup(SceneMode mode)
    {
        var result = new CleanupResult();
        try
        {
            // 1. 备份注册表 + Hosts + 服务配置
            result.BackupDir = CreateBackup(mode);

            // 2. 逐项净化
            foreach (var action in Actions)
            {
                if (!action.Applies(mode)) continue;

                // 检测软件是否安装（关键字为空则视为始终安装）
                bool installed = action.SoftwareKeyword == null
                                 || IsSoftwareInstalledFlexible(action.SoftwareKeyword);
                if (!installed)
                {
                    result.SkippedItemIds.Add(action.Id);
                    continue;
                }

                if (ApplyAction(action.Id))
                    result.CleanedItemIds.Add(action.Id);
                else
                    result.SkippedItemIds.Add(action.Id);
            }

            // 3. 记录净化时间与备份路径
            AppState.Config.Cleanup.LastCleaned = DateTime.Now;
            AppState.Config.Cleanup.BackupPath = result.BackupDir;
            ConfigManager.Save(AppState.Config);

            ErrorReporter.Log($"流氓软件净化完成（模式={mode}），已净化 {result.CleanedItemIds.Count} 项，备份={result.BackupDir}");
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, "流氓软件净化失败");
        }
        return result;
    }

    /// <summary>从最近一次备份全局一键还原</summary>
    public bool RestoreCleanup()
    {
        try
        {
            var dir = AppState.Config.Cleanup.BackupPath;
            if (string.IsNullOrEmpty(dir) || !Directory.Exists(dir))
            {
                ErrorReporter.Log("净化还原失败：未找到备份目录", "WARN");
                return false;
            }

            bool ok = true;
            // 还原所有注册表备份
            foreach (var regFile in Directory.GetFiles(dir, "*.reg"))
            {
                if (!RegistryHelper.RestoreRegistryKey(regFile))
                    ok = false;
            }

            // 还原 Hosts 文件
            var hostsBak = Directory.GetFiles(dir, "hosts_*.bak").FirstOrDefault();
            if (hostsBak != null)
                HostsHelper.Restore(hostsBak);

            AppState.Config.Cleanup.LastCleaned = null;
            ConfigManager.Save(AppState.Config);

            ErrorReporter.Log($"流氓软件净化已全局还原，备份目录={dir}");
            return ok;
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, "净化全局还原失败");
            return false;
        }
    }

    /// <summary>单项还原（按项标识）</summary>
    public bool RestoreItem(string itemId)
    {
        try
        {
            var dir = AppState.Config.Cleanup.BackupPath;
            if (string.IsNullOrEmpty(dir) || !Directory.Exists(dir)) return false;

            // Hosts 单独还原
            if (itemId == "sys_hosts")
            {
                var hostsBak = Directory.GetFiles(dir, "hosts_*.bak").FirstOrDefault();
                return hostsBak != null && HostsHelper.Restore(hostsBak);
            }

            // 性能服务还原：重新启用相关服务
            if (itemId == "sys_perf")
            {
                ServiceHelper.EnableService("DiagTrack", "auto");
                ServiceHelper.EnableService("dmwappushservice", "auto");
                return true;
            }

            var keyword = GetRestoreKeyword(itemId);
            if (keyword == null) return false;

            bool ok = false;
            foreach (var f in Directory.GetFiles(dir, "*.reg"))
            {
                if (f.IndexOf(keyword, StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    if (RegistryHelper.RestoreRegistryKey(f))
                        ok = true;
                }
            }
            return ok;
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, $"净化单项还原失败：{itemId}");
            return false;
        }
    }

    /// <summary>获取净化项列表供 UI 显示</summary>
    public List<CleanupItem> GetCleanupItems()
    {
        var mode = AppState.Config.CurrentScene;
        var list = new List<CleanupItem>();

        foreach (var a in Actions)
        {
            bool installed = a.SoftwareKeyword == null
                             || IsSoftwareInstalledFlexible(a.SoftwareKeyword);
            list.Add(new CleanupItem
            {
                Id = a.Id,
                Name = a.Name,
                Description = a.Description,
                Category = a.Category,
                IsInstalled = installed,
                IsCleaned = CheckCleaned(a.Id),
                Applicable = a.Applies(mode)
            });
        }
        return list;
    }

    #region 单项净化逻辑

    private bool ApplyAction(string id)
    {
        try
        {
            switch (id)
            {
                case "wps_ad":      CleanWpsAd();      return true;
                case "wps_cloud":   CleanWpsCloud();   return true;
                case "wps_update":  CleanWpsUpdate();  return true;
                case "wps_data":    CleanWpsData();    return true;
                case "wps_ransom":  CleanWpsRansom();  return true;

                case "b360_hotpic": Clean360HotPic();  return true;
                case "b360_bgad":   Clean360BgAd();    return true;
                case "b360_update": Clean360Update();  return true;

                case "edge_bg":      SetPolicyEdge("BackgroundModeEnabled", 0); return true;
                case "edge_preload": SetPolicyEdge("StartupBoostEnabled", 0);   return true;
                case "edge_sleep":   SetPolicyEdge("SleepingTabsEnabled", 1);   return true;
                case "edge_update":  DisableEdgeUpdateService();                return true;

                case "s2345_ad": Clean2345();        return true;
                case "zip_ad":   CleanCompressors(); return true;
                case "qq_ad":    CleanQq();          return true;
                case "wx_ad":    CleanWeChat();      return true;

                case "sys_bundle":   DisableBundleInstall();                return true;
                case "sys_autostart": CleanAutoStart();                     return true;
                case "sys_hosts":    HostsHelper.AddAdBlockRules(HostsHelper.CommonAdDomains); return true;
                case "sys_perf":     DisableExtraServices();                return true;

                default: return false;
            }
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, $"净化项执行失败：{id}");
            return false;
        }
    }

    // ===== WPS Office =====
    private static IEnumerable<string> WpsVersions()
    {
        try
        {
            using var k = Registry.CurrentUser.OpenSubKey(@"Software\Kingsoft\Office");
            return k?.GetSubKeyNames() ?? Array.Empty<string>();
        }
        catch { return Array.Empty<string>(); }
    }

    private static void CleanWpsAd()
    {
        foreach (var ver in WpsVersions())
        {
            SetHkcu($@"Software\Kingsoft\Office\{ver}\home\oem", "AdvertiseType", 0);
            SetHkcu($@"Software\Kingsoft\Office\{ver}\home\oem", "oemminews", 0);
            SetHkcu($@"Software\Kingsoft\Office\{ver}\Plugins\news", "AdIndex", 0);
        }
    }

    private static void CleanWpsCloud()
    {
        foreach (var ver in WpsVersions())
        {
            SetHkcu($@"Software\Kingsoft\Office\{ver}\Cloud", "EnableCloud", 0);
            SetHkcu($@"Software\Kingsoft\Office\{ver}\common\cloud", "AutoSync", 0);
        }
    }

    private static void CleanWpsUpdate()
    {
        foreach (var ver in WpsVersions())
        {
            SetHkcu($@"Software\Kingsoft\Office\{ver}\Update", "AutoUpdate", 0);
            SetHkcu($@"Software\Kingsoft\Office\{ver}\Update", "CheckUpdate", 0);
        }
    }

    private static void CleanWpsData()
    {
        foreach (var ver in WpsVersions())
        {
            SetHkcu($@"Software\Kingsoft\Office\{ver}\DataCollection", "Enable", 0);
            SetHkcu($@"Software\Kingsoft\Office\{ver}\common\feedback", "EnableFeedback", 0);
        }
    }

    private static void CleanWpsRansom()
    {
        // 办公防勒索：彻底关闭云盘同步，避免勒索病毒加密云端文档
        foreach (var ver in WpsVersions())
        {
            SetHkcu($@"Software\Kingsoft\Office\{ver}\Cloud", "EnableCloudSync", 0);
            SetHkcu($@"Software\Kingsoft\Office\{ver}\Cloud\Drive", "AutoStart", 0);
        }
    }

    // ===== 360浏览器 =====
    private static void Clean360HotPic()
    {
        SetHkcu(@"Software\360se6\HotPic", "Enable", 0);
        SetHkcu(@"Software\360Chrome\HotPic", "Enable", 0);
        SetHkcu(@"Software\360se6\Chrome\HotPic", "Enable", 0);
    }

    private static void Clean360BgAd()
    {
        SetHkcu(@"Software\360se6\BackgroundAd", "Enable", 0);
        SetHkcu(@"Software\360Chrome\Notify", "Enable", 0);
        SetHkcu(@"Software\360se6\Notify", "Enable", 0);
    }

    private static void Clean360Update()
    {
        SetHkcu(@"Software\360se6\Update", "AutoUpdate", 0);
        SetHkcu(@"Software\360Chrome\Update", "AutoUpdate", 0);
    }

    // ===== Microsoft Edge =====
    private static void DisableEdgeUpdateService()
    {
        // 优先禁用指定服务名，失败则尝试常见变体
        var names = new[] { "MicrosoftEdgeUpdateService", "MicrosoftEdgeUpdate", "edgeupdate" };
        foreach (var n in names)
        {
            if (ServiceHelper.ServiceExists(n))
                ServiceHelper.DisableService(n);
        }
    }

    // ===== 2345 =====
    private static void Clean2345()
    {
        SetHkcu(@"Software\2345\Explorer", "PopAd", 0);
        SetHkcu(@"Software\2345\Ad", "Enable", 0);
        SetHkcu(@"Software\2345Soft\Ad", "Enable", 0);
        SetHkcu(@"Software\2345\Notify", "Enable", 0);
    }

    // ===== 压缩软件 =====
    private static void CleanCompressors()
    {
        // Bandizip
        if (RegistryHelper.IsSoftwareInstalled("Bandizip"))
            SetHkcu(@"Software\Bandizip\config", "ShowAd", 0);
        // 好压 HaoZip
        if (RegistryHelper.IsSoftwareInstalled("HaoZip") || RegistryHelper.IsSoftwareInstalled("好压"))
            SetHkcu(@"Software\HaoZip\config", "ShowAd", 0);
        // 7-Zip 无广告，跳过
    }

    // ===== 即时通讯 =====
    private static void CleanQq()
    {
        SetHkcu(@"Software\Tencent\QQ\Ad", "Enable", 0);
        SetHkcu(@"Software\Tencent\QQ\MiniNews", "Enable", 0);
        SetHkcu(@"Software\Tencent\QQ", "Advertisement", 0);
    }

    private static void CleanWeChat()
    {
        SetHkcu(@"Software\Tencent\WeChat\Ad", "Enable", 0);
        SetHkcu(@"Software\Tencent\WeChat", "ShowAd", 0);
    }

    // ===== 系统全局 =====
    private static void DisableBundleInstall()
    {
        // 禁止系统静默安装推荐应用
        SetHkcu(@"SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager", "SilentInstalledAppsEnabled", 0);
        // 禁止通过应用安装程序静默安装
        SetHklm(@"SOFTWARE\Microsoft\Windows\CurrentVersion\AppInstall", "AutoInstall", 0);
    }

    private static void CleanAutoStart()
    {
        // 保守策略：仅清理名称或路径匹配流氓关键字的 Run 自启项
        var junkKeywords = new[] { "360", "2345", "wps", "minisite", "adcache", "popad", "huanews", "knews" };
        CleanRunKey(Registry.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\Run", junkKeywords);
        CleanRunKey(Registry.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\Run", junkKeywords);
    }

    private static void CleanRunKey(RegistryKey root, string path, string[] keywords)
    {
        try
        {
            using var k = root.OpenSubKey(path, RegistryKeyPermissionCheck.ReadWriteSubTree);
            if (k == null) return;
            foreach (var name in k.GetValueNames())
            {
                var val = k.GetValue(name)?.ToString() ?? "";
                bool hit = keywords.Any(kw =>
                    name.IndexOf(kw, StringComparison.OrdinalIgnoreCase) >= 0 ||
                    val.IndexOf(kw, StringComparison.OrdinalIgnoreCase) >= 0);
                if (hit)
                {
                    try { k.DeleteValue(name, false); } catch { }
                }
            }
        }
        catch { }
    }

    private static void DisableExtraServices()
    {
        // 老旧流畅模式：禁用非必要资源占用服务
        var services = new[] { "DiagTrack", "dmwappushservice" };
        foreach (var s in services)
        {
            if (ServiceHelper.ServiceExists(s))
                ServiceHelper.DisableService(s);
        }
    }

    #endregion

    #region 状态检测

    /// <summary>检测单项是否已净化（best-effort）</summary>
    private bool CheckCleaned(string id)
    {
        try
        {
            return id switch
            {
                "edge_bg"      => GetHklm(@"SOFTWARE\Policies\Microsoft\Edge", "BackgroundModeEnabled") == 0,
                "edge_preload" => GetHklm(@"SOFTWARE\Policies\Microsoft\Edge", "StartupBoostEnabled") == 0,
                "edge_sleep"   => GetHklm(@"SOFTWARE\Policies\Microsoft\Edge", "SleepingTabsEnabled") == 1,
                "edge_update"  => !ServiceHelper.ServiceExists("MicrosoftEdgeUpdateService")
                                   && !ServiceHelper.ServiceExists("MicrosoftEdgeUpdate"),
                "sys_bundle"   => GetHkcu(@"SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager",
                                          "SilentInstalledAppsEnabled") == 0,
                "sys_hosts"    => HostsHelper.GetBlockedDomains().Count > 0,
                _ => false
            };
        }
        catch { return false; }
    }

    /// <summary>单项还原时，匹配备份文件的关键字</summary>
    private static string? GetRestoreKeyword(string itemId) => itemId switch
    {
        "wps_ad" or "wps_cloud" or "wps_update" or "wps_data" or "wps_ransom" => "Kingsoft",
        "b360_hotpic" or "b360_bgad" or "b360_update" => "360",
        "edge_bg" or "edge_preload" or "edge_sleep" or "edge_update" => "Edge",
        "s2345_ad" => "2345",
        "zip_ad"   => "Bandizip", // best-effort
        "qq_ad" or "wx_ad" => "Tencent",
        "sys_bundle" => "ContentDeliveryManager",
        "sys_autostart" => "Run",
        _ => null
    };

    #endregion

    #region 注册表读写辅助（Microsoft.Win32）

    private static void SetHkcu(string path, string name, object value, RegistryValueKind kind = RegistryValueKind.DWord)
    {
        try
        {
            using var k = Registry.CurrentUser.CreateSubKey(path, RegistryKeyPermissionCheck.ReadWriteSubTree);
            k?.SetValue(name, value, kind);
        }
        catch { }
    }

    private static int? GetHkcu(string path, string name)
    {
        try
        {
            using var k = Registry.CurrentUser.OpenSubKey(path);
            return k?.GetValue(name) as int?;
        }
        catch { return null; }
    }

    private static void SetHklm(string path, string name, object value)
    {
        try { Registry.SetValue($@"HKEY_LOCAL_MACHINE\{path}", name, value, RegistryValueKind.DWord); }
        catch { }
    }

    private static int? GetHklm(string path, string name)
    {
        try
        {
            using var k = Registry.LocalMachine.OpenSubKey(path);
            return k?.GetValue(name) as int?;
        }
        catch { return null; }
    }

    private static void SetPolicyEdge(string name, object value) =>
        SetHklm(@"SOFTWARE\Policies\Microsoft\Edge", name, value);

    #endregion

    #region 软件检测与备份

    /// <summary>软件安装检测（带别名补充，提升中文软件识别率）</summary>
    private static bool IsSoftwareInstalledFlexible(string keyword)
    {
        if (RegistryHelper.IsSoftwareInstalled(keyword)) return true;
        var alias = keyword switch
        {
            "WeChat" => "微信",
            "QQ" => "腾讯QQ",
            "WPS" => "金山",
            _ => null
        };
        return alias != null && RegistryHelper.IsSoftwareInstalled(alias);
    }

    /// <summary>
    /// 备份注册表 + Hosts + 服务配置到带时间戳的子目录
    /// </summary>
    private string CreateBackup(SceneMode mode)
    {
        var baseDir = ConfigManager.GetBackupDir();
        var dir = Path.Combine(baseDir, $"cleanup_{mode}_{DateTime.Now:yyyyMMdd_HHmmss}");
        Directory.CreateDirectory(dir);

        // 备份相关注册表项
        var regPaths = new (RegistryHive Hive, string Path)[]
        {
            (RegistryHive.CurrentUser,  @"Software\Kingsoft\Office"),
            (RegistryHive.CurrentUser,  @"Software\360se6"),
            (RegistryHive.CurrentUser,  @"Software\360Chrome"),
            (RegistryHive.CurrentUser,  @"Software\2345"),
            (RegistryHive.CurrentUser,  @"Software\2345Soft"),
            (RegistryHive.CurrentUser,  @"Software\Bandizip"),
            (RegistryHive.CurrentUser,  @"Software\HaoZip"),
            (RegistryHive.CurrentUser,  @"Software\Tencent"),
            (RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Edge"),
            (RegistryHive.CurrentUser,  @"SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"),
            (RegistryHive.CurrentUser,  @"Software\Microsoft\Windows\CurrentVersion\Run"),
            (RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
        };
        foreach (var (h, p) in regPaths)
            RegistryHelper.BackupRegistryKey(h, p, dir);

        // 备份 Hosts 文件
        HostsHelper.Backup(dir);
        // 备份服务配置
        ServiceHelper.BackupServices(dir);

        File.WriteAllText(Path.Combine(dir, "manifest.txt"),
            $"Cleanup backup mode={mode} @ {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
        return dir;
    }

    #endregion

    protected override string GetStatusSummary()
    {
        var cfg = AppState.Config.Cleanup;
        if (cfg.LastCleaned.HasValue)
            return $"已净化-{cfg.LastCleaned:yyyy-MM-dd HH:mm}";
        return "未净化";
    }
}
