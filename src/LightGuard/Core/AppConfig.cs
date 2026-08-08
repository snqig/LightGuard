using System.Text.Json.Serialization;
using LightGuard.Backup;
using LightGuard.ClientServer;
using LightGuard.Core.Interfaces;
using LightGuard.Database;
using LightGuard.NetworkIsolation;

namespace LightGuard.Core;

/// <summary>
/// 应用全局配置
/// JSON 序列化持久化到本地
/// </summary>
public sealed class AppConfig
{
    /// <summary>UI 模式</summary>
    public UiMode UiMode { get; set; } = UiMode.Modern;

    /// <summary>首次运行引导是否完成</summary>
    public bool FirstRunCompleted { get; set; }

    /// <summary>当前选用的场景模式</summary>
    public SceneMode CurrentScene { get; set; } = SceneMode.Home;

    /// <summary>模块开关状态</summary>
    public Dictionary<string, bool> ModuleEnabled { get; set; } = new();

    /// <summary>备份配置</summary>
    public BackupConfig Backup { get; set; } = new();

    /// <summary>更新配置</summary>
    public UpdateConfig Update { get; set; } = new();

    /// <summary>云端规则更新配置</summary>
    public CloudUpdateConfig CloudUpdate { get; set; } = new();

    /// <summary>防火墙配置</summary>
    public FirewallConfig Firewall { get; set; } = new();

    /// <summary>隐私加固配置</summary>
    public PrivacyConfig Privacy { get; set; } = new();

    /// <summary>净化配置</summary>
    public CleanupConfig Cleanup { get; set; } = new();

    /// <summary>商业软件联网隔离配置（Adobe / CorelDRAW 等套件出站阻断）</summary>
    public SuiteIsolationConfig SuiteIsolation { get; set; } = new();

    /// <summary>风险告警通知配置（钉钉/企微 Webhook，P1-2）</summary>
    public AlertConfig Alert { get; set; } = new();

    /// <summary>Microsoft Defender 全业务集成配置（P1-5）</summary>
    public DefenderConfig Defender { get; set; } = new();

    /// <summary>授权状态（v3.5：未授权禁用加密备份/定时/实时/数据库全部能力）</summary>
    public LicenseConfig License { get; set; } = new();

    /// <summary>文件备份任务列表（v3.5：定时全量/增量 + 实时监控增量）</summary>
    public List<FileBackupJob> FileBackupJobs { get; set; } = new();

    /// <summary>数据库备份实例列表（v3.5：每实例独立定时全量/增量 cron）</summary>
    public List<DbBackupInstance> DbBackupInstances { get; set; } = new();

    /// <summary>客户端 C/S 备份配置（v3.6：local / client_server 模式切换）</summary>
    public ClientServerConfig ClientServer { get; set; } = new();

    /// <summary>是否允许后台调度</summary>
    public bool BackgroundSchedulingEnabled { get; set; } = true;

    /// <summary>凌晨自动维护时间（小时，0-23）</summary>
    public int AutoMaintenanceHour { get; set; } = 3;

    /// <summary>配置版本号</summary>
    public int ConfigVersion { get; set; } = 1;

    /// <summary>界面语言（ZhCN/EnUS/ZhTW）</summary>
    public string Language { get; set; } = "ZhCN";

    /// <summary>是否启用服务器模式（强制英文审计日志，精简UI）</summary>
    public bool ServerLogMode { get; set; } = false;

    /// <summary>主窗口位置与尺寸（P1-4 窗口布局记忆，格式 "x,y,width,height"）</summary>
    public string WindowBounds { get; set; } = "";

    /// <summary>主窗口是否最大化（P1-4 窗口布局记忆）</summary>
    public bool WindowMaximized { get; set; }

    public bool IsModuleEnabled(string moduleId)
    {
        return ModuleEnabled.TryGetValue(moduleId, out var enabled) ? enabled : true;
    }

    public void SetModuleEnabled(string moduleId, bool enabled)
    {
        ModuleEnabled[moduleId] = enabled;
    }
}

/// <summary>场景模式</summary>
public enum SceneMode
{
    /// <summary>家用纯净模式（默认）</summary>
    Home,

    /// <summary>办公防勒索防广告模式</summary>
    Office,

    /// <summary>老旧电脑极致流畅模式</summary>
    Performance
}

/// <summary>备份配置</summary>
public sealed class BackupConfig
{
    public bool Enabled { get; set; } = true;
    public BackupMode Mode { get; set; } = BackupMode.Incremental;
    public BackupSchedule Schedule { get; set; } = BackupSchedule.Daily;
    public int MaxBackupCount { get; set; } = 10;
    public string BackupPath { get; set; } = "";
    public string NasPath { get; set; } = "";
    public string WebDavUrl { get; set; } = "";
    public string WebDavUser { get; set; } = "";
    public string WebDavPassword { get; set; } = "";
    public bool DisguiseAsSysFile { get; set; } = true;
    public List<string> ProtectedFolders { get; set; } = new();

    /// <summary>备份前自动查杀源文件（P1-6 联动：恶意文件跳过备份）</summary>
    public bool ScanBeforeBackup { get; set; } = true;

    /// <summary>
    /// WORM 自动锁定：备份完成后自动对备份包施加三层防删除锁
    /// （NTFS ACL + 只读属性 + 标记文件），勒索病毒无法删除/篡改备份。
    /// </summary>
    public bool WormAutoLock { get; set; } = true;
}

public enum BackupMode { Full, Incremental }
public enum BackupSchedule { Hourly, Daily, Weekly }

/// <summary>更新配置</summary>
public sealed class UpdateConfig
{
    public bool AutoUpdate { get; set; } = true;
    public int UpdateCheckIntervalHours { get; set; } = 12;
    public string VirusDbUpdateUrl { get; set; } = "";
    public DateTime? LastVirusDbUpdate { get; set; }
    public DateTime? LastEngineUpdate { get; set; }

    /// <summary>是否启用规则云端自动更新</summary>
    public bool AutoUpdateRules { get; set; } = true;

    /// <summary>规则检查间隔（小时）</summary>
    public int RuleCheckIntervalHours { get; set; } = 6;

    /// <summary>规则更新服务器地址（指向规则仓库根目录）</summary>
    public string RuleUpdateServerUrl { get; set; } = "https://raw.githubusercontent.com/snqig/LightGuard-rules/main";

    /// <summary>最后规则检查时间</summary>
    public DateTime? LastRuleCheck { get; set; }

    /// <summary>各规则类型已安装版本号（键为 RuleType 枚举名，值为版本号）</summary>
    public Dictionary<string, string> InstalledRuleVersions { get; set; } = new();

    /// <summary>增量差分更新清单地址（P1-3：软件本体增量更新）</summary>
    public string IncrementalUpdateUrl { get; set; } = "";

    /// <summary>最后增量更新检查时间</summary>
    public DateTime? LastIncrementalCheck { get; set; }
}

/// <summary>云端规则更新配置</summary>
public sealed class CloudUpdateConfig
{
    /// <summary>是否启用云端规则更新</summary>
    public bool Enabled { get; set; } = true;

    /// <summary>更新通道（Stable / Beta / Nightly）</summary>
    public string Channel { get; set; } = "Stable";

    /// <summary>检查间隔（小时，默认 12）</summary>
    public int CheckIntervalHours { get; set; } = 12;

    /// <summary>服务器地址（为空则使用默认地址）</summary>
    public string ServerUrl { get; set; } = "https://update.lightguard.app/v1";

    /// <summary>是否自动应用更新（关闭后仅检查不应用）</summary>
    public bool AutoApply { get; set; } = true;
}

/// <summary>防火墙配置</summary>
public sealed class FirewallConfig
{
    public bool Enabled { get; set; } = true;
    public bool BlockAds { get; set; } = true;
    public bool BlockTelemetry { get; set; } = true;
    public bool SmartIntercept { get; set; } = true;
    public List<string> BlockedDomains { get; set; } = new();
}

/// <summary>隐私加固配置</summary>
public sealed class PrivacyConfig
{
    public bool DisableTelemetry { get; set; } = true;
    public bool DisableAds { get; set; } = true;
    public bool DisableBackgroundApps { get; set; } = true;
    public bool DisableSearchOnline { get; set; } = true;
    public bool DisableFeedback { get; set; } = true;
    public bool DisableLockScreenAds { get; set; } = true;
    public bool DisableStartMenuAds { get; set; } = true;
    public PrivacyPolicyMode PolicyMode { get; set; } = PrivacyPolicyMode.Home;
    public DateTime? LastOptimized { get; set; }
    public string? BackupPath { get; set; }
}

public enum PrivacyPolicyMode { Home, Office }

/// <summary>净化配置</summary>
public sealed class CleanupConfig
{
    public bool Enabled { get; set; } = true;
    public bool CleanWps { get; set; } = true;
    public bool Clean360 { get; set; } = true;
    public bool CleanEdge { get; set; } = true;
    public bool Clean2345 { get; set; } = true;
    public bool CleanCompressors { get; set; } = true;
    public bool CleanPlayers { get; set; } = true;
    public bool CleanImApps { get; set; } = true;
    public bool GlobalAdBlock { get; set; } = true;
    public bool GlobalAntiBundle { get; set; } = true;
    public bool GlobalAutoStartClean { get; set; } = true;
    public DateTime? LastCleaned { get; set; }
    public string? BackupPath { get; set; }
}

/// <summary>
/// 商业软件联网隔离配置
/// </summary>
public sealed class SuiteIsolationConfig
{
    /// <summary>是否启用附加 hosts 域名阻断（可选增强，需要管理员权限）</summary>
    public bool HostsBlockEnabled { get; set; }

    /// <summary>套件隔离配置列表</summary>
    public List<SuiteBlockConfig> Suites { get; set; } = new();
}

/// <summary>
/// Microsoft Defender 全业务集成配置（P1-5）
/// 定时扫描 / 病毒库自动更新 / 实时保护监控 / 威胁告警 / 处置策略
/// </summary>
public sealed class DefenderConfig
{
    /// <summary>是否启用每日定时扫描</summary>
    public bool ScheduleEnabled { get; set; } = true;

    /// <summary>每日定时扫描时间（HH:mm，24 小时制，默认 02:30）</summary>
    public string ScanTime { get; set; } = "02:30";

    /// <summary>定时扫描类型（QuickScan / FullScan）</summary>
    public string ScheduleScanType { get; set; } = "QuickScan";

    /// <summary>扫描优先级（0=Normal，1=BelowNormal）</summary>
    public int ScanPriority { get; set; }

    /// <summary>扫描发现威胁后的处置动作（Quarantine / Remove / Allow / None）</summary>
    public string ThreatAction { get; set; } = "Quarantine";

    /// <summary>是否自动更新病毒库（过期后按 SignatureMaxAgeDays 触发）</summary>
    public bool AutoUpdateSignatures { get; set; } = true;

    /// <summary>病毒库过期天数阈值（超过则自动更新，默认 3 天）</summary>
    public int SignatureMaxAgeDays { get; set; } = 3;

    /// <summary>发现威胁时是否 Webhook 告警（钉钉/企微，P1-5）</summary>
    public bool AlertOnThreat { get; set; } = true;

    /// <summary>实时保护被关闭 / 引擎异常时是否 Webhook 告警（P1-5）</summary>
    public bool AlertOnProtectionDisabled { get; set; } = true;
}
