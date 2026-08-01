using System.Text.Json.Serialization;
using LightGuard.Core.Interfaces;

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

    /// <summary>防火墙配置</summary>
    public FirewallConfig Firewall { get; set; } = new();

    /// <summary>隐私加固配置</summary>
    public PrivacyConfig Privacy { get; set; } = new();

    /// <summary>净化配置</summary>
    public CleanupConfig Cleanup { get; set; } = new();

    /// <summary>是否允许后台调度</summary>
    public bool BackgroundSchedulingEnabled { get; set; } = true;

    /// <summary>凌晨自动维护时间（小时，0-23）</summary>
    public int AutoMaintenanceHour { get; set; } = 3;

    /// <summary>配置版本号</summary>
    public int ConfigVersion { get; set; } = 1;

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
