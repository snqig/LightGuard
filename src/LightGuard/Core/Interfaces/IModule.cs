namespace LightGuard.Core.Interfaces;

/// <summary>
/// 所有功能模块的统一接口
/// 每个模块可独立开关，关闭即彻底释放资源
/// </summary>
public interface IModule : IDisposable
{
    /// <summary>模块唯一标识</summary>
    string Id { get; }

    /// <summary>模块显示名称（中文）</summary>
    string DisplayName { get; }

    /// <summary>模块描述</summary>
    string Description { get; }

    /// <summary>模块分类</summary>
    ModuleCategory Category { get; }

    /// <summary>是否已启用</summary>
    bool IsEnabled { get; }

    /// <summary>是否需要管理员权限</summary>
    bool RequiresAdmin { get; }

    /// <summary>初始化模块</summary>
    Task InitializeAsync();

    /// <summary>启用模块</summary>
    Task EnableAsync();

    /// <summary>禁用模块（彻底释放资源）</summary>
    Task DisableAsync();

    /// <summary>获取模块状态摘要（用于UI显示）</summary>
    ModuleStatus GetStatus();
}

/// <summary>模块分类</summary>
public enum ModuleCategory
{
    Core,           // 核心系统
    Privacy,        // 隐私加固
    Ransomware,     // 勒索防护 (ETW+YARA 双层防御)
    Backup,         // 加密抗勒索备份
    Firewall,       // 防火墙 ACL
    Cleanup,        // 广告屏蔽净化
    Update,         // 自动更新
    Recovery,       // 灾难恢复
    DatabaseBackup, // 数据库备份
    Audit           // SMB 文件服务器审计
}

/// <summary>模块运行状态</summary>
public enum ModuleStatus
{
    Stopped,
    Initializing,
    Running,
    Error,
    Disabled
}

/// <summary>模块状态信息（UI展示用）</summary>
public sealed class ModuleStatusInfo
{
    public ModuleStatus Status { get; set; }
    public string Summary { get; set; } = string.Empty;
    public string? LastError { get; set; }
    public DateTime? LastActionTime { get; set; }
}
