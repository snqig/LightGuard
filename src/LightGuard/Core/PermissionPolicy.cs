// © 2026 落尘（Luochen） 原创开发 - 保留所有权利

namespace LightGuard.Core;

/// <summary>
/// 权限策略（P0-4 权限重构方案A 收尾）。
/// <para>UI 以普通权限（asInvoker）运行：需要管理员的功能入口在非管理员时灰化禁用，
/// 已 Worker 化（VSS / VHD 挂载）的高危操作保留可用（自动提权执行）。</para>
/// <para>功能标识 → 是否需要管理员 的静态映射；<see cref="CanAccess"/> 供导航/按钮统一判定。</para>
/// </summary>
public static class PermissionPolicy
{
    /// <summary>当前进程是否以管理员身份运行。</summary>
    public static bool IsAdmin => AdminChecker.IsRunningAsAdmin();

    /// <summary>权限模式显示名。</summary>
    public static string ModeName => IsAdmin ? "管理员权限" : "普通权限";

    /// <summary>
    /// 需要管理员权限的功能标识集合（非管理员时对应导航 / 按钮灰化）。
    /// <para>key 与 MainForm 导航 key / 页面内功能 id 对齐。</para>
    /// </summary>
    private static readonly Dictionary<string, bool> RequiresAdminMap = new(StringComparer.OrdinalIgnoreCase)
    {
        // 普通用户可用的功能（备份已 Worker 化提权，普通可浏览/恢复；更新/设置安全）
        ["dashboard"] = false,
        ["backup"] = false,
        ["update"] = false,
        ["cloud-update"] = false,
        ["settings"] = false,

        // 系统级防护 / 管理操作：需管理员
        ["privacy"] = true,            // 隐私加固：改系统策略/注册表
        ["cleanup"] = true,            // 流氓净化：卸载/清理系统组件
        ["firewall"] = true,           // 防火墙 ACL：写防火墙规则
        ["suite-isolation"] = true,    // 网络隔离：修改 Hosts/网络接口
        ["ransomware"] = true,         // 勒索防护：ETW 监控 + 进程防护
        ["decrypt"] = true,            // 勒索解密：扫描全盘 + 写回解密
        ["defender"] = true,           // Defender 查杀：调用 MpCmdRun 需管理员
        ["audit"] = true,              // 文件审计：配置 SACL + ETW 追踪

        // 页面内功能（BackupPage 等）
        ["backup-partition"] = true,   // 分区备份：打开卷句柄需管理员
        ["backup-disk"] = true,        // 整盘备份：物理磁盘访问需管理员
        ["backup-database"] = true,    // 数据库备份：系统库/服务需管理员
    };

    /// <summary>指定功能是否需要管理员权限（未知功能默认按需管理员处理，保守灰化）。</summary>
    public static bool RequiresAdmin(string featureId)
    {
        if (string.IsNullOrWhiteSpace(featureId)) return false;
        return RequiresAdminMap.TryGetValue(featureId, out var need) ? need : true;
    }

    /// <summary>当前权限下功能是否可用（管理员全可用；普通权限下非管理员功能可用）。</summary>
    public static bool CanAccess(string featureId)
        => IsAdmin || !RequiresAdmin(featureId);
}
