// © 2026 落尘（Luochen） 原创开发 - 保留所有权利

using System.Security.AccessControl;
using System.Security.Principal;

namespace LightGuard.Core;

/// <summary>
/// 数据目录 ACL 兜底配置（P0-10 权限方案A 收尾：目录 ACL 配置）。
/// <para>
/// 服务器版数据目录 %ProgramData%\LightGuard 由安装器（管理员）创建后，默认 ACL 仅包含
/// SYSTEM / Administrators / 创建者——其他登录用户（含以 asInvoker 普通权限运行的 LightGuard UI）
/// 无法读取，导致审计日志、病毒库、配置等系统级共享数据不可用。
/// 本类在程序以管理员身份启动时做幂等兜底：为 Users 组授予 Modify（继承子目录与文件），
/// 保证普通权限 UI 可读写自己的数据；配合 WORM 文件级防删除锁与 Worker 提权形成纵深防护。
/// </para>
/// <para>注：仅管理员可修改 ACL；普通权限启动时自动跳过（不抛出）。</para>
/// </summary>
public static class DirectoryAclConfigurator
{
    /// <summary>Users 组安全标识符（S-1-5-32-545）。</summary>
    private static readonly SecurityIdentifier UsersSid = new(WellKnownSidType.BuiltinUsersSid, null);

    /// <summary>完整继承标志：规则同时应用于当前目录、子目录与文件。</summary>
    private const InheritanceFlags FullInheritance =
        InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;

    /// <summary>
    /// 服务器版数据目录路径（%ProgramData%\LightGuard）。
    /// </summary>
    public static string ServerDataDir =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "LightGuard");

    /// <summary>
    /// 应用全部目录 ACL 兜底配置（管理员启动时调用）。
    /// 非管理员 / 非服务器环境静默跳过，返回是否执行了任何配置。
    /// </summary>
    public static bool ApplyAll()
    {
        if (!AdminChecker.IsRunningAsAdmin()) return false;
        if (!IsServerEnvironment()) return false;
        return EnsureServerDataDirAccess();
    }

    /// <summary>
    /// 为服务器版数据目录授予 Users 组 Modify 权限（幂等：已配置则直接返回）。
    /// 保留既有继承规则，仅追加一条显式 Allow，避免破坏安装器预设的 ACL。
    /// </summary>
    public static bool EnsureServerDataDirAccess()
    {
        if (!AdminChecker.IsRunningAsAdmin()) return false;

        var dataDir = ServerDataDir;
        try
        {
            Directory.CreateDirectory(dataDir);
            var info = new DirectoryInfo(dataDir);
            var security = info.GetAccessControl();

            // 幂等：Users 已持有 Modify 则跳过
            if (HasUsersModify(security)) return true;

            security.AddAccessRule(new FileSystemAccessRule(
                UsersSid, FileSystemRights.Modify, FullInheritance, PropagationFlags.None, AccessControlType.Allow));
            info.SetAccessControl(security);

            ErrorReporter.Log($"已配置服务器数据目录 ACL（Users Modify）：{dataDir}", "INFO");
            return true;
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, $"配置数据目录 ACL 失败：{dataDir}");
            return false;
        }
    }

    /// <summary>
    /// 检测当前是否为服务器分发环境（不依赖 DistributionProfile 初始化顺序）。
    /// 判定顺序：环境变量 LIGHTGUARD_SERVER=1 → 应用目录 server.mode 标记。
    /// </summary>
    private static bool IsServerEnvironment()
    {
        try
        {
            if (string.Equals(Environment.GetEnvironmentVariable("LIGHTGUARD_SERVER"),
                    "1", StringComparison.OrdinalIgnoreCase))
                return true;
            if (File.Exists(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "server.mode")))
                return true;
        }
        catch { /* 检测失败按非服务器处理 */ }
        return false;
    }

    /// <summary>
    /// 检查目录 ACL 中是否已存在 Users 组的 Modify 允许规则。
    /// </summary>
    private static bool HasUsersModify(DirectorySecurity security)
    {
        try
        {
            return security
                .GetAccessRules(true, true, typeof(SecurityIdentifier))
                .Cast<FileSystemAccessRule>()
                .Any(r => r.AccessControlType == AccessControlType.Allow
                    && r.IdentityReference is SecurityIdentifier sid
                    && sid.Value == UsersSid.Value
                    && (r.FileSystemRights & FileSystemRights.Modify) == FileSystemRights.Modify);
        }
        catch
        {
            return false;
        }
    }
}
