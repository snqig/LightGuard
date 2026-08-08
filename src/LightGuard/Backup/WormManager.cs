// © 2026 落尘（Luochen） 原创开发 - 保留所有权利

using LightGuard.Core;

namespace LightGuard.Backup;

/// <summary>
/// WORM（Write Once Read Many）备份锁定管理器。
/// <para>在备份包写入完成后自动施加 <see cref="BackupPermissionLock"/> 三层防删除锁
/// （NTFS ACL 拒绝 Everyone 删除/修改/写入 + 只读/隐藏属性 + .lockfile 标记），
/// 形成抗勒索只读隔离备份池：勒索病毒（非所有者身份）无法删除、篡改或加密覆盖备份。</para>
/// <para>读取不受影响：锁定 ACL 保留 SYSTEM / Administrators / 当前用户读取权限，
/// LightGuard 可正常浏览、校验、恢复；删除/覆盖需先经 <see cref="Unlock"/> 解除。</para>
/// <para>开关：<see cref="AppConfig.Backup.WormAutoLock"/>（默认开启）；
/// <see cref="AutoLockDisabled"/> 为进程级临时关闭（测试/调试用，不改写配置）。</para>
/// </summary>
public static class WormManager
{
    private static readonly BackupPermissionLock PermissionLock = new();

    /// <summary>
    /// 进程级临时关闭自动锁定（测试 / 调试用，不持久化到配置）。
    /// </summary>
    public static bool AutoLockDisabled { get; set; }

    /// <summary>WORM 自动锁定是否启用（配置开关 &amp;&amp; 未进程级禁用）。</summary>
    public static bool IsEnabled
        => !AutoLockDisabled && IsConfigEnabled();

    /// <summary>读取配置开关（AppState 未初始化时按默认开启处理）。</summary>
    private static bool IsConfigEnabled()
    {
        try
        {
            return AppState.Instance.Config.Backup.WormAutoLock;
        }
        catch
        {
            return true;
        }
    }

    /// <summary>
    /// 对备份包自动施加 WORM 三层锁定。
    /// <para>仅在 <see cref="IsEnabled"/> 时执行；文件不存在 / 锁定失败不抛出（仅记日志），
    /// 避免锁定异常阻断备份主流程。</para>
    /// </summary>
    /// <param name="backupPath">备份包路径。</param>
    /// <returns>是否已施加锁定（未启用 / 路径无效 / 失败均返回 false）。</returns>
    public static bool AutoLock(string backupPath)
    {
        if (!IsEnabled) return false;
        if (string.IsNullOrWhiteSpace(backupPath) || !File.Exists(backupPath))
            return false;

        try
        {
            PermissionLock.LockBackupFile(backupPath);
            ErrorReporter.Log($"WORM 自动锁定完成：{backupPath}");
            return true;
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, $"WORM 自动锁定失败（不阻断备份）：{backupPath}");
            return false;
        }
    }

    /// <summary>
    /// 解除备份包的 WORM 锁定（清理 / 覆盖 / 人工管理前调用）。
    /// </summary>
    public static void Unlock(string backupPath)
    {
        if (string.IsNullOrWhiteSpace(backupPath)) return;
        try
        {
            PermissionLock.UnlockBackupFile(backupPath);
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, $"WORM 解锁失败：{backupPath}");
            throw;
        }
    }

    /// <summary>备份包是否处于 WORM 锁定状态。</summary>
    public static bool IsLocked(string backupPath)
        => !string.IsNullOrWhiteSpace(backupPath) && PermissionLock.IsBackupLocked(backupPath);

    /// <summary>获取备份包锁定状态详情。</summary>
    public static LockStatus GetStatus(string backupPath)
        => PermissionLock.GetLockStatus(backupPath);

    /// <summary>校验三层锁定完整性。</summary>
    public static LockIntegrityResult VerifyIntegrity(string backupPath)
        => PermissionLock.VerifyLockIntegrity(backupPath);
}
