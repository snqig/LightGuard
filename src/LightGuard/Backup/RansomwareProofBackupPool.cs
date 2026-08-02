// © 2026 落尘（Luochen） 原创开发 - 保留所有权利

using System.Security.AccessControl;
using System.Security.Principal;
using LightGuard.Core;

namespace LightGuard.Backup;

/// <summary>
/// 备份池安全状态与统计信息。
/// </summary>
public sealed record PoolInfo
{
    /// <summary>备份池目录绝对路径。</summary>
    public string Path { get; init; } = string.Empty;

    /// <summary>备份池是否处于锁定状态。</summary>
    public bool IsLocked { get; init; }

    /// <summary>池内 .lgbackup 备份文件数量。</summary>
    public int FileCount { get; init; }

    /// <summary>池内所有备份文件总大小（字节）。</summary>
    public long TotalSizeBytes { get; init; }

    /// <summary>备份池目录创建时间。</summary>
    public DateTime CreatedTime { get; init; }
}

/// <summary>
/// 抗勒索隔离备份池 - 通过 NTFS ACL 权限锁定实现勒索病毒无法加密、无法删除的备份隔离区。
/// <para>核心防护原理：</para>
/// <para>1. 锁定时为 Everyone（WorldSid）添加 Write / Modify / Delete / DeleteSubdirectoriesAndFiles 的 Deny 规则，
/// 由于 NTFS 中 Deny 优先于 Allow，即使管理员账户也被拒绝写入，实现"全员禁写"。</para>
/// <para>2. 仅 SYSTEM 与 Administrators 保留 FullControl 的 Allow 规则，作为解锁后的写入基础。</para>
/// <para>3. 解锁时移除 Everyone 的 Deny 规则，此时管理员可凭 Allow 规则恢复写入；普通用户因无 Allow 规则仍无法写入。</para>
/// <para>4. 勒索病毒通常以普通用户权限运行，在锁定态下无法篡改池内备份；即使提权，Deny 规则同样拦截。</para>
/// <para>写入操作通过 <see cref="UnlockPoolForWrite"/> 获取临时令牌，操作完成后自动重新锁定。</para>
/// </summary>
public sealed class RansomwareProofBackupPool : IDisposable
{
    #region 常量与 SID 标识

    /// <summary>Everyone 组安全标识符（S-1-1-0）。</summary>
    private static readonly SecurityIdentifier EveryoneSid = new(WellKnownSidType.WorldSid, null);

    /// <summary>SYSTEM 账户安全标识符（S-1-5-18）。</summary>
    private static readonly SecurityIdentifier SystemSid = new(WellKnownSidType.LocalSystemSid, null);

    /// <summary>Administrators 组安全标识符（S-1-5-32-544）。</summary>
    private static readonly SecurityIdentifier AdminsSid = new(WellKnownSidType.BuiltinAdministratorsSid, null);

    /// <summary>完全继承标志：规则同时应用于当前目录、子目录与文件。</summary>
    private const InheritanceFlags FullInheritance = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;

    /// <summary>锁定时对 Everyone 拒绝的权限集合：写入、修改、删除、删除子目录及文件。</summary>
    private const FileSystemRights DeniedRights =
        FileSystemRights.Write
        | FileSystemRights.Modify
        | FileSystemRights.Delete
        | FileSystemRights.DeleteSubdirectoriesAndFiles;

    #endregion

    #region 字段

    private string? _poolPath;
    private volatile bool _isLocked;
    private bool _disposed;
    private readonly object _syncRoot = new();

    #endregion

    #region 构造

    /// <summary>
    /// 创建抗勒索隔离备份池实例（需随后调用 <see cref="Initialize"/> 完成初始化与锁定）。
    /// </summary>
    public RansomwareProofBackupPool() { }

    /// <summary>
    /// 创建并立即初始化抗勒索隔离备份池。
    /// </summary>
    /// <param name="poolPath">备份池目录路径。</param>
    public RansomwareProofBackupPool(string poolPath)
    {
        Initialize(poolPath);
    }

    #endregion

    #region 初始化

    /// <summary>
    /// 初始化备份池：创建目录并立即锁定 NTFS ACL。
    /// </summary>
    /// <param name="poolPath">备份池目录路径（若不存在将自动创建）。</param>
    /// <exception cref="ArgumentNullException">poolPath 为 null。</exception>
    /// <exception cref="ArgumentException">poolPath 为空白。</exception>
    public void Initialize(string poolPath)
    {
        ArgumentNullException.ThrowIfNull(poolPath);
        if (string.IsNullOrWhiteSpace(poolPath))
            throw new ArgumentException("备份池路径不能为空。", nameof(poolPath));

        _poolPath = poolPath;

        try
        {
            Directory.CreateDirectory(_poolPath);
            ErrorReporter.Log($"备份池目录已创建/就绪：{_poolPath}");
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, $"创建备份池目录失败：{_poolPath}");
            throw;
        }

        LockPool();
    }

    #endregion

    #region 锁定 / 解锁

    /// <summary>
    /// 锁定备份池：禁用继承并设置 NTFS ACL，拒绝 Everyone 写入/删除，仅 SYSTEM 与 Administrators 保留完全控制。
    /// <para>锁定后勒索病毒（以普通用户权限运行）无法加密或删除池内备份文件。</para>
    /// </summary>
    /// <exception cref="InvalidOperationException">备份池未初始化或目录不存在。</exception>
    /// <exception cref="ObjectDisposedException">实例已释放。</exception>
    public void LockPool()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        EnsureInitialized();
        LockPoolCore();
    }

    /// <summary>
    /// 临时解锁备份池以允许写入：移除 Everyone 的 Deny 规则，返回可释放令牌。
    /// <para>令牌 <see cref="PoolWriteToken.Dispose"/> 时自动重新锁定，建议配合 using 语句使用。</para>
    /// <para>解锁后仅管理员可写入（凭 Allow 规则），普通用户因无 Allow 规则仍无权写入。</para>
    /// </summary>
    /// <returns>可释放写入令牌，Dispose 时自动重新锁定。</returns>
    /// <exception cref="InvalidOperationException">备份池未初始化或目录不存在。</exception>
    /// <exception cref="ObjectDisposedException">实例已释放。</exception>
    public PoolWriteToken UnlockPoolForWrite()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        EnsureInitialized();

        lock (_syncRoot)
        {
            RemoveEveryoneDenyRules();
            _isLocked = false;
            ErrorReporter.Log($"备份池已临时解锁以允许写入：{_poolPath}");
            return new PoolWriteToken(this);
        }
    }

    /// <summary>
    /// 验证备份池 ACL 安全状态是否完好。
    /// <para>检查项：继承已禁用、Everyone Deny 规则存在、SYSTEM 与 Administrators Allow FullControl 规则存在。</para>
    /// </summary>
    /// <returns>ACL 完好返回 true；否则返回 false。</returns>
    public bool VerifyPoolSecurity()
    {
        if (string.IsNullOrEmpty(_poolPath) || !Directory.Exists(_poolPath))
            return false;

        try
        {
            var security = new DirectoryInfo(_poolPath).GetAccessControl();

            // 检查继承是否已禁用（防止继承的宽松规则削弱防护）
            if (!security.AreAccessRulesProtected)
            {
                ErrorReporter.Log($"备份池安全验证失败：继承未禁用 - {_poolPath}", "WARN");
                return false;
            }

            var rules = security.GetAccessRules(true, true, typeof(SecurityIdentifier))
                .Cast<FileSystemAccessRule>()
                .ToList();

            // 检查 Everyone Deny 规则是否覆盖全部受限权限
            bool hasEveryoneDeny = rules.Any(r =>
                r.AccessControlType == AccessControlType.Deny
                && r.IdentityReference is SecurityIdentifier sid
                && sid.Value == EveryoneSid.Value
                && (r.FileSystemRights & DeniedRights) == DeniedRights);

            // 检查 SYSTEM Allow FullControl
            bool hasSystemAllow = rules.Any(r =>
                r.AccessControlType == AccessControlType.Allow
                && r.IdentityReference is SecurityIdentifier sid
                && sid.Value == SystemSid.Value
                && r.FileSystemRights == FileSystemRights.FullControl);

            // 检查 Administrators Allow FullControl
            bool hasAdminsAllow = rules.Any(r =>
                r.AccessControlType == AccessControlType.Allow
                && r.IdentityReference is SecurityIdentifier sid
                && sid.Value == AdminsSid.Value
                && r.FileSystemRights == FileSystemRights.FullControl);

            if (!hasEveryoneDeny)
                ErrorReporter.Log($"备份池安全验证失败：缺少 Everyone Deny 规则 - {_poolPath}", "WARN");
            if (!hasSystemAllow)
                ErrorReporter.Log($"备份池安全验证失败：缺少 SYSTEM Allow 规则 - {_poolPath}", "WARN");
            if (!hasAdminsAllow)
                ErrorReporter.Log($"备份池安全验证失败：缺少 Administrators Allow 规则 - {_poolPath}", "WARN");

            return hasEveryoneDeny && hasSystemAllow && hasAdminsAllow;
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, $"验证备份池安全状态失败：{_poolPath}");
            return false;
        }
    }

    #endregion

    #region 池信息

    /// <summary>
    /// 获取备份池当前状态信息：路径、锁定状态、文件数量、总大小、创建时间。
    /// </summary>
    /// <returns>备份池信息快照。</returns>
    /// <exception cref="InvalidOperationException">备份池未初始化。</exception>
    public PoolInfo GetPoolInfo()
    {
        if (string.IsNullOrEmpty(_poolPath))
            throw new InvalidOperationException("备份池未初始化，请先调用 Initialize。");

        var di = new DirectoryInfo(_poolPath);
        int fileCount = 0;
        long totalSize = 0;
        DateTime createdTime = DateTime.MinValue;

        if (di.Exists)
        {
            try
            {
                foreach (var f in di.EnumerateFiles("*" + LgBackupFormat.Extension, SearchOption.TopDirectoryOnly))
                {
                    fileCount++;
                    totalSize += f.Length;
                }
            }
            catch (Exception ex)
            {
                ErrorReporter.Log($"枚举备份池文件失败：{ex.Message}", "WARN");
            }

            try { createdTime = di.CreationTime; }
            catch { /* 忽略目录访问异常 */ }
        }

        return new PoolInfo
        {
            Path = _poolPath,
            IsLocked = _isLocked,
            FileCount = fileCount,
            TotalSizeBytes = totalSize,
            CreatedTime = createdTime
        };
    }

    #endregion

    #region 备份文件操作

    /// <summary>
    /// 将源备份文件写入隔离池（自动解锁 → 写入 → 重新锁定）。
    /// </summary>
    /// <param name="sourceFile">源备份文件完整路径。</param>
    /// <param name="destFileName">池内目标文件名（若未以 .lgbackup 结尾则自动追加）。</param>
    /// <returns>写入后的完整路径。</returns>
    /// <exception cref="ArgumentNullException">参数为 null。</exception>
    /// <exception cref="FileNotFoundException">源文件不存在。</exception>
    /// <exception cref="ArgumentException">目标文件名无效。</exception>
    public string WriteBackupToPool(string sourceFile, string destFileName)
    {
        ArgumentNullException.ThrowIfNull(sourceFile);
        ArgumentNullException.ThrowIfNull(destFileName);
        ObjectDisposedException.ThrowIf(_disposed, this);
        EnsureInitialized();

        if (!File.Exists(sourceFile))
            throw new FileNotFoundException("源备份文件不存在。", sourceFile);

        // 安全校验：仅取文件名，防止路径穿越攻击
        var safeName = Path.GetFileName(destFileName);
        if (string.IsNullOrEmpty(safeName))
            throw new ArgumentException("目标文件名无效。", nameof(destFileName));

        // 统一扩展名为 .lgbackup
        if (!safeName.EndsWith(LgBackupFormat.Extension, StringComparison.OrdinalIgnoreCase))
            safeName += LgBackupFormat.Extension;

        var destPath = Path.Combine(_poolPath!, safeName);

        using (UnlockPoolForWrite())
        {
            File.Copy(sourceFile, destPath, overwrite: true);
            ErrorReporter.Log($"已写入备份至隔离池：{sourceFile} -> {destPath}");
        }

        return destPath;
    }

    /// <summary>
    /// 列举隔离池内所有 .lgbackup 备份文件（按文件名升序）。
    /// </summary>
    /// <returns>备份文件完整路径列表；池不存在时返回空列表。</returns>
    public List<string> ListBackups()
    {
        var list = new List<string>();
        if (string.IsNullOrEmpty(_poolPath) || !Directory.Exists(_poolPath))
            return list;

        try
        {
            list = Directory
                .EnumerateFiles(_poolPath, "*" + LgBackupFormat.Extension, SearchOption.TopDirectoryOnly)
                .OrderBy(f => f, StringComparer.OrdinalIgnoreCase)
                .ToList();
        }
        catch (Exception ex)
        {
            ErrorReporter.Log($"列举备份文件失败：{ex.Message}", "WARN");
        }

        return list;
    }

    /// <summary>
    /// 从隔离池删除指定备份文件（自动解锁 → 删除 → 重新锁定）。
    /// <para>安全限制：仅允许删除 .lgbackup 文件，拒绝路径穿越与非备份文件删除。</para>
    /// </summary>
    /// <param name="fileName">池内备份文件名。</param>
    /// <returns>删除成功返回 true；文件不存在或扩展名不匹配返回 false。</returns>
    /// <exception cref="ArgumentNullException">参数为 null。</exception>
    /// <exception cref="ArgumentException">文件名无效。</exception>
    public bool DeleteBackup(string fileName)
    {
        ArgumentNullException.ThrowIfNull(fileName);
        ObjectDisposedException.ThrowIf(_disposed, this);
        EnsureInitialized();

        // 安全校验：仅取文件名，防止路径穿越
        var safeName = Path.GetFileName(fileName);
        if (string.IsNullOrEmpty(safeName))
            throw new ArgumentException("文件名无效。", nameof(fileName));

        // 仅允许删除 .lgbackup 文件
        if (!safeName.EndsWith(LgBackupFormat.Extension, StringComparison.OrdinalIgnoreCase))
        {
            ErrorReporter.Log($"拒绝删除非备份文件（扩展名不匹配）：{safeName}", "WARN");
            return false;
        }

        var targetPath = Path.Combine(_poolPath!, safeName);
        if (!File.Exists(targetPath))
        {
            ErrorReporter.Log($"待删除的备份文件不存在：{targetPath}", "WARN");
            return false;
        }

        try
        {
            using (UnlockPoolForWrite())
            {
                File.Delete(targetPath);
            }
            ErrorReporter.Log($"已从隔离池删除备份：{targetPath}");
            return true;
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, $"删除备份失败：{targetPath}");
            return false;
        }
    }

    #endregion

    #region IDisposable

    /// <summary>
    /// 释放资源：若备份池当前处于解锁状态，自动重新锁定以确保安全。
    /// </summary>
    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;

        try
        {
            if (!string.IsNullOrEmpty(_poolPath) && Directory.Exists(_poolPath) && !_isLocked)
            {
                LockPoolCore();
                ErrorReporter.Log($"备份池已在释放时重新锁定：{_poolPath}");
            }
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, $"释放备份池时重新锁定失败：{_poolPath}");
        }
    }

    #endregion

    #region 私有辅助

    /// <summary>
    /// 确保备份池已初始化且目录存在。
    /// </summary>
    /// <exception cref="InvalidOperationException">备份池未初始化或目录不存在。</exception>
    private void EnsureInitialized()
    {
        if (string.IsNullOrEmpty(_poolPath) || !Directory.Exists(_poolPath))
            throw new InvalidOperationException("备份池未初始化或目录不存在，请先调用 Initialize。");
    }

    /// <summary>
    /// 锁定核心逻辑（不含 disposed 检查），供公开 <see cref="LockPool"/> 与 <see cref="Dispose"/> 共用。
    /// </summary>
    private void LockPoolCore()
    {
        lock (_syncRoot)
        {
            try
            {
                var di = new DirectoryInfo(_poolPath!);
                var security = di.GetAccessControl();

                // 禁用继承并移除继承的规则，获得干净基线
                security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);

                // 移除所有现有显式规则，确保从干净状态重建 ACL
                var existing = security
                    .GetAccessRules(true, false, typeof(SecurityIdentifier))
                    .Cast<FileSystemAccessRule>()
                    .ToList();
                foreach (var rule in existing)
                    security.RemoveAccessRuleSpecific(rule);

                // 添加 Deny 规则：Everyone 禁止写入/修改/删除（Deny 优先于 Allow，全员禁写）
                security.AddAccessRule(new FileSystemAccessRule(
                    EveryoneSid, DeniedRights, FullInheritance, PropagationFlags.None, AccessControlType.Deny));

                // 添加 Allow 规则：SYSTEM 完全控制
                security.AddAccessRule(new FileSystemAccessRule(
                    SystemSid, FileSystemRights.FullControl, FullInheritance, PropagationFlags.None, AccessControlType.Allow));

                // 添加 Allow 规则：Administrators 完全控制
                security.AddAccessRule(new FileSystemAccessRule(
                    AdminsSid, FileSystemRights.FullControl, FullInheritance, PropagationFlags.None, AccessControlType.Allow));

                di.SetAccessControl(security);

                _isLocked = true;
                ErrorReporter.Log($"备份池已锁定（NTFS ACL 拒绝 Everyone 写入/删除）：{_poolPath}");
            }
            catch (Exception ex)
            {
                ErrorReporter.Report(ex, $"锁定备份池失败：{_poolPath}");
                throw;
            }
        }
    }

    /// <summary>
    /// 移除针对 Everyone 的所有 Deny 规则（临时解锁核心操作）。
    /// <para>移除 Deny 后，管理员凭 Administrators Allow FullControl 恢复写入能力；
    /// 普通用户因无 Allow 规则仍无法写入。</para>
    /// </summary>
    private void RemoveEveryoneDenyRules()
    {
        var di = new DirectoryInfo(_poolPath!);
        var security = di.GetAccessControl();

        var denyRules = security
            .GetAccessRules(true, false, typeof(SecurityIdentifier))
            .Cast<FileSystemAccessRule>()
            .Where(r => r.AccessControlType == AccessControlType.Deny
                        && r.IdentityReference is SecurityIdentifier sid
                        && sid.Value == EveryoneSid.Value)
            .ToList();

        foreach (var rule in denyRules)
            security.RemoveAccessRuleSpecific(rule);

        di.SetAccessControl(security);
    }

    #endregion

    #region 嵌套类型

    /// <summary>
    /// 临时写入令牌 - 释放时自动重新锁定备份池。
    /// <para>应配合 using 语句使用，请勿手动复制或长时持有。重复 Dispose 是安全的（LockPool 幂等）。</para>
    /// </summary>
    public readonly struct PoolWriteToken : IDisposable
    {
        private readonly RansomwareProofBackupPool? _pool;

        /// <summary>
        /// 内部构造：仅由 <see cref="RansomwareProofBackupPool.UnlockPoolForWrite"/> 创建。
        /// </summary>
        /// <param name="pool">所属备份池实例。</param>
        internal PoolWriteToken(RansomwareProofBackupPool pool)
        {
            _pool = pool;
        }

        /// <summary>
        /// 释放令牌：重新锁定备份池。若池已释放或锁定失败，异常将被记录而非抛出。
        /// </summary>
        public void Dispose()
        {
            if (_pool == null) return;
            try
            {
                _pool.LockPool();
            }
            catch (Exception ex)
            {
                ErrorReporter.Report(ex, "释放写入令牌时重新锁定备份池失败。");
            }
        }
    }

    #endregion
}
