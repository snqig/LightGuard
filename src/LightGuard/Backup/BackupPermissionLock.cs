// © 2026 落尘（Luochen） 原创开发 - 保留所有权利

using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using LightGuard.Core;

namespace LightGuard.Backup;

/// <summary>
/// 备份文件三层锁定状态快照。
/// </summary>
public sealed class LockStatus
{
    /// <summary>是否处于锁定状态（任意一层启用即为 true）。</summary>
    public bool IsLocked { get; set; }

    /// <summary>NTFS ACL 层是否已锁定（拒绝 Everyone 删除/修改/写入）。</summary>
    public bool AclLocked { get; set; }

    /// <summary>文件属性层是否已锁定（ReadOnly + Hidden）。</summary>
    public bool AttributeLocked { get; set; }

    /// <summary>标记文件层是否已锁定（.lockfile 存在）。</summary>
    public bool MarkerLocked { get; set; }

    /// <summary>状态详情描述。</summary>
    public string Details { get; set; } = string.Empty;
}

/// <summary>
/// 备份文件三层锁定完整性校验结果。
/// </summary>
public sealed class LockIntegrityResult
{
    /// <summary>三层是否全部完好（全部启用）。</summary>
    public bool IsIntact { get; set; }

    /// <summary>当前锁定状态快照。</summary>
    public LockStatus Status { get; set; } = new();

    /// <summary>完整性校验报告文本。</summary>
    public string Report { get; set; } = string.Empty;

    /// <summary>逐层缺失项说明。</summary>
    public List<string> Findings { get; set; } = new();
}

/// <summary>
/// 备份三层防删除权限锁 - 通过 NTFS ACL、文件属性与标记文件三重防护，阻止勒索病毒/误操作删除或篡改备份。
/// <para>三层防护：</para>
/// <para>1. NTFS ACL 层：拒绝 Everyone 删除/修改/写入，仅允许 SYSTEM 与 Administrators 读取（Deny 优先于 Allow，全员禁删禁改）。</para>
/// <para>2. 文件属性层：设置 ReadOnly + Hidden，隐藏并标记为只读。</para>
/// <para>3. 标记文件层：在备份旁写入 .lockfile 标记，用于完整性指示与防误删。</para>
/// <para>解锁时反向依次移除三层；锁定时先写属性与标记、最后施加 ACL，避免自我锁定后无法写属性。</para>
/// <para>注：备份文件所有者始终隐式持有 WRITE_DAC 权限，故合法所有者（创建备份的 LightGuard 进程）可解除 ACL；
/// 勒索病毒以非所有者身份运行时无法篡改 ACL，从而无法解锁或删除备份。</para>
/// </summary>
public sealed class BackupPermissionLock
{
    #region 常量与 SID 标识

    /// <summary>Everyone 组安全标识符（S-1-1-0）。</summary>
    private static readonly SecurityIdentifier EveryoneSid = new(WellKnownSidType.WorldSid, null);

    /// <summary>SYSTEM 账户安全标识符（S-1-5-18）。</summary>
    private static readonly SecurityIdentifier SystemSid = new(WellKnownSidType.LocalSystemSid, null);

    /// <summary>Administrators 组安全标识符（S-1-5-32-544）。</summary>
    private static readonly SecurityIdentifier AdminsSid = new(WellKnownSidType.BuiltinAdministratorsSid, null);

    /// <summary>
    /// 锁定时对 Everyone 拒绝的权限集合：写入数据、追加、删除、修改属性/扩展属性。
    /// <para>注意：不得包含 Modify（Modify 隐含 ReadData），否则 Deny 优先会连读取一起拒绝，
    /// 导致 LightGuard 自身（含 SYSTEM/管理员）也无法浏览/校验/恢复锁定备份。</para>
    /// </summary>
    private const FileSystemRights DeniedRights =
        FileSystemRights.Write
        | FileSystemRights.AppendData
        | FileSystemRights.Delete
        | FileSystemRights.WriteAttributes
        | FileSystemRights.WriteExtendedAttributes;

    /// <summary>目录锁额外拒绝"删除子目录及文件"权限。</summary>
    private const FileSystemRights DeniedDirExtraRights = FileSystemRights.DeleteSubdirectoriesAndFiles;

    /// <summary>目录完整继承标志：规则同时应用于当前目录、子目录与文件。</summary>
    private const InheritanceFlags FullInheritance = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;

    /// <summary>标记文件后缀。</summary>
    private const string LockFileSuffix = ".lockfile";

    #endregion

    #region 锁定 / 解锁（单文件）

    /// <summary>
    /// 对单个备份文件施加三层锁定。
    /// </summary>
    /// <param name="backupPath">备份文件路径。</param>
    /// <exception cref="ArgumentNullException">backupPath 为 null。</exception>
    /// <exception cref="FileNotFoundException">备份文件不存在。</exception>
    public void LockBackupFile(string backupPath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(backupPath, nameof(backupPath));
        if (!File.Exists(backupPath))
            throw new FileNotFoundException("备份文件不存在。", backupPath);

        try
        {
            // 先写标记与属性（此时 ACL 尚未拒绝写入）
            WriteMarker(backupPath);
            ApplyAttributeLock(backupPath);
            // 最后施加 ACL 拒绝（避免自我锁定后无法写属性）
            ApplyAclLock(backupPath, isDirectory: false);
            ErrorReporter.Log($"备份文件已施加三层锁定：{backupPath}");
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, $"锁定备份文件失败：{backupPath}");
            throw;
        }
    }

    /// <summary>
    /// 解除单个备份文件的三层锁定。
    /// </summary>
    /// <param name="backupPath">备份文件路径。</param>
    /// <exception cref="ArgumentNullException">backupPath 为 null。</exception>
    public void UnlockBackupFile(string backupPath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(backupPath, nameof(backupPath));
        if (!File.Exists(backupPath))
        {
            // 文件不存在时仍尝试清理残留标记
            DeleteMarker(backupPath);
            return;
        }

        try
        {
            // 先解除 ACL（恢复继承与默认权限），恢复写入能力
            ResetAcl(backupPath, isDirectory: false);
            // 再清属性与标记（此时已具备写入权限）
            ClearAttributeLock(backupPath);
            DeleteMarker(backupPath);
            ErrorReporter.Log($"备份文件已解除三层锁定：{backupPath}");
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, $"解锁备份文件失败：{backupPath}");
            throw;
        }
    }

    #endregion

    #region 锁定 / 解锁（目录）

    /// <summary>
    /// 对备份目录施加三层锁定（ACL 通过继承保护目录内全部子项）。
    /// </summary>
    /// <param name="dirPath">备份目录路径。</param>
    /// <exception cref="ArgumentNullException">dirPath 为 null。</exception>
    /// <exception cref="DirectoryNotFoundException">目录不存在。</exception>
    public void LockBackupDirectory(string dirPath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(dirPath, nameof(dirPath));
        if (!Directory.Exists(dirPath))
            throw new DirectoryNotFoundException("备份目录不存在：" + dirPath);

        try
        {
            WriteMarker(dirPath);
            ApplyAttributeLock(dirPath);
            ApplyAclLock(dirPath, isDirectory: true);
            ErrorReporter.Log($"备份目录已施加三层锁定：{dirPath}");
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, $"锁定备份目录失败：{dirPath}");
            throw;
        }
    }

    /// <summary>
    /// 解除备份目录的三层锁定。
    /// </summary>
    /// <param name="dirPath">备份目录路径。</param>
    /// <exception cref="ArgumentNullException">dirPath 为 null。</exception>
    public void UnlockBackupDirectory(string dirPath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(dirPath, nameof(dirPath));
        if (!Directory.Exists(dirPath))
        {
            DeleteMarker(dirPath);
            return;
        }

        try
        {
            ResetAcl(dirPath, isDirectory: true);
            ClearAttributeLock(dirPath);
            DeleteMarker(dirPath);
            ErrorReporter.Log($"备份目录已解除三层锁定：{dirPath}");
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, $"解锁备份目录失败：{dirPath}");
            throw;
        }
    }

    #endregion

    #region 状态查询

    /// <summary>
    /// 检查备份是否处于锁定状态（任意一层启用即为 true）。
    /// </summary>
    /// <param name="backupPath">备份文件或目录路径。</param>
    /// <returns>是否锁定。</returns>
    public bool IsBackupLocked(string backupPath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(backupPath, nameof(backupPath));
        if (!File.Exists(backupPath) && !Directory.Exists(backupPath)) return false;
        return IsAclLocked(backupPath) || IsAttributeLocked(backupPath) || IsMarkerLocked(backupPath);
    }

    /// <summary>
    /// 获取备份锁定状态详情（各层启用情况）。
    /// </summary>
    /// <param name="backupPath">备份文件或目录路径。</param>
    /// <returns>锁定状态快照。</returns>
    public LockStatus GetLockStatus(string backupPath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(backupPath, nameof(backupPath));

        var status = new LockStatus();
        if (!File.Exists(backupPath) && !Directory.Exists(backupPath))
        {
            status.Details = "路径不存在。";
            return status;
        }

        status.AclLocked = IsAclLocked(backupPath);
        status.AttributeLocked = IsAttributeLocked(backupPath);
        status.MarkerLocked = IsMarkerLocked(backupPath);
        status.IsLocked = status.AclLocked || status.AttributeLocked || status.MarkerLocked;

        var layers = new List<string>();
        if (status.AclLocked) layers.Add("NTFS ACL");
        if (status.AttributeLocked) layers.Add("属性(ReadOnly/Hidden)");
        if (status.MarkerLocked) layers.Add("标记文件(.lockfile)");
        status.Details = status.IsLocked
            ? "已启用锁定层级：" + string.Join("、", layers)
            : "未锁定（三层均未启用）";
        return status;
    }

    /// <summary>
    /// 校验三层锁定是否全部完好。
    /// </summary>
    /// <param name="backupPath">备份文件或目录路径。</param>
    /// <returns>完整性校验结果（含逐层缺失说明）。</returns>
    public LockIntegrityResult VerifyLockIntegrity(string backupPath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(backupPath, nameof(backupPath));

        var status = GetLockStatus(backupPath);
        var findings = new List<string>();
        if (!status.AclLocked) findings.Add("ACL 层缺失（未拒绝 Everyone 删除/修改/写入）");
        if (!status.AttributeLocked) findings.Add("属性层缺失（未设置 ReadOnly/Hidden）");
        if (!status.MarkerLocked) findings.Add("标记文件缺失（.lockfile 不存在）");

        bool intact = status.AclLocked && status.AttributeLocked && status.MarkerLocked;
        return new LockIntegrityResult
        {
            IsIntact = intact,
            Status = status,
            Findings = findings,
            Report = intact
                ? "完整性校验通过：三层锁定均已启用。"
                : "完整性异常：缺少 " + findings.Count + " 层 - " + string.Join("；", findings)
        };
    }

    #endregion

    #region ACL 层

    /// <summary>
    /// 施加 NTFS ACL 锁定：禁用继承并移除继承规则，添加 Everyone Deny 与 SYSTEM/Admins Allow Read。
    /// </summary>
    private void ApplyAclLock(string path, bool isDirectory)
    {
        var security = GetSecurity(path);
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);

        // 移除所有现有显式规则，从干净基线重建
        var existing = security
            .GetAccessRules(true, false, typeof(SecurityIdentifier))
            .Cast<FileSystemAccessRule>()
            .ToList();
        foreach (var rule in existing)
            security.RemoveAccessRuleSpecific(rule);

        var inheritance = isDirectory ? FullInheritance : InheritanceFlags.None;
        var denied = isDirectory ? (DeniedRights | DeniedDirExtraRights) : DeniedRights;

        // Deny：Everyone 禁止写入/修改/删除（Deny 优先于 Allow，全员禁删禁改）
        security.AddAccessRule(new FileSystemAccessRule(
            EveryoneSid, denied, inheritance, PropagationFlags.None, AccessControlType.Deny));

        // Allow：SYSTEM 与 Administrators 读取
        security.AddAccessRule(new FileSystemAccessRule(
            SystemSid, FileSystemRights.Read, inheritance, PropagationFlags.None, AccessControlType.Allow));
        security.AddAccessRule(new FileSystemAccessRule(
            AdminsSid, FileSystemRights.Read, inheritance, PropagationFlags.None, AccessControlType.Allow));

        // Allow：当前交互用户读取（WORM 场景保证 LightGuard 普通权限进程仍可浏览/校验/恢复自己的备份）
        try
        {
            var current = WindowsIdentity.GetCurrent().User;
            if (current != null && current.Value != EveryoneSid.Value)
            {
                security.AddAccessRule(new FileSystemAccessRule(
                    current, FileSystemRights.Read, inheritance, PropagationFlags.None, AccessControlType.Allow));
            }
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, "添加当前用户读取授权失败（不影响锁定生效）。");
        }

        SetSecurity(path, security);
    }

    /// <summary>
    /// 重置 NTFS ACL：移除全部显式规则并恢复继承（恢复父目录默认权限）。
    /// </summary>
    private void ResetAcl(string path, bool isDirectory)
    {
        var security = GetSecurity(path);

        var explicitRules = security
            .GetAccessRules(true, false, typeof(SecurityIdentifier))
            .Cast<FileSystemAccessRule>()
            .ToList();
        foreach (var rule in explicitRules)
            security.RemoveAccessRuleSpecific(rule);

        // 恢复继承：从父目录继承默认权限
        security.SetAccessRuleProtection(isProtected: false, preserveInheritance: true);
        SetSecurity(path, security);
    }

    /// <summary>
    /// 检查 ACL 层是否已锁定（存在 Everyone 对删除/修改/写入的 Deny 规则）。
    /// </summary>
    private static bool IsAclLocked(string path)
    {
        try
        {
            var security = GetSecurity(path);
            return security
                .GetAccessRules(true, true, typeof(SecurityIdentifier))
                .Cast<FileSystemAccessRule>()
                .Any(r => r.AccessControlType == AccessControlType.Deny
                    && r.IdentityReference is SecurityIdentifier sid
                    && sid.Value == EveryoneSid.Value
                    && (r.FileSystemRights & DeniedRights) != 0);
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, $"读取 ACL 失败：{path}");
            return false;
        }
    }

    #endregion

    #region 属性层

    /// <summary>
    /// 设置 ReadOnly + Hidden 属性（保留既有属性）。
    /// </summary>
    private static void ApplyAttributeLock(string path)
    {
        var cur = File.GetAttributes(path);
        File.SetAttributes(path, cur | FileAttributes.ReadOnly | FileAttributes.Hidden);
    }

    /// <summary>
    /// 清除 ReadOnly + Hidden 属性。
    /// </summary>
    private static void ClearAttributeLock(string path)
    {
        try
        {
            var cur = File.GetAttributes(path);
            File.SetAttributes(path, cur & ~(FileAttributes.ReadOnly | FileAttributes.Hidden));
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, $"清除文件属性失败：{path}");
        }
    }

    /// <summary>
    /// 检查属性层是否已锁定（含 ReadOnly 或 Hidden）。
    /// </summary>
    private static bool IsAttributeLocked(string path)
    {
        try
        {
            var attr = File.GetAttributes(path);
            return (attr & (FileAttributes.ReadOnly | FileAttributes.Hidden)) != 0;
        }
        catch
        {
            return false;
        }
    }

    #endregion

    #region 标记文件层

    /// <summary>
    /// 写入 .lockfile 标记（含锁定时间与层级说明），并设置 ReadOnly + Hidden。
    /// </summary>
    private static void WriteMarker(string path)
    {
        var marker = GetMarkerPath(path);
        var sb = new StringBuilder();
        sb.AppendLine("LightGuard Backup Permission Lock");
        sb.AppendLine($"锁定时间：{DateTime.Now:yyyy-MM-dd HH:mm:ss}");
        sb.AppendLine($"目标：{Path.GetFileName(path.TrimEnd('\\', '/'))}");
        sb.AppendLine("层级：NTFS ACL + ReadOnly + Hidden + Marker");
        File.WriteAllText(marker, sb.ToString(), Encoding.UTF8);
        try { File.SetAttributes(marker, FileAttributes.ReadOnly | FileAttributes.Hidden); }
        catch (Exception ex) { ErrorReporter.Report(ex, $"设置标记文件属性失败：{marker}"); }
    }

    /// <summary>
    /// 删除 .lockfile 标记（先清除只读属性再删除）。
    /// </summary>
    private static void DeleteMarker(string path)
    {
        var marker = GetMarkerPath(path);
        if (!File.Exists(marker)) return;
        try { File.SetAttributes(marker, FileAttributes.Normal); }
        catch { /* 忽略属性设置失败 */ }
        try { File.Delete(marker); }
        catch (Exception ex) { ErrorReporter.Report(ex, $"删除标记文件失败：{marker}"); }
    }

    /// <summary>
    /// 检查标记文件是否存在。
    /// </summary>
    private static bool IsMarkerLocked(string path) => File.Exists(GetMarkerPath(path));

    /// <summary>
    /// 获取标记文件路径（备份路径 + .lockfile）。
    /// </summary>
    private static string GetMarkerPath(string path) => path + LockFileSuffix;

    #endregion

    #region ACL 读写辅助

    /// <summary>
    /// 读取文件或目录的 ACL（以 <see cref="FileSystemSecurity"/> 基类形式返回）。
    /// </summary>
    private static FileSystemSecurity GetSecurity(string path)
    {
        if (Directory.Exists(path))
            return new DirectoryInfo(path).GetAccessControl();
        return new FileInfo(path).GetAccessControl();
    }

    /// <summary>
    /// 写回文件或目录的 ACL。
    /// </summary>
    private static void SetSecurity(string path, FileSystemSecurity security)
    {
        if (Directory.Exists(path))
            new DirectoryInfo(path).SetAccessControl((DirectorySecurity)security);
        else
            new FileInfo(path).SetAccessControl((FileSecurity)security);
    }

    #endregion
}
