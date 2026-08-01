using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;
using LightGuard.Core;

namespace LightGuard.Firewall;

/// <summary>
/// NTFS 权限辅助类 — 通过 ACL 保护防火墙模块相关文件不被外部篡改。
/// 支持对 EXE 文件和 JSON 配置文件设置只读权限、批量操作及权限恢复。
/// </summary>
internal static class AclPermissionHelper
{
    /// <summary>
    /// 锁定 EXE 文件为只读状态。
    /// 通过 NTFS ACL 拒绝所有用户（Everyone）的修改、写入和删除权限。
    /// </summary>
    /// <param name="exePath">EXE 文件的完整路径。</param>
    /// <returns>成功锁定返回 true；失败返回 false。</returns>
    public static bool SetExeReadonlyAcl(string exePath)
    {
        try
        {
            if (!File.Exists(exePath))
            {
                ErrorReporter.Log($"待锁定的 EXE 文件不存在: {exePath}", "WARN");
                return false;
            }

            FileInfo fileInfo = new(exePath);
            FileSecurity security = fileInfo.GetAccessControl();

            NTAccount everyone = GetEveryoneIdentity();
            security.AddAccessRule(new FileSystemAccessRule(
                everyone,
                FileSystemRights.Write | FileSystemRights.Modify | FileSystemRights.Delete,
                AccessControlType.Deny));

            fileInfo.SetAccessControl(security);

            ErrorReporter.Log($"已成功锁定 EXE 文件: {exePath}", "INFO");
            return true;
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, $"SetExeReadonlyAcl: {exePath}");
            return false;
        }
    }

    /// <summary>
    /// 恢复 EXE 文件为默认权限。
    /// 移除由本工具添加的 Everyone 拒绝规则，并重置为继承的默认权限。
    /// </summary>
    /// <param name="exePath">EXE 文件的完整路径。</param>
    /// <returns>成功恢复返回 true；失败返回 false。</returns>
    public static bool RestoreExeDefaultAcl(string exePath)
    {
        try
        {
            if (!File.Exists(exePath))
            {
                ErrorReporter.Log($"待恢复的 EXE 文件不存在: {exePath}", "WARN");
                return false;
            }

            FileInfo fileInfo = new(exePath);
            FileSecurity security = fileInfo.GetAccessControl();

            RemoveEveryoneDenyRules(security);
            security.SetAccessRuleProtection(false, true);

            fileInfo.SetAccessControl(security);

            ErrorReporter.Log($"已恢复 EXE 文件默认权限: {exePath}", "INFO");
            return true;
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, $"RestoreExeDefaultAcl: {exePath}");
            return false;
        }
    }

    /// <summary>
    /// 批量锁定指定目录下所有 EXE 文件的权限。
    /// </summary>
    /// <param name="folderPath">目标目录路径。</param>
    /// <param name="recursive">是否递归处理子目录。</param>
    /// <returns>成功锁定的 EXE 文件数量。</returns>
    public static int BatchSetFolderExeAcl(string folderPath, bool recursive)
    {
        int count = 0;
        try
        {
            if (!Directory.Exists(folderPath))
            {
                ErrorReporter.Log($"目标目录不存在: {folderPath}", "WARN");
                return 0;
            }

            SearchOption option = recursive
                ? SearchOption.AllDirectories
                : SearchOption.TopDirectoryOnly;

            string[] exeFiles = Directory.GetFiles(folderPath, "*.exe", option);
            int total = exeFiles.Length;

            foreach (string exeFile in exeFiles)
            {
                if (SetExeReadonlyAcl(exeFile))
                {
                    count++;
                }
            }

            ErrorReporter.Log($"批量锁定完成 — 目录: {folderPath}，成功 {count}/{total} 个 EXE 文件", "INFO");
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, $"BatchSetFolderExeAcl: {folderPath}");
        }

        return count;
    }

    /// <summary>
    /// 批量恢复指定目录下所有 EXE 文件的默认权限。
    /// </summary>
    /// <param name="folderPath">目标目录路径。</param>
    /// <param name="recursive">是否递归处理子目录。</param>
    /// <returns>成功恢复的 EXE 文件数量。</returns>
    public static int BatchRestoreFolderExeAcl(string folderPath, bool recursive)
    {
        int count = 0;
        try
        {
            if (!Directory.Exists(folderPath))
            {
                ErrorReporter.Log($"目标目录不存在: {folderPath}", "WARN");
                return 0;
            }

            SearchOption option = recursive
                ? SearchOption.AllDirectories
                : SearchOption.TopDirectoryOnly;

            string[] exeFiles = Directory.GetFiles(folderPath, "*.exe", option);
            int total = exeFiles.Length;

            foreach (string exeFile in exeFiles)
            {
                if (RestoreExeDefaultAcl(exeFile))
                {
                    count++;
                }
            }

            ErrorReporter.Log($"批量恢复完成 — 目录: {folderPath}，成功 {count}/{total} 个 EXE 文件", "INFO");
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, $"BatchRestoreFolderExeAcl: {folderPath}");
        }

        return count;
    }

    /// <summary>
    /// 锁定 JSON 配置文件为只读状态，防止外部篡改。
    /// 通过 NTFS ACL 拒绝所有用户（Everyone）的修改、写入和删除权限。
    /// </summary>
    /// <param name="configPath">配置文件的完整路径。</param>
    /// <returns>成功锁定返回 true；失败返回 false。</returns>
    public static bool LockConfigFile(string configPath)
    {
        try
        {
            if (!File.Exists(configPath))
            {
                ErrorReporter.Log($"待锁定的配置文件不存在: {configPath}", "WARN");
                return false;
            }

            FileInfo fileInfo = new(configPath);
            FileSecurity security = fileInfo.GetAccessControl();

            NTAccount everyone = GetEveryoneIdentity();
            security.AddAccessRule(new FileSystemAccessRule(
                everyone,
                FileSystemRights.Write | FileSystemRights.Modify | FileSystemRights.Delete,
                AccessControlType.Deny));

            fileInfo.SetAccessControl(security);

            ErrorReporter.Log($"已成功锁定配置文件: {configPath}", "INFO");
            return true;
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, $"LockConfigFile: {configPath}");
            return false;
        }
    }

    /// <summary>
    /// 解锁配置文件，移除由本工具添加的拒绝规则并恢复默认权限。
    /// </summary>
    /// <param name="configPath">配置文件的完整路径。</param>
    /// <returns>成功解锁返回 true；失败返回 false。</returns>
    public static bool UnlockConfigFile(string configPath)
    {
        try
        {
            if (!File.Exists(configPath))
            {
                ErrorReporter.Log($"待解锁的配置文件不存在: {configPath}", "WARN");
                return false;
            }

            FileInfo fileInfo = new(configPath);
            FileSecurity security = fileInfo.GetAccessControl();

            RemoveEveryoneDenyRules(security);
            security.SetAccessRuleProtection(false, true);

            fileInfo.SetAccessControl(security);

            ErrorReporter.Log($"已解锁配置文件: {configPath}", "INFO");
            return true;
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, $"UnlockConfigFile: {configPath}");
            return false;
        }
    }

    /// <summary>
    /// 获取 Everyone 账户的身份标识。
    /// </summary>
    /// <returns>表示 Everyone 账户的 NTAccount 实例。</returns>
    private static NTAccount GetEveryoneIdentity()
    {
        return new NTAccount("Everyone");
    }

    /// <summary>
    /// 从指定的文件安全描述符中移除所有针对 Everyone 账户的拒绝访问规则。
    /// </summary>
    /// <param name="security">文件安全描述符。</param>
    private static void RemoveEveryoneDenyRules(FileSecurity security)
    {
        NTAccount everyone = GetEveryoneIdentity();
        AuthorizationRuleCollection rules = security.GetAccessRules(true, true, typeof(NTAccount));

        foreach (AuthorizationRule item in rules)
        {
            if (item is FileSystemAccessRule rule &&
                rule.AccessControlType == AccessControlType.Deny &&
                string.Equals(rule.IdentityReference.Value, everyone.Value, StringComparison.OrdinalIgnoreCase))
            {
                security.RemoveAccessRule(rule);
            }
        }
    }
}
