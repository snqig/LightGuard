using Microsoft.Win32;

namespace LightGuard.Native;

/// <summary>
/// 注册表操作助手
/// 支持读取、写入、备份、还原注册表项
/// 用于隐私加固和流氓软件净化模块
/// </summary>
public static class RegistryHelper
{
    /// <summary>
    /// 安全设置注册表值（自动创建不存在的键）
    /// </summary>
    public static bool SetValue(RegistryHive hive, string path, string name, object value, RegistryValueKind kind = RegistryValueKind.DWord)
    {
        try
        {
            var root = hive == RegistryHive.LocalMachine ? Registry.LocalMachine : Registry.CurrentUser;
            using var key = root.OpenSubKey(path, RegistryKeyPermissionCheck.ReadWriteSubTree)
                ?? root.CreateSubKey(path, RegistryKeyPermissionCheck.ReadWriteSubTree);
            key.SetValue(name, value, kind);
            return true;
        }
        catch
        {
            // 如果指定根键失败，尝试另一个根键
            try
            {
                var altRoot = hive == RegistryHive.LocalMachine ? Registry.CurrentUser : Registry.LocalMachine;
                using var key = altRoot.OpenSubKey(path, RegistryKeyPermissionCheck.ReadWriteSubTree)
                    ?? altRoot.CreateSubKey(path, RegistryKeyPermissionCheck.ReadWriteSubTree);
                key.SetValue(name, value, kind);
                return true;
            }
            catch { return false; }
        }
    }

    /// <summary>
    /// 读取注册表值
    /// </summary>
    public static object? GetValue(RegistryHive hive, string path, string name)
    {
        try
        {
            var root = hive == RegistryHive.LocalMachine ? Registry.LocalMachine : Registry.CurrentUser;
            using var key = root.OpenSubKey(path);
            return key?.GetValue(name);
        }
        catch { return null; }
    }

    /// <summary>
    /// 读取 DWORD 值
    /// </summary>
    public static int GetDWord(RegistryHive hive, string path, string name, int defaultValue = 0)
    {
        var val = GetValue(hive, path, name);
        return val is int i ? i : defaultValue;
    }

    /// <summary>
    /// 删除注册表值
    /// </summary>
    public static bool DeleteValue(RegistryHive hive, string path, string name)
    {
        try
        {
            var root = hive == RegistryHive.LocalMachine ? Registry.LocalMachine : Registry.CurrentUser;
            using var key = root.OpenSubKey(path, RegistryKeyPermissionCheck.ReadWriteSubTree);
            key?.DeleteValue(name, false);
            return true;
        }
        catch { return false; }
    }

    /// <summary>
    /// 备份注册表项到 .reg 文件
    /// </summary>
    public static string BackupRegistryKey(RegistryHive hive, string path, string backupDir)
    {
        try
        {
            Directory.CreateDirectory(backupDir);
            var safeName = path.Replace('\\', '_').Replace("/", "_").TrimStart('_');
            var fileName = $"reg_{hive}_{safeName}_{DateTime.Now:yyyyMMdd_HHmmss}.reg";
            var filePath = Path.Combine(backupDir, fileName);

            var root = hive == RegistryHive.LocalMachine ? "HKEY_LOCAL_MACHINE" : "HKEY_CURRENT_USER";
            var fullKey = $"{root}\\{path}";

            // 使用 reg export 命令导出
            var psi = new System.Diagnostics.ProcessStartInfo
            {
                FileName = "reg.exe",
                Arguments = $"export \"{fullKey}\" \"{filePath}\" /y",
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };

            using var proc = System.Diagnostics.Process.Start(psi);
            proc?.WaitForExit(10000);

            return File.Exists(filePath) ? filePath : "";
        }
        catch { return ""; }
    }

    /// <summary>
    /// 从 .reg 文件还原注册表项
    /// </summary>
    public static bool RestoreRegistryKey(string regFilePath)
    {
        try
        {
            if (!File.Exists(regFilePath)) return false;

            var psi = new System.Diagnostics.ProcessStartInfo
            {
                FileName = "reg.exe",
                Arguments = $"import \"{regFilePath}\"",
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };

            using var proc = System.Diagnostics.Process.Start(psi);
            proc?.WaitForExit(10000);
            return proc?.ExitCode == 0;
        }
        catch { return false; }
    }

    /// <summary>
    /// 检查注册表项是否存在
    /// </summary>
    public static bool KeyExists(RegistryHive hive, string path)
    {
        try
        {
            var root = hive == RegistryHive.LocalMachine ? Registry.LocalMachine : Registry.CurrentUser;
            using var key = root.OpenSubKey(path);
            return key != null;
        }
        catch { return false; }
    }

    /// <summary>
    /// 检查某个软件是否已安装（通过卸载注册表）
    /// </summary>
    public static bool IsSoftwareInstalled(string displayName)
    {
        var paths = new[]
        {
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
        };

        foreach (var path in paths)
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(path);
                if (key == null) continue;

                foreach (var subKeyName in key.GetSubKeyNames())
                {
                    using var subKey = key.OpenSubKey(subKeyName);
                    var name = subKey?.GetValue("DisplayName")?.ToString();
                    if (name != null && name.Contains(displayName, StringComparison.OrdinalIgnoreCase))
                        return true;
                }
            }
            catch { }
        }

        return false;
    }

    /// <summary>
    /// 获取已安装软件列表
    /// </summary>
    public static List<SoftwareInfo> GetInstalledSoftware()
    {
        var list = new List<SoftwareInfo>();
        var paths = new[]
        {
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
        };

        foreach (var path in paths)
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(path);
                if (key == null) continue;

                foreach (var subKeyName in key.GetSubKeyNames())
                {
                    using var subKey = key.OpenSubKey(subKeyName);
                    var name = subKey?.GetValue("DisplayName")?.ToString();
                    if (string.IsNullOrEmpty(name)) continue;

                    list.Add(new SoftwareInfo
                    {
                        DisplayName = name,
                        Version = subKey?.GetValue("DisplayVersion")?.ToString() ?? "",
                        InstallPath = subKey?.GetValue("InstallLocation")?.ToString() ?? "",
                        UninstallString = subKey?.GetValue("UninstallString")?.ToString() ?? "",
                        Publisher = subKey?.GetValue("Publisher")?.ToString() ?? ""
                    });
                }
            }
            catch { }
        }

        return list;
    }
}

public sealed class SoftwareInfo
{
    public string DisplayName { get; set; } = "";
    public string Version { get; set; } = "";
    public string InstallPath { get; set; } = "";
    public string UninstallString { get; set; } = "";
    public string Publisher { get; set; } = "";
}
