using System.Diagnostics;
using System.Runtime.InteropServices;

namespace LightGuard.Core;

/// <summary>
/// 管理员权限检查与提权
/// </summary>
internal static class AdminChecker
{
    [DllImport("shell32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool IsUserAnAdmin();

    public static bool IsRunningAsAdmin()
    {
        try
        {
            using var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
            var principal = new System.Security.Principal.WindowsPrincipal(identity);
            return principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
        }
        catch
        {
            return IsUserAnAdmin();
        }
    }

    /// <summary>
    /// 以管理员身份重新启动程序
    /// </summary>
    public static void RestartAsAdmin()
    {
        try
        {
            var exePath = Application.ExecutablePath;
            var info = new ProcessStartInfo
            {
                FileName = exePath,
                UseShellExecute = true,
                Verb = "runas"
            };
            Process.Start(info);
        }
        catch
        {
            // 用户拒绝了 UAC 提升
            MessageBoxHelper.Warn("LightGuard 需要管理员权限才能运行，请以管理员身份重新启动。");
        }
        Application.Exit();
    }
}
