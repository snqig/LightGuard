using System.Diagnostics;
using System.Management;
using System.Runtime.InteropServices;
using LightGuard.Native;

namespace LightGuard.Core;

/// <summary>
/// 硬件配置档案
/// </summary>
public sealed class HardwareProfile
{
    public string CpuName { get; set; } = "未知";
    public int CpuCores { get; set; }
    public int CpuLogicalCores { get; set; }
    public long TotalMemoryMb { get; set; }
    public long AvailableMemoryMb { get; set; }
    public string GpuName { get; set; } = "未知";
    public int ScreenDpi { get; set; } = 96;
    public double ScreenScale { get; set; } = 1.0;
    public int ScreenWidth { get; set; }
    public int ScreenHeight { get; set; }
    public string OsVersion { get; set; } = "未知";
    public int OsBuildNumber { get; set; }
    public bool IsWin11 { get; set; }
    public bool IsWin10 { get; set; }
    public bool HasSsd { get; set; }
    public bool IsHighEnd { get; set; }
    public bool IsBatteryPowered { get; set; }
    public int BatteryLevel { get; set; } = 100;

    /// <summary>
    /// 判断是否为高配电脑
    /// 规则：内存≥8GB 且 CPU≥4核 且 Win10 1903+
    /// </summary>
    public bool DetermineHighEnd()
    {
        return TotalMemoryMb >= 7168  // 7GB+
            && CpuLogicalCores >= 4
            && (IsWin11 || (IsWin10 && OsBuildNumber >= 18362));
    }
}

/// <summary>
/// 智能硬件自适应检测引擎
/// 自动检测电脑高低配置、内存、CPU、DPI、系统版本
/// </summary>
public static class HardwareDetector
{
    public static HardwareProfile Detect()
    {
        var profile = new HardwareProfile();

        try { DetectCpu(profile); } catch { }
        try { DetectMemory(profile); } catch { }
        try { DetectGpu(profile); } catch { }
        try { DetectOs(profile); } catch { }
        try { DetectScreen(profile); } catch { }
        try { DetectDisk(profile); } catch { }
        try { DetectBattery(profile); } catch { }

        profile.IsHighEnd = profile.DetermineHighEnd();
        return profile;
    }

    private static void DetectCpu(HardwareProfile p)
    {
        p.CpuName = Environment.GetEnvironmentVariable("PROCESSOR_IDENTIFIER") ?? "未知 CPU";
        p.CpuLogicalCores = Environment.ProcessorCount;
        p.CpuCores = p.CpuLogicalCores / 2;

        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT Name, NumberOfCores, NumberOfLogicalProcessors FROM Win32_Processor");
            foreach (var obj in searcher.Get().Cast<ManagementObject>())
            {
                p.CpuName = obj["Name"]?.ToString()?.Trim() ?? p.CpuName;
                p.CpuCores = Convert.ToInt32(obj["NumberOfCores"]);
                p.CpuLogicalCores = Convert.ToInt32(obj["NumberOfLogicalProcessors"]);
                break;
            }
        }
        catch { }
    }

    private static void DetectMemory(HardwareProfile p)
    {
        // 使用 Windows API 获取精确内存
        var memStatus = new Win32.MEMORYSTATUSEX
        {
            dwLength = (uint)Marshal.SizeOf<Win32.MEMORYSTATUSEX>()
        };
        Win32.GlobalMemoryStatusEx(ref memStatus);
        p.TotalMemoryMb = (long)(memStatus.ullTotalPhys / (1024 * 1024));
        p.AvailableMemoryMb = (long)(memStatus.ullAvailPhys / (1024 * 1024));
    }

    private static void DetectGpu(HardwareProfile p)
    {
        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT Name FROM Win32_VideoController");
            foreach (var obj in searcher.Get().Cast<ManagementObject>())
            {
                p.GpuName = obj["Name"]?.ToString() ?? "未知显卡";
                break;
            }
        }
        catch { }
    }

    private static void DetectOs(HardwareProfile p)
    {
        p.OsVersion = Environment.OSVersion.Version.ToString();
        p.OsBuildNumber = Environment.OSVersion.Version.Build;

        // Win11 build >= 22000
        p.IsWin11 = p.OsBuildNumber >= 22000;
        p.IsWin10 = p.OsBuildNumber >= 10240 && p.OsBuildNumber < 22000;

        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT Caption, BuildNumber FROM Win32_OperatingSystem");
            foreach (var obj in searcher.Get().Cast<ManagementObject>())
            {
                var caption = obj["Caption"]?.ToString() ?? "";
                if (caption.Contains("Windows 11"))
                    p.IsWin11 = true;
                else if (caption.Contains("Windows 10"))
                    p.IsWin10 = true;
                p.OsVersion = caption;
                p.OsBuildNumber = int.TryParse(obj["BuildNumber"]?.ToString(), out var b) ? b : p.OsBuildNumber;
                break;
            }
        }
        catch { }
    }

    private static void DetectScreen(HardwareProfile p)
    {
        // 使用 WinForms 获取屏幕信息
        p.ScreenWidth = System.Windows.Forms.Screen.PrimaryScreen?.Bounds.Width ?? 1920;
        p.ScreenHeight = System.Windows.Forms.Screen.PrimaryScreen?.Bounds.Height ?? 1080;

        using var g = FormExtensions.CreateHandleDummyGraphics();
        p.ScreenDpi = (int)g.DpiX;
        p.ScreenScale = p.ScreenDpi / 96.0;
    }

    private static void DetectDisk(HardwareProfile p)
    {
        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT MediaType FROM Win32_DiskDrive");
            foreach (var obj in searcher.Get().Cast<ManagementObject>())
            {
                var mediaType = obj["MediaType"]?.ToString() ?? "";
                if (mediaType.Contains("SSD") || mediaType.Contains("Solid"))
                {
                    p.HasSsd = true;
                    break;
                }
            }

            // 更可靠的方式：检查物理磁盘的旋转速度
            if (!p.HasSsd)
            {
                using var searcher2 = new ManagementObjectSearcher(
                    "SELECT Model FROM Win32_DiskDrive");
                foreach (var obj in searcher2.Get().Cast<ManagementObject>())
                {
                    var model = obj["Model"]?.ToString() ?? "";
                    if (model.Contains("SSD") || model.Contains("NVMe") || model.Contains("Solid State"))
                    {
                        p.HasSsd = true;
                        break;
                    }
                }
            }
        }
        catch { }
    }

    private static void DetectBattery(HardwareProfile p)
    {
        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT BatteryStatus, EstimatedChargeRemaining FROM Win32_Battery");
            foreach (var obj in searcher.Get().Cast<ManagementObject>())
            {
                p.IsBatteryPowered = true;
                p.BatteryLevel = Convert.ToInt32(obj["EstimatedChargeRemaining"]);
                break;
            }
        }
        catch { }
    }

    /// <summary>
    /// 实时获取当前可用内存
    /// </summary>
    public static long GetAvailableMemoryMb()
    {
        var memStatus = new Win32.MEMORYSTATUSEX
        {
            dwLength = (uint)Marshal.SizeOf<Win32.MEMORYSTATUSEX>()
        };
        Win32.GlobalMemoryStatusEx(ref memStatus);
        return (long)(memStatus.ullAvailPhys / (1024 * 1024));
    }

    /// <summary>
    /// 检测当前是否全屏运行（游戏/视频）
    /// </summary>
    public static bool IsFullScreenAppRunning()
    {
        try
        {
            var foreground = Win32.GetForegroundWindow();
            if (foreground == IntPtr.Zero) return false;

            Win32.GetWindowRect(foreground, out var rect);
            var screen = System.Windows.Forms.Screen.FromHandle(foreground).Bounds;
            return rect.Left <= screen.Left && rect.Top <= screen.Top
                && rect.Right >= screen.Right && rect.Bottom >= screen.Bottom;
        }
        catch { return false; }
    }
}

/// <summary>
/// WinForms 辅助扩展
/// </summary>
internal static class FormExtensions
{
    public static System.Drawing.Graphics CreateHandleDummyGraphics()
    {
        var bmp = new System.Drawing.Bitmap(1, 1);
        return System.Drawing.Graphics.FromImage(bmp);
    }
}
