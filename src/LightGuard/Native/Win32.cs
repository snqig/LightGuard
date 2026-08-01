using System.Runtime.InteropServices;

namespace LightGuard.Native;

/// <summary>
/// Win32 API P/Invoke 声明
/// 包含：内存状态、窗口操作、DWM/Mica效果、文件属性、进程优先级等
/// </summary>
internal static class Win32
{
    #region 内存状态

    [StructLayout(LayoutKind.Sequential)]
    public struct MEMORYSTATUSEX
    {
        public uint dwLength;
        public uint dwMemoryLoad;
        public ulong ullTotalPhys;
        public ulong ullAvailPhys;
        public ulong ullTotalPageFile;
        public ulong ullAvailPageFile;
        public ulong ullTotalVirtual;
        public ulong ullAvailVirtual;
        public ulong ullAvailExtendedVirtual;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool GlobalMemoryStatusEx(ref MEMORYSTATUSEX lpBuffer);

    #endregion

    #region 用户输入空闲检测

    [StructLayout(LayoutKind.Sequential)]
    public struct LASTINPUTINFO
    {
        public uint cbSize;
        public uint dwTime;
    }

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool GetLastInputInfo(ref LASTINPUTINFO plii);

    #endregion

    #region 窗口操作

    [DllImport("user32.dll")]
    public static extern IntPtr GetForegroundWindow();

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool GetWindowRect(IntPtr hWnd, out RECT lpRect);

    [StructLayout(LayoutKind.Sequential)]
    public struct RECT
    {
        public int Left;
        public int Top;
        public int Right;
        public int Bottom;
    }

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    public static extern int MessageBox(IntPtr hWnd, string text, string caption, uint type);

    [DllImport("user32.dll")]
    public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

    [DllImport("user32.dll")]
    public static extern bool SetWindowPos(IntPtr hWnd, IntPtr hWndInsertAfter, int X, int Y, int cx, int cy, uint uFlags);

    #endregion

    #region DWM / Mica 云母效果

    // DWM Window Attributes
    public const int DWMWA_USE_IMMERSIVE_DARK_MODE = 20;
    public const int DWMWA_SYSTEMBACKDROP_TYPE = 38;
    public const int DWMWA_WINDOW_CORNER_PREFERENCE = 33;

    // Backdrop types
    public const int DWMSBT_AUTO = 0;
    public const int DWMSBT_NONE = 1;
    public const int DWMSBT_MAINWINDOW = 2; // Mica
    public const int DWMSBT_TRANSIENTWINDOW = 3; // Acrylic
    public const int DWMSBT_TABBEDWINDOW = 4; // Tabbed

    // Corner preferences
    public const int DWMWCP_DEFAULT = 0;
    public const int DWMWCP_DONOTROUND = 1;
    public const int DWMWCP_ROUND = 2;
    public const int DWMWCP_ROUNDSMALL = 3;

    [DllImport("dwmapi.dll")]
    public static extern int DwmSetWindowAttribute(IntPtr hwnd, int attr, ref int attrValue, int attrSize);

    [DllImport("dwmapi.dll")]
    public static extern int DwmExtendFrameIntoClientArea(IntPtr hdc, ref MARGINS pMarInset);

    [StructLayout(LayoutKind.Sequential)]
    public struct MARGINS
    {
        public int leftWidth;
        public int rightWidth;
        public int topHeight;
        public int bottomHeight;
    }

    /// <summary>
    /// 启用 Win11 Mica 云母效果
    /// </summary>
    public static bool EnableMica(IntPtr hwnd)
    {
        try
        {
            int backdrop = DWMSBT_MAINWINDOW;
            var result = DwmSetWindowAttribute(hwnd, DWMWA_SYSTEMBACKDROP_TYPE, ref backdrop, sizeof(int));
            return result == 0;
        }
        catch { return false; }
    }

    /// <summary>
    /// 启用深色模式标题栏
    /// </summary>
    public static bool EnableDarkMode(IntPtr hwnd)
    {
        try
        {
            int dark = 1;
            var result = DwmSetWindowAttribute(hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE, ref dark, sizeof(int));
            return result == 0;
        }
        catch { return false; }
    }

    /// <summary>
    /// 启用圆角窗口
    /// </summary>
    public static bool EnableRoundedCorners(IntPtr hwnd)
    {
        try
        {
            int corner = DWMWCP_ROUND;
            var result = DwmSetWindowAttribute(hwnd, DWMWA_WINDOW_CORNER_PREFERENCE, ref corner, sizeof(int));
            return result == 0;
        }
        catch { return false; }
    }

    #endregion

    #region 文件属性（伪装备份用）

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool SetFileAttributes(string lpFileName, uint dwFileAttributes);

    // File attributes
    public const uint FILE_ATTRIBUTE_HIDDEN = 0x00000002;
    public const uint FILE_ATTRIBUTE_SYSTEM = 0x00000004;
    public const uint FILE_ATTRIBUTE_READONLY = 0x00000001;

    /// <summary>
    /// 设置文件为系统隐藏只读（伪装防勒索）
    /// </summary>
    public static bool SetFileAsSystemHidden(string path)
    {
        uint attrs = FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_READONLY;
        return SetFileAttributes(path, attrs);
    }

    /// <summary>
    /// 恢复文件正常属性
    /// </summary>
    public static bool ResetFileAttributes(string path)
    {
        return SetFileAttributes(path, 0x80); // FILE_ATTRIBUTE_NORMAL
    }

    #endregion

    #region 进程优先级

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool SetProcessPriority(IntPtr hProcess, int priorityClass);

    public const int IDLE_PRIORITY_CLASS = 64;
    public const int BELOW_NORMAL_PRIORITY_CLASS = 16384;
    public const int NORMAL_PRIORITY_CLASS = 32;

    #endregion

    #region 系统版本检测

    [DllImport("ntdll.dll")]
    public static extern int RtlGetVersion(out OSVERSIONINFOEX versionInfo);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct OSVERSIONINFOEX
    {
        public int dwOSVersionInfoSize;
        public int dwMajorVersion;
        public int dwMinorVersion;
        public int dwBuildNumber;
        public int dwPlatformId;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
        public string szCSDVersion;
        public ushort wServicePackMajor;
        public ushort wServicePackMinor;
        public ushort wSuiteMask;
        public byte wProductType;
        public byte wReserved;
    }

    #endregion

    #region 系统托盘

    [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
    public static extern bool Shell_NotifyIcon(int dwMessage, ref NOTIFYICONDATA lpData);

    public const int NIM_ADD = 0x00000000;
    public const int NIM_MODIFY = 0x00000001;
    public const int NIM_DELETE = 0x00000002;

    public const int NIF_MESSAGE = 0x00000001;
    public const int NIF_ICON = 0x00000002;
    public const int NIF_TIP = 0x00000004;
    public const int NIF_INFO = 0x00000010;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct NOTIFYICONDATA
    {
        public int cbSize;
        public IntPtr hWnd;
        public int uID;
        public int uFlags;
        public int uCallbackMessage;
        public IntPtr hIcon;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
        public string szTip;
        public int dwState;
        public int dwStateMask;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
        public string szInfo;
        public int uTimeoutOrVersion;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
        public string szInfoTitle;
        public int dwInfoFlags;
    }

    #endregion

    #region 防火墙 COM API

    /// <summary>
    /// Windows Firewall COM 接口 CLSID
    /// </summary>
    public static readonly Guid CLSID_FwPolicy2 = new("{E2B3C97F-6AE1-41AC-817A-F6F92166D7DD}");
    public static readonly Guid IID_INetFwPolicy2 = new("{98325047-C671-4174-8D81-DEFCD3F0319E}");

    #endregion
}
