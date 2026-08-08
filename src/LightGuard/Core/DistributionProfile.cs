// © 2026 落尘（Luochen） 原创开发 - 保留所有权利

using Microsoft.Win32;
using System.Management;

namespace LightGuard.Core;

/// <summary>
/// 分发版本枚举。
/// <para>Client：完整 UI、全部功能、多语言、动画特效。</para>
/// <para>Server：精简 UI、英文日志、禁用动画、仅英文语言包。</para>
/// </summary>
public enum DistributionEdition
{
    /// <summary>客户端版本 — 完整 UI、全功能、多语言、动画特效</summary>
    Client,

    /// <summary>服务器版本 — 精简 UI、英文审计日志、禁用动画/图表、仅英文</summary>
    Server
}

/// <summary>
/// 部署形态枚举。
/// <para>Installed：MSI 目录部署（Program Files），支持文件级差分增量更新。</para>
/// <para>Portable：绿色便携版（单 EXE 免安装），软件本体更新走全量包替换。</para>
/// </summary>
public enum DeploymentMode
{
    /// <summary>MSI 安装部署（目录部署，可差分更新）</summary>
    Installed,

    /// <summary>绿色便携部署（单 EXE / 自定义目录）</summary>
    Portable
}

/// <summary>
/// 分发版本配置文件 — 根据运行环境自动检测并应用 Client/Server 配置。
/// <para>P1-1：双版本分发架构（MSI 安装版 + 便携版）。</para>
/// <para>调用规范：在 AppState.Initialize() 之后、LangHelper.Initialize() 之前调用 DetectFromEnvironment()。</para>
/// </summary>
public static class DistributionProfile
{
    /// <summary>当前分发版本</summary>
    public static DistributionEdition Edition { get; private set; } = DistributionEdition.Client;

    /// <summary>是否为服务器版本</summary>
    public static bool IsServerEdition => Edition == DistributionEdition.Server;

    /// <summary>是否启用动画特效（服务器版本禁用）</summary>
    public static bool EnableAnimations => !IsServerEdition;

    /// <summary>是否启用图表模块（服务器版本禁用）</summary>
    public static bool EnableCharts => !IsServerEdition;

    /// <summary>
    /// 支持的语言列表。
    /// <para>客户端版本：简体中文、英文、繁体中文。</para>
    /// <para>服务器版本：仅英文。</para>
    /// </summary>
    public static List<SupportedLanguage> SupportedLanguages =>
        IsServerEdition
            ? new() { SupportedLanguage.EnUS }
            : new() { SupportedLanguage.ZhCN, SupportedLanguage.EnUS, SupportedLanguage.ZhTW };

    /// <summary>
    /// 最大日志文件保留数量。
    /// <para>服务器版本：365 天（长期审计）；客户端版本：30 天。</para>
    /// </summary>
    public static int MaxLogFiles => IsServerEdition ? 365 : 30;

    /// <summary>
    /// 自定义数据目录。
    /// <para>服务器版本：%ProgramData%\LightGuard（系统级、跨用户共享）。</para>
    /// <para>客户端版本：%APPDATA%\LightGuard\data（用户级）。</para>
    /// </summary>
    public static string DataDir { get; private set; } = string.Empty;

    /// <summary>是否已初始化</summary>
    public static bool IsInitialized { get; private set; }

    /// <summary>
    /// 部署形态。
    /// <para>Installed：MSI 目录部署（Program Files），支持文件级差分增量更新。</para>
    /// <para>Portable：绿色便携版（单 EXE 免安装），软件本体更新走全量包替换。</para>
    /// </summary>
    public static DeploymentMode Mode { get; private set; } = DeploymentMode.Installed;

    /// <summary>是否为便携版部署。</summary>
    public static bool IsPortable => Mode == DeploymentMode.Portable;

    /// <summary>
    /// 手动初始化指定版本。
    /// </summary>
    /// <param name="edition">目标分发版本</param>
    public static void Initialize(DistributionEdition edition)
    {
        Edition = edition;
        IsInitialized = true;
        ApplyEditionSettings();
    }

    /// <summary>
    /// 从运行环境自动检测分发版本。检测顺序：
    /// <list type="number">
    ///   <item>环境变量 LIGHTGUARD_SERVER=1</item>
    ///   <item>应用目录下存在 server.mode 标记文件</item>
    ///   <item>注册表检测 Windows Server（HKLM\...\ProductName 含 "Server"）</item>
    ///   <item>WMI 检测 Win32_OperatingSystem.ProductType != 1</item>
    /// </list>
    /// </summary>
    public static void DetectFromEnvironment()
    {
        // 0. 检测部署形态（便携版标记优先于服务器标记，互不冲突）
        DetectDeploymentMode();

        // 1. 检查环境变量 LIGHTGUARD_SERVER
        var envServer = Environment.GetEnvironmentVariable("LIGHTGUARD_SERVER");
        if (string.Equals(envServer, "1", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(envServer, "true", StringComparison.OrdinalIgnoreCase))
        {
            Initialize(DistributionEdition.Server);
            ErrorReporter.Log("检测到 LIGHTGUARD_SERVER 环境变量，启用服务器版本", "INFO");
            return;
        }

        // 2. 检查应用目录下的 server.mode 标记文件
        var serverModePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "server.mode");
        if (File.Exists(serverModePath))
        {
            Initialize(DistributionEdition.Server);
            ErrorReporter.Log("检测到 server.mode 标记文件，启用服务器版本", "INFO");
            return;
        }

        // 3. 检查是否运行在 Windows Server
        if (IsRunningOnWindowsServer())
        {
            Initialize(DistributionEdition.Server);
            ErrorReporter.Log("检测到 Windows Server 操作系统，启用服务器版本", "INFO");
            return;
        }

        // 默认：客户端版本
        Initialize(DistributionEdition.Client);
        ErrorReporter.Log("未检测到服务器环境，启用客户端版本", "INFO");
    }

    /// <summary>
    /// 检测部署形态（便携版 / 安装版）。检测顺序：
    /// <list type="number">
    ///   <item>环境变量 LIGHTGUARD_PORTABLE=1</item>
    ///   <item>应用目录下存在 portable.mode 标记文件（build-portable.ps1 写入）</item>
    ///   <item>应用目录不在 Program Files 下 → 视为便携（U盘/自定义目录免安装运行）</item>
    /// </list>
    /// </summary>
    private static void DetectDeploymentMode()
    {
        try
        {
            var envPortable = Environment.GetEnvironmentVariable("LIGHTGUARD_PORTABLE");
            if (string.Equals(envPortable, "1", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(envPortable, "true", StringComparison.OrdinalIgnoreCase))
            {
                Mode = DeploymentMode.Portable;
                ErrorReporter.Log("检测到 LIGHTGUARD_PORTABLE 环境变量，启用便携部署模式", "INFO");
                return;
            }

            var baseDir = AppDomain.CurrentDomain.BaseDirectory;
            if (File.Exists(Path.Combine(baseDir, "portable.mode")))
            {
                Mode = DeploymentMode.Portable;
                ErrorReporter.Log("检测到 portable.mode 标记文件，启用便携部署模式", "INFO");
                return;
            }

            // 安装在 Program Files 下 → 安装版；否则视为便携（U盘/绿色运行）
            var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
            var programFilesX86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
            var inProgramFiles =
                (programFiles.Length > 0 && baseDir.StartsWith(programFiles, StringComparison.OrdinalIgnoreCase)) ||
                (programFilesX86.Length > 0 && baseDir.StartsWith(programFilesX86, StringComparison.OrdinalIgnoreCase));
            Mode = inProgramFiles ? DeploymentMode.Installed : DeploymentMode.Portable;
            ErrorReporter.Log($"未检测到便携标记，按安装目录判定部署模式：{Mode}", "INFO");
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, "部署形态检测失败，默认安装版");
            Mode = DeploymentMode.Installed;
        }
    }

    /// <summary>
    /// 检测是否运行在 Windows Server 上。
    /// 优先使用注册表，回退到 WMI 查询。
    /// </summary>
    private static bool IsRunningOnWindowsServer()
    {
        // 方法 1：注册表 ProductName 包含 "Server"
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows NT\CurrentVersion", writable: false);
            if (key != null)
            {
                if (key.GetValue("ProductName") is string productName &&
                    productName.Contains("Server", StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }

                // InstallationType = "Server" / "Server Core" 也表明是服务器
                if (key.GetValue("InstallationType") is string installType &&
                    installType.StartsWith("Server", StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }
        }
        catch
        {
            // 注册表访问失败（权限不足或非 Windows），继续尝试 WMI
        }

        // 方法 2：WMI 查询 Win32_OperatingSystem.ProductType
        // ProductType: 1 = 工作站, 2 = 域控制器, 3 = 服务器
        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT ProductType FROM Win32_OperatingSystem");
            foreach (var obj in searcher.Get())
            {
                if (obj["ProductType"] != null)
                {
                    var productType = Convert.ToUInt32(obj["ProductType"]);
                    if (productType != 1)
                        return true;
                }
                obj.Dispose();
            }
        }
        catch
        {
            // WMI 查询失败，保守判定为非服务器
        }

        return false;
    }

    /// <summary>
    /// 应用版本特定的配置。
    /// </summary>
    private static void ApplyEditionSettings()
    {
        if (IsServerEdition)
        {
            // 服务器版本：数据目录在 ProgramData（系统级、跨用户共享）
            DataDir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "LightGuard");
            try
            {
                Directory.CreateDirectory(DataDir);
            }
            catch
            {
                // 目录创建失败不阻断初始化
            }
        }
        else
        {
            // 客户端版本：数据目录在 %APPDATA%\LightGuard\data（用户级）
            DataDir = ConfigManager.GetDataDir();
        }

        ErrorReporter.Log(
            $"分发版本配置已应用: Edition={Edition}, DataDir={DataDir}, " +
            $"EnableAnimations={EnableAnimations}, EnableCharts={EnableCharts}, " +
            $"MaxLogFiles={MaxLogFiles}, Languages=[{string.Join(", ", SupportedLanguages)}]",
            "INFO");
    }
}
