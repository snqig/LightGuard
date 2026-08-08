using LightGuard.Core;
using LightGuard.UI;

namespace LightGuard;

internal static class Program
{
    [STAThread]
    private static void Main(string[] args)
    {
        // 高 DPI 适配（P1-4：Per-Monitor DPI V2，manifest 已声明 PerMonitorV2）
        Application.SetHighDpiMode(HighDpiMode.PerMonitorV2);
        Application.EnableVisualStyles();
        Application.SetCompatibleTextRenderingDefault(false);

        // 全局异常捕获
        Application.ThreadException += (_, e) =>
            ErrorReporter.Report(e.Exception, "UI线程异常");
        AppDomain.CurrentDomain.UnhandledException += (_, e) =>
            ErrorReporter.Report(e.ExceptionObject as Exception, "未处理异常");

        // P0-4 权限重构方案A：高权限 Worker 子进程模式（免 UAC 提权 / runas 回退）
        // 必须在 UI 初始化之前执行：命中即无界面执行操作并退出
        if (PrivilegedWorker.TryHandleWorkerMode(args))
            return;

        // P0-10 安装器生命周期命令（MSI CustomAction 以管理员身份调用，无界面执行后退出）：
        // 安装后注册免 UAC 提权计划任务；卸载前注销，保证卸载不残留任务项。
        if (args.Contains("--register-elevation-task"))
        {
            Environment.ExitCode = PrivilegedWorker.EnsureElevationTaskRegistered() ? 0 : 1;
            return;
        }
        if (args.Contains("--unregister-elevation-task"))
        {
            Environment.ExitCode = PrivilegedWorker.UnregisterElevationTask() ? 0 : 1;
            return;
        }

        // P0-4 权限重构方案A（收尾）：UI 以普通权限运行（manifest=asInvoker）。
        // 非管理员直接进入应用（高危功能导航灰化 + Worker 提权执行）；
        // 管理员启动时注册免 UAC 提权计划任务（尽力而为，供后续 Worker 使用）。
        if (AdminChecker.IsRunningAsAdmin())
        {
            PrivilegedWorker.EnsureElevationTaskRegistered();
        }

        // 单实例检测
        if (!SingleInstance.TryAcquire())
        {
            MessageBoxHelper.Warn("LightGuard 已经在运行中，请勿重复启动。");
            return;
        }

        // 初始化全局状态
        var appState = AppState.Initialize();

        // 检测分发版本（P1-1：双版本分发架构 — MSI 安装版 + 便携版）
        // 在 AppState 初始化后、多语言系统初始化前执行，确保服务器版本使用英文
        DistributionProfile.DetectFromEnvironment();

        // P0-10 目录 ACL 兜底：服务器版数据目录（%ProgramData%\LightGuard）授予 Users Modify，
        // 保证 asInvoker 普通权限 UI 可读写共享数据（审计日志/病毒库/配置）。仅管理员生效，幂等。
        DirectoryAclConfigurator.ApplyAll();

        // 初始化多语言系统（P0-3）
        var initialLang = SupportedLanguage.ZhCN;
        var serverMode = false;
        try
        {
            if (DistributionProfile.IsServerEdition)
            {
                // 服务器版本：强制英文界面 + 英文审计日志模式
                initialLang = SupportedLanguage.EnUS;
                serverMode = true;
            }
            else
            {
                // 客户端版本：从用户配置恢复语言偏好
                if (Enum.TryParse<SupportedLanguage>(appState.Config.Language, out var savedLang))
                    initialLang = savedLang;
                serverMode = appState.Config.ServerLogMode;
            }
        }
        catch { /* 配置读取失败使用默认值 */ }
        LangHelper.Initialize(initialLang, serverMode);

        // 反杀毒误报：高危 API 延时初始化（P0-2）
        // 在后台线程执行延时初始化，不阻塞 UI 启动
        Task.Run(() => AntiFalsePositive.DelayedInit("startup"));

        // 启动应用
        Application.Run(new MainForm(appState));
    }
}
