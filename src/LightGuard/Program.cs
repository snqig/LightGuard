using LightGuard.Core;
using LightGuard.UI;

namespace LightGuard;

internal static class Program
{
    [STAThread]
    private static void Main()
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

        // 检查管理员权限
        if (!AdminChecker.IsRunningAsAdmin())
        {
            AdminChecker.RestartAsAdmin();
            return;
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
