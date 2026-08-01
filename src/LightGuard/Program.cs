using LightGuard.Core;
using LightGuard.UI;

namespace LightGuard;

internal static class Program
{
    [STAThread]
    private static void Main()
    {
        // 高 DPI 适配
        Application.SetHighDpiMode(HighDpiMode.SystemAware);
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

        // 启动应用
        Application.Run(new MainForm(appState));
    }
}
