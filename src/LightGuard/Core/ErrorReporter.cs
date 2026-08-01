using System.Text;

namespace LightGuard.Core;

/// <summary>
/// 全局错误报告器
/// 所有异常记录到日志文件，通俗中文提示用户
/// </summary>
internal static class ErrorReporter
{
    public static void Report(Exception? ex, string context = "")
    {
        if (ex == null) return;

        try
        {
            var logDir = ConfigManager.GetLogDir();
            var logFile = Path.Combine(logDir, $"error_{DateTime.Now:yyyyMMdd}.log");

            var sb = new StringBuilder();
            sb.AppendLine($"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] {context}");
            sb.AppendLine($"  Type: {ex.GetType().Name}");
            sb.AppendLine($"  Message: {ex.Message}");
            sb.AppendLine($"  Stack: {ex.StackTrace}");
            if (ex.InnerException != null)
            {
                sb.AppendLine($"  Inner: {ex.InnerException.Message}");
            }
            sb.AppendLine();

            File.AppendAllText(logFile, sb.ToString());
        }
        catch { }
    }

    public static void Log(string message, string level = "INFO")
    {
        try
        {
            var logDir = ConfigManager.GetLogDir();
            var logFile = Path.Combine(logDir, $"app_{DateTime.Now:yyyyMMdd}.log");
            File.AppendAllText(logFile, $"[{DateTime.Now:HH:mm:ss}] [{level}] {message}\n");
        }
        catch { }
    }
}
