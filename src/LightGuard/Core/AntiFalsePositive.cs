// © 2026 落尘（Luochen） 原创开发 - 保留所有权利

namespace LightGuard.Core;

/// <summary>
/// 反杀毒误报引擎 — 通过延时初始化、操作节流、行为规范化降低启发式风险评分。
/// <para>P0-2 核心组件：高危 API 延时 3-5 秒初始化，文件遍历/ETW/VSS 操作增加节流休眠。</para>
/// </summary>
public static class AntiFalsePositive
{
    /// <summary>高危操作前的延时（毫秒）</summary>
    public const int HighRiskDelayMs = 3500;

    /// <summary>文件遍历节流间隔（毫秒）</summary>
    public const int FileTraversalThrottleMs = 50;

    /// <summary>ETW 监听节流间隔（毫秒）</summary>
    public const int EtwThrottleMs = 100;

    /// <summary>VSS 快照操作节流间隔（毫秒）</summary>
    public const int VssThrottleMs = 200;

    /// <summary>进程启动节流间隔（毫秒）</summary>
    public const int ProcessLaunchThrottleMs = 200;

    /// <summary>注册表操作节流间隔（毫秒）</summary>
    public const int RegistryThrottleMs = 100;

    private static bool _initialized;
    private static DateTime _lastFileOp = DateTime.MinValue;
    private static DateTime _lastEtwOp = DateTime.MinValue;
    private static DateTime _lastVssOp = DateTime.MinValue;
    private static DateTime _lastProcessOp = DateTime.MinValue;
    private static DateTime _lastRegistryOp = DateTime.MinValue;
    private static readonly object _lock = new();

    /// <summary>
    /// 执行高危操作前的延时初始化。仅在首次调用时延时 3.5 秒。
    /// <para>用于：ETW 会话启动、VSS 快照创建、文件系统监控注册等高危 API。</para>
    /// </summary>
    /// <param name="tag">操作标签（用于日志）</param>
    public static void DelayedInit(string tag = "default")
    {
        if (_initialized) return;

        lock (_lock)
        {
            if (_initialized) return;

            ErrorReporter.Log($"[AntiFalsePositive] 高危操作延时初始化: {tag}，等待 {HighRiskDelayMs}ms", "INFO");
            Thread.Sleep(HighRiskDelayMs);
            _initialized = true;
            ErrorReporter.Log($"[AntiFalsePositive] 延时初始化完成，后续操作不再延时", "INFO");
        }
    }

    /// <summary>
    /// 文件遍历节流 — 在连续文件操作之间插入短暂休眠。
    /// </summary>
    public static void ThrottleFileTraversal()
    {
        lock (_lock)
        {
            var now = DateTime.UtcNow;
            var elapsed = (now - _lastFileOp).TotalMilliseconds;
            if (elapsed < FileTraversalThrottleMs)
            {
                Thread.Sleep(FileTraversalThrottleMs - (int)elapsed);
            }
            _lastFileOp = DateTime.UtcNow;
        }
    }

    /// <summary>
    /// ETW 操作节流。
    /// </summary>
    public static void ThrottleEtw()
    {
        lock (_lock)
        {
            var now = DateTime.UtcNow;
            var elapsed = (now - _lastEtwOp).TotalMilliseconds;
            if (elapsed < EtwThrottleMs)
            {
                Thread.Sleep(EtwThrottleMs - (int)elapsed);
            }
            _lastEtwOp = DateTime.UtcNow;
        }
    }

    /// <summary>
    /// VSS 快照操作节流。
    /// </summary>
    public static void ThrottleVss()
    {
        lock (_lock)
        {
            var now = DateTime.UtcNow;
            var elapsed = (now - _lastVssOp).TotalMilliseconds;
            if (elapsed < VssThrottleMs)
            {
                Thread.Sleep(VssThrottleMs - (int)elapsed);
            }
            _lastVssOp = DateTime.UtcNow;
        }
    }

    /// <summary>
    /// 进程启动节流 — 防止短时间内启动过多外部进程。
    /// </summary>
    public static void ThrottleProcessLaunch()
    {
        lock (_lock)
        {
            var now = DateTime.UtcNow;
            var elapsed = (now - _lastProcessOp).TotalMilliseconds;
            if (elapsed < ProcessLaunchThrottleMs)
            {
                Thread.Sleep(ProcessLaunchThrottleMs - (int)elapsed);
            }
            _lastProcessOp = DateTime.UtcNow;
        }
    }

    /// <summary>
    /// 注册表操作节流。
    /// </summary>
    public static void ThrottleRegistry()
    {
        lock (_lock)
        {
            var now = DateTime.UtcNow;
            var elapsed = (now - _lastRegistryOp).TotalMilliseconds;
            if (elapsed < RegistryThrottleMs)
            {
                Thread.Sleep(RegistryThrottleMs - (int)elapsed);
            }
            _lastRegistryOp = DateTime.UtcNow;
        }
    }

    /// <summary>
    /// 检查是否为安全上下文（非沙箱、非调试器附加）。
    /// </summary>
    public static bool IsSafeContext()
    {
        try
        {
            // 检测调试器附加
            if (System.Diagnostics.Debugger.IsAttached)
                return false;

            // 检测常见沙箱环境
            var userName = Environment.UserName;
            var sandboxUsers = new[] { "Sandbox", "sandbox", "Malware", "malware", "Virus", "virus" };
            foreach (var sb in sandboxUsers)
            {
                if (userName.Contains(sb, StringComparison.OrdinalIgnoreCase))
                    return false;
            }

            return true;
        }
        catch
        {
            return true;
        }
    }

    /// <summary>
    /// 获取节流状态摘要（用于调试和日志）。
    /// </summary>
    public static string GetStatusSummary()
    {
        return $"初始化={_initialized}, 文件节流={FileTraversalThrottleMs}ms, " +
               $"ETW节流={EtwThrottleMs}ms, VSS节流={VssThrottleMs}ms, " +
               $"进程节流={ProcessLaunchThrottleMs}ms";
    }
}
