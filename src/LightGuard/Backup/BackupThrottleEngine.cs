// © 2026 落尘（Luochen） 原创开发 - 保留所有权利

using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using LightGuard.Core;

namespace LightGuard.Backup;

/// <summary>
/// 备份节流模式。
/// </summary>
public enum ThrottleMode
{
    /// <summary>全速：系统空闲时满速备份。</summary>
    FullSpeed,

    /// <summary>降速：前台应用活跃时降低 IO/网络速率以减少打扰。</summary>
    ReducedSpeed,

    /// <summary>夜间加速：非高峰时段（默认 22:00-06:00）满速备份。</summary>
    NightBoost,

    /// <summary>自定义：按用户配置的速率上限执行。</summary>
    Custom
}

/// <summary>
/// 备份节流配置。
/// </summary>
public sealed class ThrottleConfig
{
    /// <summary>IO 速率上限（MB/s）。</summary>
    public int MaxIoMBps { get; set; } = 50;

    /// <summary>网络速率上限（MB/s）。</summary>
    public int MaxNetworkMBps { get; set; } = 20;

    /// <summary>节流模式（基线模式，实际模式由 <see cref="BackupThrottleEngine.GetCurrentMode"/> 动态决定）。</summary>
    public ThrottleMode Mode { get; set; } = ThrottleMode.FullSpeed;

    /// <summary>夜间加速窗口起始时间。</summary>
    public TimeSpan NightStart { get; set; } = TimeSpan.FromHours(22);

    /// <summary>夜间加速窗口结束时间。</summary>
    public TimeSpan NightEnd { get; set; } = TimeSpan.FromHours(6);

    /// <summary>是否在前台应用活跃（CPU 繁忙）时暂停备份。</summary>
    public bool PauseOnForeground { get; set; } = true;

    /// <summary>是否在全屏应用运行时暂停备份。</summary>
    public bool PauseOnFullscreen { get; set; } = true;
}

/// <summary>
/// 备份智能节流引擎 - 根据时段、前台全屏状态与 CPU 负载动态调节备份速率，避免打扰用户。
/// <para>策略：夜间窗口（默认 22:00-06:00）满速（NightBoost）；前台应用活跃时降速（ReducedSpeed）；
/// 系统空闲时全速（FullSpeed）；全屏应用或 CPU &gt; 80% 时暂停（IsBackupAllowed 返回 false）。</para>
/// </summary>
public sealed class BackupThrottleEngine : IDisposable
{
    #region 常量

    /// <summary>标称分块大小（字节），用于换算分块间延迟。</summary>
    private const int ChunkSizeBytes = 4 * 1024 * 1024;

    /// <summary>用户空闲阈值（毫秒），超过即视为空闲。</summary>
    private const int IdleThresholdMs = 5 * 60 * 1000;

    /// <summary>CPU 使用率暂停阈值（百分比）。</summary>
    private const int CpuPauseThreshold = 80;

    /// <summary>暂停时单次休眠时长（毫秒）。</summary>
    private const int PauseDelayMs = 500;

    /// <summary>监控采样间隔。</summary>
    private static readonly TimeSpan MonitorInterval = TimeSpan.FromSeconds(5);

    /// <summary>CPU 使用率缓存有效期（秒）。</summary>
    private const double CpuCacheTtlSec = 2.0;

    #endregion

    #region 字段

    private volatile ThrottleConfig _config;
    private System.Threading.Timer? _monitorTimer;
    private PerformanceCounter? _cpuCounter;
    private bool _cpuCounterInitFailed;
    private float _cachedCpu;
    private DateTime _cpuCacheTime;
    private TimeSpan _lastProcTime;
    private DateTime _lastProcSample;
    private bool _disposed;

    #endregion

    #region 构造

    /// <summary>
    /// 使用指定配置初始化节流引擎。
    /// </summary>
    /// <param name="config">节流配置。</param>
    /// <exception cref="ArgumentNullException">config 为 null。</exception>
    public BackupThrottleEngine(ThrottleConfig config)
    {
        _config = config ?? throw new ArgumentNullException(nameof(config));
    }

    /// <summary>
    /// 使用默认配置初始化节流引擎（FullSpeed 基线，夜间 22:00-06:00 加速，IO 50MB/s，网络 20MB/s）。
    /// </summary>
    public BackupThrottleEngine() : this(CreateDefault()) { }

    /// <summary>
    /// 创建默认节流配置。
    /// </summary>
    /// <returns>默认配置实例。</returns>
    public static ThrottleConfig CreateDefault() => new()
    {
        Mode = ThrottleMode.FullSpeed,
        MaxIoMBps = 50,
        MaxNetworkMBps = 20,
        NightStart = TimeSpan.FromHours(22),
        NightEnd = TimeSpan.FromHours(6),
        PauseOnForeground = true,
        PauseOnFullscreen = true
    };

    #endregion

    #region 模式与策略

    /// <summary>
    /// 根据当前时段与系统状态决定节流模式。
    /// <para>夜间窗口 → <see cref="ThrottleMode.NightBoost"/>；自定义 → <see cref="ThrottleMode.Custom"/>；
    /// 需暂停或前台活跃 → <see cref="ThrottleMode.ReducedSpeed"/>；系统空闲 → <see cref="ThrottleMode.FullSpeed"/>。</para>
    /// </summary>
    /// <returns>当前节流模式。</returns>
    public ThrottleMode GetCurrentMode()
    {
        var now = DateTime.Now.TimeOfDay;
        if (IsInNightWindow(now)) return ThrottleMode.NightBoost;
        if (_config.Mode == ThrottleMode.Custom) return ThrottleMode.Custom;
        if (ShouldPause()) return ThrottleMode.ReducedSpeed;
        return IsUserActive() ? ThrottleMode.ReducedSpeed : ThrottleMode.FullSpeed;
    }

    /// <summary>
    /// 返回当前模式下分块之间应延迟的毫秒数。
    /// <para>FullSpeed / NightBoost 返回 0；ReducedSpeed / Custom 按 <see cref="ThrottleConfig.MaxIoMBps"/> 与分块大小换算。</para>
    /// </summary>
    /// <returns>延迟毫秒数。</returns>
    public int GetRecommendedChunkDelay()
    {
        return GetCurrentMode() switch
        {
            ThrottleMode.FullSpeed => 0,
            ThrottleMode.NightBoost => 0,
            ThrottleMode.ReducedSpeed => ComputeIoDelay(),
            ThrottleMode.Custom => ComputeIoDelay(),
            _ => 0
        };
    }

    /// <summary>
    /// 检查当前是否允许执行备份（非暂停状态）。
    /// </summary>
    /// <returns>允许备份返回 true。</returns>
    public bool IsBackupAllowed() => !ShouldPause();

    /// <summary>
    /// 检查是否应暂停备份：全屏前台应用或 CPU 使用率超过阈值。
    /// </summary>
    /// <returns>需暂停返回 true。</returns>
    public bool ShouldPause()
    {
        if (_config.PauseOnFullscreen && IsForegroundFullscreen()) return true;
        if (_config.PauseOnForeground && GetCpuUsage() > CpuPauseThreshold) return true;
        return false;
    }

    /// <summary>
    /// 应用节流：依据当前模式休眠相应时长，并响应取消请求。
    /// </summary>
    /// <param name="progress">备份进度跟踪器（用于取消响应）。</param>
    /// <returns>本次实际休眠的毫秒数。</returns>
    public int ApplyThrottle(BackupProgress progress)
    {
        ArgumentNullException.ThrowIfNull(progress);

        if (!IsBackupAllowed())
        {
            SleepCancelable(PauseDelayMs, progress);
            return PauseDelayMs;
        }

        var delay = GetRecommendedChunkDelay();
        if (delay > 0) SleepCancelable(delay, progress);
        return delay;
    }

    /// <summary>
    /// 返回当前节流状态的可读字符串。
    /// </summary>
    /// <returns>状态文本。</returns>
    public string GetThrottleStatus()
    {
        var mode = GetCurrentMode();
        var paused = ShouldPause();
        var cpu = GetCpuUsage();
        return $"节流状态：模式={mode} | CPU={cpu:F1}% | 全屏前台={IsForegroundFullscreen()} | 用户活跃={IsUserActive()} | " +
               $"暂停={paused} | IO上限={_config.MaxIoMBps}MB/s | 网络上限={_config.MaxNetworkMBps}MB/s | " +
               $"夜间窗口={_config.NightStart:hh\\:mm}-{_config.NightEnd:hh\\:mm}";
    }

    /// <summary>
    /// 更新节流配置。
    /// </summary>
    /// <param name="config">新配置。</param>
    /// <exception cref="ArgumentNullException">config 为 null。</exception>
    public void UpdateConfig(ThrottleConfig config)
    {
        ArgumentNullException.ThrowIfNull(config);
        _config = config;
        ErrorReporter.Log($"节流配置已更新：模式={config.Mode}，IO上限={config.MaxIoMBps}MB/s，" +
            $"网络上限={config.MaxNetworkMBps}MB/s，夜间={config.NightStart:hh\\:mm}-{config.NightEnd:hh\\:mm}");
    }

    #endregion

    #region 监控

    /// <summary>
    /// 启动后台监控定时器，周期性采样系统状态并记录日志。
    /// </summary>
    public void StartMonitoring()
    {
        _monitorTimer?.Dispose();
        _monitorTimer = new System.Threading.Timer(
            _ => MonitorTick(), null, TimeSpan.Zero, MonitorInterval);
        ErrorReporter.Log($"节流监控已启动（采样间隔 {MonitorInterval.TotalSeconds} 秒）");
    }

    /// <summary>
    /// 停止后台监控。
    /// </summary>
    public void StopMonitoring()
    {
        if (_monitorTimer == null) return;
        _monitorTimer.Dispose();
        _monitorTimer = null;
        ErrorReporter.Log("节流监控已停止");
    }

    /// <summary>
    /// 监控采样回调：记录当前模式、CPU、全屏与暂停状态。
    /// </summary>
    private void MonitorTick()
    {
        try
        {
            var mode = GetCurrentMode();
            var paused = ShouldPause();
            var cpu = GetCpuUsage();
            ErrorReporter.Log($"节流采样：模式={mode}，CPU={cpu:F1}%，全屏={IsForegroundFullscreen()}，暂停={paused}");
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, "节流监控采样异常");
        }
    }

    #endregion

    #region 私有：时段 / 延迟 / 休眠

    /// <summary>
    /// 判断当前时间是否落在夜间加速窗口内（支持跨午夜窗口）。
    /// </summary>
    private bool IsInNightWindow(TimeSpan now)
    {
        var start = _config.NightStart;
        var end = _config.NightEnd;
        if (start == end) return false;
        if (start < end) return now >= start && now < end;
        return now >= start || now < end; // 跨午夜，如 22:00-06:00
    }

    /// <summary>
    /// 按 IO 速率上限计算分块间延迟：延迟 = 分块大小 / 速率上限 × 1000ms。
    /// </summary>
    private int ComputeIoDelay()
    {
        if (_config.MaxIoMBps <= 0) return 0;
        double mb = ChunkSizeBytes / (1024.0 * 1024.0);
        int delay = (int)Math.Round(mb / _config.MaxIoMBps * 1000.0);
        return Math.Clamp(delay, 0, 5000);
    }

    /// <summary>
    /// 可取消的休眠：分步睡眠并周期性检查取消令牌。
    /// </summary>
    private static void SleepCancelable(int ms, BackupProgress? progress)
    {
        var token = progress?.CancellationToken ?? CancellationToken.None;
        const int step = 50;
        int waited = 0;
        while (waited < ms)
        {
            token.ThrowIfCancellationRequested();
            int slice = Math.Min(step, ms - waited);
            System.Threading.Thread.Sleep(slice);
            waited += slice;
        }
    }

    #endregion

    #region 私有：CPU 使用率

    /// <summary>
    /// 获取系统 CPU 使用率（百分比），缓存 2 秒。优先使用 PerformanceCounter，失败回退到进程 CPU 估算。
    /// </summary>
    private float GetCpuUsage()
    {
        if ((DateTime.Now - _cpuCacheTime).TotalSeconds < CpuCacheTtlSec) return _cachedCpu;

        var counter = GetCpuCounter();
        if (counter != null)
        {
            try
            {
                _cachedCpu = counter.NextValue();
                _cpuCacheTime = DateTime.Now;
                return _cachedCpu;
            }
            catch (Exception ex)
            {
                ErrorReporter.Report(ex, "CPU 使用率采样失败");
            }
        }

        _cachedCpu = EstimateCpuFromProcess();
        _cpuCacheTime = DateTime.Now;
        return _cachedCpu;
    }

    /// <summary>
    /// 懒初始化 PerformanceCounter（"\Processor(_Total)\% Processor Time"）。
    /// </summary>
    private PerformanceCounter? GetCpuCounter()
    {
        if (_cpuCounterInitFailed) return null;
        if (_cpuCounter != null) return _cpuCounter;

        try
        {
            _cpuCounter = new PerformanceCounter("Processor", "% Processor Time", "_Total");
            _ = _cpuCounter.NextValue(); // 首次调用返回 0，预热计数器
            return _cpuCounter;
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, "PerformanceCounter 初始化失败，回退到进程 CPU 估算");
            _cpuCounterInitFailed = true;
            return null;
        }
    }

    /// <summary>
    /// 回退方案：基于当前进程总处理器时间增量估算 CPU 使用率（占全部核心的百分比）。
    /// </summary>
    private float EstimateCpuFromProcess()
    {
        try
        {
            var now = DateTime.Now;
            var proc = Process.GetCurrentProcess().TotalProcessorTime;
            if (_lastProcSample != default && now > _lastProcSample)
            {
                double elapsed = (now - _lastProcSample).TotalSeconds;
                double cpuSec = (proc - _lastProcTime).TotalSeconds;
                _lastProcTime = proc;
                _lastProcSample = now;
                return (float)(cpuSec / (elapsed * Environment.ProcessorCount) * 100.0);
            }
            _lastProcTime = proc;
            _lastProcSample = now;
            return 0;
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, "进程 CPU 估算失败");
            return 0;
        }
    }

    #endregion

    #region 私有：全屏 / 空闲检测（P/Invoke）

    /// <summary>
    /// 检测当前前台窗口是否为全屏（窗口矩形覆盖其所在显示器的工作区边界）。
    /// </summary>
    private static bool IsForegroundFullscreen()
    {
        try
        {
            var hwnd = GetForegroundWindow();
            if (hwnd == IntPtr.Zero) return false;
            if (!GetWindowRect(hwnd, out var rect)) return false;

            var hmon = MonitorFromWindow(hwnd, MONITOR_DEFAULTTONEAREST);
            if (hmon == IntPtr.Zero) return false;

            var mi = new MONITORINFO { cbSize = (uint)Marshal.SizeOf<MONITORINFO>() };
            if (!GetMonitorInfo(hmon, ref mi)) return false;

            var m = mi.rcMonitor;
            const int tol = 8; // 容忍 8px 误差
            return rect.Left <= m.Left + tol
                && rect.Top <= m.Top + tol
                && rect.Right >= m.Right - tol
                && rect.Bottom >= m.Bottom - tol;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// 检测用户是否处于活跃状态（最近输入时间小于空闲阈值）。
    /// </summary>
    private static bool IsUserActive()
    {
        try
        {
            var lii = new LASTINPUTINFO { cbSize = (uint)Marshal.SizeOf<LASTINPUTINFO>() };
            if (!GetLastInputInfo(ref lii)) return true;
            uint nowTick = (uint)Environment.TickCount;
            uint idleMs = nowTick - lii.dwTime;
            return idleMs < IdleThresholdMs;
        }
        catch
        {
            return true; // 查询失败时保守视为活跃（降速）
        }
    }

    [DllImport("user32.dll")]
    private static extern IntPtr GetForegroundWindow();

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetWindowRect(IntPtr hWnd, out RECT lpRect);

    [DllImport("user32.dll")]
    private static extern IntPtr MonitorFromWindow(IntPtr hwnd, uint dwFlags);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetMonitorInfo(IntPtr hMonitor, ref MONITORINFO lpmi);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetLastInputInfo(ref LASTINPUTINFO plii);

    private const uint MONITOR_DEFAULTTONEAREST = 2;

    [StructLayout(LayoutKind.Sequential)]
    private struct RECT
    {
        public int Left;
        public int Top;
        public int Right;
        public int Bottom;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MONITORINFO
    {
        public uint cbSize;
        public RECT rcMonitor;
        public RECT rcWork;
        public uint dwFlags;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct LASTINPUTINFO
    {
        public uint cbSize;
        public uint dwTime;
    }

    #endregion

    #region IDisposable

    /// <summary>
    /// 释放资源：停止监控并释放 PerformanceCounter。
    /// </summary>
    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        try { StopMonitoring(); }
        catch (Exception ex) { ErrorReporter.Report(ex, "停止节流监控异常"); }
        try { _cpuCounter?.Dispose(); }
        catch { /* 忽略 */ }
    }

    #endregion
}
