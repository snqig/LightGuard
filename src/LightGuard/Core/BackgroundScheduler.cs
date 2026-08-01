using System.Diagnostics;
using Timer = System.Threading.Timer;

namespace LightGuard.Core;

/// <summary>
/// 智能无感后台调度系统
/// - 前台操作电脑：暂停所有负载任务
/// - 游戏全屏：暂停扫描/备份/更新
/// - 低电量：停止所有后台工作
/// - 凌晨闲置自动维护
/// - 所有任务最低 Idle 优先级
/// </summary>
public sealed class BackgroundScheduler : IDisposable
{
    private readonly HardwareProfile _hardware;
    private readonly AppConfig _config;
    private readonly System.Threading.Timer _checkTimer;
    private readonly CancellationTokenSource _cts = new();
    private bool _isPaused;
    private DateTime _lastMaintenance;
    private bool _isMaintenanceRunning;

    // 系统空闲检测
    private DateTime _lastInputTime = DateTime.Now;

    public bool IsPaused => _isPaused;
    public bool IsMaintenanceRunning => _isMaintenanceRunning;

    /// <summary>后台任务暂停状态变化</summary>
    public event Action<bool>? PauseStateChanged;

    /// <summary>维护任务开始/结束</summary>
    public event Action<bool>? MaintenanceStateChanged;

    public BackgroundScheduler(HardwareProfile hardware, AppConfig config)
    {
        _hardware = hardware;
        _config = config;

        // 每30秒检查一次系统状态
        _checkTimer = new Timer(CheckSystemState, null,
            TimeSpan.FromSeconds(5), TimeSpan.FromSeconds(30));
    }

    private void CheckSystemState(object? state)
    {
        if (_cts.IsCancellationRequested) return;

        var shouldPause = ShouldPauseBackgroundTasks();

        if (shouldPause != _isPaused)
        {
            _isPaused = shouldPause;
            PauseStateChanged?.Invoke(_isPaused);
        }

        // 检查是否需要执行自动维护
        if (!_isPaused && _config.BackgroundSchedulingEnabled)
        {
            TryRunAutoMaintenance();
        }
    }

    /// <summary>
    /// 判断是否应该暂停后台任务
    /// </summary>
    private bool ShouldPauseBackgroundTasks()
    {
        // 1. 低电量（<20%）暂停
        if (_hardware.IsBatteryPowered && _hardware.BatteryLevel < 20)
            return true;

        // 2. 全屏应用运行中（游戏/视频）暂停
        if (HardwareDetector.IsFullScreenAppRunning())
            return true;

        // 3. 用户正在操作电脑（最近30秒有输入）暂停高负载任务
        var idleTime = GetUserIdleTime();
        if (idleTime < TimeSpan.FromSeconds(30))
            return true;

        return false;
    }

    /// <summary>
    /// 获取用户空闲时间
    /// </summary>
    private static TimeSpan GetUserIdleTime()
    {
        try
        {
            var lastInput = new Native.Win32.LASTINPUTINFO
            {
                cbSize = (uint)System.Runtime.InteropServices.Marshal.SizeOf<Native.Win32.LASTINPUTINFO>()
            };
            Native.Win32.GetLastInputInfo(ref lastInput);
            var now = (uint)Environment.TickCount;
            var idleMs = now - lastInput.dwTime;
            return TimeSpan.FromMilliseconds(idleMs);
        }
        catch
        {
            return TimeSpan.Zero;
        }
    }

    /// <summary>
    /// 尝试执行自动维护（凌晨闲置时）
    /// </summary>
    private void TryRunAutoMaintenance()
    {
        var now = DateTime.Now;

        // 检查是否到达维护时间窗口（凌晨指定小时前后1小时）
        if (now.Hour != _config.AutoMaintenanceHour)
            return;

        // 今天已经执行过
        if (_lastMaintenance.Date == now.Date)
            return;

        // 用户空闲超过5分钟
        if (GetUserIdleTime() < TimeSpan.FromMinutes(5))
            return;

        _ = RunMaintenanceAsync();
    }

    /// <summary>
    /// 执行自动维护任务
    /// </summary>
    public async Task RunMaintenanceAsync()
    {
        if (_isMaintenanceRunning) return;
        _isMaintenanceRunning = true;
        MaintenanceStateChanged?.Invoke(true);

        try
        {
            // 以 Idle 优先级运行
            await Task.Run(() =>
            {
                using var proc = Process.GetCurrentProcess();
                proc.PriorityClass = ProcessPriorityClass.Idle;

                // 1. 病毒库更新
                // 2. 流氓规则更新
                // 3. 定时扫描
                // 4. 定时备份
                // 5. 清理过期备份
                // 各模块通过事件回调执行
                MaintenanceTaskExecuted?.Invoke("病毒库检查更新...");
                Thread.Sleep(100);

                MaintenanceTaskExecuted?.Invoke("流氓规则库检查更新...");
                Thread.Sleep(100);

                MaintenanceTaskExecuted?.Invoke("系统安全扫描...");
                Thread.Sleep(100);

                MaintenanceTaskExecuted?.Invoke("增量备份检查...");
                Thread.Sleep(100);

                MaintenanceTaskExecuted?.Invoke("清理过期备份...");
                Thread.Sleep(100);

            }, _cts.Token);

            _lastMaintenance = DateTime.Now;
        }
        catch (OperationCanceledException) { }
        finally
        {
            _isMaintenanceRunning = false;
            MaintenanceStateChanged?.Invoke(false);
        }
    }

    /// <summary>维护任务执行进度</summary>
    public event Action<string>? MaintenanceTaskExecuted;

    /// <summary>
    /// 手动触发维护
    /// </summary>
    public Task TriggerMaintenanceAsync() => RunMaintenanceAsync();

    public void Dispose()
    {
        _cts.Cancel();
        _checkTimer?.Dispose();
        _cts?.Dispose();
    }
}
