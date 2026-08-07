using System.Timers;
using LightGuard.Core;

namespace LightGuard.Update;

/// <summary>
/// 规则更新后台调度器
/// <para>使用 <see cref="System.Timers.Timer"/> 周期性检查云端规则更新，发现新版本时自动下载并验签应用。</para>
/// <para>所有操作通过 <see cref="ErrorReporter"/> 记录日志。线程安全，不会出现检查重叠。</para>
/// </summary>
public sealed class RuleUpdateScheduler : IDisposable
{
    #region 字段

    private readonly RuleUpdateManager _manager;
    private readonly TimeSpan _checkInterval;
    private readonly System.Timers.Timer _timer;
    private readonly object _startLock = new();

    /// <summary>0 = 空闲, 1 = 正在检查（使用 Interlocked 保证不重叠）</summary>
    private int _isChecking;

    private bool _running;
    private bool _disposed;

    #endregion

    #region 事件

    /// <summary>自动更新完成时触发（包含未发生更新的结果）</summary>
    public event Action<RuleType, RuleUpdateResult>? OnAutoUpdateCompleted;

    /// <summary>自动更新过程中发生异常时触发</summary>
    public event Action<Exception>? OnAutoUpdateError;

    #endregion

    #region 属性

    /// <summary>调度器是否正在运行</summary>
    public bool IsRunning => _running;

    /// <summary>检查间隔</summary>
    public TimeSpan CheckInterval => _checkInterval;

    #endregion

    #region 构造函数

    /// <summary>
    /// 创建规则更新调度器
    /// </summary>
    /// <param name="manager">规则更新管理器</param>
    /// <param name="checkInterval">检查间隔</param>
    public RuleUpdateScheduler(RuleUpdateManager manager, TimeSpan checkInterval)
    {
        _manager = manager;
        _checkInterval = checkInterval > TimeSpan.Zero
            ? checkInterval
            : TimeSpan.FromHours(6);

        _timer = new System.Timers.Timer
        {
            Interval = _checkInterval.TotalMilliseconds,
            AutoReset = true
        };
        _timer.Elapsed += OnTimerElapsed;
    }

    #endregion

    #region 启停控制

    /// <summary>
    /// 启动后台定时检查
    /// </summary>
    public void Start()
    {
        lock (_startLock)
        {
            if (_running) return;
            _running = true;
            _timer.Start();
            ErrorReporter.Log($"[RuleUpdate] 调度器已启动，检查间隔: {_checkInterval.TotalHours:F1} 小时");
        }
    }

    /// <summary>
    /// 停止定时检查
    /// </summary>
    public void Stop()
    {
        lock (_startLock)
        {
            if (!_running) return;
            _running = false;
            _timer.Stop();
            ErrorReporter.Log("[RuleUpdate] 调度器已停止");
        }
    }

    #endregion

    #region 定时回调

    /// <summary>
    /// 定时器回调：使用 Interlocked 防止检查重叠
    /// </summary>
    private async void OnTimerElapsed(object? sender, ElapsedEventArgs e)
    {
        // 防止重叠：若上一次检查未完成则跳过本次
        if (Interlocked.CompareExchange(ref _isChecking, 1, 0) != 0)
        {
            ErrorReporter.Log("[RuleUpdate] 上一次检查尚未完成，跳过本次定时检查", "WARN");
            return;
        }

        try
        {
            await CheckAllAndAutoUpdateAsync();
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, "[RuleUpdate] 定时自动更新检查异常");
            OnAutoUpdateError?.Invoke(ex);
        }
        finally
        {
            Interlocked.Exchange(ref _isChecking, 0);
        }
    }

    /// <summary>
    /// 检查所有规则类型并在有更新时自动应用
    /// </summary>
    private async Task CheckAllAndAutoUpdateAsync()
    {
        ErrorReporter.Log("[RuleUpdate] ===== 开始定时规则更新检查 =====");

        foreach (RuleType type in Enum.GetValues<RuleType>())
        {
            try
            {
                var available = await _manager.IsUpdateAvailableAsync(type);
                if (!available)
                {
                    ErrorReporter.Log($"[RuleUpdate] {type} 已是最新，无需更新");
                    continue;
                }

                ErrorReporter.Log($"[RuleUpdate] 发现 {type} 有可用更新，开始自动下载并应用...");
                var result = await _manager.UpdateRuleAsync(type, CancellationToken.None);
                OnAutoUpdateCompleted?.Invoke(type, result);

                if (result.Success)
                {
                    ErrorReporter.Log($"[RuleUpdate] {type} 自动更新成功: {result.OldVersion} -> {result.NewVersion}");
                }
                else
                {
                    ErrorReporter.Log($"[RuleUpdate] {type} 自动更新失败: {result.ErrorMessage}", "WARN");
                }
            }
            catch (Exception ex)
            {
                ErrorReporter.Report(ex, $"[RuleUpdate] {type} 自动更新异常");
                OnAutoUpdateError?.Invoke(ex);
            }
        }

        ErrorReporter.Log("[RuleUpdate] ===== 定时规则更新检查完成 =====");
    }

    #endregion

    #region IDisposable

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;

        Stop();
        _timer.Elapsed -= OnTimerElapsed;
        _timer.Dispose();
    }

    #endregion
}
