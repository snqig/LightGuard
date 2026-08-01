using LightGuard.Core.Interfaces;

namespace LightGuard.Core;

/// <summary>
/// 模块基类 - 提供公共实现
/// 所有模块继承此类，减少重复代码
/// </summary>
public abstract class ModuleBase : IModule
{
    protected readonly AppState AppState;
    private bool _isEnabled;
    private bool _isInitialized;
    private ModuleStatus _status = ModuleStatus.Stopped;
    private string? _lastError;
    private DateTime? _lastActionTime;

    protected ModuleBase(AppState appState)
    {
        AppState = appState;
    }

    public abstract string Id { get; }
    public abstract string DisplayName { get; }
    public abstract string Description { get; }
    public abstract ModuleCategory Category { get; }
    public virtual bool RequiresAdmin => true;

    public bool IsEnabled => _isEnabled;

    public virtual async Task InitializeAsync()
    {
        if (_isInitialized) return;
        _status = ModuleStatus.Initializing;
        try
        {
            await OnInitializeAsync();
            _isInitialized = true;
            _status = ModuleStatus.Stopped;
        }
        catch (Exception ex)
        {
            _status = ModuleStatus.Error;
            _lastError = ex.Message;
            ErrorReporter.Report(ex, $"模块 {Id} 初始化失败");
        }
    }

    public virtual async Task EnableAsync()
    {
        if (_isEnabled) return;
        try
        {
            _status = ModuleStatus.Initializing;
            await OnEnableAsync();
            _isEnabled = true;
            _status = ModuleStatus.Running;
            _lastActionTime = DateTime.Now;
        }
        catch (Exception ex)
        {
            _status = ModuleStatus.Error;
            _lastError = ex.Message;
            ErrorReporter.Report(ex, $"模块 {Id} 启用失败");
        }
    }

    public virtual async Task DisableAsync()
    {
        if (!_isEnabled) return;
        try
        {
            await OnDisableAsync();
            _isEnabled = false;
            _status = ModuleStatus.Disabled;
            _lastActionTime = DateTime.Now;
            // 彻底释放资源
            OnReleaseResources();
        }
        catch (Exception ex)
        {
            _status = ModuleStatus.Error;
            _lastError = ex.Message;
            ErrorReporter.Report(ex, $"模块 {Id} 禁用失败");
        }
    }

    public ModuleStatus GetStatus()
    {
        return _status;
    }

    public ModuleStatusInfo GetStatusInfo()
    {
        return new ModuleStatusInfo
        {
            Status = _status,
            Summary = GetStatusSummary(),
            LastError = _lastError,
            LastActionTime = _lastActionTime
        };
    }

    protected abstract Task OnInitializeAsync();
    protected abstract Task OnEnableAsync();
    protected abstract Task OnDisableAsync();

    /// <summary>
    /// 禁用时释放资源（子类可重写）
    /// </summary>
    protected virtual void OnReleaseResources() { }

    /// <summary>
    /// 获取状态摘要文本（子类可重写）
    /// </summary>
    protected virtual string GetStatusSummary() => _status switch
    {
        ModuleStatus.Running => "运行中",
        ModuleStatus.Stopped => "已停止",
        ModuleStatus.Initializing => "初始化中...",
        ModuleStatus.Error => $"错误: {_lastError}",
        ModuleStatus.Disabled => "已禁用",
        _ => "未知"
    };

    public virtual void Dispose()
    {
        if (_isEnabled)
        {
            try { OnDisableAsync().Wait(5000); } catch { }
        }
        OnReleaseResources();
    }
}
