using LightGuard.Core.Interfaces;
using LightGuard.Native;

namespace LightGuard.Core;

/// <summary>
/// 全局应用状态，贯穿整个生命周期
/// </summary>
public sealed class AppState : IDisposable
{
    private static AppState? _instance;

    public static AppState Instance => _instance ?? throw new InvalidOperationException("AppState 未初始化");

    public HardwareProfile Hardware { get; private set; }
    public AppConfig Config { get; private set; }
    public ModuleManager Modules { get; private set; }
    public BackgroundScheduler Scheduler { get; private set; }
    public UiMode UiMode { get; private set; }
    public DateTime StartTime { get; }

    private AppState()
    {
        StartTime = DateTime.Now;
    }

    public static AppState Initialize()
    {
        if (_instance != null)
            return _instance;

        var state = new AppState();

        // 硬件检测
        state.Hardware = HardwareDetector.Detect();
        state.UiMode = state.Hardware.IsHighEnd ? UiMode.Modern : UiMode.Minimal;

        // 加载配置
        state.Config = ConfigManager.Load();

        // 模块管理器
        state.Modules = new ModuleManager();

        // 后台调度器
        state.Scheduler = new BackgroundScheduler(state.Hardware, state.Config);

        _instance = state;
        return state;
    }

    /// <summary>
    /// 切换 UI 模式（高配/低配）
    /// </summary>
    public void SwitchUiMode(UiMode mode)
    {
        UiMode = mode;
        Config.UiMode = mode;
        ConfigManager.Save(Config);
    }

    /// <summary>
    /// 注册所有模块
    /// </summary>
    public void RegisterModules()
    {
        Modules.RegisterAll(this);
    }

    public void Dispose()
    {
        Scheduler?.Dispose();
        Modules?.Dispose();
        SingleInstance.Release();
    }
}

/// <summary>
/// UI 渲染模式
/// </summary>
public enum UiMode
{
    /// <summary>高配：Mica云母、圆角、渐变、阴影</summary>
    Modern,

    /// <summary>低配：纯矩形极简、无特效</summary>
    Minimal
}
