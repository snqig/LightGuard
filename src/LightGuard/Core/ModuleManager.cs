using LightGuard.Core.Interfaces;

namespace LightGuard.Core;

/// <summary>
/// 模块管理器 - 管理所有功能模块的生命周期
/// 每个模块可独立开关，关闭即彻底释放资源
/// </summary>
public sealed class ModuleManager : IDisposable
{
    private readonly Dictionary<string, IModule> _modules = new();
    private readonly List<IModule> _moduleOrder = new();
    private bool _initialized;

    public IReadOnlyList<IModule> AllModules => _moduleOrder;

    /// <summary>
    /// 注册所有内置模块
    /// </summary>
    public void RegisterAll(AppState appState)
    {
        if (_initialized) return;
        _initialized = true;
        this.appState = appState;

        // 按依赖顺序注册
        Register(new Modules.PrivacyModule(appState));
        Register(new Modules.CleanupModule(appState));
        Register(new Modules.FirewallModule(appState));
        Register(new Modules.BackupModule(appState));
        Register(new Modules.RansomwareModule(appState));
        Register(new Modules.UpdateModule(appState));
    }

    private void Register(IModule module)
    {
        if (_modules.ContainsKey(module.Id))
            return;

        _modules[module.Id] = module;
        _moduleOrder.Add(module);
    }

    /// <summary>
    /// 初始化所有已启用的模块
    /// </summary>
    public async Task InitializeEnabledModulesAsync()
    {
        foreach (var module in _moduleOrder)
        {
            if (!appState.Config.IsModuleEnabled(module.Id))
                continue;

            try
            {
                await module.InitializeAsync();
                if (appState.Config.IsModuleEnabled(module.Id))
                    await module.EnableAsync();
            }
            catch
            {
                // 模块初始化失败不影响其他模块
            }
        }
    }

    private AppState appState = null!;

    /// <summary>
    /// 设置 AppState 引用（在 RegisterAll 之前调用）
    /// </summary>
    internal void SetAppState(AppState state) => appState = state;

    /// <summary>
    /// 获取模块
    /// </summary>
    public IModule? GetModule(string id)
    {
        return _modules.TryGetValue(id, out var module) ? module : null;
    }

    /// <summary>
    /// 获取指定分类的模块
    /// </summary>
    public IEnumerable<IModule> GetModulesByCategory(ModuleCategory category)
    {
        return _moduleOrder.Where(m => m.Category == category);
    }

    /// <summary>
    /// 切换模块开关
    /// </summary>
    public async Task ToggleModuleAsync(string moduleId, bool enable)
    {
        if (!_modules.TryGetValue(moduleId, out var module))
            return;

        appState.Config.SetModuleEnabled(moduleId, enable);
        ConfigManager.Save(appState.Config);

        if (enable)
        {
            await module.InitializeAsync();
            await module.EnableAsync();
        }
        else
        {
            await module.DisableAsync();
        }
    }

    public void Dispose()
    {
        foreach (var module in _moduleOrder)
        {
            try { module.Dispose(); } catch { }
        }
        _modules.Clear();
        _moduleOrder.Clear();
    }
}
