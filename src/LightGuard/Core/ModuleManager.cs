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

        // 按依赖顺序注册 — 落尘原创七大核心模块架构
        // 第零层：程序自我保护（反调试+DACL+配置加密，必须在所有模块之前启动）
        Register(new Modules.SelfProtectionModule(appState));

        // 第一层：基础防护
        Register(new Modules.PrivacyModule(appState));
        Register(new Modules.CleanupModule(appState));
        Register(new Modules.FirewallModule(appState));

        // 第一层附加：系统守护（隔离区+快照回滚+防火墙规则守护，依赖 FirewallModule）
        Register(new Modules.SystemGuardModule(appState));

        // 第二层：勒索防御（ETW+YARA 双层 + 离线病毒库 + 进程行为沙箱）
        Register(new Modules.EtwYaraModule(appState));
        Register(new Modules.RansomwareModule(appState));

        // 第二层附加：勒索解密（家族识别 + 官方解密工具调度）
        Register(new Modules.RansomwareDecryptionModule(appState));

        // 第二层附加：Defender 查杀调度（MpCmdRun 按需扫描 + 病毒库更新）
        Register(new Modules.DefenderScanModule(appState));

        // 第三层：加密容灾（五层粒度备份 + 灾难恢复 + 数据库备份）
        Register(new Modules.EncryptedBackupModule(appState));
        Register(new Modules.DatabaseBackupModule(appState));
        Register(new Modules.DisasterRecoveryModule(appState));

        // 第四层：审计与更新
        Register(new Modules.SmbAuditModule(appState));
        Register(new Modules.AuditLogModule(appState));
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
