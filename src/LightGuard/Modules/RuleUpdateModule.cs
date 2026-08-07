using LightGuard.Core;
using LightGuard.Core.Interfaces;
using LightGuard.Update;

namespace LightGuard.Modules;

/// <summary>
/// 规则云端更新模块
/// <para>基于 RSA-2048 签名校验的云端规则自动增量更新系统。</para>
/// <para>持有 <see cref="RuleUpdateManager"/> 与 <see cref="RuleUpdateScheduler"/> 实例，</para>
/// <para>负责加载配置、创建管理器与调度器，并在启用/禁用时控制调度器生命周期。</para>
/// </summary>
public sealed class RuleUpdateModule : ModuleBase
{
    /// <summary>规则更新管理器</summary>
    public RuleUpdateManager? Manager { get; private set; }

    /// <summary>规则更新后台调度器</summary>
    public RuleUpdateScheduler? Scheduler { get; private set; }

    /// <summary>UI 控制器（供页面绑定）</summary>
    public RuleUpdateUIController? UiController { get; private set; }

    public RuleUpdateModule(AppState appState) : base(appState)
    {
    }

    /// <inheritdoc/>
    public override string Id => "rule-update";

    /// <inheritdoc/>
    public override string DisplayName => "规则云端更新";

    /// <inheritdoc/>
    public override string Description => "RSA 签名校验的云端规则自动增量更新：YARA 勒索规则、广告拦截规则、解密工具索引、病毒特征库";

    /// <inheritdoc/>
    public override ModuleCategory Category => ModuleCategory.Update;

    /// <inheritdoc/>
    protected override async Task OnInitializeAsync()
    {
        await Task.Run(() =>
        {
            var updateCfg = AppState.Config.Update;

            // 加载或构建规则更新配置
            var config = BuildConfig(updateCfg);

            // 创建管理器、调度器与 UI 控制器
            Manager = new RuleUpdateManager(config);

            var intervalHours = config.CheckIntervalHours > 0 ? config.CheckIntervalHours : 6;
            Scheduler = new RuleUpdateScheduler(Manager, TimeSpan.FromHours(intervalHours));

            UiController = new RuleUpdateUIController(Manager);

            // 订阅更新完成事件，将版本信息同步回 AppConfig
            Manager.UpdateCompleted += OnUpdateCompleted;

            ErrorReporter.Log($"[RuleUpdate] 模块初始化完成 - 服务器: {config.UpdateServerUrl} | " +
                              $"间隔: {intervalHours}h | 自动更新: {config.AutoUpdateEnabled}");
        });
    }

    /// <inheritdoc/>
    protected override async Task OnEnableAsync()
    {
        await Task.Run(() =>
        {
            var config = Manager?.GetConfig();
            if (config == null)
            {
                ErrorReporter.Log("[RuleUpdate] 管理器未初始化，无法启用", "WARN");
                return;
            }

            if (config.AutoUpdateEnabled)
            {
                Scheduler?.Start();
            }
            else
            {
                ErrorReporter.Log("[RuleUpdate] 自动更新已在配置中关闭，仅支持手动检查");
            }
        });
    }

    /// <inheritdoc/>
    protected override async Task OnDisableAsync()
    {
        await Task.Run(() =>
        {
            Scheduler?.Stop();
            SyncToAppConfig();
            ErrorReporter.Log("[RuleUpdate] 模块已禁用，调度器已停止");
        });
    }

    /// <inheritdoc/>
    protected override void OnReleaseResources()
    {
        if (Manager != null)
        {
            Manager.UpdateCompleted -= OnUpdateCompleted;
        }
        Scheduler?.Dispose();
        Manager?.Dispose();
    }

    /// <inheritdoc/>
    protected override string GetStatusSummary()
    {
        if (Manager == null)
            return "未初始化";

        var config = Manager.GetConfig();
        var installedCount = config.InstalledVersions
            .Count(kv => !string.IsNullOrEmpty(kv.Value) && kv.Value != "0.0.0");
        var lastCheck = config.LastCheckTime?.ToString("MM-dd HH:mm") ?? "从未";
        var running = Scheduler?.IsRunning ?? false;

        return running
            ? $"运行中 | 已安装 {installedCount} 项规则 | 最后检查: {lastCheck}"
            : $"已停止 | 已安装 {installedCount} 项规则 | 最后检查: {lastCheck}";
    }

    /// <inheritdoc/>
    public override void Dispose()
    {
        OnReleaseResources();
        base.Dispose();
    }

    #region 私有方法

    /// <summary>
    /// 更新完成回调：成功时将版本信息同步回 AppConfig 并持久化
    /// </summary>
    private void OnUpdateCompleted(RuleUpdateResult result)
    {
        if (result.Success)
        {
            SyncToAppConfig();
        }
    }

    /// <summary>
    /// 根据 AppConfig.Update 构建规则更新配置。
    /// 优先加载本地持久化的 rule_update_config.json（保留已安装版本记录），
    /// 再用 AppConfig 中用户可调整的设置进行覆盖。
    /// </summary>
    private static RuleUpdateConfig BuildConfig(UpdateConfig updateCfg)
    {
        // 优先加载本地持久化配置（保留已安装版本记录）
        var config = RuleUpdateManager.LoadConfig() ?? new RuleUpdateConfig();

        config.InstalledVersions ??= new Dictionary<RuleType, string>();

        // 若本地配置无已安装版本记录，则从 AppConfig 的字符串字典恢复
        if (config.InstalledVersions.Count == 0 && updateCfg.InstalledRuleVersions.Count > 0)
        {
            foreach (var kv in updateCfg.InstalledRuleVersions)
            {
                if (Enum.TryParse<RuleType>(kv.Key, true, out var rt))
                    config.InstalledVersions[rt] = kv.Value;
            }
        }

        // 用户可在 AppConfig 中调整的设置覆盖本地配置
        config.AutoUpdateEnabled = updateCfg.AutoUpdateRules;
        config.CheckIntervalHours = updateCfg.RuleCheckIntervalHours > 0
            ? updateCfg.RuleCheckIntervalHours
            : config.CheckIntervalHours;

        if (!string.IsNullOrWhiteSpace(updateCfg.RuleUpdateServerUrl))
            config.UpdateServerUrl = updateCfg.RuleUpdateServerUrl;

        if (updateCfg.LastRuleCheck.HasValue)
            config.LastCheckTime = updateCfg.LastRuleCheck;

        return config;
    }

    /// <summary>
    /// 将规则更新配置同步回 AppConfig 并持久化
    /// </summary>
    private void SyncToAppConfig()
    {
        if (Manager == null) return;

        try
        {
            var config = Manager.GetConfig();
            var updateCfg = AppState.Config.Update;

            updateCfg.AutoUpdateRules = config.AutoUpdateEnabled;
            updateCfg.RuleCheckIntervalHours = config.CheckIntervalHours;
            updateCfg.RuleUpdateServerUrl = config.UpdateServerUrl;
            updateCfg.LastRuleCheck = config.LastCheckTime;
            updateCfg.InstalledRuleVersions = config.InstalledVersions
                .ToDictionary(kv => kv.Key.ToString(), kv => kv.Value);

            ConfigManager.Save(AppState.Config);
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, "[RuleUpdate] 同步配置到 AppConfig 失败");
        }
    }

    #endregion
}
