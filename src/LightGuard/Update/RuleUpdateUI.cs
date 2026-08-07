using LightGuard.Core;

namespace LightGuard.Update;

/// <summary>
/// 规则更新状态项（供 UI 数据绑定展示）
/// </summary>
public sealed class RuleUpdateStatusItem
{
    /// <summary>规则类型</summary>
    public RuleType RuleType { get; set; }

    /// <summary>显示名称</summary>
    public string DisplayName { get; set; } = string.Empty;

    /// <summary>已安装版本</summary>
    public string InstalledVersion { get; set; } = string.Empty;

    /// <summary>服务器最新版本（未查询时为 "—"）</summary>
    public string LatestVersion { get; set; } = "—";

    /// <summary>是否有可用更新</summary>
    public bool UpdateAvailable { get; set; }

    /// <summary>最后检查时间</summary>
    public DateTime? LastCheckTime { get; set; }

    /// <summary>是否启用自动更新</summary>
    public bool AutoUpdateEnabled { get; set; }

    public override string ToString()
        => $"{DisplayName}: {InstalledVersion} -> {LatestVersion} {(UpdateAvailable ? "(有更新)" : "")}";
}

/// <summary>
/// 规则更新 UI 控制器
/// <para>非完整页面，仅为 UI 层提供数据绑定与操作入口的控制器类。</para>
/// <para>封装 <see cref="RuleUpdateManager"/> 的状态查询与触发逻辑，供 WinForms 页面调用。</para>
/// </summary>
public sealed class RuleUpdateUIController
{
    private readonly RuleUpdateManager _manager;

    /// <summary>各规则类型的最新版本缓存（由 RefreshAllAsync 填充）</summary>
    private readonly Dictionary<RuleType, RuleVersionInfo?> _latestCache = new();

    /// <summary>
    /// 创建 UI 控制器
    /// </summary>
    /// <param name="manager">规则更新管理器</param>
    public RuleUpdateUIController(RuleUpdateManager manager)
    {
        _manager = manager;
    }

    /// <summary>
    /// 获取所有规则类型的当前状态（供 UI 绑定）
    /// </summary>
    public List<RuleUpdateStatusItem> GetStatusItems()
    {
        var config = _manager.GetConfig();
        var items = new List<RuleUpdateStatusItem>();

        foreach (RuleType type in Enum.GetValues<RuleType>())
        {
            var installed = _manager.GetInstalledVersion(type);
            _latestCache.TryGetValue(type, out var latest);

            items.Add(new RuleUpdateStatusItem
            {
                RuleType = type,
                DisplayName = RuleUpdateManager.GetRuleDisplayName(type),
                InstalledVersion = installed,
                LatestVersion = latest?.Version ?? "—",
                UpdateAvailable = latest != null
                                  && RuleUpdateManager.CompareVersions(latest.Version, installed) > 0,
                LastCheckTime = config.LastCheckTime,
                AutoUpdateEnabled = config.AutoUpdateEnabled
            });
        }

        return items;
    }

    /// <summary>
    /// 从服务器刷新所有规则类型的最新版本信息
    /// </summary>
    public async Task RefreshAllAsync()
    {
        foreach (RuleType type in Enum.GetValues<RuleType>())
        {
            try
            {
                _latestCache[type] = await _manager.CheckLatestVersionAsync(type);
            }
            catch (Exception ex)
            {
                ErrorReporter.Report(ex, $"[RuleUpdate][UI] 刷新 {type} 状态失败");
                _latestCache[type] = null;
            }
        }
    }

    /// <summary>
    /// 触发指定规则类型的更新
    /// </summary>
    public async Task UpdateRuleAsync(RuleType type)
    {
        await _manager.UpdateRuleAsync(type, CancellationToken.None);

        // 更新完成后刷新该类型的最新版本缓存
        try
        {
            _latestCache[type] = await _manager.CheckLatestVersionAsync(type);
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, $"[RuleUpdate][UI] 更新后刷新 {type} 缓存失败");
        }
    }

    /// <summary>
    /// 更新所有规则类型
    /// </summary>
    public async Task UpdateAllAsync()
    {
        await _manager.UpdateAllAsync(CancellationToken.None);
        await RefreshAllAsync();
    }

    /// <summary>
    /// 设置自动更新开关。
    /// <para>当前自动更新为全局开关，<paramref name="type"/> 参数用于将来扩展按类型启停。</para>
    /// </summary>
    /// <param name="type">规则类型（保留参数）</param>
    /// <param name="enabled">是否启用</param>
    public void SetAutoUpdate(RuleType type, bool enabled)
    {
        _ = _manager.SetAutoUpdateAsync(enabled);
    }
}
