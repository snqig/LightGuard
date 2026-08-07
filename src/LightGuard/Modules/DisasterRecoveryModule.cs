// © 2026 落尘（Luochen） 原创开发 - 保留所有权利

using System.IO;
using LightGuard.Core;
using LightGuard.Core.Interfaces;

// 通过命名空间别名引用新增的 Recovery 命名空间类型，避免与既有同名类型歧义。
using LgRecovery = LightGuard.Recovery;

namespace LightGuard.Modules;

/// <summary>
/// 还原任务运行状态（全局状态同步用）。
/// </summary>
public enum RecoveryRunState
{
    /// <summary>空闲（无任务）。</summary>
    Idle,

    /// <summary>还原任务运行中。</summary>
    Running,

    /// <summary>还原任务成功完成。</summary>
    Succeeded,

    /// <summary>还原任务失败。</summary>
    Failed
}

/// <summary>
/// 灾难恢复模块（DisasterRecoveryModule）。
/// <para>持有 <see cref="LgRecovery.RecoveryEngine"/> 实例，提供加密备份包的精准恢复。</para>
/// <para>支持隔离 / 增量 / 强制覆盖三种恢复模式、跨设备 SMB 远程恢复、在线预览、版本回溯、选择性还原。</para>
/// </summary>
public sealed class DisasterRecoveryModule : ModuleBase
{
    private LgRecovery.RecoveryEngine? _engine;
    private readonly string _defaultBackupDir;

    /// <summary>
    /// 初始化灾难恢复模块。
    /// </summary>
    /// <param name="appState">全局应用状态。</param>
    public DisasterRecoveryModule(AppState appState) : base(appState)
    {
        _defaultBackupDir = Path.Combine(ConfigManager.GetDataDir(), "encrypted_backups");
    }

    /// <inheritdoc/>
    public override string Id => "disaster-recovery";

    /// <inheritdoc/>
    public override string DisplayName => "灾难恢复";

    /// <inheritdoc/>
    public override string Description =>
        "从 .lgbackup 加密备份包精准恢复：强制解密+SHA256 校验流程、三种恢复模式、跨设备 SMB 远程恢复、在线预览、版本回溯、选择性浏览还原。";

    /// <inheritdoc/>
    public override ModuleCategory Category => ModuleCategory.Recovery;

    /// <summary>恢复操作不需要管理员权限（分区/整盘裸机恢复在 PE 环境执行）。</summary>
    public override bool RequiresAdmin => false;

    /// <summary>
    /// 获取恢复引擎实例（初始化后可用）。
    /// </summary>
    public LgRecovery.RecoveryEngine? Engine => _engine;

    /// <summary>
    /// 获取默认备份检索目录。
    /// </summary>
    public string DefaultBackupDirectory => _defaultBackupDir;

    /// <summary>当前还原任务运行状态（全局状态同步）。</summary>
    public RecoveryRunState RunState { get; private set; } = RecoveryRunState.Idle;

    /// <summary>最近一次还原任务摘要（成功/失败数、目标路径等）。</summary>
    public string? LastRunSummary { get; private set; }

    /// <summary>还原状态变更事件（UI / 全局状态同步订阅）。</summary>
    public event Action<RecoveryRunState>? RecoveryStateChanged;

    /// <summary>
    /// 通知还原任务状态变更并同步全局状态。
    /// </summary>
    /// <param name="state">新的运行状态。</param>
    /// <param name="summary">可选的任务摘要。</param>
    public void NotifyRecoveryState(RecoveryRunState state, string? summary = null)
    {
        RunState = state;
        if (summary != null) LastRunSummary = summary;
        ErrorReporter.Log($"灾难恢复状态变更：{state}" + (summary != null ? $" | {summary}" : ""));
        RecoveryStateChanged?.Invoke(state);
    }

    /// <inheritdoc/>
    protected override Task OnInitializeAsync()
    {
        _engine = new LgRecovery.RecoveryEngine(AppState);
        ErrorReporter.Log("灾难恢复模块初始化完成");
        return Task.CompletedTask;
    }

    /// <inheritdoc/>
    protected override Task OnEnableAsync()
    {
        ErrorReporter.Log("灾难恢复模块已启用，恢复引擎就绪");
        return Task.CompletedTask;
    }

    /// <inheritdoc/>
    protected override Task OnDisableAsync()
    {
        ErrorReporter.Log("灾难恢复模块已禁用");
        return Task.CompletedTask;
    }

    /// <inheritdoc/>
    protected override void OnReleaseResources()
    {
        _engine = null;
    }

    /// <inheritdoc/>
    protected override string GetStatusSummary()
    {
        if (!IsEnabled) return "已禁用";
        try
        {
            int available = 0;
            if (Directory.Exists(_defaultBackupDir))
            {
                available = Directory.EnumerateFiles(_defaultBackupDir, "*.lgbackup").Count();
            }
            return available > 0
                ? $"运行中 | 恢复引擎就绪 | 可用备份包 {available} 个"
                : "运行中 | 恢复引擎就绪 | 暂无可用备份包";
        }
        catch
        {
            return "运行中 | 恢复引擎就绪";
        }
    }
}
