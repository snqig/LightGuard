// © 2026 落尘（Luochen） 原创开发 - 保留所有权利
//
// 定时/实时备份调度模块（v3.5 P0-4/P1-4）
//   - 承载全局单套 Cron 调度线程（BackupCronScheduler：文件全量/增量 + 每数据库实例独立 cron）
//   - 承载实时文件监控增量服务（RealtimeFileWatcher，按 FileBackupJob.RealtimeWatch 启动）
//   - 授权联动：未授权状态调度 tick 与实时监控均不执行

using LightGuard.Backup;
using LightGuard.Core;
using LightGuard.Core.Interfaces;

namespace LightGuard.Modules;

/// <summary>
/// 定时/实时备份调度模块（v3.5）。
/// <para>通过 ModuleManager 生命周期托管：启用即启动全局 cron 调度与实时监控。</para>
/// </summary>
public sealed class ScheduledBackupModule : ModuleBase
{
    private readonly BackupCronScheduler _scheduler;
    private readonly List<RealtimeFileWatcher> _watchers = new();

    /// <summary>全局 cron 调度器（供外部手动触发/状态查询）。</summary>
    public BackupCronScheduler Scheduler => _scheduler;

    /// <summary>
    /// 创建调度模块。
    /// </summary>
    public ScheduledBackupModule(AppState appState) : base(appState)
    {
        _scheduler = new BackupCronScheduler(appState);
    }

    /// <inheritdoc/>
    public override string Id => "scheduled-backup";

    /// <inheritdoc/>
    public override string DisplayName => "定时/实时备份调度";

    /// <inheritdoc/>
    public override string Description =>
        "全局单套 Cron 定时备份调度（文件定时全量/增量 + 每数据库实例独立 cron）+ 实时文件监控增量（防抖）+ 任务防重入 + 授权联动";

    /// <inheritdoc/>
    public override ModuleCategory Category => ModuleCategory.Backup;

    /// <summary>备份调度自身不需管理员权限（备份引擎内部按需处理）。</summary>
    public override bool RequiresAdmin => false;

    /// <inheritdoc/>
    protected override Task OnInitializeAsync()
    {
        // 授权门禁配置注入（读取 AppConfig.License）
        LicenseGuard.SetConfigProvider(() => AppState.Config.License);
        return Task.CompletedTask;
    }

    /// <inheritdoc/>
    protected override Task OnEnableAsync()
    {
        _scheduler.Start();
        StartRealtimeWatchers();
        ErrorReporter.Log($"定时/实时备份调度已启用：{AppState.Config.FileBackupJobs.Count} 个文件任务，{AppState.Config.DbBackupInstances.Count} 个数据库实例");
        return Task.CompletedTask;
    }

    /// <inheritdoc/>
    protected override Task OnDisableAsync()
    {
        StopRealtimeWatchers();
        _scheduler.Stop();
        ErrorReporter.Log("定时/实时备份调度已禁用");
        return Task.CompletedTask;
    }

    /// <inheritdoc/>
    protected override void OnReleaseResources()
    {
        StopRealtimeWatchers();
        _scheduler.Stop();
    }

    /// <inheritdoc/>
    protected override string GetStatusSummary()
    {
        if (!IsEnabled) return "已禁用";
        var watchCount = _watchers.Count(w => w.IsRunning);
        return $"运行中 | cron 调度已启动 | 实时监控 {watchCount} 个任务";
    }

    /// <summary>启动全部启用实时监控的文件任务。</summary>
    private void StartRealtimeWatchers()
    {
        StopRealtimeWatchers();
        foreach (var job in AppState.Config.FileBackupJobs.Where(j => j.Enabled && j.RealtimeWatch))
        {
            try
            {
                var watcher = new RealtimeFileWatcher(AppState, job, _scheduler.ReentryLock);
                if (watcher.Start())
                    _watchers.Add(watcher);
            }
            catch (Exception ex)
            {
                ErrorReporter.Log($"启动实时监控失败（{job.Name}）：{ex.Message}");
            }
        }
    }

    /// <summary>停止全部实时监控。</summary>
    private void StopRealtimeWatchers()
    {
        foreach (var watcher in _watchers)
        {
            try { watcher.Dispose(); } catch { }
        }
        _watchers.Clear();
    }

    /// <inheritdoc/>
    public override void Dispose()
    {
        base.Dispose();
        _scheduler.Dispose();
    }
}
