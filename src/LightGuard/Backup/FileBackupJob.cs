// © 2026 落尘（Luochen） 原创开发 - 保留所有权利
//
// 文件备份任务配置模型（v3.5 P0-2）
//   - 支持单文件 / 目录递归
//   - 定时全量 cron + 定时增量 cron
//   - 实时监控增量开关（防抖窗口）
//   - 快照链目录 + 保留策略 + 实时增量合并阈值
//   - 口令凭据引用（不落盘明文）

namespace LightGuard.Backup;

/// <summary>
/// 快照保留策略（对应 SnapshotChainManager.CleanupOldSnapshots 参数）。
/// </summary>
public sealed class SnapshotRetention
{
    /// <summary>保留的小时级快照数（负数 = 不限制）。</summary>
    public int Hourly { get; set; } = 24;

    /// <summary>保留的日级快照数（负数 = 不限制）。</summary>
    public int Daily { get; set; } = 7;

    /// <summary>保留的周级快照数（负数 = 不限制）。</summary>
    public int Weekly { get; set; } = 4;
}

/// <summary>
/// 文件备份任务（v3.5 定时/实时增量调度单元）。
/// <para>存于 AppConfig.FileBackupJobs（JSON 节，等价需求"INI 段"）。</para>
/// </summary>
public sealed class FileBackupJob
{
    /// <summary>任务名（唯一标识）。</summary>
    public string Name { get; set; } = "";

    /// <summary>源路径（文件或目录）。</summary>
    public string SourcePath { get; set; } = "";

    /// <summary>true=单文件；false=目录递归。</summary>
    public bool IsSingleFile { get; set; }

    /// <summary>是否启用。</summary>
    public bool Enabled { get; set; } = true;

    /// <summary>定时全量 cron；空 = 禁用定时全量。</summary>
    public string FullCron { get; set; } = "";

    /// <summary>定时增量 cron；空 = 禁用定时增量。</summary>
    public string IncrementalCron { get; set; } = "";

    /// <summary>实时监控增量开关。</summary>
    public bool RealtimeWatch { get; set; }

    /// <summary>实时监控事件防抖窗口（毫秒，默认 3000）。</summary>
    public int WatchDebounceMs { get; set; } = 3000;

    /// <summary>快照链目录（存放 .lgchain 与关联 .lgbackup）。</summary>
    public string ChainDir { get; set; } = "";

    /// <summary>快照保留策略。</summary>
    public SnapshotRetention Retention { get; set; } = new();

    /// <summary>实时增量达到该次数后自动合并为新全量（截断过长增量链）。</summary>
    public int MaxRealtimeBeforeMerge { get; set; } = 12;

    /// <summary>口令凭据引用（密码经 HKDF 派生，不落盘明文）。</summary>
    public string PasswordRef { get; set; } = "";

    /// <summary>最近定时全量时间。</summary>
    public DateTime? LastFullAt { get; set; }

    /// <summary>最近定时增量时间。</summary>
    public DateTime? LastIncrementalAt { get; set; }

    /// <summary>最近实时增量时间。</summary>
    public DateTime? LastRealtimeAt { get; set; }

    /// <summary>快照链 ID（首次全量后回填）。</summary>
    public string ChainId { get; set; } = "";

    /// <summary>实时增量累计次数（达到合并阈值后清零）。</summary>
    public int RealtimeCount { get; set; }

    /// <summary>生成定时调度防重入键。</summary>
    public string ScheduleKey => $"file:{Name}";
}
