// © 2026 落尘（Luochen） 原创开发 - 保留所有权利

namespace LightGuard.Recovery;

/// <summary>
/// 恢复模式。
/// </summary>
public enum RecoveryMode
{
    /// <summary>隔离恢复（默认安全）：恢复到新目录，不覆盖任何现有数据。</summary>
    Isolated,

    /// <summary>增量恢复：仅恢复变更文件，保留未变更的本地文件。</summary>
    Incremental,

    /// <summary>强制覆盖恢复：灾难恢复专用，覆盖目标已存在的同名文件。</summary>
    ForceOverwrite
}

/// <summary>
/// 恢复进度信息（UI 展示用）。
/// </summary>
public sealed class RecoveryProgressInfo
{
    /// <summary>整体完成百分比（0-100）。</summary>
    public double Percent { get; set; }

    /// <summary>解密进度百分比（0-100）。</summary>
    public double DecryptProgress { get; set; }

    /// <summary>分片恢复进度百分比（0-100）。</summary>
    public double ShardProgress { get; set; }

    /// <summary>文件写入进度百分比（0-100）。</summary>
    public double WriteProgress { get; set; }

    /// <summary>完整性校验进度百分比（0-100）。</summary>
    public double VerifyProgress { get; set; }

    /// <summary>预计剩余时间。</summary>
    public TimeSpan RemainingTime { get; set; }

    /// <summary>当前正在处理的文件。</summary>
    public string CurrentFile { get; set; } = string.Empty;
}
