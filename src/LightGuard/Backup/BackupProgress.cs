// © 2026 落尘（Luochen） 原创开发 - 保留所有权利

using System.Diagnostics;

namespace LightGuard.Backup;

/// <summary>
/// 备份阶段。
/// </summary>
public enum BackupPhase
{
    /// <summary>备份中（读取 / 分片 / 加密）。</summary>
    Backup,

    /// <summary>完整性校验中。</summary>
    Verify,

    /// <summary>上传 / 写入远程目标中。</summary>
    Upload
}

/// <summary>
/// 备份进度信息（UI 展示用）。
/// </summary>
public sealed class BackupProgressInfo
{
    /// <summary>完成百分比（0-100）。</summary>
    public double Percent { get; set; }

    /// <summary>当前处理速度（MB/s）。</summary>
    public double SpeedMBps { get; set; }

    /// <summary>已处理文件数。</summary>
    public int ProcessedFiles { get; set; }

    /// <summary>总文件数。</summary>
    public int TotalFiles { get; set; }

    /// <summary>已处理字节数。</summary>
    public long ProcessedBytes { get; set; }

    /// <summary>总字节数。</summary>
    public long TotalBytes { get; set; }

    /// <summary>预计剩余时间。</summary>
    public TimeSpan RemainingTime { get; set; }

    /// <summary>当前正在处理的文件路径。</summary>
    public string CurrentFile { get; set; } = string.Empty;

    /// <summary>是否处于加密阶段。</summary>
    public bool IsEncrypting { get; set; }

    /// <summary>当前阶段。</summary>
    public BackupPhase Phase { get; set; }
}

/// <summary>
/// 备份进度跟踪器 - 实时计算百分比、速度、剩余时间，并支持取消。
/// </summary>
public sealed class BackupProgress
{
    private readonly Stopwatch _sw = Stopwatch.StartNew();
    private int _totalFiles;
    private long _totalBytes;

    /// <summary>进度变更事件。</summary>
    public event Action<BackupProgressInfo>? ProgressChanged;

    /// <summary>取消令牌源。</summary>
    public CancellationTokenSource CancellationTokenSource { get; } = new();

    /// <summary>取消令牌。</summary>
    public CancellationToken CancellationToken => CancellationTokenSource.Token;

    /// <summary>是否已取消。</summary>
    public bool IsCancellationRequested => CancellationTokenSource.IsCancellationRequested;

    /// <summary>
    /// 设置总量（文件数与字节数）。
    /// </summary>
    /// <param name="totalFiles">总文件数。</param>
    /// <param name="totalBytes">总字节数。</param>
    public void SetTotal(int totalFiles, long totalBytes)
    {
        _totalFiles = totalFiles;
        _totalBytes = totalBytes;
    }

    /// <summary>
    /// 更新进度并触发 <see cref="ProgressChanged"/> 事件。
    /// </summary>
    /// <param name="processedFiles">已处理文件数。</param>
    /// <param name="processedBytes">已处理字节数。</param>
    /// <param name="currentFile">当前文件路径。</param>
    /// <param name="isEncrypting">是否处于加密阶段。</param>
    /// <param name="phase">当前阶段。</param>
    public void UpdateProgress(int processedFiles, long processedBytes, string currentFile, bool isEncrypting, BackupPhase phase)
    {
        var elapsedSec = _sw.Elapsed.TotalSeconds;
        var speedMBps = elapsedSec > 0 ? processedBytes / 1024.0 / 1024.0 / elapsedSec : 0;

        var percent = _totalBytes > 0
            ? Math.Min(100, processedBytes * 100.0 / _totalBytes)
            : (_totalFiles > 0 ? Math.Min(100, processedFiles * 100.0 / _totalFiles) : 0);

        var remaining = speedMBps > 0 && _totalBytes > processedBytes
            ? TimeSpan.FromSeconds((_totalBytes - processedBytes) / 1024.0 / 1024.0 / speedMBps)
            : TimeSpan.Zero;

        var info = new BackupProgressInfo
        {
            Percent = percent,
            SpeedMBps = speedMBps,
            ProcessedFiles = processedFiles,
            TotalFiles = _totalFiles,
            ProcessedBytes = processedBytes,
            TotalBytes = _totalBytes,
            RemainingTime = remaining,
            CurrentFile = currentFile ?? string.Empty,
            IsEncrypting = isEncrypting,
            Phase = phase
        };

        try { ProgressChanged?.Invoke(info); } catch { }
    }

    /// <summary>
    /// 请求取消备份。
    /// </summary>
    public void Cancel() => CancellationTokenSource.Cancel();

    /// <summary>
    /// 若已请求取消则抛出 <see cref="OperationCanceledException"/>。
    /// </summary>
    public void ThrowIfCancellationRequested() => CancellationTokenSource.Token.ThrowIfCancellationRequested();
}
