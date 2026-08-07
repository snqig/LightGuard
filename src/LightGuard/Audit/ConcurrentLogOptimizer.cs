// © 2026 落尘（Luochen） 原创开发 - 保留所有权利

using System.Text;
using System.Text.Json;
using System.Threading.Channels;
using LightGuard.Core;

// 项目启用 WinForms（System.Windows.Forms.Timer）会与 System.Threading.Timer 冲突，
// 此处显式别名为线程池定时器，用于统计信息周期性更新。
using Timer = System.Threading.Timer;

namespace LightGuard.Audit;

/// <summary>
/// 高并发日志优化器
/// <para>核心特性：</para>
/// <para>1. Channel&lt;T&gt; 无锁高吞吐队列，生产者非阻塞写入</para>
/// <para>2. 后台消费者批量刷盘，降低 I/O 压力</para>
/// <para>3. 事件去重：500ms 窗口内相同 user+action+file 的事件合并</para>
/// <para>4. 事件节流：每用户每秒最多 100 条，超出聚合统计</para>
/// <para>5. 日志轮转：文件达到 10MB 自动分割，保留最近 N 个文件</para>
/// </summary>
public sealed class ConcurrentLogOptimizer : IDisposable
{
    #region 常量

    /// <summary>后台消费者批处理间隔（毫秒）</summary>
    private const int BatchIntervalMs = 200;

    /// <summary>每批最大写入数量</summary>
    private const int BatchMaxSize = 500;

    /// <summary>每用户每秒最大事件数（节流阈值）</summary>
    private const int MaxEventsPerUserPerSec = 100;

    /// <summary>统计信息更新间隔（毫秒）</summary>
    private const int StatsUpdateIntervalMs = 5000;

    #endregion

    #region 字段

    private readonly string _logDirectory;
    private readonly long _maxFileSizeBytes;
    private readonly int _maxRetainedFiles;
    private readonly int _mergeWindowMs;

    private readonly Channel<SmbAuditEvent> _channel;
    private readonly CancellationTokenSource _cts;
    private readonly Task _consumerTask;
    private readonly Timer _statsTimer;

    private readonly object _fileLock = new();
    private string _currentLogFile;
    private long _currentFileSize;

    // 去重缓存：key = user|action|file, value = (事件, 计数, 首次时间)
    private readonly Dictionary<string, (SmbAuditEvent Evt, int Count, DateTime FirstTime)> _dedupCache = new();
    private readonly object _dedupLock = new();

    // 节流缓存：key = username, value = (当前秒的起始时间, 事件计数)
    private readonly Dictionary<string, (DateTime WindowStart, int Count)> _throttleCache = new();
    private readonly object _throttleLock = new();

    // 统计计数器（使用 InterLocked 原子操作）
    private long _totalEnqueued;
    private long _totalWritten;
    private long _duplicatesMerged;
    private long _throttledEvents;
    private int _rotatedFilesCount;
    private bool _disposed;

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = false
    };

    #endregion

    #region 事件

    /// <summary>
    /// 周期性统计信息更新事件
    /// </summary>
    public event Action<LogOptimizationStats>? StatsUpdated;

    #endregion

    #region 构造函数

    /// <summary>
    /// 初始化高并发日志优化器
    /// </summary>
    /// <param name="logDirectory">日志输出目录</param>
    /// <param name="maxFileSizeMb">单文件最大大小（MB），默认 10MB</param>
    /// <param name="maxRetainedFiles">最大保留文件数，默认 50</param>
    /// <param name="mergeWindowMs">去重合并窗口（毫秒），默认 500ms</param>
    public ConcurrentLogOptimizer(
        string logDirectory,
        int maxFileSizeMb = 10,
        int maxRetainedFiles = 50,
        int mergeWindowMs = 500)
    {
        _logDirectory = logDirectory ?? throw new ArgumentNullException(nameof(logDirectory));
        _maxFileSizeBytes = (long)maxFileSizeMb * 1024 * 1024;
        _maxRetainedFiles = maxRetainedFiles;
        _mergeWindowMs = mergeWindowMs;

        Directory.CreateDirectory(_logDirectory);

        _channel = Channel.CreateUnbounded<SmbAuditEvent>(new UnboundedChannelOptions
        {
            SingleReader = true,
            SingleWriter = false
        });

        _cts = new CancellationTokenSource();

        // 初始化当前日志文件
        _currentLogFile = GetNewLogFilePath();
        _currentFileSize = File.Exists(_currentLogFile)
            ? new FileInfo(_currentLogFile).Length
            : 0;

        // 启动后台消费者
        _consumerTask = Task.Run(() => ConsumeLoopAsync(_cts.Token));

        // 统计信息定时更新
        _statsTimer = new Timer(
            _ => StatsUpdated?.Invoke(GetStats()),
            null,
            StatsUpdateIntervalMs,
            StatsUpdateIntervalMs);

        ErrorReporter.Log(
            $"[ConcurrentLogOptimizer] 已初始化: 目录={_logDirectory}, " +
            $"最大文件={maxFileSizeMb}MB, 保留文件数={maxRetainedFiles}, " +
            $"合并窗口={mergeWindowMs}ms");
    }

    #endregion

    #region 公开方法

    /// <summary>
    /// 非阻塞入队
    /// <para>先经过节流检查，再写入 Channel。</para>
    /// </summary>
    /// <param name="evt">SMB 审计事件</param>
    public void Enqueue(SmbAuditEvent evt)
    {
        if (evt == null || _disposed) return;

        Interlocked.Increment(ref _totalEnqueued);

        // 节流检查
        if (ShouldThrottle(evt.UserName))
        {
            Interlocked.Increment(ref _throttledEvents);
            return;
        }

        // 写入 Channel（非阻塞）
        if (!_channel.Writer.TryWrite(evt))
        {
            ErrorReporter.Log(
                "[ConcurrentLogOptimizer] Channel 写入失败（已关闭）", "WARN");
        }
    }

    /// <summary>
    /// 获取当前统计信息
    /// </summary>
    /// <returns>统计快照</returns>
    public LogOptimizationStats GetStats()
    {
        return new LogOptimizationStats
        {
            TotalEnqueued = Interlocked.Read(ref _totalEnqueued),
            TotalWritten = Interlocked.Read(ref _totalWritten),
            DuplicatesMerged = Interlocked.Read(ref _duplicatesMerged),
            ThrottledEvents = Interlocked.Read(ref _throttledEvents),
            QueueDepth = _channel.Reader.CanCount ? _channel.Reader.Count : 0,
            CurrentFileSize = Interlocked.Read(ref _currentFileSize),
            RotatedFilesCount = _rotatedFilesCount
        };
    }

    /// <summary>
    /// 强制刷新待写入事件
    /// <para>等待 Channel 队列排空，并刷出去重缓存中的残留事件。</para>
    /// </summary>
    public void Flush()
    {
        try
        {
            // 等待队列排空（带超时）
            var deadline = DateTime.Now.AddSeconds(5);
            while (_channel.Reader.CanCount &&
                   _channel.Reader.Count > 0 &&
                   DateTime.Now < deadline)
            {
                Thread.Sleep(50);
            }

            // 刷出去重缓存中的残留事件
            FlushDedupCache();

            ErrorReporter.Log("[ConcurrentLogOptimizer] 刷新完成");
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, "[ConcurrentLogOptimizer] Flush 异常");
        }
    }

    #endregion

    #region 后台消费者

    /// <summary>
    /// 后台消费者循环
    /// <para>从 Channel 批量读取事件，经去重处理后写入文件。</para>
    /// </summary>
    private async Task ConsumeLoopAsync(CancellationToken ct)
    {
        var batch = new List<SmbAuditEvent>(BatchMaxSize);

        try
        {
            while (!ct.IsCancellationRequested)
            {
                batch.Clear();

                // 等待第一个事件（阻塞直到有数据或 Channel 关闭）
                SmbAuditEvent first;
                try
                {
                    first = await _channel.Reader.ReadAsync(ct);
                }
                catch (ChannelClosedException)
                {
                    break;
                }
                catch (OperationCanceledException)
                {
                    break;
                }

                batch.Add(first);

                // 批量读取更多事件（非阻塞）
                while (batch.Count < BatchMaxSize && _channel.Reader.TryRead(out var evt))
                {
                    batch.Add(evt);
                }

                // 处理批次：去重 + 写入
                ProcessBatch(batch);

                // 短暂延迟以攒批
                if (!ct.IsCancellationRequested)
                {
                    try
                    {
                        await Task.Delay(BatchIntervalMs, ct);
                    }
                    catch (OperationCanceledException)
                    {
                        break;
                    }
                }
            }

            // 最终刷新去重缓存
            FlushDedupCache();
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, "[ConcurrentLogOptimizer] 消费者循环异常");
        }
    }

    /// <summary>
    /// 处理一批事件：去重合并后写入文件
    /// </summary>
    private void ProcessBatch(List<SmbAuditEvent> batch)
    {
        if (batch.Count == 0) return;

        var toWrite = new List<SmbAuditEvent>();

        lock (_dedupLock)
        {
            var now = DateTime.Now;
            var mergeWindow = TimeSpan.FromMilliseconds(_mergeWindowMs);

            foreach (var evt in batch)
            {
                var key = $"{evt.UserName}|{evt.Action}|{evt.FilePath}";

                if (_dedupCache.TryGetValue(key, out var existing))
                {
                    if (now - existing.FirstTime < mergeWindow)
                    {
                        // 在合并窗口内：合并（计数+1，不单独写入）
                        _dedupCache[key] = (existing.Evt, existing.Count + 1, existing.FirstTime);
                        Interlocked.Increment(ref _duplicatesMerged);
                        continue;
                    }
                    else
                    {
                        // 超出合并窗口：刷出旧事件，开始新窗口
                        toWrite.Add(FinalizeDedupEntry(existing));
                        _dedupCache.Remove(key);
                    }
                }

                // 新事件加入去重缓存
                _dedupCache[key] = (evt, 1, now);
            }

            // 刷出超时的去重条目
            FlushExpiredDedupEntries(toWrite, now, mergeWindow);
        }

        // 写入文件
        if (toWrite.Count > 0)
        {
            WriteBatchToFile(toWrite);
        }
    }

    /// <summary>
    /// 刷出超时的去重缓存条目
    /// </summary>
    private void FlushExpiredDedupEntries(
        List<SmbAuditEvent> toWrite, DateTime now, TimeSpan mergeWindow)
    {
        var expiredKeys = new List<string>();

        foreach (var kvp in _dedupCache)
        {
            if (now - kvp.Value.FirstTime >= mergeWindow)
            {
                toWrite.Add(FinalizeDedupEntry(kvp.Value));
                expiredKeys.Add(kvp.Key);
            }
        }

        foreach (var key in expiredKeys)
        {
            _dedupCache.Remove(key);
        }
    }

    /// <summary>
    /// 将去重条目转为最终写入事件（附加合并次数到 RawEvent）
    /// </summary>
    private static SmbAuditEvent FinalizeDedupEntry(
        (SmbAuditEvent Evt, int Count, DateTime FirstTime) entry)
    {
        var evt = entry.Evt;
        if (entry.Count > 1)
        {
            var mergeNote = $"[合并x{entry.Count}]";
            evt.RawEvent = string.IsNullOrEmpty(evt.RawEvent)
                ? mergeNote
                : $"{evt.RawEvent} {mergeNote}";
        }

        return evt;
    }

    /// <summary>
    /// 强制刷出所有去重缓存中的事件
    /// </summary>
    private void FlushDedupCache()
    {
        lock (_dedupLock)
        {
            if (_dedupCache.Count == 0) return;

            var toWrite = new List<SmbAuditEvent>();
            foreach (var kvp in _dedupCache)
            {
                toWrite.Add(FinalizeDedupEntry(kvp.Value));
            }

            _dedupCache.Clear();

            if (toWrite.Count > 0)
                WriteBatchToFile(toWrite);
        }
    }

    #endregion

    #region 节流

    /// <summary>
    /// 检查用户是否应被节流（每用户每秒最多 100 条）
    /// </summary>
    /// <param name="userName">用户名</param>
    /// <returns>true 表示应节流（丢弃），false 表示放行</returns>
    private bool ShouldThrottle(string userName)
    {
        if (string.IsNullOrEmpty(userName)) return false;

        lock (_throttleLock)
        {
            var now = DateTime.Now;

            if (_throttleCache.TryGetValue(userName, out var entry))
            {
                if (now - entry.WindowStart < TimeSpan.FromSeconds(1))
                {
                    if (entry.Count >= MaxEventsPerUserPerSec)
                    {
                        return true; // 节流
                    }

                    _throttleCache[userName] = (entry.WindowStart, entry.Count + 1);
                }
                else
                {
                    // 新的一秒
                    _throttleCache[userName] = (now, 1);
                }
            }
            else
            {
                _throttleCache[userName] = (now, 1);
            }

            return false;
        }
    }

    #endregion

    #region 文件写入与轮转

    /// <summary>
    /// 批量写入文件
    /// </summary>
    private void WriteBatchToFile(List<SmbAuditEvent> events)
    {
        if (events.Count == 0) return;

        lock (_fileLock)
        {
            try
            {
                foreach (var evt in events)
                {
                    var line = JsonSerializer.Serialize(evt, JsonOpts);
                    var lineBytes = Encoding.UTF8.GetByteCount(line + Environment.NewLine);

                    // 检查是否需要轮转
                    if (_currentFileSize + lineBytes > _maxFileSizeBytes)
                    {
                        RotateLogFile();
                    }

                    File.AppendAllText(_currentLogFile, line + Environment.NewLine);
                    _currentFileSize += lineBytes;
                    Interlocked.Increment(ref _totalWritten);
                }
            }
            catch (Exception ex)
            {
                ErrorReporter.Report(ex, "[ConcurrentLogOptimizer] WriteBatchToFile 异常");
            }
        }
    }

    /// <summary>
    /// 日志文件轮转：创建新文件并清理超额旧文件
    /// </summary>
    private void RotateLogFile()
    {
        try
        {
            _currentLogFile = GetNewLogFilePath();
            _currentFileSize = 0;
            Interlocked.Increment(ref _rotatedFilesCount);

            // 清理超额的旧文件
            CleanupOldFiles();

            ErrorReporter.Log(
                $"[ConcurrentLogOptimizer] 日志轮转: 新文件={Path.GetFileName(_currentLogFile)}, " +
                $"轮转次数={_rotatedFilesCount}");
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, "[ConcurrentLogOptimizer] RotateLogFile 异常");
        }
    }

    /// <summary>
    /// 清理超过保留数量的旧日志文件
    /// </summary>
    private void CleanupOldFiles()
    {
        try
        {
            var files = Directory.GetFiles(_logDirectory, "smb_audit_*.jsonl")
                .OrderByDescending(f => f)
                .Skip(_maxRetainedFiles)
                .ToList();

            foreach (var file in files)
            {
                try { File.Delete(file); } catch { }
            }
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, "[ConcurrentLogOptimizer] CleanupOldFiles 异常");
        }
    }

    /// <summary>
    /// 生成新的日志文件路径（带时间戳和唯一标识）
    /// </summary>
    private string GetNewLogFilePath()
    {
        return Path.Combine(
            _logDirectory,
            $"smb_audit_{DateTime.Now:yyyyMMdd_HHmmss}_{Guid.NewGuid():N}.jsonl");
    }

    #endregion

    #region IDisposable

    /// <summary>
    /// 释放资源：停止定时器、完成 Channel、等待消费者退出、刷出残留事件
    /// </summary>
    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;

        try
        {
            _statsTimer.Dispose();

            // 完成写入并等待消费者退出
            _channel.Writer.TryComplete();
            try { _consumerTask.Wait(5000); } catch { }

            // 刷出残留事件
            FlushDedupCache();

            _cts.Cancel();
            _cts.Dispose();

            ErrorReporter.Log("[ConcurrentLogOptimizer] 已释放");
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, "[ConcurrentLogOptimizer] Dispose 异常");
        }
    }

    #endregion
}

#region 数据类型

/// <summary>
/// SMB 审计事件（高并发优化版）
/// <para>用于 ConcurrentLogOptimizer 的高吞吐事件管道。</para>
/// </summary>
public sealed class SmbAuditEvent
{
    /// <summary>事件时间戳</summary>
    public DateTime Timestamp { get; set; }

    /// <summary>用户名</summary>
    public string UserName { get; set; } = "";

    /// <summary>客户端 IP 地址</summary>
    public string ClientIp { get; set; } = "";

    /// <summary>文件路径</summary>
    public string FilePath { get; set; } = "";

    /// <summary>操作动作（Create/Read/Write/Delete/Rename 等）</summary>
    public string Action { get; set; } = "";

    /// <summary>操作结果（Success/Denied/Error）</summary>
    public string Result { get; set; } = "";

    /// <summary>原始事件数据</summary>
    public string RawEvent { get; set; } = "";

    public override string ToString()
    {
        return $"[{Timestamp:HH:mm:ss.fff}] {UserName}@{ClientIp} | {Action} | {FilePath} | {Result}";
    }
}

/// <summary>
/// 日志优化统计信息
/// </summary>
public sealed class LogOptimizationStats
{
    /// <summary>总入队数</summary>
    public long TotalEnqueued { get; set; }

    /// <summary>总写入数</summary>
    public long TotalWritten { get; set; }

    /// <summary>去重合并数</summary>
    public long DuplicatesMerged { get; set; }

    /// <summary>节流丢弃数</summary>
    public long ThrottledEvents { get; set; }

    /// <summary>当前队列深度</summary>
    public int QueueDepth { get; set; }

    /// <summary>当前文件大小（字节）</summary>
    public long CurrentFileSize { get; set; }

    /// <summary>已轮转文件数</summary>
    public int RotatedFilesCount { get; set; }

    public override string ToString()
    {
        return $"入队={TotalEnqueued}, 写入={TotalWritten}, 去重={DuplicatesMerged}, " +
               $"节流={ThrottledEvents}, 队列={QueueDepth}, " +
               $"文件大小={CurrentFileSize / 1024}KB, 轮转={RotatedFilesCount}";
    }
}

#endregion
