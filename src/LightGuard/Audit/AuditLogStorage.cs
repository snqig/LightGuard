// © 2026 落尘（Luochen） 原创开发 - 保留所有权利

using System.Text;
using System.Text.Json;
using LightGuard.Core;

namespace LightGuard.Audit;

/// <summary>
/// 分片式审计日志持久化存储
/// <para>存储格式：JSON Lines（每行一条 JSON），按天分片：audit_{yyyyMMdd}.jsonl</para>
/// <para>并发控制：SemaphoreSlim 保护文件读写</para>
/// <para>自动分片：每天一个文件，单文件超限时创建溢出分片</para>
/// <para>内存索引：启动时加载全部事件索引，支持按时间/用户/文件路径快速查询</para>
/// </summary>
public sealed class AuditLogStorage : IDisposable
{
    #region 常量

    /// <summary>分片文件名前缀</summary>
    private const string ShardPrefix = "audit_";

    /// <summary>分片文件扩展名</summary>
    private const string ShardExt = ".jsonl";

    /// <summary>单分片最大大小（字节，默认 50MB）</summary>
    private const long MaxShardSizeBytes = 50L * 1024 * 1024;

    #endregion

    #region 字段

    private readonly string _storageDir;
    private readonly SemaphoreSlim _writeLock = new(1, 1);
    private readonly SemaphoreSlim _readLock = new(1, 1);
    private bool _disposed;

    // 内存索引（启动时加载，写入时增量更新）
    private readonly List<IndexEntry> _index = new();
    private readonly object _indexLock = new();
    private readonly HashSet<string> _uniqueUsers = new();
    private readonly HashSet<string> _uniqueFiles = new();

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = false
    };

    #endregion

    #region 构造函数

    /// <summary>
    /// 初始化审计日志存储
    /// </summary>
    /// <param name="storageDir">存储目录</param>
    public AuditLogStorage(string storageDir)
    {
        _storageDir = storageDir ?? throw new ArgumentNullException(nameof(storageDir));
        Directory.CreateDirectory(_storageDir);

        // 启动时加载索引
        LoadIndex();

        ErrorReporter.Log(
            $"[AuditLogStorage] 已初始化: 目录={_storageDir}, 索引事件数={_index.Count}");
    }

    #endregion

    #region 写入

    /// <summary>
    /// 异步存储单条审计事件
    /// <para>自动写入对应日期的分片文件，超限时创建溢出分片。</para>
    /// </summary>
    /// <param name="evt">审计事件</param>
    public async Task StoreAsync(SmbAuditEvent evt)
    {
        if (evt == null || _disposed) return;

        await _writeLock.WaitAsync();
        try
        {
            var shardPath = GetShardPath(evt.Timestamp);

            // 检查分片大小，超限时创建溢出分片
            if (File.Exists(shardPath))
            {
                var size = new FileInfo(shardPath).Length;
                if (size >= MaxShardSizeBytes)
                {
                    shardPath = GetOverflowShardPath(evt.Timestamp);
                }
            }

            var line = JsonSerializer.Serialize(evt, JsonOpts) + Environment.NewLine;
            await File.AppendAllTextAsync(shardPath, line);

            // 更新内存索引
            lock (_indexLock)
            {
                _index.Add(new IndexEntry
                {
                    Timestamp = evt.Timestamp,
                    UserName = evt.UserName,
                    FilePath = evt.FilePath,
                    Action = evt.Action,
                    ShardFile = Path.GetFileName(shardPath)
                });

                _uniqueUsers.Add(evt.UserName);
                _uniqueFiles.Add(evt.FilePath);
            }
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, "[AuditLogStorage] StoreAsync 异常");
        }
        finally
        {
            _writeLock.Release();
        }
    }

    #endregion

    #region 查询

    /// <summary>
    /// 异步查询审计事件
    /// <para>支持按时间范围、用户名、文件路径、操作类型筛选。</para>
    /// <para>先根据时间范围筛选分片文件，再逐行扫描匹配。</para>
    /// </summary>
    /// <param name="filter">查询过滤条件</param>
    /// <returns>匹配的事件列表（按时间升序）</returns>
    public async Task<List<SmbAuditEvent>> QueryAsync(AuditQueryFilter filter)
    {
        if (_disposed) return new List<SmbAuditEvent>();
        filter ??= new AuditQueryFilter();

        await _readLock.WaitAsync();
        try
        {
            // 确定需要扫描的分片文件
            var shardFiles = GetShardFilesForFilter(filter);

            var results = new List<SmbAuditEvent>();
            var maxResults = filter.MaxResults > 0 ? filter.MaxResults : 1000;

            foreach (var shardFile in shardFiles)
            {
                if (results.Count >= maxResults) break;

                try
                {
                    using var fs = new FileStream(
                        shardFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs, Encoding.UTF8);

                    while (!sr.EndOfStream && results.Count < maxResults)
                    {
                        var line = await sr.ReadLineAsync();
                        if (string.IsNullOrWhiteSpace(line)) continue;

                        SmbAuditEvent? evt;
                        try
                        {
                            evt = JsonSerializer.Deserialize<SmbAuditEvent>(line, JsonOpts);
                        }
                        catch
                        {
                            continue;
                        }

                        if (evt == null) continue;
                        if (MatchesFilter(evt, filter))
                            results.Add(evt);
                    }
                }
                catch (Exception ex)
                {
                    ErrorReporter.Report(ex, $"[AuditLogStorage] 读取分片失败: {shardFile}");
                }
            }

            // 按时间排序
            results.Sort((a, b) => a.Timestamp.CompareTo(b.Timestamp));
            return results;
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, "[AuditLogStorage] QueryAsync 异常");
            return new List<SmbAuditEvent>();
        }
        finally
        {
            _readLock.Release();
        }
    }

    /// <summary>
    /// 检查事件是否匹配过滤条件
    /// </summary>
    private static bool MatchesFilter(SmbAuditEvent evt, AuditQueryFilter filter)
    {
        if (filter.StartTime.HasValue && evt.Timestamp < filter.StartTime.Value)
            return false;
        if (filter.EndTime.HasValue && evt.Timestamp > filter.EndTime.Value)
            return false;
        if (!string.IsNullOrEmpty(filter.UserName) &&
            !evt.UserName.Equals(filter.UserName, StringComparison.OrdinalIgnoreCase))
            return false;
        if (!string.IsNullOrEmpty(filter.FilePath) &&
            !evt.FilePath.Contains(filter.FilePath, StringComparison.OrdinalIgnoreCase))
            return false;
        if (!string.IsNullOrEmpty(filter.Action) &&
            !evt.Action.Equals(filter.Action, StringComparison.OrdinalIgnoreCase))
            return false;
        return true;
    }

    #endregion

    #region 清理

    /// <summary>
    /// 异步清理超过保留期限的记录
    /// </summary>
    /// <param name="retentionDays">保留天数</param>
    /// <returns>删除的记录数</returns>
    public async Task<int> PurgeAsync(int retentionDays)
    {
        if (_disposed) return 0;

        var cutoff = DateTime.Now.AddDays(-retentionDays);
        int deletedCount = 0;

        await _writeLock.WaitAsync();
        try
        {
            // 删除过期的分片文件
            var shardFiles = Directory.GetFiles(_storageDir, $"{ShardPrefix}*{ShardExt}");
            foreach (var file in shardFiles)
            {
                var shardDate = TryParseShardDate(file);
                if (shardDate.HasValue && shardDate.Value.Date < cutoff.Date)
                {
                    try
                    {
                        // 统计文件中的行数
                        var lines = await File.ReadAllLinesAsync(file);
                        deletedCount += lines.Count(l => !string.IsNullOrWhiteSpace(l));
                        File.Delete(file);
                    }
                    catch { }
                }
            }

            // 清理内存索引
            lock (_indexLock)
            {
                var removed = _index.RemoveAll(e => e.Timestamp < cutoff);
                if (deletedCount == 0) deletedCount = removed;

                // 重建去重集合
                _uniqueUsers.Clear();
                _uniqueFiles.Clear();
                foreach (var entry in _index)
                {
                    _uniqueUsers.Add(entry.UserName);
                    _uniqueFiles.Add(entry.FilePath);
                }
            }

            ErrorReporter.Log(
                $"[AuditLogStorage] 清理完成: 保留 {retentionDays} 天, " +
                $"删除 {deletedCount} 条记录");
            return deletedCount;
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, "[AuditLogStorage] PurgeAsync 异常");
            return 0;
        }
        finally
        {
            _writeLock.Release();
        }
    }

    #endregion

    #region 统计

    /// <summary>
    /// 异步获取存储统计信息
    /// </summary>
    /// <returns>存储统计快照</returns>
    public Task<AuditStorageStats> GetStatsAsync()
    {
        try
        {
            var shardFiles = Directory.GetFiles(_storageDir, $"{ShardPrefix}*{ShardExt}");
            long storageSize = 0;
            foreach (var file in shardFiles)
            {
                try { storageSize += new FileInfo(file).Length; } catch { }
            }

            DateTime? earliest = null;
            DateTime? latest = null;
            int totalEvents;

            lock (_indexLock)
            {
                totalEvents = _index.Count;
                if (_index.Count > 0)
                {
                    earliest = _index.Min(e => e.Timestamp);
                    latest = _index.Max(e => e.Timestamp);
                }
            }

            var stats = new AuditStorageStats
            {
                TotalEvents = totalEvents,
                EarliestEvent = earliest,
                LatestEvent = latest,
                UniqueUsers = _uniqueUsers.Count,
                UniqueFiles = _uniqueFiles.Count,
                StorageSizeBytes = storageSize,
                ShardCount = shardFiles.Length
            };

            return Task.FromResult(stats);
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, "[AuditLogStorage] GetStatsAsync 异常");
            return Task.FromResult(new AuditStorageStats());
        }
    }

    #endregion

    #region 分片文件管理

    /// <summary>
    /// 获取指定日期的分片文件路径
    /// </summary>
    private string GetShardPath(DateTime timestamp)
    {
        return Path.Combine(_storageDir, $"{ShardPrefix}{timestamp:yyyyMMdd}{ShardExt}");
    }

    /// <summary>
    /// 获取溢出分片文件路径（当天分片已满时使用）
    /// </summary>
    private string GetOverflowShardPath(DateTime timestamp)
    {
        int seq = 1;
        string path;
        do
        {
            path = Path.Combine(
                _storageDir,
                $"{ShardPrefix}{timestamp:yyyyMMdd}_{seq}{ShardExt}");
            seq++;
        } while (File.Exists(path) && new FileInfo(path).Length >= MaxShardSizeBytes);

        return path;
    }

    /// <summary>
    /// 根据过滤条件获取需要扫描的分片文件列表
    /// <para>优化：按时间范围跳过不在范围内的分片文件</para>
    /// </summary>
    private List<string> GetShardFilesForFilter(AuditQueryFilter filter)
    {
        var allFiles = Directory.GetFiles(_storageDir, $"{ShardPrefix}*{ShardExt}")
            .OrderBy(f => f, StringComparer.OrdinalIgnoreCase)
            .ToList();

        // 按时间范围筛选分片文件
        if (!filter.StartTime.HasValue && !filter.EndTime.HasValue)
            return allFiles;

        var result = new List<string>();
        foreach (var file in allFiles)
        {
            var shardDate = TryParseShardDate(file);
            if (shardDate.HasValue)
            {
                // 分片日期在查询结束时间之后则跳过
                if (filter.EndTime.HasValue &&
                    shardDate.Value.Date > filter.EndTime.Value.Date)
                    continue;
                // 分片日期在查询开始时间之前则跳过
                if (filter.StartTime.HasValue &&
                    shardDate.Value.Date < filter.StartTime.Value.Date.AddDays(-1))
                    continue;
            }

            result.Add(file);
        }

        return result;
    }

    /// <summary>
    /// 尝试从分片文件名解析日期
    /// </summary>
    private static DateTime? TryParseShardDate(string filePath)
    {
        var fileName = Path.GetFileNameWithoutExtension(filePath);
        var dateStr = fileName.Substring(ShardPrefix.Length);

        if (dateStr.Length >= 8 &&
            DateTime.TryParseExact(
                dateStr.Substring(0, 8), "yyyyMMdd", null,
                System.Globalization.DateTimeStyles.None, out var date))
        {
            return date;
        }

        return null;
    }

    #endregion

    #region 索引管理

    /// <summary>
    /// 加载磁盘索引（扫描所有分片文件）
    /// </summary>
    private void LoadIndex()
    {
        try
        {
            var shardFiles = Directory.GetFiles(_storageDir, $"{ShardPrefix}*{ShardExt}");
            foreach (var file in shardFiles)
            {
                try
                {
                    using var fs = new FileStream(
                        file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs, Encoding.UTF8);

                    while (!sr.EndOfStream)
                    {
                        var line = sr.ReadLine();
                        if (string.IsNullOrWhiteSpace(line)) continue;

                        try
                        {
                            var evt = JsonSerializer.Deserialize<SmbAuditEvent>(line, JsonOpts);
                            if (evt != null)
                            {
                                lock (_indexLock)
                                {
                                    _index.Add(new IndexEntry
                                    {
                                        Timestamp = evt.Timestamp,
                                        UserName = evt.UserName,
                                        FilePath = evt.FilePath,
                                        Action = evt.Action,
                                        ShardFile = Path.GetFileName(file)
                                    });
                                    _uniqueUsers.Add(evt.UserName);
                                    _uniqueFiles.Add(evt.FilePath);
                                }
                            }
                        }
                        catch { }
                    }
                }
                catch { }
            }

            // 按时间排序索引
            lock (_indexLock)
            {
                _index.Sort((a, b) => a.Timestamp.CompareTo(b.Timestamp));
            }
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, "[AuditLogStorage] LoadIndex 异常");
        }
    }

    #endregion

    #region IDisposable

    /// <summary>
    /// 释放资源
    /// </summary>
    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;

        try
        {
            _writeLock.Dispose();
            _readLock.Dispose();
        }
        catch { }

        ErrorReporter.Log("[AuditLogStorage] 已释放");
    }

    #endregion

    #region 内部类型

    /// <summary>内存索引条目</summary>
    private sealed class IndexEntry
    {
        public DateTime Timestamp { get; set; }
        public string UserName { get; set; } = "";
        public string FilePath { get; set; } = "";
        public string Action { get; set; } = "";
        public string ShardFile { get; set; } = "";
    }

    #endregion
}

#region 数据类型

/// <summary>
/// 审计查询过滤条件
/// </summary>
public sealed class AuditQueryFilter
{
    /// <summary>起始时间（null 表示不限制）</summary>
    public DateTime? StartTime { get; set; }

    /// <summary>结束时间（null 表示不限制）</summary>
    public DateTime? EndTime { get; set; }

    /// <summary>用户名筛选（精确匹配，不区分大小写）</summary>
    public string? UserName { get; set; }

    /// <summary>文件路径筛选（模糊匹配，包含即可）</summary>
    public string? FilePath { get; set; }

    /// <summary>操作类型筛选（精确匹配，不区分大小写）</summary>
    public string? Action { get; set; }

    /// <summary>最低严重等级（预留字段）</summary>
    public int? MinSeverity { get; set; }

    /// <summary>最大返回结果数</summary>
    public int MaxResults { get; set; } = 1000;
}

/// <summary>
/// 审计存储统计信息
/// </summary>
public sealed class AuditStorageStats
{
    /// <summary>总事件数</summary>
    public int TotalEvents { get; set; }

    /// <summary>最早事件时间</summary>
    public DateTime? EarliestEvent { get; set; }

    /// <summary>最新事件时间</summary>
    public DateTime? LatestEvent { get; set; }

    /// <summary>唯一用户数</summary>
    public int UniqueUsers { get; set; }

    /// <summary>唯一文件数</summary>
    public int UniqueFiles { get; set; }

    /// <summary>存储占用字节数</summary>
    public long StorageSizeBytes { get; set; }

    /// <summary>分片文件数</summary>
    public int ShardCount { get; set; }

    public override string ToString()
    {
        return $"事件总数={TotalEvents}, " +
               $"时间范围={EarliestEvent:yyyy-MM-dd}~{LatestEvent:yyyy-MM-dd}, " +
               $"用户数={UniqueUsers}, 文件数={UniqueFiles}, " +
               $"存储={StorageSizeBytes / 1024.0 / 1024.0:F1}MB, 分片={ShardCount}";
    }
}

#endregion
