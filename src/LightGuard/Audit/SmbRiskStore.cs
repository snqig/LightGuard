// © 2026 落尘（Luochen） 原创开发 - 保留所有权利

using System.Text;
using System.Text.Json;
using LightGuard.Core;

namespace LightGuard.Audit;

/// <summary>
/// SMB 风险事件持久化存储（P1-2）。
/// <para>JSON Lines 按天分片：risk_{yyyyMMdd}.jsonl（每行一条 <see cref="SmbRiskEvent"/>）。</para>
/// <para>供跨重启的风险历史追溯与审计；配合保留策略按天清理。</para>
/// </summary>
public sealed class SmbRiskStore : IDisposable
{
    /// <summary>分片文件名前缀</summary>
    private const string ShardPrefix = "risk_";

    /// <summary>分片文件扩展名</summary>
    private const string ShardExt = ".jsonl";

    private readonly string _storageDir;
    private readonly SemaphoreSlim _writeLock = new(1, 1);
    private bool _disposed;

    private static readonly JsonSerializerOptions JsonOpts = new() { WriteIndented = false };

    /// <summary>
    /// 初始化风险事件存储。
    /// </summary>
    /// <param name="storageDir">存储目录（建议 DataDir/smb_audit/risks）</param>
    public SmbRiskStore(string storageDir)
    {
        _storageDir = storageDir ?? throw new ArgumentNullException(nameof(storageDir));
        Directory.CreateDirectory(_storageDir);
        ErrorReporter.Log($"[SmbRiskStore] 已初始化: {_storageDir}");
    }

    /// <summary>
    /// 追加存储一条风险事件（写入当天分片文件）。
    /// </summary>
    public async Task StoreAsync(SmbRiskEvent risk)
    {
        if (risk == null || _disposed) return;

        await _writeLock.WaitAsync();
        try
        {
            var shardPath = GetShardPath(risk.DetectedAt);
            var line = JsonSerializer.Serialize(risk, JsonOpts) + Environment.NewLine;
            await File.AppendAllTextAsync(shardPath, line, Encoding.UTF8);
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, "[SmbRiskStore] StoreAsync 异常");
        }
        finally
        {
            _writeLock.Release();
        }
    }

    /// <summary>
    /// 查询最近 N 条风险事件（跨全部分片，按时间倒序取最新）。
    /// </summary>
    public async Task<List<SmbRiskEvent>> QueryRecentAsync(int count)
    {
        if (_disposed || count <= 0) return new List<SmbRiskEvent>();
        var max = Math.Min(count, 10000);

        var results = new List<SmbRiskEvent>();
        await _writeLock.WaitAsync();
        try
        {
            // 分片文件名按日期排序：risk_20260808.jsonl > risk_20260807.jsonl
            var shardFiles = Directory.GetFiles(_storageDir, $"{ShardPrefix}*{ShardExt}")
                .OrderByDescending(f => f, StringComparer.OrdinalIgnoreCase)
                .ToList();

            foreach (var file in shardFiles)
            {
                if (results.Count >= max) break;
                try
                {
                    // 从尾部倒序读取（避免全文件加载），读取最后若干行
                    var lines = await ReadTailLinesAsync(file, max - results.Count);
                    foreach (var line in lines)
                    {
                        try
                        {
                            var risk = JsonSerializer.Deserialize<SmbRiskEvent>(line, JsonOpts);
                            if (risk != null) results.Add(risk);
                        }
                        catch { /* 跳过损坏行 */ }
                    }
                }
                catch (Exception ex)
                {
                    ErrorReporter.Report(ex, $"[SmbRiskStore] 读取分片失败: {file}");
                }
            }
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, "[SmbRiskStore] QueryRecentAsync 异常");
        }
        finally
        {
            _writeLock.Release();
        }

        results.Sort((a, b) => b.DetectedAt.CompareTo(a.DetectedAt)); // 最新在前
        return results.Take(max).ToList();
    }

    /// <summary>
    /// 清理超过保留期限的风险事件分片文件。
    /// </summary>
    /// <param name="retentionDays">保留天数（默认 90）</param>
    /// <returns>删除的分片文件数</returns>
    public int Purge(int retentionDays = 90)
    {
        if (_disposed || retentionDays <= 0) return 0;

        var cutoff = DateTime.Now.Date.AddDays(-retentionDays);
        int deleted = 0;

        try
        {
            foreach (var file in Directory.GetFiles(_storageDir, $"{ShardPrefix}*{ShardExt}"))
            {
                var date = TryParseShardDate(file);
                if (date.HasValue && date.Value.Date < cutoff)
                {
                    try { File.Delete(file); deleted++; } catch { }
                }
            }
            if (deleted > 0)
                ErrorReporter.Log($"[SmbRiskStore] 清理完成: 删除 {deleted} 个过期分片（保留 {retentionDays} 天）");
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, "[SmbRiskStore] Purge 异常");
        }
        return deleted;
    }

    /// <summary>获取当前分片文件数（统计用）。</summary>
    public int GetShardCount()
    {
        try { return Directory.GetFiles(_storageDir, $"{ShardPrefix}*{ShardExt}").Length; }
        catch { return 0; }
    }

    /// <summary>读取文件末尾最多 <paramref name="maxLines"/> 行（倒序读取优化）。</summary>
    private static async Task<List<string>> ReadTailLinesAsync(string filePath, int maxLines)
    {
        var result = new List<string>();
        try
        {
            var allLines = await File.ReadAllLinesAsync(filePath, Encoding.UTF8);
            var start = Math.Max(0, allLines.Length - maxLines);
            for (var i = allLines.Length - 1; i >= start; i--)
            {
                if (!string.IsNullOrWhiteSpace(allLines[i]))
                    result.Add(allLines[i]);
            }
        }
        catch { /* 读取失败返回空 */ }
        return result;
    }

    /// <summary>获取指定时间的分片文件路径。</summary>
    private string GetShardPath(DateTime timestamp)
        => Path.Combine(_storageDir, $"{ShardPrefix}{timestamp:yyyyMMdd}{ShardExt}");

    /// <summary>从分片文件名解析日期。</summary>
    private static DateTime? TryParseShardDate(string filePath)
    {
        var fileName = Path.GetFileNameWithoutExtension(filePath);
        var dateStr = fileName.Substring(ShardPrefix.Length);
        if (dateStr.Length >= 8 &&
            DateTime.TryParseExact(dateStr.Substring(0, 8), "yyyyMMdd", null,
                System.Globalization.DateTimeStyles.None, out var date))
        {
            return date;
        }
        return null;
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        try { _writeLock.Dispose(); } catch { }
    }
}
