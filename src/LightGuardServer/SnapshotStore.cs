// © 2026 落尘（Luochen） 原创开发 - 保留所有权利
//
// 服务端快照存储（SnapshotStore）
//   - snapshots/{id}.json：快照元数据（客户端上报，服务端原样保存）
//   - 支持创建 / 列表 / 读取 / 删除 / 按保留策略回收
//   - 并发安全：SemaphoreSlim 串行化快照目录操作；删除时联动 BlockStore 释放引用

using System.Text.Json;
using LightGuard.Shared;

namespace LightGuardServer;

/// <summary>
/// 服务端快照存储。
/// </summary>
public sealed class SnapshotStore : IDisposable
{
    private readonly ServerConfig _config;
    private readonly BlockStore _blocks;
    private readonly SemaphoreSlim _lock = new(1, 1);
    private readonly string _snapDir;

    public SnapshotStore(ServerConfig config, BlockStore blocks)
    {
        _config = config;
        _blocks = blocks;
        _snapDir = Path.Combine(config.DataDir, "snapshots");
        Directory.CreateDirectory(_snapDir);
    }

    /// <summary>创建快照：持久化元数据，并对全部块提交引用计数。</summary>
    public CsSnapshotMeta Create(CsSnapshotMeta meta)
    {
        lock (_lock)
        {
            if (string.IsNullOrEmpty(meta.SnapshotId))
                meta.SnapshotId = $"snap_{DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()}_{Guid.NewGuid().ToString("N")[..8]}";

            var path = _config.SnapshotPath(meta.SnapshotId);
            var json = JsonSerializer.Serialize(meta, new JsonSerializerOptions { WriteIndented = true });
            var tmp = path + ".tmp";
            File.WriteAllText(tmp, json);
            File.Move(tmp, path, true);

            // 引用计数（块在客户端上传阶段已落盘，此处登记引用）
            if (meta.AllBlockHashes is { Count: > 0 })
                _blocks.CommitRefs(meta.AllBlockHashes);

            return meta;
        }
    }

    /// <summary>读取快照元数据。</summary>
    public CsSnapshotMeta? Get(string snapshotId)
    {
        lock (_lock)
        {
            var path = _config.SnapshotPath(snapshotId);
            if (!File.Exists(path)) return null;
            try { return JsonSerializer.Deserialize<CsSnapshotMeta>(File.ReadAllText(path)); }
            catch { return null; }
        }
    }

    /// <summary>列出快照概要（可按客户端过滤）。</summary>
    public List<CsSnapshotSummary> List(string? clientId = null)
    {
        lock (_lock)
        {
            var list = new List<CsSnapshotSummary>();
            foreach (var file in Directory.EnumerateFiles(_snapDir, "*" + ServerConfig.SnapshotExtension))
            {
                try
                {
                    var meta = JsonSerializer.Deserialize<CsSnapshotMeta>(File.ReadAllText(file));
                    if (meta == null) continue;
                    if (!string.IsNullOrEmpty(clientId) &&
                        !string.Equals(meta.ClientId, clientId, StringComparison.OrdinalIgnoreCase))
                        continue;

                    list.Add(new CsSnapshotSummary
                    {
                        SnapshotId = meta.SnapshotId,
                        Name = meta.Name,
                        ClientId = meta.ClientId,
                        CreatedUtc = meta.CreatedUtc,
                        EntryCount = meta.Entries?.Count ?? 0,
                        TotalBytes = meta.TotalBytes,
                        SourcePath = meta.SourcePath
                    });
                }
                catch { /* 跳过损坏快照 */ }
            }
            return list.OrderByDescending(x => x.CreatedUtc).ToList();
        }
    }

    /// <summary>删除快照：删除元数据文件 + 释放块引用（联动 BlockStore）。</summary>
    public bool Delete(string snapshotId)
    {
        lock (_lock)
        {
            var path = _config.SnapshotPath(snapshotId);
            if (!File.Exists(path)) return false;

            var meta = JsonSerializer.Deserialize<CsSnapshotMeta>(File.ReadAllText(path));
            try { File.Delete(path); } catch { }

            if (meta?.AllBlockHashes is { Count: > 0 })
                _blocks.ReleaseRefs(meta.AllBlockHashes);

            return true;
        }
    }

    /// <summary>
    /// 按保留策略回收：每客户端保留最近 N 个快照，超出删除。
    /// </summary>
    /// <returns>删除的快照数与释放的块数。</returns>
    public (int Removed, int FreedBlocks) Cleanup(int maxPerClient, string? clientId = null)
    {
        int removed = 0, freed = 0;
        if (maxPerClient < 0) return (0, 0);

        lock (_lock)
        {
            // 按客户端分组（未指定 clientId 时按全部）
            var all = List(null);
            var groups = all.GroupBy(x => x.ClientId ?? "default");
            foreach (var g in groups)
            {
                if (!string.IsNullOrEmpty(clientId) &&
                    !string.Equals(g.Key, clientId, StringComparison.OrdinalIgnoreCase))
                    continue;

                foreach (var snap in g.OrderByDescending(x => x.CreatedUtc).Skip(Math.Max(0, maxPerClient)))
                {
                    if (Delete(snap.SnapshotId!))
                        removed++;
                }
            }
        }
        return (removed, freed);
    }

    /// <inheritdoc/>
    public void Dispose() => _lock.Dispose();
}
