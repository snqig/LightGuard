// © 2026 落尘（Luochen） 原创开发 - 保留所有权利
//
// 服务端块存储（BlockStore）
//   - 本地持有加密块文件（blocks/{hash}.blk）+ 全局索引（meta.index）
//   - 块 hash 存在性校验完全本地，客户端无需读取远端备份集比对
//   - 并发安全：SemaphoreSlim 串行化索引读写 + 原子写（tmp + Move）
//   - 引用计数：块被快照引用 refs++；快照删除 refs--，归零删除块文件

using System.Text.Json;

namespace LightGuardServer;

/// <summary>块索引条目。</summary>
public sealed class BlockIndexEntry
{
    /// <summary>块文件字节数（密文包总长）。</summary>
    public long Length { get; set; }

    /// <summary>引用计数（被快照引用次数）。</summary>
    public int Refs { get; set; }

    /// <summary>最后访问时间（Unix 秒，回收辅助）。</summary>
    public long LastUsedUtc { get; set; }
}

/// <summary>全局块索引（meta.index 内存态）。</summary>
public sealed class BlockIndex
{
    /// <summary>hash → 条目。</summary>
    public Dictionary<string, BlockIndexEntry> Blocks { get; set; } = new(StringComparer.OrdinalIgnoreCase);
}

/// <summary>
/// 服务端块存储：负责块文件写入/读取、存在性查询、索引维护（引用计数）。
/// </summary>
public sealed class BlockStore : IDisposable
{
    private readonly ServerConfig _config;
    private readonly SemaphoreSlim _lock = new(1, 1);
    private readonly string _indexPath;
    private BlockIndex _index = new();
    private bool _dirty;

    /// <summary>当前块总数。</summary>
    public int BlockCount { get { lock (_lock) return _index.Blocks.Count; } }

    public BlockStore(ServerConfig config)
    {
        _config = config;
        _indexPath = config.MetaIndexPath;
        LoadIndex();
    }

    /// <summary>从 meta.index 加载（损坏则重建空索引并备份旧文件）。</summary>
    private void LoadIndex()
    {
        try
        {
            if (!File.Exists(_indexPath)) return;
            var json = File.ReadAllText(_indexPath);
            _index = JsonSerializer.Deserialize<BlockIndex>(json) ?? new BlockIndex();
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[块存储] 索引损坏，重建空索引：{ex.Message}");
            try { File.Copy(_indexPath, _indexPath + ".bak", true); } catch { }
            _index = new BlockIndex();
        }
    }

    /// <summary>持久化索引（原子写：tmp + Move）。</summary>
    private void SaveIndex()
    {
        try
        {
            var json = JsonSerializer.Serialize(_index, new JsonSerializerOptions { WriteIndented = false });
            var tmp = _indexPath + ".tmp";
            File.WriteAllText(tmp, json);
            File.Move(tmp, _indexPath, true);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[块存储] 保存索引失败：{ex.Message}");
        }
    }

    /// <summary>块是否已存在（本地索引查询，无网络 IO）。</summary>
    public bool Exists(string hash)
    {
        lock (_lock)
            return _index.Blocks.ContainsKey(hash);
    }

    /// <summary>批量查询缺失块：输入全部 hash，返回服务端不存在的列表。</summary>
    public List<string> FindMissing(IEnumerable<string> hashes)
    {
        var missing = new List<string>();
        lock (_lock)
        {
            foreach (var h in hashes)
            {
                if (string.IsNullOrWhiteSpace(h)) continue;
                if (!_index.Blocks.ContainsKey(h))
                    missing.Add(h);
            }
        }
        return missing;
    }

    /// <summary>获取块密文包字节数。</summary>
    public long GetBlockLength(string hash)
    {
        lock (_lock)
            return _index.Blocks.TryGetValue(hash, out var e) ? e.Length : -1;
    }

    /// <summary>
    /// 追加写入块分片（断点续传）。全部分片完成后返回 true（块完整落盘）。
    /// </summary>
    /// <param name="hash">块 hash。</param>
    /// <param name="data">本分片密文包字节。</param>
    /// <param name="offset">本分片在块文件中的偏移。</param>
    /// <param name="isFinal">是否最后一片。</param>
    /// <returns>当前已接收字节数。</returns>
    public long AppendBlock(string hash, byte[] data, long offset, bool isFinal)
    {
        var blockPath = _config.BlockPath(hash);
        var tmpPath = blockPath + ".part";

        lock (_lock)
        {
            // 已存在完整块：直接返回（幂等）
            if (_index.Blocks.TryGetValue(hash, out var existing) && File.Exists(blockPath))
            {
                _index.Blocks[hash].LastUsedUtc = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
                return existing.Length;
            }

            // 以追加方式写入（支持分片乱序到达，按 offset 定位）
            using (var fs = new FileStream(tmpPath, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None))
            {
                fs.Position = offset;
                fs.Write(data, 0, data.Length);
                fs.Flush();
            }

            var currentLen = new FileInfo(tmpPath).Length;

            if (isFinal)
            {
                // 最后一片：重命名 .part → .blk，登记索引
                File.Move(tmpPath, blockPath, true);
                _index.Blocks[hash] = new BlockIndexEntry
                {
                    Length = currentLen,
                    Refs = 0,
                    LastUsedUtc = DateTimeOffset.UtcNow.ToUnixTimeSeconds()
                };
                _dirty = true;
            }

            return currentLen;
        }
    }

    /// <summary>提交引用：快照创建后对全部块 refs++（幂等：先计数后持久化）。</summary>
    public void CommitRefs(IEnumerable<string> hashes)
    {
        lock (_lock)
        {
            foreach (var h in hashes)
            {
                if (_index.Blocks.TryGetValue(h, out var e))
                {
                    e.Refs++;
                    e.LastUsedUtc = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
                    _dirty = true;
                }
            }
            if (_dirty) SaveIndex();
        }
    }

    /// <summary>释放引用：删除快照后 refs--，归零删除块文件。返回释放的块数。</summary>
    public int ReleaseRefs(IEnumerable<string> hashes)
    {
        var freed = 0;
        lock (_lock)
        {
            foreach (var h in hashes)
            {
                if (!_index.Blocks.TryGetValue(h, out var e)) continue;
                e.Refs = Math.Max(0, e.Refs - 1);
                _dirty = true;
                if (e.Refs == 0)
                {
                    // 归零：删除块文件 + 索引
                    try
                    {
                        var p = _config.BlockPath(h);
                        if (File.Exists(p)) File.Delete(p);
                    }
                    catch { }
                    _index.Blocks.Remove(h);
                    freed++;
                }
            }
            if (_dirty) SaveIndex();
        }
        return freed;
    }

    /// <summary>读取块密文包分片（恢复下发）。offset/length 越界时自动截断。</summary>
    public byte[] ReadBlock(string hash, long offset, int length)
    {
        var blockPath = _config.BlockPath(hash);
        lock (_lock)
        {
            if (!_index.Blocks.TryGetValue(hash, out _) || !File.Exists(blockPath))
                throw new FileNotFoundException($"块不存在：{hash}");
        }

        using var fs = new FileStream(blockPath, FileMode.Open, FileAccess.Read, FileShare.Read);
        fs.Position = Math.Min(offset, fs.Length);
        var remaining = (int)Math.Min(length, fs.Length - fs.Position);
        if (remaining <= 0) return Array.Empty<byte>();
        var buf = new byte[remaining];
        fs.ReadExactly(buf, 0, remaining);
        return buf;
    }

    /// <summary>强制落盘索引（关闭前/定时）。</summary>
    public void Flush()
    {
        lock (_lock)
        {
            if (_dirty) SaveIndex();
            _dirty = false;
        }
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        Flush();
        _lock.Dispose();
    }
}
