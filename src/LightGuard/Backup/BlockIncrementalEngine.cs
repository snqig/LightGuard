// © 2026 落尘（Luochen） 原创开发 - 保留所有权利

using System.Security.Cryptography;

namespace LightGuard.Backup;

/// <summary>
/// 块级去重索引（块 SHA256 → 长度）。
/// <para>来源于基础备份（全量）的压缩块元数据，供增量备份判定"块是否与基准一致"。</para>
/// </summary>
public sealed class BlockChunkIndex
{
    private readonly Dictionary<string, long> _hashToLen = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>块大小（字节，固定块切分）。</summary>
    public int ChunkSize { get; }

    /// <summary>索引块数。</summary>
    public int Count => _hashToLen.Count;

    internal BlockChunkIndex(int chunkSize) => ChunkSize = chunkSize;

    /// <summary>是否包含指定块哈希。</summary>
    public bool Contains(string hash) => _hashToLen.ContainsKey(hash);

    /// <summary>尝试获取块长度。</summary>
    public bool TryGetLength(string hash, out long length) => _hashToLen.TryGetValue(hash, out length);

    internal void Add(string hash, long length) => _hashToLen[hash] = length;

    /// <summary>合并另一个索引的块哈希（供基础索引回退构建用）。</summary>
    internal void MergeFrom(BlockChunkIndex other)
    {
        if (other == null) return;
        foreach (var kv in other._hashToLen)
            _hashToLen[kv.Key] = kv.Value;
    }
}

/// <summary>
/// 单块差分记录。
/// </summary>
public sealed class BlockRef
{
    /// <summary>块在文件中的偏移。</summary>
    public long Offset { get; init; }

    /// <summary>块长度（字节）。</summary>
    public int Length { get; init; }

    /// <summary>块 SHA256（十六进制）。</summary>
    public string Hash { get; init; } = "";

    /// <summary>是否为复用块（与基准一致，无需存储新数据）。</summary>
    public bool Reused { get; init; }

    /// <summary>新块数据（Reused=false 时有效）。</summary>
    public byte[]? Data { get; init; }
}

/// <summary>
/// 块级差分结果（一个文件）。
/// </summary>
public sealed class BlockDeltaResult
{
    /// <summary>全部块记录（按文件偏移顺序）。</summary>
    public List<BlockRef> Blocks { get; } = new();

    /// <summary>新块字节数（需存储）。</summary>
    public long NewBytes { get; set; }

    /// <summary>复用块字节数（无需重复存储）。</summary>
    public long ReusedBytes { get; set; }

    /// <summary>新块数。</summary>
    public int NewCount { get; set; }

    /// <summary>复用块数。</summary>
    public int ReusedCount { get; set; }

    /// <summary>复用率（0-1，越高省空间越多）。</summary>
    public double SavingsRatio => (NewBytes + ReusedBytes) > 0 ? ReusedBytes / (double)(NewBytes + ReusedBytes) : 0;
}

/// <summary>
/// 块级增量差分引擎（P0：USN 变更追踪 + 块级差分核心）。
/// <para>固定块大小切分 → 逐块 SHA256 → 与基准块索引比对：一致块标记复用（不存储），
/// 变更块标记新增（存储）。恢复时用基准数据 + 新块数据重建最新版本。</para>
/// <para>纯数据层实现（无 IO 依赖），存储编排见 <see cref="BlockIncrementalService"/>。</para>
/// </summary>
public static class BlockIncrementalEngine
{
    /// <summary>默认块大小（字节）。</summary>
    public const int DefaultChunkSize = 256 * 1024;

    /// <summary>
    /// 从文件数据构建块索引（全量备份后调用，供下次增量复用）。
    /// </summary>
    public static BlockChunkIndex BuildIndex(byte[] data, int chunkSize = DefaultChunkSize)
    {
        ArgumentNullException.ThrowIfNull(data);
        chunkSize = Math.Max(1, chunkSize);

        var index = new BlockChunkIndex(chunkSize);
        for (int pos = 0; pos < data.Length; pos += chunkSize)
        {
            var len = Math.Min(chunkSize, data.Length - pos);
            var hash = Convert.ToHexString(SHA256.HashData(data.AsSpan(pos, len)));
            index.Add(hash, len);
        }
        return index;
    }

    /// <summary>
    /// 从压缩块元数据构建索引（Chunked 容器直接复用块哈希，无需重新读取数据）。
    /// </summary>
    public static BlockChunkIndex BuildIndexFromChunks(IEnumerable<(string Hash, long Length)> chunks, int chunkSize = DefaultChunkSize)
    {
        ArgumentNullException.ThrowIfNull(chunks);
        chunkSize = Math.Max(1, chunkSize);

        var index = new BlockChunkIndex(chunkSize);
        foreach (var (hash, length) in chunks)
        {
            if (!string.IsNullOrEmpty(hash) && length > 0)
                index.Add(hash, length);
        }
        return index;
    }

    /// <summary>
    /// 计算新文件相对基准数据的块级差分。
    /// <para>差分语义：复用判定基于「同偏移块」字节一致（文件级差分），而非全局哈希命中。
    /// 这保证插入/追加/位移场景下重建始终按偏移从基准数据取块，不会越界或取错内容。</para>
    /// <para>基准数据为 null → 全部块标记新增（等同于全量）。</para>
    /// </summary>
    /// <param name="newData">最新文件内容。</param>
    /// <param name="baseData">基准（旧版本）文件内容；null = 无基准。</param>
    /// <param name="baseIndex">基准块索引（可选加速：哈希不存在于索引中时直接判定新增，避免逐块比较）。</param>
    /// <param name="chunkSize">块大小（字节）。</param>
    public static BlockDeltaResult ComputeDelta(byte[] newData, byte[]? baseData, BlockChunkIndex? baseIndex = null, int chunkSize = DefaultChunkSize)
    {
        ArgumentNullException.ThrowIfNull(newData);
        chunkSize = Math.Max(1, chunkSize);

        var result = new BlockDeltaResult();
        var newSpan = newData.AsSpan();
        for (int pos = 0; pos < newData.Length; pos += chunkSize)
        {
            var len = Math.Min(chunkSize, newData.Length - pos);
            var hash = Convert.ToHexString(SHA256.HashData(newSpan.Slice(pos, len)));

            // 复用条件：基准存在、同偏移块范围未越界、哈希可能存在（索引加速）、逐字节一致
            bool reused = baseData != null
                          && pos + len <= baseData.Length
                          && (baseIndex == null || baseIndex.Contains(hash))
                          && newSpan.Slice(pos, len).SequenceEqual(baseData.AsSpan(pos, len));

            if (reused)
            {
                result.ReusedCount++;
                result.ReusedBytes += len;
                result.Blocks.Add(new BlockRef { Offset = pos, Length = len, Hash = hash, Reused = true });
            }
            else
            {
                result.NewCount++;
                result.NewBytes += len;
                result.Blocks.Add(new BlockRef { Offset = pos, Length = len, Hash = hash, Reused = false, Data = newSpan.Slice(pos, len).ToArray() });
            }
        }
        return result;
    }

    /// <summary>
    /// 重建文件最新内容：复用块从基准数据复制，新块从差分数据拼接。
    /// </summary>
    /// <param name="baseData">基准文件完整数据（无基准时传 null，仅当差分全为新块）。</param>
    /// <param name="delta">块级差分结果。</param>
    /// <returns>重建后的完整文件数据。</returns>
    public static byte[] Apply(byte[]? baseData, BlockDeltaResult delta)
    {
        ArgumentNullException.ThrowIfNull(delta);

        using var ms = new MemoryStream();
        foreach (var block in delta.Blocks)
        {
            if (block.Reused)
            {
                if (baseData == null)
                    throw new InvalidDataException($"复用块 {block.Hash[..16]} 缺少基准数据，无法重建。");
                if (block.Offset + block.Length > baseData.Length)
                    throw new InvalidDataException("基准数据长度不足，无法重建。");
                ms.Write(baseData, (int)block.Offset, block.Length);
            }
            else
            {
                if (block.Data == null)
                    throw new InvalidDataException($"新块 {block.Hash[..16]} 缺少数据，无法重建。");
                ms.Write(block.Data, 0, block.Data.Length);
            }
        }
        return ms.ToArray();
    }
}
