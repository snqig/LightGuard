// © 2026 落尘（Luochen） 原创开发 - 保留所有权利

using System.Security.Cryptography;
using LightGuard.Core;

namespace LightGuard.Backup;

/// <summary>
/// 备份分片实体 - 表示原始数据被切分后的一个数据块。
/// </summary>
public sealed class BackupShard
{
    /// <summary>分片序号（从 0 开始）。</summary>
    public int Index { get; set; }

    /// <summary>分片在原始数据中的字节偏移。</summary>
    public long Offset { get; set; }

    /// <summary>分片数据长度（字节）。</summary>
    public long Length { get; set; }

    /// <summary>分片明文数据。</summary>
    public byte[] Data { get; set; } = Array.Empty<byte>();

    /// <summary>分片数据的 SHA256 哈希（32 字节），用于分片级完整性校验。</summary>
    public byte[] Hash { get; set; } = Array.Empty<byte>();
}

/// <summary>
/// 备份分片处理引擎 - 负责将文件/数据切分为固定大小分片，以及合并还原。
/// <para>默认分片大小 4MB，可配置。每个分片独立计算 SHA256，整包计算 GlobalHash。</para>
/// </summary>
public static class BackupShardEngine
{
    /// <summary>默认分片大小：4MB。</summary>
    public const int DefaultShardSize = 4 * 1024 * 1024;

    /// <summary>
    /// 将文件切分为多个分片。
    /// </summary>
    /// <param name="filePath">待分片的文件路径。</param>
    /// <param name="shardSize">分片大小（字节），默认 4MB。</param>
    /// <returns>分片列表（按序号升序）。</returns>
    public static List<BackupShard> ShardFile(string filePath, int shardSize = DefaultShardSize)
    {
        if (shardSize <= 0) shardSize = DefaultShardSize;
        var shards = new List<BackupShard>();
        using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read);
        var buffer = new byte[shardSize];
        long offset = 0;
        int index = 0;
        int read;
        while ((read = fs.Read(buffer, 0, buffer.Length)) > 0)
        {
            // 注意：必须复制到新数组，因为 buffer 会在下次读取时被覆盖，
            // 而所有分片都将被保留并用于后续加密。
            var data = new byte[read];
            Buffer.BlockCopy(buffer, 0, data, 0, read);
            var shard = new BackupShard
            {
                Index = index++,
                Offset = offset,
                Length = read,
                Data = data,
                Hash = SHA256.HashData(data)
            };
            shards.Add(shard);
            offset += read;
        }

        // 空文件至少保留一个空分片，保证可逆
        if (shards.Count == 0)
        {
            shards.Add(new BackupShard { Index = 0, Offset = 0, Length = 0, Data = Array.Empty<byte>(), Hash = SHA256.HashData(Array.Empty<byte>()) });
        }
        return shards;
    }

    /// <summary>
    /// 将内存数据切分为多个分片。
    /// </summary>
    /// <param name="data">原始数据。</param>
    /// <param name="shardSize">分片大小（字节），默认 4MB。</param>
    /// <returns>分片列表（按序号升序）。</returns>
    public static List<BackupShard> ShardData(byte[] data, int shardSize = DefaultShardSize)
    {
        ArgumentNullException.ThrowIfNull(data);
        if (shardSize <= 0) shardSize = DefaultShardSize;

        var shards = new List<BackupShard>();
        long offset = 0;
        int index = 0;
        while (offset < data.Length)
        {
            int take = (int)Math.Min(shardSize, data.Length - offset);
            var chunk = new byte[take];
            Buffer.BlockCopy(data, (int)offset, chunk, 0, take);
            shards.Add(new BackupShard
            {
                Index = index++,
                Offset = offset,
                Length = take,
                Data = chunk,
                Hash = SHA256.HashData(chunk)
            });
            offset += take;
        }

        if (shards.Count == 0)
        {
            shards.Add(new BackupShard { Index = 0, Offset = 0, Length = 0, Data = Array.Empty<byte>(), Hash = SHA256.HashData(Array.Empty<byte>()) });
        }
        return shards;
    }

    /// <summary>
    /// 合并分片还原原始数据。
    /// </summary>
    /// <param name="shards">分片集合（将按 <see cref="BackupShard.Index"/> 升序合并）。</param>
    /// <returns>还原后的原始字节。</returns>
    public static byte[] MergeShards(IEnumerable<BackupShard> shards)
    {
        ArgumentNullException.ThrowIfNull(shards);
        var ordered = shards.OrderBy(s => s.Index).ToList();
        long total = ordered.Sum(s => s.Length);
        var merged = new byte[total];
        long offset = 0;
        foreach (var s in ordered)
        {
            if (s.Data.Length > 0)
            {
                Buffer.BlockCopy(s.Data, 0, merged, (int)offset, s.Data.Length);
            }
            offset += s.Length;
        }
        return merged;
    }

    /// <summary>
    /// 计算整包总哈希（SHA256），即对所有分片数据按序拼接后求哈希。
    /// </summary>
    /// <param name="shards">分片集合。</param>
    /// <returns>32 字节 SHA256 总哈希。</returns>
    public static byte[] ComputeGlobalHash(IEnumerable<BackupShard> shards)
    {
        ArgumentNullException.ThrowIfNull(shards);
        using var sha = SHA256.Create();
        foreach (var s in shards.OrderBy(x => x.Index))
        {
            if (s.Data.Length > 0)
                sha.TransformBlock(s.Data, 0, s.Data.Length, null, 0);
        }
        sha.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
        return sha.Hash ?? Array.Empty<byte>();
    }

    /// <summary>
    /// 计算整包总哈希（SHA256）并以大写十六进制字符串返回。
    /// </summary>
    /// <param name="shards">分片集合。</param>
    /// <returns>SHA256 十六进制字符串。</returns>
    public static string ComputeGlobalHashHex(IEnumerable<BackupShard> shards)
        => Convert.ToHexString(ComputeGlobalHash(shards));
}
