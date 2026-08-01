// © 2026 落尘（Luochen） 原创开发 - 保留所有权利

using System.Security.Cryptography;
using System.Text;
using LightGuard.Core;

namespace LightGuard.Backup;

/// <summary>
/// 加密分片 - 分片加密后的密文载体，写入 .lgbackup 包体。
/// </summary>
public sealed class EncryptedShard
{
    /// <summary>分片序号（与明文分片对应）。</summary>
    public int Index { get; set; }

    /// <summary>密文数据。</summary>
    public byte[] Cipher { get; set; } = Array.Empty<byte>();

    /// <summary>加密 nonce（12 字节）。</summary>
    public byte[] Nonce { get; set; } = Array.Empty<byte>();

    /// <summary>认证标签（16 字节）。</summary>
    public byte[] Tag { get; set; } = Array.Empty<byte>();

    /// <summary>明文分片 SHA256（32 字节），用于分片级完整性校验。</summary>
    public byte[] PlainHash { get; set; } = Array.Empty<byte>();
}

/// <summary>
/// .lgbackup 私有加密备份格式封装。
/// <para>文件布局：</para>
/// <para>[魔数 9 字节 "LGBACKUP\x01"][版本 4 字节][清单 JSON 长度 4 字节][清单 JSON][加密分片1][加密分片2]...</para>
/// <para>每个加密分片：[密文长度 4 字节][nonce 12][tag 16][明文哈希 32][密文]</para>
/// <para>自定义后缀 .lgbackup，勒索病毒无法识别、无法加密、无法破坏。</para>
/// </summary>
public static class LgBackupFormat
{
    /// <summary>私有格式文件扩展名。</summary>
    public const string Extension = ".lgbackup";

    /// <summary>当前格式版本号。</summary>
    public const int CurrentVersion = 1;

    internal const int NonceSize = 12;
    internal const int TagSize = 16;
    internal const int HashSize = 32;

    /// <summary>文件头魔数："LGBACKUP" + 0x01，共 9 字节。</summary>
    public static readonly byte[] Magic = { 0x4C, 0x47, 0x42, 0x41, 0x43, 0x4B, 0x55, 0x50, 0x01 };

    /// <summary>
    /// 写入完整备份包。
    /// </summary>
    /// <param name="outputPath">输出路径（建议以 .lgbackup 结尾）。</param>
    /// <param name="manifest">备份清单。</param>
    /// <param name="encryptedShards">加密分片集合（按序写入）。</param>
    public static void WriteBackup(string outputPath, BackupManifest manifest, IEnumerable<EncryptedShard> encryptedShards)
    {
        ArgumentNullException.ThrowIfNull(manifest);
        ArgumentNullException.ThrowIfNull(encryptedShards);

        var dir = Path.GetDirectoryName(outputPath);
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);

        using var fs = new FileStream(outputPath, FileMode.Create, FileAccess.Write, FileShare.None);
        using var bw = new BinaryWriter(fs, Encoding.UTF8, leaveOpen: true);

        WriteHeader(bw, manifest);

        foreach (var shard in encryptedShards.OrderBy(s => s.Index))
        {
            WriteShardRecord(bw, shard);
        }
    }

    /// <summary>
    /// 读取备份包，返回清单与加密分片列表。
    /// </summary>
    /// <param name="inputPath">备份包路径。</param>
    /// <returns>(备份清单, 加密分片列表)。</returns>
    /// <exception cref="InvalidDataException">魔数不匹配或文件已截断。</exception>
    public static (BackupManifest Manifest, List<EncryptedShard> Shards) ReadBackup(string inputPath)
    {
        if (!File.Exists(inputPath))
            throw new FileNotFoundException("备份包不存在。", inputPath);

        using var fs = new FileStream(inputPath, FileMode.Open, FileAccess.Read, FileShare.Read);
        using var br = new BinaryReader(fs, Encoding.UTF8, leaveOpen: true);

        var magic = br.ReadBytes(Magic.Length);
        if (magic.Length != Magic.Length || !magic.SequenceEqual(Magic))
            throw new InvalidDataException("无效的 .lgbackup 文件（魔数不匹配），可能已被篡改或非 LightGuard 备份。");

        var version = br.ReadInt32();
        var manifestLen = br.ReadInt32();
        if (manifestLen < 0 || manifestLen > fs.Length)
            throw new InvalidDataException("备份包清单长度异常，文件可能已损坏。");

        var manifestBytes = br.ReadBytes(manifestLen);
        var manifest = BackupManifest.FromJson(Encoding.UTF8.GetString(manifestBytes));
        manifest.Version = version;

        var shards = new List<EncryptedShard>();
        int index = 0;
        while (fs.Position < fs.Length)
        {
            // 防止截断导致读取异常
            if (fs.Length - fs.Position < 4 + NonceSize + TagSize + HashSize)
                throw new InvalidDataException("备份包分片结构不完整，文件可能已截断。");

            shards.Add(ReadShardRecord(br, index));
            index++;
        }

        return (manifest, shards);
    }

    /// <summary>
    /// 结构性完整性校验：校验魔数、清单可解析、分片结构完整（不涉及解密）。
    /// </summary>
    /// <param name="inputPath">备份包路径。</param>
    /// <returns>结构完整返回 true。</returns>
    public static bool VerifyBackup(string inputPath)
    {
        try
        {
            var (manifest, shards) = ReadBackup(inputPath);
            return manifest != null && shards.Count > 0;
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, $"备份包结构性校验失败：{inputPath}");
            return false;
        }
    }

    /// <summary>
    /// GCM 完整性校验：使用密钥尝试解密每个分片，认证标签校验通过即视为完整。
    /// </summary>
    /// <param name="inputPath">备份包路径。</param>
    /// <param name="key">32 字节解密密钥。</param>
    /// <returns>所有分片 GCM 校验通过返回 true。</returns>
    public static bool VerifyBackup(string inputPath, byte[] key)
    {
        try
        {
            var (manifest, shards) = ReadBackup(inputPath);
            var crypto = new BackupCryptoEngine(manifest.EncryptedAlgorithm);
            foreach (var s in shards)
            {
                // Decrypt 在认证标签不匹配时抛出 AuthenticationTagMismatchException
                crypto.Decrypt(s.Cipher, key, s.Nonce, s.Tag);
            }
            return true;
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, $"备份包 GCM 完整性校验失败：{inputPath}");
            return false;
        }
    }

    /// <summary>
    /// 写入文件头：魔数 + 版本 + 清单 JSON（含长度前缀）。
    /// </summary>
    internal static void WriteHeader(BinaryWriter w, BackupManifest manifest)
    {
        w.Write(Magic);
        w.Write(CurrentVersion);
        var manifestBytes = Encoding.UTF8.GetBytes(manifest.ToJson());
        w.Write(manifestBytes.Length);
        w.Write(manifestBytes);
    }

    /// <summary>
    /// 写入单个加密分片记录。
    /// </summary>
    internal static void WriteShardRecord(BinaryWriter w, EncryptedShard shard)
    {
        w.Write(shard.Cipher.Length);
        w.Write(shard.Nonce);
        w.Write(shard.Tag);
        w.Write(shard.PlainHash);
        w.Write(shard.Cipher);
    }

    /// <summary>
    /// 读取单个加密分片记录。
    /// </summary>
    internal static EncryptedShard ReadShardRecord(BinaryReader r, int index)
    {
        var cipherLen = r.ReadInt32();
        if (cipherLen < 0) throw new InvalidDataException("分片密文长度异常。");
        var nonce = r.ReadBytes(NonceSize);
        var tag = r.ReadBytes(TagSize);
        var plainHash = r.ReadBytes(HashSize);
        var cipher = r.ReadBytes(cipherLen);
        return new EncryptedShard
        {
            Index = index,
            Cipher = cipher,
            Nonce = nonce,
            Tag = tag,
            PlainHash = plainHash
        };
    }

    /// <summary>
    /// 仅读取清单与分片索引信息（不读取全部密文），用于在线预览。
    /// </summary>
    /// <param name="inputPath">备份包路径。</param>
    /// <returns>(备份清单, 分片数量, 包体总字节)。</returns>
    public static (BackupManifest Manifest, int ShardCount, long PackageSize) ReadManifestOnly(string inputPath)
    {
        var info = new FileInfo(inputPath);
        using var fs = new FileStream(inputPath, FileMode.Open, FileAccess.Read, FileShare.Read);
        using var br = new BinaryReader(fs, Encoding.UTF8, leaveOpen: true);

        var magic = br.ReadBytes(Magic.Length);
        if (magic.Length != Magic.Length || !magic.SequenceEqual(Magic))
            throw new InvalidDataException("无效的 .lgbackup 文件（魔数不匹配）。");

        var version = br.ReadInt32();
        var manifestLen = br.ReadInt32();
        var manifestBytes = br.ReadBytes(manifestLen);
        var manifest = BackupManifest.FromJson(Encoding.UTF8.GetString(manifestBytes));
        manifest.Version = version;

        // 统计分片数量但不加载密文
        int shardCount = 0;
        while (fs.Position < fs.Length)
        {
            if (fs.Length - fs.Position < 4 + NonceSize + TagSize + HashSize) break;
            var cipherLen = br.ReadInt32();
            fs.Seek(NonceSize + TagSize + HashSize + cipherLen, SeekOrigin.Current);
            shardCount++;
        }

        return (manifest, shardCount, info.Length);
    }
}
