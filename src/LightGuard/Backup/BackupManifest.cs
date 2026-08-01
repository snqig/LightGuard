// © 2026 落尘（Luochen） 原创开发 - 保留所有权利

using System.Text.Json;
using System.Text.Json.Serialization;

namespace LightGuard.Backup;

/// <summary>
/// 备份粒度类型。
/// </summary>
public enum BackupType
{
    /// <summary>单文件备份。</summary>
    File,

    /// <summary>整目录备份。</summary>
    Directory,

    /// <summary>分区镜像备份（VSS 卷影副本热备份）。</summary>
    Partition,

    /// <summary>整块硬盘扇区级镜像备份。</summary>
    Disk,

    /// <summary>数据库备份。</summary>
    Database
}

/// <summary>
/// 备份清单实体 - 描述一个 .lgbackup 备份包的全部元信息。
/// <para>以 JSON 形式嵌入备份包头部，用于恢复时定位、校验与版本回溯。</para>
/// </summary>
public sealed class BackupManifest
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = false,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    /// <summary>备份唯一标识（GUID）。</summary>
    public Guid BackupId { get; set; } = Guid.NewGuid();

    /// <summary>备份时间（本地时间）。</summary>
    public DateTime BackupTime { get; set; } = DateTime.Now;

    /// <summary>备份粒度类型。</summary>
    public BackupType BackupType { get; set; } = BackupType.File;

    /// <summary>源路径（文件 / 目录 / 盘符 / 数据库连接串等）。</summary>
    public string SourcePath { get; set; } = string.Empty;

    /// <summary>加密算法名称："AES-256-GCM" 或 "ChaCha20-Poly1305"。</summary>
    public string EncryptedAlgorithm { get; set; } = "AES-256-GCM";

    /// <summary>原始数据总大小（字节）。</summary>
    public long TotalSize { get; set; }

    /// <summary>包含的文件数量。</summary>
    public int FileCount { get; set; }

    /// <summary>分片数量。</summary>
    public int ShardCount { get; set; }

    /// <summary>分片大小（字节）。</summary>
    public long ShardSize { get; set; }

    /// <summary>整包总哈希（SHA256 十六进制），用于完整性校验。</summary>
    public string GlobalHash { get; set; } = string.Empty;

    /// <summary>PBKDF2 随机盐（Base64）。</summary>
    public string Salt { get; set; } = string.Empty;

    /// <summary>备份格式版本号。</summary>
    public int Version { get; set; } = 1;

    /// <summary>是否为核心备份锁定（锁定后生命周期清理跳过，防止误删）。</summary>
    public bool IsLocked { get; set; }

    /// <summary>附加元数据（如备份策略、数据库类型、卷影设备路径等）。</summary>
    public Dictionary<string, string> Metadata { get; set; } = new();

    /// <summary>
    /// 序列化为 JSON 字符串。
    /// </summary>
    /// <returns>JSON 文本。</returns>
    public string ToJson() => JsonSerializer.Serialize(this, JsonOptions);

    /// <summary>
    /// 从 JSON 字符串反序列化备份清单。
    /// </summary>
    /// <param name="json">JSON 文本。</param>
    /// <returns>备份清单实例。</returns>
    public static BackupManifest FromJson(string json)
        => JsonSerializer.Deserialize<BackupManifest>(json, JsonOptions) ?? new BackupManifest();
}
