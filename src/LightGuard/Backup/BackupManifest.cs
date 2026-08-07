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

    // ==================== 选择性还原：目录树构建 ====================

    /// <summary>
    /// 将备份归档中的扁平文件列表转换为层级目录树（选择性还原浏览用）。
    /// </summary>
    /// <param name="files">扁平文件列表：(相对路径, 文件大小)。相对路径以 '/' 分隔。</param>
    /// <param name="timestamp">文件修改时间（.lgbackup 格式未记录逐文件时间，统一取备份时间）。</param>
    /// <param name="rootName">树根节点名称（默认取源路径文件名）。</param>
    /// <returns>完整层级目录树，根节点为备份根目录；空目录正常保留。</returns>
    public BackupTreeNode BuildDirectoryTree(
        IEnumerable<(string RelPath, long Size)> files,
        DateTime? timestamp = null,
        string? rootName = null)
    {
        var root = new BackupTreeNode
        {
            Name = string.IsNullOrEmpty(rootName)
                ? (string.IsNullOrEmpty(SourcePath)
                    ? "backup_root"
                    : Path.GetFileName(SourcePath.TrimEnd('/', '\\')))
                : rootName,
            IsDirectory = true,
            RelPath = ""
        };

        // 目录节点索引：父相对路径（"" 为根）→ 节点
        var dirNodes = new Dictionary<string, BackupTreeNode>(StringComparer.OrdinalIgnoreCase)
        {
            [""] = root
        };

        foreach (var (rel, size) in files)
        {
            if (string.IsNullOrWhiteSpace(rel)) continue;
            var parts = rel.Replace('\\', '/').Split('/', StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length == 0) continue;

            // 定位 / 创建父目录链
            var parent = root;
            var parentRel = "";
            for (int i = 0; i < parts.Length - 1; i++)
            {
                var seg = parts[i];
                parentRel = parentRel.Length == 0 ? seg : parentRel + "/" + seg;
                if (!dirNodes.TryGetValue(parentRel, out var dirNode))
                {
                    dirNode = new BackupTreeNode
                    {
                        Name = seg,
                        IsDirectory = true,
                        RelPath = parentRel + "/"
                    };
                    parent.Children.Add(dirNode);
                    dirNodes[parentRel] = dirNode;
                }
                parent = dirNode;
            }

            var leafRel = parentRel.Length == 0 ? parts[^1] : parentRel + "/" + parts[^1];
            parent.Children.Add(new BackupTreeNode
            {
                Name = parts[^1],
                IsDirectory = false,
                RelPath = leafRel,
                FileSize = size,
                ModifiedTime = timestamp
            });
        }

        AccumulateDirSize(root);
        return root;
    }

    /// <summary>递归统计目录节点子文件总大小</summary>
    private static long AccumulateDirSize(BackupTreeNode node)
    {
        if (!node.IsDirectory) return node.FileSize;
        long total = 0;
        foreach (var child in node.Children)
            total += AccumulateDirSize(child);
        node.FileSize = total;
        return total;
    }
}

/// <summary>
/// 备份内容目录树节点（选择性还原浏览用）。
/// </summary>
public sealed class BackupTreeNode
{
    /// <summary>节点名称（目录 / 文件名）</summary>
    public string Name { get; set; } = "";

    /// <summary>是否为目录节点</summary>
    public bool IsDirectory { get; set; }

    /// <summary>相对备份根的路径（目录以 '/' 结尾）</summary>
    public string RelPath { get; set; } = "";

    /// <summary>子节点集合（目录节点有效）</summary>
    public List<BackupTreeNode> Children { get; set; } = new();

    /// <summary>文件大小（字节）；目录节点为递归子文件总大小</summary>
    public long FileSize { get; set; }

    /// <summary>修改时间（.lgbackup 未记录逐文件时间，统一为备份时间）</summary>
    public DateTime? ModifiedTime { get; set; }

    /// <summary>分片索引引用（预留：后续支持按分片局部读取）</summary>
    public int ShardIndex { get; set; } = -1;

    /// <summary>是否有子节点</summary>
    public bool HasChildren => Children.Count > 0;

    /// <summary>节点文件总大小（与 FileSize 一致，便于统一读取）</summary>
    public long TotalSize => FileSize;

    /// <summary>格式化大小显示</summary>
    public string SizeText => FileSize switch
    {
        >= 1024 * 1024 * 1024 => $"{FileSize / 1024.0 / 1024 / 1024:F2} GB",
        >= 1024 * 1024 => $"{FileSize / 1024.0 / 1024:F1} MB",
        >= 1024 => $"{FileSize / 1024.0:F1} KB",
        _ => $"{FileSize} B"
    };
}
