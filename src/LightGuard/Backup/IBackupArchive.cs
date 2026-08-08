// © 2026 落尘（Luochen） 原创开发 - 保留所有权利

namespace LightGuard.Backup;

/// <summary>
/// 备份归档格式版本。
/// <para>v1 = 旧版 AES-256-GCM/ChaCha20 分片直接加密（仅只读兼容，不再新写）；</para>
/// <para>v3 = 自研私有容器 + 7z LZMA2 压缩内核 + AEAD 加密 + 文件名加密（当前与未来唯一新写格式）。</para>
/// </summary>
public enum BackupArchiveFormat
{
    /// <summary>旧版 v1：AES 分片直接加密，无压缩。只读兼容，禁止新写。</summary>
    V1LegacySharded = 1,

    /// <summary>新版 v3：私有容器 + LZMA2 内核。所有新备份统一使用。</summary>
    V3PrivateContainer = 3
}

/// <summary>
/// 归档压缩组织模式（决定压缩率与随机访问能力）。
/// </summary>
public enum BackupArchiveCompressionMode
{
    /// <summary>固实：全部条目共用一个 LZMA2 流，压缩率最高，但随机访问/选择性还原代价高。</summary>
    Solid,

    /// <summary>非固实：每个条目独立 LZMA2 流，选择性还原可精准定位（默认）。</summary>
    PerFile,

    /// <summary>分块：按固定块大小压缩，兼顾压缩率与块级随机访问，是块级增量的基础。</summary>
    Chunked
}

/// <summary>
/// 归档打开模式。
/// </summary>
public enum BackupArchiveOpenMode
{
    /// <summary>只读：浏览、校验、还原。</summary>
    ReadOnly,

    /// <summary>读写：写入 / 追加增量。</summary>
    ReadWrite
}

/// <summary>
/// 归档写入参数（v3 格式）。
/// </summary>
public sealed class BackupArchiveOptions
{
    /// <summary>源路径（文件 / 目录，写入头部元信息）。</summary>
    public string SourcePath { get; set; } = "";

    /// <summary>目标格式版本（固定 v3；v1 仅由只读适配器暴露）。</summary>
    public BackupArchiveFormat Format { get; set; } = BackupArchiveFormat.V3PrivateContainer;

    /// <summary>LZMA2 压缩级别（0-9，默认 6）。</summary>
    public int CompressionLevel { get; set; } = 6;

    /// <summary>LZMA2 字典大小（MB，默认 64）。</summary>
    public int DictionarySizeMb { get; set; } = 64;

    /// <summary>压缩组织模式（默认非固实，保证选择性还原性能）。</summary>
    public BackupArchiveCompressionMode CompressionMode { get; set; } = BackupArchiveCompressionMode.PerFile;

    /// <summary>分块模式块大小（字节，默认 4MB；Chunked 模式生效）。</summary>
    public long ChunkSize { get; set; } = 4L * 1024 * 1024;

    /// <summary>是否加密文件名（元数据表单独 AEAD 加密，默认开启）。</summary>
    public bool EncryptFileNames { get; set; } = true;
}

/// <summary>
/// 归档条目元信息（读取端：浏览 / 选择性还原 / 健康校验）。
/// </summary>
public sealed class BackupArchiveEntryInfo
{
    /// <summary>相对路径（以 '/' 分隔，不含根）。</summary>
    public string RelPath { get; init; } = "";

    /// <summary>文件名（末段）。</summary>
    public string Name { get; init; } = "";

    /// <summary>解压后数据大小（字节）。</summary>
    public long Length { get; init; }

    /// <summary>修改时间。</summary>
    public DateTime ModifiedTime { get; init; }

    /// <summary>解压后数据 SHA256（十六进制），用于完整性校验。</summary>
    public string Hash { get; init; } = "";

    /// <summary>数据在容器流中的物理偏移（按偏移顺序读取减少随机 IO）。</summary>
    public long ArchiveOffset { get; init; }

    /// <summary>所属压缩块索引（Chunked 模式；PerFile 为 -1）。</summary>
    public int ChunkIndex { get; init; } = -1;

    /// <summary>
    /// 条目压缩块引用列表（块级增量 / 去重基础）。
    /// <para>Chunked 模式返回逐块引用；PerFile 模式返回单块（整条目）；v1 只读适配器为 null。</para>
    /// </summary>
    public IReadOnlyList<BackupChunkRef>? Chunks { get; init; }
}

/// <summary>
/// 条目压缩块引用（块级增量 / 去重索引基础）。
/// </summary>
public sealed class BackupChunkRef
{
    /// <summary>块解压后 SHA256（十六进制），用于跨包块去重。</summary>
    public string Hash { get; init; } = "";

    /// <summary>块解压后长度（字节）。</summary>
    public long Length { get; init; }

    /// <summary>块压缩负载在容器中的物理偏移（顺序读取 / 校验定位）。</summary>
    public long ArchiveOffset { get; init; }
}

/// <summary>
/// 归档写入结果。
/// </summary>
public sealed class BackupArchiveWriteResult
{
    /// <summary>实际写入格式。</summary>
    public BackupArchiveFormat Format { get; init; }

    /// <summary>解压后数据总大小（字节）。</summary>
    public long TotalBytes { get; init; }

    /// <summary>压缩后包体总大小（字节）。</summary>
    public long CompressedBytes { get; init; }

    /// <summary>条目数。</summary>
    public int EntryCount { get; init; }

    /// <summary>压缩率（压缩后 / 原始）。</summary>
    public double CompressionRatio => TotalBytes > 0 ? CompressedBytes / (double)TotalBytes : 1.0;

    /// <summary>总耗时。</summary>
    public TimeSpan Elapsed { get; init; }
}

/// <summary>
/// 归档完整性校验结果。
/// </summary>
public sealed class BackupArchiveVerifyResult
{
    /// <summary>是否全部通过。</summary>
    public bool Success { get; set; }

    /// <summary>校验条目数。</summary>
    public int EntryCount { get; set; }

    /// <summary>已校验数据字节数。</summary>
    public long VerifiedBytes { get; set; }

    /// <summary>失败明细（相对路径 + 错误）。</summary>
    public List<string> Failures { get; } = new();

    /// <summary>结果消息。</summary>
    public string Message { get; set; } = "";
}

/// <summary>
/// 备份归档统一存储抽象层。
/// <para>全局规范 1：所有存储读写必须经过本接口，禁止绕过私有封装。</para>
/// <para>写入端：备份引擎（全量 / 增量 / 差异）；读取端：恢复引擎、备份浏览器、健康校验。</para>
/// <para>设计约束：</para>
/// <list type="number">
///   <item>旧格式 v1 通过只读适配器暴露同一接口（只读兼容，不新写）；新格式统一 v3 私有容器。</item>
///   <item>压缩在加密之前（先 LZMA2 再 AEAD），保证压缩率与密文熵。</item>
///   <item>所有操作异步、可取消、可上报进度（全局规范 7）。</item>
///   <item>密钥仅用于打开归档，绝不落盘、绝不进入元数据。</item>
/// </list>
/// </summary>
public interface IBackupArchive : IDisposable
{
    /// <summary>归档实际格式版本。</summary>
    BackupArchiveFormat Format { get; }

    /// <summary>源路径（文件 / 目录，仅元信息）。</summary>
    string SourcePath { get; }

    /// <summary>解压后数据总大小（字节）。</summary>
    long TotalSize { get; }

    /// <summary>条目总数。</summary>
    int EntryCount { get; }

    // ==================== 写入（备份） ====================

    /// <summary>
    /// 全量写入：将条目流压缩（LZMA）后加密写入私有容器。
    /// </summary>
    /// <param name="entries">条目枚举：(相对路径, 数据流, 修改时间)。</param>
    /// <param name="options">写入参数。</param>
    /// <param name="progress">进度回调（复用备份进度模型）。</param>
    /// <param name="ct">取消令牌。</param>
    Task<BackupArchiveWriteResult> WriteAsync(
        IEnumerable<(string RelPath, Stream Data, DateTime ModifiedTime)> entries,
        BackupArchiveOptions options,
        IProgress<BackupProgressInfo>? progress = null,
        CancellationToken ct = default);

    /// <summary>
    /// 追加写入（增量 / 差异场景）：向已有容器追加条目，返回合并后的结果。
    /// </summary>
    Task<BackupArchiveWriteResult> AppendAsync(
        IEnumerable<(string RelPath, Stream Data, DateTime ModifiedTime)> entries,
        BackupArchiveOptions options,
        IProgress<BackupProgressInfo>? progress = null,
        CancellationToken ct = default);

    // ==================== 读取（浏览 / 还原） ====================

    /// <summary>列出全部条目（备份浏览器 / 选择性还原数据源）。</summary>
    Task<IReadOnlyList<BackupArchiveEntryInfo>> ListEntriesAsync(CancellationToken ct = default);

    /// <summary>按相对路径打开条目数据流（已解密 + 已解压）。</summary>
    Task<Stream> OpenEntryAsync(string relPath, CancellationToken ct = default);

    // ==================== 校验（健康检查） ====================

    /// <summary>完整性校验：容器结构 + 逐条目 SHA256 + 密文 AEAD 认证。</summary>
    Task<BackupArchiveVerifyResult> VerifyAsync(CancellationToken ct = default);
}
