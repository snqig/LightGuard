using System.Text.Json.Serialization;

namespace LightGuard.Decryption;

/// <summary>
/// 已知勒索软件家族枚举
/// </summary>
public enum RansomwareFamily
{
    /// <summary>未知家族</summary>
    Unknown,

    /// <summary>WannaCry（永恒之蓝勒索）</summary>
    WannaCry,

    /// <summary>Petya / NotPetya（主引导记录加密）</summary>
    Petya,

    /// <summary>GandCrab（REvil 前身，已有官方解密器）</summary>
    GandCrab,

    /// <summary>STOP/Djvu（变种极多，部分可解密）</summary>
    STOP,

    /// <summary>Maze（双重勒索，泄露+加密）</summary>
    Maze,

    /// <summary>Ryuk（定向攻击，无公开解密器）</summary>
    Ryuk,

    /// <summary>Sodinokibi / REvil（Maze 的继任者）</summary>
    Sodinokibi,

    /// <summary>Conti（Ryuk 的继任者）</summary>
    Conti,

    /// <summary>LockBit（自动化勒索即服务）</summary>
    LockBit,

    /// <summary>BlackBasta（双重勒索，2022 年活跃）</summary>
    BlackBasta,

    /// <summary>AvosLocker（基于 Linux/Windows 双平台）</summary>
    AvosLocker
}

/// <summary>
/// 勒索家族信息 - 描述一个已知勒索软件家族及其解密工具状态
/// </summary>
public sealed class RansomwareFamilyInfo
{
    /// <summary>家族枚举</summary>
    [JsonPropertyName("family")]
    public RansomwareFamily Family { get; set; } = RansomwareFamily.Unknown;

    /// <summary>家族显示名称</summary>
    [JsonPropertyName("name")]
    public string Name { get; set; } = "";

    /// <summary>加密后的文件扩展名（如 .wcry）</summary>
    [JsonPropertyName("extension")]
    public string Extension { get; set; } = "";

    /// <summary>家族描述</summary>
    [JsonPropertyName("description")]
    public string Description { get; set; } = "";

    /// <summary>是否有可用解密器</summary>
    [JsonPropertyName("hasDecryptor")]
    public bool HasDecryptor { get; set; }

    /// <summary>解密工具下载地址</summary>
    [JsonPropertyName("decryptorUrl")]
    public string DecryptorUrl { get; set; } = "";

    /// <summary>解密工具的 SHA256 校验值</summary>
    [JsonPropertyName("decryptorSha256")]
    public string DecryptorSha256 { get; set; } = "";

    /// <summary>解密工具文件名</summary>
    [JsonPropertyName("decryptorFileName")]
    public string DecryptorFileName { get; set; } = "";

    /// <summary>解密工具预计大小（字节，0 表示未知）</summary>
    [JsonPropertyName("toolSizeBytes")]
    public long ToolSizeBytes { get; set; }

    /// <summary>检测模式列表（文件扩展名模式，如 *.wcry, *.wnry）</summary>
    [JsonPropertyName("detectionPatterns")]
    public List<string> DetectionPatterns { get; set; } = new();

    /// <summary>勒索说明文件名列表（如 @WanaDecryptor@.exe.bmp.txt）</summary>
    [JsonPropertyName("ransomNoteNames")]
    public List<string> RansomNoteNames { get; set; } = new();
}

/// <summary>
/// 解密工具索引 - JSON 可序列化的工具清单
/// 包含所有已知勒索家族及其解密工具信息
/// </summary>
public sealed class DecryptionToolIndex
{
    /// <summary>索引版本号</summary>
    [JsonPropertyName("version")]
    public int Version { get; set; } = 1;

    /// <summary>索引最后更新时间</summary>
    [JsonPropertyName("lastUpdated")]
    public DateTime? LastUpdated { get; set; }

    /// <summary>家族信息列表</summary>
    [JsonPropertyName("families")]
    public List<RansomwareFamilyInfo> Families { get; set; } = new();
}

/// <summary>
/// 解密操作结果
/// </summary>
public sealed class DecryptionResult
{
    /// <summary>整体是否成功</summary>
    public bool Success { get; set; }

    /// <summary>检测到的勒索家族</summary>
    public RansomwareFamily Family { get; set; } = RansomwareFamily.Unknown;

    /// <summary>总文件数</summary>
    public int TotalFiles { get; set; }

    /// <summary>成功解密文件数</summary>
    public int DecryptedFiles { get; set; }

    /// <summary>解密失败文件数</summary>
    public int FailedFiles { get; set; }

    /// <summary>跳过的文件数（已解密或不匹配）</summary>
    public int SkippedFiles { get; set; }

    /// <summary>错误信息（失败时填充）</summary>
    public string ErrorMessage { get; set; } = "";

    /// <summary>失败原因（枚举，便于程序判断）</summary>
    public DecryptionFailureReason FailureReason { get; set; } = DecryptionFailureReason.UnknownFamily;

    /// <summary>已成功解密的文件列表</summary>
    public List<string> DecryptedFilesList { get; set; } = new();

    /// <summary>解密耗时</summary>
    public TimeSpan Duration { get; set; }

    /// <summary>备份路径（解密前的备份位置）</summary>
    public string BackupPath { get; set; } = "";
}

/// <summary>
/// 解密进度信息（通过事件回调上报 UI）
/// </summary>
public sealed class DecryptionProgress
{
    /// <summary>完成百分比（0-100）</summary>
    public double PercentComplete { get; set; }

    /// <summary>当前正在处理的文件路径</summary>
    public string CurrentFile { get; set; } = "";

    /// <summary>已处理文件数</summary>
    public int FilesProcessed { get; set; }

    /// <summary>总文件数</summary>
    public int TotalFiles { get; set; }

    /// <summary>已成功解密文件数</summary>
    public int DecryptedCount { get; set; }

    /// <summary>解密失败文件数</summary>
    public int FailedCount { get; set; }

    /// <summary>是否正在运行</summary>
    public bool IsRunning { get; set; }
}

/// <summary>
/// 解密失败原因枚举
/// </summary>
public enum DecryptionFailureReason
{
    /// <summary>未知家族</summary>
    UnknownFamily,

    /// <summary>该家族无可用解密器</summary>
    NoDecryptorAvailable,

    /// <summary>解密工具下载失败</summary>
    ToolDownloadFailed,

    /// <summary>工具哈希校验不匹配（可能被篡改）</summary>
    HashMismatch,

    /// <summary>解密工具执行失败</summary>
    ToolExecutionFailed,

    /// <summary>文件访问被拒绝（权限不足）</summary>
    FileAccessDenied,

    /// <summary>磁盘空间不足</summary>
    InsufficientDiskSpace,

    /// <summary>解密前备份失败</summary>
    BackupFailed,

    /// <summary>文件已被解密（无需重复操作）</summary>
    AlreadyDecrypted
}
