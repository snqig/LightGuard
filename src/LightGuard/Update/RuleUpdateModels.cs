using System.Text.Json.Serialization;

namespace LightGuard.Update;

/// <summary>
/// 云端规则类型
/// </summary>
public enum RuleType
{
    /// <summary>YARA 勒索规则库</summary>
    YaraRules,

    /// <summary>广告拦截规则库</summary>
    AdBlockRules,

    /// <summary>解密工具索引</summary>
    DecryptionIndex,

    /// <summary>病毒特征数据库</summary>
    VirusDb
}

/// <summary>
/// 规则版本信息（对应云端 version.json 清单文件）
/// </summary>
public sealed class RuleVersionInfo
{
    /// <summary>规则类型（由本地根据拉取路径推断，不在服务器 JSON 中）</summary>
    [JsonIgnore]
    public RuleType RuleType { get; set; }

    /// <summary>语义化版本号（如 "2.1.0"）</summary>
    [JsonPropertyName("version")]
    public string Version { get; set; } = string.Empty;

    /// <summary>发布时间（UTC）</summary>
    [JsonPropertyName("releaseDate")]
    public DateTime ReleaseDate { get; set; }

    /// <summary>规则包下载地址</summary>
    [JsonPropertyName("downloadUrl")]
    public string DownloadUrl { get; set; } = string.Empty;

    /// <summary>SHA256 哈希值（小写十六进制）</summary>
    [JsonPropertyName("sha256")]
    public string Sha256Hash { get; set; } = string.Empty;

    /// <summary>RSA-2048 数字签名（Base64 编码）</summary>
    [JsonPropertyName("signature")]
    public string SignatureBase64 { get; set; } = string.Empty;

    /// <summary>规则包文件大小（字节）</summary>
    [JsonPropertyName("fileSizeBytes")]
    public long FileSizeBytes { get; set; }

    /// <summary>变更日志</summary>
    [JsonPropertyName("changelog")]
    public string Changelog { get; set; } = string.Empty;

    public override string ToString()
        => $"{RuleType} v{Version} ({FileSizeBytes / 1024.0:F1} KB)";
}

/// <summary>
/// 单次规则更新结果
/// </summary>
public sealed class RuleUpdateResult
{
    /// <summary>是否成功</summary>
    public bool Success { get; set; }

    /// <summary>规则类型</summary>
    public RuleType RuleType { get; set; }

    /// <summary>旧版本号</summary>
    public string OldVersion { get; set; } = string.Empty;

    /// <summary>新版本号</summary>
    public string NewVersion { get; set; } = string.Empty;

    /// <summary>错误信息（失败时）</summary>
    public string? ErrorMessage { get; set; }

    /// <summary>已下载字节数</summary>
    public long DownloadedBytes { get; set; }

    /// <summary>本次更新耗时</summary>
    public TimeSpan Duration { get; set; }

    /// <summary>是否通过签名校验</summary>
    public bool Verified { get; set; }

    public override string ToString()
        => Success
            ? $"{RuleType}: {OldVersion} -> {NewVersion} 成功 (签名校验: {Verified})"
            : $"{RuleType}: 失败 - {ErrorMessage}";
}

/// <summary>
/// 规则更新进度信息（UI 订阅 ProgressChanged 用于显示进度条）
/// </summary>
public sealed class RuleUpdateProgress
{
    /// <summary>当前更新的规则类型</summary>
    public RuleType RuleType { get; set; }

    /// <summary>完成百分比（0-100）</summary>
    public double PercentComplete { get; set; }

    /// <summary>当前操作描述</summary>
    public string CurrentAction { get; set; } = string.Empty;

    /// <summary>下载速度（KB/s）</summary>
    public double DownloadSpeed { get; set; }

    /// <summary>是否正在运行</summary>
    public bool IsRunning { get; set; }

    public override string ToString()
        => IsRunning
            ? $"[{RuleType}] {PercentComplete:F1}% - {CurrentAction} @ {DownloadSpeed:F1} KB/s"
            : $"[{RuleType}] 空闲";
}

/// <summary>
/// 规则更新配置
/// </summary>
public sealed class RuleUpdateConfig
{
    /// <summary>是否启用自动更新</summary>
    public bool AutoUpdateEnabled { get; set; } = true;

    /// <summary>检查间隔（小时）</summary>
    public int CheckIntervalHours { get; set; } = 6;

    /// <summary>
    /// 更新服务器基址（指向规则仓库根目录）
    /// 为空则使用内置默认地址
    /// </summary>
    public string UpdateServerUrl { get; set; } = "https://raw.githubusercontent.com/snqig/LightGuard-rules/main";

    /// <summary>
    /// RSA-2048 公钥（XML 格式）。
    /// 占位符：为空时使用 <see cref="LightGuard.Security.UpdateSignatureVerifier"/> 内嵌的官方公钥。
    /// 待替换为正式分发的公钥。
    /// </summary>
    public string PublicKeyXml { get; set; } = string.Empty;

    /// <summary>最后检查时间</summary>
    public DateTime? LastCheckTime { get; set; }

    /// <summary>各规则类型已安装的版本号</summary>
    public Dictionary<RuleType, string> InstalledVersions { get; set; } = new();
}
