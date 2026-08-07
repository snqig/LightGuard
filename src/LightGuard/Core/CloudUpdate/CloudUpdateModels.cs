using System.Text.Json.Serialization;

namespace LightGuard.Core.CloudUpdate;

/// <summary>
/// 更新通道
/// </summary>
public enum UpdateChannel
{
    /// <summary>稳定版（默认，经过完整测试）</summary>
    Stable,

    /// <summary>Beta 版（功能预览，可能不稳定）</summary>
    Beta,

    /// <summary>每夜构建版（最新但最不稳定）</summary>
    Nightly
}

/// <summary>
/// 规则类型
/// </summary>
public enum RuleType
{
    /// <summary>YARA 勒索规则库</summary>
    YaraRansomware,

    /// <summary>广告拦截规则库</summary>
    AdBlockRules,

    /// <summary>解密工具索引</summary>
    DecryptorIndex,

    /// <summary>病毒特征数据库</summary>
    VirusDatabase
}

/// <summary>
/// 单条规则版本信息（对应清单中一项）
/// </summary>
public sealed class RuleVersionInfo
{
    /// <summary>规则类型</summary>
    [JsonPropertyName("ruleType")]
    public RuleType RuleType { get; set; }

    /// <summary>版本号（语义化版本字符串，如 "2.1.0"）</summary>
    [JsonPropertyName("version")]
    public string Version { get; set; } = "";

    /// <summary>发布时间（UTC）</summary>
    [JsonPropertyName("publishedAt")]
    public DateTime PublishedAt { get; set; }

    /// <summary>下载地址</summary>
    [JsonPropertyName("downloadUrl")]
    public string DownloadUrl { get; set; } = "";

    /// <summary>SHA256 哈希值（小写十六进制）</summary>
    [JsonPropertyName("sha256")]
    public string Sha256Hash { get; set; } = "";

    /// <summary>RSA-2048 数字签名（Base64 编码）</summary>
    [JsonPropertyName("rsaSignature")]
    public string RsaSignature { get; set; } = "";

    /// <summary>文件大小（字节）</summary>
    [JsonPropertyName("sizeBytes")]
    public long SizeBytes { get; set; }

    /// <summary>变更日志</summary>
    [JsonPropertyName("changelog")]
    public string Changelog { get; set; } = "";

    public override string ToString()
        => $"{RuleType} v{Version} ({SizeBytes / 1024.0:F1} KB)";
}

/// <summary>
/// 更新清单（服务器返回的完整清单）
/// </summary>
public sealed class UpdateManifest
{
    /// <summary>服务器当前时间（UTC）</summary>
    [JsonPropertyName("serverTime")]
    public DateTime ServerTime { get; set; }

    /// <summary>各规则类型的最新版本列表</summary>
    [JsonPropertyName("latestVersions")]
    public List<RuleVersionInfo> LatestVersions { get; set; } = new();

    /// <summary>支持此清单的最低客户端版本</summary>
    [JsonPropertyName("minClientVersion")]
    public string MinClientVersion { get; set; } = "1.0.0";
}

/// <summary>
/// 单次更新检查结果
/// </summary>
public sealed class UpdateCheckResult
{
    /// <summary>是否有可用更新</summary>
    public bool HasUpdate { get; set; }

    /// <summary>规则类型</summary>
    public RuleType RuleType { get; set; }

    /// <summary>当前版本</summary>
    public string CurrentVersion { get; set; } = "";

    /// <summary>最新版本</summary>
    public string LatestVersion { get; set; } = "";

    /// <summary>清单中对应的版本信息（可能为空）</summary>
    public RuleVersionInfo? ManifestEntry { get; set; }

    /// <summary>错误信息（检查失败时）</summary>
    public string? Error { get; set; }

    public override string ToString()
        => Error != null
            ? $"{RuleType}: 检查失败 - {Error}"
            : HasUpdate
                ? $"{RuleType}: {CurrentVersion} -> {LatestVersion}"
                : $"{RuleType}: 已是最新 ({CurrentVersion})";
}

/// <summary>
/// 更新进度信息
/// </summary>
public sealed class UpdateProgress
{
    /// <summary>完成百分比（0-100）</summary>
    public double PercentComplete { get; set; }

    /// <summary>当前正在处理的文件描述</summary>
    public string CurrentFile { get; set; } = "";

    /// <summary>下载速度（KB/s）</summary>
    public double SpeedKBps { get; set; }

    /// <summary>是否正在运行</summary>
    public bool IsRunning { get; set; }

    public override string ToString()
        => IsRunning
            ? $"[{PercentComplete:F1}%] {CurrentFile} @ {SpeedKBps:F1} KB/s"
            : "空闲";
}

/// <summary>
/// 更新应用结果
/// </summary>
public sealed class UpdateApplyResult
{
    /// <summary>是否成功</summary>
    public bool Success { get; set; }

    /// <summary>规则类型</summary>
    public RuleType RuleType { get; set; }

    /// <summary>旧版本号</summary>
    public string OldVersion { get; set; } = "";

    /// <summary>新版本号</summary>
    public string NewVersion { get; set; } = "";

    /// <summary>备份文件路径（成功时）</summary>
    public string? BackupPath { get; set; }

    /// <summary>错误信息（失败时）</summary>
    public string? Error { get; set; }

    /// <summary>操作时间</summary>
    public DateTime Timestamp { get; set; } = DateTime.Now;

    public override string ToString()
        => Success
            ? $"{RuleType}: {OldVersion} -> {NewVersion} 成功"
            : $"{RuleType}: 失败 - {Error}";
}

/// <summary>
/// 更新历史记录条目（用于持久化和 UI 展示）
/// </summary>
public sealed class UpdateHistoryEntry
{
    /// <summary>操作时间</summary>
    [JsonPropertyName("timestamp")]
    public DateTime Timestamp { get; set; }

    /// <summary>规则类型</summary>
    [JsonPropertyName("ruleType")]
    public RuleType RuleType { get; set; }

    /// <summary>旧版本号</summary>
    [JsonPropertyName("oldVersion")]
    public string OldVersion { get; set; } = "";

    /// <summary>新版本号</summary>
    [JsonPropertyName("newVersion")]
    public string NewVersion { get; set; } = "";

    /// <summary>是否成功</summary>
    [JsonPropertyName("success")]
    public bool Success { get; set; }

    /// <summary>错误信息</summary>
    [JsonPropertyName("error")]
    public string? Error { get; set; }
}
