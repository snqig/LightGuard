// © 2026 落尘（Luochen） 原创开发 - 保留所有权利

using System.Text.Json.Serialization;

namespace LightGuard.Update;

/// <summary>
/// 增量差分更新清单 — 对齐 packaging/build-diff.ps1 产物格式。
/// <para>服务器端清单 JSON 字段：</para>
/// <code>
/// {
///   "version": "3.2.0",          // 目标版本
///   "baseVersion": "3.1.0",      // 基准版本（当前版本应等于它才可应用）
///   "downloadUrl": "…/update.zip",// 差分包地址（仅新增+修改文件）
///   "sha256": "…",               // update.zip 的 SHA256
///   "signature": "…",            // update.zip 的 RSA 签名（Base64）
///   "releaseNotes": "…",
///   "added": ["file1"],
///   "modified": ["file2"],
///   "deleted": ["file3"]         // 需删除的旧文件清单
/// }
/// </code>
/// </summary>
public sealed class IncrementalUpdateManifest
{
    /// <summary>目标版本号（语义化版本）</summary>
    [JsonPropertyName("version")]
    public string Version { get; set; } = "";

    /// <summary>基准版本号（仅当当前版本等于此值时才可应用差分包）</summary>
    [JsonPropertyName("baseVersion")]
    public string BaseVersion { get; set; } = "";

    /// <summary>差分包下载地址（update.zip，仅含新增+修改文件）</summary>
    [JsonPropertyName("downloadUrl")]
    public string DownloadUrl { get; set; } = "";

    /// <summary>差分包 SHA256 哈希（小写十六进制）</summary>
    [JsonPropertyName("sha256")]
    public string Sha256 { get; set; } = "";

    /// <summary>差分包 RSA-2048 数字签名（Base64）</summary>
    [JsonPropertyName("signature")]
    public string Signature { get; set; } = "";

    /// <summary>发布说明</summary>
    [JsonPropertyName("releaseNotes")]
    public string ReleaseNotes { get; set; } = "";

    /// <summary>新增文件列表（相对应用目录）</summary>
    [JsonPropertyName("added")]
    public List<string> Added { get; set; } = new();

    /// <summary>修改文件列表（相对应用目录）</summary>
    [JsonPropertyName("modified")]
    public List<string> Modified { get; set; } = new();

    /// <summary>删除文件列表（相对应用目录）</summary>
    [JsonPropertyName("deleted")]
    public List<string> Deleted { get; set; } = new();

    /// <summary>清单发布时间</summary>
    [JsonPropertyName("publishedAt")]
    public DateTime? PublishedAt { get; set; }

    /// <summary>变更文件总数</summary>
    [JsonIgnore]
    public int TotalChanged => Added.Count + Modified.Count + Deleted.Count;
}

/// <summary>
/// 增量更新检查结果
/// </summary>
public sealed class IncrementalUpdateCheckResult
{
    /// <summary>是否有可用更新</summary>
    public bool HasUpdate { get; set; }

    /// <summary>当前版本</summary>
    public string CurrentVersion { get; set; } = "";

    /// <summary>最新版本</summary>
    public string LatestVersion { get; set; } = "";

    /// <summary>是否可应用差分包（当前版本等于 baseVersion）</summary>
    public bool CanApplyIncremental { get; set; }

    /// <summary>增量清单（可能为空）</summary>
    public IncrementalUpdateManifest? Manifest { get; set; }

    /// <summary>错误信息（检查失败时）</summary>
    public string? Error { get; set; }

    public override string ToString()
        => Error != null
            ? $"检查失败 - {Error}"
            : HasUpdate
                ? $"{CurrentVersion} -> {LatestVersion}{(CanApplyIncremental ? "（可增量更新）" : "（需全量更新）")}"
                : $"已是最新 ({CurrentVersion})";
}

/// <summary>
/// 增量更新应用结果
/// </summary>
public sealed class IncrementalUpdateResult
{
    /// <summary>是否成功</summary>
    public bool Success { get; set; }

    /// <summary>旧版本号</summary>
    public string OldVersion { get; set; } = "";

    /// <summary>新版本号</summary>
    public string NewVersion { get; set; } = "";

    /// <summary>已替换文件数</summary>
    public int ReplacedCount { get; set; }

    /// <summary>已删除文件数</summary>
    public int DeletedCount { get; set; }

    /// <summary>备份目录（成功时）</summary>
    public string? BackupPath { get; set; }

    /// <summary>错误信息（失败时）</summary>
    public string? Error { get; set; }

    /// <summary>操作时间</summary>
    public DateTime Timestamp { get; set; } = DateTime.Now;

    public override string ToString()
        => Success
            ? $"{OldVersion} -> {NewVersion} 成功（替换 {ReplacedCount}，删除 {DeletedCount}）"
            : $"失败 - {Error}";
}
