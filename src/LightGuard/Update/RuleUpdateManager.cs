using System.Diagnostics;
using System.Net.Http;
using System.Text.Json;
using System.Text.Json.Serialization;
using LightGuard.Core;
using LightGuard.Security;

namespace LightGuard.Update;

/// <summary>
/// 云端规则更新管理器
/// <para>负责与云端规则仓库交互：查询最新版本、下载规则包、SHA256 + RSA-2048 双重校验、</para>
/// <para>备份旧规则并原子安装新规则。所有更新包必须通过签名校验，防止服务器劫持下发恶意规则。</para>
/// </summary>
public sealed class RuleUpdateManager : IDisposable
{
    #region 常量与字段

    /// <summary>默认服务器基址（GitHub 规则仓库 raw 地址）</summary>
    private const string DefaultServerUrl = "https://raw.githubusercontent.com/snqig/LightGuard-rules/main";

    /// <summary>HTTP 请求超时时间</summary>
    private static readonly TimeSpan HttpTimeout = TimeSpan.FromSeconds(30);

    /// <summary>下载缓冲区大小（80 KB）</summary>
    private const int DownloadBufferSize = 81920;

    /// <summary>HTTP 客户端（复用连接池）</summary>
    private readonly HttpClient _httpClient;

    /// <summary>当前配置</summary>
    private readonly RuleUpdateConfig _config;

    /// <summary>规则文件存储基目录</summary>
    private readonly string _rulesDir;

    /// <summary>配置持久化文件路径</summary>
    private readonly string _configFilePath;

    private bool _disposed;

    /// <summary>JSON 序列化选项（枚举以字符串形式存储，便于人工阅读与跨版本兼容）</summary>
    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        PropertyNameCaseInsensitive = true,
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Converters = { new JsonStringEnumConverter() }
    };

    #endregion

    #region 事件

    /// <summary>进度变化事件（UI 可订阅以显示进度条与速度）</summary>
    public event Action<RuleUpdateProgress>? ProgressChanged;

    /// <summary>单条规则更新完成事件</summary>
    public event Action<RuleUpdateResult>? UpdateCompleted;

    #endregion

    #region 构造函数

    /// <summary>
    /// 创建云端规则更新管理器
    /// </summary>
    /// <param name="config">规则更新配置</param>
    public RuleUpdateManager(RuleUpdateConfig config)
    {
        _config = config;

        if (string.IsNullOrWhiteSpace(_config.UpdateServerUrl))
            _config.UpdateServerUrl = DefaultServerUrl;
        _config.UpdateServerUrl = _config.UpdateServerUrl.TrimEnd('/');

        _config.InstalledVersions ??= new Dictionary<RuleType, string>();

        _httpClient = new HttpClient
        {
            Timeout = HttpTimeout
        };
        _httpClient.DefaultRequestHeaders.Add("User-Agent",
            $"LightGuard-RuleUpdate/{typeof(RuleUpdateManager).Assembly.GetName().Version?.ToString() ?? "3.0.0"}");

        _rulesDir = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Resources", "rules");
        Directory.CreateDirectory(_rulesDir);

        _configFilePath = Path.Combine(_rulesDir, "rule_update_config.json");

        ErrorReporter.Log($"[RuleUpdate] 管理器已初始化 - 服务器: {_config.UpdateServerUrl} | 间隔: {_config.CheckIntervalHours}h");
    }

    #endregion

    #region 公共属性与方法

    /// <summary>获取当前配置</summary>
    public RuleUpdateConfig GetConfig() => _config;

    /// <summary>
    /// 获取指定规则类型的本地存储路径
    /// </summary>
    public string GetRulePath(RuleType type) => Path.Combine(_rulesDir, GetRuleFileName(type));

    /// <summary>
    /// 获取指定规则类型当前已安装的版本号（未安装返回 "0.0.0"）
    /// </summary>
    public string GetInstalledVersion(RuleType type)
    {
        return _config.InstalledVersions.TryGetValue(type, out var v) && !string.IsNullOrEmpty(v)
            ? v
            : "0.0.0";
    }

    /// <summary>
    /// 查询服务器上指定规则类型的最新版本信息
    /// </summary>
    /// <param name="type">规则类型</param>
    /// <returns>最新版本信息；失败返回 null</returns>
    public async Task<RuleVersionInfo?> CheckLatestVersionAsync(RuleType type)
    {
        try
        {
            var url = GetVersionJsonUrl(type);
            RaiseProgress(type, 5, "正在查询最新版本...", 0, true);

            var json = await _httpClient.GetStringAsync(url);
            var info = JsonSerializer.Deserialize<RuleVersionInfo>(json, JsonOpts);

            if (info == null || string.IsNullOrWhiteSpace(info.Version))
            {
                ErrorReporter.Log($"[RuleUpdate] {type} 版本信息为空或格式无效", "WARN");
                RaiseProgress(type, 0, "版本信息无效", 0, false);
                return null;
            }

            info.RuleType = type;

            _config.LastCheckTime = DateTime.Now;
            SaveConfig();

            RaiseProgress(type, 10, $"最新版本: v{info.Version}", 0, false);
            ErrorReporter.Log($"[RuleUpdate] {type} 最新版本: {info.Version} (发布于 {info.ReleaseDate:yyyy-MM-dd})");
            return info;
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, $"[RuleUpdate] 查询 {type} 最新版本失败");
            RaiseProgress(type, 0, "查询失败", 0, false);
            return null;
        }
    }

    /// <summary>
    /// 判断指定规则类型是否有可用更新
    /// </summary>
    public async Task<bool> IsUpdateAvailableAsync(RuleType type)
    {
        try
        {
            var latest = await CheckLatestVersionAsync(type);
            if (latest == null)
                return false;

            var installed = GetInstalledVersion(type);
            return CompareVersions(latest.Version, installed) > 0;
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, $"[RuleUpdate] 检查 {type} 更新可用性失败");
            return false;
        }
    }

    /// <summary>
    /// 执行完整的规则更新流程：
    /// <para>1. 查询服务器最新版本</para>
    /// <para>2. 下载规则包（带进度）</para>
    /// <para>3. 校验 SHA256 完整性</para>
    /// <para>4. 校验 RSA-2048 数字签名（使用 UpdateSignatureVerifier）</para>
    /// <para>5. 备份当前规则文件</para>
    /// <para>6. 原子安装新规则（写入临时文件后重命名）</para>
    /// <para>7. 更新已安装版本记录</para>
    /// </summary>
    /// <param name="type">规则类型</param>
    /// <param name="ct">取消令牌</param>
    /// <returns>更新结果</returns>
    public async Task<RuleUpdateResult> UpdateRuleAsync(RuleType type, CancellationToken ct)
    {
        var sw = Stopwatch.StartNew();
        var oldVersion = GetInstalledVersion(type);
        var result = new RuleUpdateResult
        {
            RuleType = type,
            OldVersion = oldVersion
        };

        try
        {
            // 1. 查询最新版本
            RaiseProgress(type, 5, "正在查询最新版本...", 0, true);
            var latest = await CheckLatestVersionAsync(type);
            if (latest == null)
            {
                result.ErrorMessage = "无法获取最新版本信息";
                result.Duration = sw.Elapsed;
                UpdateCompleted?.Invoke(result);
                return result;
            }

            result.NewVersion = latest.Version;

            // 已是最新版本，无需更新
            if (CompareVersions(latest.Version, oldVersion) <= 0)
            {
                result.Success = true;
                result.NewVersion = oldVersion;
                result.Verified = true;
                result.Duration = sw.Elapsed;
                RaiseProgress(type, 100, $"已是最新版本 v{oldVersion}", 0, false);
                UpdateCompleted?.Invoke(result);
                return result;
            }

            var finalPath = GetRulePath(type);
            var tempPath = finalPath + ".tmp";
            var backupPath = finalPath + ".bak";

            // 2. 下载规则包（带进度）
            RaiseProgress(type, 10, $"下载 v{latest.Version}...", 0, true);
            var downloadedBytes = await DownloadFileAsync(latest.DownloadUrl, tempPath, type, ct);
            result.DownloadedBytes = downloadedBytes;

            // 3. 校验 SHA256 完整性
            RaiseProgress(type, 65, "SHA256 校验中...", 0, true);
            if (!VerifySha256(tempPath, latest.Sha256Hash))
            {
                SafeDelete(tempPath);
                result.ErrorMessage = "SHA256 校验失败：文件可能已损坏或被篡改";
                result.Duration = sw.Elapsed;
                ErrorReporter.Log($"[RuleUpdate] {type} SHA256 校验失败", "ERROR");
                UpdateCompleted?.Invoke(result);
                return result;
            }
            ErrorReporter.Log($"[RuleUpdate] {type} SHA256 校验通过");

            // 4. 校验 RSA-2048 数字签名
            RaiseProgress(type, 75, "RSA 签名校验中...", 0, true);
            if (!VerifySignature(tempPath, latest.SignatureBase64))
            {
                SafeDelete(tempPath);
                result.ErrorMessage = "RSA 数字签名校验失败：文件可能已被篡改";
                result.Duration = sw.Elapsed;
                ErrorReporter.Log($"[RuleUpdate] {type} RSA 签名校验失败", "ERROR");
                UpdateCompleted?.Invoke(result);
                return result;
            }
            result.Verified = true;
            ErrorReporter.Log($"[RuleUpdate] {type} RSA-2048 签名校验通过");

            // 5. 备份当前规则文件
            RaiseProgress(type, 85, "备份当前规则...", 0, true);
            if (File.Exists(finalPath))
            {
                File.Copy(finalPath, backupPath, true);
                ErrorReporter.Log($"[RuleUpdate] 已备份旧规则: {backupPath}");
            }

            // 6. 原子安装：删除旧文件后移动临时文件（同卷 File.Move 为原子操作）
            RaiseProgress(type, 90, "安装新规则...", 0, true);
            if (File.Exists(finalPath))
            {
                File.Delete(finalPath);
            }
            File.Move(tempPath, finalPath);

            // 7. 更新已安装版本记录
            _config.InstalledVersions[type] = latest.Version;
            SaveConfig();

            result.Success = true;
            result.Duration = sw.Elapsed;
            RaiseProgress(type, 100, $"更新完成: v{latest.Version}", 0, false);
            ErrorReporter.Log($"[RuleUpdate] {type} 更新成功: {oldVersion} -> {latest.Version} " +
                              $"({downloadedBytes} bytes, {sw.Elapsed.TotalSeconds:F1}s)");
            UpdateCompleted?.Invoke(result);
            return result;
        }
        catch (OperationCanceledException)
        {
            result.ErrorMessage = "更新已取消";
            result.Duration = sw.Elapsed;
            RaiseProgress(type, 0, "已取消", 0, false);
            UpdateCompleted?.Invoke(result);
            return result;
        }
        catch (Exception ex)
        {
            result.ErrorMessage = ex.Message;
            result.Duration = sw.Elapsed;
            ErrorReporter.Report(ex, $"[RuleUpdate] {type} 更新失败");
            RaiseProgress(type, 0, "更新失败", 0, false);
            UpdateCompleted?.Invoke(result);
            return result;
        }
    }

    /// <summary>
    /// 更新所有规则类型
    /// </summary>
    /// <param name="ct">取消令牌</param>
    /// <returns>各规则类型的更新结果</returns>
    public async Task<Dictionary<RuleType, RuleUpdateResult>> UpdateAllAsync(CancellationToken ct)
    {
        var results = new Dictionary<RuleType, RuleUpdateResult>();
        ErrorReporter.Log("[RuleUpdate] ===== 开始全量规则更新 =====");

        foreach (RuleType type in Enum.GetValues<RuleType>())
        {
            if (ct.IsCancellationRequested)
            {
                ErrorReporter.Log("[RuleUpdate] 全量更新已被取消", "WARN");
                break;
            }

            results[type] = await UpdateRuleAsync(type, ct);
        }

        var successCount = results.Count(r => r.Value.Success);
        ErrorReporter.Log($"[RuleUpdate] ===== 全量规则更新完成，成功 {successCount}/{results.Count} 项 =====");
        return results;
    }

    /// <summary>
    /// 配置自动更新开关
    /// </summary>
    public Task SetAutoUpdateAsync(bool enabled)
    {
        _config.AutoUpdateEnabled = enabled;
        SaveConfig();
        ErrorReporter.Log($"[RuleUpdate] 自动更新已 {(enabled ? "启用" : "禁用")}");
        return Task.CompletedTask;
    }

    /// <summary>
    /// 从本地持久化文件加载配置（不存在则返回 null）
    /// </summary>
    public static RuleUpdateConfig? LoadConfig()
    {
        try
        {
            var dir = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Resources", "rules");
            var path = Path.Combine(dir, "rule_update_config.json");
            if (!File.Exists(path))
                return null;

            var json = File.ReadAllText(path);
            var config = JsonSerializer.Deserialize<RuleUpdateConfig>(json, JsonOpts);
            if (config != null && config.InstalledVersions == null)
            {
                config.InstalledVersions = new Dictionary<RuleType, string>();
            }
            return config;
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, "[RuleUpdate] 加载配置失败");
            return null;
        }
    }

    /// <summary>
    /// 比较语义化版本号
    /// 返回值: &gt;0 表示 v1 &gt; v2, &lt;0 表示 v1 &lt; v2, 0 表示相等
    /// </summary>
    public static int CompareVersions(string v1, string v2)
    {
        if (string.IsNullOrEmpty(v1)) v1 = "0";
        if (string.IsNullOrEmpty(v2)) v2 = "0";

        if (v1.StartsWith("v", StringComparison.OrdinalIgnoreCase)) v1 = v1[1..];
        if (v2.StartsWith("v", StringComparison.OrdinalIgnoreCase)) v2 = v2[1..];

        var parts1 = v1.Split('.');
        var parts2 = v2.Split('.');
        var maxLen = Math.Max(parts1.Length, parts2.Length);

        for (var i = 0; i < maxLen; i++)
        {
            var p1 = i < parts1.Length && int.TryParse(parts1[i], out var n1) ? n1 : 0;
            var p2 = i < parts2.Length && int.TryParse(parts2[i], out var n2) ? n2 : 0;
            if (p1 != p2)
                return p1.CompareTo(p2);
        }

        return 0;
    }

    /// <summary>
    /// 获取规则类型的中文显示名
    /// </summary>
    public static string GetRuleDisplayName(RuleType type) => type switch
    {
        RuleType.YaraRules => "YARA 勒索规则库",
        RuleType.AdBlockRules => "广告拦截规则库",
        RuleType.DecryptionIndex => "解密工具索引",
        RuleType.VirusDb => "病毒特征数据库",
        _ => type.ToString()
    };

    #endregion

    #region 下载

    /// <summary>
    /// 下载文件到指定路径（带进度与速度统计）
    /// </summary>
    /// <param name="url">下载地址</param>
    /// <param name="destPath">目标路径</param>
    /// <param name="type">规则类型（用于进度事件）</param>
    /// <param name="ct">取消令牌</param>
    /// <returns>已下载字节数</returns>
    private async Task<long> DownloadFileAsync(string url, string destPath, RuleType type, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(url))
            throw new InvalidOperationException("下载地址为空");

        var dir = Path.GetDirectoryName(destPath);
        if (!string.IsNullOrEmpty(dir))
            Directory.CreateDirectory(dir);

        // 下载阶段映射到 10%-60% 进度区间
        const double downloadStart = 10;
        const double downloadEnd = 60;

        using var response = await _httpClient.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, ct);
        response.EnsureSuccessStatusCode();

        var totalBytes = response.Content.Headers.ContentLength ?? -1;
        long downloadedBytes = 0;
        var sw = Stopwatch.StartNew();

        await using var contentStream = await response.Content.ReadAsStreamAsync(ct);
        await using var fileStream = new FileStream(destPath, FileMode.Create,
            FileAccess.Write, FileShare.None, DownloadBufferSize, useAsync: true);

        var buffer = new byte[DownloadBufferSize];
        int bytesRead;

        while ((bytesRead = await contentStream.ReadAsync(buffer, ct)) > 0)
        {
            await fileStream.WriteAsync(buffer.AsMemory(0, bytesRead), ct);
            downloadedBytes += bytesRead;

            if (totalBytes > 0)
            {
                var fraction = (double)downloadedBytes / totalBytes;
                var percent = downloadStart + fraction * (downloadEnd - downloadStart);
                var speedKbps = sw.Elapsed.TotalSeconds > 0
                    ? downloadedBytes / 1024.0 / sw.Elapsed.TotalSeconds
                    : 0;
                RaiseProgress(type, percent, $"下载中 {fraction * 100:F0}%", speedKbps, true);
            }
        }

        RaiseProgress(type, downloadEnd, "下载完成", 0, true);
        ErrorReporter.Log($"[RuleUpdate] 下载完成: {downloadedBytes} bytes ({url})");
        return downloadedBytes;
    }

    #endregion

    #region 校验

    /// <summary>
    /// 校验文件 SHA256 哈希值
    /// </summary>
    /// <param name="filePath">文件路径</param>
    /// <param name="expectedSha256">期望的 SHA256（十六进制字符串）</param>
    /// <returns>是否匹配（期望值为空时跳过校验并返回 true）</returns>
    private bool VerifySha256(string filePath, string expectedSha256)
    {
        if (string.IsNullOrEmpty(expectedSha256))
        {
            ErrorReporter.Log("[RuleUpdate] 未提供 SHA256，跳过完整性校验", "WARN");
            return true;
        }

        if (!File.Exists(filePath))
            return false;

        var actualHash = UpdateSignatureVerifier.ComputeSha256(filePath);
        return string.Equals(actualHash, expectedSha256.ToLowerInvariant(),
            StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// 校验文件 RSA-2048 数字签名（使用 UpdateSignatureVerifier）
    /// </summary>
    /// <param name="filePath">文件路径</param>
    /// <param name="signatureBase64">Base64 编码的签名</param>
    /// <returns>签名是否有效</returns>
    private bool VerifySignature(string filePath, string signatureBase64)
    {
        if (string.IsNullOrEmpty(signatureBase64))
        {
            ErrorReporter.Log("[RuleUpdate] 签名为空，规则包未经签名", "ERROR");
            return false;
        }

        try
        {
            // 配置的公钥为空时使用 UpdateSignatureVerifier 内嵌的官方公钥（占位符，待替换为正式公钥）
            var publicKeyXml = string.IsNullOrEmpty(_config.PublicKeyXml) ? null : _config.PublicKeyXml;
            var result = UpdateSignatureVerifier.VerifyFileSignature(filePath, signatureBase64, publicKeyXml);

            if (!result.IsValid)
            {
                ErrorReporter.Log($"[RuleUpdate] 签名校验失败: {result.Error}", "ERROR");
            }

            return result.IsValid;
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, "[RuleUpdate] 签名校验异常");
            return false;
        }
    }

    #endregion

    #region 路径与配置持久化

    /// <summary>
    /// 获取规则类型对应的云端 version.json 地址
    /// </summary>
    private string GetVersionJsonUrl(RuleType type)
        => $"{_config.UpdateServerUrl}/{GetRuleFolder(type)}/version.json";

    /// <summary>
    /// 规则类型对应的仓库子目录
    /// </summary>
    private static string GetRuleFolder(RuleType type) => type switch
    {
        RuleType.YaraRules => "yara",
        RuleType.AdBlockRules => "adblock",
        RuleType.DecryptionIndex => "decrypt",
        RuleType.VirusDb => "virusdb",
        _ => type.ToString().ToLowerInvariant()
    };

    /// <summary>
    /// 规则类型对应的本地文件名
    /// </summary>
    private static string GetRuleFileName(RuleType type) => type switch
    {
        RuleType.YaraRules => "yara_rules.json",
        RuleType.AdBlockRules => "adblock_rules.json",
        RuleType.DecryptionIndex => "decryption_index.json",
        RuleType.VirusDb => "virus_db.cvd",
        _ => "rules.dat"
    };

    /// <summary>
    /// 持久化当前配置到本地文件
    /// </summary>
    private void SaveConfig()
    {
        try
        {
            Directory.CreateDirectory(_rulesDir);
            var json = JsonSerializer.Serialize(_config, JsonOpts);
            File.WriteAllText(_configFilePath, json);
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, "[RuleUpdate] 保存配置失败");
        }
    }

    #endregion

    #region 辅助方法

    private void RaiseProgress(RuleType type, double percent, string action, double speedKbps, bool isRunning)
    {
        ProgressChanged?.Invoke(new RuleUpdateProgress
        {
            RuleType = type,
            PercentComplete = percent,
            CurrentAction = action,
            DownloadSpeed = speedKbps,
            IsRunning = isRunning
        });
    }

    private static void SafeDelete(string? path)
    {
        if (string.IsNullOrEmpty(path)) return;
        try { if (File.Exists(path)) File.Delete(path); }
        catch { /* 忽略 */ }
    }

    #endregion

    #region IDisposable

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _httpClient.Dispose();
    }

    #endregion
}
