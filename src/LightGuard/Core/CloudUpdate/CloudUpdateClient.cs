using System.Diagnostics;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using LightGuard.Core;
using LightGuard.Security;

namespace LightGuard.Core.CloudUpdate;

/// <summary>
/// 云端规则更新客户端
/// <para>负责与云端更新服务器交互：拉取清单、检查版本、下载并验签应用规则更新。</para>
/// <para>所有更新包均经过 SHA256 完整性校验 + RSA-2048 数字签名双重验证，</para>
/// <para>防止更新服务器被劫持时下发恶意规则。</para>
/// </summary>
public sealed class CloudUpdateClient : IDisposable
{
    #region 常量与字段

    /// <summary>默认服务器基址</summary>
    private const string DefaultBaseUrl = "https://update.lightguard.app/v1";

    /// <summary>HTTP 请求超时时间</summary>
    private static readonly TimeSpan RequestTimeout = TimeSpan.FromSeconds(30);

    /// <summary>最大重试次数</summary>
    private const int MaxRetries = 3;

    /// <summary>下载缓冲区大小（80 KB）</summary>
    private const int DownloadBufferSize = 81920;

    /// <summary>HTTP 客户端（复用连接池）</summary>
    private readonly HttpClient _httpClient;

    /// <summary>JSON 反序列化选项</summary>
    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        PropertyNameCaseInsensitive = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    /// <summary>规则文件存储基目录</summary>
    private readonly string _baseDir;

    /// <summary>当前缓存的清单</summary>
    private UpdateManifest? _cachedManifest;

    #endregion

    #region 属性

    /// <summary>服务器基址（可配置）</summary>
    public string BaseUrl { get; set; }

    /// <summary>规则文件存储基目录</summary>
    public string BaseDir => _baseDir;

    /// <summary>进度变化事件（UI 可订阅以显示进度条）</summary>
    public event Action<UpdateProgress>? ProgressChanged;

    #endregion

    #region 构造函数

    /// <summary>
    /// 创建云端更新客户端
    /// </summary>
    /// <param name="serverUrl">服务器基址，为空则使用默认地址</param>
    public CloudUpdateClient(string? serverUrl = null)
    {
        BaseUrl = string.IsNullOrWhiteSpace(serverUrl) ? DefaultBaseUrl : serverUrl.TrimEnd('/');

        _httpClient = new HttpClient
        {
            Timeout = RequestTimeout
        };
        _httpClient.DefaultRequestHeaders.Add("User-Agent",
            $"LightGuard/{typeof(CloudUpdateClient).Assembly.GetName().Version?.ToString() ?? "3.0.0"}");

        _baseDir = Path.Combine(ConfigManager.GetDataDir(), "cloudupdate");
        Directory.CreateDirectory(_baseDir);

        // 为每种规则类型创建子目录
        foreach (RuleType rt in Enum.GetValues<RuleType>())
        {
            Directory.CreateDirectory(Path.Combine(_baseDir, rt.ToString()));
        }

        ErrorReporter.Log("[CloudUpdate] 客户端已初始化，服务器: " + BaseUrl);
    }

    #endregion

    #region 清单获取

    /// <summary>
    /// 从服务器拉取指定通道的更新清单
    /// GET {BaseUrl}/manifest/{channel}
    /// </summary>
    /// <param name="channel">更新通道</param>
    /// <returns>更新清单；失败返回 null</returns>
    public async Task<UpdateManifest?> FetchManifestAsync(UpdateChannel channel)
    {
        var url = $"{BaseUrl}/manifest/{channel.ToString().ToLowerInvariant()}";

        for (int attempt = 0; attempt < MaxRetries; attempt++)
        {
            try
            {
                RaiseProgress(5, "正在获取更新清单...", true);

                var json = await _httpClient.GetStringAsync(url);
                var manifest = JsonSerializer.Deserialize<UpdateManifest>(json, JsonOpts);

                if (manifest != null && manifest.LatestVersions.Count > 0)
                {
                    _cachedManifest = manifest;
                    RaiseProgress(10, "清单获取完成", false);
                    ErrorReporter.Log($"[CloudUpdate] 清单获取成功，{manifest.LatestVersions.Count} 条规则");
                    return manifest;
                }

                ErrorReporter.Log("[CloudUpdate] 清单为空或格式无效", "WARN");
                return null;
            }
            catch (Exception ex)
            {
                if (attempt < MaxRetries - 1)
                {
                    var delay = TimeSpan.FromSeconds(Math.Pow(2, attempt)); // 1s, 2s, 4s
                    ErrorReporter.Log($"[CloudUpdate] 清单获取第 {attempt + 1} 次失败，{delay.TotalSeconds}s 后重试: {ex.Message}", "WARN");
                    await Task.Delay(delay);
                }
                else
                {
                    ErrorReporter.Report(ex, "[CloudUpdate] 清单获取失败（已用尽重试）");
                    RaiseProgress(0, "清单获取失败", false);
                    return null;
                }
            }
        }

        return null;
    }

    #endregion

    #region 版本检查

    /// <summary>
    /// 检查指定规则类型是否有可用更新
    /// </summary>
    /// <param name="ruleType">规则类型</param>
    /// <param name="currentVersion">当前本地版本号</param>
    /// <returns>检查结果</returns>
    public async Task<UpdateCheckResult> CheckUpdateAsync(RuleType ruleType, string currentVersion)
    {
        var result = new UpdateCheckResult
        {
            RuleType = ruleType,
            CurrentVersion = currentVersion
        };

        try
        {
            // 使用缓存的清单，未缓存则获取稳定通道
            var manifest = _cachedManifest ?? await FetchManifestAsync(UpdateChannel.Stable);
            if (manifest == null)
            {
                result.Error = "无法获取更新清单";
                return result;
            }

            var entry = manifest.LatestVersions.FirstOrDefault(v => v.RuleType == ruleType);
            if (entry == null)
            {
                result.Error = $"清单中未找到规则类型 {ruleType}";
                return result;
            }

            result.LatestVersion = entry.Version;
            result.ManifestEntry = entry;
            result.HasUpdate = CompareVersions(entry.Version, currentVersion) > 0;

            return result;
        }
        catch (Exception ex)
        {
            result.Error = ex.Message;
            ErrorReporter.Report(ex, $"[CloudUpdate] 检查 {ruleType} 更新失败");
            return result;
        }
    }

    /// <summary>
    /// 检查所有规则类型的更新状态
    /// </summary>
    /// <returns>所有规则类型的检查结果列表</returns>
    public async Task<List<UpdateCheckResult>> CheckAllUpdatesAsync()
    {
        var results = new List<UpdateCheckResult>();

        // 确保清单已缓存
        if (_cachedManifest == null)
        {
            await FetchManifestAsync(UpdateChannel.Stable);
        }

        foreach (RuleType rt in Enum.GetValues<RuleType>())
        {
            var currentVersion = GetLocalVersion(rt);
            var checkResult = await CheckUpdateAsync(rt, currentVersion);
            results.Add(checkResult);
        }

        return results;
    }

    #endregion

    #region 下载与应用

    /// <summary>
    /// 下载并应用指定规则的更新
    /// 流程：下载 -> SHA256 校验 -> RSA 签名校验 -> 备份旧文件 -> 原子应用 -> 更新版本记录
    /// </summary>
    /// <param name="ruleType">规则类型</param>
    /// <param name="version">版本信息（来自清单）</param>
    /// <param name="targetDir">目标目录（规则文件存放目录）</param>
    /// <param name="ct">取消令牌</param>
    /// <returns>应用结果</returns>
    public async Task<UpdateApplyResult> DownloadAndApplyAsync(
        RuleType ruleType,
        RuleVersionInfo version,
        string targetDir,
        CancellationToken ct)
    {
        var oldVersion = GetLocalVersion(ruleType);
        var result = new UpdateApplyResult
        {
            RuleType = ruleType,
            OldVersion = oldVersion,
            NewVersion = version.Version
        };

        try
        {
            Directory.CreateDirectory(targetDir);

            var fileName = GetRuleFileName(ruleType);
            var finalPath = Path.Combine(targetDir, fileName);
            var tempPath = finalPath + ".tmp";
            var backupPath = finalPath + ".bak";

            // 1. 下载文件（带进度）
            RaiseProgress(10, $"下载 {ruleType} v{version.Version}...", true);
            await DownloadFileAsync(version.DownloadUrl, tempPath,
                new Progress<double>(p => RaiseProgress(10 + p * 0.5, $"下载中 {p:F0}%", true)),
                ct);

            // 2. SHA256 完整性校验
            RaiseProgress(65, "SHA256 校验中...", true);
            if (!await VerifyHashAsync(tempPath, version.Sha256Hash))
            {
                SafeDeleteFile(tempPath);
                result.Error = "SHA256 校验失败：文件可能已损坏";
                ErrorReporter.Log($"[CloudUpdate] {ruleType} SHA256 校验失败", "ERROR");
                RaiseProgress(0, "校验失败", false);
                return result;
            }
            ErrorReporter.Log($"[CloudUpdate] {ruleType} SHA256 校验通过");

            // 3. RSA-2048 数字签名校验
            RaiseProgress(75, "RSA 签名校验中...", true);
            if (!await VerifySignatureAsync(tempPath, version.RsaSignature, ""))
            {
                SafeDeleteFile(tempPath);
                result.Error = "RSA 数字签名校验失败：文件可能已被篡改";
                ErrorReporter.Log($"[CloudUpdate] {ruleType} RSA 签名校验失败", "ERROR");
                RaiseProgress(0, "签名校验失败", false);
                return result;
            }
            ErrorReporter.Log($"[CloudUpdate] {ruleType} RSA-2048 签名校验通过");

            // 4. 备份当前规则文件
            RaiseProgress(85, "备份旧规则...", true);
            if (File.Exists(finalPath))
            {
                File.Copy(finalPath, backupPath, true);
                result.BackupPath = backupPath;
                ErrorReporter.Log($"[CloudUpdate] 已备份旧规则: {backupPath}");
            }

            // 5. 原子应用：先写入临时文件（已下载），再重命名替换
            RaiseProgress(90, "应用新规则...", true);
            if (File.Exists(finalPath))
            {
                File.Delete(finalPath);
            }
            // File.Move 在同卷下是原子操作
            File.Move(tempPath, finalPath);

            // 6. 更新本地版本记录
            SetLocalVersion(ruleType, version.Version);

            RaiseProgress(100, $"更新完成: v{version.Version}", false);
            result.Success = true;
            ErrorReporter.Log($"[CloudUpdate] {ruleType} 更新成功: {oldVersion} -> {version.Version}");
            return result;
        }
        catch (OperationCanceledException)
        {
            result.Error = "更新已取消";
            RaiseProgress(0, "已取消", false);
            return result;
        }
        catch (Exception ex)
        {
            result.Error = ex.Message;
            ErrorReporter.Report(ex, $"[CloudUpdate] {ruleType} 更新失败");
            RaiseProgress(0, "更新失败", false);
            return result;
        }
    }

    #endregion

    #region 文件下载（带重试）

    /// <summary>
    /// 下载文件到指定路径（带超时和指数退避重试，最多 3 次）
    /// </summary>
    /// <param name="url">下载地址</param>
    /// <param name="destPath">目标路径</param>
    /// <param name="progress">进度回调（0-100）</param>
    /// <param name="ct">取消令牌</param>
    public async Task DownloadFileAsync(string url, string destPath,
        IProgress<double>? progress, CancellationToken ct)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(destPath)!);

        Exception? lastError = null;

        for (int attempt = 0; attempt < MaxRetries; attempt++)
        {
            try
            {
                using var response = await _httpClient.GetAsync(url,
                    HttpCompletionOption.ResponseHeadersRead, ct);
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
                        var percent = (double)downloadedBytes / totalBytes * 100;
                        var speedKBps = sw.Elapsed.TotalSeconds > 0
                            ? downloadedBytes / 1024.0 / sw.Elapsed.TotalSeconds
                            : 0;
                        progress?.Report(percent);
                    }
                }

                progress?.Report(100);
                return; // 下载成功
            }
            catch (OperationCanceledException)
            {
                throw; // 取消不重试
            }
            catch (Exception ex)
            {
                lastError = ex;
                SafeDeleteFile(destPath);

                if (attempt < MaxRetries - 1)
                {
                    var delay = TimeSpan.FromSeconds(Math.Pow(2, attempt));
                    ErrorReporter.Log($"[CloudUpdate] 下载第 {attempt + 1} 次失败，{delay.TotalSeconds}s 后重试: {ex.Message}", "WARN");
                    await Task.Delay(delay, ct);
                }
            }
        }

        throw new IOException($"文件下载失败（已重试 {MaxRetries} 次）: {lastError?.Message}", lastError);
    }

    #endregion

    #region 校验方法

    /// <summary>
    /// 验证文件的 SHA256 哈希值
    /// </summary>
    /// <param name="filePath">文件路径</param>
    /// <param name="expectedSha256">期望的 SHA256（十六进制字符串）</param>
    /// <returns>是否匹配</returns>
    public async Task<bool> VerifyHashAsync(string filePath, string expectedSha256)
    {
        if (string.IsNullOrEmpty(expectedSha256))
            return true;

        if (!File.Exists(filePath))
            return false;

        try
        {
            await using var stream = File.OpenRead(filePath);
            var hashBytes = await SHA256.HashDataAsync(stream);
            var actualHash = Convert.ToHexString(hashBytes).ToLowerInvariant();
            return string.Equals(actualHash, expectedSha256.ToLowerInvariant(),
                StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// 验证文件的 RSA-2048 数字签名
    /// </summary>
    /// <param name="filePath">文件路径</param>
    /// <param name="signatureBase64">Base64 编码的签名</param>
    /// <param name="publicKey">RSA 公钥（XML 格式），为空则使用内置官方公钥</param>
    /// <returns>签名是否有效</returns>
    public Task<bool> VerifySignatureAsync(string filePath, string signatureBase64, string publicKey)
    {
        return Task.Run(() =>
        {
            try
            {
                var publicKeyXml = string.IsNullOrEmpty(publicKey) ? null : publicKey;
                var result = UpdateSignatureVerifier.VerifyFileSignature(filePath, signatureBase64, publicKeyXml);
                return result.IsValid;
            }
            catch
            {
                return false;
            }
        });
    }

    #endregion

    #region 版本文件管理

    /// <summary>
    /// 读取指定规则类型的本地版本号
    /// 版本文件路径: {targetDir}/{ruleType}.version
    /// </summary>
    public string GetLocalVersion(RuleType ruleType)
    {
        var versionFile = Path.Combine(_baseDir, ruleType.ToString(), $"{ruleType}.version");
        try
        {
            if (File.Exists(versionFile))
                return File.ReadAllText(versionFile).Trim();
        }
        catch { }
        return "0.0.0";
    }

    /// <summary>
    /// 写入指定规则类型的本地版本号
    /// </summary>
    public void SetLocalVersion(RuleType ruleType, string version)
    {
        var dir = Path.Combine(_baseDir, ruleType.ToString());
        Directory.CreateDirectory(dir);
        var versionFile = Path.Combine(dir, $"{ruleType}.version");
        File.WriteAllText(versionFile, version);
    }

    /// <summary>
    /// 获取指定规则类型的目标目录
    /// </summary>
    public string GetTargetDir(RuleType ruleType)
        => Path.Combine(_baseDir, ruleType.ToString());

    #endregion

    #region 辅助方法

    /// <summary>
    /// 获取规则类型对应的文件名
    /// </summary>
    private static string GetRuleFileName(RuleType ruleType) => ruleType switch
    {
        RuleType.YaraRansomware => "online_rules.json",
        RuleType.AdBlockRules => "adblock_rules.json",
        RuleType.DecryptorIndex => "DecryptionToolIndex.json",
        RuleType.VirusDatabase => "main.cvd",
        _ => "rules.dat"
    };

    /// <summary>
    /// 获取规则类型的中文显示名
    /// </summary>
    public static string GetRuleDisplayName(RuleType ruleType) => ruleType switch
    {
        RuleType.YaraRansomware => "YARA 勒索规则库",
        RuleType.AdBlockRules => "广告拦截规则库",
        RuleType.DecryptorIndex => "解密工具索引",
        RuleType.VirusDatabase => "病毒特征数据库",
        _ => ruleType.ToString()
    };

    /// <summary>
    /// 比较语义化版本号
    /// 返回值: >0 表示 v1 > v2, <0 表示 v1 < v2, 0 表示相等
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
    /// 安全删除文件（忽略错误）
    /// </summary>
    private static void SafeDeleteFile(string? path)
    {
        if (string.IsNullOrEmpty(path)) return;
        try { if (File.Exists(path)) File.Delete(path); }
        catch { /* 忽略 */ }
    }

    /// <summary>
    /// 触发进度事件
    /// </summary>
    private void RaiseProgress(double percent, string currentFile, bool isRunning)
    {
        ProgressChanged?.Invoke(new UpdateProgress
        {
            PercentComplete = percent,
            CurrentFile = currentFile,
            IsRunning = isRunning,
            SpeedKBps = 0
        });
    }

    #endregion

    #region IDisposable

    public void Dispose()
    {
        _httpClient.Dispose();
    }

    #endregion
}
