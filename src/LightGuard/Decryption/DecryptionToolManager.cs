using System.Diagnostics;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using LightGuard.Core;
using LightGuard.Defender;

namespace LightGuard.Decryption;

/// <summary>
/// 解密工具管理器
/// 负责解密工具的下载、SHA256 校验、本地索引管理
/// 工具存储目录：{程序基目录}/tools/decryptors/
/// </summary>
public sealed class DecryptionToolManager : IDisposable
{
    /// <summary>解密工具存储根目录</summary>
    private readonly string _toolDir;

    /// <summary>本地索引文件路径</summary>
    private readonly string _indexPath;

    /// <summary>HTTP 客户端（复用连接池）</summary>
    private readonly HttpClient _httpClient;

    /// <summary>工具索引更新服务器地址（占位，正式发布后替换）</summary>
    private const string IndexUpdateUrl = "https://download.lightguard.local/decryptors/index.json";

    /// <summary>下载超时时间</summary>
    private static readonly TimeSpan DownloadTimeout = TimeSpan.FromMinutes(10);

    /// <summary>JSON 序列化选项</summary>
    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    /// <summary>内置家族检测器（用于在索引缺失时兜底）</summary>
    private readonly RansomwareFamilyDetector _detector = new();

    /// <summary>
    /// 构造函数 - 初始化工具目录和 HTTP 客户端
    /// </summary>
    public DecryptionToolManager()
    {
        _toolDir = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "tools", "decryptors");
        Directory.CreateDirectory(_toolDir);
        _indexPath = Path.Combine(_toolDir, "DecryptionToolIndex.json");
        _httpClient = new HttpClient { Timeout = DownloadTimeout };
    }

    #region 工具下载与校验

    /// <summary>
    /// 下载指定家族的解密工具并校验 SHA256
    /// </summary>
    /// <param name="family">家族信息</param>
    /// <param name="progress">下载进度回调（0-100）</param>
    /// <returns>下载后的工具本地路径；失败返回空字符串</returns>
    public async Task<string> DownloadToolAsync(RansomwareFamilyInfo family, IProgress<double>? progress = null)
    {
        if (string.IsNullOrWhiteSpace(family.DecryptorUrl))
        {
            ErrorReporter.Log($"[解密工具] 家族 {family.Name} 无下载地址", "WARN");
            return "";
        }

        if (string.IsNullOrWhiteSpace(family.DecryptorFileName))
        {
            ErrorReporter.Log($"[解密工具] 家族 {family.Name} 无工具文件名", "WARN");
            return "";
        }

        var destPath = Path.Combine(_toolDir, family.DecryptorFileName);
        var tempPath = destPath + ".tmp";

        try
        {
            ErrorReporter.Log($"[解密工具] 开始下载 {family.Name} 解密器: {family.DecryptorUrl}");

            using var response = await _httpClient.GetAsync(family.DecryptorUrl, HttpCompletionOption.ResponseHeadersRead);
            response.EnsureSuccessStatusCode();

            var totalBytes = response.Content.Headers.ContentLength ?? -1;
            long downloadedBytes = 0;

            await using (var contentStream = await response.Content.ReadAsStreamAsync())
            await using (var fs = new FileStream(tempPath, FileMode.Create, FileAccess.Write, FileShare.None, 81920, useAsync: true))
            {
                var buffer = new byte[81920];
                int bytesRead;

                while ((bytesRead = await contentStream.ReadAsync(buffer)) != 0)
                {
                    await fs.WriteAsync(buffer.AsMemory(0, bytesRead));
                    downloadedBytes += bytesRead;

                    if (totalBytes > 0)
                    {
                        var percent = (double)downloadedBytes / totalBytes * 100;
                        progress?.Report(percent);
                    }
                }
            }

            // SHA256 校验
            if (!string.IsNullOrWhiteSpace(family.DecryptorSha256) &&
                !family.DecryptorSha256.All(c => c == '0'))
            {
                var valid = await VerifyToolAsync(tempPath, family.DecryptorSha256);
                if (!valid)
                {
                    File.Delete(tempPath);
                    ErrorReporter.Log($"[解密工具] SHA256 校验失败，已删除下载文件: {family.Name}", "ERROR");
                    return "";
                }
                ErrorReporter.Log($"[解密工具] SHA256 校验通过: {family.Name}");
            }

            // 校验通过，原子替换
            if (File.Exists(destPath))
                File.Delete(destPath);
            File.Move(tempPath, destPath);

            progress?.Report(100);
            ErrorReporter.Log($"[解密工具] 下载完成: {family.Name} -> {destPath} ({downloadedBytes} bytes)");

            // P1-6：解密工具下载完成后自动查杀，防范更新劫持风险
            await ScanDownloadedToolAsync(family, destPath);

            return destPath;
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, $"下载解密工具失败: {family.Name}");
            // 清理临时文件
            try { if (File.Exists(tempPath)) File.Delete(tempPath); } catch { }
            return "";
        }
    }

    /// <summary>
    /// 校验工具文件的 SHA256 哈希值
    /// </summary>
    /// <param name="toolPath">工具文件路径</param>
    /// <param name="expectedSha256">预期的 SHA256 哈希（十六进制字符串）</param>
    /// <returns>校验通过返回 true</returns>
    public async Task<bool> VerifyToolAsync(string toolPath, string expectedSha256)
    {
        if (!File.Exists(toolPath))
        {
            ErrorReporter.Log($"[解密工具] 校验失败，文件不存在: {toolPath}", "WARN");
            return false;
        }

        if (string.IsNullOrWhiteSpace(expectedSha256))
        {
            ErrorReporter.Log($"[解密工具] 预期哈希为空，跳过校验: {toolPath}", "WARN");
            return true; // 无预期哈希时默认通过（占位阶段）
        }

        // 占位哈希（全零）跳过校验
        if (expectedSha256.All(c => c == '0'))
        {
            ErrorReporter.Log($"[解密工具] 预期哈希为占位值，跳过校验: {toolPath}", "WARN");
            return true;
        }

        try
        {
            await using var fs = new FileStream(toolPath, FileMode.Open, FileAccess.Read, FileShare.Read, 81920, useAsync: true);
            var hashBytes = await SHA256.HashDataAsync(fs);
            var actualHash = Convert.ToHexString(hashBytes).ToLowerInvariant();
            var expected = expectedSha256.ToLowerInvariant().Trim();

            var match = string.Equals(actualHash, expected, StringComparison.OrdinalIgnoreCase);
            if (!match)
            {
                ErrorReporter.Log($"[解密工具] 哈希不匹配: 期望={expected} 实际={actualHash}", "ERROR");
            }
            return match;
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, $"SHA256 校验异常: {toolPath}");
            return false;
        }
    }

    /// <summary>
    /// 解密工具下载完成后自动查杀（P1-6 联动：防范更新劫持风险）。
    /// <para>若扫描发现威胁，说明下载的工具可能已被劫持（即使 SHA256 校验通过），
    /// 删除可疑文件并记录 Critical 审计日志；服务器模式下仅记录日志。</para>
    /// </summary>
    /// <param name="family">勒索家族信息</param>
    /// <param name="toolPath">下载后的工具文件路径</param>
    private async Task ScanDownloadedToolAsync(RansomwareFamilyInfo family, string toolPath)
    {
        try
        {
            var scanner = DefenderIntegrationService.ResolveScanner();
            if (scanner == null)
            {
                ErrorReporter.Log($"[解密工具] Defender 不可用，跳过下载后查杀: {family.Name}", "WARN");
                return;
            }

            ErrorReporter.Log($"[解密工具] 对下载的工具执行 Defender 查杀: {family.Name}");
            var result = await scanner.ScanFileAsync(toolPath, CancellationToken.None);

            // 写入审计日志
            AuditLogSystem.Log(
                result.Success && result.ThreatsFound == 0 ? LogLevel.Info : LogLevel.Critical,
                LogCategory.DefenderScan,
                $"解密工具下载后查杀：{family.Name} - {(result.Success && result.ThreatsFound == 0 ? "干净" : $"发现 {result.ThreatsFound} 个威胁")}",
                $"工具={toolPath} 耗时={result.ScanDuration.TotalSeconds:F1}s");

            if (result.Success && result.ThreatsFound > 0)
            {
                ErrorReporter.Log($"[解密工具] 下载的工具被 Defender 判定为恶意，已删除：{family.Name} ({toolPath})", "ERROR");
                try { File.Delete(toolPath); } catch { }
            }
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, "解密工具下载后查杀异常");
        }
    }

    /// <summary>
    /// 获取指定家族解密工具的本地路径
    /// </summary>
    public string GetToolPath(RansomwareFamily family)
    {
        var info = _detector.GetFamilyInfo(family);
        var fileName = info?.DecryptorFileName ?? $"decryptor_{family}.exe";
        return Path.Combine(_toolDir, fileName);
    }

    /// <summary>
    /// 检查指定家族的解密工具是否已下载且校验通过
    /// </summary>
    public bool IsToolAvailable(RansomwareFamily family)
    {
        var info = _detector.GetFamilyInfo(family);
        if (info == null || !info.HasDecryptor || string.IsNullOrEmpty(info.DecryptorFileName))
            return false;

        var toolPath = GetToolPath(family);
        if (!File.Exists(toolPath))
            return false;

        // 如果有预期哈希且非占位值，执行校验
        if (!string.IsNullOrWhiteSpace(info.DecryptorSha256) &&
            !info.DecryptorSha256.All(c => c == '0'))
        {
            return VerifyToolAsync(toolPath, info.DecryptorSha256).GetAwaiter().GetResult();
        }

        return true;
    }

    /// <summary>
    /// 获取已下载工具文件大小（字节），不存在返回 0
    /// </summary>
    public long GetToolSize(RansomwareFamily family)
    {
        try
        {
            var toolPath = GetToolPath(family);
            return File.Exists(toolPath) ? new FileInfo(toolPath).Length : 0;
        }
        catch { return 0; }
    }

    #endregion

    #region 索引管理

    /// <summary>
    /// 从服务器下载更新的工具索引（占位实现）
    /// </summary>
    public async Task UpdateToolIndexAsync()
    {
        try
        {
            ErrorReporter.Log($"[解密工具] 开始从服务器更新工具索引: {IndexUpdateUrl}");

            using var response = await _httpClient.GetAsync(IndexUpdateUrl);
            if (!response.IsSuccessStatusCode)
            {
                ErrorReporter.Log($"[解密工具] 索引更新失败，HTTP {(int)response.StatusCode}", "WARN");
                return;
            }

            var json = await response.Content.ReadAsStringAsync();
            var index = JsonSerializer.Deserialize<DecryptionToolIndex>(json);
            if (index == null || index.Families.Count == 0)
            {
                ErrorReporter.Log("[解密工具] 服务器返回的索引为空", "WARN");
                return;
            }

            index.LastUpdated = DateTime.Now;
            SaveLocalIndex(index);
            ErrorReporter.Log($"[解密工具] 索引更新成功，共 {index.Families.Count} 个家族");
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, "更新工具索引异常（可能是网络不可用，将使用内置索引）");
        }
    }

    /// <summary>
    /// 加载本地 JSON 索引文件
    /// 如果本地文件不存在，返回内置索引
    /// </summary>
    public DecryptionToolIndex LoadLocalIndex()
    {
        try
        {
            if (File.Exists(_indexPath))
            {
                var json = File.ReadAllText(_indexPath);
                var index = JsonSerializer.Deserialize<DecryptionToolIndex>(json);
                if (index != null && index.Families.Count > 0)
                    return index;
            }
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, "加载本地工具索引异常");
        }

        // 回退到内置索引
        return GetBuiltInIndex();
    }

    /// <summary>
    /// 保存索引到本地 JSON 文件
    /// </summary>
    public void SaveLocalIndex(DecryptionToolIndex index)
    {
        try
        {
            Directory.CreateDirectory(_toolDir);
            var json = JsonSerializer.Serialize(index, JsonOpts);
            File.WriteAllText(_indexPath, json);
            ErrorReporter.Log($"[解密工具] 索引已保存到 {_indexPath}");
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, "保存工具索引异常");
        }
    }

    /// <summary>
    /// 获取内置索引（从检测器的知识库生成）
    /// </summary>
    public DecryptionToolIndex GetBuiltInIndex()
    {
        return new DecryptionToolIndex
        {
            Version = 1,
            LastUpdated = DateTime.Now,
            Families = _detector.GetKnownFamilies()
        };
    }

    /// <summary>
    /// 获取索引文件路径（供 UI 显示）
    /// </summary>
    public string GetIndexPath() => _indexPath;

    /// <summary>
    /// 获取工具存储目录
    /// </summary>
    public string GetToolDir() => _toolDir;

    #endregion

    public void Dispose()
    {
        _httpClient.Dispose();
    }
}
