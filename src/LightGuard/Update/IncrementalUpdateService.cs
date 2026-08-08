// © 2026 落尘（Luochen） 原创开发 - 保留所有权利

using System.IO.Compression;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using LightGuard.Core;
using LightGuard.Security;

namespace LightGuard.Update;

/// <summary>
/// 增量差分更新服务 — 消费 packaging/build-diff.ps1 生成的差分包。
/// <para>流程：拉取清单 → 版本比对 → 下载 update.zip（SHA256+RSA 双校验）→ 备份旧文件 → 应用变更 → 删除多余文件。</para>
/// </summary>
public sealed class IncrementalUpdateService : IDisposable
{
    private readonly HttpClient _http;
    private readonly string _workDir;

    /// <summary>JSON 序列化选项</summary>
    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        PropertyNameCaseInsensitive = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    /// <summary>
    /// 构造增量更新服务。
    /// </summary>
    /// <param name="workDir">工作目录（存放下载的差分包与备份）</param>
    public IncrementalUpdateService(string workDir)
    {
        _workDir = workDir;
        Directory.CreateDirectory(_workDir);
        _http = new HttpClient
        {
            Timeout = TimeSpan.FromMinutes(10)
        };
        _http.DefaultRequestHeaders.Add("User-Agent",
            $"LightGuard/{typeof(IncrementalUpdateService).Assembly.GetName().Version}");
    }

    // ==================== 版本比对 ====================

    /// <summary>
    /// 判断差分包分发形态与当前分发形态是否兼容（P1-1 双版本分发）。
    /// <para>清单未声明 edition 或声明为 universal 时始终兼容；否则需与当前形态（client/server）一致。</para>
    /// </summary>
    /// <param name="manifestEdition">差分包声明的适用形态（client/server/universal/空）</param>
    /// <param name="currentEdition">当前分发形态（client/server；缺省按 client）</param>
    /// <returns>是否兼容</returns>
    public static bool IsEditionCompatible(string? manifestEdition, string? currentEdition)
    {
        if (string.IsNullOrWhiteSpace(manifestEdition)) return true;
        if (string.Equals(manifestEdition, "universal", StringComparison.OrdinalIgnoreCase)) return true;
        var edition = string.IsNullOrWhiteSpace(currentEdition) ? "client" : currentEdition;
        return string.Equals(manifestEdition, edition, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// 比较语义化版本号。
    /// <para>返回：&gt;0 表示 v1 &gt; v2；&lt;0 表示 v1 &lt; v2；0 表示相等。</para>
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

        for (int i = 0; i < maxLen; i++)
        {
            int p1 = i < parts1.Length && int.TryParse(parts1[i], out var n1) ? n1 : 0;
            int p2 = i < parts2.Length && int.TryParse(parts2[i], out var n2) ? n2 : 0;
            if (p1 != p2) return p1.CompareTo(p2);
        }
        return 0;
    }

    // ==================== 检查更新 ====================

    /// <summary>
    /// 拉取增量更新清单并做版本比对。
    /// </summary>
    /// <param name="manifestUrl">清单地址（update-manifest.json）</param>
    /// <param name="currentVersion">当前版本</param>
    /// <param name="currentEdition">当前分发形态（client / server / universal），用于拒绝不适用的差分包</param>
    /// <returns>检查结果</returns>
    public async Task<IncrementalUpdateCheckResult> CheckAsync(
        string manifestUrl, string currentVersion, string? currentEdition = null)
    {
        var result = new IncrementalUpdateCheckResult
        {
            CurrentVersion = currentVersion
        };

        if (string.IsNullOrWhiteSpace(manifestUrl))
        {
            result.Error = "未配置增量更新服务器地址";
            return result;
        }

        try
        {
            var json = await _http.GetStringAsync(manifestUrl);
            var manifest = JsonSerializer.Deserialize<IncrementalUpdateManifest>(json, JsonOpts);

            if (manifest == null || string.IsNullOrEmpty(manifest.Version))
            {
                result.Error = "更新清单解析失败或格式无效";
                return result;
            }

            // P1-1 双版本分发：差分包适用形态校验（Server 与 Client 文件集不同，防装错）
            if (!IsEditionCompatible(manifest.Edition, currentEdition))
            {
                var edition = string.IsNullOrWhiteSpace(currentEdition) ? "client" : currentEdition;
                result.Error = $"差分包适用于 {manifest.Edition} 版，当前为 {edition} 版（双版本分发形态不匹配，请获取对应版本的更新包）";
                ErrorReporter.Log($"增量更新：{result.Error}", "WARN");
                return result;
            }

            result.Manifest = manifest;
            result.LatestVersion = manifest.Version;

            var cmp = CompareVersions(manifest.Version, currentVersion);
            result.HasUpdate = cmp > 0;
            // 当前版本等于 baseVersion 时可直接应用差分包
            result.CanApplyIncremental =
                string.IsNullOrEmpty(manifest.BaseVersion)
                || CompareVersions(manifest.BaseVersion, currentVersion) == 0;

            return result;
        }
        catch (Exception ex)
        {
            result.Error = $"检查更新失败: {ex.Message}";
            ErrorReporter.Report(ex, "增量更新检查失败");
            return result;
        }
    }

    // ==================== 下载差分包 ====================

    /// <summary>
    /// 下载差分包并进行 SHA256 + RSA 数字签名双重校验。
    /// </summary>
    /// <param name="manifest">增量清单</param>
    /// <param name="progress">进度回调（0-100）</param>
    /// <returns>差分包本地路径；失败返回 null</returns>
    public async Task<string?> DownloadAsync(IncrementalUpdateManifest manifest, IProgress<int>? progress = null)
    {
        if (manifest == null || string.IsNullOrEmpty(manifest.DownloadUrl))
        {
            ErrorReporter.Log("增量更新：清单无下载地址", "WARN");
            return null;
        }

        try
        {
            progress?.Report(5);
            var packagePath = Path.Combine(_workDir, $"update_{manifest.Version}.zip");

            // 已下载且校验通过则复用
            if (File.Exists(packagePath) &&
                (string.IsNullOrEmpty(manifest.Sha256) || VerifySha256(packagePath, manifest.Sha256)))
            {
                progress?.Report(100);
                return packagePath;
            }

            using var response = await _http.GetAsync(manifest.DownloadUrl, HttpCompletionOption.ResponseHeadersRead);
            response.EnsureSuccessStatusCode();

            var totalBytes = response.Content.Headers.ContentLength ?? -1;
            long downloadedBytes = 0;

            // 下载到本地文件（显式作用域：先释放文件句柄，再进行校验/删除。
            // FileShare.None 下若句柄未释放，同进程内的重读/删除会被判定为“文件被占用”）
            {
                await using var contentStream = await response.Content.ReadAsStreamAsync();
                await using var fileStream = RetryFileOp(() =>
                    new FileStream(packagePath, FileMode.Create, FileAccess.Write, FileShare.None));
                var buffer = new byte[81920];
                int bytesRead;

                while ((bytesRead = await contentStream.ReadAsync(buffer)) > 0)
                {
                    await fileStream.WriteAsync(buffer.AsMemory(0, bytesRead));
                    downloadedBytes += bytesRead;
                    if (totalBytes > 0)
                    {
                        var pct = (int)(downloadedBytes * 90 / totalBytes) + 5;
                        progress?.Report(Math.Min(pct, 95));
                    }
                }
            }

            progress?.Report(95);

            // SHA256 完整性校验（带重试，应对杀软对新写入文件的瞬时锁）
            if (!string.IsNullOrEmpty(manifest.Sha256) &&
                !WaitUntil(() => VerifySha256(packagePath, manifest.Sha256)))
            {
                ErrorReporter.Log($"增量更新：SHA256 校验失败，已删除 {packagePath}", "ERROR");
                RetryFileOp(() => { File.Delete(packagePath); return true; });
                progress?.Report(100);
                return null;
            }

            // RSA 数字签名校验（防更新服务器劫持）
            if (!string.IsNullOrEmpty(manifest.Signature))
            {
                var sigResult = WaitUntil(() => UpdateSignatureVerifier
                    .VerifyFileSignature(packagePath, manifest.Signature).IsValid)
                    ? UpdateSignatureVerifier.VerifyFileSignature(packagePath, manifest.Signature)
                    : null;
                if (sigResult == null || !sigResult.IsValid)
                {
                    ErrorReporter.Log($"增量更新：RSA 签名验证失败 {sigResult?.Error ?? "未知"}", "ERROR");
                    RetryFileOp(() => { File.Delete(packagePath); return true; });
                    progress?.Report(100);
                    return null;
                }
                ErrorReporter.Log($"增量更新：RSA 签名验证通过 ({sigResult.Algorithm})");
            }
            else
            {
                ErrorReporter.Log("增量更新：警告 - 差分包未包含数字签名", "WARN");
            }

            progress?.Report(100);
            ErrorReporter.Log($"增量更新：差分包下载完成 {packagePath}（{downloadedBytes / 1024} KB）");
            return packagePath;
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, "增量更新下载失败");
            progress?.Report(100);
            return null;
        }
    }

    // ==================== 应用差分包 ====================

    /// <summary>
    /// 应用差分包：备份旧文件 → 替换变更文件 → 删除多余文件。
    /// </summary>
    /// <param name="packagePath">差分包路径</param>
    /// <param name="manifest">增量清单</param>
    /// <param name="appDir">应用目录（AppContext.BaseDirectory）</param>
    /// <returns>应用结果</returns>
    public IncrementalUpdateResult Apply(string packagePath, IncrementalUpdateManifest manifest, string appDir)
    {
        var result = new IncrementalUpdateResult
        {
            OldVersion = GetCurrentVersion(),
            NewVersion = manifest.Version
        };

        if (!File.Exists(packagePath))
        {
            result.Error = "差分包不存在";
            return result;
        }

        try
        {
            // 应用前最终校验（SHA256 + RSA 双重）
            var verify = UpdateSignatureVerifier.VerifyUpdatePackage(
                packagePath, manifest.Sha256, manifest.Signature);
            if (!verify.IsValid)
            {
                result.Error = $"差分包应用前验证失败: {verify.Error}";
                ErrorReporter.Log($"增量更新：应用前验证失败 {verify.Error}", "ERROR");
                return result;
            }

            // 解压到临时目录
            var extractDir = Path.Combine(_workDir, "extracted");
            if (Directory.Exists(extractDir)) Directory.Delete(extractDir, true);
            Directory.CreateDirectory(extractDir);
            RetryFileOp(() => { ZipFile.ExtractToDirectory(packagePath, extractDir, true); return true; });

            // 备份目录（支持回滚）
            var backupDir = Path.Combine(_workDir, "backup", manifest.Version);
            Directory.CreateDirectory(backupDir);

            int replaced = 0, deleted = 0;

            // 1. 替换新增 + 修改文件
            var changeFiles = new List<string>();
            changeFiles.AddRange(manifest.Added ?? new List<string>());
            changeFiles.AddRange(manifest.Modified ?? new List<string>());

            foreach (var rel in changeFiles.Distinct(StringComparer.OrdinalIgnoreCase))
            {
                if (string.IsNullOrWhiteSpace(rel)) continue;
                var src = Path.Combine(extractDir, rel);
                var dest = Path.Combine(appDir, rel);
                if (!File.Exists(src)) continue;

                // 备份旧文件
                if (File.Exists(dest))
                {
                    var bak = Path.Combine(backupDir, rel);
                    Directory.CreateDirectory(Path.GetDirectoryName(bak)!);
                    RetryFileOp(() => { File.Copy(dest, bak, true); return true; });
                }

                Directory.CreateDirectory(Path.GetDirectoryName(dest)!);
                RetryFileOp(() => { File.Copy(src, dest, true); return true; });
                replaced++;
            }

            // 2. 删除多余文件
            foreach (var rel in manifest.Deleted ?? new List<string>())
            {
                if (string.IsNullOrWhiteSpace(rel)) continue;
                var target = Path.Combine(appDir, rel);
                if (File.Exists(target))
                {
                    // 备份后删除
                    var bak = Path.Combine(backupDir, rel);
                    Directory.CreateDirectory(Path.GetDirectoryName(bak)!);
                    RetryFileOp(() => { File.Copy(target, bak, true); return true; });
                    RetryFileOp(() => { File.Delete(target); return true; });
                    deleted++;
                }
            }

            // 3. 记录版本
            try
            {
                var versionFile = Path.Combine(_workDir, "app-version.txt");
                File.WriteAllText(versionFile, manifest.Version);
            }
            catch { }

            result.Success = true;
            result.ReplacedCount = replaced;
            result.DeletedCount = deleted;
            result.BackupPath = backupDir;
            ErrorReporter.Log($"增量更新应用完成：替换 {replaced}，删除 {deleted}（备份 {backupDir}）");
            return result;
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, "增量更新应用失败");
            result.Error = $"应用失败: {ex.Message}";
            return result;
        }
    }

    /// <summary>计算当前软件版本</summary>
    private static string GetCurrentVersion()
    {
        try
        {
            return typeof(IncrementalUpdateService).Assembly.GetName().Version?.ToString() ?? "0.0.0";
        }
        catch { return "0.0.0"; }
    }

    // ==================== 文件操作重试（杀软瞬时锁防护） ====================

    /// <summary>
    /// 带异常重试的文件操作。
    /// <para>杀软/扫描器常在新写入的文件上短暂持有独占锁，导致立即重读/删除失败；
    /// 此处遇到 IOException / UnauthorizedAccessException 时等待后重试，上限约 6 秒。</para>
    /// </summary>
    private static T RetryFileOp<T>(Func<T> action, int attempts = 12, int delayMs = 500)
    {
        Exception? last = null;
        for (var i = 0; i < attempts; i++)
        {
            try { return action(); }
            catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException)
            {
                last = ex;
                Thread.Sleep(delayMs);
            }
        }
        throw last ?? new IOException("文件操作重试失败");
    }

    /// <summary>
    /// 轮询等待条件成立（用于文件校验重试：校验因瞬时锁返回失败时持续重试）。
    /// </summary>
    private static bool WaitUntil(Func<bool> condition, int attempts = 12, int delayMs = 500)
    {
        for (var i = 0; i < attempts; i++)
        {
            if (condition()) return true;
            Thread.Sleep(delayMs);
        }
        return condition();
    }

    /// <summary>验证文件 SHA256 哈希</summary>
    private static bool VerifySha256(string filePath, string expectedHash)
    {
        if (string.IsNullOrEmpty(expectedHash)) return true;
        try
        {
            using var stream = File.OpenRead(filePath);
            var hashBytes = SHA256.HashData(stream);
            var actual = Convert.ToHexString(hashBytes).ToLowerInvariant();
            return string.Equals(actual, expectedHash.ToLowerInvariant(), StringComparison.OrdinalIgnoreCase);
        }
        catch { return false; }
    }

    public void Dispose()
    {
        _http.Dispose();
    }
}
