// © 2026 落尘（Luochen） 原创开发 - 保留所有权利

using System.Net;
using System.Security.Cryptography;
using LightGuard.Security;
using LightGuard.Update;

namespace IncrementalUpdateTest;

/// <summary>
/// 增量更新端到端测试客户端。
/// <para>模拟 LightGuard 客户端从 v3.0.0 升级到 v3.1.0：</para>
/// <list type="number">
///   <item>CheckAsync：拉取 update-manifest.json 并做版本比对</item>
///   <item>DownloadAsync：下载差分包 + SHA256/RSA 校验</item>
///   <item>Apply：备份旧文件 → 替换变更 → 删除多余文件</item>
///   <item>安全补充：篡改拦截 + RSA 签名验证（测试密钥对）</item>
/// </list>
/// 用法：
///   IncrementalUpdateTest &lt;manifestUrl&gt; &lt;appDir&gt; &lt;workDir&gt; &lt;expectedVersion&gt; [serverDir] [port]
/// 当提供 serverDir 时，客户端在自身进程内启动 HTTP 服务器（避免 PowerShell
/// 后台任务承载 HttpListener 不响应请求的问题），manifestUrl 由端口自动拼接。
/// </summary>
internal static class Program
{
    private static int _passed;
    private static int _failed;

    private static void Assert(bool condition, string name)
    {
        if (condition)
        {
            _passed++;
            Console.WriteLine($"  [PASS] {name}");
        }
        else
        {
            _failed++;
            Console.WriteLine($"  [FAIL] {name}");
        }
    }

    private static async Task<int> Main(string[] args)
    {
        Console.WriteLine("==============================================");
        Console.WriteLine(" LightGuard 增量更新端到端测试（v3.0.0 → v3.1.0）");
        Console.WriteLine("==============================================");

        if (args.Length < 4)
        {
            Console.WriteLine("用法: IncrementalUpdateTest <manifestUrl> <appDir> <workDir> <expectedVersion> [serverDir] [port]");
            return 2;
        }

        var manifestUrl = args[0];
        var appDir = args[1];
        var workDir = args[2];
        var expectedVersion = args[3];
        var serverDir = args.Length > 4 ? args[4] : "";
        var port = args.Length > 5 && int.TryParse(args[5], out var p) ? p : 0;

        // ==================== 0. 自托管测试 HTTP 服务器 ====================
        HttpListener? listener = null;
        if (!string.IsNullOrEmpty(serverDir))
        {
            if (port <= 0)
            {
                Console.WriteLine("  [FAIL] 提供 serverDir 时必须同时提供端口");
                return 2;
            }

            listener = new HttpListener();
            listener.Prefixes.Add($"http://127.0.0.1:{port}/");
            listener.Start();
            _ = Task.Run(() => ServeLoop(listener, serverDir));
            manifestUrl = $"http://127.0.0.1:{port}/update-manifest.json";
            Console.WriteLine($"\n[0/4] 自托管测试服务器已启动: http://127.0.0.1:{port}/ （目录 {serverDir}）");

            // 自检：确认服务器确实可响应（避免静默超时）
            try
            {
                using var probe = new HttpClient { Timeout = TimeSpan.FromSeconds(10) };
                var probeJson = await probe.GetStringAsync(manifestUrl);
                Console.WriteLine($"  服务器自检通过（清单 {probeJson.Length} 字节）");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"  [FAIL] 服务器自检失败: {ex.Message}");
                return 1;
            }
        }

        try
        {
            using var service = new IncrementalUpdateService(workDir);

            // ==================== 1. 检查更新（版本比对） ====================
            Console.WriteLine("\n[1/4] 检查更新（版本比对）");
            var check = await service.CheckAsync(manifestUrl, "3.0.0");

            if (check.Error != null)
            {
                Console.WriteLine($"  [FAIL] 检查更新报错: {check.Error}");
                return 1;
            }
            Assert(check.HasUpdate, $"检测到新版本（当前 3.0.0，最新 {check.LatestVersion}）");
            Assert(check.LatestVersion == expectedVersion, $"最新版本为 {expectedVersion}（实际 {check.LatestVersion}）");
            Assert(check.CanApplyIncremental, "可应用增量差分包（当前版本 == baseVersion）");

            var manifest = check.Manifest!;
            Console.WriteLine($"  清单: {manifest.Version} (base {manifest.BaseVersion}) | " +
                              $"新增 {manifest.Added.Count} / 修改 {manifest.Modified.Count} / 删除 {manifest.Deleted.Count}");
            Assert(manifest.Added.Count > 0, "清单含新增文件");
            Assert(manifest.Deleted.Count > 0, "清单含删除文件");
            Assert(!string.IsNullOrEmpty(manifest.Sha256), "清单含 SHA256");

            // ==================== 2. 下载差分包 ====================
            Console.WriteLine("\n[2/4] 下载差分包（SHA256 校验）");
            var packagePath = await service.DownloadAsync(manifest);
            Assert(packagePath != null, "差分包下载成功");
            if (packagePath == null)
            {
                Console.WriteLine("  差分包下载失败，请查看 %APPDATA%\\LightGuard\\logs 中的错误日志");
                return 1;
            }

            var actualHash = RetryFile(() => ComputeSha256(packagePath));
            Assert(string.Equals(actualHash, manifest.Sha256, StringComparison.OrdinalIgnoreCase),
                $"SHA256 校验通过（{actualHash[..16]}…）");
            Console.WriteLine($"  差分包: {packagePath}");

            // ==================== 3. 应用差分包 ====================
            Console.WriteLine("\n[3/4] 应用差分包");
            var result = service.Apply(packagePath, manifest, appDir);

            Assert(result.Success, "应用成功");
            if (result.Success)
            {
                Assert(result.ReplacedCount == manifest.Added.Count + manifest.Modified.Count,
                    $"替换文件数正确（{result.ReplacedCount} = 新增 {manifest.Added.Count} + 修改 {manifest.Modified.Count}）");
                Assert(result.DeletedCount == manifest.Deleted.Count,
                    $"删除文件数正确（{result.DeletedCount} = {manifest.Deleted.Count}）");
                Console.WriteLine($"  备份目录: {result.BackupPath}");
            }
            else
            {
                Console.WriteLine($"  应用失败: {result.Error}");
            }

            // ==================== 4. 安全校验补充 ====================
            Console.WriteLine("\n[4/4] 安全校验补充（篡改拦截 + RSA 签名验证）");

            // 4a. 篡改检测：翻转 1 字节后 SHA256 必须失败
            var tamperedPath = Path.Combine(workDir, "update_tampered.zip");
            RetryFile(() => { File.Copy(packagePath, tamperedPath, true); return true; });
            RetryFile(() =>
            {
                using var fs = new FileStream(tamperedPath, FileMode.Open, FileAccess.ReadWrite);
                var b = fs.ReadByte();
                fs.Position = 0;
                fs.WriteByte((byte)(b ^ 0xFF));
                return true;
            });
            var tamperedCheck = RetryFile(() =>
                UpdateSignatureVerifier.VerifyUpdatePackage(tamperedPath, manifest.Sha256, ""));
            Assert(!tamperedCheck.IsValid, "篡改差分包被 SHA256 校验拦截");
            RetryFile(() => { File.Delete(tamperedPath); return true; });

            // 4b. RSA 签名验证（测试密钥对，与生产同路径的 VerifyFileSignature）
            var (pubXml, privXml) = UpdateSignatureVerifier.GenerateTestKeyPair();
            var sig = RetryFile(() => UpdateSignatureVerifier.SignFile(packagePath, privXml));
            SignatureVerifyResult? sigOk = null;
            for (var i = 0; i < 12; i++)
            {
                sigOk = UpdateSignatureVerifier.VerifyFileSignature(packagePath, sig, pubXml);
                if (sigOk.IsValid) break;
                Thread.Sleep(500);
            }
            Assert(sigOk is { IsValid: true }, $"RSA 签名验证通过（{sigOk?.Algorithm}）");

            Console.WriteLine($"\n==============================================");
            Console.WriteLine($" 结果: {_passed} 通过 / {_failed} 失败");
            Console.WriteLine($"==============================================");
            return _failed == 0 ? 0 : 1;
        }
        finally
        {
            if (listener != null)
            {
                listener.Stop();
                listener.Close();
            }
        }
    }

    /// <summary>
    /// 极简静态文件 HTTP 服务器循环（仅服务测试目录内文件）。
    /// </summary>
    private static async Task ServeLoop(HttpListener listener, string baseDir)
    {
        var root = Path.GetFullPath(baseDir);
        while (listener.IsListening)
        {
            HttpListenerContext ctx;
            try
            {
                ctx = await listener.GetContextAsync();
            }
            catch
            {
                break; // 监听器已停止
            }

            try
            {
                var rel = ctx.Request.Url!.AbsolutePath.TrimStart('/').Replace('/', Path.DirectorySeparatorChar);
                var full = Path.GetFullPath(Path.Combine(baseDir, rel));

                // 防目录穿越：完整路径必须位于服务根目录内
                if (!full.StartsWith(root, StringComparison.OrdinalIgnoreCase) || !File.Exists(full))
                {
                    ctx.Response.StatusCode = 404;
                }
                else
                {
                    var bytes = await File.ReadAllBytesAsync(full);
                    ctx.Response.ContentType = "application/octet-stream";
                    ctx.Response.ContentLength64 = bytes.Length;
                    await ctx.Response.OutputStream.WriteAsync(bytes.AsMemory());
                }
            }
            catch
            {
                try { ctx.Response.StatusCode = 500; } catch { }
            }
            finally
            {
                try { ctx.Response.Close(); } catch { }
            }
        }
    }

    /// <summary>
    /// 带重试的文件操作（本机杀软/扫描器会对新写入文件短暂持有独占锁，
    /// 立即重读/删除会偶发失败；重试上限约 6 秒）。
    /// </summary>
    private static T RetryFile<T>(Func<T> action, int attempts = 12)
    {
        for (var i = 0; i < attempts; i++)
        {
            try { return action(); }
            catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException)
            {
                Thread.Sleep(500);
            }
        }
        throw new IOException("文件操作重试失败");
    }

    private static string ComputeSha256(string path)
    {
        using var stream = File.OpenRead(path);
        var bytes = SHA256.HashData(stream);
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }
}
