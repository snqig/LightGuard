// © 2026 落尘（Luochen） 原创开发 - 保留所有权利

using System.Diagnostics;
using System.Text.Json;

namespace LightGuard.Core;

/// <summary>
/// 工作进程请求规格（JSON 文件传递，避免命令行参数长度限制）。
/// </summary>
public sealed class WorkerSpec
{
    /// <summary>操作名："VssBackup" 等。</summary>
    public string Op { get; set; } = "";

    /// <summary>源（VSS 备份的目录 / VHD 文件路径）。</summary>
    public string? Source { get; set; }

    /// <summary>目标目录。</summary>
    public string? Dest { get; set; }

    /// <summary>备份口令。</summary>
    public string? Password { get; set; }

    /// <summary>附加选项：VHD 挂载是否只读（VhdAttach 用）。</summary>
    public bool ReadOnly { get; set; }

    /// <summary>通用 JSON 负载（ApplyIncrementalUpdate 用：增量更新清单 JSON 序列化）。</summary>
    public string? JsonData { get; set; }
}

/// <summary>
/// 工作进程执行结果（JSON 文件回传）。
/// </summary>
public sealed class WorkerResult
{
    /// <summary>是否成功。</summary>
    public bool Success { get; set; }

    /// <summary>结果消息。</summary>
    public string Message { get; set; } = "";

    /// <summary>补充信息（如备份包路径）。</summary>
    public string? Detail { get; set; }
}

/// <summary>
/// 高权限 Worker 子进程（P0-4 权限重构方案A）。
/// <para>UI 普通权限运行，高危操作（VSS/磁盘/挂载等）经由 Worker 在管理员权限下执行：</para>
/// <list type="number">
///   <item>首选：安装/首次管理员运行时注册「最高权限计划任务」→ schtasks /run 免 UAC 自动提权（管理员用户无弹窗）。</item>
///   <item>回退：标准 runas 提权（UAC 确认弹窗）——合法权限架构，无任何绕过/隐藏技术。</item>
/// </list>
/// <para>通信：请求/结果通过 %TEMP%\LightGuard\ 下的 JSON 文件传递（请求文件执行后即删）。</para>
/// </summary>
public static class PrivilegedWorker
{
    /// <summary>免 UAC 提权计划任务名。</summary>
    public const string ElevationTaskName = "LightGuardElevation";

    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = false };

    /// <summary>工作目录（请求/结果文件所在）。</summary>
    public static string WorkDirectory
    {
        get
        {
            var dir = Path.Combine(Path.GetTempPath(), "LightGuard");
            try { Directory.CreateDirectory(dir); } catch { }
            return dir;
        }
    }

    /// <summary>当前进程是否以管理员身份运行。</summary>
    public static bool IsAdmin => AdminChecker.IsRunningAsAdmin();

    /// <summary>计划任务指向的免 UAC 提权命令。</summary>
    public static string ElevationTaskCommand => $"\"{Environment.ProcessPath}\" --worker-pending";

    // ==================== 主入口：UI 侧调用 ====================

    /// <summary>
    /// 在当前进程执行工作操作；若需管理员权限则自动提权执行（免 UAC 优先，runas 回退）。
    /// </summary>
    public static async Task<WorkerResult> RunAsync(WorkerSpec spec, int timeoutSec = 300)
    {
        ArgumentNullException.ThrowIfNull(spec);

        // 已是管理员：直接内联执行（无需子进程）
        if (IsAdmin)
            return await Task.Run(() => ExecuteWorkerOp(spec)).ConfigureAwait(false);

        var requestId = Guid.NewGuid().ToString("N");
        var dir = WorkDirectory;
        var requestFile = Path.Combine(dir, $"request_{requestId}.json");
        var resultFile = Path.Combine(dir, $"result_{requestId}.json");
        try
        {
            File.WriteAllText(requestFile, JsonSerializer.Serialize(spec, JsonOptions));

            bool started = false;
            string? startError = null;

            // 1) 计划任务通道（已注册 → 免 UAC）
            if (IsElevationTaskRegistered())
            {
                var psi = new ProcessStartInfo("schtasks.exe", $"/run /tn {ElevationTaskName}")
                {
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                };
                using var p = Process.Start(psi);
                var taskOut = p?.StandardOutput.ReadToEnd() ?? "";
                p?.WaitForExit(15000);
                started = p != null && p.ExitCode == 0;
                if (!started) startError = "计划任务运行失败（" + taskOut.Trim() + "），回退到 UAC 提权。";
            }

            // 2) runas 回退（标准 UAC，非绕过）
            if (!started)
            {
                var info = new ProcessStartInfo
                {
                    FileName = Environment.ProcessPath!,
                    Arguments = $"--worker \"{requestFile}\"",
                    UseShellExecute = true,
                    Verb = "runas"
                };
                try
                {
                    Process.Start(info);
                    started = true;
                }
                catch
                {
                    startError = "用户拒绝了提权请求，无法执行管理员操作。";
                }
            }

            if (!started)
                return new WorkerResult { Success = false, Message = startError ?? "提权失败。" };

            // 3) 轮询结果
            var deadline = DateTime.Now.AddSeconds(timeoutSec);
            while (DateTime.Now < deadline)
            {
                if (File.Exists(resultFile))
                {
                    try
                    {
                        return JsonSerializer.Deserialize<WorkerResult>(File.ReadAllText(resultFile), JsonOptions)
                               ?? new WorkerResult { Success = false, Message = "工作进程返回空结果。" };
                    }
                    catch (Exception ex)
                    {
                        return new WorkerResult { Success = false, Message = $"结果解析失败：{ex.Message}" };
                    }
                }
                await Task.Delay(500).ConfigureAwait(false);
            }

            return new WorkerResult { Success = false, Message = "工作进程超时（操作可能仍在后台执行，请检查目标目录）。" };
        }
        finally
        {
            try { if (File.Exists(requestFile)) File.Delete(requestFile); } catch { }
        }
    }

    // ==================== 工作进程侧（无界面模式） ====================

    /// <summary>
    /// 处理工作进程命令行模式。命中则执行并退出，返回 true；否则返回 false（正常启动 UI）。
    /// </summary>
    public static bool TryHandleWorkerMode(string[] args)
    {
        try
        {
            string? requestFile = null;

            if (args.Contains("--worker-pending"))
            {
                // 计划任务通道：扫描最新请求
                requestFile = Directory.EnumerateFiles(WorkDirectory, "request_*.json")
                    .OrderByDescending(f => File.GetLastWriteTimeUtc(f))
                    .FirstOrDefault();
            }
            else
            {
                var idx = Array.IndexOf(args, "--worker");
                if (idx >= 0 && idx + 1 < args.Length && File.Exists(args[idx + 1]))
                    requestFile = args[idx + 1];
            }

            if (requestFile == null) return false;

            WorkerSpec spec;
            try
            {
                spec = JsonSerializer.Deserialize<WorkerSpec>(File.ReadAllText(requestFile), JsonOptions) ?? new WorkerSpec();
            }
            catch
            {
                spec = new WorkerSpec();
            }

            var result = ExecuteWorkerOp(spec);
            var resultFile = Path.Combine(
                Path.GetDirectoryName(requestFile) ?? WorkDirectory,
                Path.GetFileName(requestFile).Replace("request_", "result_"));
            try { File.WriteAllText(resultFile, JsonSerializer.Serialize(result, JsonOptions)); } catch { }
            return true; // 工作进程执行完毕，直接退出
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// 执行工作操作（调度器）。所有异常捕获，返回结构化结果，不抛出。
    /// </summary>
    public static WorkerResult ExecuteWorkerOp(WorkerSpec spec)
    {
        if (spec == null) return new WorkerResult { Success = false, Message = "空请求。" };
        try
        {
            return spec.Op switch
            {
                "VssBackup" => RunVssBackup(spec),
                "VhdAttach" => RunVhdAttach(spec),
                "VhdDetach" => RunVhdDetach(spec),
                "ApplyIncrementalUpdate" => RunApplyIncrementalUpdate(spec),
                _ => new WorkerResult { Success = false, Message = $"未知工作操作：{spec.Op}" }
            };
        }
        catch (Exception ex)
        {
            return new WorkerResult { Success = false, Message = $"工作操作执行异常：{ex.Message}" };
        }
    }

    /// <summary>VSS 卷影备份（需管理员）。</summary>
    private static WorkerResult RunVssBackup(WorkerSpec spec)
    {
        if (string.IsNullOrWhiteSpace(spec.Source) || string.IsNullOrWhiteSpace(spec.Dest) || string.IsNullOrEmpty(spec.Password))
            return new WorkerResult { Success = false, Message = "VSS 备份参数不完整（需要源目录 / 目标目录 / 口令）。" };

        var appState = AppState.Initialize();
        using var vss = new Backup.VssShadowCopyEngine(appState);
        var manifest = vss.BackupDirectoryWithVss(spec.Source, spec.Dest, spec.Password, null);
        return manifest != null
            ? new WorkerResult
            {
                Success = true,
                Message = $"VSS 备份完成：{manifest.FileCount} 文件 / {manifest.TotalSize / 1024.0:F1} KB",
                Detail = manifest.SourcePath
            }
            : new WorkerResult { Success = false, Message = "VSS 备份失败：未生成备份清单。" };
    }

    /// <summary>挂载 VHD 虚拟磁盘（需管理员；只读默认防写宿主盘）。</summary>
    private static WorkerResult RunVhdAttach(WorkerSpec spec)
    {
        if (string.IsNullOrWhiteSpace(spec.Source))
            return new WorkerResult { Success = false, Message = "VHD 挂载参数不完整（需要 VHD 文件路径）。" };

        try
        {
            var info = Backup.VhdMountManager.Attach(spec.Source, spec.ReadOnly, assignDriveLetter: true);
            return new WorkerResult
            {
                Success = true,
                Message = $"VHD 挂载完成：{info.PhysicalPath} | 盘符 [{string.Join(", ", info.DriveLetters)}]",
                Detail = string.Join(",", info.DriveLetters)
            };
        }
        catch (Exception ex)
        {
            return new WorkerResult { Success = false, Message = $"VHD 挂载失败：{ex.Message}" };
        }
    }

    /// <summary>卸载 VHD 虚拟磁盘（需管理员）。</summary>
    private static WorkerResult RunVhdDetach(WorkerSpec spec)
    {
        if (string.IsNullOrWhiteSpace(spec.Source))
            return new WorkerResult { Success = false, Message = "VHD 卸载参数不完整（需要 VHD 文件路径）。" };

        try
        {
            Backup.VhdMountManager.Detach(spec.Source);
            return new WorkerResult { Success = true, Message = $"VHD 已卸载：{spec.Source}" };
        }
        catch (Exception ex)
        {
            return new WorkerResult { Success = false, Message = $"VHD 卸载失败：{ex.Message}" };
        }
    }

    /// <summary>
    /// 应用软件增量差分包（需对安装目录有写权限——MSI 版安装在 Program Files，普通权限不可写，经本 Worker 提权执行）。
    /// <para>Source=差分包路径，Dest=应用目录，JsonData=IncrementalUpdateManifest JSON。</para>
    /// </summary>
    private static WorkerResult RunApplyIncrementalUpdate(WorkerSpec spec)
    {
        if (string.IsNullOrWhiteSpace(spec.Source) || string.IsNullOrWhiteSpace(spec.Dest) || string.IsNullOrEmpty(spec.JsonData))
            return new WorkerResult { Success = false, Message = "增量更新应用参数不完整（需要差分包路径 / 应用目录 / 清单）。" };

        try
        {
            var manifest = System.Text.Json.JsonSerializer.Deserialize<Update.IncrementalUpdateManifest>(
                spec.JsonData, new System.Text.Json.JsonSerializerOptions
                {
                    PropertyNameCaseInsensitive = true
                });
            if (manifest == null || string.IsNullOrEmpty(manifest.Version))
                return new WorkerResult { Success = false, Message = "增量更新清单解析失败。" };

            var workDir = Path.Combine(Path.GetTempPath(), "LightGuard", "update-worker");
            Directory.CreateDirectory(workDir);
            using var service = new Update.IncrementalUpdateService(workDir);
            var result = service.Apply(spec.Source, manifest, spec.Dest);

            return result.Success
                ? new WorkerResult
                {
                    Success = true,
                    Message = $"增量更新应用完成：替换 {result.ReplacedCount}，删除 {result.DeletedCount}",
                    Detail = result.BackupPath
                }
                : new WorkerResult { Success = false, Message = $"增量更新应用失败：{result.Error}" };
        }
        catch (Exception ex)
        {
            return new WorkerResult { Success = false, Message = $"增量更新应用异常：{ex.Message}" };
        }
    }

    // ==================== 计划任务注册 ====================

    /// <summary>查询免 UAC 提权任务是否已注册。</summary>
    public static bool IsElevationTaskRegistered()
    {
        try
        {
            var psi = new ProcessStartInfo("schtasks.exe", $"/query /tn {ElevationTaskName}")
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };
            using var p = Process.Start(psi);
            _ = p?.StandardOutput.ReadToEnd();
            p?.WaitForExit(10000);
            return p != null && p.ExitCode == 0;
        }
        catch { return false; }
    }

    /// <summary>
    /// 注册免 UAC 提权计划任务（需管理员权限；安装 / 首次管理员运行时调用）。
    /// 任务以最高权限运行本程序（--worker-pending 模式），此后 schtasks /run 无需 UAC 弹窗。
    /// </summary>
    public static bool EnsureElevationTaskRegistered()
    {
        if (!IsAdmin) return false;
        if (IsElevationTaskRegistered()) return true;

        try
        {
            var args = $"/create /tn {ElevationTaskName} /tr \"{ElevationTaskCommand}\" " +
                       "/sc once /st 00:00 /rl highest /f";
            var psi = new ProcessStartInfo("schtasks.exe", args)
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };
            using var p = Process.Start(psi);
            var output = p?.StandardOutput.ReadToEnd() ?? "";
            p?.WaitForExit(15000);
            var ok = p != null && p.ExitCode == 0;
            if (!ok) ErrorReporter.Log($"免 UAC 提权任务注册失败：{output.Trim()}", "WARN");
            return ok;
        }
        catch (Exception ex)
        {
            ErrorReporter.Log($"免 UAC 提权任务注册异常：{ex.Message}", "WARN");
            return false;
        }
    }

    /// <summary>
    /// 注销免 UAC 提权计划任务（需管理员权限；MSI 卸载时调用）。
    /// 任务不存在时视为成功（幂等），保证卸载不残留任务项。
    /// </summary>
    public static bool UnregisterElevationTask()
    {
        if (!IsAdmin) return false;
        if (!IsElevationTaskRegistered()) return true; // 未注册视为已清理（幂等）

        try
        {
            var psi = new ProcessStartInfo("schtasks.exe", $"/delete /tn {ElevationTaskName} /f")
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };
            using var p = Process.Start(psi);
            var output = p?.StandardOutput.ReadToEnd() ?? "";
            p?.WaitForExit(15000);
            var ok = p != null && p.ExitCode == 0;
            if (!ok) ErrorReporter.Log($"免 UAC 提权任务注销失败：{output.Trim()}", "WARN");
            return ok;
        }
        catch (Exception ex)
        {
            ErrorReporter.Log($"免 UAC 提权任务注销异常：{ex.Message}", "WARN");
            return false;
        }
    }
}
