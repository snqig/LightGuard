using System.Diagnostics;
using System.Text;
using LightGuard.Core;

namespace LightGuard.Decryption;

/// <summary>
/// 勒索软件解密引擎
/// 负责协调家族检测、工具下载、备份、解密执行和结果汇总
/// 解密工具为外部可执行文件，本引擎仅负责调度和结果解析
/// </summary>
public sealed class RansomwareDecryptor : IDisposable
{
    /// <summary>文件操作之间的节流间隔（毫秒），降低启发式风险（P0-2 要求）</summary>
    private const int ThrottleMs = 300;

    /// <summary>解密工具执行超时（秒）</summary>
    private const int ToolTimeoutSeconds = 120;

    private readonly RansomwareFamilyDetector _detector;
    private readonly DecryptionToolManager _toolManager;

    /// <summary>解密进度变更事件（UI 订阅）</summary>
    public event Action<DecryptionProgress>? ProgressChanged;

    /// <summary>解密历史记录文件路径</summary>
    private readonly string _historyPath;

    /// <summary>
    /// 构造函数
    /// </summary>
    /// <param name="toolManager">解密工具管理器（可传入共享实例，否则内部创建）</param>
    public RansomwareDecryptor(DecryptionToolManager? toolManager = null)
    {
        _detector = new RansomwareFamilyDetector();
        _toolManager = toolManager ?? new DecryptionToolManager();
        _historyPath = Path.Combine(ConfigManager.GetDataDir(), "decryption_history.json");
    }

    #region 单文件解密

    /// <summary>
    /// 解密单个文件
    /// 流程：检测家族 -> 检查/下载工具 -> 备份 -> 执行解密 -> 解析结果
    /// </summary>
    /// <param name="filePath">加密文件路径</param>
    /// <param name="ct">取消令牌</param>
    /// <returns>解密结果</returns>
    public async Task<DecryptionResult> DecryptFileAsync(string filePath, CancellationToken ct = default)
    {
        var sw = Stopwatch.StartNew();
        var result = new DecryptionResult { TotalFiles = 1 };

        try
        {
            // 1. 检测勒索家族
            ReportProgress(new DecryptionProgress
            {
                IsRunning = true,
                CurrentFile = filePath,
                FilesProcessed = 0,
                TotalFiles = 1
            });

            var family = _detector.DetectFamily(filePath);
            result.Family = family;

            if (family == RansomwareFamily.Unknown)
            {
                result.Success = false;
                result.FailureReason = DecryptionFailureReason.UnknownFamily;
                result.ErrorMessage = "无法识别该文件的勒索家族，请尝试手动选择家族。";
                sw.Stop();
                result.Duration = sw.Elapsed;
                return result;
            }

            ct.ThrowIfCancellationRequested();

            // 2. 获取家族信息并检查解密器可用性
            var familyInfo = _detector.GetFamilyInfo(family);
            if (familyInfo == null || !familyInfo.HasDecryptor)
            {
                result.Success = false;
                result.FailureReason = DecryptionFailureReason.NoDecryptorAvailable;
                result.ErrorMessage = $"{familyInfo?.Name ?? family.ToString()} 家族暂无可用解密器。";
                sw.Stop();
                result.Duration = sw.Elapsed;
                return result;
            }

            ct.ThrowIfCancellationRequested();

            // 3. 检查工具是否已下载，否则下载
            var toolPath = _toolManager.GetToolPath(family);
            if (!_toolManager.IsToolAvailable(family))
            {
                ReportProgress(new DecryptionProgress
                {
                    IsRunning = true,
                    CurrentFile = filePath,
                    PercentComplete = 10,
                    FilesProcessed = 0,
                    TotalFiles = 1
                });

                toolPath = await _toolManager.DownloadToolAsync(familyInfo);
                if (string.IsNullOrEmpty(toolPath) || !File.Exists(toolPath))
                {
                    result.Success = false;
                    result.FailureReason = DecryptionFailureReason.ToolDownloadFailed;
                    result.ErrorMessage = $"解密工具下载失败：{familyInfo.Name}";
                    sw.Stop();
                    result.Duration = sw.Elapsed;
                    return result;
                }
            }

            ct.ThrowIfCancellationRequested();

            // 4. 创建备份
            var backupPath = CreatePreDecryptionBackup(filePath);
            if (string.IsNullOrEmpty(backupPath))
            {
                result.Success = false;
                result.FailureReason = DecryptionFailureReason.BackupFailed;
                result.ErrorMessage = "解密前备份失败，已中止解密以保护原始文件。";
                sw.Stop();
                result.Duration = sw.Elapsed;
                return result;
            }
            result.BackupPath = backupPath;

            // 节流：文件操作间隔（P0-2 要求，降低启发式风险）
            Thread.Sleep(ThrottleMs);

            ct.ThrowIfCancellationRequested();

            // 5. 执行解密工具
            ReportProgress(new DecryptionProgress
            {
                IsRunning = true,
                CurrentFile = filePath,
                PercentComplete = 50,
                FilesProcessed = 0,
                TotalFiles = 1
            });

            var toolOutput = await ExecuteDecryptionToolAsync(toolPath, filePath, ct);

            // 6. 解析工具输出判断成功/失败
            var success = ParseToolResult(toolOutput, filePath, familyInfo);

            if (success)
            {
                result.Success = true;
                result.DecryptedFiles = 1;
                result.DecryptedFilesList.Add(filePath);
            }
            else
            {
                result.Success = false;
                result.FailedFiles = 1;
                result.FailureReason = DetectFailureReason(toolOutput, filePath);
                result.ErrorMessage = $"解密工具执行未成功。工具输出: {toolOutput.Stderr}";
            }

            sw.Stop();
            result.Duration = sw.Elapsed;

            ReportProgress(new DecryptionProgress
            {
                IsRunning = false,
                CurrentFile = filePath,
                PercentComplete = 100,
                FilesProcessed = 1,
                TotalFiles = 1,
                DecryptedCount = result.DecryptedFiles,
                FailedCount = result.FailedFiles
            });

            // 记录历史
            RecordHistory(result);

            return result;
        }
        catch (OperationCanceledException)
        {
            sw.Stop();
            result.Duration = sw.Elapsed;
            result.Success = false;
            result.ErrorMessage = "解密操作已取消。";
            result.SkippedFiles = 1;
            ReportProgress(new DecryptionProgress { IsRunning = false });
            return result;
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, $"解密文件异常: {filePath}");
            sw.Stop();
            result.Duration = sw.Elapsed;
            result.Success = false;
            result.FailedFiles = 1;
            result.ErrorMessage = $"解密异常: {ex.Message}";
            result.FailureReason = DecryptionFailureReason.ToolExecutionFailed;
            ReportProgress(new DecryptionProgress { IsRunning = false });
            return result;
        }
    }

    #endregion

    #region 批量目录解密

    /// <summary>
    /// 批量解密目录中的所有加密文件
    /// 流程：扫描目录 -> 检测家族 -> 下载工具 -> 批量备份 -> 逐文件解密 -> 汇总
    /// </summary>
    /// <param name="dirPath">目录路径</param>
    /// <param name="ct">取消令牌</param>
    /// <returns>汇总解密结果</returns>
    public async Task<DecryptionResult> DecryptDirectoryAsync(string dirPath, CancellationToken ct = default)
    {
        var sw = Stopwatch.StartNew();
        var result = new DecryptionResult();

        try
        {
            if (!Directory.Exists(dirPath))
            {
                result.Success = false;
                result.ErrorMessage = "目录不存在。";
                result.FailureReason = DecryptionFailureReason.UnknownFamily;
                sw.Stop();
                result.Duration = sw.Elapsed;
                return result;
            }

            // 1. 扫描目录中的文件，检测家族
            ReportProgress(new DecryptionProgress
            {
                IsRunning = true,
                CurrentFile = "正在扫描目录...",
                FilesProcessed = 0,
                TotalFiles = 0
            });

            var allFiles = Directory.EnumerateFiles(dirPath, "*.*", SearchOption.AllDirectories).ToList();

            // 2. 从第一个匹配的文件检测家族
            RansomwareFamily detectedFamily = RansomwareFamily.Unknown;
            string? firstMatchFile = null;

            foreach (var file in allFiles)
            {
                var family = _detector.DetectFamily(file);
                if (family != RansomwareFamily.Unknown)
                {
                    detectedFamily = family;
                    firstMatchFile = file;
                    break;
                }
            }

            if (detectedFamily == RansomwareFamily.Unknown || firstMatchFile == null)
            {
                result.Success = false;
                result.FailureReason = DecryptionFailureReason.UnknownFamily;
                result.ErrorMessage = "目录中未检测到已知勒索家族的加密文件。";
                sw.Stop();
                result.Duration = sw.Elapsed;
                ReportProgress(new DecryptionProgress { IsRunning = false });
                return result;
            }

            result.Family = detectedFamily;
            var familyInfo = _detector.GetFamilyInfo(detectedFamily);

            if (familyInfo == null || !familyInfo.HasDecryptor)
            {
                result.Success = false;
                result.FailureReason = DecryptionFailureReason.NoDecryptorAvailable;
                result.ErrorMessage = $"{familyInfo?.Name ?? detectedFamily.ToString()} 家族暂无可用解密器。";
                sw.Stop();
                result.Duration = sw.Elapsed;
                ReportProgress(new DecryptionProgress { IsRunning = false });
                return result;
            }

            ct.ThrowIfCancellationRequested();

            // 3. 筛选匹配该家族扩展名的文件
            var targetFiles = FilterFilesByFamily(allFiles, familyInfo);
            result.TotalFiles = targetFiles.Count;

            if (targetFiles.Count == 0)
            {
                result.Success = false;
                result.ErrorMessage = "目录中没有匹配该家族扩展名的文件。";
                sw.Stop();
                result.Duration = sw.Elapsed;
                ReportProgress(new DecryptionProgress { IsRunning = false });
                return result;
            }

            // 4. 下载/验证工具（仅一次）
            var toolPath = _toolManager.GetToolPath(detectedFamily);
            if (!_toolManager.IsToolAvailable(detectedFamily))
            {
                ReportProgress(new DecryptionProgress
                {
                    IsRunning = true,
                    CurrentFile = "正在下载解密工具...",
                    PercentComplete = 5,
                    TotalFiles = targetFiles.Count
                });

                toolPath = await _toolManager.DownloadToolAsync(familyInfo);
                if (string.IsNullOrEmpty(toolPath) || !File.Exists(toolPath))
                {
                    result.Success = false;
                    result.FailureReason = DecryptionFailureReason.ToolDownloadFailed;
                    result.ErrorMessage = "解密工具下载失败。";
                    sw.Stop();
                    result.Duration = sw.Elapsed;
                    ReportProgress(new DecryptionProgress { IsRunning = false });
                    return result;
                }
            }

            ct.ThrowIfCancellationRequested();

            // 5. 创建备份目录
            var backupDir = CreatePreDecryptionBackupDirectory(dirPath);
            result.BackupPath = backupDir;

            // 6. 逐文件处理
            int processed = 0;
            int decrypted = 0;
            int failed = 0;
            int skipped = 0;

            foreach (var file in targetFiles)
            {
                ct.ThrowIfCancellationRequested();

                var percent = (double)processed / targetFiles.Count * 100;
                ReportProgress(new DecryptionProgress
                {
                    IsRunning = true,
                    CurrentFile = file,
                    PercentComplete = percent,
                    FilesProcessed = processed,
                    TotalFiles = targetFiles.Count,
                    DecryptedCount = decrypted,
                    FailedCount = failed
                });

                try
                {
                    // 检查文件是否已被解密（不再有加密扩展名）
                    if (IsAlreadyDecrypted(file, familyInfo))
                    {
                        skipped++;
                        processed++;
                        continue;
                    }

                    // 检查磁盘空间
                    if (!CheckDiskSpace(file))
                    {
                        result.FailureReason = DecryptionFailureReason.InsufficientDiskSpace;
                        result.ErrorMessage = "磁盘空间不足，无法继续解密。";
                        failed++;
                        processed++;
                        break;
                    }

                    // 执行解密工具
                    var toolOutput = await ExecuteDecryptionToolAsync(toolPath, file, ct);
                    var success = ParseToolResult(toolOutput, file, familyInfo);

                    if (success)
                    {
                        decrypted++;
                        result.DecryptedFilesList.Add(file);
                    }
                    else
                    {
                        failed++;
                        ErrorReporter.Log($"[解密] 文件解密失败: {file} | 输出: {toolOutput.Stderr}", "WARN");
                    }
                }
                catch (UnauthorizedAccessException)
                {
                    failed++;
                    result.FailureReason = DecryptionFailureReason.FileAccessDenied;
                    ErrorReporter.Log($"[解密] 文件访问被拒绝: {file}", "WARN");
                }
                catch (OperationCanceledException)
                {
                    throw;
                }
                catch (Exception ex)
                {
                    failed++;
                    ErrorReporter.Report(ex, $"解密文件异常: {file}");
                }

                processed++;

                // 节流：文件操作间隔（P0-2 要求，降低启发式风险）
                Thread.Sleep(ThrottleMs);
            }

            // 7. 汇总结果
            result.DecryptedFiles = decrypted;
            result.FailedFiles = failed;
            result.SkippedFiles = skipped;
            result.Success = failed == 0 || decrypted > 0;
            if (failed > 0 && decrypted == 0 && result.FailureReason == DecryptionFailureReason.UnknownFamily)
            {
                result.FailureReason = DecryptionFailureReason.ToolExecutionFailed;
                result.ErrorMessage = "所有文件解密均失败。";
            }

            sw.Stop();
            result.Duration = sw.Elapsed;

            ReportProgress(new DecryptionProgress
            {
                IsRunning = false,
                PercentComplete = 100,
                FilesProcessed = processed,
                TotalFiles = targetFiles.Count,
                DecryptedCount = decrypted,
                FailedCount = failed
            });

            // 记录历史
            RecordHistory(result);

            return result;
        }
        catch (OperationCanceledException)
        {
            sw.Stop();
            result.Duration = sw.Elapsed;
            result.Success = false;
            result.ErrorMessage = "解密操作已取消。";
            ReportProgress(new DecryptionProgress { IsRunning = false });
            return result;
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, $"批量解密目录异常: {dirPath}");
            sw.Stop();
            result.Duration = sw.Elapsed;
            result.Success = false;
            result.ErrorMessage = $"批量解密异常: {ex.Message}";
            result.FailureReason = DecryptionFailureReason.ToolExecutionFailed;
            ReportProgress(new DecryptionProgress { IsRunning = false });
            return result;
        }
    }

    #endregion

    #region 备份

    /// <summary>
    /// 解密前备份单个文件（复制为 .bak）
    /// </summary>
    /// <param name="filePath">原始文件路径</param>
    /// <returns>备份文件路径；失败返回空字符串</returns>
    public string CreatePreDecryptionBackup(string filePath)
    {
        try
        {
            if (!File.Exists(filePath))
            {
                ErrorReporter.Log($"[解密备份] 源文件不存在: {filePath}", "WARN");
                return "";
            }

            var backupPath = filePath + ".bak";

            // 如果备份已存在，添加时间戳避免覆盖
            if (File.Exists(backupPath))
            {
                var timestamp = DateTime.Now.ToString("yyyyMMddHHmmss");
                backupPath = $"{filePath}.{timestamp}.bak";
            }

            File.Copy(filePath, backupPath, overwrite: false);
            ErrorReporter.Log($"[解密备份] 已备份: {filePath} -> {backupPath}");
            return backupPath;
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, $"创建解密前备份失败: {filePath}");
            return "";
        }
    }

    /// <summary>
    /// 解密前备份整个目录（复制到带时间戳的备份目录）
    /// </summary>
    /// <param name="dirPath">源目录路径</param>
    /// <returns>备份目录路径；失败返回空字符串</returns>
    public string CreatePreDecryptionBackupDirectory(string dirPath)
    {
        try
        {
            if (!Directory.Exists(dirPath))
            {
                ErrorReporter.Log($"[解密备份] 源目录不存在: {dirPath}", "WARN");
                return "";
            }

            var dirName = Path.GetFileName(dirPath.TrimEnd('\\'));
            if (string.IsNullOrEmpty(dirName)) dirName = "root";

            var timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
            var backupRoot = Path.Combine(ConfigManager.GetBackupDir(), "decryption_backup");
            Directory.CreateDirectory(backupRoot);

            var backupDir = Path.Combine(backupRoot, $"{dirName}_{timestamp}");

            // 递归复制目录
            CopyDirectory(dirPath, backupDir);

            ErrorReporter.Log($"[解密备份] 目录已备份: {dirPath} -> {backupDir}");
            return backupDir;
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, $"创建解密前目录备份失败: {dirPath}");
            return "";
        }
    }

    /// <summary>递归复制目录</summary>
    private static void CopyDirectory(string sourceDir, string destDir)
    {
        Directory.CreateDirectory(destDir);

        // 复制文件
        foreach (var file in Directory.EnumerateFiles(sourceDir))
        {
            var destFile = Path.Combine(destDir, Path.GetFileName(file));
            File.Copy(file, destFile, overwrite: true);
        }

        // 递归复制子目录
        foreach (var dir in Directory.EnumerateDirectories(sourceDir))
        {
            var destSubDir = Path.Combine(destDir, Path.GetFileName(dir));
            CopyDirectory(dir, destSubDir);
        }
    }

    #endregion

    #region 工具执行

    /// <summary>
    /// 执行解密工具（通过 Process 启动外部可执行文件）
    /// </summary>
    /// <param name="toolPath">解密工具路径</param>
    /// <param name="targetFile">目标加密文件</param>
    /// <param name="ct">取消令牌</param>
    /// <returns>工具的标准输出和标准错误</returns>
    public async Task<ToolOutput> ExecuteDecryptionToolAsync(string toolPath, string targetFile, CancellationToken ct = default)
    {
        var output = new ToolOutput();

        try
        {
            if (!File.Exists(toolPath))
            {
                output.Stderr = $"解密工具不存在: {toolPath}";
                ErrorReporter.Log($"[解密执行] 工具不存在: {toolPath}", "ERROR");
                return output;
            }

            // 构建命令行参数（通用格式，不同工具可能需要适配）
            var args = BuildToolArguments(toolPath, targetFile);

            var psi = new ProcessStartInfo
            {
                FileName = toolPath,
                Arguments = args,
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                StandardOutputEncoding = Encoding.UTF8,
                StandardErrorEncoding = Encoding.UTF8,
                WorkingDirectory = Path.GetDirectoryName(toolPath) ?? ""
            };

            ErrorReporter.Log($"[解密执行] 启动工具: {toolPath} {args}");

            using var process = new Process { StartInfo = psi };
            process.Start();

            // 注册取消令牌：取消时杀死进程
            await using var ctRegistration = ct.Register(() =>
            {
                try
                {
                    if (!process.HasExited)
                        process.Kill(entireProcessTree: true);
                }
                catch { }
            });

            // 异步读取输出避免死锁
            var stdoutTask = process.StandardOutput.ReadToEndAsync();
            var stderrTask = process.StandardError.ReadToEndAsync();

            var exited = process.WaitForExit(ToolTimeoutSeconds * 1000);
            if (!exited)
            {
                try { process.Kill(entireProcessTree: true); } catch { }
                output.Stderr = $"解密工具执行超时（{ToolTimeoutSeconds}秒），已终止。";
                ErrorReporter.Log($"[解密执行] 工具执行超时: {toolPath}", "WARN");
                return output;
            }

            output.Stdout = await stdoutTask;
            output.Stderr = await stderrTask;
            output.ExitCode = process.ExitCode;

            ErrorReporter.Log($"[解密执行] 工具退出码={process.ExitCode} | Stdout长度={output.Stdout.Length} | Stderr长度={output.Stderr.Length}");

            return output;
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, $"执行解密工具异常: {toolPath}");
            output.Stderr = $"执行异常: {ex.Message}";
            return output;
        }
    }

    /// <summary>
    /// 根据工具文件名构建命令行参数
    /// 不同解密工具的命令行格式可能不同，这里提供通用适配
    /// </summary>
    private static string BuildToolArguments(string toolPath, string targetFile)
    {
        var toolName = Path.GetFileNameWithoutExtension(toolPath).ToLowerInvariant();

        // 根据已知工具名适配参数格式
        return toolName switch
        {
            "wanakidecryptor" => $"\"{targetFile}\"",          // WanakiDecryptor: 直接传入文件
            "gandcrabdecryptor" => $"-d \"{targetFile}\"",     // GandCrabDecryptor: -d 解密
            "stopdecryptor" => $"\"{targetFile}\"",            // STOPDecryptor: 直接传入文件
            _ => $"\"{targetFile}\""                            // 默认：直接传入文件路径
        };
    }

    /// <summary>
    /// 解析工具输出判断解密是否成功
    /// </summary>
    private bool ParseToolResult(ToolOutput output, string filePath, RansomwareFamilyInfo familyInfo)
    {
        // 退出码为 0 通常表示成功
        if (output.ExitCode == 0)
        {
            // 检查输出中是否包含成功关键词
            var combined = (output.Stdout + " " + output.Stderr).ToLowerInvariant();

            // 成功关键词
            var successKeywords = new[] { "success", "decrypted", "完成", "成功", "recovered", "restored" };
            if (successKeywords.Any(k => combined.Contains(k)))
                return true;

            // 无明显错误关键词且退出码为 0，视为成功
            var errorKeywords = new[] { "error", "failed", "失败", "错误", "cannot", "unable" };
            if (!errorKeywords.Any(k => combined.Contains(k)))
                return true;
        }

        return false;
    }

    /// <summary>
    /// 从工具输出推断失败原因
    /// </summary>
    private DecryptionFailureReason DetectFailureReason(ToolOutput output, string filePath)
    {
        var combined = (output.Stdout + " " + output.Stderr).ToLowerInvariant();

        if (combined.Contains("access denied") || combined.Contains("permission"))
            return DecryptionFailureReason.FileAccessDenied;

        if (combined.Contains("disk space") || combined.Contains("no space"))
            return DecryptionFailureReason.InsufficientDiskSpace;

        if (combined.Contains("already") || combined.Contains("decrypted"))
            return DecryptionFailureReason.AlreadyDecrypted;

        return DecryptionFailureReason.ToolExecutionFailed;
    }

    #endregion

    #region 辅助方法

    /// <summary>根据家族信息筛选目录中匹配扩展名的文件</summary>
    private List<string> FilterFilesByFamily(List<string> allFiles, RansomwareFamilyInfo familyInfo)
    {
        var result = new List<string>();
        var extensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        // 收集该家族的所有扩展名
        if (!string.IsNullOrEmpty(familyInfo.Extension))
            extensions.Add(familyInfo.Extension);

        foreach (var pattern in familyInfo.DetectionPatterns)
        {
            // *.wcry -> .wcry
            if (pattern.StartsWith("*."))
                extensions.Add(pattern.Substring(1));
        }

        foreach (var file in allFiles)
        {
            var ext = Path.GetExtension(file);
            if (extensions.Contains(ext))
            {
                result.Add(file);
            }
            else
            {
                // 扩展名不匹配时，也通过检测器确认
                var family = _detector.DetectFamilyByExtension(ext);
                if (family == familyInfo.Family)
                    result.Add(file);
            }
        }

        return result;
    }

    /// <summary>检查文件是否已被解密（不再有加密扩展名）</summary>
    private bool IsAlreadyDecrypted(string filePath, RansomwareFamilyInfo familyInfo)
    {
        var ext = Path.GetExtension(filePath).ToLowerInvariant();
        var familyExt = familyInfo.Extension.ToLowerInvariant();

        // 如果文件扩展名不再是该家族的加密扩展名，可能已解密
        if (!string.IsNullOrEmpty(familyExt) && ext != familyExt)
        {
            // 检查是否匹配其他家族扩展名
            foreach (var pattern in familyInfo.DetectionPatterns)
            {
                if (pattern.StartsWith("*."))
                {
                    var patternExt = pattern.Substring(1).ToLowerInvariant();
                    if (ext == patternExt)
                        return false; // 仍匹配加密扩展名
                }
            }
            return true; // 不再匹配任何加密扩展名
        }

        return false;
    }

    /// <summary>检查磁盘是否有足够空间（至少需要文件大小的 2 倍）</summary>
    private bool CheckDiskSpace(string filePath)
    {
        try
        {
            var fileInfo = new FileInfo(filePath);
            var drive = new DriveInfo(fileInfo.DirectoryName ?? "C:\\");
            var requiredBytes = fileInfo.Length * 2; // 备份 + 解密结果
            return drive.AvailableFreeSpace > requiredBytes;
        }
        catch
        {
            return true; // 无法检测时默认允许继续
        }
    }

    /// <summary>上报进度</summary>
    private void ReportProgress(DecryptionProgress progress)
    {
        try
        {
            ProgressChanged?.Invoke(progress);
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, "上报解密进度异常");
        }
    }

    #endregion

    #region 历史记录

    /// <summary>解密历史记录条目</summary>
    public sealed class DecryptionHistoryEntry
    {
        public DateTime Timestamp { get; set; }
        public RansomwareFamily Family { get; set; }
        public int TotalFiles { get; set; }
        public int DecryptedFiles { get; set; }
        public int FailedFiles { get; set; }
        public double DurationSeconds { get; set; }
        public string BackupPath { get; set; } = "";
        public bool Success { get; set; }
    }

    /// <summary>记录解密历史</summary>
    private void RecordHistory(DecryptionResult result)
    {
        try
        {
            var history = GetHistory();
            history.Add(new DecryptionHistoryEntry
            {
                Timestamp = DateTime.Now,
                Family = result.Family,
                TotalFiles = result.TotalFiles,
                DecryptedFiles = result.DecryptedFiles,
                FailedFiles = result.FailedFiles,
                DurationSeconds = result.Duration.TotalSeconds,
                BackupPath = result.BackupPath,
                Success = result.Success
            });

            // 仅保留最近 500 条
            if (history.Count > 500)
                history = history.Skip(history.Count - 500).ToList();

            var json = System.Text.Json.JsonSerializer.Serialize(history);
            File.WriteAllText(_historyPath, json);
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, "记录解密历史异常");
        }
    }

    /// <summary>获取解密历史记录（供 UI 显示）</summary>
    public List<DecryptionHistoryEntry> GetHistory()
    {
        try
        {
            if (!File.Exists(_historyPath))
                return new List<DecryptionHistoryEntry>();

            var json = File.ReadAllText(_historyPath);
            return System.Text.Json.JsonSerializer.Deserialize<List<DecryptionHistoryEntry>>(json)
                   ?? new List<DecryptionHistoryEntry>();
        }
        catch
        {
            return new List<DecryptionHistoryEntry>();
        }
    }

    /// <summary>清空解密历史</summary>
    public void ClearHistory()
    {
        try
        {
            if (File.Exists(_historyPath))
                File.Delete(_historyPath);
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, "清空解密历史异常");
        }
    }

    #endregion

    #region 公共访问器

    /// <summary>获取家族检测器实例</summary>
    public RansomwareFamilyDetector GetDetector() => _detector;

    /// <summary>获取工具管理器实例</summary>
    public DecryptionToolManager GetToolManager() => _toolManager;

    #endregion

    public void Dispose()
    {
        _toolManager.Dispose();
    }
}

/// <summary>
/// 解密工具执行输出
/// </summary>
public sealed class ToolOutput
{
    /// <summary>标准输出</summary>
    public string Stdout { get; set; } = "";

    /// <summary>标准错误</summary>
    public string Stderr { get; set; } = "";

    /// <summary>退出码（-1 表示未退出/异常）</summary>
    public int ExitCode { get; set; } = -1;
}
