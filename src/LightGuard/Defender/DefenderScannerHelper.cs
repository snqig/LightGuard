using System.Diagnostics;
using System.ServiceProcess;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using LightGuard.Core;

namespace LightGuard.Defender;

/// <summary>
/// Microsoft Defender 查杀调度核心助手
/// 通过 MpCmdRun.exe 实现按需查杀、快速/全盘扫描、病毒库更新与状态查询
///
/// 命令规范：
///   -Scan -ScanType 1            快速扫描
///   -Scan -ScanType 2            全盘扫描
///   -Scan -ScanType 3 -File path 自定义扫描（文件或目录）
///   -DisableRemediation          扫描时不禁用处置，仅检测不隔离（与 -File 配合）
///   -SignatureUpdate             病毒库更新
///
/// 退出码：
///   0  未发现威胁（干净）
///   2  发现威胁
///   其他  错误
/// </summary>
public sealed class DefenderScannerHelper : IDisposable
{
    // ===== MpCmdRun.exe 搜索路径（按优先级） =====
    private static readonly string[] PrimarySearchPaths = new[]
    {
        @"C:\Program Files\Windows Defender\MpCmdRun.exe",
        @"C:\Program Files (x86)\Windows Defender\MpCmdRun.exe"
    };

    /// <summary>带版本号的平台目录（需要 glob 取最新版本）</summary>
    private const string PlatformDir = @"C:\ProgramData\Microsoft\Windows Defender\Platform";

    /// <summary>进程节流间隔（毫秒）—— P0-2 要求：文件操作间加节流，降低启发式误判风险</summary>
    private const int ThrottleMs = 200;

    /// <summary>状态查询/签名更新的默认超时</summary>
    private const int StatusTimeoutMs = 20000;

    private string? _mpCmdRunPath;
    private bool _pathResolved;
    private bool _disposed;

    // 当前运行进程引用（用于取消/释放）
    private Process? _runningProcess;

    /// <summary>扫描进度实时上报事件（在后台线程触发，UI 需自行 Invoke）</summary>
    public event Action<DefenderScanProgress>? ProgressChanged;

    /// <summary>扫描进程优先级（策略配置可调，默认正常）</summary>
    public ProcessPriorityClass ScanPriority { get; set; } = ProcessPriorityClass.Normal;

    /// <summary>扫描时是否禁用自动处置（仅检测）。默认 true，配合 -DisableRemediation</summary>
    public bool DisableRemediation { get; set; } = true;

    public DefenderScannerHelper()
    {
        // 构造时即尝试定位 MpCmdRun.exe，失败也不抛异常（延迟到首次使用时重试）
        _mpCmdRunPath = ResolveMpCmdRun();
        _pathResolved = _mpCmdRunPath != null;
    }

    // ==================== 公共 API ====================

    /// <summary>
    /// 检查 Microsoft Defender 是否存在且服务正在运行
    /// </summary>
    public bool IsDefenderAvailable()
    {
        try
        {
            // 1. MpCmdRun.exe 必须能找到
            var exe = EnsureMpCmdRun();
            if (string.IsNullOrEmpty(exe) || !File.Exists(exe))
                return false;

            // 2. WinDefend 服务必须在运行
            try
            {
                using var sc = new ServiceController("WinDefend");
                return sc.Status == ServiceControllerStatus.Running;
            }
            catch
            {
                // 某些精简版系统服务名不同，退而检查 MpCmdRun 是否可执行
                return true;
            }
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// 当前进程是否以管理员身份运行（复用 LightGuard.Core.AdminChecker）
    /// </summary>
    public bool IsRunningAsAdmin() => AdminChecker.IsRunningAsAdmin();

    /// <summary>
    /// 查询 Defender 引擎与病毒库状态（优先 PowerShell Get-MpComputerStatus）
    /// </summary>
    public DefenderStatusInfo GetDefenderStatus()
    {
        var info = new DefenderStatusInfo();
        var sw = Stopwatch.StartNew();

        try
        {
            // 优先使用 PowerShell Get-MpComputerStatus | ConvertTo-Json，结构化、可靠
            var psi = new ProcessStartInfo
            {
                FileName = "powershell.exe",
                Arguments = "-NoProfile -NonInteractive -Command \"Get-MpComputerStatus | ConvertTo-Json -Depth 2\"",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
                StandardOutputEncoding = Encoding.UTF8
            };

            using var p = Process.Start(psi);
            if (p == null)
            {
                info.ErrorMessage = "无法启动 PowerShell 进程";
                return info;
            }

            var json = p.StandardOutput.ReadToEnd();
            var err = p.StandardError.ReadToEnd();
            p.WaitForExit(StatusTimeoutMs);

            if (p.ExitCode != 0 || string.IsNullOrWhiteSpace(json))
            {
                // 回退到 WMI AntiVirusProduct
                var fallback = QueryStatusViaWmi();
                if (fallback != null)
                    return fallback;

                info.ErrorMessage = string.IsNullOrWhiteSpace(err)
                    ? "Get-MpComputerStatus 无输出"
                    : err.Trim();
                return info;
            }

            ParseMpComputerStatus(json, info);
            info.IsValid = true;
            info.IsHealthy = info.AntivirusEnabled
                             && info.RealTimeProtectionEnabled
                             && IsSignatureFresh(info.SignatureLastUpdated);

            ErrorReporter.Log($"Defender 状态查询完成 耗时 {sw.ElapsedMilliseconds}ms - 实时保护:{info.RealTimeProtectionEnabled} 病毒库:{info.SignatureVersion} 健康:{info.IsHealthy}");
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, "查询 Defender 状态失败");
            info.ErrorMessage = ex.Message;
        }

        return info;
    }

    /// <summary>单文件扫描</summary>
    public Task<DefenderScanResult> ScanFileAsync(string filePath, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(filePath))
            return Task.FromResult(Fail(DefenderScanType.SingleFile, "文件路径为空"));

        if (!File.Exists(filePath))
            return Task.FromResult(Fail(DefenderScanType.SingleFile, $"文件不存在：{filePath}", filePath));

        // 节流（P0-2）
        Throttle();

        var args = $"-Scan -ScanType 3 -File \"{filePath}\" -DisableRemediation";
        return RunScanAsync(args, DefenderScanType.SingleFile, ct, filePath);
    }

    /// <summary>目录扫描</summary>
    public Task<DefenderScanResult> ScanDirectoryAsync(string dirPath, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(dirPath))
            return Task.FromResult(Fail(DefenderScanType.Directory, "目录路径为空"));

        if (!Directory.Exists(dirPath))
            return Task.FromResult(Fail(DefenderScanType.Directory, $"目录不存在：{dirPath}", dirPath));

        Throttle();

        var args = $"-Scan -ScanType 3 -File \"{dirPath}\" -DisableRemediation";
        return RunScanAsync(args, DefenderScanType.Directory, ct, dirPath);
    }

    /// <summary>快速扫描</summary>
    public Task<DefenderScanResult> QuickScanAsync(CancellationToken ct)
    {
        Throttle();
        return RunScanAsync("-Scan -ScanType 1", DefenderScanType.QuickScan, ct, null);
    }

    /// <summary>全盘扫描</summary>
    public Task<DefenderScanResult> FullScanAsync(CancellationToken ct)
    {
        Throttle();
        return RunScanAsync("-Scan -ScanType 2", DefenderScanType.FullScan, ct, null);
    }

    /// <summary>
    /// 更新病毒库签名
    /// </summary>
    public async Task UpdateSignaturesAsync()
    {
        var exe = EnsureMpCmdRun();
        if (exe == null)
        {
            ErrorReporter.Log("病毒库更新失败：未找到 MpCmdRun.exe", "ERROR");
            return;
        }

        try
        {
            ErrorReporter.Log("开始更新 Defender 病毒库签名...");
            var psi = BuildProcessStartInfo(exe, "-SignatureUpdate");

            using var p = Process.Start(psi);
            if (p == null) return;

            _runningProcess = p;
            var output = new StringBuilder();
            p.OutputDataReceived += (s, e) => { if (e.Data != null) output.AppendLine(e.Data); };
            p.ErrorDataReceived += (s, e) => { if (e.Data != null) output.AppendLine(e.Data); };

            p.BeginOutputReadLine();
            p.BeginErrorReadLine();

            await WaitForExitAsync(p, CancellationToken.None);
            p.WaitForExit();

            ErrorReporter.Log($"病毒库更新完成 退出码 {p.ExitCode}。输出：{output}");
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, "更新病毒库签名失败");
        }
        finally
        {
            _runningProcess = null;
        }
    }

    // ==================== 内部实现 ====================

    /// <summary>定位 MpCmdRun.exe（多路径 + 平台版本 glob 取最新）</summary>
    private static string? ResolveMpCmdRun()
    {
        // 1. 主路径 / x86 路径
        foreach (var path in PrimarySearchPaths)
        {
            if (File.Exists(path))
                return path;
        }

        // 2. 平台版本目录 glob：C:\ProgramData\Microsoft\Windows Defender\Platform\*\MpCmdRun.exe
        try
        {
            if (Directory.Exists(PlatformDir))
            {
                // 取版本号最大的子目录（目录名形如 4.18.23050.x）
                var subDirs = Directory.GetDirectories(PlatformDir, "*");
                if (subDirs.Length > 0)
                {
                    // 按目录名降序，取第一个包含 MpCmdRun.exe 的
                    var latest = subDirs
                        .OrderByDescending(d => Path.GetFileName(d), StringComparer.OrdinalIgnoreCase)
                        .Select(d => Path.Combine(d, "MpCmdRun.exe"))
                        .FirstOrDefault(File.Exists);

                    if (latest != null)
                        return latest;
                }
            }
        }
        catch
        {
            // 忽略目录访问异常
        }

        return null;
    }

    /// <summary>确保已解析 MpCmdRun 路径，未解析则重试一次</summary>
    private string? EnsureMpCmdRun()
    {
        if (_pathResolved)
            return _mpCmdRunPath;

        _mpCmdRunPath = ResolveMpCmdRun();
        _pathResolved = true;
        return _mpCmdRunPath;
    }

    /// <summary>执行一次 MpCmdRun 扫描并解析输出</summary>
    private async Task<DefenderScanResult> RunScanAsync(
        string arguments, DefenderScanType scanType, CancellationToken ct, string? targetPath)
    {
        var exe = EnsureMpCmdRun();
        if (exe == null)
        {
            return Fail(scanType, "未找到 MpCmdRun.exe，请确认 Windows Defender 已启用", targetPath);
        }

        var sw = Stopwatch.StartNew();
        var outputLines = new List<string>();
        var threatNames = new List<string>();
        var threats = new List<DefenderThreat>();
        int filesScanned = 0;

        var result = new DefenderScanResult
        {
            ScanType = scanType,
            TargetPath = targetPath
        };

        Process? process = null;
        try
        {
            var psi = BuildProcessStartInfo(exe, arguments);
            process = new Process { StartInfo = psi, EnableRaisingEvents = true };

            // 实时解析输出并上报进度
            process.OutputDataReceived += (s, e) =>
            {
                if (e.Data == null) return;
                outputLines.Add(e.Data);
                HandleOutputLine(e.Data, threatNames, threats, ref filesScanned);
                ReportProgress(threatNames.Count, filesScanned, e.Data, true);
                // 节流（P0-2）：文件操作间加 200ms 节流
                Throttle();
            };
            process.ErrorDataReceived += (s, e) =>
            {
                if (e.Data == null) return;
                outputLines.Add("[stderr] " + e.Data);
            };

            if (!process.Start())
            {
                result.Success = false;
                result.ErrorMessage = "MpCmdRun 启动失败";
                return result;
            }

            _runningProcess = process;
            // 应用扫描优先级（策略配置）
            try { process.PriorityClass = ScanPriority; }
            catch { /* 部分系统/权限下设置优先级失败，忽略 */ }
            process.BeginOutputReadLine();
            process.BeginErrorReadLine();

            ReportProgress(0, 0, string.Empty, true);

            // 等待退出（支持取消）
            await WaitForExitAsync(process, ct);
            // 确保异步读取器刷新完成
            process.WaitForExit();

            result.ExitCode = process.ExitCode;
            result.RawOutput = string.Join(Environment.NewLine, outputLines);
        }
        catch (OperationCanceledException)
        {
            result.Success = false;
            result.ErrorMessage = "扫描已被用户取消";
            result.ExitCode = -1;
            sw.Stop();
            result.ScanDuration = sw.Elapsed;
            result.ScannedItems = filesScanned;
            result.ThreatsFound = threatNames.Count;
            result.ThreatNames = threatNames;
            result.Threats = threats;
            ReportProgress(threatNames.Count, filesScanned, string.Empty, false);
            return result;
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, $"Defender 扫描失败 ({scanType})");
            result.Success = false;
            result.ErrorMessage = ex.Message;
            result.ExitCode = -1;
            sw.Stop();
            result.ScanDuration = sw.Elapsed;
            result.ScannedItems = filesScanned;
            result.ThreatsFound = threatNames.Count;
            result.ThreatNames = threatNames;
            result.Threats = threats;
            ReportProgress(threatNames.Count, filesScanned, string.Empty, false);
            return result;
        }
        finally
        {
            _runningProcess = null;
            process?.Dispose();
        }

        sw.Stop();
        result.ScanDuration = sw.Elapsed;
        result.ScannedItems = filesScanned;
        result.ThreatNames = threatNames;
        result.Threats = threats;

        // 二次解析（部分威胁信息仅在结束时完整）
        FinalizeThreats(outputLines, threats, threatNames);

        // 退出码判定：0=干净, 2=发现威胁, 其他=错误
        switch (result.ExitCode)
        {
            case 0:
                result.Success = true;
                result.ThreatsFound = 0;
                break;
            case 2:
                result.Success = true;
                result.ThreatsFound = Math.Max(threatNames.Count, 1);
                // 若未解析到威胁名，给出占位
                if (threatNames.Count == 0)
                    threatNames.Add("Threat (未命名)");
                break;
            default:
                result.Success = false;
                result.ErrorMessage = string.IsNullOrEmpty(result.ErrorMessage)
                    ? $"MpCmdRun 异常退出，退出码 {result.ExitCode}"
                    : result.ErrorMessage;
                break;
        }

        ReportProgress(result.ThreatsFound, filesScanned, string.Empty, false);
        return result;
    }

    /// <summary>构建 MpCmdRun 进程启动信息</summary>
    private static ProcessStartInfo BuildProcessStartInfo(string exe, string arguments)
    {
        return new ProcessStartInfo
        {
            FileName = exe,
            Arguments = arguments,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8,
            WindowStyle = ProcessWindowStyle.Hidden
        };
    }

    /// <summary>实时解析单行输出，提取威胁与文件信息</summary>
    private static void HandleOutputLine(string line, List<string> threatNames, List<DefenderThreat> threats, ref int filesScanned)
    {
        if (string.IsNullOrWhiteSpace(line))
            return;

        // 威胁名提取：匹配 "Threat (名称)" 或 "Threat :名称" 或 "Threat: 名称"
        var threatMatch = Regex.Match(line, @"Threat\s*[\(:]\s*(?<name>[^\)\:]+)", RegexOptions.IgnoreCase);
        if (threatMatch.Success)
        {
            var name = threatMatch.Groups["name"].Value.Trim();
            if (!string.IsNullOrEmpty(name) && !threatNames.Contains(name))
            {
                threatNames.Add(name);
                var threat = new DefenderThreat
                {
                    ThreatName = name,
                    Severity = GuessSeverity(name)
                };
                // 同行可能附带文件路径
                var path = ExtractFilePath(line);
                if (!string.IsNullOrEmpty(path))
                    threat.FilePath = path;
                threats.Add(threat);
            }
        }

        // 文件路径提取（用于进度）
        var fp = ExtractFilePath(line);
        if (!string.IsNullOrEmpty(fp))
        {
            filesScanned++;
            // 为最近未带路径的威胁补全路径
            if (threats.Count > 0 && string.IsNullOrEmpty(threats[^1].FilePath))
                threats[^1].FilePath = fp;
        }

        // "Scanning" 行计数
        if (line.Contains("Scanning", StringComparison.OrdinalIgnoreCase))
            filesScanned++;
    }

    /// <summary>结束后的二次解析，补全威胁列表</summary>
    private static void FinalizeThreats(List<string> lines, List<DefenderThreat> threats, List<string> threatNames)
    {
        // 某些版本输出形如 "Threat  :Trojan:Win32/xxx  on  C:\path\file.exe"
        foreach (var line in lines)
        {
            if (!line.Contains("Threat", StringComparison.OrdinalIgnoreCase))
                continue;

            var name = Regex.Match(line, @"Threat\s*[\(:]\s*(?<name>[^\:]+?)(?:\s+on\s+|$)", RegexOptions.IgnoreCase);
            if (name.Success)
            {
                var n = name.Groups["name"].Value.Trim();
                if (!string.IsNullOrEmpty(n) && !threatNames.Contains(n))
                {
                    threatNames.Add(n);
                    threats.Add(new DefenderThreat
                    {
                        ThreatName = n,
                        FilePath = ExtractFilePath(line) ?? string.Empty,
                        Severity = GuessSeverity(n)
                    });
                }
            }
        }
    }

    /// <summary>从一行文本中提取 Windows 文件路径</summary>
    private static string? ExtractFilePath(string line)
    {
        // 匹配盘符开头的路径，如 C:\folder\file.exe
        var m = Regex.Match(line, @"[A-Za-z]:\\[^\s\]]+");
        return m.Success ? m.Value.TrimEnd('.') : null;
    }

    /// <summary>根据威胁名粗略推断严重等级</summary>
    private static ThreatSeverity GuessSeverity(string threatName)
    {
        if (string.IsNullOrEmpty(threatName))
            return ThreatSeverity.Medium;

        var lower = threatName.ToLowerInvariant();
        if (lower.Contains("severe") || lower.Contains("ransom") || lower.Contains("trojan"))
            return ThreatSeverity.High;
        if (lower.Contains("worm") || lower.Contains("backdoor"))
            return ThreatSeverity.Severe;
        if (lower.Contains("adware") || lower.Contains("pup"))
            return ThreatSeverity.Low;
        return ThreatSeverity.Medium;
    }

    /// <summary>解析 Get-MpComputerStatus 的 JSON 输出</summary>
    private static void ParseMpComputerStatus(string json, DefenderStatusInfo info)
    {
        try
        {
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;

            info.RealTimeProtectionEnabled = GetBool(root, "RealTimeProtectionEnabled");
            info.AntivirusEnabled = GetBool(root, "AntivirusEnabled");
            info.AntispywareEnabled = GetBool(root, "AntispywareEnabled");
            info.SignatureVersion = GetString(root, "AntivirusSignatureVersion");
            info.EngineVersion = GetString(root, "AMEngineVersion");
            info.ProductVersion = GetString(root, "AMProductVersion");
            info.SignatureLastUpdated = GetDateTime(root, "AntivirusSignatureLastUpdated");

            // 病毒库版本为空时尝试 NIS 通道
            if (string.IsNullOrEmpty(info.SignatureVersion))
                info.SignatureVersion = GetString(root, "NISSignatureVersion");
            if (info.SignatureLastUpdated == default)
                info.SignatureLastUpdated = GetDateTime(root, "NISSignatureLastUpdated");
        }
        catch
        {
            // 解析失败保持默认值
        }
    }

    /// <summary>WMI 回退查询（部分环境 PowerShell 不可用）</summary>
    private static DefenderStatusInfo? QueryStatusViaWmi()
    {
        try
        {
            using var searcher = new System.Management.ManagementObjectSearcher(
                @"root\SecurityCenter2", "SELECT * FROM AntiVirusProduct");
            foreach (var mo in searcher.Get().Cast<System.Management.ManagementObject>())
            {
                var info = new DefenderStatusInfo { IsValid = true };
                var name = mo["displayName"]?.ToString() ?? "";
                if (!name.Contains("Defender", StringComparison.OrdinalIgnoreCase))
                    continue;

                info.ProductVersion = mo["productState"]?.ToString() ?? "";
                info.AntivirusEnabled = true;
                info.RealTimeProtectionEnabled = true;
                info.IsHealthy = true;
                return info;
            }
        }
        catch
        {
            // WMI 不可用
        }
        return null;
    }

    private static bool GetBool(JsonElement root, string name)
    {
        return root.TryGetProperty(name, out var el) && el.ValueKind == JsonValueKind.True;
    }

    private static string GetString(JsonElement root, string name)
    {
        return root.TryGetProperty(name, out var el) && el.ValueKind == JsonValueKind.String
            ? el.GetString() ?? string.Empty
            : string.Empty;
    }

    private static DateTime GetDateTime(JsonElement root, string name)
    {
        if (root.TryGetProperty(name, out var el) && el.ValueKind == JsonValueKind.String)
        {
            var s = el.GetString();
            if (!string.IsNullOrEmpty(s) && DateTime.TryParse(s, out var dt))
                return dt;
        }
        return default;
    }

    /// <summary>病毒库是否在 7 天内更新过（视为不过期）</summary>
    private static bool IsSignatureFresh(DateTime lastUpdated)
    {
        if (lastUpdated == default)
            return false;
        return DateTime.Now - lastUpdated <= TimeSpan.FromDays(7);
    }

    /// <summary>上报进度</summary>
    private void ReportProgress(int threatsFound, int filesScanned, string currentFile, bool running)
    {
        try
        {
            ProgressChanged?.Invoke(new DefenderScanProgress
            {
                ThreatsFound = threatsFound,
                FilesScanned = filesScanned,
                CurrentFile = currentFile ?? string.Empty,
                IsRunning = running,
                PercentComplete = running ? -1 : 100
            });
        }
        catch
        {
            // 进度回调失败不影响扫描
        }
    }

    /// <summary>节流：文件操作间 200ms 休眠（P0-2）</summary>
    private static void Throttle()
    {
        try { Thread.Sleep(ThrottleMs); }
        catch { /* 忽略 */ }
    }

    /// <summary>构造失败结果</summary>
    private static DefenderScanResult Fail(DefenderScanType type, string message, string? targetPath = null)
    {
        return new DefenderScanResult
        {
            ScanType = type,
            TargetPath = targetPath,
            Success = false,
            ErrorMessage = message,
            ExitCode = -1
        };
    }

    /// <summary>带取消支持的进程等待</summary>
    private static async Task WaitForExitAsync(Process process, CancellationToken ct)
    {
        var tcs = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        void OnExited(object? s, EventArgs e) => tcs.TrySetResult(true);
        process.Exited += OnExited;

        try
        {
            await using (ct.Register(() =>
            {
                try { if (!process.HasExited) process.Kill(entireProcessTree: true); }
                catch { /* 忽略 */ }
                tcs.TrySetCanceled(ct);
            }))
            {
                if (process.HasExited)
                    return;
                await tcs.Task;
            }
        }
        finally
        {
            process.Exited -= OnExited;
        }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;

        try
        {
            if (_runningProcess is { HasExited: false })
            {
                _runningProcess.Kill(entireProcessTree: true);
            }
        }
        catch { /* 忽略 */ }

        _runningProcess = null;
    }
}
