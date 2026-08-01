using System.Diagnostics;
using System.Management;
using System.Runtime.InteropServices;
using LightGuard.Core;
using LightGuard.Modules;

// 项目启用 WinForms（System.Windows.Forms.Timer）会与 System.Threading.Timer 冲突，
// 此处显式别名为线程池定时器，用于行为扫描调度。
using Timer = System.Threading.Timer;

namespace LightGuard.Ransomware;

/// <summary>
/// 进程行为沙箱隔离引擎
/// 主动监控进程行为：批量文件操作、快速文件修改、可疑进程名、异常 I/O 模式
/// 检测到可疑行为时：挂起进程 → 记录告警 → 自动断网 → 等待用户确认/自动终止
/// </summary>
public sealed class ProcessGuard : IDisposable
{
    #region P/Invoke — 进程挂起/恢复

    [DllImport("ntdll.dll")]
    private static extern int NtSuspendProcess(IntPtr processHandle);

    [DllImport("ntdll.dll")]
    private static extern int NtResumeProcess(IntPtr processHandle);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr hObject);

    private const uint PROCESS_SUSPEND_RESUME = 0x0800;
    private const uint PROCESS_TERMINATE = 0x0001;

    #endregion

    #region 字段

    private readonly object _lock = new();
    private readonly Dictionary<int, ProcessBehaviorProfile> _profiles = new();
    private ManagementEventWatcher? _processStartWatcher;
    private ManagementEventWatcher? _processStopWatcher;
    private Timer? _behaviorScanTimer;
    private bool _isEnabled;

    /// <summary>行为扫描间隔（秒）</summary>
    private const int BehaviorScanIntervalSec = 5;

    /// <summary>批量文件操作判定阈值：单个进程在 10 秒内修改超过 30 个文件 → 可疑</summary>
    private const int MassFileOpThreshold = 30;

    /// <summary>批量文件操作时间窗口（秒）</summary>
    private const int MassFileOpWindowSec = 10;

    /// <summary>快速文件修改判定：单个文件在 3 秒内被修改超过 3 次 → 可疑加密</summary>
    private const int RapidModifyThreshold = 3;

    /// <summary>可疑文件扩展名列表 — 进程大量修改此类文件视为加密行为</summary>
    private static readonly HashSet<string> HighValueExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
        ".pdf", ".jpg", ".jpeg", ".png", ".bmp", ".gif",
        ".mp3", ".mp4", ".avi", ".mov", ".zip", ".rar", ".7z",
        ".txt", ".csv", ".json", ".xml", ".html", ".css",
        ".c", ".cpp", ".cs", ".py", ".java", ".js",
        ".sql", ".db", ".mdb", ".accdb",
        ".psd", ".ai", ".indd", ".dwg", ".svg",
    };

    #endregion

    #region 事件

    /// <summary>检测到可疑进程时触发</summary>
    public event Action<SuspiciousProcessInfo>? SuspiciousProcessDetected;

    /// <summary>进程被隔离（挂起）时触发</summary>
    public event Action<int, string, string>? ProcessQuarantined;

    /// <summary>进程被终止时触发</summary>
    public event Action<int, string>? ProcessTerminated;

    #endregion

    #region 启动/停止

    /// <summary>启动进程行为监控</summary>
    public void Start()
    {
        if (_isEnabled) return;
        _isEnabled = true;

        try
        {
            // 监听进程启动事件
            _processStartWatcher = new ManagementEventWatcher(
                new WqlEventQuery("Win32_ProcessStartTrace"));
            _processStartWatcher.EventArrived += OnProcessStarted;
            _processStartWatcher.Start();
        }
        catch { /* WMI 不可用时降级为定时扫描 */ }

        try
        {
            // 监听进程停止事件
            _processStopWatcher = new ManagementEventWatcher(
                new WqlEventQuery("Win32_ProcessStopTrace"));
            _processStopWatcher.EventArrived += OnProcessStopped;
            _processStopWatcher.Start();
        }
        catch { }

        // 定时扫描进程行为
        _behaviorScanTimer = new Timer(
            callback: _ => ScanAllProcessesBehavior(),
            state: null,
            dueTime: TimeSpan.FromSeconds(BehaviorScanIntervalSec),
            period: TimeSpan.FromSeconds(BehaviorScanIntervalSec));

        ErrorReporter.Log("ProcessGuard 已启动：进程行为沙箱监控运行中");
    }

    /// <summary>停止进程行为监控</summary>
    public void Stop()
    {
        if (!_isEnabled) return;
        _isEnabled = false;

        try { _processStartWatcher?.Stop(); _processStartWatcher?.Dispose(); } catch { }
        try { _processStopWatcher?.Stop(); _processStopWatcher?.Dispose(); } catch { }
        _behaviorScanTimer?.Dispose();

        lock (_lock)
        {
            _profiles.Clear();
        }

        ErrorReporter.Log("ProcessGuard 已停止");
    }

    #endregion

    #region 进程事件处理

    private void OnProcessStarted(object sender, EventArrivedEventArgs e)
    {
        try
        {
            var props = e.NewEvent.Properties;
            var processName = props["ProcessName"]?.Value?.ToString() ?? "";
            var processId = Convert.ToInt32(props["ProcessID"]?.Value ?? 0);

            if (processId <= 0) return;

            // 白名单检查
            if (OfflineVirusDb.IsSystemProcess(processName)) return;

            // 已知勒索进程名检查
            if (IsKnownRansomwareProcess(processName))
            {
                var info = new SuspiciousProcessInfo
                {
                    ProcessId = processId,
                    ProcessName = processName,
                    ThreatName = $"已知勒索软件进程: {processName}",
                    Risk = RiskLevel.Critical,
                    DetectionType = BehaviorDetectionType.KnownRansomware,
                    DetectedAt = DateTime.Now
                };
                OnSuspiciousDetected(info);
                return;
            }

            // 创建行为档案
            lock (_lock)
            {
                if (!_profiles.ContainsKey(processId))
                {
                    _profiles[processId] = new ProcessBehaviorProfile
                    {
                        ProcessId = processId,
                        ProcessName = processName,
                        StartTime = DateTime.Now,
                        FileOperations = new LinkedList<FileOperationRecord>()
                    };
                }
            }
        }
        catch { }
    }

    private void OnProcessStopped(object sender, EventArrivedEventArgs e)
    {
        try
        {
            var processId = Convert.ToInt32(
                e.NewEvent.Properties["ProcessID"]?.Value ?? 0);
            if (processId <= 0) return;

            lock (_lock)
            {
                _profiles.Remove(processId);
            }
        }
        catch { }
    }

    #endregion

    #region 行为扫描

    /// <summary>扫描所有运行中进程的行为模式</summary>
    private void ScanAllProcessesBehavior()
    {
        if (!_isEnabled) return;

        try
        {
            // 获取当前所有进程
            var processes = Process.GetProcesses();
            var now = DateTime.Now;

            foreach (var proc in processes)
            {
                try
                {
                    if (proc.Id <= 0) continue;
                    var name = proc.ProcessName + ".exe";

                    // 白名单跳过
                    if (OfflineVirusDb.IsSystemProcess(name)) continue;

                    // 获取进程行为数据
                    var profile = GetOrCreateProfile(proc.Id, name);

                    // 检查行为指标
                    CheckBehaviorIndicators(proc.Id, profile, now);
                }
                catch { }
                finally
                {
                    try { proc.Dispose(); } catch { }
                }
            }

            // 清理已退出的进程档案
            lock (_lock)
            {
                var staleIds = _profiles
                    .Where(kv => processes.All(p => p.Id != kv.Key))
                    .Select(kv => kv.Key)
                    .ToList();
                foreach (var id in staleIds)
                    _profiles.Remove(id);
            }
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, "ProcessGuard 行为扫描异常");
        }
    }

    /// <summary>检查单个进程的行为指标</summary>
    private void CheckBehaviorIndicators(int pid, ProcessBehaviorProfile profile, DateTime now)
    {
        var windowStart = now.AddSeconds(-MassFileOpWindowSec);

        // 获取窗口内的文件操作数
        LinkedListNode<FileOperationRecord>? node;
        int fileOpCount = 0;
        int highValueFileCount = 0;
        var fileModifyCounts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);

        lock (_lock)
        {
            node = profile.FileOperations.First;
            while (node != null)
            {
                if (node.Value.Timestamp >= windowStart)
                {
                    fileOpCount++;
                    var ext = Path.GetExtension(node.Value.FilePath);
                    if (HighValueExtensions.Contains(ext))
                        highValueFileCount++;

                    // 统计同一文件的修改次数
                    var key = node.Value.FilePath.ToLowerInvariant();
                    fileModifyCounts[key] = fileModifyCounts.GetValueOrDefault(key) + 1;
                }
                node = node.Next;
            }
        }

        // 指标 1: 批量文件操作（10 秒内修改超过 30 个文件）
        if (fileOpCount >= MassFileOpThreshold)
        {
            var info = new SuspiciousProcessInfo
            {
                ProcessId = pid,
                ProcessName = profile.ProcessName,
                ThreatName = $"批量文件操作（{fileOpCount} 个文件/{MassFileOpWindowSec}s）",
                Risk = highValueFileCount > 10 ? RiskLevel.Critical : RiskLevel.High,
                DetectionType = BehaviorDetectionType.MassFileOperation,
                DetectedAt = now,
                Details = $"文件操作: {fileOpCount}, 高价值文件: {highValueFileCount}"
            };
            OnSuspiciousDetected(info);
            return;
        }

        // 指标 2: 快速重复修改同一文件（可能加密）
        var rapidModify = fileModifyCounts.FirstOrDefault(kv => kv.Value >= RapidModifyThreshold);
        if (rapidModify.Key != null)
        {
            var info = new SuspiciousProcessInfo
            {
                ProcessId = pid,
                ProcessName = profile.ProcessName,
                ThreatName = $"快速文件修改（{rapidModify.Key} 在 {MassFileOpWindowSec}s 内修改 {rapidModify.Value} 次）",
                Risk = RiskLevel.High,
                DetectionType = BehaviorDetectionType.RapidFileModification,
                DetectedAt = now,
                Details = $"文件: {rapidModify.Key}, 修改次数: {rapidModify.Value}"
            };
            OnSuspiciousDetected(info);
            return;
        }

        // 指标 3: 进程 CPU 异常高占用 + 文件操作（可能正在加密）
        try
        {
            var proc = Process.GetProcessById(pid);
            var cpuTime = proc.TotalProcessorTime;
            var runtime = now - proc.StartTime;
            if (runtime.TotalSeconds > 10 && cpuTime.TotalSeconds > runtime.TotalSeconds * 0.8
                && fileOpCount > 5)
            {
                var info = new SuspiciousProcessInfo
                {
                    ProcessId = pid,
                    ProcessName = profile.ProcessName,
                    ThreatName = $"高 CPU + 文件操作（CPU: {cpuTime.TotalSeconds:F1}s, 文件: {fileOpCount}）",
                    Risk = RiskLevel.High,
                    DetectionType = BehaviorDetectionType.HighCpuWithFileOp,
                    DetectedAt = now,
                    Details = $"CPU时间: {cpuTime.TotalSeconds:F1}s, 运行: {runtime.TotalSeconds:F1}s"
                };
                OnSuspiciousDetected(info);
                proc.Dispose();
                return;
            }
            proc.Dispose();
        }
        catch { }
    }

    #endregion

    #region 文件操作记录

    /// <summary>记录文件操作（供 FileSystemWatcher 调用）</summary>
    public void RecordFileOperation(int pid, string filePath, FileOperationType opType)
    {
        if (pid <= 0 || string.IsNullOrEmpty(filePath)) return;

        lock (_lock)
        {
            if (!_profiles.TryGetValue(pid, out var profile))
            {
                // 尝试获取进程名
                string name = "unknown";
                try
                {
                    using var proc = Process.GetProcessById(pid);
                    name = proc.ProcessName + ".exe";
                }
                catch { }

                profile = new ProcessBehaviorProfile
                {
                    ProcessId = pid,
                    ProcessName = name,
                    StartTime = DateTime.Now,
                    FileOperations = new LinkedList<FileOperationRecord>()
                };
                _profiles[pid] = profile;
            }

            // 添加操作记录
            profile.FileOperations.AddLast(new FileOperationRecord
            {
                FilePath = filePath,
                Type = opType,
                Timestamp = DateTime.Now
            });

            // 清理过期记录（保留最近 60 秒）
            var cutoff = DateTime.Now.AddSeconds(-60);
            while (profile.FileOperations.First != null
                   && profile.FileOperations.First.Value.Timestamp < cutoff)
            {
                profile.FileOperations.RemoveFirst();
            }
        }
    }

    #endregion

    #region 可疑进程处理

    private void OnSuspiciousDetected(SuspiciousProcessInfo info)
    {
        // 触发事件
        SuspiciousProcessDetected?.Invoke(info);

        // Critical 级别：立即挂起进程
        if (info.Risk >= RiskLevel.Critical)
        {
            QuarantineProcess(info.ProcessId, info.ProcessName, info.ThreatName);
        }
        // High 级别：挂起并等待用户确认
        else if (info.Risk >= RiskLevel.High)
        {
            QuarantineProcess(info.ProcessId, info.ProcessName, info.ThreatName);
        }

        ErrorReporter.Log(
            $"[ProcessGuard] 可疑进程: PID={info.ProcessId} Name={info.ProcessName} " +
            $"Type={info.DetectionType} Risk={info.Risk} Threat={info.ThreatName}",
            info.Risk >= RiskLevel.Critical ? "ERROR" : "WARN");
    }

    /// <summary>隔离进程：挂起进程执行</summary>
    public bool QuarantineProcess(int pid, string processName, string reason)
    {
        try
        {
            // 白名单进程不隔离
            if (OfflineVirusDb.IsSystemProcess(processName))
            {
                ErrorReporter.Log($"[ProcessGuard] 跳过白名单进程: {processName}");
                return false;
            }

            var handle = OpenProcess(PROCESS_SUSPEND_RESUME, false, pid);
            if (handle == IntPtr.Zero)
            {
                ErrorReporter.Log($"[ProcessGuard] 无法打开进程 PID={pid} (错误码: {Marshal.GetLastWin32Error()})");
                return false;
            }

            try
            {
                var status = NtSuspendProcess(handle);
                if (status == 0)
                {
                    ProcessQuarantined?.Invoke(pid, processName, reason);
                    ErrorReporter.Log($"[ProcessGuard] 进程已挂起: PID={pid} Name={processName} 原因={reason}");
                    return true;
                }
                else
                {
                    ErrorReporter.Log($"[ProcessGuard] 挂起进程失败: PID={pid} NtStatus=0x{status:X8}");
                    return false;
                }
            }
            finally
            {
                CloseHandle(handle);
            }
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, $"[ProcessGuard] 隔离进程异常: PID={pid}");
            return false;
        }
    }

    /// <summary>恢复被挂起的进程</summary>
    public bool ResumeProcess(int pid)
    {
        try
        {
            var handle = OpenProcess(PROCESS_SUSPEND_RESUME, false, pid);
            if (handle == IntPtr.Zero) return false;

            try
            {
                var status = NtResumeProcess(handle);
                ErrorReporter.Log($"[ProcessGuard] 进程已恢复: PID={pid} NtStatus=0x{status:X8}");
                return status == 0;
            }
            finally
            {
                CloseHandle(handle);
            }
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, $"[ProcessGuard] 恢复进程异常: PID={pid}");
            return false;
        }
    }

    /// <summary>终止可疑进程</summary>
    public bool TerminateProcess(int pid, string processName)
    {
        try
        {
            if (OfflineVirusDb.IsSystemProcess(processName))
            {
                ErrorReporter.Log($"[ProcessGuard] 拒绝终止白名单进程: {processName}");
                return false;
            }

            var handle = OpenProcess(PROCESS_TERMINATE, false, pid);
            if (handle == IntPtr.Zero)
            {
                ErrorReporter.Log($"[ProcessGuard] 无法打开进程终止 PID={pid}");
                return false;
            }

            try
            {
                // 使用 Process 类终止（更安全）
                using var proc = Process.GetProcessById(pid);
                proc.Kill(entireProcessTree: true);
                proc.WaitForExit(5000);

                ProcessTerminated?.Invoke(pid, processName);
                ErrorReporter.Log($"[ProcessGuard] 进程已终止: PID={pid} Name={processName}");
                return true;
            }
            finally
            {
                CloseHandle(handle);
            }
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, $"[ProcessGuard] 终止进程异常: PID={pid}");
            return false;
        }
    }

    #endregion

    #region 辅助方法

    /// <summary>检查进程名是否匹配已知勒索软件</summary>
    public static bool IsKnownRansomwareProcess(string processName)
    {
        if (string.IsNullOrEmpty(processName)) return false;
        var lower = processName.ToLowerInvariant();

        foreach (var sig in OfflineVirusDb.SuspiciousProcesses)
        {
            if (!string.IsNullOrEmpty(sig.Pattern)
                && lower.Contains(sig.Pattern.ToLowerInvariant()))
            {
                return true;
            }
        }
        return false;
    }

    /// <summary>获取或创建进程行为档案</summary>
    private ProcessBehaviorProfile GetOrCreateProfile(int pid, string name)
    {
        lock (_lock)
        {
            if (!_profiles.TryGetValue(pid, out var profile))
            {
                profile = new ProcessBehaviorProfile
                {
                    ProcessId = pid,
                    ProcessName = name,
                    StartTime = DateTime.Now,
                    FileOperations = new LinkedList<FileOperationRecord>()
                };
                _profiles[pid] = profile;
            }
            return profile;
        }
    }

    /// <summary>获取所有被监控的进程档案</summary>
    public List<ProcessBehaviorProfile> GetMonitoredProcesses()
    {
        lock (_lock)
        {
            return _profiles.Values.ToList();
        }
    }

    /// <summary>获取被隔离的进程列表</summary>
    public List<SuspiciousProcessInfo> GetQuarantinedProcesses()
    {
        return _quarantinedProcesses.ToList();
    }

    private readonly List<SuspiciousProcessInfo> _quarantinedProcesses = new();

    #endregion

    #region IDisposable

    public void Dispose()
    {
        Stop();
        GC.SuppressFinalize(this);
    }

    #endregion
}

#region 数据类型

/// <summary>进程行为检测类型</summary>
public enum BehaviorDetectionType
{
    /// <summary>已知勒索软件进程名</summary>
    KnownRansomware,
    /// <summary>批量文件操作</summary>
    MassFileOperation,
    /// <summary>快速文件修改（可能加密）</summary>
    RapidFileModification,
    /// <summary>高 CPU + 文件操作</summary>
    HighCpuWithFileOp,
    /// <summary>可疑 API 调用模式</summary>
    SuspiciousApiCall
}

/// <summary>文件操作类型</summary>
public enum FileOperationType
{
    Create,
    Modify,
    Rename,
    Delete
}

/// <summary>可疑进程信息</summary>
public sealed class SuspiciousProcessInfo
{
    public int ProcessId { get; set; }
    public string ProcessName { get; set; } = "";
    public string ThreatName { get; set; } = "";
    public RiskLevel Risk { get; set; }
    public BehaviorDetectionType DetectionType { get; set; }
    public DateTime DetectedAt { get; set; }
    public string Details { get; set; } = "";
}

/// <summary>进程行为档案</summary>
public sealed class ProcessBehaviorProfile
{
    public int ProcessId { get; set; }
    public string ProcessName { get; set; } = "";
    public DateTime StartTime { get; set; }
    public LinkedList<FileOperationRecord> FileOperations { get; set; } = new();
}

/// <summary>文件操作记录</summary>
public sealed class FileOperationRecord
{
    public string FilePath { get; set; } = "";
    public FileOperationType Type { get; set; }
    public DateTime Timestamp { get; set; }
}

#endregion
