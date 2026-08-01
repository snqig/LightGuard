// © 2026 落尘（Luochen） 原创开发 - 保留所有权利

using System.Diagnostics;
using System.Diagnostics.Tracing;
using System.Management;
using System.Text;
using LightGuard.Core;
using LightGuard.Modules;

// 项目启用 WinForms（System.Windows.Forms.Timer）会与 System.Threading.Timer 冲突，
// 此处显式别名为线程池定时器，用于行为扫描调度。
using Timer = System.Threading.Timer;

namespace LightGuard.Ransomware;

/// <summary>
/// ETW 行为监控引擎
/// <para>基于 ETW（Event Tracing for Windows）实时监控文件 I/O 操作，识别勒索软件高危行为模式。</para>
/// <para>监控行为：批量篡改文件后缀、短时间大量加密写入、遍历全盘目录、删除 VSS 卷影副本、批量移动加密文件。</para>
/// <para>降级容错：ETW 不可用时自动降级为 WMI 定时扫描，确保防护不中断。</para>
/// </summary>
public sealed class EtwBehaviorMonitor : IDisposable
{
    #region 常量

    /// <summary>批量篡改后缀判定阈值：10 秒内修改 30+ 文件后缀</summary>
    private const int MassExtensionChangeThreshold = 30;

    /// <summary>批量篡改后缀判定时间窗口（秒）</summary>
    private const int MassExtensionChangeWindowSec = 10;

    /// <summary>批量加密写入判定阈值：10 秒内写入 50+ 高价值文件</summary>
    private const int MassEncryptionThreshold = 50;

    /// <summary>批量加密写入时间窗口（秒）</summary>
    private const int MassEncryptionWindowSec = 10;

    /// <summary>遍历全盘目录判定阈值：单进程在 30 秒内访问 200+ 个不同目录</summary>
    private const int DirectoryTraversalThreshold = 200;

    /// <summary>遍历全盘目录时间窗口（秒）</summary>
    private const int DirectoryTraversalWindowSec = 30;

    /// <summary>批量移动文件判定阈值：10 秒内移动 20+ 文件</summary>
    private const int MassFileMoveThreshold = 20;

    /// <summary>批量移动文件时间窗口（秒）</summary>
    private const int MassFileMoveWindowSec = 10;

    /// <summary>WMI 降级扫描间隔（秒）</summary>
    private const int FallbackScanIntervalSec = 5;

    /// <summary>滑动窗口最大保留时长（秒），超过此时间的记录将被清理</summary>
    private const int SlidingWindowRetentionSec = 60;

    /// <summary>高价值文件扩展名集合 — 大量修改此类文件视为加密行为</summary>
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

    /// <summary>VSS 删除相关命令行关键字</summary>
    private static readonly string[] VssDeletionKeywords =
    {
        "delete shadows", "delete shadow", "resize shadowstorage",
        "vssadmin delete", "wmic shadowcopy delete"
    };

    #endregion

    #region 字段

    private readonly object _lock = new();
    private readonly Dictionary<int, ProcessBehaviorWindow> _windows = new();
    private readonly List<int> _alertedPids = new();

    private FileIoEventListener? _etwListener;
    private ManagementEventWatcher? _processStartWatcher;
    private Timer? _behaviorScanTimer;
    private Timer? _wmiFallbackTimer;
    private bool _isEnabled;
    private bool _etwAvailable;
    private DateTime _lastProcessScan;

    #endregion

    #region 事件

    /// <summary>
    /// 检测到勒索行为时触发的事件回调
    /// </summary>
    public event Action<RansomBehaviorAlert>? BehaviorAlertDetected;

    #endregion

    #region 启动/停止

    /// <summary>
    /// 启动 ETW 行为监控
    /// <para>优先尝试 ETW 实时会话，不可用时自动降级为 WMI 定时扫描。</para>
    /// </summary>
    public void Start()
    {
        if (_isEnabled) return;
        _isEnabled = true;

        // 尝试启用 ETW 监听
        try
        {
            _etwListener = new FileIoEventListener();
            _etwListener.OnEvent += OnEtwEventWritten;
            _etwAvailable = true;
            ErrorReporter.Log("[EtwBehaviorMonitor] ETW 监听器已启动");
        }
        catch (Exception ex)
        {
            _etwAvailable = false;
            ErrorReporter.Report(ex, "[EtwBehaviorMonitor] ETW 不可用，降级为 WMI 扫描");
        }

        // WMI 进程启动监控（始终启用，作为 ETW 的补充和降级方案）
        try
        {
            _processStartWatcher = new ManagementEventWatcher(
                new WqlEventQuery("Win32_ProcessStartTrace"));
            _processStartWatcher.EventArrived += OnProcessStarted;
            _processStartWatcher.Start();
            ErrorReporter.Log("[EtwBehaviorMonitor] WMI 进程启动监控已启动");
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, "[EtwBehaviorMonitor] WMI 进程监控启动失败");
        }

        // 行为扫描定时器
        _behaviorScanTimer = new Timer(
            callback: _ => ScanBehaviors(),
            state: null,
            dueTime: TimeSpan.FromSeconds(FallbackScanIntervalSec),
            period: TimeSpan.FromSeconds(FallbackScanIntervalSec));

        // WMI 降级扫描定时器（当 ETW 不可用时，使用更高频率的进程 I/O 扫描）
        if (!_etwAvailable)
        {
            _wmiFallbackTimer = new Timer(
                callback: _ => FallbackProcessIoScan(),
                state: null,
                dueTime: TimeSpan.FromSeconds(2),
                period: TimeSpan.FromSeconds(2));
            ErrorReporter.Log("[EtwBehaviorMonitor] 已降级为 WMI 定时扫描模式");
        }

        ErrorReporter.Log("[EtwBehaviorMonitor] 行为监控引擎已启动");
    }

    /// <summary>
    /// 停止 ETW 行为监控，释放所有资源
    /// </summary>
    public void Stop()
    {
        if (!_isEnabled) return;
        _isEnabled = false;

        try { _etwListener?.Dispose(); } catch { }
        _etwListener = null;

        try { _processStartWatcher?.Stop(); _processStartWatcher?.Dispose(); } catch { }
        _processStartWatcher = null;

        _behaviorScanTimer?.Dispose();
        _behaviorScanTimer = null;

        _wmiFallbackTimer?.Dispose();
        _wmiFallbackTimer = null;

        lock (_lock)
        {
            _windows.Clear();
            _alertedPids.Clear();
        }

        ErrorReporter.Log("[EtwBehaviorMonitor] 行为监控引擎已停止");
    }

    #endregion

    #region ETW 事件处理

    /// <summary>
    /// ETW 事件写入回调
    /// </summary>
    private void OnEtwEventWritten(EventWrittenEventArgs eventData)
    {
        if (!_isEnabled || eventData == null) return;

        try
        {
            // 提取事件信息
            var eventName = eventData.EventName ?? "";
            var payload = eventData.Payload;
            if (payload == null || payload.Count == 0) return;

            // 尝试从 payload 中提取文件路径和进程信息
            string? filePath = null;
            int processId = eventData.ActivityId != default ? 0 : 0;

            foreach (var item in payload)
            {
                var str = item?.ToString();
                if (str != null && str.Length > 2 && (str.Contains('\\') || str.Contains("/")))
                {
                    filePath = str;
                    break;
                }
            }

            if (string.IsNullOrEmpty(filePath)) return;

            // 判断操作类型
            var kind = DetermineOperationKind(eventName);
            if (kind == FileOperationKind.Unknown) return;

            // 获取进程 ID（ETW 事件通常包含 ProcessId）
            if (processId <= 0)
            {
                foreach (var item in payload)
                {
                    if (int.TryParse(item?.ToString(), out var pid) && pid > 0)
                    {
                        processId = pid;
                        break;
                    }
                }
            }

            if (processId <= 0) return;

            RecordFileOperation(processId, filePath, kind);
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, "[EtwBehaviorMonitor] ETW 事件处理异常");
        }
    }

    /// <summary>
    /// 根据 ETW 事件名称推断文件操作类型
    /// </summary>
    private static FileOperationKind DetermineOperationKind(string eventName)
    {
        var lower = eventName.ToLowerInvariant();
        if (lower.Contains("rename") || lower.Contains("moved"))
            return FileOperationKind.Rename;
        if (lower.Contains("delete") || lower.Contains("remove"))
            return FileOperationKind.Delete;
        if (lower.Contains("write") || lower.Contains("create") || lower.Contains("modify"))
            return FileOperationKind.Write;
        if (lower.Contains("read") || lower.Contains("open"))
            return FileOperationKind.Read;
        return FileOperationKind.Unknown;
    }

    #endregion

    #region WMI 进程事件处理

    /// <summary>
    /// 进程启动事件回调 — 检测 VSS 删除命令和已知勒索进程
    /// </summary>
    private void OnProcessStarted(object sender, EventArrivedEventArgs e)
    {
        try
        {
            var props = e.NewEvent.Properties;
            var processName = props["ProcessName"]?.Value?.ToString() ?? "";
            var processId = Convert.ToInt32(props["ProcessID"]?.Value ?? 0);

            if (processId <= 0) return;

            // 检测 VSS 删除命令
            if (IsVssDeletionProcess(processName, processId))
            {
                RaiseAlert(new RansomBehaviorAlert
                {
                    ProcessId = processId,
                    ProcessName = processName,
                    BehaviorType = BehaviorType.VssDeletion,
                    RiskLevel = RiskLevel.Critical,
                    Description = $"检测到 VSS 卷影副本删除操作：进程 {processName} (PID={processId}) 正在调用 vssadmin 删除卷影副本",
                    DetectedAt = DateTime.Now
                });
                return;
            }

            // 创建行为窗口
            lock (_lock)
            {
                if (!_windows.ContainsKey(processId))
                {
                    _windows[processId] = new ProcessBehaviorWindow
                    {
                        ProcessId = processId,
                        ProcessName = processName,
                        StartTime = DateTime.Now
                    };
                }
            }
        }
        catch { }
    }

    /// <summary>
    /// 检测进程是否在执行 VSS 卷影副本删除操作
    /// </summary>
    private static bool IsVssDeletionProcess(string processName, int processId)
    {
        try
        {
            var lowerName = processName.ToLowerInvariant();
            if (lowerName != "vssadmin.exe" && lowerName != "wmic.exe" &&
                lowerName != "powershell.exe" && lowerName != "cmd.exe" &&
                lowerName != "pwsh.exe")
                return false;

            // 查询进程命令行
            using var searcher = new ManagementObjectSearcher(
                $"SELECT CommandLine FROM Win32_Process WHERE ProcessId = {processId}");
            foreach (var obj in searcher.Get())
            {
                var cmdLine = obj["CommandLine"]?.ToString() ?? "";
                var lowerCmd = cmdLine.ToLowerInvariant();

                foreach (var keyword in VssDeletionKeywords)
                {
                    if (lowerCmd.Contains(keyword))
                        return true;
                }
            }
        }
        catch { }

        return false;
    }

    #endregion

    #region 文件操作记录与滑动窗口

    /// <summary>
    /// 记录文件操作到进程的滑动窗口
    /// </summary>
    /// <param name="processId">进程 ID</param>
    /// <param name="filePath">文件路径</param>
    /// <param name="kind">操作类型</param>
    public void RecordFileOperation(int processId, string filePath, FileOperationKind kind)
    {
        if (processId <= 0 || string.IsNullOrEmpty(filePath)) return;

        // 跳过系统进程
        var processName = GetProcessName(processId);
        if (OfflineVirusDb.IsSystemProcess(processName)) return;

        var now = DateTime.Now;

        lock (_lock)
        {
            if (!_windows.TryGetValue(processId, out var window))
            {
                window = new ProcessBehaviorWindow
                {
                    ProcessId = processId,
                    ProcessName = processName,
                    StartTime = now
                };
                _windows[processId] = window;
            }

            // 添加操作记录到滑动窗口末尾
            window.Operations.AddLast(new FileOperationTimestamp(filePath, kind, now));

            // 清理过期记录（滑动窗口保留策略）
            var cutoff = now.AddSeconds(-SlidingWindowRetentionSec);
            while (window.Operations.First != null &&
                   window.Operations.First.Value.Timestamp < cutoff)
            {
                window.Operations.RemoveFirst();
            }
        }
    }

    /// <summary>
    /// 获取进程名称（带缓存）
    /// </summary>
    private static string GetProcessName(int processId)
    {
        try
        {
            using var proc = Process.GetProcessById(processId);
            return proc.ProcessName + ".exe";
        }
        catch
        {
            return "unknown";
        }
    }

    #endregion

    #region 行为扫描

    /// <summary>
    /// 扫描所有进程的滑动窗口，检测勒索行为模式
    /// </summary>
    private void ScanBehaviors()
    {
        if (!_isEnabled) return;

        try
        {
            List<ProcessBehaviorWindow> snapshots;
            lock (_lock)
            {
                snapshots = _windows.Values.ToList();
            }

            var now = DateTime.Now;

            foreach (var window in snapshots)
            {
                try
                {
                    CheckMassExtensionChange(window, now);
                    CheckMassEncryption(window, now);
                    CheckDirectoryTraversal(window, now);
                    CheckMassFileMove(window, now);
                }
                catch (Exception ex)
                {
                    ErrorReporter.Report(ex, $"[EtwBehaviorMonitor] 行为扫描异常 PID={window.ProcessId}");
                }
            }

            // 清理已退出的进程窗口
            CleanupStaleWindows();
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, "[EtwBehaviorMonitor] 行为扫描整体异常");
        }
    }

    /// <summary>
    /// 检测批量篡改文件后缀行为
    /// </summary>
    private void CheckMassExtensionChange(ProcessBehaviorWindow window, DateTime now)
    {
        var windowStart = now.AddSeconds(-MassExtensionChangeWindowSec);
        int extensionChangeCount = 0;

        lock (_lock)
        {
            var node = window.Operations.First;
            while (node != null)
            {
                if (node.Value.Timestamp >= windowStart &&
                    node.Value.Kind == FileOperationKind.Rename)
                {
                    // 检查是否为扩展名变更（文件名中包含多次 . 或后缀异常）
                    var path = node.Value.FilePath;
                    var ext = Path.GetExtension(path);
                    if (!string.IsNullOrEmpty(ext) && ext.Length > 1)
                        extensionChangeCount++;
                }
                node = node.Next;
            }
        }

        if (extensionChangeCount >= MassExtensionChangeThreshold)
        {
            RaiseAlert(new RansomBehaviorAlert
            {
                ProcessId = window.ProcessId,
                ProcessName = window.ProcessName,
                BehaviorType = BehaviorType.MassExtensionChange,
                RiskLevel = RiskLevel.Critical,
                Description = $"批量篡改文件后缀：进程 {window.ProcessName} (PID={window.ProcessId}) " +
                              $"在 {MassExtensionChangeWindowSec} 秒内修改了 {extensionChangeCount} 个文件后缀",
                DetectedAt = now
            });
        }
    }

    /// <summary>
    /// 检测短时间大量加密写入行为
    /// </summary>
    private void CheckMassEncryption(ProcessBehaviorWindow window, DateTime now)
    {
        var windowStart = now.AddSeconds(-MassEncryptionWindowSec);
        int writeCount = 0;
        int highValueCount = 0;

        lock (_lock)
        {
            var node = window.Operations.First;
            while (node != null)
            {
                if (node.Value.Timestamp >= windowStart &&
                    node.Value.Kind == FileOperationKind.Write)
                {
                    writeCount++;
                    var ext = Path.GetExtension(node.Value.FilePath);
                    if (HighValueExtensions.Contains(ext))
                        highValueCount++;
                }
                node = node.Next;
            }
        }

        if (highValueCount >= MassEncryptionThreshold)
        {
            RaiseAlert(new RansomBehaviorAlert
            {
                ProcessId = window.ProcessId,
                ProcessName = window.ProcessName,
                BehaviorType = BehaviorType.MassEncryption,
                RiskLevel = RiskLevel.Critical,
                Description = $"批量加密写入：进程 {window.ProcessName} (PID={window.ProcessId}) " +
                              $"在 {MassEncryptionWindowSec} 秒内写入了 {highValueCount} 个高价值文件（总写入 {writeCount}）",
                DetectedAt = now
            });
        }
    }

    /// <summary>
    /// 检测遍历全盘目录行为
    /// </summary>
    private void CheckDirectoryTraversal(ProcessBehaviorWindow window, DateTime now)
    {
        var windowStart = now.AddSeconds(-DirectoryTraversalWindowSec);
        var uniqueDirs = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        lock (_lock)
        {
            var node = window.Operations.First;
            while (node != null)
            {
                if (node.Value.Timestamp >= windowStart)
                {
                    var dir = Path.GetDirectoryName(node.Value.FilePath);
                    if (!string.IsNullOrEmpty(dir))
                        uniqueDirs.Add(dir);
                }
                node = node.Next;
            }
        }

        if (uniqueDirs.Count >= DirectoryTraversalThreshold)
        {
            RaiseAlert(new RansomBehaviorAlert
            {
                ProcessId = window.ProcessId,
                ProcessName = window.ProcessName,
                BehaviorType = BehaviorType.DirectoryTraversal,
                RiskLevel = RiskLevel.High,
                Description = $"遍历全盘目录：进程 {window.ProcessName} (PID={window.ProcessId}) " +
                              $"在 {DirectoryTraversalWindowSec} 秒内访问了 {uniqueDirs.Count} 个不同目录",
                DetectedAt = now
            });
        }
    }

    /// <summary>
    /// 检测批量移动文件行为
    /// </summary>
    private void CheckMassFileMove(ProcessBehaviorWindow window, DateTime now)
    {
        var windowStart = now.AddSeconds(-MassFileMoveWindowSec);
        int moveCount = 0;

        lock (_lock)
        {
            var node = window.Operations.First;
            while (node != null)
            {
                if (node.Value.Timestamp >= windowStart &&
                    node.Value.Kind == FileOperationKind.Move)
                {
                    moveCount++;
                }
                node = node.Next;
            }
        }

        if (moveCount >= MassFileMoveThreshold)
        {
            RaiseAlert(new RansomBehaviorAlert
            {
                ProcessId = window.ProcessId,
                ProcessName = window.ProcessName,
                BehaviorType = BehaviorType.MassFileMove,
                RiskLevel = RiskLevel.High,
                Description = $"批量移动文件：进程 {window.ProcessName} (PID={window.ProcessId}) " +
                              $"在 {MassFileMoveWindowSec} 秒内移动了 {moveCount} 个文件",
                DetectedAt = now
            });
        }
    }

    #endregion

    #region WMI 降级扫描

    /// <summary>
    /// WMI 降级扫描：当 ETW 不可用时，通过进程 I/O 计数器检测异常行为
    /// </summary>
    private void FallbackProcessIoScan()
    {
        if (!_isEnabled) return;

        try
        {
            var processes = Process.GetProcesses();
            var now = DateTime.Now;

            foreach (var proc in processes)
            {
                try
                {
                    if (proc.Id <= 0) continue;
                    var name = proc.ProcessName + ".exe";
                    if (OfflineVirusDb.IsSystemProcess(name)) continue;

                    // 获取进程 I/O 计数器
                    var ioCounters = GetProcessIoCounters(proc);

                    // 记录 I/O 操作（作为文件操作的近似信号）
                    if (ioCounters.HasSignificantIo)
                    {
                        // 将 I/O 操作映射为文件操作记录
                        var fakePath = $@"\\{proc.ProcessName}\io_activity";
                        RecordFileOperation(proc.Id, fakePath, FileOperationKind.Write);
                    }

                    // 检查已知勒索进程名
                    if (ProcessGuard.IsKnownRansomwareProcess(name))
                    {
                        RaiseAlert(new RansomBehaviorAlert
                        {
                            ProcessId = proc.Id,
                            ProcessName = name,
                            BehaviorType = BehaviorType.MassEncryption,
                            RiskLevel = RiskLevel.Critical,
                            Description = $"检测到已知勒索软件进程：{name} (PID={proc.Id})",
                            DetectedAt = now
                        });
                    }
                }
                catch { }
                finally
                {
                    try { proc.Dispose(); } catch { }
                }
            }

            _lastProcessScan = now;
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, "[EtwBehaviorMonitor] WMI 降级扫描异常");
        }
    }

    /// <summary>
    /// 获取进程 I/O 计数器并判断是否有显著 I/O 活动
    /// </summary>
    private static ProcessIoSnapshot GetProcessIoCounters(Process proc)
    {
        try
        {
            // 使用 WMI 查询进程 I/O 信息
            using var searcher = new ManagementObjectSearcher(
                $"SELECT * FROM Win32_Process WHERE ProcessId = {proc.Id}");
            foreach (var obj in searcher.Get())
            {
                var readOp = Convert.ToUInt64(obj["ReadOperationCount"] ?? 0);
                var writeOp = Convert.ToUInt64(obj["WriteOperationCount"] ?? 0);
                var otherOp = Convert.ToUInt64(obj["OtherOperationCount"] ?? 0);
                var readBytes = Convert.ToUInt64(obj["ReadTransferCount"] ?? 0);
                var writeBytes = Convert.ToUInt64(obj["WriteTransferCount"] ?? 0);

                // 判定标准：写入操作超过 1000 次或写入字节数超过 10MB
                var hasSignificantIo = writeOp > 1000 || writeBytes > 10 * 1024 * 1024;

                return new ProcessIoSnapshot
                {
                    ReadOperations = readOp,
                    WriteOperations = writeOp,
                    OtherOperations = otherOp,
                    ReadBytes = readBytes,
                    WriteBytes = writeBytes,
                    HasSignificantIo = hasSignificantIo
                };
            }
        }
        catch { }

        return new ProcessIoSnapshot();
    }

    #endregion

    #region 告警与清理

    /// <summary>
    /// 触发行为告警
    /// </summary>
    private void RaiseAlert(RansomBehaviorAlert alert)
    {
        // 避免对同一进程短时间内重复告警
        lock (_lock)
        {
            if (_alertedPids.Contains(alert.ProcessId))
            {
                // 5 分钟内已告警过，跳过（除非是 Critical 级别的新行为类型）
                return;
            }
            _alertedPids.Add(alert.ProcessId);

            // 定时清理告警记录（5分钟后可再次告警）
            _ = Task.Run(async () =>
            {
                await Task.Delay(TimeSpan.FromMinutes(5));
                lock (_lock) { _alertedPids.Remove(alert.ProcessId); }
            });
        }

        ErrorReporter.Log(
            $"[EtwBehaviorMonitor] 勒索行为告警: PID={alert.ProcessId} " +
            $"Name={alert.ProcessName} Type={alert.BehaviorType} " +
            $"Risk={alert.RiskLevel} | {alert.Description}",
            alert.RiskLevel >= RiskLevel.Critical ? "ERROR" : "WARN");

        BehaviorAlertDetected?.Invoke(alert);
    }

    /// <summary>
    /// 清理已退出进程的滑动窗口
    /// </summary>
    private void CleanupStaleWindows()
    {
        try
        {
            var currentPids = new HashSet<int>(
                Process.GetProcesses().Select(p => p.Id));

            lock (_lock)
            {
                var stalePids = _windows
                    .Where(kv => !currentPids.Contains(kv.Key))
                    .Select(kv => kv.Key)
                    .ToList();

                foreach (var pid in stalePids)
                    _windows.Remove(pid);
            }
        }
        catch { }
    }

    #endregion

    #region IDisposable

    /// <summary>
    /// 释放资源
    /// </summary>
    public void Dispose()
    {
        Stop();
        GC.SuppressFinalize(this);
    }

    #endregion
}

#region ETW 事件监听器

/// <summary>
/// 文件 I/O ETW 事件监听器
/// <para>继承 EventListener，订阅系统内可用的 EventSource 以捕获文件操作事件。</para>
/// </summary>
internal sealed class FileIoEventListener : EventListener
{
    /// <summary>事件转发委托</summary>
    public event Action<EventWrittenEventArgs>? OnEvent;

    protected override void OnEventSourceCreated(EventSource eventSource)
    {
        try
        {
            var name = eventSource.Name;
            // 订阅文件 I/O 和内核相关事件源
            if (name.Contains("File", StringComparison.OrdinalIgnoreCase) ||
                name.Contains("Kernel", StringComparison.OrdinalIgnoreCase) ||
                name.Contains("IO", StringComparison.OrdinalIgnoreCase) ||
                name.Contains("Disk", StringComparison.OrdinalIgnoreCase))
            {
                EnableEvents(eventSource, EventLevel.Informational,
                    EventKeywords.All);
            }
        }
        catch { }
    }

    protected override void OnEventWritten(EventWrittenEventArgs eventData)
    {
        try
        {
            OnEvent?.Invoke(eventData);
        }
        catch { }
    }
}

#endregion

#region 数据类型

/// <summary>
/// 勒索行为类型枚举
/// </summary>
public enum BehaviorType
{
    /// <summary>批量篡改文件后缀</summary>
    MassExtensionChange,

    /// <summary>短时间大量加密写入</summary>
    MassEncryption,

    /// <summary>遍历全盘目录</summary>
    DirectoryTraversal,

    /// <summary>删除 VSS 卷影副本</summary>
    VssDeletion,

    /// <summary>批量移动文件</summary>
    MassFileMove
}

/// <summary>
/// 文件操作类型（ETW 监控用）
/// </summary>
public enum FileOperationKind
{
    /// <summary>未知操作</summary>
    Unknown,

    /// <summary>读取</summary>
    Read,

    /// <summary>写入</summary>
    Write,

    /// <summary>删除</summary>
    Delete,

    /// <summary>重命名</summary>
    Rename,

    /// <summary>移动</summary>
    Move
}

/// <summary>
/// 勒索行为告警信息
/// </summary>
public sealed class RansomBehaviorAlert
{
    /// <summary>进程 ID</summary>
    public int ProcessId { get; set; }

    /// <summary>进程名称</summary>
    public string ProcessName { get; set; } = "";

    /// <summary>行为类型</summary>
    public BehaviorType BehaviorType { get; set; }

    /// <summary>风险等级</summary>
    public RiskLevel RiskLevel { get; set; }

    /// <summary>告警描述</summary>
    public string Description { get; set; } = "";

    /// <summary>检测时间</summary>
    public DateTime DetectedAt { get; set; }

    public override string ToString()
    {
        return $"[{BehaviorType}] PID={ProcessId} {ProcessName} | {RiskLevel} | {Description}";
    }
}

/// <summary>
/// 进程行为滑动窗口
/// </summary>
internal sealed class ProcessBehaviorWindow
{
    /// <summary>进程 ID</summary>
    public int ProcessId { get; set; }

    /// <summary>进程名称</summary>
    public string ProcessName { get; set; } = "";

    /// <summary>窗口开始时间</summary>
    public DateTime StartTime { get; set; }

    /// <summary>文件操作时间戳滑动窗口（LinkedList 实现）</summary>
    public LinkedList<FileOperationTimestamp> Operations { get; } = new();
}

/// <summary>
/// 文件操作时间戳记录
/// </summary>
internal sealed record FileOperationTimestamp(
    string FilePath,
    FileOperationKind Kind,
    DateTime Timestamp);

/// <summary>
/// 进程 I/O 计数器快照（WMI 降级扫描用）
/// </summary>
internal sealed class ProcessIoSnapshot
{
    public ulong ReadOperations { get; set; }
    public ulong WriteOperations { get; set; }
    public ulong OtherOperations { get; set; }
    public ulong ReadBytes { get; set; }
    public ulong WriteBytes { get; set; }
    public bool HasSignificantIo { get; set; }
}

#endregion
