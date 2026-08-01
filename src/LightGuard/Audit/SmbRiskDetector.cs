// © 2026 落尘（Luochen） 原创开发 - 保留所有权利

using LightGuard.Core;
using LightGuard.Modules;

// 项目启用 WinForms（System.Windows.Forms.Timer）会与 System.Threading.Timer 冲突，
// 此处显式别名为线程池定时器，用于风险分析调度。
using Timer = System.Threading.Timer;

namespace LightGuard.Audit;

/// <summary>
/// SMB 风险行为识别引擎
/// <para>批量文件外泄检测：短时间内大量文件被远程读取。</para>
/// <para>凌晨非工作时段访问检测：22:00-06:00 的异常访问。</para>
/// <para>高频删除行为检测：1 分钟内删除 10+ 文件。</para>
/// <para>与勒索防护联动：备份目录异常访问触发高危告警。</para>
/// </summary>
public sealed class SmbRiskDetector : IDisposable
{
    #region 常量

    /// <summary>批量文件外泄判定阈值：5 分钟内远程读取 100+ 文件</summary>
    private const int MassExfiltrationThreshold = 100;

    /// <summary>批量文件外泄时间窗口（分钟）</summary>
    private const int MassExfiltrationWindowMin = 5;

    /// <summary>凌晨非工作时段起始时间（22:00）</summary>
    private const int OffHoursStartHour = 22;

    /// <summary>凌晨非工作时段结束时间（06:00）</summary>
    private const int OffHoursEndHour = 6;

    /// <summary>高频删除判定阈值：1 分钟内删除 10+ 文件</summary>
    private const int HighFreqDeleteThreshold = 10;

    /// <summary>高频删除时间窗口（秒）</summary>
    private const int HighFreqDeleteWindowSec = 60;

    /// <summary>风险分析间隔（秒）</summary>
    private const int AnalysisIntervalSec = 10;

    /// <summary>滑动窗口最大保留记录数</summary>
    private const int MaxWindowRecords = 5000;

    /// <summary>同一风险事件去重间隔（分钟）</summary>
    private const int RiskDedupMin = 5;

    #endregion

    #region 字段

    private readonly object _lock = new();
    private readonly LinkedList<SmbAuditEntry> _window = new();
    private readonly List<SmbRiskEvent> _riskHistory = new();
    private readonly Dictionary<SmbRiskType, DateTime> _lastRiskTime = new();
    private readonly List<string> _backupPaths;
    private Timer? _analysisTimer;
    private bool _isEnabled;

    #endregion

    #region 事件

    /// <summary>
    /// 检测到风险行为时触发
    /// </summary>
    public event Action<SmbRiskEvent>? RiskDetected;

    #endregion

    #region 构造函数

    /// <summary>
    /// 初始化 SMB 风险行为识别引擎
    /// </summary>
    /// <param name="backupPaths">受保护的备份目录路径列表（用于勒索防护联动）</param>
    public SmbRiskDetector(IEnumerable<string>? backupPaths = null)
    {
        _backupPaths = backupPaths?.ToList() ?? new List<string>();

        // 自动添加 LightGuard 数据目录和备份目录为受保护路径
        _backupPaths.Add(ConfigManager.GetDataDir());
        _backupPaths.Add(ConfigManager.GetBackupDir());
    }

    #endregion

    #region 生命周期

    /// <summary>
    /// 启动风险行为识别引擎
    /// </summary>
    public void Start()
    {
        if (_isEnabled) return;
        _isEnabled = true;

        _analysisTimer = new Timer(
            callback: _ => AnalyzeRisks(),
            state: null,
            dueTime: TimeSpan.FromSeconds(AnalysisIntervalSec),
            period: TimeSpan.FromSeconds(AnalysisIntervalSec));

        ErrorReporter.Log("[SmbRiskDetector] SMB 风险行为识别引擎已启动");
    }

    /// <summary>
    /// 停止风险行为识别引擎
    /// </summary>
    public void Stop()
    {
        if (!_isEnabled) return;
        _isEnabled = false;

        _analysisTimer?.Dispose();
        _analysisTimer = null;

        lock (_lock)
        {
            _window.Clear();
        }

        ErrorReporter.Log("[SmbRiskDetector] SMB 风险行为识别引擎已停止");
    }

    #endregion

    #region 数据输入

    /// <summary>
    /// 添加审计记录到风险分析窗口
    /// <para>由 SmbAuditCollector 的 AuditEntryRecorded 事件回调调用。</para>
    /// </summary>
    /// <param name="entry">SMB 审计记录</param>
    public void AddEntry(SmbAuditEntry entry)
    {
        if (!_isEnabled || entry == null) return;

        lock (_lock)
        {
            _window.AddLast(entry);

            // 清理超出窗口的记录
            while (_window.Count > MaxWindowRecords)
            {
                _window.RemoveFirst();
            }
        }

        // 实时检测凌晨访问（不等定时器）
        if (IsOffHours(entry.Time) && entry.IsRemote)
        {
            RaiseRiskEvent(SmbRiskType.AfterHoursAccess, RiskLevel.Medium,
                "凌晨非工作时段远程访问",
                $"用户 {entry.UserName} 在 {entry.Time:HH:mm:ss} 通过 {entry.ClientIp} 远程访问了 {entry.FilePath}",
                new List<SmbAuditEntry> { entry });
        }

        // 实时检测备份目录访问（勒索防护联动）
        if (IsBackupPathAccess(entry.FilePath))
        {
            RaiseRiskEvent(SmbRiskType.BackupAnomalousAccess, RiskLevel.Critical,
                "备份目录异常访问（勒索防护联动）",
                $"用户 {entry.UserName} 在 {entry.Time:HH:mm:ss} 访问了备份目录: {entry.FilePath} | " +
                $"操作: {entry.Operation} | IP: {entry.ClientIp}",
                new List<SmbAuditEntry> { entry });
        }
    }

    /// <summary>
    /// 批量添加审计记录
    /// </summary>
    public void AddEntries(IEnumerable<SmbAuditEntry> entries)
    {
        if (entries == null) return;
        foreach (var entry in entries)
        {
            AddEntry(entry);
        }
    }

    #endregion

    #region 风险分析

    /// <summary>
    /// 执行风险分析（定时触发）
    /// </summary>
    private void AnalyzeRisks()
    {
        if (!_isEnabled) return;

        try
        {
            List<SmbAuditEntry> snapshot;
            lock (_lock)
            {
                snapshot = _window.ToList();
            }

            if (snapshot.Count == 0) return;

            var now = DateTime.Now;

            CheckMassExfiltration(snapshot, now);
            CheckHighFrequencyDeletion(snapshot, now);

            // 清理过期记录
            CleanupExpiredRecords(now);
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, "[SmbRiskDetector] 风险分析异常");
        }
    }

    /// <summary>
    /// 检测批量文件外泄行为
    /// </summary>
    private void CheckMassExfiltration(List<SmbAuditEntry> entries, DateTime now)
    {
        var windowStart = now.AddMinutes(-MassExfiltrationWindowMin);

        // 按用户和 IP 分组统计远程读取操作
        var readByUserIp = entries
            .Where(e => e.Time >= windowStart &&
                        e.IsRemote &&
                        (e.Operation == SmbOperation.Read || e.Operation == SmbOperation.Login))
            .GroupBy(e => new { e.UserName, e.ClientIp })
            .Select(g => new { g.Key.UserName, g.Key.ClientIp, Count = g.Count(), Entries = g.ToList() })
            .Where(x => x.Count >= MassExfiltrationThreshold)
            .ToList();

        foreach (var group in readByUserIp)
        {
            var description = $"用户 {group.UserName} ({group.ClientIp}) 在 {MassExfiltrationWindowMin} 分钟内" +
                              $"远程读取了 {group.Count} 个文件，疑似批量文件外泄";

            RaiseRiskEvent(SmbRiskType.MassExfiltration, RiskLevel.High,
                "批量文件外泄", description, group.Entries);
        }
    }

    /// <summary>
    /// 检测高频删除行为
    /// </summary>
    private void CheckHighFrequencyDeletion(List<SmbAuditEntry> entries, DateTime now)
    {
        var windowStart = now.AddSeconds(-HighFreqDeleteWindowSec);

        // 按用户分组统计删除操作
        var deletesByUser = entries
            .Where(e => e.Time >= windowStart &&
                        e.Operation == SmbOperation.Delete)
            .GroupBy(e => e.UserName)
            .Select(g => new { UserName = g.Key, Count = g.Count(), Entries = g.ToList() })
            .Where(x => x.Count >= HighFreqDeleteThreshold)
            .ToList();

        foreach (var group in deletesByUser)
        {
            // 删除数量超过阈值的 3 倍时，升级为批量删除
            var riskLevel = group.Count >= HighFreqDeleteThreshold * 3
                ? RiskLevel.Critical
                : RiskLevel.High;
            var riskType = group.Count >= HighFreqDeleteThreshold * 3
                ? SmbRiskType.HighFrequencyDeletion
                : SmbRiskType.HighFrequencyDeletion;

            var description = $"用户 {group.UserName} 在 {HighFreqDeleteWindowSec} 秒内" +
                              $"删除了 {group.Count} 个文件，疑似勒索软件或恶意删除";

            RaiseRiskEvent(riskType, riskLevel,
                "高频删除行为", description, group.Entries);
        }
    }

    #endregion

    #region 辅助方法

    /// <summary>
    /// 判断是否为凌晨非工作时段（22:00-06:00）
    /// </summary>
    private static bool IsOffHours(DateTime time)
    {
        var hour = time.Hour;
        return hour >= OffHoursStartHour || hour < OffHoursEndHour;
    }

    /// <summary>
    /// 判断文件路径是否在备份/受保护目录下
    /// </summary>
    private bool IsBackupPathAccess(string filePath)
    {
        if (string.IsNullOrEmpty(filePath)) return false;

        foreach (var backupPath in _backupPaths)
        {
            if (!string.IsNullOrEmpty(backupPath) &&
                filePath.StartsWith(backupPath, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        // 检查常见备份目录模式
        var lower = filePath.ToLowerInvariant();
        return lower.Contains("backup") ||
               lower.Contains("vss") ||
               lower.Contains("shadowcopy") ||
               lower.Contains("lightguard");
    }

    /// <summary>
    /// 清理过期记录
    /// </summary>
    private void CleanupExpiredRecords(DateTime now)
    {
        var cutoff = now.AddMinutes(-MassExfiltrationWindowMin * 2);

        lock (_lock)
        {
            while (_window.First != null && _window.First.Value.Time < cutoff)
            {
                _window.RemoveFirst();
            }
        }
    }

    #endregion

    #region 风险事件管理

    /// <summary>
    /// 触发风险事件
    /// </summary>
    private void RaiseRiskEvent(
        SmbRiskType type,
        RiskLevel severity,
        string title,
        string description,
        List<SmbAuditEntry> relatedEntries)
    {
        // 去重检查：同一类型风险在去重间隔内不重复触发
        lock (_lock)
        {
            if (_lastRiskTime.TryGetValue(type, out var lastTime))
            {
                if (DateTime.Now - lastTime < TimeSpan.FromMinutes(RiskDedupMin))
                    return;
            }
            _lastRiskTime[type] = DateTime.Now;
        }

        var riskEvent = new SmbRiskEvent
        {
            Type = type,
            Severity = severity,
            Title = title,
            Description = description,
            RelatedEntries = relatedEntries,
            DetectedAt = DateTime.Now
        };

        lock (_lock)
        {
            _riskHistory.Add(riskEvent);
            if (_riskHistory.Count > 500)
            {
                _riskHistory.RemoveAt(0);
            }
        }

        ErrorReporter.Log(
            $"[SmbRiskDetector] 风险事件: Type={type} Severity={severity} | {description}",
            severity >= RiskLevel.Critical ? "ERROR" : "WARN");

        RiskDetected?.Invoke(riskEvent);
    }

    /// <summary>
    /// 获取风险事件历史记录
    /// </summary>
    public List<SmbRiskEvent> GetRiskHistory()
    {
        lock (_lock) return _riskHistory.ToList();
    }

    /// <summary>
    /// 获取当前窗口中的记录数
    /// </summary>
    public int GetWindowRecordCount()
    {
        lock (_lock) return _window.Count;
    }

    /// <summary>
    /// 添加受保护的备份路径
    /// </summary>
    /// <param name="path">备份目录路径</param>
    public void AddBackupPath(string path)
    {
        if (!string.IsNullOrEmpty(path))
        {
            _backupPaths.Add(path);
        }
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

#region 数据类型

/// <summary>
/// SMB 风险行为类型枚举
/// </summary>
public enum SmbRiskType
{
    /// <summary>批量文件外泄</summary>
    MassExfiltration,

    /// <summary>凌晨非工作时段访问</summary>
    AfterHoursAccess,

    /// <summary>高频删除行为</summary>
    HighFrequencyDeletion,

    /// <summary>备份目录异常访问（勒索防护联动）</summary>
    BackupAnomalousAccess
}

/// <summary>
/// SMB 风险事件
/// </summary>
public sealed class SmbRiskEvent
{
    /// <summary>风险类型</summary>
    public SmbRiskType Type { get; set; }

    /// <summary>风险严重等级</summary>
    public RiskLevel Severity { get; set; }

    /// <summary>风险标题</summary>
    public string Title { get; set; } = "";

    /// <summary>风险描述</summary>
    public string Description { get; set; } = "";

    /// <summary>关联的审计记录列表</summary>
    public List<SmbAuditEntry> RelatedEntries { get; set; } = new();

    /// <summary>检测时间</summary>
    public DateTime DetectedAt { get; set; }

    public override string ToString()
    {
        return $"[{Type}] {Severity} | {Title} | {Description} | 关联记录: {RelatedEntries.Count}";
    }
}

#endregion
