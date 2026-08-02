// © 2026 落尘（Luochen） 原创开发 - 保留所有权利

using System.Diagnostics;
using System.Text;
using LightGuard.Core;
using LightGuard.Modules;
using LightGuard.Native;

namespace LightGuard.Ransomware;

/// <summary>
/// 双层防御协调器 — 整合 ETW 行为监控与 YARA 特征核验
/// <para>第一层（ETW）：实时捕获未知异常行为模式（批量加密、目录遍历、VSS 删除等）。</para>
/// <para>第二层（YARA）：对 ETW 触发的目标文件按需匹配已知勒索特征。</para>
/// <para>综合判定：ETW + YARA 双重确认 = Critical 级别；仅 ETW 或仅 YARA = High 级别。</para>
/// <para>风险响应链：挂起进程 → 防火墙断网 → 弹窗告警 → 锁定 VSS 备份。</para>
/// </summary>
public sealed class RansomDefenseEngine : IDisposable
{
    #region 字段

    private readonly EtwBehaviorMonitor _etwMonitor;
    private readonly YaraEngine _yaraEngine;
    private readonly ProcessGuard _processGuard;
    private readonly object _lock = new();

    private readonly List<DefenseAlert> _alertHistory = new();
    private readonly HashSet<int> _processedPids = new();
    private bool _isEnabled;

    /// <summary>最大告警历史保留数</summary>
    private const int MaxAlertHistory = 500;

    /// <summary>同一进程告警去重间隔（秒）</summary>
    private const int DedupIntervalSec = 30;

    #endregion

    #region 事件

    /// <summary>
    /// 防御告警事件 — 当检测到威胁并执行响应时触发
    /// </summary>
    public event Action<DefenseAlert>? AlertRaised;

    #endregion

    #region 构造函数

    /// <summary>
    /// 初始化双层防御协调器
    /// </summary>
    public RansomDefenseEngine()
    {
        _etwMonitor = new EtwBehaviorMonitor();
        _yaraEngine = new YaraEngine();
        _processGuard = new ProcessGuard();

        // 订阅 ETW 行为告警
        _etwMonitor.BehaviorAlertDetected += OnEtwBehaviorAlert;
    }

    #endregion

    #region 生命周期

    /// <summary>
    /// 启动双层防御引擎
    /// <para>ETW 行为监控 + 进程行为沙箱同步启动，YARA 引擎按需触发。</para>
    /// </summary>
    public void Start()
    {
        if (_isEnabled) return;
        _isEnabled = true;

        // 启动 ETW 行为监控
        _etwMonitor.Start();

        // 启动进程行为沙箱（用于挂起/隔离进程）
        _processGuard.Start();

        ErrorReporter.Log("[RansomDefenseEngine] 双层防御引擎已启动 | ETW + YARA + ProcessGuard");
    }

    /// <summary>
    /// 停止双层防御引擎
    /// </summary>
    public void Stop()
    {
        if (!_isEnabled) return;
        _isEnabled = false;

        _etwMonitor.Stop();
        _processGuard.Stop();

        ErrorReporter.Log("[RansomDefenseEngine] 双层防御引擎已停止");
    }

    #endregion

    #region ETW 行为告警处理

    /// <summary>
    /// ETW 行为告警回调 — 触发 YARA 二次核验
    /// </summary>
    private void OnEtwBehaviorAlert(RansomBehaviorAlert etwAlert)
    {
        try
        {
            // 去重检查
            lock (_lock)
            {
                if (_processedPids.Contains(etwAlert.ProcessId))
                {
                    ErrorReporter.Log($"[RansomDefenseEngine] 跳过重复告警 PID={etwAlert.ProcessId}");
                    return;
                }
                _processedPids.Add(etwAlert.ProcessId);

                // 定时清理去重标记
                _ = Task.Run(async () =>
                {
                    await Task.Delay(TimeSpan.FromSeconds(DedupIntervalSec));
                    lock (_lock) { _processedPids.Remove(etwAlert.ProcessId); }
                });
            }

            // VSS 删除行为直接触发 Critical 告警（无需 YARA 核验）
            if (etwAlert.BehaviorType == BehaviorType.VssDeletion)
            {
                var alert = new DefenseAlert
                {
                    Layer = DefenseLayer.Etw,
                    EtwAlert = etwAlert,
                    YaraResult = null,
                    RiskLevel = RiskLevel.Critical,
                    Summary = $"[ETW] VSS 卷影副本删除检测: {etwAlert.Description}",
                    ResponseActions = new List<ResponseAction>(),
                    DetectedAt = DateTime.Now
                };

                ExecuteResponseChain(alert, etwAlert.ProcessId, etwAlert.ProcessName);
                RaiseAlert(alert);
                return;
            }

            // 触发 YARA 二次核验
            var yaraResults = _yaraEngine.ScanProcess(etwAlert.ProcessId);
            var matchedResults = yaraResults.Where(r => r.IsMatched).ToList();
            var maxRisk = matchedResults.Any()
                ? matchedResults.Max(r => r.RiskLevel)
                : RiskLevel.Clean;

            // 综合判定
            DefenseLayer layer;
            RiskLevel combinedRisk;
            string summary;

            if (matchedResults.Any())
            {
                // ETW + YARA 双重确认 = Critical
                layer = DefenseLayer.Dual;
                combinedRisk = RiskLevel.Critical;
                var matchedRules = string.Join(", ",
                    matchedResults.SelectMany(r => r.MatchedRules).Distinct());
                summary = $"[双层确认] ETW 检测到 {etwAlert.BehaviorType} 行为，" +
                          $"YARA 匹配规则: {matchedRules} | 进程: {etwAlert.ProcessName} (PID={etwAlert.ProcessId})";
            }
            else
            {
                // 仅 ETW 检测到异常行为，YARA 未匹配已知特征
                layer = DefenseLayer.Etw;
                combinedRisk = etwAlert.RiskLevel;
                summary = $"[ETW 单层] 检测到 {etwAlert.BehaviorType} 行为但 YARA 未匹配已知特征，" +
                          $"进程: {etwAlert.ProcessName} (PID={etwAlert.ProcessId}) | {etwAlert.Description}";
            }

            var defenseAlert = new DefenseAlert
            {
                Layer = layer,
                EtwAlert = etwAlert,
                YaraResult = matchedResults.FirstOrDefault(),
                RiskLevel = combinedRisk,
                Summary = summary,
                ResponseActions = new List<ResponseAction>(),
                DetectedAt = DateTime.Now
            };

            ExecuteResponseChain(defenseAlert, etwAlert.ProcessId, etwAlert.ProcessName);
            RaiseAlert(defenseAlert);
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, $"[RansomDefenseEngine] ETW 告警处理异常 PID={etwAlert.ProcessId}");
        }
    }

    #endregion

    #region 风险响应链

    /// <summary>
    /// 执行风险响应链
    /// <para>顺序：挂起进程 → 防火墙断网 → 锁定 VSS 备份</para>
    /// <para>弹窗告警由 AlertRaised 事件回调方处理（UI 层）</para>
    /// </summary>
    private void ExecuteResponseChain(DefenseAlert alert, int processId, string processName)
    {
        // Critical 级别：执行完整响应链
        if (alert.RiskLevel >= RiskLevel.Critical)
        {
            // 1. 挂起进程
            if (_processGuard.QuarantineProcess(processId, processName,
                alert.Summary))
            {
                alert.ResponseActions.Add(ResponseAction.ProcessSuspended);
                ErrorReporter.Log($"[RansomDefenseEngine] 进程已挂起: PID={processId} {processName}");
            }

            // 2. 防火墙断网
            var exePath = GetProcessExePath(processId);
            if (!string.IsNullOrEmpty(exePath))
            {
                try
                {
                    var ruleName = "LightGuard_Defense_" + Path.GetFileNameWithoutExtension(exePath);
                    FirewallHelper.BlockProgram(ruleName, exePath);
                    alert.ResponseActions.Add(ResponseAction.FirewallBlocked);
                    ErrorReporter.Log($"[RansomDefenseEngine] 已断网: {exePath}");
                }
                catch (Exception ex)
                {
                    ErrorReporter.Report(ex, $"[RansomDefenseEngine] 防火墙断网失败 PID={processId}");
                }
            }

            // 3. 锁定 VSS 备份（防止被删除）
            LockVssBackups();
            alert.ResponseActions.Add(ResponseAction.VssLocked);
        }
        // High 级别：仅挂起进程
        else if (alert.RiskLevel >= RiskLevel.High)
        {
            if (_processGuard.QuarantineProcess(processId, processName,
                alert.Summary))
            {
                alert.ResponseActions.Add(ResponseAction.ProcessSuspended);
                ErrorReporter.Log($"[RansomDefenseEngine] 进程已挂起（High 级别）: PID={processId} {processName}");
            }
        }

        // 标记弹窗告警动作
        alert.ResponseActions.Add(ResponseAction.AlertShown);
    }

    /// <summary>
    /// 锁定 VSS 备份 — 创建应急快照并记录现有卷影副本，阻止勒索病毒清空 VSS
    /// </summary>
    private static void LockVssBackups()
    {
        try
        {
            // 1. 记录当前所有 VSS 卷影副本 ID（用于后续检测是否被删除）
            var existingShadows = new List<string>();
            var listPsi = new ProcessStartInfo
            {
                FileName = "cmd.exe",
                Arguments = "/c vssadmin list shadows",
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true
            };
            using (var listProc = Process.Start(listPsi))
            {
                if (listProc != null)
                {
                    var output = listProc.StandardOutput.ReadToEnd();
                    listProc.WaitForExit(5000);
                    foreach (var line in output.Split('\n', StringSplitOptions.RemoveEmptyEntries))
                    {
                        var trimmed = line.Trim();
                        if (trimmed.Contains("Shadow Copy ID:", StringComparison.OrdinalIgnoreCase))
                        {
                            existingShadows.Add(trimmed);
                        }
                    }
                }
            }

            // 2. 为所有固定卷创建应急 VSS 快照（勒索病毒攻击前的保命快照）
            foreach (var drive in DriveInfo.GetDrives())
            {
                if (drive.DriveType != DriveType.Fixed || !drive.IsReady) continue;
                var volume = drive.Name[0]; // 取盘符首字母
                try
                {
                    var snapPsi = new ProcessStartInfo
                    {
                        FileName = "cmd.exe",
                        Arguments = $"/c vssadmin create shadow /for={volume}: 2>&1",
                        UseShellExecute = false,
                        CreateNoWindow = true,
                        RedirectStandardOutput = true
                    };
                    using var snapProc = Process.Start(snapPsi);
                    snapProc?.WaitForExit(10000);
                }
                catch { }
            }

            // 3. 通过 NTFS 权限临时限制 vssadmin.exe 和 wmic.exe 的执行（阻止勒索病毒调用）
            foreach (var exeName in new[] { "vssadmin.exe", "wmic.exe" })
            {
                var exePath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), exeName);
                if (!File.Exists(exePath)) continue;
                try
                {
                    // 移除普通用户执行权限，仅保留 SYSTEM 和 Administrators
                    var icaclsPsi = new ProcessStartInfo
                    {
                        FileName = "icacls.exe",
                        Arguments = $"\"{exePath}\" /inheritance:r /grant:r \"SYSTEM:(RX)\" \"Administrators:(RX)\"",
                        UseShellExecute = false,
                        CreateNoWindow = true,
                        RedirectStandardOutput = true
                    };
                    using var icaclsProc = Process.Start(icaclsPsi);
                    icaclsProc?.WaitForExit(5000);
                }
                catch { }
            }

            ErrorReporter.Log($"[RansomDefenseEngine] VSS 应急保护已启动：记录 {existingShadows.Count} 个现有快照，已创建应急快照，已限制 vssadmin/wmic 执行权限");
            AuditLogSystem.Log(LogLevel.Critical, LogCategory.System,
                "VSS 应急保护已启动",
                $"现有卷影副本 {existingShadows.Count} 个，已创建应急快照并限制 vssadmin/wmic 权限");
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, "[RansomDefenseEngine] 锁定 VSS 备份异常");
        }
    }

    /// <summary>
    /// 获取进程的可执行文件路径
    /// </summary>
    private static string GetProcessExePath(int pid)
    {
        try
        {
            using var proc = Process.GetProcessById(pid);
            return proc.MainModule?.FileName ?? "";
        }
        catch
        {
            return "";
        }
    }

    #endregion

    #region 告警管理

    /// <summary>
    /// 触发告警事件
    /// </summary>
    private void RaiseAlert(DefenseAlert alert)
    {
        lock (_lock)
        {
            _alertHistory.Add(alert);
            if (_alertHistory.Count > MaxAlertHistory)
            {
                _alertHistory.RemoveAt(0);
            }
        }

        ErrorReporter.Log(
            $"[RansomDefenseEngine] 防御告警: Layer={alert.Layer} Risk={alert.RiskLevel} | {alert.Summary}",
            alert.RiskLevel >= RiskLevel.Critical ? "ERROR" : "WARN");

        AlertRaised?.Invoke(alert);
    }

    /// <summary>
    /// 获取告警历史记录
    /// </summary>
    public List<DefenseAlert> GetAlertHistory()
    {
        lock (_lock) return _alertHistory.ToList();
    }

    /// <summary>
    /// 获取 YARA 引擎实例（供外部调用按需扫描）
    /// </summary>
    public YaraEngine GetYaraEngine() => _yaraEngine;

    /// <summary>
    /// 获取 ETW 行为监控器实例
    /// </summary>
    public EtwBehaviorMonitor GetEtwMonitor() => _etwMonitor;

    /// <summary>
    /// 获取 ProcessGuard 实例（供 RansomwareModule 共享，避免重复实例化）
    /// </summary>
    public ProcessGuard GetProcessGuard() => _processGuard;

    #endregion

    #region IDisposable

    /// <summary>
    /// 释放资源
    /// </summary>
    public void Dispose()
    {
        Stop();
        _etwMonitor.Dispose();
        _yaraEngine.Dispose();
        _processGuard.Dispose();
        GC.SuppressFinalize(this);
    }

    #endregion
}

#region 数据类型

/// <summary>
/// 防御层级枚举
/// </summary>
public enum DefenseLayer
{
    /// <summary>仅 ETW 行为监控层</summary>
    Etw,

    /// <summary>仅 YARA 特征核验层</summary>
    Yara,

    /// <summary>ETW + YARA 双层确认</summary>
    Dual
}

/// <summary>
/// 风险响应动作枚举
/// </summary>
public enum ResponseAction
{
    /// <summary>进程已挂起</summary>
    ProcessSuspended,

    /// <summary>防火墙已断网</summary>
    FirewallBlocked,

    /// <summary>弹窗告警已显示</summary>
    AlertShown,

    /// <summary>VSS 备份已锁定</summary>
    VssLocked
}

/// <summary>
/// 防御告警信息
/// </summary>
public sealed class DefenseAlert
{
    /// <summary>防御层级（ETW / YARA / Dual）</summary>
    public DefenseLayer Layer { get; set; }

    /// <summary>ETW 行为告警详情</summary>
    public RansomBehaviorAlert? EtwAlert { get; set; }

    /// <summary>YARA 扫描结果（如有）</summary>
    public YaraScanResult? YaraResult { get; set; }

    /// <summary>综合风险等级</summary>
    public RiskLevel RiskLevel { get; set; }

    /// <summary>告警摘要</summary>
    public string Summary { get; set; } = "";

    /// <summary>已执行的响应动作列表</summary>
    public List<ResponseAction> ResponseActions { get; set; } = new();

    /// <summary>检测时间</summary>
    public DateTime DetectedAt { get; set; }

    public override string ToString()
    {
        var actions = ResponseActions.Count > 0
            ? string.Join(", ", ResponseActions)
            : "无";
        return $"[{Layer}] {RiskLevel} | {Summary} | 响应: {actions} | {DetectedAt:HH:mm:ss}";
    }
}

#endregion
