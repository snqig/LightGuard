using LightGuard.Core;
using LightGuard.Core.Interfaces;
using LightGuard.Defender;
using Timer = System.Threading.Timer;

namespace LightGuard.Modules;

/// <summary>
/// Defender 查杀调度模块（P0-4 / P1-5 Defender 全业务集成）
/// 封装 Microsoft Defender MpCmdRun.exe 的按需查杀能力，统一对外暴露：
///   - 引擎/病毒库健康状态查询
///   - 单文件 / 目录 / 快速 / 全盘扫描
///   - 病毒库签名更新（手动 + 过期自动）
///   - 扫描历史与威胁清单管理（持久化到磁盘，重启不丢）
///   - 每日定时扫描调度 + 实时保护状态监控 + 威胁 Webhook 告警（P1-5）
/// 模块生命周期与 DefenderScannerHelper 绑定：启用时创建、禁用时释放。
/// </summary>
public sealed class DefenderScanModule : ModuleBase
{
    /// <summary>核心扫描助手（启用后非空）</summary>
    private DefenderScannerHelper? _scanner;

    /// <summary>扫描历史记录（最近的扫描结果）</summary>
    private readonly List<DefenderScanResult> _history = new();

    /// <summary>累计发现的威胁清单</summary>
    private readonly List<DefenderThreat> _threats = new();

    /// <summary>缓存的状态信息（避免频繁拉起 PowerShell）</summary>
    private LightGuard.Defender.DefenderStatusInfo? _cachedStatus;

    // ==================== P1-5 调度字段 ====================

    /// <summary>每日调度定时器（每分钟 tick）</summary>
    private Timer? _scheduleTimer;

    /// <summary>最近一次定时扫描的日期（防同日重复触发）</summary>
    private DateTime? _lastScheduledScanDate;

    /// <summary>最近一次病毒库过期检查日期（每日一次）</summary>
    private DateTime? _lastSignatureCheckDate;

    /// <summary>最近一次实时保护异常告警日期（每日限流一次）</summary>
    private DateTime? _lastProtectionAlertDate;

    /// <summary>定时扫描是否进行中（防重入）</summary>
    private bool _scanInProgress;

    /// <summary>调度状态锁</summary>
    private readonly object _scheduleLock = new();

    public DefenderScanModule(AppState appState) : base(appState)
    {
    }

    /// <inheritdoc/>
    public override string Id => "defender-scan";

    /// <inheritdoc/>
    public override string DisplayName => "Defender查杀调度";

    /// <inheritdoc/>
    public override string Description =>
        "Microsoft Defender 按需查杀调度引擎：单文件/目录/快速/全盘扫描、病毒库更新、" +
        "威胁与历史持久化、每日定时扫描与保护监控";

    /// <inheritdoc/>
    public override ModuleCategory Category => ModuleCategory.Core;

    /// <inheritdoc/>
    public override bool RequiresAdmin => true;

    /// <summary>对外暴露的扫描助手（其他模块可复用，例如备份前自动查杀）</summary>
    public DefenderScannerHelper? Scanner => _scanner;

    // ==================== 生命周期 ====================

    /// <inheritdoc/>
    protected override async Task OnInitializeAsync()
    {
        await Task.Run(() =>
        {
            // 加载持久化的扫描历史与威胁清单（P1-5：重启不丢失）
            var (history, threats) = DefenderScanStore.Load();
            lock (_history) _history.AddRange(history);
            lock (_threats) _threats.AddRange(threats);

            // 探测 Defender 是否可用并记录状态
            using var probe = new DefenderScannerHelper();
            var available = probe.IsDefenderAvailable();
            var isAdmin = probe.IsRunningAsAdmin();

            ErrorReporter.Log(
                $"Defender 查杀模块初始化 - MpCmdRun可用:{available} 管理员:{isAdmin} " +
                $"历史:{_history.Count} 条 / 威胁:{_threats.Count} 条");

            if (available)
            {
                try
                {
                    _cachedStatus = probe.GetDefenderStatus();
                    ErrorReporter.Log(
                        $"Defender 状态 - 实时保护:{_cachedStatus.RealTimeProtectionEnabled} " +
                        $"反病毒:{_cachedStatus.AntivirusEnabled} " +
                        $"病毒库:{_cachedStatus.SignatureVersion} " +
                        $"引擎:{_cachedStatus.EngineVersion} " +
                        $"健康:{_cachedStatus.IsHealthy}");
                }
                catch (Exception ex)
                {
                    ErrorReporter.Report(ex, "初始化时获取 Defender 状态失败");
                }
            }
            else
            {
                ErrorReporter.Log("Microsoft Defender 不可用，查杀模块将以降级模式运行", "WARN");
            }
        });
    }

    /// <inheritdoc/>
    protected override async Task OnEnableAsync()
    {
        await Task.Run(() =>
        {
            _scanner = new DefenderScannerHelper();
            StartScheduleTimer();
            ErrorReporter.Log("Defender 查杀模块已启用，扫描助手已就绪，每日调度已启动");
        });
    }

    /// <inheritdoc/>
    protected override async Task OnDisableAsync()
    {
        await Task.Run(() =>
        {
            StopScheduleTimer();
            PersistData();
            _scanner?.Dispose();
            _scanner = null;
            ErrorReporter.Log("Defender 查杀模块已禁用，扫描助手已释放");
        });
    }

    /// <inheritdoc/>
    protected override void OnReleaseResources()
    {
        StopScheduleTimer();
        PersistData();
        _scanner?.Dispose();
        _scanner = null;
        _history.Clear();
        _threats.Clear();
    }

    // ==================== 对外查询/操作 ====================

    /// <summary>获取当前 Defender 状态（启用时实时查询，未启用时返回缓存）</summary>
    public LightGuard.Defender.DefenderStatusInfo GetDefenderStatus()
    {
        if (_scanner != null)
        {
            try
            {
                _cachedStatus = _scanner.GetDefenderStatus();
            }
            catch (Exception ex)
            {
                ErrorReporter.Report(ex, "DefenderScanModule 获取状态失败");
            }
        }
        return _cachedStatus ?? new LightGuard.Defender.DefenderStatusInfo { ErrorMessage = "模块未启用" };
    }

    /// <summary>获取扫描历史副本</summary>
    public List<DefenderScanResult> GetScanHistory()
    {
        lock (_history)
        {
            return _history.ToList();
        }
    }

    /// <summary>获取累计威胁清单副本</summary>
    public List<DefenderThreat> GetThreatList()
    {
        lock (_threats)
        {
            return _threats.ToList();
        }
    }

    /// <summary>记录一次扫描结果，并合并其威胁到累计清单（P1-5：同步持久化）</summary>
    public void RecordScan(DefenderScanResult result)
    {
        if (result == null) return;

        lock (_history)
        {
            _history.Add(result);
            // 仅保留最近 200 条
            if (_history.Count > DefenderScanStore.MaxHistory)
                _history.RemoveRange(0, _history.Count - DefenderScanStore.MaxHistory);
        }

        if (result.Threats.Count > 0)
        {
            lock (_threats)
            {
                _threats.AddRange(result.Threats);
                if (_threats.Count > DefenderScanStore.MaxThreats)
                    _threats.RemoveRange(0, _threats.Count - DefenderScanStore.MaxThreats);
            }
        }

        PersistData();
    }

    /// <summary>清空扫描历史（P1-5：同步清理持久化）</summary>
    public void ClearHistory()
    {
        lock (_history) _history.Clear();
        DefenderScanStore.Clear();
    }

    /// <summary>
    /// 更新指定威胁的处置动作（事后处置联动，P1-5）并持久化。
    /// <para>威胁清单 UI 中执行隔离/删除/允许后回写处置状态，重启后保留。</para>
    /// </summary>
    /// <param name="threatName">威胁名称</param>
    /// <param name="filePath">受影响的文件路径</param>
    /// <param name="action">处置动作</param>
    public void UpdateThreatAction(string threatName, string filePath, ThreatAction action)
    {
        if (string.IsNullOrWhiteSpace(threatName) || string.IsNullOrWhiteSpace(filePath)) return;
        lock (_threats)
        {
            foreach (var t in _threats)
            {
                if (t.ThreatName == threatName &&
                    string.Equals(t.FilePath, filePath, StringComparison.OrdinalIgnoreCase))
                {
                    t.ActionTaken = action;
                    break;
                }
            }
        }
        PersistData();
    }

    /// <summary>触发病毒库签名更新</summary>
    public async Task UpdateSignaturesAsync()
    {
        if (_scanner == null)
        {
            ErrorReporter.Log("病毒库更新失败：Defender 查杀模块未启用", "WARN");
            return;
        }
        await _scanner.UpdateSignaturesAsync();
        // 更新后刷新缓存状态
        _cachedStatus = _scanner.GetDefenderStatus();
    }

    // ==================== P1-5 调度与联动 ====================

    /// <summary>启动每日调度定时器（每分钟 tick，检查定时扫描 / 病毒库过期 / 实时保护）。</summary>
    private void StartScheduleTimer()
    {
        StopScheduleTimer();
        lock (_scheduleLock)
        {
            _scheduleTimer = new Timer(_ => OnScheduleTick(), null,
                TimeSpan.FromSeconds(30), TimeSpan.FromMinutes(1));
        }
    }

    /// <summary>停止每日调度定时器。</summary>
    private void StopScheduleTimer()
    {
        lock (_scheduleLock)
        {
            _scheduleTimer?.Dispose();
            _scheduleTimer = null;
        }
    }

    /// <summary>每日调度 tick：定时扫描 → 病毒库过期自动更新 → 实时保护监控告警。</summary>
    private void OnScheduleTick()
    {
        try
        {
            var now = DateTime.Now;
            var cfg = AppState.Config.Defender;

            // 1. 每日定时扫描（时间匹配且当日未执行过，防重入）
            if (cfg.ScheduleEnabled && _scanner != null && !_scanInProgress &&
                IsScheduledTimeDue(cfg.ScanTime, now, _lastScheduledScanDate))
            {
                _ = Task.Run(() => RunScheduledScanAsync());
            }

            // 2. 病毒库过期自动更新（每日检查一次）
            if (cfg.AutoUpdateSignatures && _scanner != null &&
                (_lastSignatureCheckDate == null || _lastSignatureCheckDate.Value.Date != now.Date))
            {
                _lastSignatureCheckDate = now;
                if (IsSignatureOutdated(_cachedStatus, cfg.SignatureMaxAgeDays))
                {
                    ErrorReporter.Log($"[Defender] 病毒库过期（阈值 {cfg.SignatureMaxAgeDays} 天），自动更新中...", "WARN");
                    _ = Task.Run(async () =>
                    {
                        try { await UpdateSignaturesAsync(); }
                        catch (Exception ex) { ErrorReporter.Report(ex, "病毒库自动更新失败"); }
                    });
                }
            }

            // 3. 实时保护状态监控（每日限流一次告警）
            if (cfg.AlertOnProtectionDisabled && _scanner != null &&
                (_lastProtectionAlertDate == null || _lastProtectionAlertDate.Value.Date != now.Date))
            {
                _lastProtectionAlertDate = now;
                CheckProtectionHealth();
            }
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, "Defender 调度 tick 异常");
        }
    }

    /// <summary>执行定时扫描（快速/全盘，按配置），结果入库 + 威胁告警。</summary>
    private async Task RunScheduledScanAsync()
    {
        if (_scanner == null) return;
        lock (_scheduleLock)
        {
            if (_scanInProgress) return;
            _scanInProgress = true;
            _lastScheduledScanDate = DateTime.Now.Date;
        }
        try
        {
            var cfg = AppState.Config.Defender;
            var isQuick = !string.Equals(cfg.ScheduleScanType, "FullScan", StringComparison.OrdinalIgnoreCase);
            var result = isQuick
                ? await _scanner.QuickScanAsync(CancellationToken.None)
                : await _scanner.FullScanAsync(CancellationToken.None);
            result.ScanType = isQuick ? DefenderScanType.QuickScan : DefenderScanType.FullScan;

            RecordScan(result);
            if (result.Threats.Count > 0)
                NotifyThreat(result, "定时扫描");

            ErrorReporter.Log($"[Defender] 定时扫描完成：{result.ScanType}，威胁 {result.ThreatsFound}，耗时 {result.ScanDuration.TotalSeconds:F0}s");
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, "Defender 定时扫描异常");
        }
        finally
        {
            lock (_scheduleLock) _scanInProgress = false;
        }
    }

    /// <summary>发现威胁时经 AlertNotifier 外发告警（钉钉/企微，P1-5）。</summary>
    private void NotifyThreat(DefenderScanResult result, string source)
    {
        var cfg = AppState.Config.Defender;
        if (!cfg.AlertOnThreat) return;

        var severity = result.Threats.Any(t => t.Severity >= ThreatSeverity.High)
            ? RiskLevel.Critical
            : RiskLevel.High;
        var names = string.Join("、", result.ThreatNames.Take(5));
        _ = AlertNotifier.NotifyAsync(
            $"Defender 发现 {result.Threats.Count} 个威胁（{source}）",
            $"威胁：{names}\n扫描类型：{DefenderIntegrationService.TypeName(result.ScanType)}\n" +
            $"处置策略：{cfg.ThreatAction}\n时间：{DateTime.Now:yyyy-MM-dd HH:mm}",
            severity);
    }

    /// <summary>实时保护 / 引擎健康检查，异常时 Webhook 告警（每日限流）。</summary>
    private void CheckProtectionHealth()
    {
        try
        {
            if (_scanner == null) return;
            var status = GetDefenderStatus();
            if (!status.IsValid) return;

            if (!status.RealTimeProtectionEnabled)
            {
                ErrorReporter.Log("[Defender] 实时保护已关闭！", "WARN");
                _ = AlertNotifier.NotifyAsync(
                    "Defender 实时保护已关闭",
                    "检测到 Microsoft Defender 实时保护被关闭，建议立即开启以抵御勒索与恶意软件。\n" +
                    $"时间：{DateTime.Now:yyyy-MM-dd HH:mm}",
                    RiskLevel.Critical);
            }
            else if (!status.IsHealthy)
            {
                ErrorReporter.Log("[Defender] 引擎健康状态异常（可能病毒库过期）", "WARN");
                _ = AlertNotifier.NotifyAsync(
                    "Defender 引擎异常",
                    "Defender 整体健康状态异常（病毒库可能过期或引擎异常），建议更新病毒库。\n" +
                    $"时间：{DateTime.Now:yyyy-MM-dd HH:mm}",
                    RiskLevel.High);
            }
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, "Defender 保护健康检查异常");
        }
    }

    /// <summary>持久化当前历史与威胁（写盘失败不抛出）。</summary>
    private void PersistData()
    {
        List<DefenderScanResult> historySnapshot;
        List<DefenderThreat> threatsSnapshot;
        lock (_history) historySnapshot = _history.ToList();
        lock (_threats) threatsSnapshot = _threats.ToList();
        DefenderScanStore.Save(historySnapshot, threatsSnapshot);
    }

    // ==================== 调度判定（静态，便于测试） ====================

    /// <summary>
    /// 判断是否到达每日定时扫描时刻：HH:mm 匹配且当日尚未执行。
    /// </summary>
    /// <param name="scanTime">配置的扫描时间（HH:mm）</param>
    /// <param name="now">当前时间</param>
    /// <param name="lastRunDate">当日已执行过的日期（null 表示未执行）</param>
    public static bool IsScheduledTimeDue(string scanTime, DateTime now, DateTime? lastRunDate)
    {
        if (lastRunDate != null && lastRunDate.Value.Date == now.Date) return false;
        if (string.IsNullOrWhiteSpace(scanTime) || !TimeSpan.TryParse(scanTime, out var t)) return false;
        return now.Hour == t.Hours && now.Minute == t.Minutes;
    }

    /// <summary>
    /// 判断病毒库是否过期（超出最大天数阈值）。
    /// <para>状态无效返回 false（无法判定）；最后更新时间为默认值时视为过期（建议更新）。</para>
    /// </summary>
    /// <param name="status">Defender 状态（可为 null）</param>
    /// <param name="maxAgeDays">过期天数阈值（&lt;=0 表示不判定）</param>
    public static bool IsSignatureOutdated(LightGuard.Defender.DefenderStatusInfo? status, int maxAgeDays)
    {
        if (status == null || !status.IsValid) return false;
        if (maxAgeDays <= 0) return false;
        if (status.SignatureLastUpdated == default) return true; // 未知 → 视为过期
        return (DateTime.Now - status.SignatureLastUpdated).TotalDays > maxAgeDays;
    }

    /// <inheritdoc/>
    protected override string GetStatusSummary()
    {
        if (_scanner == null)
            return "未启用";

        var status = _cachedStatus;
        if (status == null || !status.IsValid)
            return "运行中（状态未知）";

        var health = status.IsHealthy ? "健康" : "需关注";
        var sigAge = status.SignatureLastUpdated == default
            ? "未知"
            : $"{(int)(DateTime.Now - status.SignatureLastUpdated).TotalDays}天前";
        var schedule = AppState.Config.Defender.ScheduleEnabled
            ? $"定时{AppState.Config.Defender.ScanTime}"
            : "定时关";
        return $"实时保护:{(status.RealTimeProtectionEnabled ? "开" : "关")} " +
               $"病毒库:{status.SignatureVersion}({sigAge}) " +
               $"| {health} | {schedule} | 历史:{_history.Count} 条";
    }

    /// <inheritdoc/>
    public override void Dispose()
    {
        StopScheduleTimer();
        PersistData();
        _scanner?.Dispose();
        _scanner = null;
        base.Dispose();
    }
}
