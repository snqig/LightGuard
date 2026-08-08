// © 2026 落尘（Luochen） 原创开发 - 保留所有权利

using LightGuard.Audit;
using LightGuard.Core;
using LightGuard.Core.Interfaces;

namespace LightGuard.Modules;

/// <summary>
/// SMB 文件服务器审计模块
/// <para>整合 SmbAuditCollector（双采集融合）与 SmbRiskDetector（风险行为识别）。</para>
/// <para>采集来源：NTFS SACL 安全事件日志 + ETW 实时事件。</para>
/// <para>监控行为：SMB 远程登录、文件读写/删除/移动/重命名、权限篡改、越权访问。</para>
/// <para>风险识别：批量文件外泄、凌晨非工作时段访问、高频删除、备份目录异常访问。</para>
/// </summary>
public sealed class SmbAuditModule : ModuleBase
{
    #region 字段

    /// <summary>SMB 审计采集器实例</summary>
    private SmbAuditCollector? _collector;

    /// <summary>SMB 风险行为识别引擎实例</summary>
    private SmbRiskDetector? _riskDetector;

    /// <summary>审计记录持久化存储（JSONL 按天分片，P1-2）</summary>
    private AuditLogStorage? _storage;

    /// <summary>风险事件持久化存储（P1-2）</summary>
    private SmbRiskStore? _riskStore;

    /// <summary>每日保留策略清理定时器（P1-2）</summary>
    private System.Threading.Timer? _cleanupTimer;

    /// <summary>审计记录保留天数（与 SmbDeployConfig.LogRetentionDays 默认一致）</summary>
    private const int RetentionDays = 90;

    /// <summary>累计审计记录数</summary>
    private int _totalRecords;

    /// <summary>累计风险事件数</summary>
    private int _totalRiskEvents;

    #endregion

    #region 构造与模块信息

    /// <summary>
    /// 构造 SMB 文件服务器审计模块
    /// </summary>
    /// <param name="appState">全局应用状态</param>
    public SmbAuditModule(AppState appState) : base(appState)
    {
    }

    /// <inheritdoc/>
    public override string Id => "smb-audit";

    /// <inheritdoc/>
    public override string DisplayName => "SMB文件服务器审计";

    /// <inheritdoc/>
    public override string Description =>
        "SMB 文件服务器审计与风险识别：双采集融合（NTFS SACL + ETW），" +
        "监控远程登录、文件操作、权限篡改，识别批量外泄、凌晨访问、高频删除等风险行为";

    /// <inheritdoc/>
    public override ModuleCategory Category => ModuleCategory.Audit;

    /// <inheritdoc/>
    public override bool RequiresAdmin => true;

    #endregion

    #region 生命周期

    /// <summary>
    /// 初始化审计采集器、风险检测器与持久化存储
    /// </summary>
    protected override Task OnInitializeAsync()
    {
        // 初始化审计采集器
        _collector = new SmbAuditCollector();

        // 初始化风险检测器（传入受保护的备份目录路径）
        var backupPaths = AppState.Config.Backup.ProtectedFolders;
        _riskDetector = new SmbRiskDetector(backupPaths);

        // P1-2：审计记录持久化（JSONL 按天分片）
        var auditDir = Path.Combine(ConfigManager.GetDataDir(), "smb_audit");
        _storage = new AuditLogStorage(Path.Combine(auditDir, "records"));
        _riskStore = new SmbRiskStore(Path.Combine(auditDir, "risks"));

        // 订阅采集器的审计记录事件
        _collector.AuditEntryRecorded += OnAuditEntryRecorded;

        // 订阅风险检测器的事件
        _riskDetector.RiskDetected += OnRiskDetected;

        ErrorReporter.Log("[SmbAuditModule] 初始化完成 | SmbAuditCollector + SmbRiskDetector + 持久化存储");

        return Task.CompletedTask;
    }

    /// <summary>
    /// 启动审计采集、风险检测与每日保留策略清理
    /// </summary>
    protected override Task OnEnableAsync()
    {
        _riskDetector?.Start();
        _collector?.Start();

        // P1-2：启动时清理过期记录 + 每日定时清理
        TryPurgeRetention();
        _cleanupTimer = new System.Threading.Timer(
            callback: _ => TryPurgeRetention(),
            state: null,
            dueTime: TimeSpan.FromHours(6),
            period: TimeSpan.FromDays(1));

        ErrorReporter.Log("[SmbAuditModule] SMB 审计采集与风险检测已启动（含保留策略清理）");

        return Task.CompletedTask;
    }

    /// <summary>
    /// 停止审计采集和风险检测
    /// </summary>
    protected override Task OnDisableAsync()
    {
        _cleanupTimer?.Dispose();
        _cleanupTimer = null;

        _collector?.Stop();
        _riskDetector?.Stop();

        ErrorReporter.Log("[SmbAuditModule] SMB 审计采集与风险检测已停止");

        return Task.CompletedTask;
    }

    /// <summary>
    /// 释放资源
    /// </summary>
    protected override void OnReleaseResources()
    {
        _cleanupTimer?.Dispose();
        _cleanupTimer = null;

        if (_collector != null)
        {
            _collector.AuditEntryRecorded -= OnAuditEntryRecorded;
            _collector.Dispose();
            _collector = null;
        }

        if (_riskDetector != null)
        {
            _riskDetector.RiskDetected -= OnRiskDetected;
            _riskDetector.Dispose();
            _riskDetector = null;
        }

        _storage?.Dispose();
        _storage = null;
        _riskStore?.Dispose();
        _riskStore = null;
    }

    #endregion

    #region 事件处理

    /// <summary>
    /// 审计记录回调 — 持久化 + 转发给风险检测器
    /// </summary>
    private void OnAuditEntryRecorded(SmbAuditEntry entry)
    {
        _totalRecords++;

        // P1-2：异步持久化（映射为存储模型，fire-and-forget，失败不影响采集）
        PersistEntry(entry);

        // 将审计记录转发给风险检测器进行分析
        _riskDetector?.AddEntry(entry);
    }

    /// <summary>
    /// 风险事件回调 — 持久化 + 告警通知
    /// </summary>
    private void OnRiskDetected(SmbRiskEvent riskEvent)
    {
        _totalRiskEvents++;

        ErrorReporter.Log(
            $"[SmbAuditModule] 风险事件 #{_totalRiskEvents}: {riskEvent}",
            riskEvent.Severity >= RiskLevel.Critical ? "ERROR" : "WARN");

        // P1-2：风险事件持久化（跨重启追溯）
        var risk = riskEvent;
        Task.Run(async () =>
        {
            try { if (_riskStore != null) await _riskStore.StoreAsync(risk); }
            catch { /* 持久化失败不阻断 */ }
        });

        // P1-2：告警通知（钉钉/企微 Webhook，配置启用时）
        _ = AlertNotifier.NotifyAsync(riskEvent.Title, riskEvent.Description, riskEvent.Severity);
    }

    /// <summary>
    /// 将采集记录映射为存储模型并异步持久化。
    /// </summary>
    private void PersistEntry(SmbAuditEntry entry)
    {
        if (_storage == null) return;
        var evt = new SmbAuditEvent
        {
            Timestamp = entry.Time,
            UserName = entry.UserName,
            ClientIp = entry.ClientIp,
            FilePath = entry.FilePath,
            Action = entry.Operation.ToString(),
            Result = entry.IsRemote ? "Remote" : "Local",
            RawEvent = entry.RiskTag
        };
        Task.Run(async () =>
        {
            try { await _storage.StoreAsync(evt); }
            catch { /* 持久化失败不阻断采集 */ }
        });
    }

    /// <summary>
    /// 执行保留策略清理（审计记录 + 风险事件，失败静默）。
    /// </summary>
    private void TryPurgeRetention()
    {
        try
        {
            if (_storage != null)
                _ = _storage.PurgeAsync(RetentionDays);
            _riskStore?.Purge(RetentionDays);
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, "[SmbAuditModule] 保留策略清理异常");
        }
    }

    #endregion

    #region 状态摘要

    /// <summary>
    /// 获取审计状态摘要
    /// </summary>
    protected override string GetStatusSummary()
    {
        if (!IsEnabled || _collector == null)
            return "已停止";

        var recordCount = _collector.GetRecordCount();
        var riskHistory = _riskDetector?.GetRiskHistory() ?? new List<SmbRiskEvent>();
        var criticalRisks = riskHistory.Count(r => r.Severity >= RiskLevel.Critical);

        return $"运行中 | 审计记录 {recordCount} 条 | " +
               $"风险事件 {riskHistory.Count} 次（Critical {criticalRisks}）";
    }

    #endregion

    #region 公共接口

    /// <summary>
    /// 获取审计采集器实例（供 UI 调用）
    /// </summary>
    public SmbAuditCollector? GetCollector() => _collector;

    /// <summary>
    /// 获取风险检测器实例（供 UI 调用）
    /// </summary>
    public SmbRiskDetector? GetRiskDetector() => _riskDetector;

    /// <summary>
    /// 获取审计记录列表
    /// </summary>
    public List<SmbAuditEntry> GetAuditRecords()
    {
        return _collector?.GetRecords() ?? new List<SmbAuditEntry>();
    }

    /// <summary>
    /// 获取风险事件历史记录
    /// </summary>
    public List<SmbRiskEvent> GetRiskHistory()
    {
        return _riskDetector?.GetRiskHistory() ?? new List<SmbRiskEvent>();
    }

    /// <summary>
    /// 一键配置服务器安全策略（开启文件审核）
    /// </summary>
    public bool ConfigureSecurityPolicy()
    {
        return _collector?.ConfigureSecurityPolicy() ?? false;
    }

    /// <summary>
    /// 查询历史审计记录（跨重启持久化数据，P1-2）。
    /// <para>支持按时间范围 / 用户名 / 文件路径 / 操作类型筛选。</para>
    /// </summary>
    public async Task<List<SmbAuditEvent>> QueryHistoricalRecords(AuditQueryFilter? filter = null)
    {
        if (_storage == null) return new List<SmbAuditEvent>();
        return await _storage.QueryAsync(filter ?? new AuditQueryFilter());
    }

    /// <summary>
    /// 查询持久化的风险事件历史（跨重启，P1-2），最近 <paramref name="count"/> 条。
    /// </summary>
    public async Task<List<SmbRiskEvent>> GetPersistentRiskHistory(int count = 100)
    {
        if (_riskStore == null) return new List<SmbRiskEvent>();
        return await _riskStore.QueryRecentAsync(count);
    }

    /// <summary>
    /// 立即执行保留策略清理（审计记录 + 风险事件，P1-2）。
    /// </summary>
    public void PurgeRetentionNow()
    {
        TryPurgeRetention();
    }

    #endregion
}
