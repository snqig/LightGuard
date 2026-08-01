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
    /// 初始化审计采集器和风险检测器
    /// </summary>
    protected override Task OnInitializeAsync()
    {
        // 初始化审计采集器
        _collector = new SmbAuditCollector();

        // 初始化风险检测器（传入受保护的备份目录路径）
        var backupPaths = AppState.Config.Backup.ProtectedFolders;
        _riskDetector = new SmbRiskDetector(backupPaths);

        // 订阅采集器的审计记录事件
        _collector.AuditEntryRecorded += OnAuditEntryRecorded;

        // 订阅风险检测器的事件
        _riskDetector.RiskDetected += OnRiskDetected;

        ErrorReporter.Log("[SmbAuditModule] 初始化完成 | SmbAuditCollector + SmbRiskDetector");

        return Task.CompletedTask;
    }

    /// <summary>
    /// 启动审计采集和风险检测
    /// </summary>
    protected override Task OnEnableAsync()
    {
        _riskDetector?.Start();
        _collector?.Start();

        ErrorReporter.Log("[SmbAuditModule] SMB 审计采集与风险检测已启动");

        return Task.CompletedTask;
    }

    /// <summary>
    /// 停止审计采集和风险检测
    /// </summary>
    protected override Task OnDisableAsync()
    {
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
    }

    #endregion

    #region 事件处理

    /// <summary>
    /// 审计记录回调 — 将记录转发给风险检测器
    /// </summary>
    private void OnAuditEntryRecorded(SmbAuditEntry entry)
    {
        _totalRecords++;

        // 将审计记录转发给风险检测器进行分析
        _riskDetector?.AddEntry(entry);
    }

    /// <summary>
    /// 风险事件回调
    /// </summary>
    private void OnRiskDetected(SmbRiskEvent riskEvent)
    {
        _totalRiskEvents++;

        ErrorReporter.Log(
            $"[SmbAuditModule] 风险事件 #{_totalRiskEvents}: {riskEvent}",
            riskEvent.Severity >= RiskLevel.Critical ? "ERROR" : "WARN");
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

    #endregion
}
