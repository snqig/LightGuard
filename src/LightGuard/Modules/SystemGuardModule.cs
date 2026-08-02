// © 2026 落尘（Luochen）原创开发 - 保留所有权利

using LightGuard.Core;
using LightGuard.Core.Interfaces;
using LightGuard.Firewall;
using LightGuard.Security;

namespace LightGuard.Modules;

/// <summary>
/// 系统守护模块
/// <para>整合文件隔离区、操作快照回滚、防火墙规则守护三大安全能力</para>
/// <para>所有可疑文件加密隔离而非直接删除，系统级修改可一键回滚</para>
/// </summary>
public class SystemGuardModule : ModuleBase
{
    private QuarantineManager? _quarantine;
    private SystemSnapshotManager? _snapshots;
    private FirewallGuardian? _fwGuardian;

    public SystemGuardModule(AppState appState) : base(appState)
    {
    }

    /// <inheritdoc/>
    public override string Id => "system-guard";

    /// <inheritdoc/>
    public override string DisplayName => "系统守护与回滚";

    /// <inheritdoc/>
    public override string Description =>
        "文件隔离区(AES加密) + 操作快照一键回滚(注册表/Hosts/防火墙) + 防火墙规则防篡改监控";

    /// <inheritdoc/>
    public override ModuleCategory Category => ModuleCategory.Core;

    /// <inheritdoc/>
    public override bool RequiresAdmin => true;

    /// <summary>获取隔离区管理器</summary>
    public QuarantineManager? GetQuarantineManager() => _quarantine;

    /// <summary>获取快照管理器</summary>
    public SystemSnapshotManager? GetSnapshotManager() => _snapshots;

    /// <summary>获取防火墙守护引擎</summary>
    public FirewallGuardian? GetFirewallGuardian() => _fwGuardian;

    protected override Task OnInitializeAsync()
    {
        _quarantine = new QuarantineManager();
        _snapshots = new SystemSnapshotManager();

        // 防火墙守护引擎需要 FirewallModule 的 AclManager 实例
        var fwModule = AppState.Modules.GetModule("firewall") as FirewallModule;
        if (fwModule?.AclManager != null)
        {
            _fwGuardian = new FirewallGuardian(fwModule.AclManager);
            _fwGuardian.RuleTamperingDetected += OnRuleTampering;
            _fwGuardian.GuardianAlert += OnGuardianAlert;
        }
        else
        {
            ErrorReporter.Log("[SystemGuard] 防火墙模块未就绪，规则守护功能暂不可用");
        }

        // 启动时清理过期数据
        try
        {
            var expiredQuarantine = _quarantine.CleanupExpired();
            var expiredSnapshots = _snapshots.CleanupExpired();
            if (expiredQuarantine > 0 || expiredSnapshots > 0)
            {
                ErrorReporter.Log($"[SystemGuard] 启动清理: 隔离区 {expiredQuarantine} 项, 快照 {expiredSnapshots} 项");
            }
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, "[SystemGuard] 启动清理失败");
        }

        ErrorReporter.Log("[SystemGuard] 系统守护模块初始化完成");
        return Task.CompletedTask;
    }

    protected override Task OnEnableAsync()
    {
        _fwGuardian?.Start();
        ErrorReporter.Log("[SystemGuard] 系统守护已启动（防火墙规则监控+隔离区+快照回滚）");
        AuditLogSystem.Log(LogLevel.Info, LogCategory.System,
            "系统守护模块已启动",
            $"防火墙守护: {(_fwGuardian != null ? "活跃" : "未就绪")} | 隔离区: 就绪 | 快照回滚: 就绪");
        return Task.CompletedTask;
    }

    protected override Task OnDisableAsync()
    {
        _fwGuardian?.Stop();
        ErrorReporter.Log("[SystemGuard] 系统守护已停止");
        return Task.CompletedTask;
    }

    protected override void OnReleaseResources()
    {
        _fwGuardian?.Dispose();
        _quarantine?.Dispose();
        _snapshots?.Dispose();
        _fwGuardian = null;
        _quarantine = null;
        _snapshots = null;
    }

    private void OnRuleTampering(List<RuleChangeRecord> changes)
    {
        foreach (var change in changes)
        {
            AuditLogSystem.Log(LogLevel.Critical, LogCategory.System,
                $"防火墙规则篡改检测: {change.RuleName}",
                $"变更类型: {change.ChangeType} | 详情: {change.Details}");
        }
        ErrorReporter.Log($"[SystemGuard][CRITICAL] 检测到 {changes.Count} 项防火墙规则篡改，已自动回滚", "ERROR");
    }

    private void OnGuardianAlert(string message)
    {
        AuditLogSystem.Log(LogLevel.Warning, LogCategory.System, "防火墙守护告警", message);
    }

    protected override string GetStatusSummary()
    {
        if (!IsEnabled) return "已禁用";
        var quarantineCount = _quarantine?.ListQuarantinedFiles().Count ?? 0;
        var snapshotCount = _snapshots?.ListSnapshots().Count ?? 0;
        var fwGuard = _fwGuardian != null ? "活跃" : "未就绪";
        return $"运行中 | 防火墙守护:{fwGuard} | 隔离文件:{quarantineCount} | 快照:{snapshotCount}";
    }
}
