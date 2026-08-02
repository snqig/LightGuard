// © 2026 落尘（Luochen）原创开发 - 保留所有权利

using System.Runtime.InteropServices;
using System.Text;
using LightGuard.Core;

using Timer = System.Threading.Timer;

namespace LightGuard.Firewall;

/// <summary>规则变更类型</summary>
public enum RuleChangeType
{
    /// <summary>新增规则</summary>
    Added,
    /// <summary>规则被删除</summary>
    Removed,
    /// <summary>规则被修改（方向/端口/协议/程序路径）</summary>
    Modified,
    /// <summary>规则被禁用</summary>
    Disabled,
    /// <summary>规则动作被篡改（Allow/Block 反转）</summary>
    ActionChanged
}

/// <summary>规则变更记录</summary>
public sealed class RuleChangeRecord
{
    public RuleChangeType ChangeType { get; set; }
    public string RuleName { get; set; } = "";
    public string Details { get; set; } = "";
    public DateTime DetectedAt { get; set; } = DateTime.Now;
}

/// <summary>规则冲突类型</summary>
public enum ConflictType
{
    /// <summary>重复规则</summary>
    Duplicate,
    /// <summary>矛盾规则</summary>
    Contradictory,
    /// <summary>优先级倒置</summary>
    PriorityInversion
}

/// <summary>规则冲突记录</summary>
public sealed class RuleConflict
{
    public ConflictType Type { get; set; }
    public string Rule1Name { get; set; } = "";
    public string Rule2Name { get; set; } = "";
    public string Description { get; set; } = "";
}

/// <summary>
/// 防火墙规则守护引擎 — 实时监控规则变更，自动回滚篡改，检测冲突
/// <para>核心能力：</para>
/// <para>1. 后台线程每 15 秒轮询 Windows 防火墙规则（COM INetFwPolicy2 枚举）</para>
/// <para>2. 对比快照检测 LightGuard 规则被删除/禁用/篡改，以及新增的可疑阻断规则</para>
/// <para>3. 检测到篡改时自动从内存快照回滚，并记录 Critical 审计日志</para>
/// <para>4. 提供规则冲突检测（重复/矛盾/优先级倒置）与规则去重</para>
/// </summary>
public sealed class FirewallGuardian : IDisposable
{
    // ===== 常量 =====

    /// <summary>HNetCfg.FwPolicy2 的 CLSID（与 FirewallAclManager 保持一致）</summary>
    private static readonly Guid CLSID_FwPolicy2 = new("{E2B3C97F-6AE1-41AC-842A-9F92B56C68B1}");

    /// <summary>监控轮询间隔（毫秒）</summary>
    private const int MonitorIntervalMs = 15_000;

    // ===== 字段 =====

    private readonly FirewallAclManager _manager;
    private Timer? _monitorTimer;
    private Dictionary<string, RuleSnapshot> _lastSnapshot = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _snapshotLock = new();
    private bool _running;
    private int _polling; // 0 = 空闲, 1 = 轮询中（Interlocked 防重入）
    private bool _disposed;

    // ===== 事件 =====

    /// <summary>检测到 LightGuard 规则被篡改时触发（携带变更记录列表）</summary>
    public event Action<List<RuleChangeRecord>>? RuleTamperingDetected;

    /// <summary>守护告警（如发现可疑新增阻断规则）</summary>
    public event Action<string>? GuardianAlert;

    // ===== 构造与生命周期 =====

    public FirewallGuardian(FirewallAclManager manager)
    {
        _manager = manager ?? throw new ArgumentNullException(nameof(manager));
    }

    /// <summary>启动监控（15 秒间隔轮询）。启动时建立初始基线快照。</summary>
    public void Start()
    {
        if (_running) return;
        _running = true;

        // 建立初始基线快照，避免首轮误报
        lock (_snapshotLock)
        {
            _lastSnapshot = CaptureCurrentSnapshot();
        }

        AuditLogSystem.Log(LogLevel.Info, LogCategory.System,
            "FirewallGuardian 守护引擎已启动",
            $"初始基线规则数: {_lastSnapshot.Count}, 轮询间隔: {MonitorIntervalMs / 1000} 秒");

        _monitorTimer = new Timer(OnMonitorTick, null, MonitorIntervalMs, MonitorIntervalMs);
    }

    /// <summary>停止监控</summary>
    public void Stop()
    {
        if (!_running) return;
        _running = false;

        _monitorTimer?.Dispose();
        _monitorTimer = null;

        AuditLogSystem.Log(LogLevel.Info, LogCategory.System, "FirewallGuardian 守护引擎已停止");
    }

    /// <summary>监控引擎是否正在运行</summary>
    public bool IsRunning => _running;

    // ===== 监控主循环 =====

    /// <summary>定时监控回调（线程池线程）</summary>
    private void OnMonitorTick(object? state)
    {
        // 防止重入：若上一轮轮询尚未完成则跳过本轮
        if (Interlocked.CompareExchange(ref _polling, 1, 0) != 0)
            return;

        try
        {
            MonitorOnce();
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, "FirewallGuardian 监控周期异常");
        }
        finally
        {
            Interlocked.Exchange(ref _polling, 0);
        }
    }

    /// <summary>执行一次完整的监控检测周期</summary>
    private void MonitorOnce()
    {
        var current = CaptureCurrentSnapshot();

        // 快照为空大概率是 COM 枚举失败，跳过本轮以免误报全部规则被删除
        if (current.Count == 0)
        {
            bool lastHadRules;
            lock (_snapshotLock) { lastHadRules = _lastSnapshot.Count > 0; }
            if (lastHadRules)
            {
                ErrorReporter.Log("FirewallGuardian 本轮快照为空，疑似 COM 枚举失败，跳过检测", "WARN");
            }
            return;
        }

        List<RuleChangeRecord> tamperingChanges;
        List<RuleChangeRecord> suspiciousNewRules;

        // 在锁内读取基线快照引用用于对比
        lock (_snapshotLock)
        {
            tamperingChanges = DetectLgRuleTampering(current, _lastSnapshot);
            suspiciousNewRules = DetectSuspiciousNewRules(current, _lastSnapshot);
        }

        // 处理 LightGuard 规则篡改：自动回滚
        if (tamperingChanges.Count > 0)
        {
            var details = string.Join("; ", tamperingChanges.Select(c => $"{c.RuleName}({c.ChangeType})"));
            AuditLogSystem.Log(LogLevel.Critical, LogCategory.System,
                "检测到 LightGuard 防火墙规则被篡改，已启动自动回滚",
                details);

            int restored = PerformRollback(tamperingChanges);

            AuditLogSystem.Log(LogLevel.Warning, LogCategory.System,
                "FirewallGuardian 自动回滚完成",
                $"已恢复 {restored}/{tamperingChanges.Count} 条规则");

            RuleTamperingDetected?.Invoke(tamperingChanges);
        }

        // 处理可疑新增阻断规则：告警
        if (suspiciousNewRules.Count > 0)
        {
            var alert = $"发现 {suspiciousNewRules.Count} 条新增的可疑阻断规则：" +
                        string.Join(", ", suspiciousNewRules.Select(r => r.RuleName));
            AuditLogSystem.Log(LogLevel.Warning, LogCategory.System,
                "发现可疑新增防火墙阻断规则（可能被恶意软件利用）",
                alert);
            GuardianAlert?.Invoke(alert);
        }

        // 更新基线快照
        lock (_snapshotLock)
        {
            _lastSnapshot = current;
        }
    }

    // ===== 变更检测 =====

    /// <summary>
    /// 检测 LightGuard 管理规则的篡改：
    /// (a) 被外部删除、(b) 被禁用、(c) 动作/方向/端口/协议/程序路径被修改
    /// </summary>
    private static List<RuleChangeRecord> DetectLgRuleTampering(
        Dictionary<string, RuleSnapshot> current,
        Dictionary<string, RuleSnapshot> last)
    {
        var changes = new List<RuleChangeRecord>();

        foreach (var (name, oldSnap) in last)
        {
            if (!name.StartsWith(FirewallConst.RulePrefix, StringComparison.OrdinalIgnoreCase))
                continue;

            if (!current.TryGetValue(name, out var newSnap))
            {
                // (a) LightGuard 规则被外部删除
                changes.Add(new RuleChangeRecord
                {
                    ChangeType = RuleChangeType.Removed,
                    RuleName = name,
                    Details = "LightGuard 管理的规则被外部删除"
                });
                continue;
            }

            // (b) 规则被禁用
            if (!newSnap.Enabled && oldSnap.Enabled)
            {
                changes.Add(new RuleChangeRecord
                {
                    ChangeType = RuleChangeType.Disabled,
                    RuleName = name,
                    Details = "规则被外部禁用"
                });
            }

            // (c) 动作被修改
            if (newSnap.Action != oldSnap.Action)
            {
                changes.Add(new RuleChangeRecord
                {
                    ChangeType = RuleChangeType.ActionChanged,
                    RuleName = name,
                    Details = $"规则动作被修改: {oldSnap.Action} -> {newSnap.Action}"
                });
            }

            // (c) 方向/端口/协议/程序路径被修改
            if (newSnap.Direction != oldSnap.Direction ||
                newSnap.Protocol != oldSnap.Protocol ||
                !string.Equals(newSnap.LocalPorts, oldSnap.LocalPorts, StringComparison.OrdinalIgnoreCase) ||
                !string.Equals(newSnap.RemotePorts, oldSnap.RemotePorts, StringComparison.OrdinalIgnoreCase) ||
                !string.Equals(newSnap.AppPath, oldSnap.AppPath, StringComparison.OrdinalIgnoreCase))
            {
                changes.Add(new RuleChangeRecord
                {
                    ChangeType = RuleChangeType.Modified,
                    RuleName = name,
                    Details = BuildModifiedDetails(oldSnap, newSnap)
                });
            }
        }

        return changes;
    }

    /// <summary>检测新增的非 LightGuard 可疑阻断规则（可能被恶意软件利用）</summary>
    private static List<RuleChangeRecord> DetectSuspiciousNewRules(
        Dictionary<string, RuleSnapshot> current,
        Dictionary<string, RuleSnapshot> last)
    {
        var suspicious = new List<RuleChangeRecord>();
        var blockValue = (int)NET_FW_ACTION_.NET_FW_ACTION_BLOCK;

        foreach (var (name, snap) in current)
        {
            // 跳过 LightGuard 管理的规则
            if (name.StartsWith(FirewallConst.RulePrefix, StringComparison.OrdinalIgnoreCase))
                continue;

            // 仅关注上次快照中不存在的新增规则
            if (last.ContainsKey(name))
                continue;

            // 仅关注已启用的阻断规则
            if (!snap.Enabled || snap.Action != blockValue)
                continue;

            suspicious.Add(new RuleChangeRecord
            {
                ChangeType = RuleChangeType.Added,
                RuleName = name,
                Details = $"新增可疑阻断规则: 程序={snap.AppPath}, 协议={snap.Protocol}, " +
                          $"本地端口={snap.LocalPorts}, 远程端口={snap.RemotePorts}"
            });
        }

        return suspicious;
    }

    /// <summary>构建规则被修改的详细信息文本</summary>
    private static string BuildModifiedDetails(RuleSnapshot oldSnap, RuleSnapshot newSnap)
    {
        var sb = new StringBuilder();
        if (newSnap.Direction != oldSnap.Direction)
            sb.Append($"方向:{oldSnap.Direction}->{newSnap.Direction}; ");
        if (newSnap.Protocol != oldSnap.Protocol)
            sb.Append($"协议:{oldSnap.Protocol}->{newSnap.Protocol}; ");
        if (!string.Equals(newSnap.LocalPorts, oldSnap.LocalPorts, StringComparison.OrdinalIgnoreCase))
            sb.Append($"本地端口:{oldSnap.LocalPorts}->{newSnap.LocalPorts}; ");
        if (!string.Equals(newSnap.RemotePorts, oldSnap.RemotePorts, StringComparison.OrdinalIgnoreCase))
            sb.Append($"远程端口:{oldSnap.RemotePorts}->{newSnap.RemotePorts}; ");
        if (!string.Equals(newSnap.AppPath, oldSnap.AppPath, StringComparison.OrdinalIgnoreCase))
            sb.Append("程序路径变更; ");
        return sb.ToString().TrimEnd(' ', ';');
    }

    // ===== 自动回滚 =====

    /// <summary>从内存快照恢复被篡改的 LightGuard 规则，返回成功恢复的数量</summary>
    private int PerformRollback(List<RuleChangeRecord> changes)
    {
        int restored = 0;
        var localRules = _manager.GetAllLocalRules();
        var fwPolicy = CreateFwPolicy();

        if (fwPolicy == null)
        {
            ErrorReporter.Log("FirewallGuardian 回滚失败：无法创建防火墙 COM 策略对象", "ERROR");
            return 0;
        }

        try
        {
            foreach (var change in changes)
            {
                // 仅处理 LightGuard 管理的规则
                if (!change.RuleName.StartsWith(FirewallConst.RulePrefix, StringComparison.OrdinalIgnoreCase))
                    continue;

                // 按防火墙规则名匹配内存中的本地规则快照
                var localRule = localRules.FirstOrDefault(r =>
                    string.Equals(r.GetFirewallRuleName(), change.RuleName, StringComparison.OrdinalIgnoreCase));

                if (localRule == null)
                {
                    ErrorReporter.Log(
                        $"FirewallGuardian 回滚跳过：内存中未找到对应规则 {change.RuleName}", "WARN");
                    continue;
                }

                try
                {
                    switch (change.ChangeType)
                    {
                        case RuleChangeType.Disabled:
                            // 重新启用：优先走管理器 API（同步更新本地规则状态）
                            if (!_manager.ToggleRuleStatus(localRule.RuleId, true))
                            {
                                // 管理器不可用时直接通过 COM 启用
                                ReEnableRuleViaCom(fwPolicy, change.RuleName);
                            }
                            restored++;
                            break;

                        case RuleChangeType.Removed:
                        case RuleChangeType.Modified:
                        case RuleChangeType.ActionChanged:
                            // 删除被篡改的同名规则并从内存快照重建
                            // （内存中的 localRule 即为受信任的正确副本，无需修改本地列表）
                            RestoreRuleToFirewall(fwPolicy, localRule);
                            restored++;
                            break;
                    }
                }
                catch (Exception ex)
                {
                    ErrorReporter.Report(ex, $"FirewallGuardian 回滚单条规则失败: {change.RuleName}");
                }
            }
        }
        finally
        {
            if (Marshal.IsComObject(fwPolicy))
                Marshal.ReleaseComObject(fwPolicy);
        }

        return restored;
    }

    /// <summary>直接通过 COM 重新启用指定名称的规则</summary>
    private static void ReEnableRuleViaCom(INetFwPolicy2 fwPolicy, string ruleName)
    {
        try
        {
            foreach (INetFwRule fwRule in fwPolicy.Rules)
            {
                if (string.Equals(fwRule.Name, ruleName, StringComparison.OrdinalIgnoreCase))
                {
                    fwRule.Enabled = true;
                    return;
                }
            }
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, $"FirewallGuardian COM 重新启用规则失败: {ruleName}");
        }
    }

    /// <summary>
    /// 从内存快照重建规则到防火墙。
    /// 不修改 FirewallAclManager 的本地规则列表，因为内存中已存在受信任的正确副本。
    /// 字段映射与 FirewallAclManager.CreateFullRule 保持一致。
    /// </summary>
    private static void RestoreRuleToFirewall(INetFwPolicy2 fwPolicy, FirewallAclRule rule)
    {
        try
        {
            // 先移除被篡改的同名规则（忽略不存在的情况）
            try { fwPolicy.Rules.Remove(rule.GetFirewallRuleName()); } catch { }

            var fwRule = (INetFwRule)Activator.CreateInstance(
                Type.GetTypeFromProgID("HNetCfg.FWRule")!)!;

            fwRule.Name = rule.GetFirewallRuleName();
            fwRule.Description = string.IsNullOrEmpty(rule.Remark) ? rule.RuleName : rule.Remark;
            fwRule.Enabled = rule.Enabled;
            fwRule.Action = (NET_FW_ACTION_)rule.Action;
            fwRule.Direction = (NET_FW_RULE_DIRECTION_)rule.Direction;
            fwRule.Profiles = (int)rule.Profile;

            // 程序绑定
            if (!string.IsNullOrEmpty(rule.ApplicationPath))
                fwRule.ApplicationName = rule.ApplicationPath;

            // 服务绑定
            if (!string.IsNullOrEmpty(rule.ServiceName))
                fwRule.serviceName = rule.ServiceName;

            // 协议与端口
            if (rule.Protocol != FirewallConst.FwProtocol.Any)
            {
                fwRule.Protocol = (int)rule.Protocol;

                if (rule.Protocol == FirewallConst.FwProtocol.TCP ||
                    rule.Protocol == FirewallConst.FwProtocol.UDP)
                {
                    var localPort = FormatPortString(rule.LocalPortStart, rule.LocalPortEnd);
                    var remotePort = FormatPortString(rule.RemotePortStart, rule.RemotePortEnd);
                    if (!string.IsNullOrEmpty(localPort) && localPort != "*")
                        fwRule.LocalPorts = localPort;
                    if (!string.IsNullOrEmpty(remotePort) && remotePort != "*")
                        fwRule.RemotePorts = remotePort;
                }
            }

            // 地址
            if (!string.IsNullOrEmpty(rule.LocalAddresses) && rule.LocalAddresses != "*")
                fwRule.LocalAddresses = rule.LocalAddresses;
            if (!string.IsNullOrEmpty(rule.RemoteAddresses) && rule.RemoteAddresses != "*")
                fwRule.RemoteAddresses = rule.RemoteAddresses;

            // 网卡接口类型
            fwRule.InterfaceTypes = MapInterfaceTypes(rule.InterfaceType);

            // 分组标签
            if (!string.IsNullOrEmpty(rule.GroupTag))
                fwRule.Grouping = rule.GroupTag;

            // 边缘遍历
            fwRule.EdgeTraversal = rule.EdgeTraversal;

            fwPolicy.Rules.Add(fwRule);
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, $"FirewallGuardian 恢复规则到防火墙失败: {rule.RuleName}");
        }
    }

    // ===== 快照采集 =====

    /// <summary>通过 COM INetFwPolicy2 枚举当前所有防火墙规则并生成快照</summary>
    private static Dictionary<string, RuleSnapshot> CaptureCurrentSnapshot()
    {
        var snapshot = new Dictionary<string, RuleSnapshot>(StringComparer.OrdinalIgnoreCase);
        var fwPolicy = CreateFwPolicy();
        if (fwPolicy == null)
            return snapshot;

        try
        {
            foreach (INetFwRule rule in fwPolicy.Rules)
            {
                try
                {
                    var snap = new RuleSnapshot
                    {
                        Name = rule.Name ?? string.Empty,
                        Enabled = rule.Enabled,
                        Action = (int)rule.Action,
                        Direction = (int)rule.Direction,
                        AppPath = rule.ApplicationName ?? string.Empty,
                        Protocol = rule.Protocol,
                        LocalPorts = rule.LocalPorts ?? string.Empty,
                        RemotePorts = rule.RemotePorts ?? string.Empty
                    };
                    snapshot[snap.Name] = snap;
                }
                catch
                {
                    // 单条规则读取失败时跳过，继续枚举其余规则
                }
            }
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, "FirewallGuardian 枚举防火墙规则失败");
        }
        finally
        {
            if (Marshal.IsComObject(fwPolicy))
                Marshal.ReleaseComObject(fwPolicy);
        }

        return snapshot;
    }

    /// <summary>创建防火墙 COM 策略对象</summary>
    private static INetFwPolicy2? CreateFwPolicy()
    {
        try
        {
            var type = Type.GetTypeFromCLSID(CLSID_FwPolicy2);
            if (type == null) return null;
            return Activator.CreateInstance(type) as INetFwPolicy2;
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, "FirewallGuardian 创建防火墙 COM 策略对象失败");
            return null;
        }
    }

    // ===== 冲突检测 =====

    /// <summary>生成冲突分析报告，返回当前所有规则冲突列表</summary>
    public List<RuleConflict> GetConflictReport()
    {
        var rules = _manager.GetAllLocalRules();
        var conflicts = new List<RuleConflict>();

        DetectDuplicateRules(rules, conflicts);
        DetectContradictoryRules(rules, conflicts);
        DetectPriorityInversion(rules, conflicts);

        return conflicts;
    }

    /// <summary>检测重复规则：相同 ApplicationPath + Direction + Action + Protocol + Port</summary>
    private static void DetectDuplicateRules(List<FirewallAclRule> rules, List<RuleConflict> conflicts)
    {
        for (int i = 0; i < rules.Count; i++)
        {
            for (int j = i + 1; j < rules.Count; j++)
            {
                if (IsDuplicatePair(rules[i], rules[j]))
                {
                    conflicts.Add(new RuleConflict
                    {
                        Type = ConflictType.Duplicate,
                        Rule1Name = rules[i].GetFirewallRuleName(),
                        Rule2Name = rules[j].GetFirewallRuleName(),
                        Description = "重复规则：相同的程序路径、方向、动作、协议与端口"
                    });
                }
            }
        }
    }

    /// <summary>检测矛盾规则：相同 ApplicationPath + Direction 但 Action 相反</summary>
    private static void DetectContradictoryRules(List<FirewallAclRule> rules, List<RuleConflict> conflicts)
    {
        for (int i = 0; i < rules.Count; i++)
        {
            for (int j = i + 1; j < rules.Count; j++)
            {
                var a = rules[i];
                var b = rules[j];

                if (a.Action == b.Action)
                    continue;
                if (a.Direction != b.Direction)
                    continue;
                if (string.IsNullOrEmpty(a.ApplicationPath))
                    continue;
                if (!string.Equals(a.ApplicationPath, b.ApplicationPath, StringComparison.OrdinalIgnoreCase))
                    continue;

                conflicts.Add(new RuleConflict
                {
                    Type = ConflictType.Contradictory,
                    Rule1Name = a.GetFirewallRuleName(),
                    Rule2Name = b.GetFirewallRuleName(),
                    Description = $"矛盾规则：同一程序与方向存在相反动作（{a.Action} vs {b.Action}）"
                });
            }
        }
    }

    /// <summary>检测优先级倒置：相同 ApplicationPath + Direction 下 Block 优先级低于 Allow</summary>
    private static void DetectPriorityInversion(List<FirewallAclRule> rules, List<RuleConflict> conflicts)
    {
        // 按 (ApplicationPath, Direction) 分组
        var groups = rules
            .Where(r => !string.IsNullOrEmpty(r.ApplicationPath))
            .GroupBy(r => (r.ApplicationPath, r.Direction));

        foreach (var group in groups)
        {
            var list = group.ToList();
            var blocks = list.Where(r => r.Action == FirewallConst.FwAction.Block).ToList();
            var allows = list.Where(r => r.Action == FirewallConst.FwAction.Allow).ToList();

            foreach (var block in blocks)
            {
                foreach (var allow in allows)
                {
                    // 数值越小优先级越高；Block 优先级数值 > Allow 即为倒置（阻断被放行覆盖）
                    if (block.RulePriority > allow.RulePriority)
                    {
                        conflicts.Add(new RuleConflict
                        {
                            Type = ConflictType.PriorityInversion,
                            Rule1Name = block.GetFirewallRuleName(),
                            Rule2Name = allow.GetFirewallRuleName(),
                            Description = $"优先级倒置：Block 规则(优先级{block.RulePriority})低于 " +
                                          $"Allow 规则(优先级{allow.RulePriority})，阻断可能被放行覆盖"
                        });
                    }
                }
            }
        }
    }

    /// <summary>判断两条规则是否构成重复（程序路径 + 方向 + 动作 + 协议 + 端口）</summary>
    private static bool IsDuplicatePair(FirewallAclRule a, FirewallAclRule b)
    {
        return a.Action == b.Action
            && a.Direction == b.Direction
            && a.Protocol == b.Protocol
            && a.LocalPortStart == b.LocalPortStart
            && a.LocalPortEnd == b.LocalPortEnd
            && a.RemotePortStart == b.RemotePortStart
            && a.RemotePortEnd == b.RemotePortEnd
            && string.Equals(a.ApplicationPath, b.ApplicationPath, StringComparison.OrdinalIgnoreCase);
    }

    // ===== 规则去重 =====

    /// <summary>
    /// 自动合并重复规则，保留最早创建的（内存列表中靠前者），删除后续重复项。
    /// 返回移除的重复规则数量。
    /// </summary>
    public int DeduplicateRules()
    {
        var rules = _manager.GetAllLocalRules();
        var seen = new Dictionary<string, FirewallAclRule>(StringComparer.Ordinal);
        var toDelete = new List<FirewallAclRule>();

        foreach (var rule in rules)
        {
            var key = MakeDuplicateKey(rule);
            if (seen.ContainsKey(key))
            {
                toDelete.Add(rule);
            }
            else
            {
                seen[key] = rule;
            }
        }

        int removed = 0;
        foreach (var rule in toDelete)
        {
            if (_manager.DeleteRuleByName(rule.GetFirewallRuleName()))
                removed++;
        }

        if (removed > 0)
        {
            AuditLogSystem.Log(LogLevel.Info, LogCategory.System,
                "FirewallGuardian 规则去重完成",
                $"检测到 {toDelete.Count} 条重复规则，已移除 {removed} 条");
        }

        return removed;
    }

    /// <summary>生成重复判定键（ApplicationPath + Direction + Action + Protocol + Port）</summary>
    private static string MakeDuplicateKey(FirewallAclRule rule)
    {
        return string.Join("|",
            (rule.ApplicationPath ?? "").ToUpperInvariant(),
            (int)rule.Direction,
            (int)rule.Action,
            (int)rule.Protocol,
            rule.LocalPortStart, rule.LocalPortEnd,
            rule.RemotePortStart, rule.RemotePortEnd);
    }

    // ===== 辅助方法（与 FirewallAclManager 字段映射保持一致）=====

    private static string FormatPortString(int start, int end)
    {
        if (start == 0 && end == 0) return "*";
        if (start == end) return start.ToString();
        if (end == 0) return start.ToString();
        return $"{start}-{end}";
    }

    private static string MapInterfaceTypes(FirewallConst.FwInterfaceType type)
    {
        return type switch
        {
            FirewallConst.FwInterfaceType.All => "All",
            FirewallConst.FwInterfaceType.PhysicalOnly => "Lan",
            FirewallConst.FwInterfaceType.VpnOnly => "RemoteAccess",
            FirewallConst.FwInterfaceType.Wireless => "Wireless",
            FirewallConst.FwInterfaceType.IPv6Tunnel => "All",
            _ => "All"
        };
    }

    /// <summary>获取最近一次快照中的规则数量（用于诊断）</summary>
    public int GetLastSnapshotCount()
    {
        lock (_snapshotLock)
        {
            return _lastSnapshot.Count;
        }
    }

    // ===== 资源释放 =====

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        Stop();
    }
}

/// <summary>
/// 防火墙规则快照（用于变更对比）
/// 记录某一时刻单条防火墙规则的关键属性，供前后快照 diff 使用。
/// </summary>
internal sealed class RuleSnapshot
{
    public string Name { get; set; } = string.Empty;
    public bool Enabled { get; set; }
    /// <summary>动作（COM 原始值：0=Block, 1=Allow）</summary>
    public int Action { get; set; }
    /// <summary>方向（COM 原始值：1=Inbound, 2=Outbound）</summary>
    public int Direction { get; set; }
    public string AppPath { get; set; } = string.Empty;
    public int Protocol { get; set; }
    public string LocalPorts { get; set; } = string.Empty;
    public string RemotePorts { get; set; } = string.Empty;
}
