using System.Collections;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using LightGuard.Core;

namespace LightGuard.Firewall;

/// <summary>
/// 防火墙 ACL 核心管理器
/// 使用 Windows Firewall COM API (NetFwTypeLib) 实现全字段规则管理
/// 支持：单程序、批量目录、纯端口 IP 三类规则
/// 支持：VPN 防绕过、NTFS 权限加固、备份还原、无效规则清理
/// </summary>
public sealed class FirewallAclManager : IDisposable
{
    private readonly INetFwPolicy2? _fwPolicy;
    private readonly List<FirewallAclRule> _localRules = new();
    private bool _disposed;

    // COM 类型 GUID 常量
    private static readonly Guid CLSID_FwPolicy2 = new("{E2B3C97F-6AE1-41AC-842A-9F92B56C68B1}");
    private static readonly Guid IID_INetFwPolicy2 = new("{98325047-C671-4174-8D81-DEFCD3F0319E}");

    public FirewallAclManager()
    {
        try
        {
            var type = Type.GetTypeFromCLSID(CLSID_FwPolicy2);
            _fwPolicy = (INetFwPolicy2?)Activator.CreateInstance(type!);
            ErrorReporter.Log("防火墙 ACL 管理器初始化成功，COM 组件已连接");
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, "防火墙 COM 组件初始化失败");
            _fwPolicy = null;
        }
    }

    // ===== 3.1 基础前置校验 =====

    /// <summary>校验管理员权限</summary>
    public static bool CheckAdminPrivilege()
    {
        try
        {
            using var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
            var principal = new System.Security.Principal.WindowsPrincipal(identity);
            return principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
        }
        catch { return false; }
    }

    /// <summary>检测 Windows 防火墙服务运行状态</summary>
    public bool TestFirewallComConnect()
    {
        if (_fwPolicy == null) return false;
        try
        {
            // 尝试读取当前配置文件状态
            _ = _fwPolicy.get_FirewallEnabled(NET_FW_PROFILE_TYPE2.NET_FW_PROFILE2_PUBLIC);
            return true;
        }
        catch
        {
            return false;
        }
    }

    // ===== 3.2 单条通用规则操作 =====

    /// <summary>
    /// 全字段写入防火墙规则，自动查重避免重复规则
    /// 创建前自动清洗 Unicode 文本，防止非法字符引发 COM 异常
    /// </summary>
    public bool CreateFullRule(FirewallAclRule rule)
    {
        if (_fwPolicy == null) return false;

        // 清洗所有文本字段（多语言安全）
        rule.SanitizeTexts();

        // 如果备注为空，自动生成系统备注
        if (string.IsNullOrEmpty(rule.Remark))
            rule.Remark = UnicodeTextHelper.AutoGenerateRemark(rule);

        // 查重：检查是否已存在同名规则（使用规则名 + 方向作为防火墙唯一键）
        if (RuleExists(rule.GetFirewallRuleName()))
        {
            ErrorReporter.Log($"规则已存在，跳过创建: {rule.RuleName}", "WARN");
            return true;
        }

        try
        {
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
            {
                fwRule.ApplicationName = rule.ApplicationPath;
            }

            // 服务绑定
            if (!string.IsNullOrEmpty(rule.ServiceName))
            {
                fwRule.serviceName = rule.ServiceName;
            }

            // 协议与端口
            if (rule.Protocol != FirewallConst.FwProtocol.Any)
            {
                fwRule.Protocol = (int)rule.Protocol;

                if (rule.Protocol == FirewallConst.FwProtocol.TCP || rule.Protocol == FirewallConst.FwProtocol.UDP)
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

            // 添加到防火墙
            _fwPolicy.Rules.Add(fwRule);

            // 记录到本地规则列表
            _localRules.Add(rule);

            ErrorReporter.Log($"已创建防火墙规则: {rule.RuleName} [{rule.GetFullDescription()}]");
            return true;
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, $"创建防火墙规则失败: {rule.RuleName}");
            return false;
        }
    }

    /// <summary>按 RuleId 精准删除单条规则</summary>
    public bool DeleteRuleById(string ruleId)
    {
        var rule = _localRules.FirstOrDefault(r => r.RuleId == ruleId);
        if (rule == null) return false;
        return DeleteRuleByName(rule.GetFirewallRuleName());
    }

    /// <summary>按规则名删除（精准删除单条规则）</summary>
    public bool DeleteRuleByName(string firewallRuleName)
    {
        if (_fwPolicy == null) return false;
        try
        {
            _fwPolicy.Rules.Remove(firewallRuleName);
            _localRules.RemoveAll(r => r.GetFirewallRuleName() == firewallRuleName);
            ErrorReporter.Log($"已删除防火墙规则: {firewallRuleName}");
            return true;
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, $"删除防火墙规则失败: {firewallRuleName}");
            return false;
        }
    }

    /// <summary>单独启用/禁用规则，无需删除重建</summary>
    public bool ToggleRuleStatus(string ruleId, bool enabled)
    {
        if (_fwPolicy == null) return false;
        var rule = _localRules.FirstOrDefault(r => r.RuleId == ruleId);
        if (rule == null) return false;

        try
        {
            var fwRuleName = rule.GetFirewallRuleName();
            foreach (INetFwRule fwRule in _fwPolicy.Rules)
            {
                if (fwRule.Name == fwRuleName)
                {
                    fwRule.Enabled = enabled;
                    rule.Enabled = enabled;
                    ErrorReporter.Log($"规则状态切换: {rule.RuleName} -> {(enabled ? "启用" : "禁用")}");
                    return true;
                }
            }
            return false;
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, $"切换规则状态失败: {rule.RuleName}");
            return false;
        }
    }

    /// <summary>按 RuleId 获取规则</summary>
    public FirewallAclRule? GetRuleById(string ruleId)
    {
        return _localRules.FirstOrDefault(r => r.RuleId == ruleId);
    }

    /// <summary>按分组查询规则</summary>
    public List<FirewallAclRule> QueryRulesByGroup(string groupTag)
    {
        return _localRules.Where(r => r.GroupTag == groupTag).ToList();
    }

    /// <summary>按程序路径查询规则</summary>
    public List<FirewallAclRule> QueryRulesByAppPath(string appPath)
    {
        return _localRules.Where(r =>
            string.Equals(r.ApplicationPath, appPath, StringComparison.OrdinalIgnoreCase)).ToList();
    }

    /// <summary>按端口范围查询规则</summary>
    public List<FirewallAclRule> QueryRulesByPortRange(int portStart, int portEnd)
    {
        return _localRules.Where(r =>
            (r.LocalPortStart > 0 && r.LocalPortStart >= portStart && r.LocalPortEnd <= portEnd) ||
            (r.RemotePortStart > 0 && r.RemotePortStart >= portStart && r.RemotePortEnd <= portEnd)).ToList();
    }

    /// <summary>获取所有本程序创建的规则</summary>
    public List<FirewallAclRule> GetAllLocalRules()
    {
        return new List<FirewallAclRule>(_localRules);
    }

    // ===== 3.3 场景 1：单个 EXE 精细化管控 =====

    /// <summary>
    /// 可自定义五元组所有参数，支持三种网卡模式
    /// </summary>
    public bool CreateCustomExeRule(
        string ruleName,
        string exePath,
        FirewallConst.FwAction action = FirewallConst.FwAction.Block,
        FirewallConst.FwDirection direction = FirewallConst.FwDirection.Outbound,
        FirewallConst.FwProtocol protocol = FirewallConst.FwProtocol.Any,
        int localPortStart = 0, int localPortEnd = 0,
        int remotePortStart = 0, int remotePortEnd = 0,
        string localAddresses = "*",
        string remoteAddresses = "*",
        FirewallConst.FwInterfaceType interfaceType = FirewallConst.FwInterfaceType.All,
        string groupTag = FirewallConst.GroupCustom,
        string remark = "")
    {
        // 白名单检查
        if (IsSystemWhitelisted(exePath))
        {
            ErrorReporter.Log($"跳过系统白名单程序: {exePath}", "WARN");
            return false;
        }

        // 入站+出站各创建一条
        var directions = direction == FirewallConst.FwDirection.Inbound
            ? new[] { FirewallConst.FwDirection.Inbound }
            : direction == FirewallConst.FwDirection.Outbound
                ? new[] { FirewallConst.FwDirection.Outbound }
                : new[] { FirewallConst.FwDirection.Inbound, FirewallConst.FwDirection.Outbound };

        bool allSuccess = true;
        foreach (var dir in directions)
        {
            var rule = new FirewallAclRule
            {
                RuleName = $"{ruleName}_{(dir == FirewallConst.FwDirection.Inbound ? "in" : "out")}",
                GroupTag = groupTag,
                Remark = remark,
                Action = action,
                Direction = dir,
                Enabled = true,
                ApplicationPath = exePath,
                Protocol = protocol,
                LocalPortStart = localPortStart,
                LocalPortEnd = localPortEnd,
                RemotePortStart = remotePortStart,
                RemotePortEnd = remotePortEnd,
                LocalAddresses = localAddresses,
                RemoteAddresses = remoteAddresses,
                InterfaceType = interfaceType,
                Profile = FirewallConst.FwProfile.All
            };

            // VPN 网段绑定
            if (interfaceType == FirewallConst.FwInterfaceType.VpnOnly ||
                interfaceType == FirewallConst.FwInterfaceType.All)
            {
                rule.VpnIpCidrList = string.Join(",", VpnNetworkTool.GetAllVpnCidrList());
            }

            if (!CreateFullRule(rule))
                allSuccess = false;
        }

        return allSuccess;
    }

    // ===== 3.4 场景 2：多级目录批量 EXE 拦截 =====

    /// <summary>递归遍历本级 + 所有多级子目录 EXE，自动过滤系统白名单程序</summary>
    public List<string> ScanRecursiveExe(string folderPath, bool recursive = true)
    {
        var result = new List<string>();
        try
        {
            var searchOption = recursive ? SearchOption.AllDirectories : SearchOption.TopDirectoryOnly;
            var exeFiles = Directory.GetFiles(folderPath, "*.exe", searchOption);

            foreach (var exe in exeFiles)
            {
                if (!IsSystemWhitelisted(exe))
                    result.Add(exe);
            }
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, $"扫描目录 EXE 失败: {folderPath}");
        }
        return result;
    }

    /// <summary>
    /// 批量生成入站 + 出站规则，支持自定义端口策略、网卡 VPN 限制
    /// </summary>
    public (int Created, int Skipped, int Failed) BatchCreateFolderExeRule(
        string folderPath,
        bool recursive = true,
        FirewallConst.FwAction action = FirewallConst.FwAction.Block,
        int remotePortStart = 0, int remotePortEnd = 0,
        FirewallConst.FwInterfaceType interfaceType = FirewallConst.FwInterfaceType.All,
        string groupTag = "")
    {
        if (string.IsNullOrEmpty(groupTag))
            groupTag = $"目录拦截_{Path.GetFileName(folderPath.TrimEnd('\\'))}";

        var exeList = ScanRecursiveExe(folderPath, recursive);
        int created = 0, skipped = 0, failed = 0;

        foreach (var exe in exeList)
        {
            var name = Path.GetFileNameWithoutExtension(exe);
            var success = CreateCustomExeRule(
                ruleName: $"{groupTag}_{name}",
                exePath: exe,
                action: action,
                direction: FirewallConst.FwDirection.Outbound, // 批量默认出站
                remotePortStart: remotePortStart,
                remotePortEnd: remotePortEnd,
                interfaceType: interfaceType,
                groupTag: groupTag,
                remark: $"批量目录拦截: {folderPath}");

            if (success) created++;
            else failed++;
        }

        ErrorReporter.Log($"批量目录拦截完成: 目录={folderPath}, 创建={created}, 跳过={skipped}, 失败={failed}");
        return (created, skipped, failed);
    }

    /// <summary>按目录分组一键清空所有配套 ACL 规则</summary>
    public int BatchRemoveFolderGroupRules(string groupTag)
    {
        var rules = QueryRulesByGroup(groupTag);
        int removed = 0;
        foreach (var rule in rules.ToList())
        {
            if (DeleteRuleByName(rule.GetFirewallRuleName()))
                removed++;
        }
        ErrorReporter.Log($"按分组清空规则: 分组={groupTag}, 删除={removed} 条");
        return removed;
    }

    /// <summary>重新扫描目录，新增 EXE 自动补规则、已删除 EXE 自动清理无效规则</summary>
    public (int Added, int Removed) RefreshFolderRules(
        string folderPath, bool recursive, string groupTag,
        FirewallConst.FwAction action, int remotePortStart, int remotePortEnd,
        FirewallConst.FwInterfaceType interfaceType)
    {
        var currentExes = ScanRecursiveExe(folderPath, recursive);
        var existingRules = QueryRulesByGroup(groupTag);
        var existingPaths = existingRules
            .Where(r => !string.IsNullOrEmpty(r.ApplicationPath))
            .Select(r => r.ApplicationPath!)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToHashSet();

        // 新增的 EXE
        int added = 0;
        foreach (var exe in currentExes)
        {
            if (!existingPaths.Contains(exe))
            {
                var name = Path.GetFileNameWithoutExtension(exe);
                if (CreateCustomExeRule(
                    ruleName: $"{groupTag}_{name}",
                    exePath: exe,
                    action: action,
                    remotePortStart: remotePortStart,
                    remotePortEnd: remotePortEnd,
                    interfaceType: interfaceType,
                    groupTag: groupTag))
                    added++;
            }
        }

        // 已删除的 EXE
        int removed = 0;
        var currentExeSet = currentExes
            .Select(p => p.ToUpperInvariant())
            .ToHashSet();
        foreach (var rule in existingRules.ToList())
        {
            if (!string.IsNullOrEmpty(rule.ApplicationPath) &&
                !currentExeSet.Contains(rule.ApplicationPath.ToUpperInvariant()))
            {
                if (DeleteRuleByName(rule.GetFirewallRuleName()))
                    removed++;
            }
        }

        ErrorReporter.Log($"目录规则刷新: 分组={groupTag}, 新增={added}, 清理={removed}");
        return (added, removed);
    }

    // ===== 3.5 场景 3：全局端口 / IP 规则 =====

    /// <summary>全局封禁高危端口（无程序绑定）</summary>
    public bool CreatePurePortRule(
        string ruleName,
        int portStart, int portEnd,
        FirewallConst.FwDirection direction = FirewallConst.FwDirection.Inbound,
        FirewallConst.FwAction action = FirewallConst.FwAction.Block,
        FirewallConst.FwProtocol protocol = FirewallConst.FwProtocol.TCP,
        string remoteAddresses = "*",
        string groupTag = FirewallConst.GroupCustom)
    {
        var rule = new FirewallAclRule
        {
            RuleName = ruleName,
            GroupTag = groupTag,
            Action = action,
            Direction = direction,
            Enabled = true,
            ApplicationPath = "", // 纯端口规则无程序绑定
            Protocol = protocol,
            RemotePortStart = portStart,
            RemotePortEnd = portEnd,
            RemoteAddresses = remoteAddresses,
            InterfaceType = FirewallConst.FwInterfaceType.All,
            Profile = FirewallConst.FwProfile.All,
            Remark = $"全局端口规则: {portStart}-{portEnd}/{protocol}"
        };

        return CreateFullRule(rule);
    }

    /// <summary>批量拉黑恶意 IP、VPN 隧道网段、代理地址</summary>
    public int BatchAddIpBlackList(List<string> ipList, string groupTag = "IP黑名单")
    {
        int added = 0;
        foreach (var ip in ipList.Distinct())
        {
            if (string.IsNullOrEmpty(ip)) continue;

            var rule = new FirewallAclRule
            {
                RuleName = $"BlockIP_{ip.Replace('/', '_').Replace('.', '_')}",
                GroupTag = groupTag,
                Action = FirewallConst.FwAction.Block,
                Direction = FirewallConst.FwDirection.Outbound,
                Enabled = true,
                ApplicationPath = "",
                Protocol = FirewallConst.FwProtocol.Any,
                RemoteAddresses = ip,
                InterfaceType = FirewallConst.FwInterfaceType.All,
                Profile = FirewallConst.FwProfile.All,
                Remark = $"IP 黑名单: {ip}"
            };

            if (CreateFullRule(rule))
                added++;
        }
        ErrorReporter.Log($"批量 IP 黑名单: 添加 {added} 条");
        return added;
    }

    /// <summary>拦截程序访问本地代理端口（1080/8080 等）</summary>
    public int BlockProxyPortRule(string exePath, string groupTag = "代理端口拦截")
    {
        int added = 0;
        foreach (var port in FirewallConst.ProxyPorts)
        {
            if (CreateCustomExeRule(
                ruleName: $"ProxyBlock_{Path.GetFileNameWithoutExtension(exePath)}_{port}",
                exePath: exePath,
                action: FirewallConst.FwAction.Block,
                direction: FirewallConst.FwDirection.Outbound,
                protocol: FirewallConst.FwProtocol.TCP,
                remotePortStart: port,
                remotePortEnd: port,
                interfaceType: FirewallConst.FwInterfaceType.All,
                groupTag: groupTag,
                remark: $"代理端口拦截: {port}"))
                added++;
        }
        return added;
    }

    // ===== 3.6 VPN 防绕过专属逻辑 =====

    /// <summary>VPN 隧道接口默认阻断指定程序出站（高优先级）</summary>
    public bool CreateVpnBlockRule(string exePath, string ruleName = "")
    {
        if (string.IsNullOrEmpty(ruleName))
            ruleName = $"VpnBlock_{Path.GetFileNameWithoutExtension(exePath)}";

        var vpnCidrs = VpnNetworkTool.GetAllVpnCidrList();
        var remoteAddr = string.Join(",", vpnCidrs);

        return CreateCustomExeRule(
            ruleName: ruleName,
            exePath: exePath,
            action: FirewallConst.FwAction.Block,
            direction: FirewallConst.FwDirection.Outbound,
            protocol: FirewallConst.FwProtocol.Any,
            remoteAddresses: remoteAddr,
            interfaceType: FirewallConst.FwInterfaceType.VpnOnly,
            groupTag: "VPN防绕过",
            remark: "VPN 隧道阻断规则");
    }

    /// <summary>隧道网段阻断：禁止目标程序访问所有 VPN CIDR 网段</summary>
    public int BlockVpnCidrForApp(string exePath)
    {
        var vpnCidrs = VpnNetworkTool.GetAllVpnCidrList();
        int added = 0;

        // 将 VPN 网段合并为一条规则（逗号分隔）
        if (vpnCidrs.Count > 0)
        {
            var remoteAddr = string.Join(",", vpnCidrs);
            if (CreateCustomExeRule(
                ruleName: $"VpnCidrBlock_{Path.GetFileNameWithoutExtension(exePath)}",
                exePath: exePath,
                action: FirewallConst.FwAction.Block,
                direction: FirewallConst.FwDirection.Outbound,
                remoteAddresses: remoteAddr,
                interfaceType: FirewallConst.FwInterfaceType.All,
                groupTag: "VPN网段阻断",
                remark: "VPN 网段阻断"))
                added++;
        }

        return added;
    }

    /// <summary>网卡动态监听：新增 VPN 适配器自动适配拦截策略</summary>
    public void RefreshVpnRules()
    {
        var currentVpnCidrs = VpnNetworkTool.GetAllVpnCidrList();
        var vpnRules = _localRules.Where(r => r.GroupTag == "VPN网段阻断").ToList();

        foreach (var rule in vpnRules)
        {
            var newRemoteAddr = string.Join(",", currentVpnCidrs);
            if (rule.RemoteAddresses != newRemoteAddr)
            {
                // 删除旧规则，创建新规则
                DeleteRuleByName(rule.GetFirewallRuleName());
                rule.RemoteAddresses = newRemoteAddr;
                rule.VpnIpCidrList = newRemoteAddr;
                CreateFullRule(rule);
                ErrorReporter.Log($"VPN 规则已刷新: {rule.RuleName}");
            }
        }
    }

    // ===== 3.7 备份、还原、无效规则清理 =====

    /// <summary>导出指定分组规则为 JSON 文件（UTF-8 BOM 编码）</summary>
    public bool ExportGroupRules(string groupTag, string filePath)
    {
        try
        {
            var rules = QueryRulesByGroup(groupTag);
            var json = FirewallAclRule.ToJsonList(rules);
            UnicodeTextHelper.WriteJsonWithBom(filePath, json);
            ErrorReporter.Log($"导出规则: 分组={groupTag}, 数量={rules.Count}, 文件={filePath}");
            return true;
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, $"导出规则失败: {filePath}");
            return false;
        }
    }

    /// <summary>导出所有规则为 JSON 文件（UTF-8 BOM 编码）</summary>
    public bool ExportAllRules(string filePath)
    {
        try
        {
            var json = FirewallAclRule.ToJsonList(_localRules);
            UnicodeTextHelper.WriteJsonWithBom(filePath, json);
            ErrorReporter.Log($"导出全部规则: 数量={_localRules.Count}, 文件={filePath}");
            return true;
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, $"导出全部规则失败: {filePath}");
            return false;
        }
    }

    /// <summary>批量导入规则，自动去重合并（支持 UTF-8 BOM 文件）</summary>
    public (int Imported, int Skipped) ImportRuleSet(string filePath)
    {
        try
        {
            var json = UnicodeTextHelper.ReadJsonFile(filePath);
            var rules = FirewallAclRule.FromJsonList(json);
            if (rules == null) return (0, 0);

            int imported = 0, skipped = 0;
            foreach (var rule in rules)
            {
                // 去重：检查是否已存在
                var exists = _localRules.Any(r => r.IsDuplicateOf(rule));
                if (exists)
                {
                    skipped++;
                    continue;
                }

                // 重新生成 RuleId 避免冲突
                rule.RuleId = Guid.NewGuid().ToString("N");
                if (CreateFullRule(rule))
                    imported++;
                else
                    skipped++;
            }

            ErrorReporter.Log($"导入规则: 导入={imported}, 跳过={skipped}, 文件={filePath}");
            return (imported, skipped);
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, $"导入规则失败: {filePath}");
            return (0, 0);
        }
    }

    /// <summary>一键清空本程序创建的全部防火墙规则（全局还原）</summary>
    public int ClearAllSelfRules()
    {
        if (_fwPolicy == null) return 0;
        int removed = 0;
        try
        {
            var toRemove = new List<string>();
            foreach (INetFwRule fwRule in _fwPolicy.Rules)
            {
                if (fwRule.Name.StartsWith(FirewallConst.RulePrefix, StringComparison.OrdinalIgnoreCase))
                    toRemove.Add(fwRule.Name);
            }

            foreach (var name in toRemove)
            {
                try { _fwPolicy.Rules.Remove(name); removed++; }
                catch { }
            }

            _localRules.Clear();
            ErrorReporter.Log($"全局还原: 已清空 {removed} 条自定义防火墙规则");
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, "清空全部自定义规则失败");
        }
        return removed;
    }

    /// <summary>自动清理 EXE 已删除、网卡已卸载的无效规则</summary>
    public int CleanDeadRules()
    {
        int cleaned = 0;
        var deadRules = _localRules.Where(r =>
            !string.IsNullOrEmpty(r.ApplicationPath) && !File.Exists(r.ApplicationPath)).ToList();

        foreach (var rule in deadRules)
        {
            if (DeleteRuleByName(rule.GetFirewallRuleName()))
                cleaned++;
        }

        ErrorReporter.Log($"清理无效规则: 删除 {cleaned} 条");
        return cleaned;
    }

    // ===== Hosts 域名劫持辅助 =====

    /// <summary>批量写入软件官方域名指向 127.0.0.1</summary>
    public bool AddDomainBlockHosts(IEnumerable<string> domains)
    {
        try
        {
            var hostsPath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.System),
                "drivers", "etc", "hosts");

            var content = File.ReadAllText(hostsPath);
            content = RemoveLightGuardHostsSection(content);

            var sb = new StringBuilder(content);
            sb.AppendLine();
            sb.AppendLine(FirewallConst.HostsMarker);
            foreach (var domain in domains.Distinct())
            {
                sb.AppendLine($"127.0.0.1 {domain}");
            }
            sb.AppendLine(FirewallConst.HostsEndMarker);

            File.WriteAllText(hostsPath, sb.ToString());
            ErrorReporter.Log($"Hosts 域名劫持: 已写入 {domains.Count()} 条");
            return true;
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, "Hosts 域名劫持失败");
            return false;
        }
    }

    /// <summary>封锁解除后恢复原始 Hosts 文件</summary>
    public bool RestoreOriginalHosts()
    {
        try
        {
            var hostsPath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.System),
                "drivers", "etc", "hosts");

            var content = File.ReadAllText(hostsPath);
            content = RemoveLightGuardHostsSection(content);
            File.WriteAllText(hostsPath, content);
            ErrorReporter.Log("Hosts 域名劫持已解除");
            return true;
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, "恢复 Hosts 失败");
            return false;
        }
    }

    /// <summary>配套目录批量规则同步写入劫持域名</summary>
    public bool AddDomainBlockForFolder(string folderPath, IEnumerable<string> domains)
    {
        // 先添加防火墙规则
        var exeList = ScanRecursiveExe(folderPath);
        foreach (var exe in exeList)
        {
            var name = Path.GetFileNameWithoutExtension(exe);
            CreateCustomExeRule(
                ruleName: $"HostsBlock_{name}",
                exePath: exe,
                action: FirewallConst.FwAction.Block,
                direction: FirewallConst.FwDirection.Outbound,
                interfaceType: FirewallConst.FwInterfaceType.All,
                groupTag: "Hosts域名劫持");
        }

        // 再写入 Hosts
        return AddDomainBlockHosts(domains);
    }

    // ===== NTFS 权限加固 =====

    /// <summary>锁定 EXE 只读 + 创建防火墙规则（三层兜底）</summary>
    public bool CreateRuleWithAclLock(FirewallAclRule rule)
    {
        var success = CreateFullRule(rule);
        if (success && !string.IsNullOrEmpty(rule.ApplicationPath) && File.Exists(rule.ApplicationPath))
        {
            AclPermissionHelper.SetExeReadonlyAcl(rule.ApplicationPath);
        }
        return success;
    }

    /// <summary>删除规则 + 恢复 EXE 权限</summary>
    public bool DeleteRuleAndRestoreAcl(string ruleId)
    {
        var rule = GetRuleById(ruleId);
        if (rule == null) return false;

        var success = DeleteRuleByName(rule.GetFirewallRuleName());
        if (success && !string.IsNullOrEmpty(rule.ApplicationPath) && File.Exists(rule.ApplicationPath))
        {
            AclPermissionHelper.RestoreExeDefaultAcl(rule.ApplicationPath);
        }
        return success;
    }

    // ===== 辅助方法 =====

    private bool RuleExists(string ruleName)
    {
        if (_fwPolicy == null) return false;
        try
        {
            foreach (INetFwRule fwRule in _fwPolicy.Rules)
            {
                if (fwRule.Name == ruleName) return true;
            }
        }
        catch { }
        return false;
    }

    /// <summary>检查程序是否在系统白名单中</summary>
    public static bool IsSystemWhitelisted(string exePath)
    {
        if (string.IsNullOrEmpty(exePath)) return false;

        // 路径前缀匹配
        foreach (var whitelistPath in FirewallConst.SystemWhitelistPaths)
        {
            if (exePath.StartsWith(whitelistPath, StringComparison.OrdinalIgnoreCase))
                return true;
        }

        // 进程名匹配
        var fileName = Path.GetFileNameWithoutExtension(exePath);
        foreach (var whitelistProc in FirewallConst.SystemWhitelistProcesses)
        {
            if (string.Equals(fileName, whitelistProc, StringComparison.OrdinalIgnoreCase))
                return true;
        }

        return false;
    }

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

    private static string RemoveLightGuardHostsSection(string content)
    {
        var startIdx = content.IndexOf(FirewallConst.HostsMarker);
        if (startIdx < 0) return content;

        var endIdx = content.IndexOf(FirewallConst.HostsEndMarker, startIdx);
        if (endIdx < 0) return content;

        var endPos = endIdx + FirewallConst.HostsEndMarker.Length;
        while (endPos < content.Length && content[endPos] != '\n') endPos++;
        if (endPos < content.Length) endPos++;

        return content.Remove(startIdx, endPos - startIdx);
    }

    /// <summary>从防火墙加载已存在的本程序规则到本地列表</summary>
    public void LoadExistingRules()
    {
        if (_fwPolicy == null) return;
        try
        {
            _localRules.Clear();
            foreach (INetFwRule fwRule in _fwPolicy.Rules)
            {
                if (!fwRule.Name.StartsWith(FirewallConst.RulePrefix, StringComparison.OrdinalIgnoreCase))
                    continue;

                var rule = ParseFwRuleToLocal(fwRule);
                if (rule != null)
                    _localRules.Add(rule);
            }
            ErrorReporter.Log($"加载已存在的防火墙规则: {_localRules.Count} 条");
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, "加载防火墙规则失败");
        }
    }

    private static FirewallAclRule? ParseFwRuleToLocal(INetFwRule fwRule)
    {
        try
        {
            var name = fwRule.Name;
            // 解析规则名：LG_ACL_RuleName_dir
            var prefixLen = FirewallConst.RulePrefix.Length;
            if (name.Length <= prefixLen) return null;

            var rest = name.Substring(prefixLen);
            var lastUnderscore = rest.LastIndexOf('_');
            var ruleName = lastUnderscore > 0 ? rest.Substring(0, lastUnderscore) : rest;
            var dirStr = lastUnderscore > 0 ? rest.Substring(lastUnderscore + 1) : "out";

            var rule = new FirewallAclRule
            {
                RuleName = ruleName,
                GroupTag = fwRule.Grouping ?? FirewallConst.GroupCustom,
                Remark = fwRule.Description ?? "",
                Action = (FirewallConst.FwAction)fwRule.Action,
                Direction = (FirewallConst.FwDirection)fwRule.Direction,
                Enabled = fwRule.Enabled,
                ApplicationPath = fwRule.ApplicationName ?? "",
                Protocol = (FirewallConst.FwProtocol)(fwRule.Protocol == 0 ? 256 : fwRule.Protocol),
                LocalAddresses = fwRule.LocalAddresses ?? "*",
                RemoteAddresses = fwRule.RemoteAddresses ?? "*",
                Profile = (FirewallConst.FwProfile)fwRule.Profiles,
                EdgeTraversal = fwRule.EdgeTraversal
            };

            // 解析端口
            if (!string.IsNullOrEmpty(fwRule.LocalPorts) && fwRule.LocalPorts != "*")
            {
                var (start, end) = ParsePortString(fwRule.LocalPorts);
                rule.LocalPortStart = start;
                rule.LocalPortEnd = end;
            }
            if (!string.IsNullOrEmpty(fwRule.RemotePorts) && fwRule.RemotePorts != "*")
            {
                var (start, end) = ParsePortString(fwRule.RemotePorts);
                rule.RemotePortStart = start;
                rule.RemotePortEnd = end;
            }

            return rule;
        }
        catch { return null; }
    }

    private static (int start, int end) ParsePortString(string portStr)
    {
        if (string.IsNullOrEmpty(portStr) || portStr == "*") return (0, 0);

        // 支持单个端口 "80" 或范围 "80-443" 或离散 "80,443,8080"
        if (portStr.Contains('-'))
        {
            var parts = portStr.Split('-');
            if (parts.Length == 2 && int.TryParse(parts[0], out var s) && int.TryParse(parts[1], out var e))
                return (s, e);
        }

        if (int.TryParse(portStr, out var single))
            return (single, single);

        // 离散端口取第一个
        var firstPort = portStr.Split(',')[0].Trim();
        if (int.TryParse(firstPort, out var p))
            return (p, p);

        return (0, 0);
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _localRules.Clear();
        // COM 对象由 GC 自动释放
        if (_fwPolicy != null && Marshal.IsComObject(_fwPolicy))
        {
            Marshal.ReleaseComObject(_fwPolicy);
        }
    }
}

// ===== Windows Firewall COM 互操作类型 =====

internal enum NET_FW_PROFILE_TYPE2
{
    NET_FW_PROFILE2_DOMAIN = 1,
    NET_FW_PROFILE2_PRIVATE = 2,
    NET_FW_PROFILE2_PUBLIC = 4,
    NET_FW_PROFILE2_ALL = 0x7FFFFFFF
}

internal enum NET_FW_ACTION_
{
    NET_FW_ACTION_BLOCK = 0,
    NET_FW_ACTION_ALLOW = 1
}

internal enum NET_FW_RULE_DIRECTION_
{
    NET_FW_RULE_DIR_IN = 1,
    NET_FW_RULE_DIR_OUT = 2
}

/// <summary>Windows Firewall COM 规则接口</summary>
[ComImport]
[Guid("AF230D27-BABA-4E42-ACED-F524F22CFCE2")]
[InterfaceType(ComInterfaceType.InterfaceIsIDispatch)]
internal interface INetFwRule
{
    string Name { get; set; }
    string Description { get; set; }
    string ApplicationName { get; set; }
    string serviceName { get; set; }
    int Protocol { get; set; }
    string LocalPorts { get; set; }
    string RemotePorts { get; set; }
    string LocalAddresses { get; set; }
    string RemoteAddresses { get; set; }
    string InterfaceTypes { get; set; }
    string Grouping { get; set; }
    int Profiles { get; set; }
    NET_FW_RULE_DIRECTION_ Direction { get; set; }
    NET_FW_ACTION_ Action { get; set; }
    bool Enabled { get; set; }
    bool EdgeTraversal { get; set; }
}

/// <summary>Windows Firewall 规则集合接口</summary>
[ComImport]
[Guid("B43D21CC-6F02-4B5F-B058-5D69F1F11053")]
[InterfaceType(ComInterfaceType.InterfaceIsIDispatch)]
internal interface INetFwRules
{
    int Count { get; }
    INetFwRule Add(INetFwRule rule);
    void Remove(string name);
    INetFwRule this[object index] { get; }
    IEnumerator GetEnumerator();
}

/// <summary>Windows Firewall 策略接口</summary>
[ComImport]
[Guid("98325047-C671-4174-8D81-DEFCD3F0319E")]
[InterfaceType(ComInterfaceType.InterfaceIsIDispatch)]
internal interface INetFwPolicy2
{
    INetFwRules Rules { get; }
    bool get_FirewallEnabled(NET_FW_PROFILE_TYPE2 profileType);
    void set_FirewallEnabled(NET_FW_PROFILE_TYPE2 profileType, bool enabled);
}
