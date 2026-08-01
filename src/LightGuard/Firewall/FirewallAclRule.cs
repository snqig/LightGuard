using System.Text.Json;
using System.Text.Json.Serialization;
using LightGuard.Core;

namespace LightGuard.Firewall;

/// <summary>
/// 防火墙 ACL 规则实体类 — 标准五元组全参数
/// 支持单程序、批量目录、纯端口 IP 三类规则
/// </summary>
public sealed class FirewallAclRule
{
    /// <summary>全局唯一 RuleId (GUID)</summary>
    public string RuleId { get; set; } = Guid.NewGuid().ToString("N");

    /// <summary>规则名称（统一命名规范，实际写入防火墙时会加前缀）</summary>
    public string RuleName { get; set; } = "";

    /// <summary>分组标签（用于批量管理）</summary>
    public string GroupTag { get; set; } = FirewallConst.GroupCustom;

    /// <summary>备注说明</summary>
    public string Remark { get; set; } = "";

    // ===== 基础控制字段 =====

    /// <summary>动作：Allow 允许 / Block 阻止</summary>
    public FirewallConst.FwAction Action { get; set; } = FirewallConst.FwAction.Block;

    /// <summary>方向：Inbound 入站 / Outbound 出站</summary>
    public FirewallConst.FwDirection Direction { get; set; } = FirewallConst.FwDirection.Outbound;

    /// <summary>是否启用</summary>
    public bool Enabled { get; set; } = true;

    /// <summary>规则优先级（数值越小优先级越高，默认 100）</summary>
    public int RulePriority { get; set; } = 100;

    // ===== 完整五元组字段 =====

    /// <summary>
    /// 本地地址：支持单 IP、CIDR、Any、IPv4/IPv6
    /// 多个用逗号分隔，如 "192.168.1.0/24,10.0.0.5"
    /// "*" 或空代表 Any
    /// </summary>
    public string LocalAddresses { get; set; } = "*";

    /// <summary>
    /// 远程地址：支持单 IP、CIDR、Any、IPv4/IPv6
    /// 多个用逗号分隔
    /// </summary>
    public string RemoteAddresses { get; set; } = "*";

    /// <summary>本地端口起始（0 代表全端口）</summary>
    public int LocalPortStart { get; set; } = 0;

    /// <summary>本地端口结束（0 代表单端口或全端口）</summary>
    public int LocalPortEnd { get; set; } = 0;

    /// <summary>远程端口起始（0 代表全端口）</summary>
    public int RemotePortStart { get; set; } = 0;

    /// <summary>远程端口结束（0 代表单端口或全端口）</summary>
    public int RemotePortEnd { get; set; } = 0;

    /// <summary>协议类型</summary>
    public FirewallConst.FwProtocol Protocol { get; set; } = FirewallConst.FwProtocol.Any;

    // ===== 程序 / 服务绑定字段 =====

    /// <summary>EXE 绝对路径，空值代表纯端口 IP 规则</summary>
    public string ApplicationPath { get; set; } = "";

    /// <summary>Windows 系统服务名（可选）</summary>
    public string ServiceName { get; set; } = "";

    // ===== 网络配置文件 =====

    /// <summary>网络配置文件（域/专用/公网/全部）</summary>
    public FirewallConst.FwProfile Profile { get; set; } = FirewallConst.FwProfile.All;

    // ===== 网卡接口扩展（防 VPN 绕过核心）=====

    /// <summary>网卡接口类型筛选</summary>
    public FirewallConst.FwInterfaceType InterfaceType { get; set; } = FirewallConst.FwInterfaceType.All;

    /// <summary>VPN 隧道网段黑名单 CIDR 列表（逗号分隔存储）</summary>
    public string VpnIpCidrList { get; set; } = "";

    // ===== 高级防火墙参数 =====

    /// <summary>边缘遍历（Edge Traversal），允许 NAT 穿透</summary>
    public bool EdgeTraversal { get; set; } = false;

    /// <summary>是否限制本地 IP 映射</summary>
    public bool LocalIpMappingLimit { get; set; } = false;

    // ===== 序列化方法（UTF-8 BOM + Unicode 安全编码）=====

    /// <summary>序列化为 JSON（使用 UnsafeRelaxedJsonEscaping 保证多语言字符不转义）</summary>
    public string ToJson()
    {
        return UnicodeTextHelper.SerializeToJsonWithBom(this);
    }

    /// <summary>从 JSON 反序列化</summary>
    public static FirewallAclRule? FromJson(string json)
    {
        try
        {
            var rule = JsonSerializer.Deserialize<FirewallAclRule>(json);
            rule?.SanitizeTexts();
            return rule;
        }
        catch
        {
            return null;
        }
    }

    /// <summary>从 JSON 列表反序列化</summary>
    public static List<FirewallAclRule>? FromJsonList(string json)
    {
        try
        {
            var rules = JsonSerializer.Deserialize<List<FirewallAclRule>>(json);
            if (rules != null)
            {
                foreach (var r in rules)
                    r.SanitizeTexts();
            }
            return rules;
        }
        catch
        {
            return null;
        }
    }

    /// <summary>序列化规则列表为 JSON（UTF-8 BOM 兼容）</summary>
    public static string ToJsonList(IEnumerable<FirewallAclRule> rules)
    {
        return UnicodeTextHelper.SerializeToJsonWithBom(rules.ToList());
    }

    /// <summary>
    /// 清洗所有文本字段（规则名/分组/备注）
    /// 在反序列化后和创建规则前调用，确保无非法字符
    /// </summary>
    public void SanitizeTexts()
    {
        RuleName = UnicodeTextHelper.SanitizeRuleName(RuleName);
        GroupTag = UnicodeTextHelper.SanitizeGroupTag(GroupTag);
        Remark = UnicodeTextHelper.SanitizeRemark(Remark);
    }

    // ===== 去重判断 =====

    /// <summary>
    /// 去重判断：两个规则是否功能等价
    /// 不依赖 RuleName 匹配，仅比较五元组功能参数，规避多语种字符导致查重异常
    /// </summary>
    public bool IsDuplicateOf(FirewallAclRule other)
    {
        return Action == other.Action
            && Direction == other.Direction
            && string.Equals(ApplicationPath, other.ApplicationPath, StringComparison.OrdinalIgnoreCase)
            && Protocol == other.Protocol
            && LocalPortStart == other.LocalPortStart
            && LocalPortEnd == other.LocalPortEnd
            && RemotePortStart == other.RemotePortStart
            && RemotePortEnd == other.RemotePortEnd
            && string.Equals(LocalAddresses, other.LocalAddresses, StringComparison.OrdinalIgnoreCase)
            && string.Equals(RemoteAddresses, other.RemoteAddresses, StringComparison.OrdinalIgnoreCase)
            && InterfaceType == other.InterfaceType
            && Profile == other.Profile;
    }

    /// <summary>获取端口范围描述文本</summary>
    public string GetPortDescription()
    {
        if (Protocol == FirewallConst.FwProtocol.ICMPv4 || Protocol == FirewallConst.FwProtocol.ICMPv6
            || Protocol == FirewallConst.FwProtocol.IGMP)
            return Protocol.ToString();

        var localPort = FormatPortRange(LocalPortStart, LocalPortEnd);
        var remotePort = FormatPortRange(RemotePortStart, RemotePortEnd);

        if (localPort == "*" && remotePort == "*")
            return "全端口";
        if (localPort == "*")
            return $"远程:{remotePort}";
        if (remotePort == "*")
            return $"本地:{localPort}";
        return $"本地:{localPort} 远程:{remotePort}";
    }

    private static string FormatPortRange(int start, int end)
    {
        if (start == 0 && end == 0) return "*";
        if (start == end) return start.ToString();
        if (end == 0) return start.ToString();
        return $"{start}-{end}";
    }

    /// <summary>获取网卡类型描述</summary>
    public string GetInterfaceDescription()
    {
        return InterfaceType switch
        {
            FirewallConst.FwInterfaceType.All => "全部网卡",
            FirewallConst.FwInterfaceType.PhysicalOnly => "仅物理网卡",
            FirewallConst.FwInterfaceType.VpnOnly => "仅VPN隧道",
            FirewallConst.FwInterfaceType.Wireless => "无线网卡",
            FirewallConst.FwInterfaceType.IPv6Tunnel => "IPv6隧道",
            _ => InterfaceType.ToString()
        };
    }

    /// <summary>获取完整规则描述（用于日志和 UI 显示）</summary>
    public string GetFullDescription()
    {
        var parts = new List<string>
        {
            Action == FirewallConst.FwAction.Block ? "阻止" : "允许",
            Direction == FirewallConst.FwDirection.Inbound ? "入站" : "出站",
            Protocol.ToString(),
            GetPortDescription()
        };

        if (!string.IsNullOrEmpty(ApplicationPath))
            parts.Add($"程序:{Path.GetFileName(ApplicationPath)}");

        if (RemoteAddresses != "*")
            parts.Add($"远程:{RemoteAddresses}");

        parts.Add(GetInterfaceDescription());

        return string.Join(" | ", parts);
    }

    /// <summary>生成防火墙规则名（带前缀）</summary>
    public string GetFirewallRuleName()
    {
        var dir = Direction == FirewallConst.FwDirection.Inbound ? "in" : "out";
        return $"{FirewallConst.RulePrefix}{RuleName}_{dir}";
    }

    /// <summary>深拷贝</summary>
    public FirewallAclRule Clone()
    {
        var json = ToJson();
        return FromJson(json) ?? new FirewallAclRule();
    }
}
