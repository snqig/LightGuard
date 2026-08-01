using System.Collections.ObjectModel;

namespace LightGuard.Firewall;

/// <summary>
/// 防火墙原生枚举、规则前缀常量、系统白名单路径、VPN 通用网段、高危端口列表
/// </summary>
public static class FirewallConst
{
    /// <summary>本程序创建的规则统一前缀，用于识别和清理</summary>
    public const string RulePrefix = "LG_ACL_";

    /// <summary>Hosts 劫持标记</summary>
    public const string HostsMarker = "# LightGuard Firewall Domain Block";
    public const string HostsEndMarker = "# LightGuard Firewall Domain Block End";

    // ===== 防火墙动作枚举映射 =====

    /// <summary>规则动作</summary>
    public enum FwAction
    {
        Allow = 0,
        Block = 1
    }

    /// <summary>规则方向</summary>
    public enum FwDirection
    {
        Inbound = 1,
        Outbound = 2
    }

    /// <summary>网络配置文件</summary>
    public enum FwProfile
    {
        Domain = 1,
        Private = 2,
        Public = 4,
        All = 0x7FFFFFFF
    }

    /// <summary>协议枚举</summary>
    public enum FwProtocol
    {
        /// <summary>TCP = 6</summary>
        TCP = 6,
        /// <summary>UDP = 17</summary>
        UDP = 17,
        /// <summary>ICMPv4 = 1</summary>
        ICMPv4 = 1,
        /// <summary>ICMPv6 = 58</summary>
        ICMPv6 = 58,
        /// <summary>IGMP = 2</summary>
        IGMP = 2,
        /// <summary>任意协议 = 256</summary>
        Any = 256
    }

    /// <summary>网卡接口类型</summary>
    public enum FwInterfaceType
    {
        /// <summary>全部网卡</summary>
        All,
        /// <summary>仅本地物理网卡（LAN/WiFi）</summary>
        PhysicalOnly,
        /// <summary>仅 VPN 隧道接口</summary>
        VpnOnly,
        /// <summary>无线网卡</summary>
        Wireless,
        /// <summary>IPv6 隧道</summary>
        IPv6Tunnel
    }

    // ===== 系统白名单路径（不会误拦截 Windows 核心服务）=====

    /// <summary>系统核心程序白名单（绝对路径前缀匹配）</summary>
    public static readonly ReadOnlyCollection<string> SystemWhitelistPaths = Array.AsReadOnly(new[]
    {
        @"C:\Windows\System32\",
        @"C:\Windows\SysWOW64\",
        @"C:\Windows\WinSxS\",
        @"C:\Windows\servicing\",
        @"C:\Windows\SoftwareDistribution\",
        @"C:\Windows\Microsoft.NET\",
        @"C:\Program Files\WindowsApps\",
        @"C:\Program Files\Windows Defender\",
        @"C:\ProgramData\Microsoft\Windows Defender\",
        @"C:\Windows\explorer.exe",
        @"C:\Windows\System32\svchost.exe",
        @"C:\Windows\System32\lsass.exe",
        @"C:\Windows\System32\services.exe",
        @"C:\Windows\System32\winlogon.exe",
        @"C:\Windows\System32\csrss.exe",
        @"C:\Windows\System32\smss.exe",
        @"C:\Windows\System32\wininit.exe",
        @"C:\Windows\System32\dns.exe",
        @"C:\Windows\System32\spoolsv.exe",
        @"C:\Windows\System32\rpcss.dll",
    });

    /// <summary>系统核心进程名白名单</summary>
    public static readonly ReadOnlyCollection<string> SystemWhitelistProcesses = Array.AsReadOnly(new[]
    {
        "svchost", "lsass", "services", "winlogon", "csrss", "smss",
        "wininit", "explorer", "System", "Idle", "dwm", "fontdrvhost",
        "RuntimeBroker", "SearchIndexer", "Search", "sihost",
        "taskhostw", "ctfmon", "conhost", "dllhost", "spoolsv",
        "MsMpEng", "MsSense", "SecurityHealthService", "NisSrv",
        "WmiPrvSE", "audiodg", "WUDFHost", "wbengine",
    });

    // ===== 高危端口列表 =====

    /// <summary>勒索病毒常用高危端口（SMB/RDP/NetBION 等）</summary>
    public static readonly ReadOnlyCollection<int> HighRiskPorts = Array.AsReadOnly(new[]
    {
        135,   // RPC
        139,   // NetBIOS Session
        445,   // SMB
        3389,  // RDP
        5985,  // WinRM HTTP
        5986,  // WinRM HTTPS
    });

    // ===== 代理端口列表 =====

    /// <summary>常见本地代理端口</summary>
    public static readonly ReadOnlyCollection<int> ProxyPorts = Array.AsReadOnly(new[]
    {
        1080,  // SOCKS5
        1081,  // SOCKS5 alt
        7890,  // Clash
        7891,  // Clash alt
        8080,  // HTTP proxy
        8118,  // Privoxy
        8123,  // Polipo
        9090,  // V2Ray
        10808, // V2Ray SOCKS
        10809, // V2Ray HTTP
        20171, // Shadowsocks
    });

    // ===== VPN 通用网段 =====

    /// <summary>常见 VPN 虚拟网段（CIDR）</summary>
    public static readonly ReadOnlyCollection<string> CommonVpnCidrs = Array.AsReadOnly(new[]
    {
        "10.0.0.0/8",
        "10.8.0.0/16",    // OpenVPN 默认
        "10.13.0.0/16",   // WireGuard 常见
        "10.64.0.0/16",   // V2Ray Tun 常见
        "10.100.0.0/16",  // 企业 VPN 常见
        "10.200.0.0/16",  // 企业 VPN
        "172.16.0.0/12",  // 私有网段
        "192.168.0.0/16", // 私有网段
    });

    /// <summary>VPN 虚拟网卡关键词（用于接口识别）</summary>
    public static readonly ReadOnlyCollection<string> VpnInterfaceKeywords = Array.AsReadOnly(new[]
    {
        "Wintun",          // WireGuard Wintun
        "WireGuard",       // WireGuard TUN
        "TAP-Windows",     // OpenVPN TAP
        "TAP-Win32",       // OpenVPN TAP 旧版
        "WAN Miniport",    // Windows VPN
        "PPTP",            // PPTP VPN
        "L2TP",            // L2TP VPN
        "SSTP",            // SSTP VPN
        "IKEv2",           // IKEv2 VPN
        "V2Ray",           // V2Ray Tun
        "tun0",            // 通用 TUN
        "utun",            // macOS utun（兼容）
        "Clash",           // Clash Tun
        "NekoBox",         // NekoBox Tun
        "Sing-box",        // Sing-box Tun
        "OpenVPN",         // OpenVPN
    });

    // ===== 预设模板分组标签 =====

    public const string GroupAdobe = "Adobe全家桶封锁";
    public const string GroupRogueUpdate = "流氓软件更新拦截";
    public const string GroupRansomPort = "勒索高危端口";
    public const string GroupEmergency = "勒索应急断网";
    public const string GroupCustom = "自定义规则";

    // ===== Adobe 域名列表（用于 Hosts 劫持）=====

    public static readonly ReadOnlyCollection<string> AdobeDomains = Array.AsReadOnly(new[]
    {
        "lm.licenses.adobe.com",
        "na1r.services.adobe.com",
        "swupmf.adobe.com",
        "swupdl.adobe.com",
        "genuine.adobe.com",
        "agsupdate.adobe.com",
        "prod.adobegenuine.com",
        "crl.versign.com",
        "ocsp.verisign.com",
        "lcs-certs.adobe.com",
        "ns.adobe.com",
        "activate.adobe.com",
        "practivate.adobe.com",
        "ereg.adobe.com",
        "wip3.adobe.com",
        "hlrcv.stage.adobe.com",
    });

    // ===== WPS/360/Edge 更新域名 =====

    public static readonly ReadOnlyCollection<string> RogueUpdateDomains = Array.AsReadOnly(new[]
    {
        "update.wpscdn.cn",
        "ad.wpscdn.cn",
        "news.wpscdn.cn",
        "cloud.wpscdn.cn",
        "config.wpscdn.cn",
        "dl.360safe.com",
        "update.360safe.com",
        "softupdate.360.cn",
        "edgedl.me.gfx.ms",
        "msedge.api.cdp.microsoft.com",
    });
}
