using System.Net;
using System.Net.NetworkInformation;
using LightGuard.Core;
using Microsoft.Win32;

namespace LightGuard.Firewall;

/// <summary>
/// 系统代理信息记录
/// </summary>
public record ProxyInfo(string Address, int Port, bool Enabled);

/// <summary>
/// VPN 网络检测工具
/// 提供虚拟网卡识别、VPN 网段提取、系统代理读取、接口变更监听等功能
/// 用于防火墙 ACL 模块防止 VPN 绕过
/// </summary>
internal static class VpnNetworkTool
{
    // ===== 1. VPN 接口识别 =====

    /// <summary>
    /// 获取所有 VPN 虚拟网卡别名列表
    /// 遍历系统所有网卡，对比名称和描述与 <see cref="FirewallConst.VpnInterfaceKeywords"/> 关键词列表进行匹配
    /// </summary>
    /// <returns>匹配的 VPN 网卡名称列表</returns>
    public static List<string> GetAllVpnInterfaceAlias()
    {
        var result = new List<string>();
        try
        {
            foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (CheckIsVpnInterface(ni.Name) || CheckIsVpnInterface(ni.Description))
                {
                    if (!result.Contains(ni.Name))
                        result.Add(ni.Name);
                }
            }
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, "GetAllVpnInterfaceAlias");
        }
        return result;
    }

    // ===== 2. VPN 网段提取 =====

    /// <summary>
    /// 获取所有 VPN 网卡的 CIDR 网段列表
    /// 对每个 VPN 接口获取其单播地址并转换为 CIDR 格式，跳过回环和链路本地地址
    /// </summary>
    /// <returns>CIDR 网段列表（如 "10.8.0.1/24"）</returns>
    public static List<string> GetVpnIpRange()
    {
        var result = new List<string>();
        try
        {
            foreach (var alias in GetAllVpnInterfaceAlias())
            {
                foreach (var cidr in GetVpnIpRange(alias))
                {
                    if (!result.Contains(cidr))
                        result.Add(cidr);
                }
            }
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, "GetVpnIpRange");
        }
        return result;
    }

    /// <summary>
    /// 获取指定网卡的 CIDR 网段列表
    /// </summary>
    /// <param name="interfaceAlias">网卡名称</param>
    /// <returns>该网卡的 CIDR 网段列表，跳过回环和链路本地地址</returns>
    public static List<string> GetVpnIpRange(string interfaceAlias)
    {
        var result = new List<string>();
        try
        {
            foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (!string.Equals(ni.Name, interfaceAlias, StringComparison.OrdinalIgnoreCase))
                    continue;

                var ipProps = ni.GetIPProperties();
                foreach (var addr in ipProps.UnicastAddresses)
                {
                    var ip = addr.Address;

                    // 跳过回环地址
                    if (IPAddress.IsLoopback(ip))
                        continue;

                    var bytes = ip.GetAddressBytes();

                    // 跳过 IPv4 链路本地地址 (169.254.0.0/16)
                    if (bytes.Length == 4 && bytes[0] == 169 && bytes[1] == 254)
                        continue;

                    // 跳过 IPv6 链路本地地址 (fe80::/10)
                    if (ip.IsIPv6LinkLocal)
                        continue;

                    var cidr = $"{ip}/{addr.PrefixLength}";
                    if (!result.Contains(cidr))
                        result.Add(cidr);
                }
            }
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, $"GetVpnIpRange({interfaceAlias})");
        }
        return result;
    }

    // ===== 3. 系统代理读取 =====

    /// <summary>
    /// 读取 Windows 系统代理设置
    /// 从注册表 HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings 读取
    /// 支持 "127.0.0.1:7890" 和 "http=127.0.0.1:7890;https=..." 两种 ProxyServer 格式
    /// </summary>
    /// <returns>代理信息，包含地址、端口和启用状态；未启用或解析失败返回空值</returns>
    public static ProxyInfo GetSystemProxyInfo()
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(
                @"Software\Microsoft\Windows\CurrentVersion\Internet Settings");
            if (key == null)
                return new ProxyInfo("", 0, false);

            var enableVal = key.GetValue("ProxyEnable");
            bool enabled = enableVal is int ei && ei == 1;
            if (!enabled)
                return new ProxyInfo("", 0, false);

            var server = key.GetValue("ProxyServer")?.ToString() ?? "";
            if (string.IsNullOrWhiteSpace(server))
                return new ProxyInfo("", 0, false);

            var addressPart = ExtractProxyAddress(server);
            if (string.IsNullOrEmpty(addressPart))
                return new ProxyInfo("", 0, false);

            return ParseProxyAddress(addressPart, enabled);
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, "GetSystemProxyInfo");
            return new ProxyInfo("", 0, false);
        }
    }

    /// <summary>
    /// 从 ProxyServer 字符串中提取地址:端口部分
    /// 支持 "127.0.0.1:7890" 和 "http=127.0.0.1:7890;https=..." 两种格式
    /// </summary>
    private static string ExtractProxyAddress(string server)
    {
        // 多协议格式: "http=127.0.0.1:7890;https=127.0.0.1:7890"
        if (server.Contains(';'))
        {
            var entries = server.Split(';', StringSplitOptions.RemoveEmptyEntries);
            // 优先取 http= 条目
            var httpEntry = entries.FirstOrDefault(
                e => e.StartsWith("http=", StringComparison.OrdinalIgnoreCase));
            var entry = httpEntry ?? entries.FirstOrDefault();
            if (entry == null)
                return "";
            return entry.Contains('=')
                ? entry[(entry.IndexOf('=') + 1)..]
                : entry;
        }

        // 单条目格式: 可能带协议前缀 "http=127.0.0.1:7890"
        if (server.Contains('='))
            return server[(server.IndexOf('=') + 1)..];

        return server;
    }

    /// <summary>
    /// 解析 "地址:端口" 字符串，支持 IPv4 和 IPv6 ([::1]:port) 格式
    /// </summary>
    private static ProxyInfo ParseProxyAddress(string addr, bool enabled)
    {
        if (string.IsNullOrWhiteSpace(addr))
            return new ProxyInfo("", 0, enabled);

        addr = addr.Trim();

        // IPv6 格式: [::1]:8080
        if (addr.StartsWith('['))
        {
            var closeIdx = addr.IndexOf(']');
            if (closeIdx > 0)
            {
                var ipPart = addr[1..closeIdx];
                var portPart = addr[(closeIdx + 1)..];
                var port = 0;
                if (portPart.StartsWith(':') && int.TryParse(portPart[1..], out var p))
                    port = p;
                return new ProxyInfo(ipPart, port, enabled);
            }
        }

        // IPv4 格式: 127.0.0.1:8080
        var lastColon = addr.LastIndexOf(':');
        if (lastColon > 0)
        {
            var ipPart = addr[..lastColon];
            var portPart = addr[(lastColon + 1)..];
            var port = 0;
            if (int.TryParse(portPart, out var p))
                port = p;
            return new ProxyInfo(ipPart, port, enabled);
        }

        // 只有地址，没有端口
        return new ProxyInfo(addr, 0, enabled);
    }

    // ===== 4. VPN 接口判断 =====

    /// <summary>
    /// 判断指定接口名称是否为 VPN 虚拟网卡
    /// 将接口名称与 <see cref="FirewallConst.VpnInterfaceKeywords"/> 关键词列表进行匹配
    /// </summary>
    /// <param name="interfaceAlias">网卡名称或描述</param>
    /// <returns>匹配到 VPN 关键词返回 true，否则返回 false</returns>
    public static bool CheckIsVpnInterface(string interfaceAlias)
    {
        if (string.IsNullOrEmpty(interfaceAlias))
            return false;

        try
        {
            foreach (var keyword in FirewallConst.VpnInterfaceKeywords)
            {
                if (interfaceAlias.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                    return true;
            }
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, "CheckIsVpnInterface");
        }
        return false;
    }

    // ===== 5. 合并 VPN 网段列表 =====

    /// <summary>
    /// 获取合并后的 VPN CIDR 网段列表
    /// 将实际检测到的 VPN 接口网段与 <see cref="FirewallConst.CommonVpnCidrs"/> 常见 VPN 网段合并去重
    /// </summary>
    /// <returns>合并去重后的 CIDR 网段列表</returns>
    public static List<string> GetAllVpnCidrList()
    {
        var result = new List<string>();
        try
        {
            // 添加实际检测到的 VPN 接口网段
            foreach (var cidr in GetVpnIpRange())
            {
                if (!result.Contains(cidr))
                    result.Add(cidr);
            }

            // 添加常见 VPN 网段
            foreach (var cidr in FirewallConst.CommonVpnCidrs)
            {
                if (!result.Contains(cidr))
                    result.Add(cidr);
            }
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, "GetAllVpnCidrList");
        }
        return result;
    }

    // ===== 6. VPN 接口变更监听 =====

    /// <summary>
    /// 监听 VPN 接口的添加和移除事件
    /// 基于 <see cref="NetworkChange.NetworkAddressChanged"/> 事件，使用 500ms 防抖定时器避免频繁触发
    /// 当检测到 VPN 接口数量变化时调用回调
    /// </summary>
    /// <param name="onVpnChanged">VPN 接口变更时的回调</param>
    /// <returns>IDisposable 对象，调用 Dispose 取消监听</returns>
    public static IDisposable MonitorVpnInterfaces(Action onVpnChanged)
    {
        ArgumentNullException.ThrowIfNull(onVpnChanged);
        return new VpnInterfaceMonitor(onVpnChanged);
    }

    /// <summary>
    /// VPN 接口变更监控器
    /// 内部类，实现 IDisposable 用于取消事件订阅和释放定时器
    /// </summary>
    private sealed class VpnInterfaceMonitor : IDisposable
    {
        private const int DebounceMs = 500;

        private readonly Action _callback;
        private readonly System.Threading.Timer _debounceTimer;
        private int _lastVpnCount;
        private volatile bool _disposed;

        public VpnInterfaceMonitor(Action callback)
        {
            _callback = callback;
            _lastVpnCount = SafeGetVpnCount();
            // 创建定时器但暂不启动（dueTime = Infinite）
            _debounceTimer = new System.Threading.Timer(
                OnDebounceElapsed, null, Timeout.Infinite, Timeout.Infinite);
            NetworkChange.NetworkAddressChanged += OnNetworkAddressChanged;
            ErrorReporter.Log($"VPN 接口监控已启动，当前 VPN 接口数: {_lastVpnCount}");
        }

        /// <summary>
        /// 安全获取当前 VPN 接口数量，异常时返回 -1
        /// </summary>
        private static int SafeGetVpnCount()
        {
            try
            {
                return GetAllVpnInterfaceAlias().Count;
            }
            catch
            {
                return -1;
            }
        }

        /// <summary>
        /// 网络地址变更事件回调，重置防抖定时器
        /// </summary>
        private void OnNetworkAddressChanged(object? sender, EventArgs e)
        {
            if (_disposed) return;
            // 每次收到事件都重置定时器为 DebounceMs 后触发
            _debounceTimer.Change(DebounceMs, Timeout.Infinite);
        }

        /// <summary>
        /// 防抖定时器回调，检查 VPN 接口数量是否变化
        /// </summary>
        private void OnDebounceElapsed(object? state)
        {
            if (_disposed) return;
            try
            {
                var currentCount = SafeGetVpnCount();
                if (currentCount != _lastVpnCount)
                {
                    _lastVpnCount = currentCount;
                    ErrorReporter.Log($"VPN 接口数量变更: {currentCount}，触发回调");
                    _callback();
                }
            }
            catch (Exception ex)
            {
                ErrorReporter.Report(ex, "VpnInterfaceMonitor.OnDebounceElapsed");
            }
        }

        /// <summary>
        /// 取消事件订阅并释放定时器
        /// </summary>
        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;
            NetworkChange.NetworkAddressChanged -= OnNetworkAddressChanged;
            _debounceTimer.Change(Timeout.Infinite, Timeout.Infinite);
            _debounceTimer.Dispose();
            ErrorReporter.Log("VPN 接口监控已停止");
        }
    }
}
