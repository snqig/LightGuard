using System.Diagnostics;
using System.Management;
using LightGuard.Core;
using LightGuard.Core.Interfaces;
using LightGuard.Firewall;
using LightGuard.Native;

namespace LightGuard.Modules;

/// <summary>
/// 网络连接信息（供 UI 显示）
/// </summary>
public sealed class NetworkConnection
{
    /// <summary>协议（TCP/UDP）</summary>
    public string Protocol { get; set; } = "";

    /// <summary>本地地址</summary>
    public string LocalAddress { get; set; } = "";

    /// <summary>远程地址</summary>
    public string ForeignAddress { get; set; } = "";

    /// <summary>连接状态</summary>
    public string State { get; set; } = "";

    /// <summary>进程 PID</summary>
    public int PID { get; set; }

    /// <summary>进程名称</summary>
    public string ProcessName { get; set; } = "";

    /// <summary>是否为可疑连接</summary>
    public bool IsSuspicious { get; set; }

    /// <summary>进程完整路径</summary>
    public string ProcessPath { get; set; } = "";
}

/// <summary>
/// Windows Defender 状态信息
/// </summary>
public sealed class DefenderStatusInfo
{
    /// <summary>Defender 是否已安装</summary>
    public bool IsInstalled { get; set; }

    /// <summary>反间谍软件是否启用</summary>
    public bool AntiSpywareEnabled { get; set; }

    /// <summary>实时保护是否启用</summary>
    public bool RealTimeProtectionEnabled { get; set; }

    /// <summary>防病毒是否启用</summary>
    public bool AntivirusEnabled { get; set; }

    /// <summary>运行模式</summary>
    public string RunningMode { get; set; } = "未知";

    /// <summary>病毒库最后更新时间</summary>
    public DateTime? SignatureLastUpdated { get; set; }

    /// <summary>引擎版本</summary>
    public string EngineVersion { get; set; } = "未知";

    /// <summary>是否与 LightGuard 冲突（双杀检测）</summary>
    public bool HasConflict { get; set; }
}

/// <summary>
/// 原生高级防火墙可视化模块
/// 功能：完整入站/出站规则管理、智能拦截流氓软件偷流量、
/// 禁止软件捆绑后台联网/广告推送联网、Windows Defender 智能兼容
/// </summary>
public sealed class FirewallModule : ModuleBase
{
    /// <summary>
    /// 已知流氓软件进程名列表
    /// 这些进程会偷传流量、推送广告、后台联网
    /// </summary>
    private static readonly string[] KnownRogueProcesses = new[]
    {
        // 360 系列
        "360tray.exe", "360sd.exe", "360safe.exe", "360se.exe",
        "360leakfixer.exe", "360doctor.exe", "360conf.exe",
        // 2345 系列
        "2345Explorer.exe", "2345Pic.exe", "2345MiniPage.exe",
        "2345MPC.exe", "2345SoftManager.exe", "2345SpeedUp.exe",
        // WPS 系列
        "wpscloudsvr.exe", "wpscenter.exe", "wpsupdate.exe",
        "wps.exe", "wpscloudlaunch.exe", "wpsmeeting.exe",
        "kingsoftrpcserver.exe", "kxescore.exe",
        // 百度系列
        "baidusd.exe", "baidusf.exe", "baiduhi.exe",
        "baidubrowser.exe", "baiduinput.exe",
        // 腾讯系列
        "tencentdl.exe", "qqpcmgr.exe", "qqpctray.exe",
        "qqpcrealtimespeedup.exe", "tenioce.exe",
        // 搜狗系列
        "sogoucloud.exe", "sogouinput.exe", "sogouexplorer.exe",
        // 其他
        "hao123.exe", "kugou.exe", "toutiao.exe",
        "byteboost.exe", "fastsearch.exe",
        "miaokit.exe", "bundlemgr.exe"
    };

    /// <summary>
    /// 已知流氓软件常见安装路径（用于预防性阻止）
    /// </summary>
    private static readonly string[] KnownRoguePaths = new[]
    {
        @"C:\Program Files\360\360Safe\360tray.exe",
        @"C:\Program Files (x86)\360\360Safe\360tray.exe",
        @"C:\Program Files\360\360se\360se.exe",
        @"C:\Program Files (x86)\360\360se\360se.exe",
        @"C:\Program Files\2345Soft\2345Explorer\2345Explorer.exe",
        @"C:\Program Files (x86)\2345Soft\2345Explorer\2345Explorer.exe",
        @"C:\Users\Public\Documents\Kingsoft\office6\wpscloudsvr.exe",
        @"C:\Program Files\WPS Office\office6\wpscloudsvr.exe",
        @"C:\Program Files (x86)\WPS Office\office6\wpscloudsvr.exe",
        @"C:\Program Files\baidu\BaiduSd\BaiduSd.exe",
        @"C:\Program Files (x86)\baidu\BaiduSd\BaiduSd.exe",
        @"C:\Program Files\Tencent\QQPCMgr\QQPCMgr.exe",
        @"C:\Program Files (x86)\Tencent\QQPCMgr\QQPCMgr.exe",
        @"C:\Program Files\sogou\SogouInput\SogouCloud.exe",
        @"C:\Program Files (x86)\sogou\SogouInput\SogouCloud.exe"
    };

    /// <summary>
    /// 广告/遥测域名列表（从 HostsHelper 获取并合并配置）
    /// </summary>
    private List<string> _adDomains = new();

    /// <summary>
    /// 已阻止的流氓程序名称集合（避免重复阻止）
    /// </summary>
    private readonly HashSet<string> _blockedPrograms = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// 智能拦截检测定时器
    /// </summary>
    private System.Threading.Timer? _detectTimer;

    /// <summary>
    /// 最后一次检测到的网络连接列表
    /// </summary>
    private List<NetworkConnection> _lastConnections = new();

    /// <summary>
    /// 最后一次 Defender 状态
    /// </summary>
    private DefenderStatusInfo _lastDefenderStatus = new();

    /// <summary>
    /// 扫描时是否已接管 Defender（双杀不冲突策略）
    /// </summary>
    private bool _hasTakenOverDefender;

    /// <summary>
    /// 防火墙 ACL 核心管理器（五元组全参数规则管理）
    /// </summary>
    private FirewallAclManager? _aclManager;

    /// <summary>
    /// VPN 接口变更监听器（动态适配拦截策略）
    /// </summary>
    private IDisposable? _vpnMonitor;

    /// <summary>
    /// 获取防火墙 ACL 管理器实例（供 UI 调用）
    /// </summary>
    public FirewallAclManager? AclManager => _aclManager;

    public FirewallModule(AppState appState) : base(appState)
    {
        // 初始化广告域名列表：合并内置库和配置中的自定义域名
        _adDomains = new List<string>(HostsHelper.CommonAdDomains);
    }

    /// <inheritdoc/>
    public override string Id => "firewall";

    /// <inheritdoc/>
    public override string DisplayName => "防火墙管理";

    /// <inheritdoc/>
    public override string Description => "原生高级防火墙：入站/出站规则管理、智能拦截流氓软件偷流量、禁止后台广告联网、Windows Defender 智能兼容";

    /// <inheritdoc/>
    public override ModuleCategory Category => ModuleCategory.Firewall;

    /// <inheritdoc/>
    protected override async Task OnInitializeAsync()
    {
        await Task.Run(() =>
        {
            // 合并配置中的自定义屏蔽域名
            var configDomains = AppState.Config.Firewall.BlockedDomains;
            if (configDomains != null && configDomains.Count > 0)
            {
                foreach (var domain in configDomains)
                {
                    if (!_adDomains.Contains(domain))
                        _adDomains.Add(domain);
                }
            }

            // 检查防火墙初始状态
            if (!FirewallHelper.IsFirewallEnabled())
            {
                ErrorReporter.Log("防火墙未启用，将在模块启用时自动开启", "WARN");
            }

            // 初始检测 Defender 状态
            _lastDefenderStatus = CheckDefenderStatus();

            // 初始化防火墙 ACL 管理器
            _aclManager = new FirewallAclManager();
            if (_aclManager.TestFirewallComConnect())
            {
                // 加载已存在的本程序创建的防火墙规则
                _aclManager.LoadExistingRules();
                ErrorReporter.Log($"防火墙 ACL 管理器已初始化，加载 {_aclManager.GetAllLocalRules().Count} 条已有规则");
            }
            else
            {
                ErrorReporter.Log("防火墙 COM 组件连接失败，ACL 功能不可用", "ERROR");
            }

            ErrorReporter.Log($"防火墙模块初始化完成，广告域名 {_adDomains.Count} 条，Defender 已安装: {_lastDefenderStatus.IsInstalled}");
        });
    }

    /// <inheritdoc/>
    protected override async Task OnEnableAsync()
    {
        await Task.Run(() =>
        {
            var config = AppState.Config.Firewall;

            // 1. 确保防火墙已启用
            if (!FirewallHelper.IsFirewallEnabled())
            {
                FirewallHelper.EnableFirewall();
                ErrorReporter.Log("已自动启用 Windows 防火墙");
            }

            // 2. 预防性阻止已知流氓软件路径联网
            if (config.SmartIntercept)
            {
                BlockKnownRogueSoftware();
            }

            // 3. 应用广告域名屏蔽（通过 Hosts 文件）
            if (config.BlockAds)
            {
                HostsHelper.AddAdBlockRules(_adDomains);
                ErrorReporter.Log($"已应用 {_adDomains.Count} 条广告域名屏蔽规则");
            }

            // 4. 启动智能拦截定时器（每 60 秒检测一次可疑连接）
            if (config.SmartIntercept)
            {
                _detectTimer = new System.Threading.Timer(
                    callback: _ => DetectSuspiciousConnections(),
                    state: null,
                    dueTime: TimeSpan.FromSeconds(10),
                    period: TimeSpan.FromSeconds(60));
                ErrorReporter.Log("智能拦截检测已启动（间隔 60 秒）");
            }

            // 5. 首次执行可疑连接检测
            DetectSuspiciousConnections();

            // 6. 启动 VPN 接口动态监听（新增 VPN 适配器自动适配拦截策略）
            if (_aclManager != null)
            {
                _vpnMonitor = VpnNetworkTool.MonitorVpnInterfaces(() =>
                {
                    try
                    {
                        _aclManager.RefreshVpnRules();
                        ErrorReporter.Log("VPN 接口变更，已自动刷新拦截策略");
                    }
                    catch (Exception ex)
                    {
                        ErrorReporter.Report(ex, "VPN 接口变更刷新失败");
                    }
                });
            }
        });
    }

    /// <inheritdoc/>
    protected override async Task OnDisableAsync()
    {
        await Task.Run(() =>
        {
            // 停止 VPN 接口监听
            _vpnMonitor?.Dispose();
            _vpnMonitor = null;

            // 停止检测定时器
            _detectTimer?.Dispose();
            _detectTimer = null;

            // 如果之前接管了 Defender，交还控制权
            if (_hasTakenOverDefender)
            {
                ResumeDefenderProtection();
            }

            ErrorReporter.Log("防火墙模块已禁用，检测定时器已停止");
        });
    }

    /// <inheritdoc/>
    protected override void OnReleaseResources()
    {
        _detectTimer?.Dispose();
        _detectTimer = null;
        _vpnMonitor?.Dispose();
        _vpnMonitor = null;
        _aclManager?.Dispose();
        _aclManager = null;
        _blockedPrograms.Clear();
        _lastConnections.Clear();
    }

    /// <summary>
    /// 获取防火墙规则列表（供 UI 显示）
    /// </summary>
    public List<FirewallRule> GetFirewallRules()
    {
        return FirewallHelper.GetAllRules();
    }

    /// <summary>
    /// 获取网络连接列表（供 UI 显示）
    /// </summary>
    public List<NetworkConnection> GetNetworkConnections()
    {
        return ParseNetstatOutput(RunNetstat());
    }

    /// <summary>
    /// 获取 Windows Defender 状态信息（供 UI 显示）
    /// </summary>
    public DefenderStatusInfo GetDefenderStatus()
    {
        _lastDefenderStatus = CheckDefenderStatus();
        return _lastDefenderStatus;
    }

    /// <summary>
    /// 添加防火墙阻止规则
    /// </summary>
    /// <param name="name">规则名称</param>
    /// <param name="programPath">程序路径</param>
    /// <param name="inbound">阻止入站</param>
    /// <param name="outbound">阻止出站</param>
    /// <returns>是否成功</returns>
    public bool AddBlockRule(string name, string programPath, bool inbound = true, bool outbound = true)
    {
        var success = FirewallHelper.AddBlockRule(name, programPath, inbound, outbound);
        if (success)
            ErrorReporter.Log($"已添加防火墙阻止规则: {name} -> {programPath}");
        return success;
    }

    /// <summary>
    /// 删除防火墙规则
    /// </summary>
    /// <param name="name">规则名称</param>
    /// <returns>是否成功</returns>
    public bool RemoveRule(string name)
    {
        var success = FirewallHelper.RemoveRule(name);
        if (success)
            ErrorReporter.Log($"已删除防火墙规则: {name}");
        return success;
    }

    /// <summary>
    /// 阻止指定程序联网
    /// </summary>
    /// <param name="name">规则名称</param>
    /// <param name="programPath">程序完整路径</param>
    /// <returns>是否成功</returns>
    public bool BlockProgram(string name, string programPath)
    {
        var success = FirewallHelper.BlockProgram(name, programPath);
        if (success)
        {
            _blockedPrograms.Add(name);
            ErrorReporter.Log($"已阻止程序联网: {name} -> {programPath}");
        }
        return success;
    }

    /// <summary>
    /// 解除程序联网阻止
    /// </summary>
    /// <param name="name">规则名称</param>
    /// <returns>是否成功</returns>
    public bool UnblockProgram(string name)
    {
        var success = FirewallHelper.UnblockProgram(name);
        if (success)
        {
            _blockedPrograms.Remove(name);
            ErrorReporter.Log($"已解除程序联网阻止: {name}");
        }
        return success;
    }

    /// <summary>
    /// 一键启用防火墙
    /// </summary>
    /// <returns>是否成功</returns>
    public bool EnableFirewall()
    {
        return FirewallHelper.EnableFirewall();
    }

    /// <summary>
    /// 检查防火墙是否启用
    /// </summary>
    /// <returns>是否启用</returns>
    public bool IsFirewallEnabled()
    {
        return FirewallHelper.IsFirewallEnabled();
    }

    /// <summary>
    /// 智能拦截流氓软件偷流量
    /// 使用 netstat 检测异常网络连接，自动阻止可疑程序联网
    /// </summary>
    public void DetectSuspiciousConnections()
    {
        try
        {
            // 执行 netstat -ano 获取所有网络连接
            var output = RunNetstat();
            var connections = ParseNetstatOutput(output);

            // 标记可疑连接并自动阻止
            var suspiciousCount = 0;
            foreach (var conn in connections)
            {
                if (IsProcessSuspicious(conn.ProcessName))
                {
                    conn.IsSuspicious = true;
                    suspiciousCount++;

                    // 自动阻止可疑程序联网（仅阻止出站，避免影响系统功能）
                    if (!string.IsNullOrEmpty(conn.ProcessPath) && File.Exists(conn.ProcessPath))
                    {
                        var ruleName = $"LightGuard_Block_{conn.ProcessName}";
                        if (!_blockedPrograms.Contains(ruleName))
                        {
                            FirewallHelper.BlockProgram(ruleName, conn.ProcessPath);
                            _blockedPrograms.Add(ruleName);
                            ErrorReporter.Log($"智能拦截：已自动阻止流氓程序联网 [{conn.ProcessName}] PID={conn.PID} 远程={conn.ForeignAddress}", "WARN");
                        }
                    }
                }
            }

            _lastConnections = connections;

            if (suspiciousCount > 0)
            {
                ErrorReporter.Log($"智能拦截检测完成：发现 {suspiciousCount} 个可疑连接，已自动阻止", "WARN");
            }
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, "智能拦截检测失败");
        }
    }

    /// <summary>
    /// 预防性阻止已知流氓软件路径联网
    /// </summary>
    private void BlockKnownRogueSoftware()
    {
        var blocked = 0;
        foreach (var path in KnownRoguePaths)
        {
            if (File.Exists(path))
            {
                var name = Path.GetFileNameWithoutExtension(path);
                var ruleName = $"LightGuard_Prevent_{name}";
                if (!_blockedPrograms.Contains(ruleName))
                {
                    if (FirewallHelper.BlockProgram(ruleName, path))
                    {
                        _blockedPrograms.Add(ruleName);
                        blocked++;
                    }
                }
            }
        }

        if (blocked > 0)
        {
            ErrorReporter.Log($"预防性阻止：已阻止 {blocked} 个已知流氓软件联网");
        }
    }

    /// <summary>
    /// 判断进程是否为可疑流氓软件
    /// </summary>
    /// <param name="processName">进程名</param>
    /// <returns>是否可疑</returns>
    private bool IsProcessSuspicious(string processName)
    {
        if (string.IsNullOrEmpty(processName))
            return false;

        // 与已知流氓软件进程名列表匹配（不区分大小写）
        foreach (var rogue in KnownRogueProcesses)
        {
            if (string.Equals(processName, rogue, StringComparison.OrdinalIgnoreCase))
                return true;
        }

        return false;
    }

    /// <summary>
    /// 执行 netstat -ano 命令并返回输出
    /// </summary>
    private static string RunNetstat()
    {
        var psi = new ProcessStartInfo
        {
            FileName = "netstat.exe",
            Arguments = "-ano",
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            StandardOutputEncoding = System.Text.Encoding.UTF8
        };

        using var proc = Process.Start(psi);
        var output = proc?.StandardOutput.ReadToEnd() ?? "";
        proc?.WaitForExit(10000);
        return output;
    }

    /// <summary>
    /// 解析 netstat 输出为网络连接列表
    /// </summary>
    private static List<NetworkConnection> ParseNetstatOutput(string output)
    {
        var connections = new List<NetworkConnection>();
        if (string.IsNullOrEmpty(output))
            return connections;

        var lines = output.Split('\n', StringSplitOptions.RemoveEmptyEntries);

        foreach (var line in lines)
        {
            var trimmed = line.Trim();
            if (trimmed.Length < 5)
                continue;

            // 跳过表头行
            if (trimmed.StartsWith("Proto", StringComparison.OrdinalIgnoreCase) ||
                trimmed.StartsWith("活动连接", StringComparison.OrdinalIgnoreCase) ||
                trimmed.StartsWith("Active Connections", StringComparison.OrdinalIgnoreCase))
                continue;

            var parts = trimmed.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 4)
                continue;

            var conn = new NetworkConnection
            {
                Protocol = parts[0]
            };

            // TCP 连接有状态字段：Proto Local Foreign State PID
            // UDP 连接可能没有状态：Proto Local Foreign * PID
            if (parts.Length >= 5 && int.TryParse(parts[^1], out var pid))
            {
                conn.LocalAddress = parts[1];
                conn.ForeignAddress = parts[2];
                conn.State = parts[3];
                conn.PID = pid;
            }
            else if (parts.Length >= 4 && int.TryParse(parts[^1], out var pidUdp))
            {
                conn.LocalAddress = parts[1];
                conn.ForeignAddress = parts[2];
                conn.State = "*";
                conn.PID = pidUdp;
            }
            else
            {
                continue;
            }

            // 获取进程名和路径
            try
            {
                using var proc = Process.GetProcessById(conn.PID);
                conn.ProcessName = proc.ProcessName;

                // 尝试获取进程完整路径
                try
                {
                    conn.ProcessPath = proc.MainModule?.FileName ?? "";
                }
                catch
                {
                    // 访问被拒绝或进程已退出，忽略路径
                    conn.ProcessPath = "";
                }
            }
            catch
            {
                // 进程可能已退出
            }

            connections.Add(conn);
        }

        return connections;
    }

    /// <summary>
    /// 检查 Windows Defender 运行状态
    /// 使用 ManagementObjectSearcher 查询 AntiSpywareEnabled 和 RealTimeProtectionEnabled
    /// </summary>
    /// <returns>Defender 状态信息</returns>
    public static DefenderStatusInfo CheckDefenderStatus()
    {
        var info = new DefenderStatusInfo();

        try
        {
            // 查询 Windows Defender WMI 命名空间
            using var searcher = new ManagementObjectSearcher(
                @"root\Microsoft\WindowsDefender",
                "SELECT * FROM MSFT_MpComputerStatus");

            foreach (var obj in searcher.Get().Cast<ManagementObject>())
            {
                info.IsInstalled = true;

                // 反间谍软件启用状态
                info.AntiSpywareEnabled = Convert.ToBoolean(obj["AntispywareEnabled"]);

                // 实时保护启用状态
                info.RealTimeProtectionEnabled = Convert.ToBoolean(obj["RealTimeProtectionEnabled"]);

                // 防病毒启用状态
                info.AntivirusEnabled = Convert.ToBoolean(obj["AntivirusEnabled"]);

                // 运行模式
                info.RunningMode = obj["AMRunningMode"]?.ToString() ?? "未知";

                // 病毒库最后更新时间
                var sigTime = obj["AntivirusSignatureLastUpdated"]?.ToString();
                if (DateTime.TryParse(sigTime, out var sigDate))
                    info.SignatureLastUpdated = sigDate;

                // 引擎版本
                info.EngineVersion = obj["AMEngineVersion"]?.ToString() ?? "未知";

                // 双杀冲突检测：如果 Defender 实时保护启用且 LightGuard 也在扫描
                info.HasConflict = info.RealTimeProtectionEnabled && info.AntiSpywareEnabled;
                break;
            }
        }
        catch
        {
            // WMI 查询失败，尝试备用方案：通过注册表检查
            try
            {
                using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                    @"SOFTWARE\Microsoft\Windows Defender\Real-Time Protection");
                if (key != null)
                {
                    info.IsInstalled = true;
                    var rtValue = key.GetValue("DisableRealtimeMonitoring");
                    info.RealTimeProtectionEnabled = rtValue is int v && v == 0;
                }

                using var key2 = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                    @"SOFTWARE\Microsoft\Windows Defender");
                if (key2 != null)
                {
                    info.IsInstalled = true;
                    var avValue = key2.GetValue("DisableAntiVirus");
                    info.AntivirusEnabled = avValue is int av && av == 0;
                    info.AntiSpywareEnabled = info.AntivirusEnabled;
                }
            }
            catch
            {
                // Defender 可能未安装
                info.IsInstalled = false;
            }
        }

        return info;
    }

    /// <summary>
    /// 双杀不冲突策略 - 扫描时平滑接管 Defender
    /// 临时关闭 Defender 实时保护，避免与 LightGuard 扫描冲突
    /// </summary>
    public void TakeOverDefenderProtection()
    {
        if (_hasTakenOverDefender)
            return;

        try
        {
            var status = CheckDefenderStatus();
            if (!status.IsInstalled || !status.RealTimeProtectionEnabled)
            {
                _hasTakenOverDefender = true;
                return;
            }

            // 通过 PowerShell 临时关闭 Defender 实时保护
            // 注意：需要管理员权限和 Tamper Protection 关闭
            var psi = new ProcessStartInfo
            {
                FileName = "powershell.exe",
                Arguments = "-Command \"Set-MpPreference -DisableRealtimeMonitoring $true\"",
                UseShellExecute = false,
                CreateNoWindow = true,
                Verb = "runas"
            };

            using var proc = Process.Start(psi);
            proc?.WaitForExit(10000);

            _hasTakenOverDefender = true;
            ErrorReporter.Log("双杀策略：已临时接管 Defender 实时保护，扫描期间由 LightGuard 接管");
        }
        catch (Exception ex)
        {
            // 接管失败不影响扫描流程
            ErrorReporter.Report(ex, "接管 Defender 失败（不影响 LightGuard 扫描）");
            _hasTakenOverDefender = true; // 标记为已接管，避免重复尝试
        }
    }

    /// <summary>
    /// 双杀不冲突策略 - 扫描结束自动交还 Defender
    /// 恢复 Defender 实时保护
    /// </summary>
    public void ResumeDefenderProtection()
    {
        if (!_hasTakenOverDefender)
            return;

        try
        {
            // 恢复 Defender 实时保护
            var psi = new ProcessStartInfo
            {
                FileName = "powershell.exe",
                Arguments = "-Command \"Set-MpPreference -DisableRealtimeMonitoring $false\"",
                UseShellExecute = false,
                CreateNoWindow = true,
                Verb = "runas"
            };

            using var proc = Process.Start(psi);
            proc?.WaitForExit(10000);

            _hasTakenOverDefender = false;
            ErrorReporter.Log("双杀策略：已交还 Defender 实时保护");
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, "恢复 Defender 实时保护失败");
        }
        finally
        {
            _hasTakenOverDefender = false;
        }
    }

    /// <summary>
    /// 获取广告域名列表
    /// </summary>
    public List<string> GetAdDomains()
    {
        return new List<string>(_adDomains);
    }

    /// <summary>
    /// 添加自定义屏蔽域名
    /// </summary>
    public void AddBlockedDomain(string domain)
    {
        if (!_adDomains.Contains(domain, StringComparer.OrdinalIgnoreCase))
        {
            _adDomains.Add(domain);
            AppState.Config.Firewall.BlockedDomains.Add(domain);
            ConfigManager.Save(AppState.Config);
            ErrorReporter.Log($"已添加屏蔽域名: {domain}");
        }
    }

    /// <summary>
    /// 刷新广告域名屏蔽规则（重新写入 Hosts）
    /// </summary>
    public void RefreshAdBlockRules()
    {
        HostsHelper.AddAdBlockRules(_adDomains);
        ErrorReporter.Log($"已刷新广告域名屏蔽规则（共 {_adDomains.Count} 条）");
    }

    /// <inheritdoc/>
    protected override string GetStatusSummary()
    {
        var firewallOn = FirewallHelper.IsFirewallEnabled();
        var blockedCount = _blockedPrograms.Count;
        var defenderOn = _lastDefenderStatus.IsInstalled && _lastDefenderStatus.RealTimeProtectionEnabled;
        var aclRuleCount = _aclManager?.GetAllLocalRules().Count ?? 0;
        var vpnCount = VpnNetworkTool.GetAllVpnInterfaceAlias().Count;
        return $"防火墙: {(firewallOn ? "已启用" : "未启用")} | ACL规则: {aclRuleCount} | 已阻止程序: {blockedCount} | VPN接口: {vpnCount} | Defender: {(defenderOn ? "运行中" : "未运行")} | 广告域名: {_adDomains.Count} 条";
    }
}
