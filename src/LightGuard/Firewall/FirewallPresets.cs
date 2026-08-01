using LightGuard.Core;

namespace LightGuard.Firewall;

/// <summary>
/// 预设业务模板 — 直接对接净化 / 勒索防护模块
/// Adobe 封锁、流氓软件更新拦截、勒索高危端口、勒索应急断网
/// </summary>
public static class FirewallPresets
{
    // ===== Adobe 全家桶封锁模板 =====

    /// <summary>
    /// Adobe 封锁模板：递归扫描 Adobe 全目录 EXE、全部网卡拦截 80/443 端口
    /// VPN 网段阻断、Hosts 劫持、EXE 只读锁定
    /// 规则名称使用指定语种自动生成
    /// </summary>
    public static PresetResult ApplyAdobeBlock(FirewallAclManager manager, string? adobePath = null,
        MultilingualTemplates.Language lang = MultilingualTemplates.Language.SimplifiedChinese)
    {
        var groupName = MultilingualTemplates.Get(lang, "AdobeBlock");
        var result = new PresetResult { TemplateName = groupName };

        // 自动检测 Adobe 安装路径
        var paths = DetectAdobePaths();
        if (adobePath != null && Directory.Exists(adobePath))
            paths.Insert(0, adobePath);

        if (paths.Count == 0)
        {
            result.Message = "未检测到 Adobe 安装目录";
            ErrorReporter.Log("Adobe 封锁模板: 未检测到 Adobe 安装目录", "WARN");
            return result;
        }

        int totalRules = 0;
        int totalLocked = 0;

        foreach (var path in paths)
        {
            // 1. 递归扫描 EXE，拦截 80/443 端口出站，全部网卡
            var (created, _, failed) = manager.BatchCreateFolderExeRule(
                folderPath: path,
                recursive: true,
                action: FirewallConst.FwAction.Block,
                remotePortStart: 80, remotePortEnd: 443,
                interfaceType: FirewallConst.FwInterfaceType.All,
                groupTag: groupName);

            totalRules += created;

            // 2. EXE 只读锁定
            totalLocked += AclPermissionHelper.BatchSetFolderExeAcl(path, true);

            // 3. VPN 网段阻断
            var exeList = manager.ScanRecursiveExe(path);
            foreach (var exe in exeList)
            {
                manager.BlockVpnCidrForApp(exe);
            }
        }

        // 4. Hosts 劫持 Adobe 域名
        manager.AddDomainBlockHosts(FirewallConst.AdobeDomains);

        result.RulesCreated = totalRules;
        result.FilesLocked = totalLocked;
        result.HostsBlocked = FirewallConst.AdobeDomains.Count;
        result.Success = true;
        result.Message = $"Adobe 封锁完成: 拦截 {totalRules} 条规则, 锁定 {totalLocked} 个 EXE, 劫持 {FirewallConst.AdobeDomains.Count} 个域名";

        ErrorReporter.Log($"Adobe 封锁模板: {result.Message}");
        return result;
    }

    // ===== 流氓软件更新拦截模板 =====

    /// <summary>
    /// 流氓软件更新模板（WPS/360/Edge）：阻断更新服务器端口、全接口拦截 VPN 绕行
    /// 规则名称使用指定语种自动生成
    /// </summary>
    public static PresetResult ApplyRogueUpdateBlock(FirewallAclManager manager,
        MultilingualTemplates.Language lang = MultilingualTemplates.Language.SimplifiedChinese)
    {
        var groupName = MultilingualTemplates.Get(lang, "RogueUpdate");
        var result = new PresetResult { TemplateName = groupName };

        var targetPaths = DetectRogueSoftwarePaths();
        int totalRules = 0;

        foreach (var (name, path) in targetPaths)
        {
            if (!Directory.Exists(path)) continue;

            // 阻断 80/443 端口出站
            var (created, _, _) = manager.BatchCreateFolderExeRule(
                folderPath: path,
                recursive: true,
                action: FirewallConst.FwAction.Block,
                remotePortStart: 80, remotePortEnd: 443,
                interfaceType: FirewallConst.FwInterfaceType.All,
                groupTag: groupName);

            totalRules += created;

            // VPN 防绕过
            var exeList = manager.ScanRecursiveExe(path);
            foreach (var exe in exeList)
            {
                manager.CreateVpnBlockRule(exe);
            }
        }

        // Hosts 劫持更新域名
        manager.AddDomainBlockHosts(FirewallConst.RogueUpdateDomains);

        result.RulesCreated = totalRules;
        result.HostsBlocked = FirewallConst.RogueUpdateDomains.Count;
        result.Success = true;
        result.Message = $"流氓软件更新拦截: 拦截 {totalRules} 条规则, 劫持 {FirewallConst.RogueUpdateDomains.Count} 个域名";

        ErrorReporter.Log($"流氓软件更新模板: {result.Message}");
        return result;
    }

    // ===== 勒索高危端口模板 =====

    /// <summary>
    /// 勒索高危端口模板：全局阻断 135/139/445/3389 入站流量
    /// 规则名称使用指定语种自动生成
    /// </summary>
    public static PresetResult ApplyRansomwarePortBlock(FirewallAclManager manager,
        MultilingualTemplates.Language lang = MultilingualTemplates.Language.SimplifiedChinese)
    {
        var groupName = MultilingualTemplates.Get(lang, "RansomPort");
        var result = new PresetResult { TemplateName = groupName };

        int created = 0;
        var tcpLabel = MultilingualTemplates.Get(lang, "Block") + "_TCP_";
        var udpLabel = MultilingualTemplates.Get(lang, "Block") + "_UDP_";
        foreach (var port in FirewallConst.HighRiskPorts)
        {
            // TCP 入站阻断
            if (manager.CreatePurePortRule(
                ruleName: $"{groupName}_{tcpLabel}{port}",
                portStart: port, portEnd: port,
                direction: FirewallConst.FwDirection.Inbound,
                action: FirewallConst.FwAction.Block,
                protocol: FirewallConst.FwProtocol.TCP,
                groupTag: groupName))
                created++;

            // UDP 入站阻断
            if (manager.CreatePurePortRule(
                ruleName: $"{groupName}_{udpLabel}{port}",
                portStart: port, portEnd: port,
                direction: FirewallConst.FwDirection.Inbound,
                action: FirewallConst.FwAction.Block,
                protocol: FirewallConst.FwProtocol.UDP,
                groupTag: groupName))
                created++;
        }

        result.RulesCreated = created;
        result.Success = true;
        result.Message = $"勒索高危端口防护: 阻断 {FirewallConst.HighRiskPorts.Count} 个端口 ({string.Join("/", FirewallConst.HighRiskPorts)})，创建 {created} 条规则";

        ErrorReporter.Log($"勒索高危端口模板: {result.Message}");
        return result;
    }

    // ===== 勒索应急断网模板 =====

    /// <summary>
    /// 勒索应急断网模板：最高优先级，可疑进程全端口阻断所有网卡流量
    /// 规则名称使用指定语种自动生成
    /// </summary>
    public static PresetResult ApplyEmergencyNetworkBlock(FirewallAclManager manager, string processPath,
        MultilingualTemplates.Language lang = MultilingualTemplates.Language.SimplifiedChinese)
    {
        var groupName = MultilingualTemplates.Get(lang, "Emergency");
        var result = new PresetResult { TemplateName = groupName };

        if (!File.Exists(processPath))
        {
            result.Message = $"进程文件不存在: {processPath}";
            return result;
        }

        int created = 0;
        var exeName = Path.GetFileNameWithoutExtension(processPath);
        var inboundLabel = MultilingualTemplates.Get(lang, "Inbound");
        var outboundLabel = MultilingualTemplates.Get(lang, "Outbound");

        // 入站全端口阻断
        if (manager.CreateCustomExeRule(
            ruleName: $"{groupName}_{inboundLabel}_{exeName}",
            exePath: processPath,
            action: FirewallConst.FwAction.Block,
            direction: FirewallConst.FwDirection.Inbound,
            protocol: FirewallConst.FwProtocol.Any,
            interfaceType: FirewallConst.FwInterfaceType.All,
            groupTag: groupName,
            remark: $"{groupName} - {inboundLabel}"))
            created++;

        // 出站全端口阻断
        if (manager.CreateCustomExeRule(
            ruleName: $"{groupName}_{outboundLabel}_{exeName}",
            exePath: processPath,
            action: FirewallConst.FwAction.Block,
            direction: FirewallConst.FwDirection.Outbound,
            protocol: FirewallConst.FwProtocol.Any,
            interfaceType: FirewallConst.FwInterfaceType.All,
            groupTag: groupName,
            remark: $"{groupName} - {outboundLabel}"))
            created++;

        // VPN 隧道阻断
        manager.CreateVpnBlockRule(processPath);

        // EXE 只读锁定
        AclPermissionHelper.SetExeReadonlyAcl(processPath);

        result.RulesCreated = created;
        result.FilesLocked = 1;
        result.Success = true;
        result.Message = $"应急断网完成: {Path.GetFileName(processPath)} 已全端口阻断所有网卡流量，EXE 已锁定";

        ErrorReporter.Log($"勒索应急断网模板: {result.Message}", "WARN");
        return result;
    }

    // ===== 一键还原模板 =====

    /// <summary>还原指定模板创建的所有规则（支持多语种分组名）</summary>
    public static int RevertPreset(FirewallAclManager manager, string groupTag)
    {
        int removed = manager.BatchRemoveFolderGroupRules(groupTag);

        // 检查是否为 Adobe 或流氓软件模板（跨所有语种匹配）
        bool isAdobe = IsGroupMatch(groupTag, "AdobeBlock");
        bool isRogue = IsGroupMatch(groupTag, "RogueUpdate");

        if (isAdobe || isRogue)
        {
            manager.RestoreOriginalHosts();

            // 恢复 EXE 权限
            var paths = isAdobe
                ? DetectAdobePaths()
                : DetectRogueSoftwarePaths().Select(p => p.Path).ToList();

            foreach (var path in paths)
            {
                if (Directory.Exists(path))
                    AclPermissionHelper.BatchRestoreFolderExeAcl(path, true);
            }
        }

        ErrorReporter.Log($"模板还原: {groupTag}, 删除 {removed} 条规则");
        return removed;
    }

    /// <summary>
    /// 检查分组名是否匹配指定模板键的任意语种翻译
    /// </summary>
    private static bool IsGroupMatch(string groupTag, string templateKey)
    {
        if (string.IsNullOrEmpty(groupTag)) return false;

        // 直接匹配常量名（向后兼容旧规则）
        if (templateKey == "AdobeBlock" && groupTag == FirewallConst.GroupAdobe) return true;
        if (templateKey == "RogueUpdate" && groupTag == FirewallConst.GroupRogueUpdate) return true;

        // 跨所有语种匹配
        foreach (MultilingualTemplates.Language lang in Enum.GetValues<MultilingualTemplates.Language>())
        {
            var translated = MultilingualTemplates.Get(lang, templateKey);
            if (string.Equals(groupTag, translated, StringComparison.OrdinalIgnoreCase))
                return true;
        }
        return false;
    }

    // ===== 路径检测辅助 =====

    /// <summary>自动检测 Adobe 安装路径</summary>
    private static List<string> DetectAdobePaths()
    {
        var paths = new List<string>();
        var candidates = new[]
        {
            @"C:\Program Files\Adobe",
            @"C:\Program Files (x86)\Adobe",
            @"C:\Program Files\Common Files\Adobe",
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Adobe"),
        };

        foreach (var path in candidates.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            if (Directory.Exists(path))
                paths.Add(path);
        }

        return paths;
    }

    /// <summary>自动检测流氓软件安装路径</summary>
    private static List<(string Name, string Path)> DetectRogueSoftwarePaths()
    {
        var paths = new List<(string, string)>();

        var candidates = new[]
        {
            ("WPS", @"C:\Program Files\WPS Office"),
            ("WPS", @"C:\Program Files (x86)\WPS Office"),
            ("WPS", @"C:\Users\Public\Documents\Kingsoft"),
            ("360", @"C:\Program Files\360"),
            ("360", @"C:\Program Files (x86)\360"),
            ("2345", @"C:\Program Files\2345Soft"),
            ("2345", @"C:\Program Files (x86)\2345Soft"),
            ("Baidu", @"C:\Program Files\baidu"),
            ("Baidu", @"C:\Program Files (x86)\baidu"),
            ("Sogou", @"C:\Program Files\sogou"),
            ("Sogou", @"C:\Program Files (x86)\sogou"),
        };

        foreach (var (name, path) in candidates)
        {
            if (Directory.Exists(path))
                paths.Add((name, path));
        }

        return paths;
    }

    /// <summary>获取所有可用预设模板列表（使用指定语种）</summary>
    public static List<PresetInfo> GetAvailablePresets(
        MultilingualTemplates.Language lang = MultilingualTemplates.Language.SimplifiedChinese)
    {
        return new List<PresetInfo>
        {
            new() { Name = MultilingualTemplates.Get(lang, "AdobeBlock"), Description = MultilingualTemplates.Get(lang, "AdobeBlock"), IsDanger = false },
            new() { Name = MultilingualTemplates.Get(lang, "RogueUpdate"), Description = MultilingualTemplates.Get(lang, "RogueUpdate"), IsDanger = false },
            new() { Name = MultilingualTemplates.Get(lang, "RansomPort"), Description = MultilingualTemplates.Get(lang, "RansomPort"), IsDanger = false },
            new() { Name = MultilingualTemplates.Get(lang, "Emergency"), Description = MultilingualTemplates.Get(lang, "Emergency"), IsDanger = true },
        };
    }
}

/// <summary>预设模板执行结果</summary>
public sealed class PresetResult
{
    public string TemplateName { get; set; } = "";
    public bool Success { get; set; }
    public string Message { get; set; } = "";
    public int RulesCreated { get; set; }
    public int FilesLocked { get; set; }
    public int HostsBlocked { get; set; }
}

/// <summary>预设模板信息</summary>
public sealed class PresetInfo
{
    public string Name { get; set; } = "";
    public string Description { get; set; } = "";
    public bool IsDanger { get; set; }
}
