// © 2026 落尘（Luochen） 原创开发 - 保留所有权利

using System.Security.Cryptography;
using System.Text;
using LightGuard.Core;
using LightGuard.Firewall;

namespace LightGuard.NetworkIsolation;

/// <summary>
/// 商业软件联网隔离服务（Adobe + CorelDRAW + 通用框架）。
/// <para>核心原则：</para>
/// <list type="bullet">
///   <item>只阻断「出站」流量（上报、激活校验、更新、遥测），绝不锁 EXE 执行权限、不改文件 ACL、不用 AppLocker/DisallowRun</item>
///   <item>不创建入站阻止规则，放行 127.0.0.1 本地 IPC 通信（Corel Font Manager 等依赖本地 socket）</item>
///   <item>规则统一命名前缀 + 分组标签，可批量删除，不污染用户原有防火墙规则</item>
///   <item>软件升级后 exe 路径变化 → 「刷新规则」按钮先清后建</item>
/// </list>
/// </summary>
public sealed class SuiteIsolationService : IDisposable
{
    private readonly FirewallAclManager _fw;

    /// <summary>套件 hosts 阻断标记（用于按套件精准清理，不清空用户原有 hosts 行）</summary>
    private const string HostsStartMarker = "# LightGuard Suite Block Start ";
    private const string HostsEndMarker = "# LightGuard Suite Block End ";

    /// <summary>hosts 文件路径</summary>
    private static string HostsPath =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "drivers", "etc", "hosts");

    public SuiteIsolationService()
    {
        _fw = new FirewallAclManager();
        if (_fw.TestFirewallComConnect())
        {
            _fw.LoadExistingRules();
        }
    }

    /// <summary>防火墙 COM 是否可用</summary>
    public bool IsAvailable => _fw.TestFirewallComConnect();

    // ==================== 扫描 ====================

    /// <summary>
    /// 扫描套件配置中的所有目录，收集 .exe 完整路径。
    /// <para>只读取 exe 路径，不读取、不修改任何 exe 文件权限/ACL。</para>
    /// </summary>
    public List<string> ScanExecutables(SuiteBlockConfig suite)
    {
        var exes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var exclude = new HashSet<string>(suite.ExcludeExe ?? new(), StringComparer.OrdinalIgnoreCase);

        foreach (var dirTemplate in suite.ScanDirs ?? new())
        {
            var dir = Environment.ExpandEnvironmentVariables(dirTemplate);
            if (string.IsNullOrWhiteSpace(dir) || !Directory.Exists(dir)) continue;

            try
            {
                foreach (var file in Directory.EnumerateFiles(dir, "*.exe", SearchOption.AllDirectories))
                {
                    try
                    {
                        var fi = new FileInfo(file);
                        if (fi.Length == 0) continue;          // 跳过 0 字节损坏文件
                        if (exclude.Contains(fi.Name)) continue; // 跳过排除进程（本地辅助进程）
                        exes.Add(fi.FullName);
                    }
                    catch { } // 单文件访问失败（权限等）不影响整体扫描
                }
            }
            catch (Exception ex)
            {
                ErrorReporter.Report(ex, $"[SuiteIsolation] 扫描目录失败: {dir}");
            }
        }

        return exes.OrderBy(x => x, StringComparer.OrdinalIgnoreCase).ToList();
    }

    // ==================== 规则增删 ====================

    /// <summary>
    /// 应用套件隔离：先清除该套件全部旧规则（应对升级后 exe 路径变更），
    /// 再重新扫描并创建「出站阻止」规则。仅出站，绝不创建入站规则。
    /// </summary>
    /// <returns>创建成功的规则数</returns>
    public int ApplyRules(SuiteBlockConfig suite, Action<string>? log = null)
    {
        var cleared = ClearRules(suite, log);
        log?.Invoke($"[INFO] {suite.UiName}：已清除旧规则 {cleared} 条，开始扫描...");

        var exes = ScanExecutables(suite);
        log?.Invoke($"[INFO] {suite.UiName}：扫描到可执行文件 {exes.Count} 个，创建出站阻断规则...");

        int created = 0;
        foreach (var exe in exes)
        {
            var rule = BuildOutboundBlockRule(suite, exe);
            if (_fw.CreateFullRule(rule))
            {
                created++;
                log?.Invoke($"[INFO] 添加防火墙规则：{exe}");
            }
            else
            {
                log?.Invoke($"[WARN] 添加防火墙规则失败：{exe}");
            }
        }

        log?.Invoke($"[INFO] {suite.UiName}：本次创建 {created} 条规则（排除进程与重复规则不计）");
        return created;
    }

    /// <summary>
    /// 清除该套件创建的全部防火墙规则（按分组标签 + 规则名前缀双重匹配）。
    /// 只会删除本工具创建的规则，不会触碰用户手动添加的防火墙规则。
    /// </summary>
    public int ClearRules(SuiteBlockConfig suite, Action<string>? log = null)
    {
        int removed = 0;
        foreach (var rule in GetSuiteRules(suite))
        {
            if (_fw.DeleteRuleByName(rule.GetFirewallRuleName()))
            {
                removed++;
                log?.Invoke($"[INFO] 删除防火墙规则：{rule.ApplicationPath}");
            }
        }
        return removed;
    }

    /// <summary>统计该套件当前规则数</summary>
    public int CountRules(SuiteBlockConfig suite) => GetSuiteRules(suite).Count;

    /// <summary>获取该套件创建的规则（分组标签或规则名前缀匹配）</summary>
    private List<FirewallAclRule> GetSuiteRules(SuiteBlockConfig suite)
    {
        if (string.IsNullOrEmpty(suite.RulePrefix)) return new List<FirewallAclRule>();
        return _fw.GetAllLocalRules()
            .Where(r => string.Equals(r.GroupTag, suite.GroupTag, StringComparison.OrdinalIgnoreCase)
                     || r.RuleName.StartsWith(suite.RulePrefix, StringComparison.OrdinalIgnoreCase))
            .ToList();
    }

    /// <summary>构建单条「出站阻止」规则</summary>
    private static FirewallAclRule BuildOutboundBlockRule(SuiteBlockConfig suite, string exePath)
    {
        return new FirewallAclRule
        {
            RuleName = $"{suite.RulePrefix}{ComputeShortHash(exePath)}",
            GroupTag = suite.GroupTag,
            Remark = $"商业软件联网隔离（{suite.UiName}）：仅阻断出站联网，不影响程序运行 {exePath}",
            Action = FirewallConst.FwAction.Block,
            Direction = FirewallConst.FwDirection.Outbound, // 唯一主方案：出站阻止
            Enabled = true,
            ApplicationPath = exePath,
            Protocol = FirewallConst.FwProtocol.Any,
            Profile = FirewallConst.FwProfile.All,          // 域/专用/公用全部生效
            InterfaceType = FirewallConst.FwInterfaceType.All,
            EdgeTraversal = false
        };
    }

    /// <summary>路径短哈希（避免同名 exe 不同目录导致规则名冲突）</summary>
    private static string ComputeShortHash(string path)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(path.ToLowerInvariant()));
        return Convert.ToHexString(bytes)[..10].ToLowerInvariant();
    }

    // ==================== 可选 hosts 补充阻断 ====================

    /// <summary>是否已对该套件写入 hosts 阻断</summary>
    public bool IsHostsBlocked(SuiteBlockConfig suite)
    {
        try
        {
            if (!File.Exists(HostsPath)) return false;
            return File.ReadAllLines(HostsPath).Any(l => l.Trim() == $"{HostsStartMarker}{suite.Id}");
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, "[SuiteIsolation] 读取 hosts 失败");
            return false;
        }
    }

    /// <summary>
    /// 应用 hosts 补充阻断（可选增强，需管理员权限）。
    /// 只追加本套件标记块，清除时仅删除本工具标记的行，不清空整个 hosts。
    /// </summary>
    public bool ApplyHostsBlock(SuiteBlockConfig suite)
    {
        try
        {
            var domains = suite.ExtraHostsBlock?.Where(d => !string.IsNullOrWhiteSpace(d)).ToList() ?? new();
            if (domains.Count == 0) return true;

            var lines = File.Exists(HostsPath)
                ? File.ReadAllLines(HostsPath).ToList()
                : new List<string>();

            // 先移除本套件旧标记块（防重复）
            RemoveSuiteBlock(lines, suite.Id);

            lines.Add($"{HostsStartMarker}{suite.Id}");
            foreach (var domain in domains)
            {
                lines.Add($"127.0.0.1 {domain}");
                lines.Add($"::1 {domain}");
            }
            lines.Add($"{HostsEndMarker}{suite.Id}");

            File.WriteAllLines(HostsPath, lines);
            ErrorReporter.Log($"[SuiteIsolation] 已写入 hosts 阻断：{suite.UiName}（{domains.Count} 个域名）");
            return true;
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, $"[SuiteIsolation] 写入 hosts 失败（{suite.UiName}，需要管理员权限）");
            return false;
        }
    }

    /// <summary>移除该套件的 hosts 阻断块</summary>
    public bool RestoreHostsBlock(SuiteBlockConfig suite)
    {
        try
        {
            if (!File.Exists(HostsPath)) return true;

            var lines = File.ReadAllLines(HostsPath).ToList();
            var removed = RemoveSuiteBlock(lines, suite.Id);
            if (removed) File.WriteAllLines(HostsPath, lines);

            ErrorReporter.Log($"[SuiteIsolation] 已清除 hosts 阻断：{suite.UiName}");
            return true;
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, $"[SuiteIsolation] 清除 hosts 失败（{suite.UiName}）");
            return false;
        }
    }

    /// <summary>移除指定套件标记之间的所有行（含标记本身）</summary>
    private static bool RemoveSuiteBlock(List<string> lines, string suiteId)
    {
        var startIdx = -1;
        var endIdx = -1;
        for (int i = 0; i < lines.Count; i++)
        {
            var trimmed = lines[i].Trim();
            if (startIdx < 0 && trimmed == $"{HostsStartMarker}{suiteId}") startIdx = i;
            else if (startIdx >= 0 && trimmed == $"{HostsEndMarker}{suiteId}") { endIdx = i; break; }
        }
        if (startIdx < 0) return false;
        if (endIdx < 0) endIdx = lines.Count - 1; // 标记不完整时清到文件末尾
        lines.RemoveRange(startIdx, endIdx - startIdx + 1);
        return true;
    }

    public void Dispose()
    {
        _fw.Dispose();
    }
}
