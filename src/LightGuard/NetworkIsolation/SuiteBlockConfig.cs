// © 2026 落尘（Luochen） 原创开发 - 保留所有权利

namespace LightGuard.NetworkIsolation;

/// <summary>
/// 商业软件套件联网隔离配置模型。
/// <para>统一数据结构：后续新增软件（Affinity、Autodesk、Capture One、SketchUp 等）
/// 只需新增一个 <see cref="SuiteBlockConfig"/> 实例，无需重写扫描与规则增删逻辑。</para>
/// <para>隔离策略：仅创建「出站阻止」防火墙规则（不阻断入站，保护 127.0.0.1 本地 IPC），
/// 绝不修改 exe 权限/ACL、不使用 AppLocker 或 DisallowRun。</para>
/// </summary>
public sealed class SuiteBlockConfig
{
    /// <summary>套件唯一标识（用于配置持久化与 hosts 标记）</summary>
    public string Id { get; set; } = "";

    /// <summary>UI 显示名称</summary>
    public string UiName { get; set; } = "";

    /// <summary>规则名前缀（用于批量识别/删除本套件创建的规则，统一命名规范）</summary>
    public string RulePrefix { get; set; } = "";

    /// <summary>防火墙分组标签（Grouping，配合规则名双重匹配批量删除）</summary>
    public string GroupTag { get; set; } = "";

    /// <summary>需要扫描的目录列表（支持 %ProgramData%/%LOCALAPPDATA% 等环境变量）</summary>
    public List<string> ScanDirs { get; set; } = new();

    /// <summary>需要排除的 exe 文件名（本地辅助进程，不阻断出站）</summary>
    public List<string> ExcludeExe { get; set; } = new();

    /// <summary>可选补充 hosts 阻断域名（激活/遥测服务器；作为防火墙按程序阻断的补充）</summary>
    public List<string> ExtraHostsBlock { get; set; } = new();

    /// <summary>是否启用该套件隔离</summary>
    public bool Enabled { get; set; }
}

/// <summary>
/// 预置套件配置（Adobe 全家桶 + CorelDRAW 套件 + Affinity 预留扩展位）
/// </summary>
public static class SuiteBlockPresets
{
    /// <summary>
    /// 获取默认预置配置列表
    /// </summary>
    public static List<SuiteBlockConfig> GetDefaultPresets() => new()
    {
        new SuiteBlockConfig
        {
            Id = "adobe",
            UiName = "Adobe 全家桶 网络隔离",
            RulePrefix = "LightGuard-Suite-Adobe-",
            GroupTag = "LG_Suite_Adobe",
            ScanDirs =
            {
                @"C:\Program Files\Adobe",
                @"C:\Program Files\Common Files\Adobe",
                @"C:\Program Files (x86)\Adobe",
                @"C:\Program Files (x86)\Common Files\Adobe",
                @"%ProgramData%\Adobe",
                @"%LOCALAPPDATA%\Adobe",
                @"%APPDATA%\Adobe",
            },
            ExtraHostsBlock =
            {
                "activate.adobe.com",
                "lm.licenses.adobe.com",
                "na1r.services.adobe.com",
                "swupmf.adobe.com",
                "swupdl.adobe.com",
                "genuine.adobe.com",
                "prod.adobegenuine.com",
                "ereg.adobe.com",
                "practivate.adobe.com",
            },
        },
        new SuiteBlockConfig
        {
            Id = "coreldraw",
            UiName = "CorelDRAW 套件 网络隔离",
            RulePrefix = "LightGuard-Suite-Corel-",
            GroupTag = "LG_Suite_Corel",
            ScanDirs =
            {
                @"C:\Program Files\Corel",
                @"C:\Program Files\CorelDRAW Graphics Suite",
                @"C:\Program Files (x86)\Corel",
                @"%ProgramData%\Corel",
                @"%LOCALAPPDATA%\Corel",
                @"%APPDATA%\Corel",
            },
            ExtraHostsBlock =
            {
                "activation.corel.com",
                "update.corel.com",
                "telemetry.corel.com",
            },
        },
        // 预留扩展位：Affinity（Photo / Designer / Publisher）
        new SuiteBlockConfig
        {
            Id = "affinity",
            UiName = "Affinity 系列（预留）",
            RulePrefix = "LightGuard-Suite-Affinity-",
            GroupTag = "LG_Suite_Affinity",
            ScanDirs =
            {
                @"%LOCALAPPDATA%\Affinity",
                @"%PROGRAMFILES%\Affinity",
                @"%PROGRAMFILES(X86)%\Affinity",
            },
            ExtraHostsBlock =
            {
                "affinity.serif.com",
                "updates.serif.com",
            },
        },
    };
}
