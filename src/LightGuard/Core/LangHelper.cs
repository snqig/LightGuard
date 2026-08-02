// © 2026 落尘（Luochen） 原创开发 - 保留所有权利

using System.Collections.Concurrent;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace LightGuard.Core;

/// <summary>
/// 支持的语言枚举。
/// </summary>
public enum SupportedLanguage
{
    /// <summary>简体中文（默认）</summary>
    ZhCN,

    /// <summary>英文</summary>
    EnUS,

    /// <summary>繁体中文</summary>
    ZhTW
}

/// <summary>
/// 全局多语言管理器 — 统一管理三语种资源文件，提供零硬编码文本访问。
/// <para>调用规范：LangHelper.GetText("KEY") 或 LangHelper.T("KEY")</para>
/// <para>支持运行时动态切换语言，无需重启程序。</para>
/// </summary>
public static class LangHelper
{
    /// <summary>当前语言</summary>
    public static SupportedLanguage CurrentLanguage { get; private set; } = SupportedLanguage.ZhCN;

    /// <summary>语言变更事件</summary>
    public static event Action<SupportedLanguage>? LanguageChanged;

    /// <summary>是否已初始化</summary>
    public static bool IsInitialized { get; private set; }

    // 主语言字典：key -> text
    private static readonly ConcurrentDictionary<string, string> _currentTexts = new();
    // 备用语言字典（当前语言缺失时回退到简体中文）
    private static readonly ConcurrentDictionary<string, string> _fallbackTexts = new();

    // 所有已加载的语言包：language -> (key -> text)
    private static readonly ConcurrentDictionary<SupportedLanguage, Dictionary<string, string>> _allPacks = new();

    // 日志模式：界面跟随语言 / 服务器强制英文
    private static bool _serverLogMode = false;

    // JSON 序列化选项
    private static readonly JsonSerializerOptions _jsonOpts = new()
    {
        WriteIndented = true,
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    /// <summary>语言资源目录（相对于程序基目录）</summary>
    private static string ResourcesDir => Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Resources", "lang");

    /// <summary>
    /// 初始化多语言系统。加载默认语言（简体中文）。
    /// </summary>
    /// <param name="initialLanguage">初始语言（默认简体中文）</param>
    /// <param name="serverLogMode">是否启用服务器强制英文日志模式</param>
    public static void Initialize(SupportedLanguage initialLanguage = SupportedLanguage.ZhCN, bool serverLogMode = false)
    {
        if (IsInitialized) return;

        _serverLogMode = serverLogMode;

        // 加载所有语言包
        foreach (SupportedLanguage lang in Enum.GetValues<SupportedLanguage>())
        {
            var texts = LoadLanguageFile(lang);
            _allPacks[lang] = texts;
            ErrorReporter.Log($"已加载语言包: {lang} ({texts.Count} 条文本)", "INFO");
        }

        // 设置回退语言（简体中文）
        _fallbackTexts.Clear();
        if (_allPacks.TryGetValue(SupportedLanguage.ZhCN, out var fallback))
        {
            foreach (var kv in fallback)
                _fallbackTexts[kv.Key] = kv.Value;
        }

        // 设置当前语言
        SetLanguage(initialLanguage);
        IsInitialized = true;
        ErrorReporter.Log($"多语言系统初始化完成，当前语言: {CurrentLanguage}", "INFO");
    }

    /// <summary>
    /// 获取文本。等同于 <see cref="GetText"/>。
    /// </summary>
    /// <param name="key">文本键</param>
    /// <param name="args">格式化参数（可选）</param>
    /// <returns>当前语言对应文本；缺失时回退到简体中文；仍缺失则返回 key 本身。</returns>
    public static string T(string key, params object[] args) => GetText(key, args);

    /// <summary>
    /// 获取文本（主接口）。
    /// </summary>
    /// <param name="key">文本键</param>
    /// <param name="args">格式化参数（可选，支持 {0} {1} 格式）</param>
    /// <returns>当前语言对应文本；缺失时回退到简体中文；仍缺失则返回 key 本身。</returns>
    public static string GetText(string key, params object[] args)
    {
        if (string.IsNullOrEmpty(key)) return string.Empty;

        string text;
        if (_currentTexts.TryGetValue(key, out var found))
        {
            text = found;
        }
        else if (_fallbackTexts.TryGetValue(key, out var fallback))
        {
            text = fallback;
        }
        else
        {
            // 键不存在，返回 key 本身并记录警告
            text = key;
        }

        // 应用格式化参数
        if (args != null && args.Length > 0)
        {
            try { text = string.Format(text, args); }
            catch { /* 格式化失败则返回原文 */ }
        }

        return text;
    }

    /// <summary>
    /// 获取日志文本。服务器模式下强制返回英文，否则跟随当前语言。
    /// </summary>
    public static string GetLogText(string key, params object[] args)
    {
        if (_serverLogMode)
        {
            // 服务器模式：强制使用英文
            if (_allPacks.TryGetValue(SupportedLanguage.EnUS, out var enTexts) &&
                enTexts.TryGetValue(key, out var enText))
            {
                if (args != null && args.Length > 0)
                {
                    try { return string.Format(enText, args); }
                    catch { }
                }
                return enText;
            }
        }
        return GetText(key, args);
    }

    /// <summary>
    /// 切换语言（运行时动态切换，无需重启）。
    /// </summary>
    /// <param name="language">目标语言</param>
    public static void SetLanguage(SupportedLanguage language)
    {
        if (CurrentLanguage == language && IsInitialized) return;

        CurrentLanguage = language;

        _currentTexts.Clear();
        if (_allPacks.TryGetValue(language, out var texts))
        {
            foreach (var kv in texts)
                _currentTexts[kv.Key] = kv.Value;
        }

        ErrorReporter.Log($"语言已切换: {language}", "INFO");

        // 保存用户语言偏好
        try
        {
            AppState.Instance.Config.Language = language.ToString();
            ConfigManager.Save(AppState.Instance.Config);
        }
        catch { /* 配置保存失败不影响语言切换 */ }

        LanguageChanged?.Invoke(language);
    }

    /// <summary>
    /// 设置服务器日志模式（强制英文审计日志）。
    /// </summary>
    /// <param name="enabled">是否启用</param>
    public static void SetServerLogMode(bool enabled)
    {
        _serverLogMode = enabled;
    }

    /// <summary>
    /// 获取所有已加载的语言列表。
    /// </summary>
    public static List<SupportedLanguage> GetAvailableLanguages()
    {
        return _allPacks.Keys.ToList();
    }

    /// <summary>
    /// 获取语言显示名称。
    /// </summary>
    public static string GetLanguageDisplayName(SupportedLanguage lang) => lang switch
    {
        SupportedLanguage.ZhCN => "简体中文",
        SupportedLanguage.EnUS => "English",
        SupportedLanguage.ZhTW => "繁體中文",
        _ => lang.ToString()
    };

    /// <summary>
    /// 检查指定键是否在当前语言中存在。
    /// </summary>
    public static bool HasKey(string key)
    {
        return _currentTexts.ContainsKey(key) || _fallbackTexts.ContainsKey(key);
    }

    /// <summary>
    /// 获取当前语言所有键的数量。
    /// </summary>
    public static int GetKeyCount()
    {
        return _currentTexts.Count;
    }

    /// <summary>
    /// 从用户配置恢复语言偏好。
    /// </summary>
    public static void RestoreFromConfig()
    {
        try
        {
            var langStr = AppState.Instance.Config.Language;
            if (Enum.TryParse<SupportedLanguage>(langStr, out var lang))
            {
                SetLanguage(lang);
            }
        }
        catch { /* 配置恢复失败使用默认语言 */ }
    }

    /// <summary>
    /// 加载语言资源文件。优先从文件系统加载，失败时使用内置默认文本。
    /// </summary>
    private static Dictionary<string, string> LoadLanguageFile(SupportedLanguage language)
    {
        var fileName = language switch
        {
            SupportedLanguage.ZhCN => "lang_zh-CN.json",
            SupportedLanguage.EnUS => "lang_en-US.json",
            SupportedLanguage.ZhTW => "lang_zh-TW.json",
            _ => "lang_zh-CN.json"
        };

        var filePath = Path.Combine(ResourcesDir, fileName);

        // 尝试从文件加载
        if (File.Exists(filePath))
        {
            try
            {
                var json = File.ReadAllText(filePath);
                var dict = JsonSerializer.Deserialize<Dictionary<string, string>>(json);
                if (dict != null && dict.Count > 0)
                    return dict;
            }
            catch (Exception ex)
            {
                ErrorReporter.Log($"加载语言文件失败 {fileName}: {ex.Message}", "WARN");
            }
        }

        // 回退到内置默认文本
        return GetBuiltInTexts(language);
    }

    /// <summary>
    /// 内置默认文本（文件缺失时的兜底方案）。
    /// </summary>
    private static Dictionary<string, string> GetBuiltInTexts(SupportedLanguage language)
    {
        return language switch
        {
            SupportedLanguage.EnUS => BuiltInTexts.EnUS,
            SupportedLanguage.ZhTW => BuiltInTexts.ZhTW,
            _ => BuiltInTexts.ZhCN
        };
    }

    /// <summary>
    /// 导出当前语言包为 JSON 文件（用于编辑和更新）。
    /// </summary>
    public static void ExportLanguageFile(SupportedLanguage language, string outputPath)
    {
        if (_allPacks.TryGetValue(language, out var texts))
        {
            var json = JsonSerializer.Serialize(texts, _jsonOpts);
            Directory.CreateDirectory(Path.GetDirectoryName(outputPath)!);
            File.WriteAllText(outputPath, json);
        }
    }
}

/// <summary>
/// 内置默认文本 — 文件缺失时的兜底方案。
/// </summary>
internal static class BuiltInTexts
{
    public static readonly Dictionary<string, string> ZhCN = new()
    {
        // ===== 通用 =====
        ["app.name"] = "LightGuard",
        ["app.tagline"] = "全栈安全容灾审计系统",
        ["common.ok"] = "确定",
        ["common.cancel"] = "取消",
        ["common.save"] = "保存",
        ["common.delete"] = "删除",
        ["common.refresh"] = "刷新",
        ["common.close"] = "关闭",
        ["common.yes"] = "是",
        ["common.no"] = "否",
        ["common.loading"] = "加载中...",
        ["common.success"] = "成功",
        ["common.failed"] = "失败",
        ["common.warning"] = "警告",
        ["common.error"] = "错误",
        ["common.info"] = "信息",
        ["common.export"] = "导出",
        ["common.import"] = "导入",
        ["common.select"] = "选择",
        ["common.browse"] = "浏览...",
        ["common.start"] = "开始",
        ["common.stop"] = "停止",
        ["common.enable"] = "启用",
        ["common.disable"] = "禁用",
        ["common.search"] = "搜索",
        ["common.clear"] = "清空",
        ["common.all"] = "全部",
        ["common.none"] = "无",
        ["common.unknown"] = "未知",

        // ===== 导航 =====
        ["nav.dashboard"] = "仪表盘",
        ["nav.privacy"] = "隐私加固",
        ["nav.cleanup"] = "流氓净化",
        ["nav.firewall"] = "防火墙",
        ["nav.ransomware"] = "勒索防护",
        ["nav.backup"] = "加密备份",
        ["nav.audit"] = "文件审计",
        ["nav.update"] = "自动更新",
        ["nav.settings"] = "设置",
        ["nav.defender"] = "Defender查杀",
        ["nav.decrypt"] = "勒索解密",

        // ===== 仪表盘 =====
        ["dashboard.title"] = "安全仪表盘",
        ["dashboard.subtitle"] = "系统安全状态总览",
        ["dashboard.protection_status"] = "防护状态",
        ["dashboard.modules_active"] = "已启用模块",
        ["dashboard.threats_blocked"] = "已拦截威胁",
        ["dashboard.last_scan"] = "上次扫描",
        ["dashboard.system_health"] = "系统健康度",

        // ===== Defender 查杀 =====
        ["defender.title"] = "Defender 按需查杀",
        ["defender.subtitle"] = "Microsoft Defender 智能调度引擎",
        ["defender.tab.overview"] = "扫描概览",
        ["defender.tab.scan"] = "按需扫描",
        ["defender.tab.history"] = "扫描历史",
        ["defender.tab.policy"] = "策略配置",
        ["defender.realtime_protection"] = "实时保护",
        ["defender.signature_version"] = "病毒库版本",
        ["defender.engine_version"] = "引擎版本",
        ["defender.last_update"] = "最后更新",
        ["defender.health"] = "健康状态",
        ["defender.healthy"] = "正常",
        ["defender.unhealthy"] = "异常",
        ["defender.scan_file"] = "单文件扫描",
        ["defender.scan_dir"] = "目录扫描",
        ["defender.scan_quick"] = "快速扫描",
        ["defender.scan_full"] = "全盘扫描",
        ["defender.scanning"] = "扫描中...",
        ["defender.scan_complete"] = "扫描完成",
        ["defender.threats_found"] = "发现威胁",
        ["defender.no_threats"] = "未发现威胁",
        ["defender.update_signatures"] = "更新病毒库",
        ["defender.scan_priority"] = "扫描优先级",
        ["defender.remediation_action"] = "处置策略",
        ["defender.action.quarantine"] = "隔离",
        ["defender.action.remove"] = "删除",
        ["defender.action.allow"] = "允许",
        ["defender.scan_before_backup"] = "备份前自动查杀",

        // ===== 勒索解密 =====
        ["decrypt.title"] = "勒索解密",
        ["decrypt.subtitle"] = "自动识别勒索家族 · 匹配官方解密工具",
        ["decrypt.tab.emergency"] = "应急解密",
        ["decrypt.tab.tools"] = "工具库",
        ["decrypt.tab.history"] = "解密历史",
        ["decrypt.select_file"] = "选择加密文件",
        ["decrypt.select_dir"] = "选择加密目录",
        ["decrypt.detect_family"] = "检测勒索家族",
        ["decrypt.start_decrypt"] = "开始解密",
        ["decrypt.backup_before"] = "解密前自动备份",
        ["decrypt.family_detected"] = "检测到勒索家族",
        ["decrypt.family_unknown"] = "未识别勒索家族",
        ["decrypt.no_decryptor"] = "暂无可用解密工具",
        ["decrypt.decryptor_available"] = "解密工具可用",
        ["decrypt.downloading_tool"] = "正在下载解密工具...",
        ["decrypt.verifying_tool"] = "正在校验工具哈希...",
        ["decrypt.decrypting"] = "解密中...",
        ["decrypt.decrypt_complete"] = "解密完成",
        ["decrypt.backup_created"] = "已创建解密前备份",
        ["decrypt.update_index"] = "更新索引",
        ["decrypt.download_tool"] = "下载工具",
        ["decrypt.verify_tool"] = "校验工具",

        // ===== 备份 =====
        ["backup.title"] = "加密备份",
        ["backup.subtitle"] = "AES-256 加密 · VSS 卷影 · 防勒索隔离",
        ["backup.tab.encrypt"] = "加密备份",
        ["backup.tab.restore"] = "灾难恢复",
        ["backup.tab.database"] = "数据库备份",
        ["backup.tab.lifecycle"] = "生命周期",
        ["backup.tab.enterprise"] = "企业容灾",
        ["backup.tab.audit"] = "快照审计",

        // ===== 设置 =====
        ["settings.title"] = "设置",
        ["settings.subtitle"] = "系统配置与偏好",
        ["settings.language"] = "界面语言",
        ["settings.theme"] = "主题模式",
        ["settings.server_mode"] = "服务器模式",
        ["settings.server_mode_desc"] = "强制英文审计日志，精简UI",
        ["settings.about"] = "关于",
        ["settings.version"] = "版本",

        // ===== 消息 =====
        ["msg.admin_required"] = "需要管理员权限才能执行此操作。",
        ["msg.confirm_delete"] = "确认删除？",
        ["msg.operation_success"] = "操作成功",
        ["msg.operation_failed"] = "操作失败",
        ["msg.file_not_found"] = "文件不存在",
        ["msg.dir_not_found"] = "目录不存在",
        ["msg.disk_space_insufficient"] = "磁盘空间不足",
    };

    public static readonly Dictionary<string, string> EnUS = new()
    {
        // ===== Common =====
        ["app.name"] = "LightGuard",
        ["app.tagline"] = "Full-Stack Security & Disaster Recovery Suite",
        ["common.ok"] = "OK",
        ["common.cancel"] = "Cancel",
        ["common.save"] = "Save",
        ["common.delete"] = "Delete",
        ["common.refresh"] = "Refresh",
        ["common.close"] = "Close",
        ["common.yes"] = "Yes",
        ["common.no"] = "No",
        ["common.loading"] = "Loading...",
        ["common.success"] = "Success",
        ["common.failed"] = "Failed",
        ["common.warning"] = "Warning",
        ["common.error"] = "Error",
        ["common.info"] = "Info",
        ["common.export"] = "Export",
        ["common.import"] = "Import",
        ["common.select"] = "Select",
        ["common.browse"] = "Browse...",
        ["common.start"] = "Start",
        ["common.stop"] = "Stop",
        ["common.enable"] = "Enable",
        ["common.disable"] = "Disable",
        ["common.search"] = "Search",
        ["common.clear"] = "Clear",
        ["common.all"] = "All",
        ["common.none"] = "None",
        ["common.unknown"] = "Unknown",

        // ===== Navigation =====
        ["nav.dashboard"] = "Dashboard",
        ["nav.privacy"] = "Privacy",
        ["nav.cleanup"] = "Cleanup",
        ["nav.firewall"] = "Firewall",
        ["nav.ransomware"] = "Ransomware",
        ["nav.backup"] = "Backup",
        ["nav.audit"] = "File Audit",
        ["nav.update"] = "Update",
        ["nav.settings"] = "Settings",
        ["nav.defender"] = "Defender Scan",
        ["nav.decrypt"] = "Decryption",

        // ===== Dashboard =====
        ["dashboard.title"] = "Security Dashboard",
        ["dashboard.subtitle"] = "System Security Overview",
        ["dashboard.protection_status"] = "Protection Status",
        ["dashboard.modules_active"] = "Active Modules",
        ["dashboard.threats_blocked"] = "Threats Blocked",
        ["dashboard.last_scan"] = "Last Scan",
        ["dashboard.system_health"] = "System Health",

        // ===== Defender =====
        ["defender.title"] = "Defender On-Demand Scan",
        ["defender.subtitle"] = "Microsoft Defender Scheduling Engine",
        ["defender.tab.overview"] = "Overview",
        ["defender.tab.scan"] = "On-Demand Scan",
        ["defender.tab.history"] = "Scan History",
        ["defender.tab.policy"] = "Policy",
        ["defender.realtime_protection"] = "Real-Time Protection",
        ["defender.signature_version"] = "Signature Version",
        ["defender.engine_version"] = "Engine Version",
        ["defender.last_update"] = "Last Update",
        ["defender.health"] = "Health",
        ["defender.healthy"] = "Healthy",
        ["defender.unhealthy"] = "Unhealthy",
        ["defender.scan_file"] = "Scan File",
        ["defender.scan_dir"] = "Scan Directory",
        ["defender.scan_quick"] = "Quick Scan",
        ["defender.scan_full"] = "Full Scan",
        ["defender.scanning"] = "Scanning...",
        ["defender.scan_complete"] = "Scan Complete",
        ["defender.threats_found"] = "Threats Found",
        ["defender.no_threats"] = "No Threats Found",
        ["defender.update_signatures"] = "Update Signatures",
        ["defender.scan_priority"] = "Scan Priority",
        ["defender.remediation_action"] = "Remediation Action",
        ["defender.action.quarantine"] = "Quarantine",
        ["defender.action.remove"] = "Remove",
        ["defender.action.allow"] = "Allow",
        ["defender.scan_before_backup"] = "Auto-scan before backup",

        // ===== Decryption =====
        ["decrypt.title"] = "Ransomware Decryption",
        ["decrypt.subtitle"] = "Auto-detect family · Match official decryptors",
        ["decrypt.tab.emergency"] = "Emergency Decrypt",
        ["decrypt.tab.tools"] = "Tool Library",
        ["decrypt.tab.history"] = "History",
        ["decrypt.select_file"] = "Select encrypted file",
        ["decrypt.select_dir"] = "Select encrypted directory",
        ["decrypt.detect_family"] = "Detect Family",
        ["decrypt.start_decrypt"] = "Start Decryption",
        ["decrypt.backup_before"] = "Backup before decryption",
        ["decrypt.family_detected"] = "Detected ransomware family",
        ["decrypt.family_unknown"] = "Unknown ransomware family",
        ["decrypt.no_decryptor"] = "No decryptor available",
        ["decrypt.decryptor_available"] = "Decryptor available",
        ["decrypt.downloading_tool"] = "Downloading decryptor...",
        ["decrypt.verifying_tool"] = "Verifying tool hash...",
        ["decrypt.decrypting"] = "Decrypting...",
        ["decrypt.decrypt_complete"] = "Decryption complete",
        ["decrypt.backup_created"] = "Pre-decryption backup created",
        ["decrypt.update_index"] = "Update Index",
        ["decrypt.download_tool"] = "Download Tool",
        ["decrypt.verify_tool"] = "Verify Tool",

        // ===== Backup =====
        ["backup.title"] = "Encrypted Backup",
        ["backup.subtitle"] = "AES-256 · VSS Snapshot · Anti-Ransomware Isolation",
        ["backup.tab.encrypt"] = "Encrypted Backup",
        ["backup.tab.restore"] = "Disaster Recovery",
        ["backup.tab.database"] = "Database Backup",
        ["backup.tab.lifecycle"] = "Lifecycle",
        ["backup.tab.enterprise"] = "Enterprise DR",
        ["backup.tab.audit"] = "Snapshot Audit",

        // ===== Settings =====
        ["settings.title"] = "Settings",
        ["settings.subtitle"] = "System Configuration",
        ["settings.language"] = "Interface Language",
        ["settings.theme"] = "Theme Mode",
        ["settings.server_mode"] = "Server Mode",
        ["settings.server_mode_desc"] = "Force English audit logs, minimal UI",
        ["settings.about"] = "About",
        ["settings.version"] = "Version",

        // ===== Messages =====
        ["msg.admin_required"] = "Administrator privileges required.",
        ["msg.confirm_delete"] = "Confirm deletion?",
        ["msg.operation_success"] = "Operation successful",
        ["msg.operation_failed"] = "Operation failed",
        ["msg.file_not_found"] = "File not found",
        ["msg.dir_not_found"] = "Directory not found",
        ["msg.disk_space_insufficient"] = "Insufficient disk space",
    };

    public static readonly Dictionary<string, string> ZhTW = new()
    {
        // ===== 通用 =====
        ["app.name"] = "LightGuard",
        ["app.tagline"] = "全端安全容災稽核系統",
        ["common.ok"] = "確定",
        ["common.cancel"] = "取消",
        ["common.save"] = "儲存",
        ["common.delete"] = "刪除",
        ["common.refresh"] = "重新整理",
        ["common.close"] = "關閉",
        ["common.yes"] = "是",
        ["common.no"] = "否",
        ["common.loading"] = "載入中...",
        ["common.success"] = "成功",
        ["common.failed"] = "失敗",
        ["common.warning"] = "警告",
        ["common.error"] = "錯誤",
        ["common.info"] = "資訊",
        ["common.export"] = "匯出",
        ["common.import"] = "匯入",
        ["common.select"] = "選擇",
        ["common.browse"] = "瀏覽...",
        ["common.start"] = "開始",
        ["common.stop"] = "停止",
        ["common.enable"] = "啟用",
        ["common.disable"] = "停用",
        ["common.search"] = "搜尋",
        ["common.clear"] = "清除",
        ["common.all"] = "全部",
        ["common.none"] = "無",
        ["common.unknown"] = "未知",

        // ===== 導航 =====
        ["nav.dashboard"] = "儀表板",
        ["nav.privacy"] = "隱私加固",
        ["nav.cleanup"] = "流氓淨化",
        ["nav.firewall"] = "防火牆",
        ["nav.ransomware"] = "勒索防護",
        ["nav.backup"] = "加密備份",
        ["nav.audit"] = "檔案稽核",
        ["nav.update"] = "自動更新",
        ["nav.settings"] = "設定",
        ["nav.defender"] = "Defender查殺",
        ["nav.decrypt"] = "勒索解密",

        // ===== 儀表板 =====
        ["dashboard.title"] = "安全儀表板",
        ["dashboard.subtitle"] = "系統安全狀態總覽",
        ["dashboard.protection_status"] = "防護狀態",
        ["dashboard.modules_active"] = "已啟用模組",
        ["dashboard.threats_blocked"] = "已攔截威脅",
        ["dashboard.last_scan"] = "上次掃描",
        ["dashboard.system_health"] = "系統健康度",

        // ===== Defender 查殺 =====
        ["defender.title"] = "Defender 按需查殺",
        ["defender.subtitle"] = "Microsoft Defender 智慧排程引擎",
        ["defender.tab.overview"] = "掃描概覽",
        ["defender.tab.scan"] = "按需掃描",
        ["defender.tab.history"] = "掃描歷史",
        ["defender.tab.policy"] = "策略配置",
        ["defender.realtime_protection"] = "即時保護",
        ["defender.signature_version"] = "病毒庫版本",
        ["defender.engine_version"] = "引擎版本",
        ["defender.last_update"] = "最後更新",
        ["defender.health"] = "健康狀態",
        ["defender.healthy"] = "正常",
        ["defender.unhealthy"] = "異常",
        ["defender.scan_file"] = "單檔案掃描",
        ["defender.scan_dir"] = "目錄掃描",
        ["defender.scan_quick"] = "快速掃描",
        ["defender.scan_full"] = "全盤掃描",
        ["defender.scanning"] = "掃描中...",
        ["defender.scan_complete"] = "掃描完成",
        ["defender.threats_found"] = "發現威脅",
        ["defender.no_threats"] = "未發現威脅",
        ["defender.update_signatures"] = "更新病毒庫",
        ["defender.scan_priority"] = "掃描優先級",
        ["defender.remediation_action"] = "處置策略",
        ["defender.action.quarantine"] = "隔離",
        ["defender.action.remove"] = "刪除",
        ["defender.action.allow"] = "允許",
        ["defender.scan_before_backup"] = "備份前自動查殺",

        // ===== 勒索解密 =====
        ["decrypt.title"] = "勒索解密",
        ["decrypt.subtitle"] = "自動辨識勒索家族 · 匹配官方解密工具",
        ["decrypt.tab.emergency"] = "應急解密",
        ["decrypt.tab.tools"] = "工具庫",
        ["decrypt.tab.history"] = "解密歷史",
        ["decrypt.select_file"] = "選擇加密檔案",
        ["decrypt.select_dir"] = "選擇加密目錄",
        ["decrypt.detect_family"] = "偵測勒索家族",
        ["decrypt.start_decrypt"] = "開始解密",
        ["decrypt.backup_before"] = "解密前自動備份",
        ["decrypt.family_detected"] = "偵測到勒索家族",
        ["decrypt.family_unknown"] = "未辨識勒索家族",
        ["decrypt.no_decryptor"] = "暫無可用解密工具",
        ["decrypt.decryptor_available"] = "解密工具可用",
        ["decrypt.downloading_tool"] = "正在下載解密工具...",
        ["decrypt.verifying_tool"] = "正在校驗工具雜湊...",
        ["decrypt.decrypting"] = "解密中...",
        ["decrypt.decrypt_complete"] = "解密完成",
        ["decrypt.backup_created"] = "已建立解密前備份",
        ["decrypt.update_index"] = "更新索引",
        ["decrypt.download_tool"] = "下載工具",
        ["decrypt.verify_tool"] = "校驗工具",

        // ===== 備份 =====
        ["backup.title"] = "加密備份",
        ["backup.subtitle"] = "AES-256 加密 · VSS 卷影 · 防勒索隔離",
        ["backup.tab.encrypt"] = "加密備份",
        ["backup.tab.restore"] = "災難復原",
        ["backup.tab.database"] = "資料庫備份",
        ["backup.tab.lifecycle"] = "生命週期",
        ["backup.tab.enterprise"] = "企業容災",
        ["backup.tab.audit"] = "快照稽核",

        // ===== 設定 =====
        ["settings.title"] = "設定",
        ["settings.subtitle"] = "系統配置與偏好",
        ["settings.language"] = "介面語言",
        ["settings.theme"] = "主題模式",
        ["settings.server_mode"] = "伺服器模式",
        ["settings.server_mode_desc"] = "強制英文稽核日誌，精簡UI",
        ["settings.about"] = "關於",
        ["settings.version"] = "版本",

        // ===== 訊息 =====
        ["msg.admin_required"] = "需要管理員權限才能執行此操作。",
        ["msg.confirm_delete"] = "確認刪除？",
        ["msg.operation_success"] = "操作成功",
        ["msg.operation_failed"] = "操作失敗",
        ["msg.file_not_found"] = "檔案不存在",
        ["msg.dir_not_found"] = "目錄不存在",
        ["msg.disk_space_insufficient"] = "磁碟空間不足",
    };
}
