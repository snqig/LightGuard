using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace LightGuard.Firewall;

/// <summary>
/// 多语言 Unicode 文本处理工具
/// 提供字符校验、非法字符过滤、长度截断、UTF-8 BOM 编码转换
/// 支持：简/繁中文、英文、越南语、印地语、阿拉伯语等全 Unicode 语种
/// </summary>
public static class UnicodeTextHelper
{
    /// <summary>规则名称最大长度（Unicode 字符数）</summary>
    public const int MaxRuleNameLength = 255;

    /// <summary>备注最大长度（Unicode 字符数）</summary>
    public const int MaxRemarkLength = 1024;

    /// <summary>分组标签最大长度</summary>
    public const int MaxGroupTagLength = 128;

    /// <summary>
    /// 过滤非法控制字符（0x00~0x1F），保留所有 Unicode 文字、数字、标点、空格
    /// </summary>
    /// <param name="input">原始输入文本</param>
    /// <returns>过滤后的安全文本</returns>
    public static string FilterIllegalChars(string? input)
    {
        if (string.IsNullOrEmpty(input))
            return "";

        // 移除 0x00~0x1F 控制字符（保留换行 \n 和制表符 \t）
        var sb = new StringBuilder(input.Length);
        foreach (char c in input)
        {
            // 允许：0x09(Tab) 0x0A(LF) 0x0D(CR)，拒绝 0x00~0x08, 0x0B~0x0C, 0x0E~0x1F
            if (c >= 0x20 || c == '\t' || c == '\n' || c == '\r')
                sb.Append(c);
        }

        return sb.ToString();
    }

    /// <summary>
    /// 过滤并截断文本到指定长度
    /// </summary>
    /// <param name="input">原始文本</param>
    /// <param name="maxLength">最大 Unicode 字符数</param>
    /// <returns>过滤并截断后的文本</returns>
    public static string SanitizeAndTruncate(string? input, int maxLength)
    {
        var filtered = FilterIllegalChars(input);

        // 按 Unicode 字符数截断（不是字节数）
        if (filtered.Length > maxLength)
            return filtered.Substring(0, maxLength);

        return filtered;
    }

    /// <summary>
    /// 清洗规则名称：过滤非法字符 + 截断到 255 字符
    /// </summary>
    public static string SanitizeRuleName(string? name)
    {
        return SanitizeAndTruncate(name, MaxRuleNameLength).Trim();
    }

    /// <summary>
    /// 清洗备注文本：过滤非法字符 + 截断到 1024 字符
    /// </summary>
    public static string SanitizeRemark(string? remark)
    {
        return SanitizeAndTruncate(remark, MaxRemarkLength).Trim();
    }

    /// <summary>
    /// 清洗分组标签：过滤非法字符 + 截断到 128 字符
    /// </summary>
    public static string SanitizeGroupTag(string? groupTag)
    {
        return SanitizeAndTruncate(groupTag, MaxGroupTagLength).Trim();
    }

    /// <summary>
    /// 自动生成系统备注（用户未填写时使用）
    /// </summary>
    /// <param name="rule">规则实体</param>
    /// <returns>自动生成的备注文本</returns>
    public static string AutoGenerateRemark(FirewallAclRule rule)
    {
        var parts = new List<string>();

        parts.Add(rule.Action == FirewallConst.FwAction.Block ? "阻止" : "允许");
        parts.Add(rule.Direction == FirewallConst.FwDirection.Inbound ? "入站" : "出站");

        if (rule.Protocol != FirewallConst.FwProtocol.Any)
            parts.Add(rule.Protocol.ToString());

        var portDesc = rule.GetPortDescription();
        if (portDesc != "全端口")
            parts.Add(portDesc);

        if (!string.IsNullOrEmpty(rule.ApplicationPath))
            parts.Add($"程序:{Path.GetFileName(rule.ApplicationPath)}");

        parts.Add(rule.GetInterfaceDescription());

        return string.Join(" | ", parts);
    }

    /// <summary>
    /// 将 JSON 内容以 UTF-8 带 BOM 格式写入文件
    /// </summary>
    /// <param name="filePath">文件路径</param>
    /// <param name="jsonContent">JSON 文本内容</param>
    public static void WriteJsonWithBom(string filePath, string jsonContent)
    {
        var utf8WithBom = new UTF8Encoding(encoderShouldEmitUTF8Identifier: true);
        File.WriteAllText(filePath, jsonContent, utf8WithBom);
    }

    /// <summary>
    /// 读取 UTF-8 BOM 文件（也兼容无 BOM 的 UTF-8）
    /// </summary>
    /// <param name="filePath">文件路径</param>
    /// <returns>文件文本内容</returns>
    public static string ReadJsonFile(string filePath)
    {
        return File.ReadAllText(filePath, Encoding.UTF8);
    }

    /// <summary>
    /// 序列化对象为 UTF-8 BOM JSON 字符串
    /// </summary>
    public static string SerializeToJsonWithBom<T>(T data)
    {
        var json = JsonSerializer.Serialize(data, new JsonSerializerOptions
        {
            WriteIndented = true,
            Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping
        });

        return json;
    }

    /// <summary>
    /// 验证文本是否包含有效 Unicode 字符（非空且过滤后仍有内容）
    /// </summary>
    public static bool IsValidText(string? input)
    {
        return !string.IsNullOrWhiteSpace(FilterIllegalChars(input));
    }

    /// <summary>
    /// 检测文本是否包含可能引发 COM 异常的字符
    /// </summary>
    public static bool HasUnsafeChars(string? input)
    {
        if (string.IsNullOrEmpty(input))
            return false;

        foreach (char c in input)
        {
            if (c < 0x20 && c != '\t' && c != '\n' && c != '\r')
                return true;
        }

        return false;
    }
}

/// <summary>
/// 多语种模板文字字典
/// 支持：简体中文、繁体中文、English、Tiếng Việt、हिन्दी、العربية
/// </summary>
public static class MultilingualTemplates
{
    /// <summary>支持的语言枚举</summary>
    public enum Language
    {
        /// <summary>简体中文</summary>
        SimplifiedChinese,
        /// <summary>繁体中文</summary>
        TraditionalChinese,
        /// <summary>英语</summary>
        English,
        /// <summary>越南语</summary>
        Vietnamese,
        /// <summary>印地语</summary>
        Hindi,
        /// <summary>阿拉伯语</summary>
        Arabic
    }

    /// <summary>语言显示名称（用于 UI 下拉选择）</summary>
    public static readonly Dictionary<Language, string> LanguageNames = new()
    {
        { Language.SimplifiedChinese, "简体中文" },
        { Language.TraditionalChinese, "繁體中文" },
        { Language.English, "English" },
        { Language.Vietnamese, "Tiếng Việt" },
        { Language.Hindi, "हिन्दी" },
        { Language.Arabic, "العربية" }
    };

    /// <summary>
    /// 获取指定语言的模板文字字典
    /// Key: 模板标识符, Value: 该语言下的显示文字
    /// </summary>
    private static readonly Dictionary<Language, Dictionary<string, string>> TemplateTexts = new()
    {
        [Language.SimplifiedChinese] = new()
        {
            ["Block"] = "阻止",
            ["Allow"] = "允许",
            ["Inbound"] = "入站",
            ["Outbound"] = "出站",
            ["AllInterfaces"] = "全部网卡",
            ["PhysicalOnly"] = "仅物理网卡",
            ["VpnOnly"] = "仅VPN隧道",
            ["Wireless"] = "无线网卡",
            ["IPv6Tunnel"] = "IPv6隧道",
            ["AdobeBlock"] = "Adobe全家桶封锁",
            ["RogueUpdate"] = "流氓软件更新拦截",
            ["RansomPort"] = "勒索高危端口防护",
            ["Emergency"] = "勒索应急断网",
            ["CustomRule"] = "自定义规则",
            ["AllPorts"] = "全端口",
            ["HighRiskPorts"] = "高危端口(135/139/445/3389)",
            ["WebPorts"] = "Web端口(80/443)",
            ["ProxyPorts"] = "代理端口(1080/8080)",
            ["BlockAll"] = "阻断全部端口",
            ["BlockSpecified"] = "阻断指定端口",
            ["AllowSpecified"] = "仅放行指定端口",
            ["NewRule"] = "新建规则",
            ["BatchFolder"] = "批量目录拦截",
            ["ExportAll"] = "导出全部规则",
            ["ImportRules"] = "导入规则",
            ["CleanDead"] = "清理无效规则",
            ["ClearAll"] = "一键清空全部",
            ["RuleName"] = "规则名称",
            ["GroupTag"] = "分组标签",
            ["Remark"] = "备注",
            ["Action"] = "动作",
            ["Direction"] = "方向",
            ["Protocol"] = "协议",
            ["LocalPort"] = "本地端口",
            ["RemotePort"] = "远程端口",
            ["RemoteAddress"] = "远程地址",
            ["AppPath"] = "程序路径",
            ["InterfaceType"] = "网卡限制",
            ["Enabled"] = "启用",
            ["Priority"] = "优先级",
            ["Profile"] = "网络配置文件",
            ["EdgeTraversal"] = "边缘遍历",
            ["BrowseExe"] = "浏览EXE",
            ["BrowseFolder"] = "浏览文件夹",
            ["RecursiveScan"] = "递归扫描子目录",
            ["VpnBlock"] = "同时拦截VPN隧道流量",
            ["Create"] = "创建规则",
            ["Cancel"] = "取消",
            ["Execute"] = "执行",
            ["Scan"] = "扫描目录",
            ["LanguageLabel"] = "命名语种",
            ["PortTemplate"] = "端口模板",
            ["AddressTemplate"] = "地址模板",
            ["ConfirmExecute"] = "确认执行？",
            ["EmergencyWarn"] = "应急模式：将以最高优先级全端口阻断所有网卡流量"
        },
        [Language.TraditionalChinese] = new()
        {
            ["Block"] = "阻止",
            ["Allow"] = "允許",
            ["Inbound"] = "入站",
            ["Outbound"] = "出站",
            ["AllInterfaces"] = "全部網卡",
            ["PhysicalOnly"] = "僅實體網卡",
            ["VpnOnly"] = "僅VPN隧道",
            ["Wireless"] = "無線網卡",
            ["IPv6Tunnel"] = "IPv6隧道",
            ["AdobeBlock"] = "Adobe全家桶封鎖",
            ["RogueUpdate"] = "流氓軟體更新攔截",
            ["RansomPort"] = "勒索高危連接埠防護",
            ["Emergency"] = "勒索應急斷網",
            ["CustomRule"] = "自訂規則",
            ["AllPorts"] = "全連接埠",
            ["HighRiskPorts"] = "高危連接埠(135/139/445/3389)",
            ["WebPorts"] = "Web連接埠(80/443)",
            ["ProxyPorts"] = "代理連接埠(1080/8080)",
            ["BlockAll"] = "阻斷全部連接埠",
            ["BlockSpecified"] = "阻斷指定連接埠",
            ["AllowSpecified"] = "僅放行指定連接埠",
            ["NewRule"] = "新建規則",
            ["BatchFolder"] = "批次目錄攔截",
            ["ExportAll"] = "匯出全部規則",
            ["ImportRules"] = "匯入規則",
            ["CleanDead"] = "清理無效規則",
            ["ClearAll"] = "一鍵清空全部",
            ["RuleName"] = "規則名稱",
            ["GroupTag"] = "分組標籤",
            ["Remark"] = "備註",
            ["Action"] = "動作",
            ["Direction"] = "方向",
            ["Protocol"] = "協定",
            ["LocalPort"] = "本地連接埠",
            ["RemotePort"] = "遠端連接埠",
            ["RemoteAddress"] = "遠端位址",
            ["AppPath"] = "程式路徑",
            ["InterfaceType"] = "網卡限制",
            ["Enabled"] = "啟用",
            ["Priority"] = "優先級",
            ["Profile"] = "網路設定檔",
            ["EdgeTraversal"] = "邊緣遍歷",
            ["BrowseExe"] = "瀏覽EXE",
            ["BrowseFolder"] = "瀏覽資料夾",
            ["RecursiveScan"] = "遞迴掃描子目錄",
            ["VpnBlock"] = "同時攔截VPN隧道流量",
            ["Create"] = "建立規則",
            ["Cancel"] = "取消",
            ["Execute"] = "執行",
            ["Scan"] = "掃描目錄",
            ["LanguageLabel"] = "命名語種",
            ["PortTemplate"] = "連接埠範本",
            ["AddressTemplate"] = "位址範本",
            ["ConfirmExecute"] = "確認執行？",
            ["EmergencyWarn"] = "應急模式：將以最高優先級全連接埠阻斷所有網卡流量"
        },
        [Language.English] = new()
        {
            ["Block"] = "Block",
            ["Allow"] = "Allow",
            ["Inbound"] = "Inbound",
            ["Outbound"] = "Outbound",
            ["AllInterfaces"] = "All Interfaces",
            ["PhysicalOnly"] = "Physical Only",
            ["VpnOnly"] = "VPN Only",
            ["Wireless"] = "Wireless",
            ["IPv6Tunnel"] = "IPv6 Tunnel",
            ["AdobeBlock"] = "Adobe Suite Block",
            ["RogueUpdate"] = "Rogue Software Update Block",
            ["RansomPort"] = "Ransomware High-Risk Port Protection",
            ["Emergency"] = "Emergency Network Block",
            ["CustomRule"] = "Custom Rule",
            ["AllPorts"] = "All Ports",
            ["HighRiskPorts"] = "High-Risk Ports (135/139/445/3389)",
            ["WebPorts"] = "Web Ports (80/443)",
            ["ProxyPorts"] = "Proxy Ports (1080/8080)",
            ["BlockAll"] = "Block All Ports",
            ["BlockSpecified"] = "Block Specified Ports",
            ["AllowSpecified"] = "Allow Specified Ports Only",
            ["NewRule"] = "New Rule",
            ["BatchFolder"] = "Batch Folder Block",
            ["ExportAll"] = "Export All Rules",
            ["ImportRules"] = "Import Rules",
            ["CleanDead"] = "Clean Dead Rules",
            ["ClearAll"] = "Clear All Rules",
            ["RuleName"] = "Rule Name",
            ["GroupTag"] = "Group Tag",
            ["Remark"] = "Remark",
            ["Action"] = "Action",
            ["Direction"] = "Direction",
            ["Protocol"] = "Protocol",
            ["LocalPort"] = "Local Port",
            ["RemotePort"] = "Remote Port",
            ["RemoteAddress"] = "Remote Address",
            ["AppPath"] = "Application Path",
            ["InterfaceType"] = "Interface Type",
            ["Enabled"] = "Enabled",
            ["Priority"] = "Priority",
            ["Profile"] = "Network Profile",
            ["EdgeTraversal"] = "Edge Traversal",
            ["BrowseExe"] = "Browse EXE",
            ["BrowseFolder"] = "Browse Folder",
            ["RecursiveScan"] = "Recursive Scan Subfolders",
            ["VpnBlock"] = "Also Block VPN Tunnel Traffic",
            ["Create"] = "Create Rule",
            ["Cancel"] = "Cancel",
            ["Execute"] = "Execute",
            ["Scan"] = "Scan Folder",
            ["LanguageLabel"] = "Naming Language",
            ["PortTemplate"] = "Port Template",
            ["AddressTemplate"] = "Address Template",
            ["ConfirmExecute"] = "Confirm execution?",
            ["EmergencyWarn"] = "Emergency mode: Will block all ports on all interfaces with highest priority"
        },
        [Language.Vietnamese] = new()
        {
            ["Block"] = "Chặn",
            ["Allow"] = "Cho phép",
            ["Inbound"] = "Vào",
            ["Outbound"] = "Ra",
            ["AllInterfaces"] = "Tất cả giao diện",
            ["PhysicalOnly"] = "Chỉ vật lý",
            ["VpnOnly"] = "Chỉ VPN",
            ["Wireless"] = "Không dây",
            ["IPv6Tunnel"] = "Đường hầm IPv6",
            ["AdobeBlock"] = "Chặn Adobe Suite",
            ["RogueUpdate"] = "Chặn cập nhật phần mềm độc hại",
            ["RansomPort"] = "Bảo vệ cổng rủi ro cao",
            ["Emergency"] = "Khẩn cấp chặn mạng",
            ["CustomRule"] = "Quy tắc tùy chỉnh",
            ["AllPorts"] = "Tất cả cổng",
            ["HighRiskPorts"] = "Cổng rủi ro cao (135/139/445/3389)",
            ["WebPorts"] = "Cổng Web (80/443)",
            ["ProxyPorts"] = "Cổng proxy (1080/8080)",
            ["BlockAll"] = "Chặn tất cả cổng",
            ["BlockSpecified"] = "Chặn cổng chỉ định",
            ["AllowSpecified"] = "Chỉ cho phép cổng chỉ định",
            ["NewRule"] = "Tạo quy tắc mới",
            ["BatchFolder"] = "Chặn thư mục hàng loạt",
            ["ExportAll"] = "Xuất tất cả quy tắc",
            ["ImportRules"] = "Nhập quy tắc",
            ["CleanDead"] = "Dọn quy tắc vô hiệu",
            ["ClearAll"] = "Xóa tất cả quy tắc",
            ["RuleName"] = "Tên quy tắc",
            ["GroupTag"] = "Nhãn nhóm",
            ["Remark"] = "Ghi chú",
            ["Action"] = "Hành động",
            ["Direction"] = "Hướng",
            ["Protocol"] = "Giao thức",
            ["LocalPort"] = "Cổng cục bộ",
            ["RemotePort"] = "Cổng từ xa",
            ["RemoteAddress"] = "Địa chỉ từ xa",
            ["AppPath"] = "Đường dẫn ứng dụng",
            ["InterfaceType"] = "Loại giao diện",
            ["Enabled"] = "Kích hoạt",
            ["Priority"] = "Ưu tiên",
            ["Profile"] = "Hồ sơ mạng",
            ["EdgeTraversal"] = "Duyệt biên",
            ["BrowseExe"] = "Duyệt EXE",
            ["BrowseFolder"] = "Duyệt thư mục",
            ["RecursiveScan"] = "Quét đệ quy thư mục con",
            ["VpnBlock"] = "Cũng chặn lưu lượng đường hầm VPN",
            ["Create"] = "Tạo quy tắc",
            ["Cancel"] = "Hủy",
            ["Execute"] = "Thực thi",
            ["Scan"] = "Quét thư mục",
            ["LanguageLabel"] = "Ngôn ngữ đặt tên",
            ["PortTemplate"] = "Mẫu cổng",
            ["AddressTemplate"] = "Mẫu địa chỉ",
            ["ConfirmExecute"] = "Xác nhận thực thi?",
            ["EmergencyWarn"] = "Chế độ khẩn cấp: Sẽ chặn tất cả cổng trên tất cả giao diện với ưu tiên cao nhất"
        },
        [Language.Hindi] = new()
        {
            ["Block"] = "अवरोध",
            ["Allow"] = "अनुमति",
            ["Inbound"] = "इनबाउंड",
            ["Outbound"] = "आउटबाउंड",
            ["AllInterfaces"] = "सभी इंटरफेस",
            ["PhysicalOnly"] = "केवल भौतिक",
            ["VpnOnly"] = "केवल VPN",
            ["Wireless"] = "वायरलेस",
            ["IPv6Tunnel"] = "IPv6 सुरंग",
            ["AdobeBlock"] = "Adobe सुइट अवरोध",
            ["RogueUpdate"] = "दुर्भावनापूर्ण सॉफ्टवेयर अपडेट अवरोध",
            ["RansomPort"] = "रैंसमवेयर उच्च-जोखिम पोर्ट सुरक्षा",
            ["Emergency"] = "आपातकालीन नेटवर्क अवरोध",
            ["CustomRule"] = "कस्टम नियम",
            ["AllPorts"] = "सभी पोर्ट",
            ["HighRiskPorts"] = "उच्च-जोखिम पोर्ट (135/139/445/3389)",
            ["WebPorts"] = "वेब पोर्ट (80/443)",
            ["ProxyPorts"] = "प्रॉक्सी पोर्ट (1080/8080)",
            ["BlockAll"] = "सभी पोर्ट अवरोधित करें",
            ["BlockSpecified"] = "निर्दिष्ट पोर्ट अवरोधित करें",
            ["AllowSpecified"] = "केवल निर्दिष्ट पोर्ट अनुमति दें",
            ["NewRule"] = "नया नियम",
            ["BatchFolder"] = "बैच फ़ोल्डर अवरोध",
            ["ExportAll"] = "सभी नियम निर्यात करें",
            ["ImportRules"] = "नियम आयात करें",
            ["CleanDead"] = "निष्क्रिय नियम साफ़ करें",
            ["ClearAll"] = "सभी नियम साफ़ करें",
            ["RuleName"] = "नियम नाम",
            ["GroupTag"] = "समूह टैग",
            ["Remark"] = "टिप्पणी",
            ["Action"] = "क्रिया",
            ["Direction"] = "दिशा",
            ["Protocol"] = "प्रोटोकॉल",
            ["LocalPort"] = "स्थानीय पोर्ट",
            ["RemotePort"] = "दूरस्थ पोर्ट",
            ["RemoteAddress"] = "दूरस्थ पता",
            ["AppPath"] = "एप्लिकेशन पथ",
            ["InterfaceType"] = "इंटरफेस प्रकार",
            ["Enabled"] = "सक्षम",
            ["Priority"] = "प्राथमिकता",
            ["Profile"] = "नेटवर्क प्रोफ़ाइल",
            ["EdgeTraversal"] = "एज ट्रैवर्सल",
            ["BrowseExe"] = "EXE ब्राउज़ करें",
            ["BrowseFolder"] = "फ़ोल्डर ब्राउज़ करें",
            ["RecursiveScan"] = "रिकर्सिव स्कैन सबफ़ोल्डर",
            ["VpnBlock"] = "VPN सुरंग ट्रैफ़िक भी अवरोधित करें",
            ["Create"] = "नियम बनाएं",
            ["Cancel"] = "रद्द करें",
            ["Execute"] = "निष्पादित करें",
            ["Scan"] = "फ़ोल्डर स्कैन करें",
            ["LanguageLabel"] = "नामकरण भाषा",
            ["PortTemplate"] = "पोर्ट टेम्पलेट",
            ["AddressTemplate"] = "पता टेम्पलेट",
            ["ConfirmExecute"] = "निष्पादन की पुष्टि करें?",
            ["EmergencyWarn"] = "आपातकालीन मोड: उच्चतम प्राथमिकता के साथ सभी इंटरफेस पर सभी पोर्ट को अवरोधित करेगा"
        },
        [Language.Arabic] = new()
        {
            ["Block"] = "حظر",
            ["Allow"] = "سماح",
            ["Inbound"] = "وارد",
            ["Outbound"] = "صادر",
            ["AllInterfaces"] = "جميع الواجهات",
            ["PhysicalOnly"] = "فيزيائي فقط",
            ["VpnOnly"] = "VPN فقط",
            ["Wireless"] = "لاسلكي",
            ["IPv6Tunnel"] = "نفق IPv6",
            ["AdobeBlock"] = "حظر Adobe Suite",
            ["RogueUpdate"] = "حظر تحديث البرامج الضارة",
            ["RansomPort"] = "حماية المنافذ عالية المخاطر",
            ["Emergency"] = "حظر شبكة طارئ",
            ["CustomRule"] = "قاعدة مخصصة",
            ["AllPorts"] = "جميع المنافذ",
            ["HighRiskPorts"] = "منافذ عالية المخاطر (135/139/445/3389)",
            ["WebPorts"] = "منافذ الويب (80/443)",
            ["ProxyPorts"] = "منافذ الوكيل (1080/8080)",
            ["BlockAll"] = "حظر جميع المنافذ",
            ["BlockSpecified"] = "حظر منافذ محددة",
            ["AllowSpecified"] = "سماح فقط للمنافذ المحددة",
            ["NewRule"] = "قاعدة جديدة",
            ["BatchFolder"] = "حظر مجلد دفعي",
            ["ExportAll"] = "تصدير جميع القواعد",
            ["ImportRules"] = "استيراد القواعد",
            ["CleanDead"] = "تنظيف القواعد المعطلة",
            ["ClearAll"] = "مسح جميع القواعد",
            ["RuleName"] = "اسم القاعدة",
            ["GroupTag"] = "وسم المجموعة",
            ["Remark"] = "ملاحظة",
            ["Action"] = "إجراء",
            ["Direction"] = "اتجاه",
            ["Protocol"] = "بروتوكول",
            ["LocalPort"] = "منفذ محلي",
            ["RemotePort"] = "منفذ بعيد",
            ["RemoteAddress"] = "عنوان بعيد",
            ["AppPath"] = "مسار التطبيق",
            ["InterfaceType"] = "نوع الواجهة",
            ["Enabled"] = "مفعّل",
            ["Priority"] = "أولوية",
            ["Profile"] = "ملف الشبكة",
            ["EdgeTraversal"] = "عبور الحافة",
            ["BrowseExe"] = "تصفح EXE",
            ["BrowseFolder"] = "تصفح المجلد",
            ["RecursiveScan"] = "فحص متكرر للمجلدات الفرعية",
            ["VpnBlock"] = "حظر أيضاً حركة نفق VPN",
            ["Create"] = "إنشاء قاعدة",
            ["Cancel"] = "إلغاء",
            ["Execute"] = "تنفيذ",
            ["Scan"] = "فحص المجلد",
            ["LanguageLabel"] = "لغة التسمية",
            ["PortTemplate"] = "قالب المنفذ",
            ["AddressTemplate"] = "قالب العنوان",
            ["ConfirmExecute"] = "تأكيد التنفيذ؟",
            ["EmergencyWarn"] = "وضع الطوارئ: سيحظر جميع المنافذ على جميع الواجهات بأعلى أولوية"
        }
    };

    /// <summary>
    /// 获取指定语言的模板文字
    /// </summary>
    /// <param name="lang">语言</param>
    /// <param name="key">模板键</param>
    /// <returns>对应语言的文字，找不到则返回键名</returns>
    public static string Get(Language lang, string key)
    {
        if (TemplateTexts.TryGetValue(lang, out var dict) && dict.TryGetValue(key, out var text))
            return text;
        return key;
    }

    /// <summary>
    /// 获取指定语言的所有模板文字字典
    /// </summary>
    public static Dictionary<string, string> GetTemplates(Language lang)
    {
        return TemplateTexts.TryGetValue(lang, out var dict)
            ? new Dictionary<string, string>(dict)
            : new Dictionary<string, string>();
    }

    /// <summary>
    /// 根据语言和模板类型生成规则名称
    /// </summary>
    /// <param name="lang">语言</param>
    /// <param name="templateKey">模板键（如 AdobeBlock/RogueUpdate 等）</param>
    /// <param name="suffix">可选后缀（如程序名）</param>
    /// <returns>生成的规则名称</returns>
    public static string GenerateRuleName(Language lang, string templateKey, string? suffix = null)
    {
        var baseName = Get(lang, templateKey);
        if (!string.IsNullOrEmpty(suffix))
            return $"{baseName}_{suffix}";
        return baseName;
    }
}
