// © 2026 落尘（Luochen） 原创开发 - 保留所有权利

using System.IO;
using System.Text.Json;
using System.Text.RegularExpressions;
using LightGuard.Core;

namespace LightGuard.Backup;

/// <summary>
/// 过滤规则类型。
/// </summary>
public enum FilterType
{
    /// <summary>按文件扩展名排除。</summary>
    ExcludeExtension,

    /// <summary>按目录名/路径段排除。</summary>
    ExcludeDirectory,

    /// <summary>按通配模式排除。</summary>
    ExcludePattern,

    /// <summary>强制包含（覆盖所有排除规则）。</summary>
    IncludeForce,

    /// <summary>系统文件排除（pagefile.sys 等）。</summary>
    ExcludeSystem
}

/// <summary>
/// 过滤规则 - 一条黑名单/白名单匹配项。
/// </summary>
public sealed class FilterRule
{
    /// <summary>匹配模式（扩展名 / 目录名 / 通配符 / 文件名，含义随 <see cref="Type"/> 而定）。</summary>
    public string Pattern { get; set; } = string.Empty;

    /// <summary>规则类型。</summary>
    public FilterType Type { get; set; }

    /// <summary>规则描述（便于展示与日志）。</summary>
    public string Description { get; set; } = string.Empty;
}

/// <summary>
/// 过滤判定结果。
/// </summary>
public sealed class FilterResult
{
    /// <summary>是否纳入备份。</summary>
    public bool Include { get; set; }

    /// <summary>判定原因（便于日志与调试）。</summary>
    public string? Reason { get; set; }

    /// <summary>命中的规则；未命中任何规则时为 null。</summary>
    public FilterRule? MatchedRule { get; set; }
}

/// <summary>
/// 智能备份黑名单/白名单过滤引擎 - 按规则集判定文件是否纳入备份。
/// <para>内置默认规则：排除临时文件、缓存、回收站、系统卷信息、版本控制目录、构建输出目录、系统文件等。</para>
/// <para>判定优先级：强制包含 > 系统排除 > 扩展名排除 > 目录排除 > 模式排除 > 默认包含。</para>
/// <para>支持自定义规则增删、批量过滤、统计与 JSON 持久化。</para>
/// </summary>
public sealed class SmartFilterEngine
{
    private static readonly JsonSerializerOptions RuleJsonOptions = new()
    {
        WriteIndented = true
    };

    /// <summary>当前生效的全部规则（按添加顺序）。</summary>
    public List<FilterRule> Rules { get; private set; } = new();

    /// <summary>累计已过滤（排除）的文件数。</summary>
    public long TotalFiltered { get; private set; }

    /// <summary>累计因过滤节省的字节数。</summary>
    public long TotalFilteredBytes { get; private set; }

    /// <summary>
    /// 初始化过滤引擎并加载默认规则。
    /// </summary>
    public SmartFilterEngine()
    {
        ResetToDefaults();
    }

    /// <summary>
    /// 添加自定义排除扩展名规则。
    /// </summary>
    /// <param name="ext">扩展名（是否带前导点均可，如 ".tmp" 或 "tmp"）。</param>
    public void AddExcludeExtension(string ext)
    {
        if (string.IsNullOrWhiteSpace(ext)) return;
        var norm = NormalizeExtension(ext);
        if (string.IsNullOrEmpty(norm)) return;

        Rules.Add(new FilterRule
        {
            Pattern = norm,
            Type = FilterType.ExcludeExtension,
            Description = $"自定义排除扩展名 {norm}"
        });
        ErrorReporter.Log($"新增排除扩展名规则：{norm}");
    }

    /// <summary>
    /// 添加自定义排除目录规则。
    /// </summary>
    /// <param name="dir">目录名或相对路径段（如 "node_modules"、"AppData/Local/Temp"）。</param>
    public void AddExcludeDirectory(string dir)
    {
        if (string.IsNullOrWhiteSpace(dir)) return;
        var norm = dir.Replace('\\', '/').Trim('/');

        Rules.Add(new FilterRule
        {
            Pattern = norm,
            Type = FilterType.ExcludeDirectory,
            Description = $"自定义排除目录 {norm}"
        });
        ErrorReporter.Log($"新增排除目录规则：{norm}");
    }

    /// <summary>
    /// 添加强制包含目录规则（覆盖所有排除规则，命中即纳入备份）。
    /// </summary>
    /// <param name="dir">目录路径（可为相对 rootDir 的路径或绝对路径）。</param>
    public void AddIncludeForce(string dir)
    {
        if (string.IsNullOrWhiteSpace(dir)) return;
        var norm = dir.Replace('\\', '/').Trim('/');

        Rules.Add(new FilterRule
        {
            Pattern = norm,
            Type = FilterType.IncludeForce,
            Description = $"强制包含目录 {norm}"
        });
        ErrorReporter.Log($"新增强制包含目录规则：{norm}");
    }

    /// <summary>
    /// 添加自定义排除通配模式规则。
    /// </summary>
    /// <param name="pattern">通配模式（支持 * 与 ?，如 "*.tmp"、"~$*"、"Thumbs.db"）。</param>
    public void AddExcludePattern(string pattern)
    {
        if (string.IsNullOrWhiteSpace(pattern)) return;

        Rules.Add(new FilterRule
        {
            Pattern = pattern,
            Type = FilterType.ExcludePattern,
            Description = $"自定义排除模式 {pattern}"
        });
        ErrorReporter.Log($"新增排除模式规则：{pattern}");
    }

    /// <summary>
    /// 移除首条与指定规则（类型 + 模式）匹配的规则。
    /// </summary>
    /// <param name="rule">待移除的规则（按类型与模式匹配，忽略大小写）。</param>
    public void RemoveRule(FilterRule rule)
    {
        ArgumentNullException.ThrowIfNull(rule);

        for (int i = 0; i < Rules.Count; i++)
        {
            if (Rules[i].Type == rule.Type
                && string.Equals(Rules[i].Pattern, rule.Pattern, StringComparison.OrdinalIgnoreCase))
            {
                ErrorReporter.Log($"移除规则：[{rule.Type}] {rule.Pattern}");
                Rules.RemoveAt(i);
                return;
            }
        }
    }

    /// <summary>
    /// 主过滤判定：判断单个文件是否纳入备份。
    /// <para>判定顺序：强制包含 → 系统排除 → 扩展名排除 → 目录排除 → 模式排除 → 默认包含。</para>
    /// </summary>
    /// <param name="filePath">文件绝对路径。</param>
    /// <param name="rootDir">备份根目录（用于计算相对路径）。</param>
    /// <returns>过滤结果。</returns>
    public FilterResult ShouldInclude(string filePath, string rootDir)
    {
        ArgumentNullException.ThrowIfNull(filePath);
        ArgumentNullException.ThrowIfNull(rootDir);

        string relPath;
        try
        {
            relPath = Path.GetRelativePath(rootDir, filePath).Replace('\\', '/');
        }
        catch
        {
            relPath = filePath.Replace('\\', '/');
        }

        var fileName = Path.GetFileName(filePath);
        var fileExt = Path.GetExtension(filePath);

        // 1. 强制包含优先（命中即纳入）
        foreach (var rule in Rules)
        {
            if (rule.Type != FilterType.IncludeForce) continue;
            if (IsUnderDirectory(filePath, rootDir, rule.Pattern))
                return new FilterResult { Include = true, Reason = $"强制包含：{rule.Pattern}", MatchedRule = rule };
        }

        // 2. 系统文件排除
        foreach (var rule in Rules)
        {
            if (rule.Type != FilterType.ExcludeSystem) continue;
            if (string.Equals(fileName, rule.Pattern, StringComparison.OrdinalIgnoreCase))
                return Exclude(rule, $"系统文件排除：{fileName}");
        }

        // 3. 扩展名排除
        foreach (var rule in Rules)
        {
            if (rule.Type != FilterType.ExcludeExtension) continue;
            if (string.Equals(fileExt, NormalizeExtension(rule.Pattern), StringComparison.OrdinalIgnoreCase))
                return Exclude(rule, $"扩展名排除：{fileExt}");
        }

        // 4. 目录排除
        foreach (var rule in Rules)
        {
            if (rule.Type != FilterType.ExcludeDirectory) continue;
            if (MatchesDirectory(relPath, rule.Pattern))
                return Exclude(rule, $"目录排除：{rule.Pattern}");
        }

        // 5. 通配模式排除
        foreach (var rule in Rules)
        {
            if (rule.Type != FilterType.ExcludePattern) continue;
            if (MatchesGlob(fileName, rule.Pattern) || MatchesGlob(relPath, rule.Pattern))
                return Exclude(rule, $"模式排除：{rule.Pattern}");
        }

        // 6. 默认包含
        return new FilterResult { Include = true, Reason = "默认包含", MatchedRule = null };
    }

    /// <summary>
    /// 批量过滤文件集合。
    /// </summary>
    /// <param name="files">文件路径集合。</param>
    /// <param name="rootDir">备份根目录。</param>
    /// <returns>(纳入备份的文件列表, 被排除的文件列表)。</returns>
    public (List<string> Included, List<string> Excluded) FilterFiles(IEnumerable<string> files, string rootDir)
    {
        ArgumentNullException.ThrowIfNull(files);

        var included = new List<string>();
        var excluded = new List<string>();

        foreach (var file in files)
        {
            var result = ShouldInclude(file, rootDir);
            if (result.Include)
            {
                included.Add(file);
            }
            else
            {
                excluded.Add(file);
                TotalFiltered++;
                try
                {
                    TotalFilteredBytes += new FileInfo(file).Length;
                }
                catch (Exception ex)
                {
                    ErrorReporter.Log($"无法读取文件大小，跳过统计 {file}：{ex.Message}", "WARN");
                }
            }
        }

        ErrorReporter.Log($"批量过滤完成：纳入 {included.Count} 个，排除 {excluded.Count} 个，累计节省 {TotalFilteredBytes} 字节");
        return (included, excluded);
    }

    /// <summary>
    /// 返回过滤统计信息字符串。
    /// </summary>
    /// <returns>统计文本。</returns>
    public string GetFilterStats()
    {
        return $"规则总数：{Rules.Count} | "
            + $"扩展名排除：{CountOf(FilterType.ExcludeExtension)} | "
            + $"目录排除：{CountOf(FilterType.ExcludeDirectory)} | "
            + $"模式排除：{CountOf(FilterType.ExcludePattern)} | "
            + $"强制包含：{CountOf(FilterType.IncludeForce)} | "
            + $"系统排除：{CountOf(FilterType.ExcludeSystem)} | "
            + $"已过滤文件：{TotalFiltered} 个 | "
            + $"节省空间：{FormatBytes(TotalFilteredBytes)}";
    }

    /// <summary>
    /// 将当前规则集持久化为 JSON 文件。
    /// </summary>
    /// <param name="filePath">目标文件路径。</param>
    public void SaveRules(string filePath)
    {
        var dir = Path.GetDirectoryName(filePath);
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);

        var json = JsonSerializer.Serialize(Rules, RuleJsonOptions);
        File.WriteAllText(filePath, json);
        ErrorReporter.Log($"过滤规则已保存：{filePath}（共 {Rules.Count} 条）");
    }

    /// <summary>
    /// 从 JSON 文件加载规则集（替换当前规则）。
    /// </summary>
    /// <param name="filePath">规则文件路径。</param>
    public void LoadRules(string filePath)
    {
        if (!File.Exists(filePath))
            throw new FileNotFoundException("规则文件不存在。", filePath);

        var json = File.ReadAllText(filePath);
        var loaded = JsonSerializer.Deserialize<List<FilterRule>>(json, RuleJsonOptions);
        Rules = loaded ?? new List<FilterRule>();
        ErrorReporter.Log($"过滤规则已加载：{filePath}（共 {Rules.Count} 条）");
    }

    /// <summary>
    /// 重置为默认规则集（不影响累计统计）。
    /// </summary>
    public void ResetToDefaults()
    {
        Rules = new List<FilterRule>();

        // 默认排除扩展名
        foreach (var ext in new[] { ".tmp", ".temp", ".log", ".cache", ".thumbs", ".lnk", ".bak", ".old" })
        {
            Rules.Add(new FilterRule
            {
                Pattern = ext,
                Type = FilterType.ExcludeExtension,
                Description = "默认排除扩展名"
            });
        }

        // 默认排除目录
        foreach (var dir in new[]
        {
            "$Recycle.Bin",
            "System Volume Information",
            "Windows/Temp",
            "AppData/Local/Temp",
            "AppData/Local/Microsoft/Windows/INetCache",
            "node_modules",
            ".git",
            "__pycache__",
            ".vs",
            "bin",
            "obj"
        })
        {
            Rules.Add(new FilterRule
            {
                Pattern = dir,
                Type = FilterType.ExcludeDirectory,
                Description = "默认排除目录"
            });
        }

        // 默认排除通配模式
        foreach (var pattern in new[] { "*.tmp", "~$*", "*.partial", "*.crdownload", "Thumbs.db", "desktop.ini" })
        {
            Rules.Add(new FilterRule
            {
                Pattern = pattern,
                Type = FilterType.ExcludePattern,
                Description = "默认排除模式"
            });
        }

        // 默认系统文件排除
        foreach (var sys in new[] { "pagefile.sys", "hiberfil.sys", "swapfile.sys", "ntuser.dat.log" })
        {
            Rules.Add(new FilterRule
            {
                Pattern = sys,
                Type = FilterType.ExcludeSystem,
                Description = "系统文件排除"
            });
        }

        ErrorReporter.Log($"过滤引擎已重置为默认规则（共 {Rules.Count} 条）");
    }

    #region 匹配辅助

    /// <summary>
    /// 构造排除结果。
    /// </summary>
    private static FilterResult Exclude(FilterRule rule, string reason)
        => new() { Include = false, Reason = reason, MatchedRule = rule };

    /// <summary>
    /// 规范化扩展名，确保带前导点。
    /// </summary>
    private static string NormalizeExtension(string ext)
    {
        if (string.IsNullOrEmpty(ext)) return string.Empty;
        ext = ext.Trim();
        if (ext.Length == 0) return string.Empty;
        return ext.StartsWith('.') ? ext : "." + ext;
    }

    /// <summary>
    /// 目录匹配：单段匹配任意路径段；多段（含 /）匹配相对路径子串。
    /// </summary>
    private static bool MatchesDirectory(string relPath, string dirPattern)
    {
        var normalized = relPath.Replace('\\', '/');
        var pattern = dirPattern.Replace('\\', '/').Trim('/');

        if (pattern.Length == 0) return false;

        if (pattern.Contains('/'))
        {
            return normalized.IndexOf(pattern, StringComparison.OrdinalIgnoreCase) >= 0;
        }

        var segments = normalized.Split('/', StringSplitOptions.RemoveEmptyEntries);
        foreach (var seg in segments)
        {
            if (string.Equals(seg, pattern, StringComparison.OrdinalIgnoreCase))
                return true;
        }
        return false;
    }

    /// <summary>
    /// 通配符匹配（支持 * 与 ?），转义为正则后整体匹配。
    /// </summary>
    private static bool MatchesGlob(string text, string pattern)
    {
        if (string.IsNullOrEmpty(pattern)) return false;
        if (string.IsNullOrEmpty(text)) return false;

        var regexPattern = "^" + Regex.Escape(pattern).Replace("\\*", ".*").Replace("\\?", ".") + "$";
        return Regex.IsMatch(text, regexPattern, RegexOptions.IgnoreCase);
    }

    /// <summary>
    /// 判断文件是否位于强制包含目录之下（dirPattern 可为相对 rootDir 的路径或绝对路径）。
    /// </summary>
    private static bool IsUnderDirectory(string filePath, string rootDir, string dirPattern)
    {
        var normalizedFile = filePath.Replace('\\', '/').TrimEnd('/');

        string baseDir;
        if (Path.IsPathRooted(dirPattern))
            baseDir = dirPattern.Replace('\\', '/').TrimEnd('/');
        else
            baseDir = Path.Combine(rootDir, dirPattern).Replace('\\', '/').TrimEnd('/');

        return normalizedFile.StartsWith(baseDir + "/", StringComparison.OrdinalIgnoreCase)
            || string.Equals(normalizedFile, baseDir, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// 统计指定类型的规则数量。
    /// </summary>
    private int CountOf(FilterType type) => Rules.Count(r => r.Type == type);

    /// <summary>
    /// 将字节数格式化为带单位的可读字符串。
    /// </summary>
    private static string FormatBytes(long bytes)
    {
        string[] units = { "B", "KB", "MB", "GB", "TB", "PB" };
        double size = bytes;
        int u = 0;
        while (size >= 1024 && u < units.Length - 1)
        {
            size /= 1024;
            u++;
        }
        return $"{size:0.##} {units[u]}";
    }

    #endregion
}
