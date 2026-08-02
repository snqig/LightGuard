// © 2026 落尘（Luochen） 原创开发 - 保留所有权利

using System.Text.RegularExpressions;

namespace LightGuard.Core;

/// <summary>
/// 硬编码文本扫描工具 — 全局检索未接入 LangHelper 的硬编码中文字符串。
/// <para>用于 P0-3 多语言框架的配套验证，确保零硬编码。</para>
/// <para>使用方式：var results = HardcodeScanner.ScanDirectory(srcDir);</para>
/// </summary>
public static class HardcodeScanner
{
    /// <summary>扫描结果条目</summary>
    public sealed class ScanResult
    {
        /// <summary>文件路径</summary>
        public string FilePath { get; set; } = string.Empty;

        /// <summary>行号</summary>
        public int LineNumber { get; set; }

        /// <summary>硬编码文本内容</summary>
        public string Text { get; set; } = string.Empty;

        /// <summary>整行内容</summary>
        public string LineContent { get; set; } = string.Empty;

        /// <summary>建议的 LangHelper 键</summary>
        public string SuggestedKey { get; set; } = string.Empty;
    }

    /// <summary>扫描统计</summary>
    public sealed class ScanStatistics
    {
        public int TotalFilesScanned { get; set; }
        public int TotalHardcodedStrings { get; set; }
        public Dictionary<string, int> HardcodedByFile { get; set; } = new();
        public Dictionary<string, int> HardcodedByDirectory { get; set; } = new();
    }

    // 匹配中文字符的正则（含中文标点）
    private static readonly Regex ChineseTextRegex = new(
        @"[\u4e00-\u9fff\u3000-\u303f\uff00-\uffef]+",
        RegexOptions.Compiled);

    // 需要跳过的模式（注释、using语句等）
    private static readonly Regex[] SkipPatterns =
    {
        new(@"^\s*//", RegexOptions.Compiled),              // 单行注释
        new(@"^\s*\*", RegexOptions.Compiled),               // 块注释行
        new(@"^\s*///\s*<", RegexOptions.Compiled),          // XML 文档注释标签
        new(@"^\s*using\s", RegexOptions.Compiled),          // using 语句
        new(@"^\s*namespace\s", RegexOptions.Compiled),      // namespace 声明
        new(@"^\s*\[", RegexOptions.Compiled),               // 特性标注
    };

    // 需要跳过的文件名
    private static readonly HashSet<string> SkipFiles = new(StringComparer.OrdinalIgnoreCase)
    {
        "LangHelper.cs", "HardcodeScanner.cs", "BuiltInTexts.cs",
        "Theme.cs", "Program.cs", "AppState.cs"
    };

    // 需要跳过的目录
    private static readonly HashSet<string> SkipDirs = new(StringComparer.OrdinalIgnoreCase)
    {
        "obj", "bin", ".vs", "Properties"
    };

    /// <summary>
    /// 扫描指定目录下的所有 .cs 文件，查找硬编码中文字符串。
    /// </summary>
    /// <param name="directory">源代码目录</param>
    /// <returns>扫描结果列表</returns>
    public static (List<ScanResult> results, ScanStatistics stats) ScanDirectory(string directory)
    {
        var results = new List<ScanResult>();
        var stats = new ScanStatistics();

        if (!Directory.Exists(directory))
        {
            ErrorReporter.Log($"扫描目录不存在: {directory}", "WARN");
            return (results, stats);
        }

        var csFiles = Directory.GetFiles(directory, "*.cs", SearchOption.AllDirectories);

        foreach (var file in csFiles)
        {
            // 跳过排除目录
            var relativePath = Path.GetRelativePath(directory, file);
            var parts = relativePath.Split(Path.DirectorySeparatorChar);
            if (parts.Any(p => SkipDirs.Contains(p)))
                continue;

            // 跳过排除文件
            if (SkipFiles.Contains(Path.GetFileName(file)))
                continue;

            var fileResults = ScanFile(file);
            results.AddRange(fileResults);
            stats.TotalFilesScanned++;

            if (fileResults.Count > 0)
            {
                stats.HardcodedByFile[relativePath] = fileResults.Count;
                var dir = Path.GetDirectoryName(relativePath) ?? "(root)";
                stats.HardcodedByDirectory[dir] = stats.HardcodedByDirectory.GetValueOrDefault(dir) + fileResults.Count;
            }
        }

        stats.TotalHardcodedStrings = results.Count;
        ErrorReporter.Log($"硬编码扫描完成: {stats.TotalFilesScanned} 文件, {stats.TotalHardcodedStrings} 处硬编码", "INFO");

        return (results, stats);
    }

    /// <summary>
    /// 扫描单个文件。
    /// </summary>
    public static List<ScanResult> ScanFile(string filePath)
    {
        var results = new List<ScanResult>();

        try
        {
            var lines = File.ReadAllLines(filePath);

            for (int i = 0; i < lines.Length; i++)
            {
                var line = lines[i];

                // 跳过注释等
                if (ShouldSkipLine(line))
                    continue;

                // 查找中文字符串
                var matches = ChineseTextRegex.Matches(line);
                foreach (Match match in matches)
                {
                    // 只关注字符串字面量中的中文（被引号包围）
                    if (!IsInsideStringLiteral(line, match.Index))
                        continue;

                    // 跳过很短的（单个字符可能是符号）
                    if (match.Value.Length < 2)
                        continue;

                    results.Add(new ScanResult
                    {
                        FilePath = filePath,
                        LineNumber = i + 1,
                        Text = match.Value,
                        LineContent = line.Trim(),
                        SuggestedKey = GenerateSuggestedKey(match.Value, filePath)
                    });
                }
            }
        }
        catch (Exception ex)
        {
            ErrorReporter.Log($"扫描文件失败 {filePath}: {ex.Message}", "WARN");
        }

        return results;
    }

    /// <summary>
    /// 生成扫描报告（文本格式）。
    /// </summary>
    public static string GenerateReport(List<ScanResult> results, ScanStatistics stats)
    {
        var sb = new System.Text.StringBuilder();
        sb.AppendLine("=== LightGuard 硬编码文本扫描报告 ===");
        sb.AppendLine($"扫描时间: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
        sb.AppendLine($"扫描文件数: {stats.TotalFilesScanned}");
        sb.AppendLine($"硬编码字符串数: {stats.TotalHardcodedStrings}");
        sb.AppendLine();

        if (stats.HardcodedByDirectory.Count > 0)
        {
            sb.AppendLine("--- 按目录统计 ---");
            foreach (var kv in stats.HardcodedByDirectory.OrderByDescending(x => x.Value))
            {
                sb.AppendLine($"  {kv.Key}: {kv.Value} 处");
            }
            sb.AppendLine();
        }

        if (results.Count > 0)
        {
            sb.AppendLine("--- 详细列表 ---");
            foreach (var r in results.Take(200)) // 限制输出数量
            {
                var relativePath = r.FilePath;
                sb.AppendLine($"  [{r.LineNumber}] {relativePath}");
                sb.AppendLine($"    文本: {r.Text}");
                sb.AppendLine($"    建议键: {r.SuggestedKey}");
                sb.AppendLine($"    代码: {r.LineContent}");
                sb.AppendLine();
            }

            if (results.Count > 200)
            {
                sb.AppendLine($"  ... 还有 {results.Count - 200} 条未显示");
            }
        }
        else
        {
            sb.AppendLine("✓ 未发现硬编码中文字符串！");
        }

        return sb.ToString();
    }

    /// <summary>
    /// 判断指定位置是否在字符串字面量内。
    /// </summary>
    private static bool IsInsideStringLiteral(string line, int index)
    {
        bool inString = false;
        bool inVerbatim = false;
        bool escaped = false;

        for (int i = 0; i < index && i < line.Length; i++)
        {
            var c = line[i];

            if (escaped)
            {
                escaped = false;
                continue;
            }

            if (c == '\\' && !inVerbatim)
            {
                escaped = true;
                continue;
            }

            if (c == '"')
            {
                if (!inString)
                {
                    inString = true;
                    inVerbatim = (i > 0 && line[i - 1] == '@');
                }
                else if (!inVerbatim)
                {
                    inString = false;
                }
                else if (i + 1 < line.Length && line[i + 1] == '"')
                {
                    i++; // 跳过转义的引号
                }
                else
                {
                    inString = false;
                    inVerbatim = false;
                }
            }
        }

        return inString;
    }

    /// <summary>
    /// 判断该行是否应该跳过。
    /// </summary>
    private static bool ShouldSkipLine(string line)
    {
        foreach (var pattern in SkipPatterns)
        {
            if (pattern.IsMatch(line))
                return true;
        }
        return false;
    }

    /// <summary>
    /// 根据硬编码文本和文件路径生成建议的 LangHelper 键。
    /// </summary>
    private static string GenerateSuggestedKey(string text, string filePath)
    {
        var fileName = Path.GetFileNameWithoutExtension(filePath).ToLowerInvariant();
        // 取文本前几个字符的拼音首字母（简化版：使用 hash）
        var hash = Math.Abs(text.GetHashCode() % 10000);
        return $"{fileName}.{hash}";
    }
}
