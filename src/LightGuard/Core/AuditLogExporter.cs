// © 2026 落尘（Luochen） 原创开发 - 保留所有权利

using System.Text;

namespace LightGuard.Core;

/// <summary>
/// 审计日志导出器
/// <para>支持导出 CSV / TXT 报表，并提供时间范围、级别、分类、关键词筛选与统计摘要。</para>
/// </summary>
public static class AuditLogExporter
{
    #region CSV 导出

    /// <summary>
    /// 将日志条目导出为 CSV 报表
    /// <para>列格式：时间,级别,分类,来源,用户,消息,详情</para>
    /// </summary>
    /// <param name="entries">要导出的日志条目列表</param>
    /// <param name="filePath">目标 CSV 文件路径</param>
    /// <returns>是否导出成功</returns>
    public static bool ExportToCsv(List<AuditLogEntry> entries, string filePath)
    {
        try
        {
            var sb = new StringBuilder();

            // UTF-8 BOM（Excel 兼容中文）
            sb.Append('\uFEFF');

            // 表头
            sb.AppendLine("时间,级别,分类,来源,用户,消息,详情");

            foreach (var e in entries)
            {
                sb.Append(EscapeCsvField(e.Timestamp.ToString("yyyy-MM-dd HH:mm:ss")));
                sb.Append(',');
                sb.Append(EscapeCsvField(e.Level.ToString()));
                sb.Append(',');
                sb.Append(EscapeCsvField(e.Category.ToString()));
                sb.Append(',');
                sb.Append(EscapeCsvField(e.Source));
                sb.Append(',');
                sb.Append(EscapeCsvField(e.UserName));
                sb.Append(',');
                sb.Append(EscapeCsvField(e.Message));
                sb.Append(',');
                sb.Append(EscapeCsvField(e.Details));
                sb.AppendLine();
            }

            File.WriteAllText(filePath, sb.ToString(), new UTF8Encoding(true));
            return true;
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, "导出 CSV 审计日志失败");
            return false;
        }
    }

    #endregion

    #region TXT 导出

    /// <summary>
    /// 将日志条目导出为 TXT 格式报表（可读性排版）
    /// </summary>
    /// <param name="entries">要导出的日志条目列表</param>
    /// <param name="filePath">目标 TXT 文件路径</param>
    /// <returns>是否导出成功</returns>
    public static bool ExportToTxt(List<AuditLogEntry> entries, string filePath)
    {
        try
        {
            var sb = new StringBuilder();

            sb.AppendLine("========================================");
            sb.AppendLine("        LightGuard 审计日志报表");
            sb.AppendLine("========================================");
            sb.AppendLine($"导出时间：{DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            sb.AppendLine($"条目总数：{entries.Count}");
            sb.AppendLine();

            foreach (var e in entries)
            {
                sb.AppendLine($"[{e.Timestamp:yyyy-MM-dd HH:mm:ss}] [{e.Level}] [{e.Category}]");
                if (!string.IsNullOrEmpty(e.Source))
                    sb.AppendLine($"  来源：{e.Source}");
                if (!string.IsNullOrEmpty(e.MachineName))
                    sb.AppendLine($"  机器：{e.MachineName}");
                if (!string.IsNullOrEmpty(e.UserName))
                    sb.AppendLine($"  用户：{e.UserName}");
                sb.AppendLine($"  消息：{e.Message}");
                if (!string.IsNullOrEmpty(e.Details))
                    sb.AppendLine($"  详情：{e.Details}");
                sb.AppendLine("----------------------------------------");
            }

            File.WriteAllText(filePath, sb.ToString(), new UTF8Encoding(true));
            return true;
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, "导出 TXT 审计日志失败");
            return false;
        }
    }

    #endregion

    #region 统计摘要

    /// <summary>
    /// 生成日志统计摘要
    /// <para>包含各级别数量、各分类数量、时间跨度等统计信息。</para>
    /// </summary>
    /// <param name="entries">要统计的日志条目列表</param>
    /// <returns>统计摘要文本</returns>
    public static string ExportSummary(List<AuditLogEntry> entries)
    {
        var sb = new StringBuilder();

        sb.AppendLine("========================================");
        sb.AppendLine("        LightGuard 审计日志统计摘要");
        sb.AppendLine("========================================");
        sb.AppendLine($"生成时间：{DateTime.Now:yyyy-MM-dd HH:mm:ss}");
        sb.AppendLine($"日志总条数：{entries.Count}");
        sb.AppendLine();

        // 时间跨度
        if (entries.Count > 0)
        {
            var earliest = entries.Min(e => e.Timestamp);
            var latest = entries.Max(e => e.Timestamp);
            sb.AppendLine($"最早记录：{earliest:yyyy-MM-dd HH:mm:ss}");
            sb.AppendLine($"最晚记录：{latest:yyyy-MM-dd HH:mm:ss}");
            sb.AppendLine($"时间跨度：{latest - earliest}");
        }
        sb.AppendLine();

        // 各级别统计
        sb.AppendLine("---- 各级别统计 ----");
        foreach (LogLevel level in Enum.GetValues(typeof(LogLevel)))
        {
            var count = entries.Count(e => e.Level == level);
            sb.AppendLine($"  {level,-10} : {count}");
        }
        sb.AppendLine();

        // 各分类统计
        sb.AppendLine("---- 各分类统计 ----");
        foreach (LogCategory cat in Enum.GetValues(typeof(LogCategory)))
        {
            var count = entries.Count(e => e.Category == cat);
            if (count > 0)
                sb.AppendLine($"  {cat,-20} : {count}");
        }
        sb.AppendLine();

        // 机器/用户统计
        var machines = entries.Select(e => e.MachineName).Where(m => !string.IsNullOrEmpty(m)).Distinct().ToList();
        var users = entries.Select(e => e.UserName).Where(u => !string.IsNullOrEmpty(u)).Distinct().ToList();
        if (machines.Count > 0)
        {
            sb.AppendLine($"涉及机器：{machines.Count} 台");
            foreach (var m in machines)
                sb.AppendLine($"  - {m}");
        }
        if (users.Count > 0)
        {
            sb.AppendLine($"涉及用户：{users.Count} 个");
            foreach (var u in users)
                sb.AppendLine($"  - {u}");
        }

        sb.AppendLine("========================================");
        return sb.ToString();
    }

    #endregion

    #region 筛选

    /// <summary>
    /// 按条件筛选日志条目
    /// </summary>
    /// <param name="entries">原始日志列表</param>
    /// <param name="startTime">起始时间（null 表示不限制）</param>
    /// <param name="endTime">结束时间（null 表示不限制）</param>
    /// <param name="level">日志级别筛选（null 表示不筛选）</param>
    /// <param name="category">日志分类筛选（null 表示不筛选）</param>
    /// <param name="keyword">关键词搜索（在消息和详情中搜索，null 表示不搜索）</param>
    /// <returns>筛选后的日志条目列表（按时间升序）</returns>
    public static List<AuditLogEntry> Filter(
        List<AuditLogEntry> entries,
        DateTime? startTime = null,
        DateTime? endTime = null,
        LogLevel? level = null,
        LogCategory? category = null,
        string? keyword = null)
    {
        var query = entries.AsEnumerable();

        if (startTime.HasValue)
            query = query.Where(e => e.Timestamp >= startTime.Value);
        if (endTime.HasValue)
            query = query.Where(e => e.Timestamp <= endTime.Value);
        if (level.HasValue)
            query = query.Where(e => e.Level == level.Value);
        if (category.HasValue)
            query = query.Where(e => e.Category == category.Value);
        if (!string.IsNullOrWhiteSpace(keyword))
        {
            var kw = keyword.Trim();
            query = query.Where(e =>
                e.Message.IndexOf(kw, StringComparison.OrdinalIgnoreCase) >= 0 ||
                e.Details.IndexOf(kw, StringComparison.OrdinalIgnoreCase) >= 0 ||
                e.Source.IndexOf(kw, StringComparison.OrdinalIgnoreCase) >= 0);
        }

        return query.OrderBy(e => e.Timestamp).ToList();
    }

    #endregion

    #region 辅助方法

    /// <summary>
    /// CSV 字段转义：包含逗号、引号、换行符的字段用双引号包裹，内部引号翻倍
    /// </summary>
    private static string EscapeCsvField(string field)
    {
        if (string.IsNullOrEmpty(field)) return string.Empty;

        bool needsQuoting = field.IndexOfAny(new[] { ',', '"', '\r', '\n' }) >= 0;
        if (!needsQuoting) return field;

        return $"\"{field.Replace("\"", "\"\"")}\"";
    }

    #endregion
}
