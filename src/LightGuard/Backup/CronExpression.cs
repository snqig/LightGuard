// © 2026 落尘（Luochen） 原创开发 - 保留所有权利
//
// 轻量 5 段 Cron 表达式解析/匹配器（v3.5 P0-1）
//   - 字段顺序：分 时 日 月 周
//   - 支持语法：* / */n / a,b / a-b / a-b/n
//   - 提供快捷周期预设（FromPreset），普通用户无需手写 cron

using System.Globalization;

namespace LightGuard.Backup;

/// <summary>快捷周期预设（映射为 cron，供 dbconfig / 配置界面使用）</summary>
public enum CronPreset
{
    /// <summary>禁用定时</summary>
    Disabled,

    /// <summary>每天（每日 02:00）</summary>
    Daily,

    /// <summary>每周（每周日 02:00）</summary>
    Weekly,

    /// <summary>每 2 小时</summary>
    Every2Hours,

    /// <summary>每 6 小时</summary>
    Every6Hours,

    /// <summary>每 12 小时</summary>
    Every12Hours
}

/// <summary>
/// 轻量 5 段 Cron 表达式（分 时 日 月 周）。
/// <para>不依赖第三方库，支持 * 、*/n 、a,b 、a-b 、a-b/n 语法。</para>
/// </summary>
public sealed class CronExpression
{
    private readonly HashSet<int> _minutes = new();
    private readonly HashSet<int> _hours = new();
    private readonly HashSet<int> _daysOfMonth = new();
    private readonly HashSet<int> _months = new();
    private readonly HashSet<int> _daysOfWeek = new();
    private readonly string _raw;

    /// <summary>原始表达式文本。</summary>
    public string Raw => _raw;

    private CronExpression(string raw)
    {
        _raw = raw;
    }

    /// <summary>
    /// 解析 5 段 cron 表达式。
    /// </summary>
    /// <param name="expr">如 "0 2 * * *"（每 2:00）</param>
    /// <returns>解析后的表达式；空串或无效表达式抛出 <see cref="FormatException"/>。</returns>
    public static CronExpression Parse(string expr)
    {
        if (string.IsNullOrWhiteSpace(expr))
            throw new FormatException("cron 表达式为空。");

        var fields = expr.Trim().Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (fields.Length != 5)
            throw new FormatException($"cron 表达式必须为 5 段（分 时 日 月 周），实际 {fields.Length} 段：{expr}");

        var result = new CronExpression(expr);
        result._minutes.UnionWith(ParseField(fields[0], 0, 59, "分"));
        result._hours.UnionWith(ParseField(fields[1], 0, 23, "时"));
        result._daysOfMonth.UnionWith(ParseField(fields[2], 1, 31, "日"));
        result._months.UnionWith(ParseField(fields[3], 1, 12, "月"));
        result._daysOfWeek.UnionWith(ParseField(fields[4], 0, 7, "周")); // 0=周日, 7=周日
        return result;
    }

    /// <summary>
    /// 解析单个字段（支持 * 、*/n 、a,b 、a-b 、a-b/n）。
    /// </summary>
    private static HashSet<int> ParseField(string field, int min, int max, string name)
    {
        var result = new HashSet<int>();
        foreach (var part in field.Split(',', StringSplitOptions.RemoveEmptyEntries))
        {
            var step = 1;
            var rangePart = part;
            var slashIdx = part.IndexOf('/');
            if (slashIdx >= 0)
            {
                rangePart = part[..slashIdx];
                if (!int.TryParse(part[(slashIdx + 1)..], out step) || step <= 0)
                    throw new FormatException($"cron 步长无效：{part}（{name}）");
            }

            int start, end;
            if (rangePart == "*")
            {
                start = min;
                end = max;
            }
            else
            {
                var dashIdx = rangePart.IndexOf('-');
                if (dashIdx > 0)
                {
                    if (!int.TryParse(rangePart[..dashIdx], out start) ||
                        !int.TryParse(rangePart[(dashIdx + 1)..], out end))
                        throw new FormatException($"cron 范围无效：{rangePart}（{name}）");
                }
                else
                {
                    if (!int.TryParse(rangePart, out start))
                        throw new FormatException($"cron 数值无效：{rangePart}（{name}）");
                    end = start;
                }
            }

            for (var v = start; v <= end; v += step)
            {
                if (v >= min && v <= max)
                    result.Add(v);
            }
        }
        return result;
    }

    /// <summary>
    /// 判断当前时刻是否命中（分钟级）。
    /// <para>周字段与日字段按"或"语义匹配（与标准 cron 一致）。</para>
    /// </summary>
    public bool IsMatch(DateTime now)
    {
        // 周字段 7 归一为 0（周日）
        var dow = (int)now.DayOfWeek % 7;

        var dayMatches = _daysOfMonth.Contains(now.Day);
        var dowMatches = _daysOfWeek.Contains(dow) || _daysOfWeek.Contains(7);

        // 日/周都为 * 时只看月份；否则任一匹配即可（标准 cron 语义）
        var dayOk = (_daysOfMonth.Count == 0 || dayMatches) && (_daysOfWeek.Count == 0 || dowMatches);
        if (_daysOfMonth.Count == 31 && _daysOfWeek.Count == 8)
            dayOk = true;

        return _minutes.Contains(now.Minute)
            && _hours.Contains(now.Hour)
            && _months.Contains(now.Month)
            && dayOk;
    }

    /// <summary>
    /// 判断是否命中且当日尚未执行过（供定时调度去重：同一任务一天只跑一次）。
    /// </summary>
    /// <param name="now">当前时间</param>
    /// <param name="lastRun">上次执行时间（null 表示从未执行）</param>
    public bool IsDue(DateTime now, DateTime? lastRun)
    {
        if (!IsMatch(now)) return false;
        // 上次执行与当前在同一"日"（按分钟判断，避免跨小时重复触发）则跳过
        return !lastRun.HasValue || lastRun.Value.Date != now.Date || lastRun.Value.Hour != now.Hour || lastRun.Value.Minute != now.Minute;
    }

    /// <summary>
    /// 快捷周期预设 → cron 表达式。
    /// </summary>
    public static string FromPreset(CronPreset preset) => preset switch
    {
        CronPreset.Daily => "0 2 * * *",
        CronPreset.Weekly => "0 2 * * 0",
        CronPreset.Every2Hours => "0 */2 * * *",
        CronPreset.Every6Hours => "0 */6 * * *",
        CronPreset.Every12Hours => "0 */12 * * *",
        _ => ""
    };

    /// <summary>快捷预设 → 可读描述（dbconfig 展示用）。</summary>
    public static string DescribePreset(CronPreset preset) => preset switch
    {
        CronPreset.Daily => "每天 02:00",
        CronPreset.Weekly => "每周日 02:00",
        CronPreset.Every2Hours => "每 2 小时",
        CronPreset.Every6Hours => "每 6 小时",
        CronPreset.Every12Hours => "每 12 小时",
        _ => "禁用"
    };

    /// <summary>将 cron 表达式转回快捷预设（匹配则返回对应预设，否则 Disabled）。</summary>
    public static CronPreset ToPreset(string cron)
    {
        if (string.IsNullOrWhiteSpace(cron)) return CronPreset.Disabled;
        foreach (CronPreset p in Enum.GetValues<CronPreset>())
        {
            if (p == CronPreset.Disabled) continue;
            if (string.Equals(FromPreset(p), cron.Trim(), StringComparison.OrdinalIgnoreCase))
                return p;
        }
        return CronPreset.Disabled;
    }
}
