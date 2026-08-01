using System.Text;

namespace LightGuard.Native;

/// <summary>
/// Hosts 文件操作助手
/// 用于全局广告域名屏蔽
/// </summary>
public static class HostsHelper
{
    private static readonly string HostsPath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.System),
        "drivers", "etc", "hosts");

    private const string LightGuardMarker = "# LightGuard AD Block";
    private const string LightGuardEndMarker = "# LightGuard AD Block End";

    /// <summary>
    /// 备份 Hosts 文件
    /// </summary>
    public static string Backup(string backupDir)
    {
        try
        {
            Directory.CreateDirectory(backupDir);
            var backupPath = Path.Combine(backupDir, $"hosts_{DateTime.Now:yyyyMMdd_HHmmss}.bak");
            File.Copy(HostsPath, backupPath, true);
            return backupPath;
        }
        catch { return ""; }
    }

    /// <summary>
    /// 添加广告域名屏蔽规则
    /// </summary>
    public static bool AddAdBlockRules(IEnumerable<string> domains)
    {
        try
        {
            var content = File.ReadAllText(HostsPath);

            // 先移除旧的 LightGuard 规则
            content = RemoveLightGuardSection(content);

            // 添加新规则
            var sb = new StringBuilder(content);
            sb.AppendLine();
            sb.AppendLine(LightGuardMarker);
            foreach (var domain in domains.Distinct())
            {
                sb.AppendLine($"0.0.0.0 {domain}");
            }
            sb.AppendLine(LightGuardEndMarker);

            File.WriteAllText(HostsPath, sb.ToString());
            return true;
        }
        catch { return false; }
    }

    /// <summary>
    /// 移除 LightGuard 添加的所有广告屏蔽规则
    /// </summary>
    public static bool RemoveAdBlockRules()
    {
        try
        {
            var content = File.ReadAllText(HostsPath);
            content = RemoveLightGuardSection(content);
            File.WriteAllText(HostsPath, content);
            return true;
        }
        catch { return false; }
    }

    /// <summary>
    /// 从 Hosts 还原
    /// </summary>
    public static bool Restore(string backupPath)
    {
        try
        {
            if (File.Exists(backupPath))
            {
                File.Copy(backupPath, HostsPath, true);
                return true;
            }
            return false;
        }
        catch { return false; }
    }

    /// <summary>
    /// 获取当前被屏蔽的域名列表
    /// </summary>
    public static List<string> GetBlockedDomains()
    {
        var list = new List<string>();
        try
        {
            var lines = File.ReadAllLines(HostsPath);
            var inSection = false;

            foreach (var line in lines)
            {
                if (line.Trim() == LightGuardMarker) { inSection = true; continue; }
                if (line.Trim() == LightGuardEndMarker) { inSection = false; continue; }
                if (!inSection) continue;

                var trimmed = line.Trim();
                if (string.IsNullOrEmpty(trimmed) || trimmed.StartsWith("#")) continue;

                var parts = trimmed.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length >= 2 && parts[0] == "0.0.0.0")
                    list.Add(parts[1]);
            }
        }
        catch { }
        return list;
    }

    private static string RemoveLightGuardSection(string content)
    {
        var startIdx = content.IndexOf(LightGuardMarker);
        if (startIdx < 0) return content;

        var endIdx = content.IndexOf(LightGuardEndMarker, startIdx);
        if (endIdx < 0) return content;

        var endPos = endIdx + LightGuardEndMarker.Length;
        // 移除到行尾
        while (endPos < content.Length && content[endPos] != '\n') endPos++;
        if (endPos < content.Length) endPos++; // 跳过换行

        return content.Remove(startIdx, endPos - startIdx);
    }

    /// <summary>
    /// 常见广告/追踪域名库
    /// </summary>
    public static readonly string[] CommonAdDomains = new[]
    {
        // 广告联盟
        "pagead2.googlesyndication.com",
        "googleads.g.doubleclick.net",
        "ad.thsi.cn",
        "adsclick.cn",
        "dianru.com",
        "domob.cn",
        // WPS 广告
        "ad.wpscdn.cn",
        "news.wpscdn.cn",
        "docer.com",
        // 360 广告
        "hao.360.cn",
        "huabaner.com",
        "kan.diao.com",
        // 2345 广告
        "2345.com",
        "dh.restul.com",
        // 遥测
        "vortex.data.microsoft.com",
        "telemetry.microsoft.com",
        "settings-win.data.microsoft.com",
    };
}
