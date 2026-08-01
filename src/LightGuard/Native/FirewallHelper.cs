using System.Diagnostics;

namespace LightGuard.Native;

/// <summary>
/// Windows 防火墙操作助手
/// 使用 netsh 命令和 COM API 管理入站/出站规则
/// </summary>
public static class FirewallHelper
{
    /// <summary>
    /// 添加防火墙阻止规则
    /// </summary>
    public static bool AddBlockRule(string name, string programPath, bool inbound = true, bool outbound = true)
    {
        try
        {
            var directions = new List<string>();
            if (inbound) directions.Add("in");
            if (outbound) directions.Add("out");

            foreach (var dir in directions)
            {
                var args = $"advfirewall firewall add rule name=\"{name}_{dir}\" dir={dir} action=block program=\"{programPath}\" enable=yes";
                RunNetsh(args);
            }
            return true;
        }
        catch { return false; }
    }

    /// <summary>
    /// 删除防火墙规则
    /// </summary>
    public static bool RemoveRule(string name)
    {
        try
        {
            RunNetsh($"advfirewall firewall delete rule name=\"{name}\"");
            RunNetsh($"advfirewall firewall delete rule name=\"{name}_in\"");
            RunNetsh($"advfirewall firewall delete rule name=\"{name}_out\"");
            return true;
        }
        catch { return false; }
    }

    /// <summary>
    /// 阻止程序联网
    /// </summary>
    public static bool BlockProgram(string name, string programPath)
    {
        return AddBlockRule(name, programPath, true, true);
    }

    /// <summary>
    /// 解除程序联网阻止
    /// </summary>
    public static bool UnblockProgram(string name)
    {
        return RemoveRule(name);
    }

    /// <summary>
    /// 获取所有防火墙规则
    /// </summary>
    public static List<FirewallRule> GetAllRules()
    {
        var rules = new List<FirewallRule>();
        try
        {
            var output = RunNetsh("advfirewall firewall show rule name=all");
            var lines = output.Split('\n');
            FirewallRule? current = null;

            foreach (var line in lines)
            {
                var trimmed = line.Trim();
                if (trimmed.StartsWith("规则名称") || trimmed.StartsWith("Rule Name"))
                {
                    if (current != null) rules.Add(current);
                    current = new FirewallRule();
                    var colonIdx = trimmed.IndexOf(':');
                    current.Name = colonIdx >= 0 ? trimmed.Substring(colonIdx + 1).Trim() : trimmed;
                }
                else if (current != null)
                {
                    if (trimmed.StartsWith("已启用") || trimmed.StartsWith("Enabled"))
                        current.Enabled = trimmed.Contains("是") || trimmed.Contains("Yes");
                    else if (trimmed.StartsWith("方向") || trimmed.StartsWith("Direction"))
                        current.Direction = trimmed.Contains("入站") || trimmed.Contains("In") ? "Inbound" : "Outbound";
                    else if (trimmed.StartsWith("操作") || trimmed.StartsWith("Action"))
                        current.Action = trimmed.Contains("阻止") || trimmed.Contains("Block") ? "Block" : "Allow";
                    else if (trimmed.StartsWith("程序") || trimmed.StartsWith("Program"))
                    {
                        var colonIdx = trimmed.IndexOf(':');
                        current.Program = colonIdx >= 0 ? trimmed.Substring(colonIdx + 1).Trim() : "";
                    }
                }
            }
            if (current != null) rules.Add(current);
        }
        catch { }
        return rules;
    }

    /// <summary>
    /// 检查防火墙是否启用
    /// </summary>
    public static bool IsFirewallEnabled()
    {
        try
        {
            var output = RunNetsh("advfirewall show allprofiles state");
            return output.Contains("ON", StringComparison.OrdinalIgnoreCase);
        }
        catch { return false; }
    }

    /// <summary>
    /// 启用防火墙
    /// </summary>
    public static bool EnableFirewall()
    {
        try
        {
            RunNetsh("advfirewall set allprofiles state on");
            return true;
        }
        catch { return false; }
    }

    private static string RunNetsh(string args)
    {
        var psi = new ProcessStartInfo
        {
            FileName = "netsh.exe",
            Arguments = args,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            StandardOutputEncoding = System.Text.Encoding.Unicode
        };

        using var proc = Process.Start(psi);
        var output = proc?.StandardOutput.ReadToEnd() ?? "";
        proc?.WaitForExit(10000);
        return output;
    }
}

public sealed class FirewallRule
{
    public string Name { get; set; } = "";
    public bool Enabled { get; set; }
    public string Direction { get; set; } = "";
    public string Action { get; set; } = "";
    public string Program { get; set; } = "";
}
