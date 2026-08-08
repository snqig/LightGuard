// © 2026 落尘（Luochen） 原创开发 - 保留所有权利

using System.Text.Json;
using LightGuard.Modules;

namespace LightGuard.Core;

/// <summary>
/// 告警通知配置（P1-2 SMB 审计改进：风险事件告警通道）。
/// </summary>
public sealed class AlertConfig
{
    /// <summary>是否启用告警通知（本地日志始终记录，此开关控制 Webhook 外发）。</summary>
    public bool Enabled { get; set; } = true;

    /// <summary>钉钉群机器人 Webhook 地址（留空不发送）。</summary>
    public string DingTalkWebhook { get; set; } = "";

    /// <summary>企业微信群机器人 Webhook 地址（留空不发送）。</summary>
    public string WeComWebhook { get; set; } = "";

    /// <summary>仅对 Critical（严重）等级告警外发（默认 false = 高及以下也外发）。</summary>
    public bool AlertOnCriticalOnly { get; set; }

    /// <summary>告警文本前缀（用于区分来源/环境，如服务器名）。</summary>
    public string TitlePrefix { get; set; } = "LightGuard";
}

/// <summary>
/// 风险事件告警通知器（P1-2）。
/// <para>本地日志始终记录；Webhook（钉钉/企微群机器人）按配置外发，失败静默不影响主流程。</para>
/// <para>风险事件触发：批量外泄 / 权限篡改 / 高频删除 / 凌晨访问 / 备份目录异常访问。</para>
/// </summary>
public static class AlertNotifier
{
    private static readonly HttpClient Http = CreateHttpClient();

    private static HttpClient CreateHttpClient()
    {
        var client = new HttpClient { Timeout = TimeSpan.FromSeconds(10) };
        client.DefaultRequestHeaders.Add("User-Agent", "LightGuard");
        return client;
    }

    /// <summary>
    /// 发送风险告警（异步；Webhook 失败静默）。
    /// </summary>
    /// <param name="title">告警标题</param>
    /// <param name="message">告警内容</param>
    /// <param name="severity">风险等级</param>
    public static async Task NotifyAsync(string title, string message, RiskLevel severity)
    {
        try
        {
            // 1. 本地日志（始终记录，供审计留痕）
            ErrorReporter.Log(
                $"[告警:{severity}] {title} - {message}",
                severity >= RiskLevel.High ? "ERROR" : "WARN");

            // 2. Webhook 外发（按配置）
            var cfg = GetConfig();
            if (cfg == null || !cfg.Enabled) return;
            if (cfg.AlertOnCriticalOnly && severity < RiskLevel.Critical) return;

            var text = FormatMessage(cfg, title, message, severity);
            var tasks = new List<Task>();
            if (!string.IsNullOrWhiteSpace(cfg.DingTalkWebhook))
                tasks.Add(SendWebhookAsync(cfg.DingTalkWebhook, text, "钉钉"));
            if (!string.IsNullOrWhiteSpace(cfg.WeComWebhook))
                tasks.Add(SendWebhookAsync(cfg.WeComWebhook, text, "企业微信"));

            if (tasks.Count > 0)
                await Task.WhenAll(tasks).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, "风险告警通知异常（不影响主流程）");
        }
    }

    /// <summary>
    /// 发送到钉钉 / 企业微信群机器人（两者均为 text 消息格式，失败静默）。
    /// </summary>
    private static async Task SendWebhookAsync(string webhook, string text, string channel)
    {
        try
        {
            var payload = JsonSerializer.Serialize(new
            {
                msgtype = "text",
                text = new { content = text }
            });
            using var content = new StringContent(payload, System.Text.Encoding.UTF8, "application/json");
            using var resp = await Http.PostAsync(webhook, content).ConfigureAwait(false);
            if (!resp.IsSuccessStatusCode)
                ErrorReporter.Log($"[告警通知] {channel} Webhook 发送失败: HTTP {(int)resp.StatusCode}", "WARN");
        }
        catch (Exception ex)
        {
            ErrorReporter.Log($"[告警通知] {channel} Webhook 发送异常: {ex.Message}", "WARN");
        }
    }

    /// <summary>组装告警文本。</summary>
    private static string FormatMessage(AlertConfig cfg, string title, string message, RiskLevel severity)
    {
        var prefix = string.IsNullOrWhiteSpace(cfg.TitlePrefix) ? "LightGuard" : cfg.TitlePrefix;
        return $"[{prefix}] 风险告警（{severity}）\n{title}\n{message}\n时间：{DateTime.Now:yyyy-MM-dd HH:mm:ss}";
    }

    /// <summary>读取告警配置（AppState 未初始化时返回默认）。</summary>
    private static AlertConfig? GetConfig()
    {
        try { return AppState.Instance.Config.Alert; }
        catch { return null; }
    }
}
