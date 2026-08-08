// © 2026 落尘（Luochen） 原创开发 - 保留所有权利
//
// 授权模块联动门禁（v3.5 P0-3）
//   - 未授权状态：加密备份、定时任务、实时备份、数据库全部功能禁用
//   - 即使 ini/json 配置开启也不会执行（调度/实时/手动入口统一走本门禁）
//   - 授权状态持久化于 AppConfig.License 节（License.activated）

using System.Text.Json;

namespace LightGuard.Core;

/// <summary>
/// 授权状态配置（AppConfig.License）。
/// </summary>
public sealed class LicenseConfig
{
    /// <summary>是否已授权激活。</summary>
    public bool Activated { get; set; }

    /// <summary>授权到期时间（null = 永久）。</summary>
    public DateTime? ExpiresAt { get; set; }

    /// <summary>授权方式描述（如 离线密钥/在线激活）。</summary>
    public string Method { get; set; } = "";

    /// <summary>激活码哈希（SHA256，不存明文激活码）。</summary>
    public string KeyHash { get; set; } = "";
}

/// <summary>
/// 授权门禁：未授权时禁用备份相关全部能力。
/// <para>与 AppConfig 解耦：通过 <see cref="SetConfigProvider"/> 注入配置读取器，避免静态依赖顺序问题。</para>
/// </summary>
public static class LicenseGuard
{
    private static Func<LicenseConfig>? _configProvider;

    /// <summary>注入授权配置读取器（AppState 初始化后调用一次）。</summary>
    public static void SetConfigProvider(Func<LicenseConfig> provider)
        => _configProvider = provider ?? throw new ArgumentNullException(nameof(provider));

    private static LicenseConfig GetConfig()
    {
        try { return _configProvider?.Invoke() ?? new LicenseConfig(); }
        catch { return new LicenseConfig(); }
    }

    /// <summary>是否已授权（含到期校验）。</summary>
    public static bool IsActivated
    {
        get
        {
            var cfg = GetConfig();
            if (!cfg.Activated) return false;
            if (cfg.ExpiresAt.HasValue && cfg.ExpiresAt.Value < DateTime.Now) return false;
            return true;
        }
    }

    /// <summary>
    /// 备份能力总门禁：未授权时加密备份/定时任务/实时备份/数据库全部禁用。
    /// </summary>
    public static bool IsBackupEnabled() => IsActivated;

    /// <summary>校验激活码格式与授权（供激活入口调用；此处仅校验哈希一致）。</summary>
    public static bool ValidateKey(string activationKey, string storedKeyHash)
    {
        if (string.IsNullOrEmpty(activationKey) || string.IsNullOrEmpty(storedKeyHash))
            return false;
        var hash = System.Security.Cryptography.SHA256.HashData(
            System.Text.Encoding.UTF8.GetBytes(activationKey.Trim()));
        var hashHex = Convert.ToHexString(hash).ToLowerInvariant();
        return string.Equals(hashHex, storedKeyHash, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>计算激活码 SHA256 哈希（激活时落盘用）。</summary>
    public static string HashKey(string activationKey)
    {
        var hash = System.Security.Cryptography.SHA256.HashData(
            System.Text.Encoding.UTF8.GetBytes(activationKey.Trim()));
        return Convert.ToHexString(hash).ToLowerInvariant();
    }
}
