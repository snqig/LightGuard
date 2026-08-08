// © 2026 落尘（Luochen） 原创开发 - 保留所有权利
//
// 运行时密码凭据存储（v3.5 P2 密码策略）
//   - 密码仅存在于内存，不落盘（配置仅存 CredentialRef + 盐）
//   - 定时任务 / 手动备份从本存储取派生密钥，任务结束可主动清除
//   - 未录入凭据时使用内置默认口令（本地加密备份的兜底，不依赖交互）

using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;

namespace LightGuard.Backup;

/// <summary>
/// 备份密码凭据运行时存储。
/// <para>凭据值经 HKDF 派生后以十六进制口令形式使用（供 BackupExecutor / 备份容器解密）。</para>
/// <para>本存储仅驻留内存；进程退出即清空。</para>
/// </summary>
public static class BackupCredentialStore
{
    /// <summary>默认口令：本地加密备份的兜底口令（不依赖交互输入）。</summary>
    public const string DefaultPassword = "lightguard-local-backup-v3";

    private static readonly ConcurrentDictionary<string, string> Credentials = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// 注册运行时密码并派生密钥口令。
    /// </summary>
    /// <param name="credentialRef">凭据 ID（与配置 CredentialRef/PasswordRef 对应）。</param>
    /// <param name="password">明文密码（函数内立即派生并清零）。</param>
    /// <param name="saltBase64">持久化盐（Base64，从配置读取）。</param>
    public static void Register(string credentialRef, string password, string? saltBase64)
    {
        if (string.IsNullOrWhiteSpace(credentialRef)) return;
        var salt = string.IsNullOrEmpty(saltBase64)
            ? KeyDerivation.NewSalt()
            : KeyDerivation.SaltFromBase64(saltBase64);

        var key = KeyDerivation.DeriveKey(password, salt, credentialRef);
        try
        {
            Credentials[credentialRef] = Convert.ToHexString(key).ToLowerInvariant();
        }
        finally
        {
            KeyDerivation.ZeroMemory(key);
        }
    }

    /// <summary>获取凭据派生口令；未注册返回 null。</summary>
    public static string? Get(string? credentialRef)
        => string.IsNullOrWhiteSpace(credentialRef) ? null
           : Credentials.TryGetValue(credentialRef, out var v) ? v : null;

    /// <summary>是否已注册指定凭据。</summary>
    public static bool Has(string? credentialRef)
        => !string.IsNullOrWhiteSpace(credentialRef) && Credentials.ContainsKey(credentialRef);

    /// <summary>清除指定凭据（任务结束调用）。</summary>
    public static void Clear(string? credentialRef)
    {
        if (string.IsNullOrWhiteSpace(credentialRef)) return;
        Credentials.TryRemove(credentialRef, out _);
    }

    /// <summary>清除全部凭据（退出/安全事件）。</summary>
    public static void ClearAll() => Credentials.Clear();

    /// <summary>已注册的凭据 ID 列表。</summary>
    public static IReadOnlyCollection<string> RegisteredRefs => Credentials.Keys.ToList();
}
