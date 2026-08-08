// © 2026 落尘（Luochen） 原创开发 - 保留所有权利
//
// 密码派生与内存密钥管理（v3.5 P2-3）
//   - HKDF-SHA256 从用户密码派生 AES-256 备份密钥（不落盘明文密码）
//   - 每次配置保存生成独立随机盐（盐可落盘，密钥不可）
//   - 任务结束 ZeroMemory 清空内存中的密钥

using System.Security.Cryptography;
using System.Text;

namespace LightGuard.Backup;

/// <summary>
/// 密码派生工具：HKDF-SHA256 派生备份密钥 + 内存密钥零化。
/// <para>密码仅运行时交互输入，经 HKDF 与随机盐派生 AES-256 密钥；</para>
/// <para>配置仅保存盐与凭据引用，不保存明文密码。</para>
/// </summary>
public static class KeyDerivation
{
    /// <summary>派生密钥长度（AES-256）</summary>
    public const int KeySizeBytes = 32;

    /// <summary>盐长度（字节）</summary>
    public const int SaltSizeBytes = 16;

    /// <summary>
    /// 使用 HKDF-SHA256 从密码派生密钥。
    /// </summary>
    /// <param name="password">用户密码（仅运行时存在）。</param>
    /// <param name="salt">随机盐（可持久化）。</param>
    /// <param name="info">上下文信息（如凭据名），增强多实例隔离。</param>
    /// <param name="keySize">派生密钥长度，默认 32 字节（AES-256）。</param>
    /// <returns>派生密钥字节数组。</returns>
    public static byte[] DeriveKey(string password, byte[] salt, string? info = null, int keySize = KeySizeBytes)
    {
        ArgumentNullException.ThrowIfNull(password);
        ArgumentNullException.ThrowIfNull(salt);

        var pwdBytes = Encoding.UTF8.GetBytes(password);
        try
        {
            var infoBytes = string.IsNullOrEmpty(info) ? Array.Empty<byte>() : Encoding.UTF8.GetBytes(info);
            return HKDF.DeriveKey(
                HashAlgorithmName.SHA256,
                ikm: pwdBytes,
                outputLength: keySize,
                salt: salt,
                info: infoBytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(pwdBytes);
        }
    }

    /// <summary>生成随机盐。</summary>
    public static byte[] NewSalt(int size = SaltSizeBytes) => RandomNumberGenerator.GetBytes(size);

    /// <summary>盐转 Base64（持久化到配置）。</summary>
    public static string SaltToBase64(byte[] salt) => Convert.ToBase64String(salt);

    /// <summary>从 Base64 还原盐。</summary>
    public static byte[] SaltFromBase64(string saltBase64)
        => string.IsNullOrEmpty(saltBase64) ? Array.Empty<byte>() : Convert.FromBase64String(saltBase64);

    /// <summary>安全清空内存中的密钥/密码字节。</summary>
    public static void ZeroMemory(byte[]? key)
    {
        if (key is { Length: > 0 })
            CryptographicOperations.ZeroMemory(key);
    }

    /// <summary>安全清空内存中的密钥/密码字符串（不可变字符串仅尽力而为）。</summary>
    public static void ZeroMemoryString(string? value)
    {
        // string 不可变，此方法仅为 API 语义占位；实际密码应尽快脱离托管字符串
        _ = value;
    }
}
