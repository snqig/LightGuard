// © 2026 落尘（Luochen） 原创开发 - 保留所有权利

using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using LightGuard.Core;

namespace LightGuard.Backup;

/// <summary>
/// 备份加密引擎 - 提供抗勒索加密与密钥派生能力。
/// <para>默认使用 AES-256-GCM（加密 + 完整性校验，防篡改、防勒索二次加密）。</para>
/// <para>ARM64 或低配设备自动切换为 ChaCha20-Poly1305（无硬件加速时性能更优）。</para>
/// <para>密钥派生：PBKDF2-HMAC-SHA256，10 万次迭代 + 32 字节随机盐，抵御彩虹表。</para>
/// </summary>
public sealed class BackupCryptoEngine
{
    /// <summary>对称密钥长度（字节），对应 AES-256 / ChaCha20 的 256 位密钥。</summary>
    public const int KeySize = 32;

    /// <summary>PBKDF2 随机盐长度（字节）。</summary>
    public const int SaltSize = 32;

    /// <summary>GCM / Poly1305 随机 nonce 长度（字节）。</summary>
    public const int NonceSize = 12;

    /// <summary>GCM / Poly1305 认证标签长度（字节）。</summary>
    public const int TagSize = 16;

    /// <summary>PBKDF2-HMAC-SHA256 迭代次数（10 万次）。</summary>
    public const int Pbkdf2Iterations = 100_000;

    private readonly bool _useChaCha;

    /// <summary>
    /// 初始化加密引擎并自动选择算法。
    /// </summary>
    /// <param name="hardware">硬件档案；为 null 时按当前环境启发式检测。</param>
    public BackupCryptoEngine(HardwareProfile? hardware = null)
    {
        IsArm64 = hardware?.IsArm64 ?? (RuntimeInformation.ProcessArchitecture == Architecture.Arm64);
        IsLowEndDevice = hardware != null
            ? !hardware.IsHighEnd
            : DetectLowEndDevice();
        _useChaCha = IsArm64 || IsLowEndDevice;
    }

    /// <summary>
    /// 初始化加密引擎并强制使用指定算法（用于恢复时匹配备份清单记录的算法）。
    /// </summary>
    /// <param name="algorithmName">算法名称："AES-256-GCM" 或 "ChaCha20-Poly1305"。</param>
    public BackupCryptoEngine(string algorithmName)
    {
        _useChaCha = string.Equals(algorithmName, "ChaCha20-Poly1305", StringComparison.OrdinalIgnoreCase);
        IsArm64 = false;
        IsLowEndDevice = false;
    }

    /// <summary>是否为 ARM64 架构。</summary>
    public bool IsArm64 { get; }

    /// <summary>是否为低配设备（自动选择算法的依据之一）。</summary>
    public bool IsLowEndDevice { get; }

    /// <summary>当前使用的加密算法名称。</summary>
    public string AlgorithmName => _useChaCha ? "ChaCha20-Poly1305" : "AES-256-GCM";

    /// <summary>当前是否使用 ChaCha20-Poly1305。</summary>
    public bool UseChaCha20Poly1305 => _useChaCha;

    /// <summary>
    /// 生成 32 字节密码学安全随机盐。
    /// </summary>
    /// <returns>32 字节随机盐。</returns>
    public byte[] GenerateSalt() => RandomNumberGenerator.GetBytes(SaltSize);

    /// <summary>
    /// 使用 PBKDF2-HMAC-SHA256（10 万次迭代）从口令派生 32 字节密钥。
    /// </summary>
    /// <param name="password">用户口令。</param>
    /// <param name="salt">随机盐（建议 32 字节）。</param>
    /// <returns>32 字节派生密钥。</returns>
    public byte[] DeriveKey(string password, byte[] salt)
    {
        ArgumentNullException.ThrowIfNull(password);
        ArgumentNullException.ThrowIfNull(salt);

        var passwordBytes = Encoding.UTF8.GetBytes(password);
        using var pbkdf2 = new Rfc2898DeriveBytes(passwordBytes, salt, Pbkdf2Iterations, HashAlgorithmName.SHA256);
        return pbkdf2.GetBytes(KeySize);
    }

    /// <summary>
    /// 加密明文字节，返回密文及随机 nonce 与认证标签。
    /// </summary>
    /// <param name="plainBytes">明文字节。</param>
    /// <param name="key">32 字节密钥。</param>
    /// <returns>(密文, nonce, 认证标签)。</returns>
    public (byte[] CipherBytes, byte[] Nonce, byte[] Tag) Encrypt(byte[] plainBytes, byte[] key)
    {
        ArgumentNullException.ThrowIfNull(plainBytes);
        ArgumentNullException.ThrowIfNull(key);
        if (key.Length != KeySize)
            throw new ArgumentException($"密钥长度必须为 {KeySize} 字节。", nameof(key));

        var nonce = RandomNumberGenerator.GetBytes(NonceSize);
        var tag = new byte[TagSize];
        var cipher = new byte[plainBytes.Length];

        if (_useChaCha)
        {
            using var chacha = new ChaCha20Poly1305(key);
            chacha.Encrypt(nonce, plainBytes, cipher, tag);
        }
        else
        {
            using var aes = new AesGcm(key, TagSize);
            aes.Encrypt(nonce, plainBytes, cipher, tag);
        }

        return (cipher, nonce, tag);
    }

    /// <summary>
    /// 解密密文。认证标签校验失败时抛出 <see cref="AuthenticationTagMismatchException"/>（GCM 完整性校验失败）。
    /// </summary>
    /// <param name="cipherBytes">密文字节。</param>
    /// <param name="key">32 字节密钥。</param>
    /// <param name="nonce">加密时使用的 nonce。</param>
    /// <param name="tag">认证标签。</param>
    /// <returns>明文字节。</returns>
    /// <exception cref="AuthenticationTagMismatchException">GCM/Poly1305 认证标签校验失败（数据被篡改或密钥错误）。</exception>
    public byte[] Decrypt(byte[] cipherBytes, byte[] key, byte[] nonce, byte[] tag)
    {
        ArgumentNullException.ThrowIfNull(cipherBytes);
        ArgumentNullException.ThrowIfNull(key);
        ArgumentNullException.ThrowIfNull(nonce);
        ArgumentNullException.ThrowIfNull(tag);
        if (key.Length != KeySize)
            throw new ArgumentException($"密钥长度必须为 {KeySize} 字节。", nameof(key));
        if (nonce.Length != NonceSize)
            throw new ArgumentException($"nonce 长度必须为 {NonceSize} 字节。", nameof(nonce));
        if (tag.Length != TagSize)
            throw new ArgumentException($"认证标签长度必须为 {TagSize} 字节。", nameof(tag));

        var plain = new byte[cipherBytes.Length];

        if (_useChaCha)
        {
            using var chacha = new ChaCha20Poly1305(key);
            chacha.Decrypt(nonce, cipherBytes, tag, plain);
        }
        else
        {
            using var aes = new AesGcm(key, TagSize);
            aes.Decrypt(nonce, cipherBytes, tag, plain);
        }

        return plain;
    }

    /// <summary>
    /// 启发式检测当前是否为低配设备（无硬件档案时使用）。
    /// 规则：可用内存 &lt; 2GB 或 逻辑核心数 &lt; 4 视为低配。
    /// </summary>
    private static bool DetectLowEndDevice()
    {
        try
        {
            var availMb = HardwareDetector.GetAvailableMemoryMb();
            if (availMb > 0 && availMb < 2048) return true;
        }
        catch { }
        return Environment.ProcessorCount < 4;
    }
}
