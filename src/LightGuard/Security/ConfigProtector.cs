// © 2026 落尘（Luochen）原创开发 - 保留所有权利

using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using LightGuard.Core;
using LightGuard.Native;

namespace LightGuard.Security;

/// <summary>
/// 配置加密结果枚举
/// </summary>
public enum ConfigEncryptionResult
{
    /// <summary>加密成功，敏感字段已保护</summary>
    Success,

    /// <summary>所有敏感字段均已加密，无需重复操作</summary>
    AlreadyEncrypted,

    /// <summary>未发现需要加密的敏感字段</summary>
    NoSensitiveFields,

    /// <summary>部分字段加密失败</summary>
    PartialFailure,

    /// <summary>加密完全失败</summary>
    Failed
}

/// <summary>
/// 配置保护器 — 对敏感配置字段与配置文件进行多层加密保护。
/// <para>保护层次：</para>
/// <para>1. 字段级：使用 DPAPI（CurrentUser 作用域）加密敏感字段（WebDavPassword、NasPath 等），</para>
/// <para>   序列化前加密、反序列化后解密，密文以 "DPAPI:" 前缀 + Base64 标记存储。</para>
/// <para>2. 文件级：使用 AES-256-GCM 加密配置完整副本（config.json.protected），</para>
/// <para>   AES 密钥由 DPAPI 保护后存储在 config.key 文件中，严禁硬编码任何密钥。</para>
/// <para>3. 目录级：对 %APPDATA%\LightGuard\ 设置 NTFS 权限，仅允许当前用户与 SYSTEM 完全控制。</para>
/// </summary>
public sealed class ConfigProtector
{
    #region 常量

    /// <summary>AES-256 密钥长度（字节）</summary>
    private const int AesKeySize = 32;

    /// <summary>GCM Nonce 长度（字节）</summary>
    private const int NonceSize = 12;

    /// <summary>GCM 认证标签长度（字节）</summary>
    private const int TagSize = 16;

    /// <summary>AES-256-GCM 加密的配置完整副本文件名</summary>
    private const string ProtectedConfigFile = "config.json.protected";

    /// <summary>DPAPI 保护的 AES 密钥文件名</summary>
    private const string KeyFile = "config.key";

    /// <summary>已加密字段的标记前缀（Base64 密文紧随其后）</summary>
    private const string EncryptedFieldPrefix = "DPAPI:";

    #endregion

    #region 字段

    private static readonly object KeyLock = new();

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    #endregion

    #region DPAPI 敏感字段加密 / 解密

    /// <summary>
    /// 使用 DPAPI（CurrentUser 作用域）加密敏感字段明文，返回密文字节。
    /// <para>DPAPI 密钥由 Windows 操作系统基于当前用户凭据派生，不随软件分发，无需硬编码。</para>
    /// </summary>
    /// <param name="plaintext">敏感字段明文。</param>
    /// <returns>DPAPI 加密后的密文字节；明文为空时返回空数组。</returns>
    public byte[] EncryptSensitiveField(string plaintext)
    {
        if (string.IsNullOrEmpty(plaintext))
            return Array.Empty<byte>();

        var plainBytes = Encoding.UTF8.GetBytes(plaintext);
        return ProtectedData.Protect(plainBytes, null, DataProtectionScope.CurrentUser);
    }

    /// <summary>
    /// 使用 DPAPI（CurrentUser 作用域）解密敏感字段密文，返回明文字符串。
    /// </summary>
    /// <param name="cipher">DPAPI 加密的密文字节。</param>
    /// <returns>解密后的明文字符串；密文为空时返回空字符串。</returns>
    public string DecryptSensitiveField(byte[] cipher)
    {
        if (cipher == null || cipher.Length == 0)
            return string.Empty;

        var plainBytes = ProtectedData.Unprotect(cipher, null, DataProtectionScope.CurrentUser);
        return Encoding.UTF8.GetString(plainBytes);
    }

    #endregion

    #region 敏感字段标记加密（带 DPAPI: 前缀）

    /// <summary>
    /// 判断字段值是否已被 DPAPI 标记加密。
    /// </summary>
    private static bool IsEncryptedField(string? value)
        => !string.IsNullOrEmpty(value)
           && value.StartsWith(EncryptedFieldPrefix, StringComparison.Ordinal);

    /// <summary>
    /// 加密明文并附加 "DPAPI:" 前缀标记，返回可安全序列化的字符串。
    /// </summary>
    private string EncryptField(string plaintext)
    {
        var cipher = EncryptSensitiveField(plaintext);
        return EncryptedFieldPrefix + Convert.ToBase64String(cipher);
    }

    /// <summary>
    /// 解密带 "DPAPI:" 前缀标记的字段值，返回明文；未标记则原样返回。
    /// </summary>
    private string DecryptField(string markedValue)
    {
        if (!IsEncryptedField(markedValue))
            return markedValue;

        var base64 = markedValue.Substring(EncryptedFieldPrefix.Length);
        var cipher = Convert.FromBase64String(base64);
        return DecryptSensitiveField(cipher);
    }

    /// <summary>
    /// 获取 AppConfig 中的敏感字段访问器列表。
    /// <para>包含：WebDavPassword、WebDavUser、NasPath、WebDavUrl 等远程凭据与路径。</para>
    /// </summary>
    private static List<(Func<string> Get, Action<string> Set, string Name)> GetSensitiveAccessors(AppConfig config)
    {
        return new List<(Func<string>, Action<string>, string)>
        {
            (() => config.Backup.WebDavPassword,
             v => config.Backup.WebDavPassword = v, "Backup.WebDavPassword"),
            (() => config.Backup.WebDavUser,
             v => config.Backup.WebDavUser = v, "Backup.WebDavUser"),
            (() => config.Backup.NasPath,
             v => config.Backup.NasPath = v, "Backup.NasPath"),
            (() => config.Backup.WebDavUrl,
             v => config.Backup.WebDavUrl = v, "Backup.WebDavUrl")
        };
    }

    /// <summary>
    /// 遍历配置中的敏感字段，若发现明文则使用 DPAPI 加密并标记。
    /// <para>同时创建 AES-256-GCM 加密的配置完整副本（config.json.protected）。</para>
    /// </summary>
    /// <param name="config">应用配置实例。</param>
    /// <returns>加密结果。</returns>
    public ConfigEncryptionResult EnsureConfigProtected(AppConfig config)
    {
        ArgumentNullException.ThrowIfNull(config);

        int encryptedCount = 0;
        int failedCount = 0;
        bool foundAny = false;

        foreach (var (getter, setter, fieldName) in GetSensitiveAccessors(config))
        {
            try
            {
                var value = getter();
                if (string.IsNullOrEmpty(value))
                    continue;

                foundAny = true;

                if (IsEncryptedField(value))
                    continue; // 已加密，跳过

                var encrypted = EncryptField(value);
                setter(encrypted);
                encryptedCount++;
            }
            catch (Exception ex)
            {
                failedCount++;
                ErrorReporter.Report(ex, $"加密敏感字段 {fieldName} 失败");
            }
        }

        if (!foundAny && encryptedCount == 0 && failedCount == 0)
            return ConfigEncryptionResult.NoSensitiveFields;

        // 创建 AES-256-GCM 加密的配置完整副本
        try
        {
            if (!EncryptConfigFile(config))
            {
                failedCount++;
                AuditLogSystem.Log(LogLevel.Warning, LogCategory.Crypto,
                    "配置完整副本加密失败", "config.json.protected 未生成");
            }
        }
        catch (Exception ex)
        {
            failedCount++;
            ErrorReporter.Report(ex, "加密配置完整副本异常");
        }

        if (failedCount > 0 && encryptedCount > 0)
            return ConfigEncryptionResult.PartialFailure;
        if (failedCount > 0 && encryptedCount == 0)
            return ConfigEncryptionResult.Failed;
        if (encryptedCount == 0)
            return ConfigEncryptionResult.AlreadyEncrypted;

        AuditLogSystem.Log(LogLevel.Info, LogCategory.Crypto,
            "敏感配置字段已加密保护", $"已加密 {encryptedCount} 个字段");
        return ConfigEncryptionResult.Success;
    }

    /// <summary>
    /// 解密配置中所有已被 DPAPI 标记加密的敏感字段，恢复为明文供业务逻辑使用。
    /// <para>应在反序列化后、使用配置前调用。</para>
    /// </summary>
    /// <param name="config">应用配置实例。</param>
    public void DecryptSensitiveFields(AppConfig config)
    {
        ArgumentNullException.ThrowIfNull(config);

        foreach (var (getter, setter, fieldName) in GetSensitiveAccessors(config))
        {
            try
            {
                var value = getter();
                if (IsEncryptedField(value))
                    setter(DecryptField(value));
            }
            catch (Exception ex)
            {
                ErrorReporter.Report(ex, $"解密敏感字段 {fieldName} 失败");
            }
        }
    }

    #endregion

    #region NTFS 目录权限加固

    /// <summary>
    /// 对 %APPDATA%\LightGuard\ 目录设置 NTFS 权限：
    /// <para>1. 禁用继承并清除现有规则；</para>
    /// <para>2. 仅授予当前用户完全控制（容器与对象继承）；</para>
    /// <para>3. 仅授予 SYSTEM 完全控制（容器与对象继承）。</para>
    /// <para>移除其他所有用户/组的访问权限，防止非授权读取或篡改配置。</para>
    /// </summary>
    /// <returns>加固成功返回 true；失败返回 false。</returns>
    public bool HardenConfigDirectoryNtfs()
    {
        try
        {
            var dir = ConfigManager.GetConfigDir();
            Directory.CreateDirectory(dir);

            var dirInfo = new DirectoryInfo(dir);
            var security = dirInfo.GetAccessControl();

            // 禁用继承，不保留继承的规则
            security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);

            // 移除所有现有访问规则
            var existingRules = security.GetAccessRules(true, true, typeof(NTAccount))
                .Cast<FileSystemAccessRule>()
                .ToList();
            foreach (var rule in existingRules)
                security.RemoveAccessRule(rule);

            var inheritance = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;

            // 授予当前用户完全控制
            var currentUserSid = WindowsIdentity.GetCurrent().User;
            if (currentUserSid != null)
            {
                security.AddAccessRule(new FileSystemAccessRule(
                    currentUserSid,
                    FileSystemRights.FullControl,
                    inheritance,
                    PropagationFlags.None,
                    AccessControlType.Allow));
            }

            // 授予 SYSTEM 完全控制
            var systemSid = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
            security.AddAccessRule(new FileSystemAccessRule(
                systemSid,
                FileSystemRights.FullControl,
                inheritance,
                PropagationFlags.None,
                AccessControlType.Allow));

            dirInfo.SetAccessControl(security);

            AuditLogSystem.Log(LogLevel.Info, LogCategory.System,
                "配置目录 NTFS 权限已加固",
                $"目录: {dir} | 仅当前用户与 SYSTEM 拥有完全控制");
            return true;
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, "加固配置目录 NTFS 权限失败");
            AuditLogSystem.Log(LogLevel.Warning, LogCategory.System,
                "配置目录 NTFS 权限加固失败", ex.Message);
            return false;
        }
    }

    /// <summary>
    /// 检查配置目录的 NTFS 权限是否已加固。
    /// <para>验证 DACL 中仅包含针对当前用户和 SYSTEM 的允许规则（无其他主体）。</para>
    /// </summary>
    /// <returns>已加固返回 true；未加固或检查失败返回 false。</returns>
    public bool IsConfigDirectorySecured()
    {
        try
        {
            var dir = ConfigManager.GetConfigDir();
            if (!Directory.Exists(dir))
                return false;

            var dirInfo = new DirectoryInfo(dir);
            var security = dirInfo.GetAccessControl();
            var rules = security.GetAccessRules(true, true, typeof(NTAccount));

            var currentUserName = WindowsIdentity.GetCurrent().Name;

            foreach (FileSystemAccessRule rule in rules)
            {
                // 拒绝规则不影响判定（有显式拒绝反而更严格）
                if (rule.AccessControlType != AccessControlType.Allow)
                    continue;

                var identity = rule.IdentityReference.Value;

                // 允许当前用户
                if (currentUserName.Equals(identity, StringComparison.OrdinalIgnoreCase))
                    continue;

                // 允许 SYSTEM
                if (identity.Equals("NT AUTHORITY\\SYSTEM", StringComparison.OrdinalIgnoreCase)
                    || identity.Equals("SYSTEM", StringComparison.OrdinalIgnoreCase))
                    continue;

                // 发现针对其他主体的允许规则 → 未加固
                return false;
            }

            return true;
        }
        catch
        {
            return false;
        }
    }

    #endregion

    #region AES-256-GCM 配置文件完整副本加密

    /// <summary>
    /// 使用 AES-256-GCM 加密配置 JSON 字符串，写入 config.json.protected 完整副本。
    /// <para>文件格式：[nonce(12)][tag(16)][明文长度(4)][密文(N)]。</para>
    /// <para>AES 密钥由 DPAPI 保护存储在 config.key 中，严禁硬编码。</para>
    /// </summary>
    /// <param name="jsonContent">配置 JSON 字符串。</param>
    /// <returns>加密成功返回 true；失败返回 false。</returns>
    public bool EncryptConfigFile(string jsonContent)
    {
        try
        {
            var key = EnsureAesKey();
            var plainBytes = Encoding.UTF8.GetBytes(jsonContent);

            var nonce = RandomNumberGenerator.GetBytes(NonceSize);
            var tag = new byte[TagSize];
            var cipher = new byte[plainBytes.Length];

            using var aes = new AesGcm(key, TagSize);
            aes.Encrypt(nonce, plainBytes, cipher, tag);

            var protectedPath = GetProtectedConfigPath();
            using var fs = new FileStream(protectedPath, FileMode.Create, FileAccess.Write, FileShare.None);
            using var bw = new BinaryWriter(fs, Encoding.UTF8, leaveOpen: true);
            bw.Write(nonce);                 // 12 bytes
            bw.Write(tag);                   // 16 bytes
            bw.Write(plainBytes.Length);     // 4 bytes（明文长度 = 密文长度）
            bw.Write(cipher);                // N bytes

            Win32.SetFileAsSystemHidden(protectedPath);
            return true;
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, "加密配置文件完整副本失败");
            return false;
        }
    }

    /// <summary>
    /// 序列化 AppConfig 并使用 AES-256-GCM 加密为 config.json.protected 完整副本。
    /// </summary>
    /// <param name="config">应用配置实例。</param>
    /// <returns>加密成功返回 true；失败返回 false。</returns>
    public bool EncryptConfigFile(AppConfig config)
    {
        ArgumentNullException.ThrowIfNull(config);
        try
        {
            var json = JsonSerializer.Serialize(config, JsonOpts);
            return EncryptConfigFile(json);
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, "序列化配置用于加密失败");
            return false;
        }
    }

    /// <summary>
    /// 解密 config.json.protected 完整副本，返回配置 JSON 字符串。
    /// </summary>
    /// <returns>解密成功返回 JSON 字符串；文件不存在或解密失败返回 null。</returns>
    public string? DecryptConfigFile()
    {
        try
        {
            var protectedPath = GetProtectedConfigPath();
            if (!File.Exists(protectedPath))
                return null;

            var key = LoadAesKey();
            if (key == null || key.Length != AesKeySize)
                return null;

            using var fs = new FileStream(protectedPath, FileMode.Open, FileAccess.Read, FileShare.Read);
            if (fs.Length < NonceSize + TagSize + 4)
                return null;

            using var br = new BinaryReader(fs, Encoding.UTF8, leaveOpen: true);
            var nonce = br.ReadBytes(NonceSize);
            if (nonce.Length < NonceSize) return null;

            var tag = br.ReadBytes(TagSize);
            if (tag.Length < TagSize) return null;

            var dataLen = br.ReadInt32();
            if (dataLen <= 0 || dataLen > fs.Length) return null;

            var cipher = br.ReadBytes(dataLen);
            if (cipher.Length < dataLen) return null;

            var plain = new byte[dataLen];
            using var aes = new AesGcm(key, TagSize);
            aes.Decrypt(nonce, cipher, tag, plain);

            return Encoding.UTF8.GetString(plain);
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, "解密配置文件完整副本失败");
            return null;
        }
    }

    #endregion

    #region AES-256 密钥管理（DPAPI 保护）

    /// <summary>
    /// 确保存在 AES-256 密钥；不存在则生成并使用 DPAPI 保护后保存。
    /// </summary>
    private static byte[] EnsureAesKey()
    {
        lock (KeyLock)
        {
            var existing = LoadAesKey();
            if (existing != null && existing.Length == AesKeySize)
                return existing;

            var key = RandomNumberGenerator.GetBytes(AesKeySize);
            SaveAesKey(key);
            return key;
        }
    }

    /// <summary>
    /// 使用 DPAPI 保护 AES 密钥并保存到 config.key 文件。
    /// </summary>
    private static void SaveAesKey(byte[] key)
    {
        var keyPath = GetKeyPath();
        var protectedKey = ProtectedData.Protect(key, null, DataProtectionScope.CurrentUser);
        File.WriteAllBytes(keyPath, protectedKey);
        Win32.SetFileAsSystemHidden(keyPath);
    }

    /// <summary>
    /// 从 config.key 文件读取并用 DPAPI 解密 AES 密钥。
    /// </summary>
    private static byte[]? LoadAesKey()
    {
        try
        {
            var keyPath = GetKeyPath();
            if (!File.Exists(keyPath))
                return null;

            var protectedKey = File.ReadAllBytes(keyPath);
            return ProtectedData.Unprotect(protectedKey, null, DataProtectionScope.CurrentUser);
        }
        catch
        {
            return null;
        }
    }

    /// <summary>获取 DPAPI 保护的 AES 密钥文件路径（%APPDATA%\LightGuard\data\config.key）。</summary>
    private static string GetKeyPath()
        => Path.Combine(ConfigManager.GetDataDir(), KeyFile);

    /// <summary>获取 AES-256-GCM 加密的配置完整副本路径（%APPDATA%\LightGuard\config.json.protected）。</summary>
    private static string GetProtectedConfigPath()
        => Path.Combine(ConfigManager.GetConfigDir(), ProtectedConfigFile);

    #endregion
}
