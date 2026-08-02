// © 2026 落尘（Luochen）原创开发 - 保留所有权利

using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using LightGuard.Core;
using LightGuard.Native;

namespace LightGuard.Security;

/// <summary>
/// 隔离文件记录
/// <para>记录被隔离文件的元数据信息，包括原始路径、哈希值、隔离原因等。</para>
/// </summary>
public sealed class QuarantineRecord
{
    /// <summary>隔离记录唯一标识</summary>
    public string Id { get; set; } = Guid.NewGuid().ToString("N");

    /// <summary>原始文件完整路径</summary>
    public string OriginalPath { get; set; } = "";

    /// <summary>原始文件名</summary>
    public string FileName { get; set; } = "";

    /// <summary>隔离区文件路径（加密后的 .quarantine 文件）</summary>
    public string QuarantinePath { get; set; } = "";

    /// <summary>原始文件大小（字节）</summary>
    public long FileSize { get; set; }

    /// <summary>原始文件的 SHA256 哈希值</summary>
    public string Sha256Hash { get; set; } = "";

    /// <summary>隔离原因</summary>
    public string Reason { get; set; } = "";

    /// <summary>隔离时间</summary>
    public DateTime QuarantinedAt { get; set; } = DateTime.Now;

    /// <summary>威胁名称（如勒索病毒家族名等）</summary>
    public string ThreatName { get; set; } = "";
}

/// <summary>
/// 文件隔离区管理器
/// <para>核心特性：</para>
/// <para>1. AES-256-GCM 加密隔离文件，密钥由 DPAPI 保护存储在 quarantine.key</para>
/// <para>2. 保留完整的隔离元数据（路径、哈希、原因、时间等）</para>
/// <para>3. 支持文件恢复、永久删除、清空隔离区</para>
/// <para>4. 自动清理超过 30 天的过期隔离文件</para>
/// </summary>
public sealed class QuarantineManager : IDisposable
{
    #region 常量

    /// <summary>AES-256 密钥长度（字节）</summary>
    private const int AesKeySize = 32;

    /// <summary>GCM Nonce 长度（字节）</summary>
    private const int NonceSize = 12;

    /// <summary>GCM 认证标签长度（字节）</summary>
    private const int TagSize = 16;

    /// <summary>隔离区密钥文件名</summary>
    private const string KeyFileName = "quarantine.key";

    /// <summary>隔离区元数据索引文件名</summary>
    private const string MetaFileName = "quarantine_index.json";

    /// <summary>隔离区目录名</summary>
    private const string QuarantineFolderName = "quarantine";

    /// <summary>隔离文件扩展名</summary>
    private const string QuarantineFileExt = ".quarantine";

    #endregion

    #region 字段

    private readonly string _quarantineDir;
    private readonly string _metaDataPath;
    private readonly string _keyPath;
    private readonly object _lock = new();
    private List<QuarantineRecord> _records;
    private byte[]? _aesKey;
    private bool _disposed;

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = null,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    #endregion

    #region 构造与初始化

    /// <summary>
    /// 初始化隔离区管理器，加载密钥和历史隔离记录。
    /// </summary>
    public QuarantineManager()
    {
        var configDir = ConfigManager.GetConfigDir();
        _quarantineDir = Path.Combine(configDir, QuarantineFolderName);
        _metaDataPath = Path.Combine(_quarantineDir, MetaFileName);
        _keyPath = Path.Combine(ConfigManager.GetDataDir(), KeyFileName);
        _records = new List<QuarantineRecord>();

        try
        {
            Directory.CreateDirectory(_quarantineDir);
            _aesKey = EnsureKey();
            LoadRecords();

            AuditLogSystem.Log(LogLevel.Info, LogCategory.System,
                "隔离区管理器初始化完成", $"隔离记录数: {_records.Count}");
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, "QuarantineManager 初始化失败");
        }
    }

    #endregion

    #region 文件隔离

    /// <summary>
    /// 将可疑文件隔离到隔离区。
    /// <para>隔离时对文件进行 AES-256-GCM 加密，保留元数据。</para>
    /// <para>文件格式：[nonce(12)][tag(16)][ciphertext(N)]</para>
    /// </summary>
    /// <param name="filePath">要隔离的文件路径</param>
    /// <param name="reason">隔离原因</param>
    /// <param name="threatName">威胁名称（可选）</param>
    /// <returns>隔离记录 ID；隔离失败返回空字符串</returns>
    public string QuarantineFile(string filePath, string reason, string threatName = "")
    {
        try
        {
            if (!File.Exists(filePath))
            {
                AuditLogSystem.LogWarning(LogCategory.System,
                    $"隔离失败：文件不存在 - {filePath}");
                return "";
            }

            if (_aesKey == null)
            {
                AuditLogSystem.LogError(LogCategory.Crypto,
                    "隔离失败：AES 密钥未初始化");
                return "";
            }

            // 读取原始文件
            var fileBytes = File.ReadAllBytes(filePath);
            var fileName = Path.GetFileName(filePath);
            var fileSize = fileBytes.Length;

            // 计算 SHA256 哈希
            var hashBytes = SHA256.HashData(fileBytes);
            var sha256Hash = Convert.ToHexString(hashBytes).ToLowerInvariant();

            // AES-256-GCM 加密
            var nonce = RandomNumberGenerator.GetBytes(NonceSize);
            var tag = new byte[TagSize];
            var cipher = new byte[fileBytes.Length];

            using (var aes = new AesGcm(_aesKey, TagSize))
            {
                aes.Encrypt(nonce, fileBytes, cipher, tag);
            }

            // 清除明文密钥数据
            Array.Clear(fileBytes, 0, fileBytes.Length);

            // 生成隔离记录
            var record = new QuarantineRecord
            {
                OriginalPath = filePath,
                FileName = fileName,
                FileSize = fileSize,
                Sha256Hash = sha256Hash,
                Reason = reason,
                ThreatName = threatName
            };

            // 写入加密文件
            record.QuarantinePath = Path.Combine(_quarantineDir,
                $"{record.Id}{QuarantineFileExt}");

            using (var fs = new FileStream(record.QuarantinePath,
                       FileMode.Create, FileAccess.Write, FileShare.None))
            using (var bw = new BinaryWriter(fs, Encoding.UTF8, leaveOpen: true))
            {
                bw.Write(nonce);        // 12 bytes
                bw.Write(tag);          // 16 bytes
                bw.Write(cipher);       // N bytes
            }

            // 设置隔离文件为系统隐藏（伪装防勒索）
            Win32.SetFileAsSystemHidden(record.QuarantinePath);

            // 删除原始文件
            try
            {
                File.Delete(filePath);
            }
            catch (Exception ex)
            {
                // 原始文件删除失败不影响隔离，但记录警告
                AuditLogSystem.LogWarning(LogCategory.System,
                    $"隔离后删除原始文件失败 - {filePath}", ex.Message);
            }

            // 保存记录
            lock (_lock)
            {
                _records.Add(record);
                SaveRecords();
            }

            AuditLogSystem.Log(LogLevel.Info, LogCategory.System,
                $"文件已隔离: {fileName}",
                $"ID={record.Id}, 原始路径={filePath}, 哈希={sha256Hash}, " +
                $"大小={fileSize} 字节, 原因={reason}, 威胁={threatName}");

            return record.Id;
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, $"隔离文件失败: {filePath}");
            AuditLogSystem.LogError(LogCategory.System,
                $"隔离文件失败: {filePath}", ex.Message);
            return "";
        }
    }

    #endregion

    #region 文件恢复

    /// <summary>
    /// 从隔离区恢复文件到原始位置。
    /// <para>解密文件并还原到原始路径。若目标路径已存在文件：</para>
    /// <para>- overwrite=true：覆盖目标文件</para>
    /// <para>- overwrite=false：自动重命名（添加 _restored 后缀）</para>
    /// </summary>
    /// <param name="quarantineId">隔离记录 ID</param>
    /// <param name="overwrite">是否覆盖已存在的目标文件</param>
    /// <returns>恢复成功返回 true；失败返回 false</returns>
    public bool RestoreFile(string quarantineId, bool overwrite = false)
    {
        try
        {
            QuarantineRecord? record;
            lock (_lock)
            {
                record = _records.FirstOrDefault(r => r.Id == quarantineId);
            }

            if (record == null)
            {
                AuditLogSystem.LogWarning(LogCategory.System,
                    $"恢复失败：隔离记录不存在 - {quarantineId}");
                return false;
            }

            if (_aesKey == null)
            {
                AuditLogSystem.LogError(LogCategory.Crypto,
                    "恢复失败：AES 密钥未初始化");
                return false;
            }

            if (!File.Exists(record.QuarantinePath))
            {
                AuditLogSystem.LogError(LogCategory.System,
                    $"恢复失败：隔离文件不存在 - {record.QuarantinePath}");
                return false;
            }

            // 读取并解密文件
            byte[] plainBytes;
            using (var fs = new FileStream(record.QuarantinePath,
                       FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                if (fs.Length < NonceSize + TagSize)
                {
                    AuditLogSystem.LogError(LogCategory.Crypto,
                        $"恢复失败：隔离文件已损坏 - {record.QuarantinePath}");
                    return false;
                }

                using var br = new BinaryReader(fs, Encoding.UTF8, leaveOpen: true);
                var nonce = br.ReadBytes(NonceSize);
                var tag = br.ReadBytes(TagSize);
                var cipher = br.ReadBytes((int)(fs.Length - NonceSize - TagSize));

                plainBytes = new byte[cipher.Length];
                using var aes = new AesGcm(_aesKey, TagSize);
                aes.Decrypt(nonce, cipher, tag, plainBytes);
            }

            // 确定目标路径
            var targetPath = record.OriginalPath;
            if (File.Exists(targetPath) && !overwrite)
            {
                // 自动重命名：添加 _restored 后缀
                var dir = Path.GetDirectoryName(targetPath) ?? "";
                var nameWithoutExt = Path.GetFileNameWithoutExtension(targetPath);
                var ext = Path.GetExtension(targetPath);
                var counter = 1;
                do
                {
                    targetPath = Path.Combine(dir,
                        $"{nameWithoutExt}_restored{counter}{ext}");
                    counter++;
                } while (File.Exists(targetPath));
            }

            // 确保目标目录存在
            var targetDir = Path.GetDirectoryName(targetPath);
            if (!string.IsNullOrEmpty(targetDir))
                Directory.CreateDirectory(targetDir);

            // 写入文件
            File.WriteAllBytes(targetPath, plainBytes);

            // 从隔离区移除
            lock (_lock)
            {
                _records.Remove(record);
                SaveRecords();
            }

            // 删除隔离文件
            try
            {
                Win32.ResetFileAttributes(record.QuarantinePath);
                File.Delete(record.QuarantinePath);
            }
            catch { }

            AuditLogSystem.Log(LogLevel.Info, LogCategory.System,
                $"文件已恢复: {record.FileName}",
                $"ID={record.Id}, 恢复到={targetPath}, 覆盖={overwrite}");

            return true;
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, $"恢复隔离文件失败: {quarantineId}");
            AuditLogSystem.LogError(LogCategory.System,
                $"恢复隔离文件失败: {quarantineId}", ex.Message);
            return false;
        }
    }

    #endregion

    #region 隔离区管理

    /// <summary>
    /// 列出所有隔离文件记录。
    /// </summary>
    /// <returns>隔离记录列表（副本）</returns>
    public List<QuarantineRecord> ListQuarantinedFiles()
    {
        lock (_lock)
        {
            return _records.ToList();
        }
    }

    /// <summary>
    /// 永久删除指定的隔离文件。
    /// </summary>
    /// <param name="quarantineId">隔离记录 ID</param>
    /// <returns>删除成功返回 true；失败返回 false</returns>
    public bool DeleteQuarantined(string quarantineId)
    {
        try
        {
            QuarantineRecord? record;
            lock (_lock)
            {
                record = _records.FirstOrDefault(r => r.Id == quarantineId);
            }

            if (record == null)
            {
                AuditLogSystem.LogWarning(LogCategory.System,
                    $"删除失败：隔离记录不存在 - {quarantineId}");
                return false;
            }

            // 删除隔离文件
            if (File.Exists(record.QuarantinePath))
            {
                Win32.ResetFileAttributes(record.QuarantinePath);
                File.Delete(record.QuarantinePath);
            }

            // 移除记录
            lock (_lock)
            {
                _records.Remove(record);
                SaveRecords();
            }

            AuditLogSystem.Log(LogLevel.Info, LogCategory.System,
                $"隔离文件已永久删除: {record.FileName}",
                $"ID={record.Id}, 原始路径={record.OriginalPath}");

            return true;
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, $"删除隔离文件失败: {quarantineId}");
            AuditLogSystem.LogError(LogCategory.System,
                $"删除隔离文件失败: {quarantineId}", ex.Message);
            return false;
        }
    }

    /// <summary>
    /// 清空隔离区，删除所有隔离文件。
    /// </summary>
    public void ClearAll()
    {
        try
        {
            List<QuarantineRecord> recordsCopy;
            lock (_lock)
            {
                recordsCopy = _records.ToList();
                _records.Clear();
                SaveRecords();
            }

            var deletedCount = 0;
            foreach (var record in recordsCopy)
            {
                try
                {
                    if (File.Exists(record.QuarantinePath))
                    {
                        Win32.ResetFileAttributes(record.QuarantinePath);
                        File.Delete(record.QuarantinePath);
                        deletedCount++;
                    }
                }
                catch { }
            }

            AuditLogSystem.Log(LogLevel.Info, LogCategory.System,
                "隔离区已清空", $"删除 {deletedCount}/{recordsCopy.Count} 个文件");
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, "清空隔离区失败");
            AuditLogSystem.LogError(LogCategory.System,
                "清空隔离区失败", ex.Message);
        }
    }

    /// <summary>
    /// 获取隔离区总大小（字节）。
    /// </summary>
    /// <returns>隔离区文件总大小</returns>
    public long GetQuarantineSize()
    {
        try
        {
            long totalSize = 0;
            lock (_lock)
            {
                foreach (var record in _records)
                {
                    if (File.Exists(record.QuarantinePath))
                    {
                        var info = new FileInfo(record.QuarantinePath);
                        totalSize += info.Length;
                    }
                }
            }
            return totalSize;
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, "获取隔离区大小失败");
            return 0;
        }
    }

    /// <summary>
    /// 自动清理过期的隔离文件。
    /// </summary>
    /// <param name="maxAgeDays">最大保留天数（默认 30 天）</param>
    /// <returns>清理的文件数量</returns>
    public int CleanupExpired(int maxAgeDays = 30)
    {
        try
        {
            var cutoff = DateTime.Now.AddDays(-maxAgeDays);
            List<QuarantineRecord> expired;

            lock (_lock)
            {
                expired = _records
                    .Where(r => r.QuarantinedAt < cutoff)
                    .ToList();
            }

            var deletedCount = 0;
            foreach (var record in expired)
            {
                try
                {
                    if (File.Exists(record.QuarantinePath))
                    {
                        Win32.ResetFileAttributes(record.QuarantinePath);
                        File.Delete(record.QuarantinePath);
                    }

                    lock (_lock)
                    {
                        _records.Remove(record);
                    }
                    deletedCount++;
                }
                catch { }
            }

            if (deletedCount > 0)
            {
                lock (_lock)
                {
                    SaveRecords();
                }

                AuditLogSystem.Log(LogLevel.Info, LogCategory.AutoCleanup,
                    "隔离区自动清理完成",
                    $"清理 {deletedCount} 个过期文件（超过 {maxAgeDays} 天）");
            }

            return deletedCount;
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, "清理过期隔离文件失败");
            return 0;
        }
    }

    #endregion

    #region AES-256-GCM 密钥管理（DPAPI 保护）

    /// <summary>
    /// 确保存在 AES-256 密钥；不存在则生成并使用 DPAPI 保护后保存。
    /// </summary>
    private byte[] EnsureKey()
    {
        var existing = LoadKey();
        if (existing != null && existing.Length == AesKeySize)
            return existing;

        var key = RandomNumberGenerator.GetBytes(AesKeySize);
        SaveKey(key);
        return key;
    }

    /// <summary>使用 DPAPI 保护密钥并保存到本地</summary>
    private void SaveKey(byte[] key)
    {
        try
        {
            var protectedKey = ProtectedData.Protect(key, null,
                DataProtectionScope.CurrentUser);
            File.WriteAllBytes(_keyPath, protectedKey);
            Win32.SetFileAsSystemHidden(_keyPath);
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, "保存隔离区密钥失败");
        }
    }

    /// <summary>从本地读取并用 DPAPI 解密密钥</summary>
    private byte[]? LoadKey()
    {
        try
        {
            if (!File.Exists(_keyPath))
                return null;
            var protectedKey = File.ReadAllBytes(_keyPath);
            return ProtectedData.Unprotect(protectedKey, null,
                DataProtectionScope.CurrentUser);
        }
        catch { return null; }
    }

    #endregion

    #region 元数据读写

    /// <summary>从 JSON 文件加载隔离记录</summary>
    private void LoadRecords()
    {
        try
        {
            if (!File.Exists(_metaDataPath))
            {
                _records = new List<QuarantineRecord>();
                return;
            }

            var json = File.ReadAllText(_metaDataPath, Encoding.UTF8);
            _records = JsonSerializer.Deserialize<List<QuarantineRecord>>(json, JsonOptions)
                       ?? new List<QuarantineRecord>();
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, "加载隔离记录失败");
            _records = new List<QuarantineRecord>();
        }
    }

    /// <summary>保存隔离记录到 JSON 文件</summary>
    private void SaveRecords()
    {
        try
        {
            var json = JsonSerializer.Serialize(_records, JsonOptions);
            File.WriteAllText(_metaDataPath, json, Encoding.UTF8);
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, "保存隔离记录失败");
        }
    }

    #endregion

    #region IDisposable

    /// <summary>
    /// 释放资源，保存元数据并清除内存中的密钥。
    /// </summary>
    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;

        try
        {
            lock (_lock)
            {
                SaveRecords();
            }

            // 清除内存中的密钥
            if (_aesKey != null)
            {
                Array.Clear(_aesKey, 0, _aesKey.Length);
                _aesKey = null;
            }
        }
        catch { }

        GC.SuppressFinalize(this);
    }

    #endregion
}
