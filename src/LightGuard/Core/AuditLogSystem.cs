// © 2026 落尘（Luochen） 原创开发 - 保留所有权利

using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using LightGuard.Native;

using Timer = System.Threading.Timer;

namespace LightGuard.Core;

/// <summary>
/// 日志级别枚举
/// </summary>
public enum LogLevel
{
    /// <summary>常规信息</summary>
    Info,

    /// <summary>警告</summary>
    Warning,

    /// <summary>错误</summary>
    Error,

    /// <summary>严重错误（需立即关注）</summary>
    Critical
}

/// <summary>
/// 日志分类枚举
/// </summary>
public enum LogCategory
{
    /// <summary>文件备份相关</summary>
    Backup,

    /// <summary>加密/解密相关</summary>
    Crypto,

    /// <summary>完整性校验相关</summary>
    Verify,

    /// <summary>SMB 连接相关</summary>
    SmbConnection,

    /// <summary>自动清理相关</summary>
    AutoCleanup,

    /// <summary>数据库备份相关</summary>
    Database,

    /// <summary>勒索病毒告警</summary>
    RansomwareAlert,

    /// <summary>SMB 审计相关</summary>
    SmbAudit,

    /// <summary>系统相关</summary>
    System,

    /// <summary>灾难恢复相关</summary>
    Recovery,

    /// <summary>Defender 查杀相关（P1-6 业务联动）</summary>
    DefenderScan,

    /// <summary>选择性还原相关（浏览 / 批量恢复）</summary>
    SelectiveRecovery
}

/// <summary>
/// 审计日志条目实体
/// </summary>
public sealed class AuditLogEntry
{
    /// <summary>时间戳</summary>
    public DateTime Timestamp { get; set; }

    /// <summary>日志级别</summary>
    public LogLevel Level { get; set; }

    /// <summary>日志分类</summary>
    public LogCategory Category { get; set; }

    /// <summary>日志消息</summary>
    public string Message { get; set; } = string.Empty;

    /// <summary>详细信息（可选）</summary>
    public string Details { get; set; } = string.Empty;

    /// <summary>来源（调用方标识）</summary>
    public string Source { get; set; } = string.Empty;

    /// <summary>机器名</summary>
    public string MachineName { get; set; } = string.Empty;

    /// <summary>用户名</summary>
    public string UserName { get; set; } = string.Empty;
}

/// <summary>
/// 全局日志审计系统（静态服务类）
/// <para>核心特性：</para>
/// <para>1. AES-256-GCM 加密存储防篡改</para>
/// <para>2. 日志文件按天滚动：audit-yyyy-MM-dd.log.enc</para>
/// <para>3. 线程安全：ConcurrentQueue 缓冲 + 定时刷盘</para>
/// <para>4. 启动时自动加载解密历史日志到内存索引</para>
/// <para>5. 支持 SMB 远程日志同步（双副本归档）</para>
/// <para>6. 日志保留策略：默认 90 天自动清理</para>
/// </summary>
public static class AuditLogSystem
{
    #region 常量

    /// <summary>AES-256 密钥长度（字节）</summary>
    private const int AesKeySize = 32;

    /// <summary>GCM Nonce 长度（字节）</summary>
    private const int NonceSize = 12;

    /// <summary>GCM 认证标签长度（字节）</summary>
    private const int TagSize = 16;

    /// <summary>缓冲刷盘间隔（毫秒）</summary>
    private const int FlushIntervalMs = 5000;

    /// <summary>过期清理检查间隔（毫秒，24 小时）</summary>
    private const int CleanupIntervalMs = 24 * 60 * 60 * 1000;

    /// <summary>默认日志保留天数</summary>
    private const int DefaultRetentionDays = 90;

    /// <summary>日志文件名前缀</summary>
    private const string LogFilePrefix = "audit-";

    /// <summary>日志文件扩展名</summary>
    private const string LogFileExt = ".log.enc";

    /// <summary>密钥文件名</summary>
    private const string KeyFileName = "audit.key";

    #endregion

    #region 字段

    private static readonly ConcurrentQueue<AuditLogEntry> _buffer = new();
    private static readonly List<AuditLogEntry> _index = new();
    private static readonly object _indexLock = new();
    private static readonly object _fileLock = new();
    private static Timer? _flushTimer;
    private static Timer? _cleanupTimer;
    private static byte[]? _aesKey;
    private static string _logDir = string.Empty;
    private static string _keyPath = string.Empty;
    private static string? _smbSyncPath;
    private static int _retentionDays = DefaultRetentionDays;
    private static bool _initialized;
    private static bool _running;

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        Converters = { new JsonStringEnumConverter() },
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    #endregion

    #region 属性

    /// <summary>内存索引中的日志总条数</summary>
    public static int TotalEntries
    {
        get
        {
            lock (_indexLock)
            {
                return _index.Count;
            }
        }
    }

    /// <summary>系统是否正在运行（定时刷盘已启动）</summary>
    public static bool IsRunning => _running;

    /// <summary>SMB 远程同步路径（双副本归档目标）</summary>
    public static string? SmbSyncPath
    {
        get => _smbSyncPath;
        set => _smbSyncPath = string.IsNullOrWhiteSpace(value) ? null : value;
    }

    /// <summary>日志保留天数</summary>
    public static int RetentionDays
    {
        get => _retentionDays;
        set => _retentionDays = value > 0 ? value : DefaultRetentionDays;
    }

    #endregion

    #region 初始化与生命周期

    /// <summary>
    /// 初始化审计日志系统
    /// 加载（或生成）AES-256-GCM 密钥，并将历史加密日志解密加载到内存索引。
    /// </summary>
    /// <param name="smbSyncPath">SMB 远程同步路径（null 表示不启用远程同步）</param>
    /// <param name="retentionDays">日志保留天数（默认 90 天）</param>
    public static void Initialize(string? smbSyncPath = null, int retentionDays = DefaultRetentionDays)
    {
        if (_initialized) return;

        _logDir = ConfigManager.GetLogDir();
        _keyPath = Path.Combine(ConfigManager.GetDataDir(), KeyFileName);
        _smbSyncPath = string.IsNullOrWhiteSpace(smbSyncPath) ? null : smbSyncPath;
        _retentionDays = retentionDays > 0 ? retentionDays : DefaultRetentionDays;

        // 加载或生成 AES-256 密钥（DPAPI 保护）
        _aesKey = EnsureKey();

        // 启动时加载历史日志到内存索引
        LoadHistoricalLogs();

        _initialized = true;
        ErrorReporter.Log($"审计日志系统初始化完成，已加载 {_index.Count} 条历史日志");
    }

    /// <summary>
    /// 启动日志系统（开始定时刷盘和过期清理）
    /// </summary>
    public static void Start()
    {
        if (!_initialized)
            Initialize();

        if (_running) return;

        _flushTimer = new Timer(OnFlushTick, null, FlushIntervalMs, FlushIntervalMs);
        _cleanupTimer = new Timer(OnCleanupTick, null, CleanupIntervalMs, CleanupIntervalMs);
        _running = true;
        ErrorReporter.Log("审计日志系统已启动（定时刷盘 + 过期清理）");
    }

    /// <summary>
    /// 停止日志系统（刷盘剩余缓冲并停止定时器）
    /// </summary>
    public static void Stop()
    {
        if (!_running) return;

        _flushTimer?.Dispose();
        _flushTimer = null;
        _cleanupTimer?.Dispose();
        _cleanupTimer = null;
        _running = false;

        // 刷盘剩余缓冲
        FlushBuffer();

        ErrorReporter.Log("审计日志系统已停止");
    }

    #endregion

    #region 日志写入

    /// <summary>
    /// 记录一条审计日志（线程安全，写入缓冲队列，由定时器刷盘）
    /// </summary>
    /// <param name="level">日志级别</param>
    /// <param name="category">日志分类</param>
    /// <param name="message">日志消息</param>
    /// <param name="details">详细信息（可选）</param>
    public static void Log(LogLevel level, LogCategory category, string message, string details = "")
    {
        if (!_initialized)
            Initialize();

        var entry = new AuditLogEntry
        {
            Timestamp = DateTime.Now,
            Level = level,
            Category = category,
            Message = message ?? string.Empty,
            Details = details ?? string.Empty,
            Source = TryGetCallerSource(),
            MachineName = Environment.MachineName,
            UserName = Environment.UserName
        };

        _buffer.Enqueue(entry);

        // Critical 级别立即刷盘
        if (level == LogLevel.Critical)
            FlushBuffer();
    }

    /// <summary>
    /// 记录 Info 级别日志（快捷方法）
    /// </summary>
    public static void LogInfo(LogCategory category, string message, string details = "")
        => Log(LogLevel.Info, category, message, details);

    /// <summary>
    /// 记录 Warning 级别日志（快捷方法）
    /// </summary>
    public static void LogWarning(LogCategory category, string message, string details = "")
        => Log(LogLevel.Warning, category, message, details);

    /// <summary>
    /// 记录 Error 级别日志（快捷方法）
    /// </summary>
    public static void LogError(LogCategory category, string message, string details = "")
        => Log(LogLevel.Error, category, message, details);

    /// <summary>
    /// 记录 Critical 级别日志（快捷方法，立即刷盘）
    /// </summary>
    public static void LogCritical(LogCategory category, string message, string details = "")
        => Log(LogLevel.Critical, category, message, details);

    #endregion

    #region 查询

    /// <summary>
    /// 查询指定时间范围内的日志条目
    /// </summary>
    /// <param name="startTime">起始时间</param>
    /// <param name="endTime">结束时间</param>
    /// <param name="level">日志级别筛选（null 表示不筛选）</param>
    /// <param name="category">日志分类筛选（null 表示不筛选）</param>
    /// <returns>匹配的日志条目列表（按时间升序）</returns>
    public static List<AuditLogEntry> Query(DateTime startTime, DateTime endTime, LogLevel? level = null, LogCategory? category = null)
    {
        lock (_indexLock)
        {
            var query = _index.AsEnumerable();

            if (startTime != DateTime.MinValue)
                query = query.Where(e => e.Timestamp >= startTime);
            if (endTime != DateTime.MaxValue)
                query = query.Where(e => e.Timestamp <= endTime);
            if (level.HasValue)
                query = query.Where(e => e.Level == level.Value);
            if (category.HasValue)
                query = query.Where(e => e.Category == category.Value);

            return query.OrderBy(e => e.Timestamp).ToList();
        }
    }

    /// <summary>
    /// 查询所有日志条目（按时间升序）
    /// </summary>
    public static List<AuditLogEntry> QueryAll()
    {
        lock (_indexLock)
        {
            return _index.OrderBy(e => e.Timestamp).ToList();
        }
    }

    /// <summary>
    /// 获取最近的 N 条日志
    /// </summary>
    /// <param name="count">条数</param>
    public static List<AuditLogEntry> GetRecent(int count)
    {
        lock (_indexLock)
        {
            return _index
                .OrderByDescending(e => e.Timestamp)
                .Take(count)
                .OrderBy(e => e.Timestamp)
                .ToList();
        }
    }

    #endregion

    #region 定时刷盘

    /// <summary>定时刷盘回调</summary>
    private static void OnFlushTick(object? state)
    {
        try { FlushBuffer(); }
        catch (Exception ex) { ErrorReporter.Report(ex, "审计日志刷盘失败"); }
    }

    /// <summary>
    /// 将缓冲队列中的所有日志条目刷盘到加密文件
    /// </summary>
    public static void FlushBuffer()
    {
        if (_aesKey == null) return;

        // 按日期分组
        var entries = new List<AuditLogEntry>();
        while (_buffer.TryDequeue(out var entry))
            entries.Add(entry);

        if (entries.Count == 0) return;

        lock (_fileLock)
        {
            // 按日期分组写入对应的日志文件
            var grouped = entries.GroupBy(e => e.Timestamp.Date);
            foreach (var group in grouped)
            {
                var filePath = GetDailyFilePath(group.Key);
                foreach (var entry in group)
                {
                    WriteEncryptedEntry(filePath, entry);
                }

                // SMB 远程同步（双副本归档）
                SyncToSmb(filePath);
            }
        }

        // 更新内存索引
        lock (_indexLock)
        {
            _index.AddRange(entries);
        }
    }

    #endregion

    #region 过期清理

    /// <summary>定时清理回调</summary>
    private static void OnCleanupTick(object? state)
    {
        try { CleanupOldLogs(); }
        catch (Exception ex) { ErrorReporter.Report(ex, "审计日志清理失败"); }
    }

    /// <summary>
    /// 清理超过保留期限的日志文件
    /// </summary>
    public static void CleanupOldLogs()
    {
        try
        {
            if (!Directory.Exists(_logDir)) return;

            var cutoff = DateTime.Now.AddDays(-_retentionDays);
            var files = Directory.EnumerateFiles(_logDir, $"{LogFilePrefix}*{LogFileExt}");

            foreach (var file in files)
            {
                var fileName = Path.GetFileNameWithoutExtension(file);
                // 文件名格式：audit-2026-08-01（去掉 .log.enc 后）
                var dateStr = fileName.Substring(LogFilePrefix.Length);
                // 去掉可能的 .log 后缀
                if (dateStr.EndsWith(".log"))
                    dateStr = dateStr.Substring(0, dateStr.Length - 4);

                if (DateTime.TryParseExact(dateStr, "yyyy-MM-dd", null,
                    System.Globalization.DateTimeStyles.None, out var fileDate))
                {
                    if (fileDate.Date < cutoff.Date)
                    {
                        try { File.Delete(file); } catch { }
                    }
                }
            }

            // 清理内存索引中过期的条目
            lock (_indexLock)
            {
                _index.RemoveAll(e => e.Timestamp < cutoff);
            }

            ErrorReporter.Log($"审计日志清理完成，保留 {_retentionDays} 天");
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, "审计日志清理异常");
        }
    }

    #endregion

    #region 加密文件读写

    /// <summary>
    /// 将单条日志条目加密后追加写入日志文件
    /// <para>每条记录格式：[nonce(12)][tag(16)][data_len(4)][ciphertext(N)]</para>
    /// </summary>
    private static void WriteEncryptedEntry(string filePath, AuditLogEntry entry)
    {
        try
        {
            var json = JsonSerializer.SerializeToUtf8Bytes(entry, JsonOpts);
            var nonce = RandomNumberGenerator.GetBytes(NonceSize);
            var tag = new byte[TagSize];
            var cipher = new byte[json.Length];

            using var aes = new AesGcm(_aesKey!, TagSize);
            aes.Encrypt(nonce, json, cipher, tag);

            using var fs = new FileStream(filePath, FileMode.Append, FileAccess.Write, FileShare.None);
            using var bw = new BinaryWriter(fs, Encoding.UTF8, leaveOpen: true);
            bw.Write(nonce);                 // 12 bytes
            bw.Write(tag);                   // 16 bytes
            bw.Write(json.Length);           // 4 bytes (明文长度 = 密文长度)
            bw.Write(cipher);                // N bytes
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, "写入加密审计日志失败");
        }
    }

    /// <summary>
    /// 从加密日志文件中读取所有日志条目
    /// </summary>
    private static List<AuditLogEntry> ReadEncryptedFile(string filePath)
    {
        var result = new List<AuditLogEntry>();
        if (_aesKey == null || !File.Exists(filePath)) return result;

        try
        {
            using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read);
            if (fs.Length < NonceSize + TagSize + 4) return result;

            using var br = new BinaryReader(fs, Encoding.UTF8, leaveOpen: true);
            using var aes = new AesGcm(_aesKey, TagSize);

            while (fs.Position < fs.Length)
            {
                try
                {
                    var nonce = br.ReadBytes(NonceSize);
                    if (nonce.Length < NonceSize) break;

                    var tag = br.ReadBytes(TagSize);
                    if (tag.Length < TagSize) break;

                    var dataLen = br.ReadInt32();
                    if (dataLen <= 0 || dataLen > fs.Length) break;

                    var cipher = br.ReadBytes(dataLen);
                    if (cipher.Length < dataLen) break;

                    var plain = new byte[dataLen];
                    aes.Decrypt(nonce, cipher, tag, plain);

                    var entry = JsonSerializer.Deserialize<AuditLogEntry>(plain, JsonOpts);
                    if (entry != null)
                        result.Add(entry);
                }
                catch { break; }
            }
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, $"读取加密审计日志失败：{filePath}");
        }

        return result;
    }

    #endregion

    #region 历史日志加载

    /// <summary>
    /// 启动时加载所有历史加密日志到内存索引
    /// </summary>
    private static void LoadHistoricalLogs()
    {
        try
        {
            if (!Directory.Exists(_logDir)) return;

            var files = Directory.EnumerateFiles(_logDir, $"{LogFilePrefix}*{LogFileExt}")
                .OrderBy(f => f);

            lock (_indexLock)
            {
                _index.Clear();
                foreach (var file in files)
                {
                    var entries = ReadEncryptedFile(file);
                    _index.AddRange(entries);
                }
                _index.Sort((a, b) => a.Timestamp.CompareTo(b.Timestamp));
            }
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, "加载历史审计日志失败");
        }
    }

    #endregion

    #region SMB 远程同步

    /// <summary>
    /// 将日志文件同步到 SMB 远程路径（双副本归档）
    /// </summary>
    private static void SyncToSmb(string filePath)
    {
        if (string.IsNullOrWhiteSpace(_smbSyncPath)) return;

        try
        {
            Directory.CreateDirectory(_smbSyncPath);
            var dest = Path.Combine(_smbSyncPath, Path.GetFileName(filePath));
            File.Copy(filePath, dest, true);
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, $"SMB 日志同步失败：{_smbSyncPath}");
        }
    }

    #endregion

    #region AES-256-GCM 密钥管理（DPAPI 保护）

    /// <summary>
    /// 确保存在 AES-256 密钥；不存在则生成并使用 DPAPI 保护后保存
    /// </summary>
    private static byte[] EnsureKey()
    {
        var existing = LoadKey();
        if (existing != null && existing.Length == AesKeySize) return existing;

        var key = RandomNumberGenerator.GetBytes(AesKeySize);
        SaveKey(key);
        return key;
    }

    /// <summary>使用 DPAPI 保护密钥并保存到本地</summary>
    private static void SaveKey(byte[] key)
    {
        try
        {
            var protectedKey = ProtectedData.Protect(key, null, DataProtectionScope.CurrentUser);
            File.WriteAllBytes(_keyPath, protectedKey);
            Win32.SetFileAsSystemHidden(_keyPath);
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, "保存审计日志密钥失败");
        }
    }

    /// <summary>从本地读取并用 DPAPI 解密密钥</summary>
    private static byte[]? LoadKey()
    {
        try
        {
            if (!File.Exists(_keyPath)) return null;
            var protectedKey = File.ReadAllBytes(_keyPath);
            return ProtectedData.Unprotect(protectedKey, null, DataProtectionScope.CurrentUser);
        }
        catch { return null; }
    }

    #endregion

    #region 辅助方法

    /// <summary>获取当天日志文件路径</summary>
    private static string GetDailyFilePath(DateTime date)
    {
        return Path.Combine(_logDir, $"{LogFilePrefix}{date:yyyy-MM-dd}{LogFileExt}");
    }

    /// <summary>尝试获取调用方来源信息</summary>
    private static string TryGetCallerSource()
    {
        try
        {
            var frame = new System.Diagnostics.StackTrace(2, false).GetFrame(0);
            var method = frame?.GetMethod();
            if (method == null) return string.Empty;
            return $"{method.DeclaringType?.Name}.{method.Name}";
        }
        catch { return string.Empty; }
    }

    #endregion
}
