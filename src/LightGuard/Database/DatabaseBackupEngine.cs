// © 2026 落尘（Luochen） 原创开发 - 保留所有权利

using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using LightGuard.Core;
using LightGuard.Native;

namespace LightGuard.Database;

/// <summary>
/// 支持的数据库类型
/// </summary>
public enum DatabaseType
{
    /// <summary>SQLite 本地数据库</summary>
    SQLite,

    /// <summary>MySQL 数据库</summary>
    MySQL,

    /// <summary>MariaDB 数据库</summary>
    MariaDB,

    /// <summary>Microsoft SQL Server 数据库</summary>
    SqlServer,

    /// <summary>Microsoft Access 数据库</summary>
    Access
}

/// <summary>
/// 数据库备份模式
/// </summary>
public enum BackupMode
{
    /// <summary>完整备份</summary>
    Full,

    /// <summary>单表备份</summary>
    SingleTable,

    /// <summary>事务日志备份（仅 SqlServer）</summary>
    TransactionLog
}

/// <summary>
/// 数据库备份进度信息
/// </summary>
public sealed class DatabaseBackupProgress
{
    /// <summary>进度百分比（0-100）</summary>
    public int Percent { get; set; }

    /// <summary>当前处理的表名</summary>
    public string CurrentTable { get; set; } = string.Empty;

    /// <summary>总表数</summary>
    public int TotalTables { get; set; }

    /// <summary>处理速度（MB/s）</summary>
    public double SpeedMBps { get; set; }

    /// <summary>当前状态描述</summary>
    public string Status { get; set; } = string.Empty;
}

/// <summary>
/// 数据库备份结果
/// </summary>
public sealed class DatabaseBackupResult
{
    /// <summary>是否成功</summary>
    public bool Success { get; set; }

    /// <summary>备份文件路径</summary>
    public string? BackupPath { get; set; }

    /// <summary>结果消息</summary>
    public string Message { get; set; } = string.Empty;

    /// <summary>备份大小（字节）</summary>
    public long SizeBytes { get; set; }

    /// <summary>耗时</summary>
    public TimeSpan Duration { get; set; }

    /// <summary>原始数据 SHA256 哈希</summary>
    public string? Hash { get; set; }
}

/// <summary>
/// 多数据库备份引擎
/// <para>支持 SQLite / MySQL / MariaDB / SqlServer / Access 五种数据库类型，</para>
/// <para>所有备份包使用 AES-256-GCM 加密，支持热备份、完整性校验与自动修复。</para>
/// </summary>
public sealed class DatabaseBackupEngine
{
    #region 常量

    /// <summary>私有文件头魔数 "LDBK" = 0x4C44424B</summary>
    private const uint MAGIC = 0x4C44424B;

    /// <summary>备份文件格式版本号</summary>
    private const ushort CURRENT_VERSION = 1;

    /// <summary>文件头总长度</summary>
    private const int HeaderSize = 4 + 2 + 8 + 1 + 1 + 32 + 12 + 16 + 8;

    /// <summary>AES-256 密钥长度（字节）</summary>
    private const int AesKeySize = 32;

    /// <summary>GCM Nonce 长度</summary>
    private const int NonceSize = 12;

    /// <summary>GCM 认证标签长度</summary>
    private const int TagSize = 16;

    /// <summary>文件复制缓冲区大小（64KB）</summary>
    private const int CopyBufferSize = 64 * 1024;

    /// <summary>密钥文件名</summary>
    private const string KeyFileName = "dbbackup.key";

    #endregion

    #region 字段

    private readonly string _dataDir;
    private readonly string _keyPath;
    private byte[]? _aesKey;
    private readonly object _lock = new();

    #endregion

    #region 事件

    /// <summary>
    /// 备份进度变更事件
    /// </summary>
    public event Action<DatabaseBackupProgress>? ProgressChanged;

    #endregion

    #region 构造函数

    /// <summary>
    /// 创建数据库备份引擎实例
    /// </summary>
    public DatabaseBackupEngine()
    {
        _dataDir = ConfigManager.GetDataDir();
        _keyPath = Path.Combine(_dataDir, KeyFileName);
    }

    #endregion

    #region 公开方法 - 备份

    /// <summary>
    /// 备份指定数据库
    /// </summary>
    /// <param name="dbType">数据库类型</param>
    /// <param name="connStr">连接字符串</param>
    /// <param name="destDir">备份目标目录</param>
    /// <param name="mode">备份模式</param>
    /// <param name="tableName">单表备份时的表名（mode=SingleTable 时必填）</param>
    /// <returns>备份结果（包含加密备份文件路径）</returns>
    public DatabaseBackupResult BackupDatabase(
        DatabaseType dbType,
        string connStr,
        string destDir,
        BackupMode mode = BackupMode.Full,
        string? tableName = null)
    {
        var result = new DatabaseBackupResult();
        var sw = Stopwatch.StartNew();

        try
        {
            lock (_lock)
            {
                _aesKey ??= EnsureKey();
            }

            Directory.CreateDirectory(destDir);

            var timestamp = DateTime.Now;
            var ext = dbType switch
            {
                DatabaseType.SQLite => ".sqlite",
                DatabaseType.MySQL => ".mysql",
                DatabaseType.MariaDB => ".mariadb",
                DatabaseType.SqlServer => ".sqlserver",
                DatabaseType.Access => ".access",
                _ => ".db"
            };
            var backupName = $"dbbackup_{dbType}_{timestamp:yyyyMMdd_HHmmss}{ext}.enc";
            var backupPath = Path.Combine(destDir, backupName);

            ReportProgress(0, string.Empty, 0, "正在准备备份...");

            // 获取原始备份数据
            byte[] rawData;
            switch (dbType)
            {
                case DatabaseType.SQLite:
                    rawData = BackupSqlite(connStr);
                    break;
                case DatabaseType.MySQL:
                case DatabaseType.MariaDB:
                    rawData = BackupMySql(dbType, connStr, mode, tableName);
                    break;
                case DatabaseType.SqlServer:
                    rawData = BackupSqlServer(connStr, mode, tableName);
                    break;
                case DatabaseType.Access:
                    rawData = BackupAccess(connStr);
                    break;
                default:
                    result.Success = false;
                    result.Message = $"不支持的数据库类型：{dbType}";
                    return result;
            }

            if (rawData.Length == 0)
            {
                result.Success = false;
                result.Message = "备份数据为空";
                return result;
            }

            ReportProgress(60, string.Empty, 0, "正在加密备份...");

            // 计算原始数据 SHA256 哈希
            var hash = SHA256.HashData(rawData);

            // AES-256-GCM 加密
            var nonce = RandomNumberGenerator.GetBytes(NonceSize);
            var tag = new byte[TagSize];
            var cipher = new byte[rawData.Length];
            using (var aes = new AesGcm(_aesKey!, TagSize))
            {
                aes.Encrypt(nonce, rawData, cipher, tag);
            }

            ReportProgress(85, string.Empty, 0, "正在写入备份文件...");

            // 组装加密备份文件
            using (var fs = new FileStream(backupPath, FileMode.Create, FileAccess.Write, FileShare.None))
            using (var bw = new BinaryWriter(fs, Encoding.UTF8, leaveOpen: true))
            {
                bw.Write(MAGIC);                    // 魔数 4 字节
                bw.Write(CURRENT_VERSION);          // 版本号 2 字节
                bw.Write(timestamp.ToBinary());     // 时间戳 8 字节
                bw.Write((byte)dbType);             // 数据库类型 1 字节
                bw.Write((byte)mode);               // 备份模式 1 字节
                bw.Write(hash);                     // 原始数据 SHA256 32 字节
                bw.Write(nonce);                    // GCM Nonce 12 字节
                bw.Write(tag);                      // GCM Tag 16 字节
                bw.Write((long)rawData.Length);     // 数据长度 8 字节
                bw.Write(cipher);                   // 密文
            }

            sw.Stop();
            result.Success = true;
            result.BackupPath = backupPath;
            result.SizeBytes = new FileInfo(backupPath).Length;
            result.Duration = sw.Elapsed;
            result.Hash = BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
            result.Message = $"{dbType} 数据库备份成功";

            ReportProgress(100, string.Empty, 0, "备份完成");

            // 审计日志
            AuditLogSystem.LogInfo(LogCategory.Database,
                $"数据库备份完成：{dbType}",
                $"路径={backupPath}, 大小={result.SizeBytes}B, 耗时={sw.Elapsed.TotalSeconds:F1}s");
        }
        catch (Exception ex)
        {
            result.Success = false;
            result.Message = $"备份失败：{ex.Message}";
            ErrorReporter.Report(ex, $"数据库备份失败（{dbType}）");
            AuditLogSystem.LogError(LogCategory.Database, $"数据库备份失败：{dbType}", ex.Message);
        }

        return result;
    }

    #endregion

    #region 公开方法 - 还原

    /// <summary>
    /// 从加密备份文件还原数据库
    /// </summary>
    /// <param name="dbType">数据库类型</param>
    /// <param name="connStr">目标数据库连接字符串</param>
    /// <param name="backupPath">加密备份文件路径</param>
    /// <param name="password">备份文件解密密码（当前版本使用 DPAPI 本地密钥，此参数预留）</param>
    /// <returns>是否还原成功</returns>
    public bool RestoreDatabase(DatabaseType dbType, string connStr, string backupPath, string? password = null)
    {
        try
        {
            lock (_lock)
            {
                _aesKey ??= EnsureKey();
            }

            if (!File.Exists(backupPath))
            {
                ErrorReporter.Log($"还原失败：备份文件不存在 {backupPath}", "ERROR");
                return false;
            }

            ReportProgress(0, string.Empty, 0, "正在读取备份文件...");

            // 读取并解密备份文件
            var (rawData, header) = ReadAndDecryptBackup(backupPath);
            if (rawData == null || header == null)
            {
                ErrorReporter.Log($"还原失败：备份文件解密失败 {backupPath}", "ERROR");
                return false;
            }

            // 完整性校验
            ReportProgress(20, string.Empty, 0, "正在校验完整性...");
            var currentHash = SHA256.HashData(rawData);
            if (!ConstantTimeEquals(currentHash, header.BodyHash))
            {
                ErrorReporter.Log($"还原失败：备份文件哈希校验失败 {backupPath}", "ERROR");
                AuditLogSystem.LogError(LogCategory.Database, "数据库还原校验失败", backupPath);
                return false;
            }

            ReportProgress(40, string.Empty, 0, "正在还原数据库...");

            // 根据数据库类型执行还原
            bool success;
            switch (header.DbType)
            {
                case DatabaseType.SQLite:
                    success = RestoreSqlite(connStr, rawData);
                    break;
                case DatabaseType.MySQL:
                case DatabaseType.MariaDB:
                    success = RestoreMySql(header.DbType, connStr, rawData);
                    break;
                case DatabaseType.SqlServer:
                    success = RestoreSqlServer(connStr, rawData);
                    break;
                case DatabaseType.Access:
                    success = RestoreAccess(connStr, rawData);
                    break;
                default:
                    ErrorReporter.Log($"还原失败：不支持的数据库类型 {header.DbType}", "ERROR");
                    return false;
            }

            ReportProgress(100, string.Empty, 0, success ? "还原完成" : "还原失败");

            if (success)
            {
                AuditLogSystem.LogInfo(LogCategory.Database,
                    $"数据库还原完成：{header.DbType}",
                    $"备份文件={backupPath}");
            }

            return success;
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, $"数据库还原失败（{dbType}）");
            AuditLogSystem.LogError(LogCategory.Database, $"数据库还原失败：{dbType}", ex.Message);
            return false;
        }
    }

    #endregion

    #region 公开方法 - 完整性校验

    /// <summary>
    /// 校验加密备份文件的完整性（魔数 + GCM 标签 + SHA256 哈希）
    /// </summary>
    /// <param name="backupPath">备份文件路径</param>
    /// <returns>是否通过完整性校验</returns>
    public bool VerifyBackup(string backupPath)
    {
        try
        {
            lock (_lock)
            {
                _aesKey ??= EnsureKey();
            }

            var (rawData, header) = ReadAndDecryptBackup(backupPath);
            if (rawData == null || header == null) return false;

            // SHA256 哈希校验
            var currentHash = SHA256.HashData(rawData);
            return ConstantTimeEquals(currentHash, header.BodyHash);
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// 尝试自动修复轻微损坏的备份文件
    /// <para>对于 GCM 标签验证失败但文件头完整的情况，尝试截断末尾可能损坏的数据。</para>
    /// </summary>
    /// <param name="backupPath">备份文件路径</param>
    /// <returns>是否修复成功</returns>
    public bool TryRepairBackup(string backupPath)
    {
        try
        {
            lock (_lock)
            {
                _aesKey ??= EnsureKey();
            }

            if (!File.Exists(backupPath)) return false;

            using var fs = new FileStream(backupPath, FileMode.Open, FileAccess.Read, FileShare.Read);
            if (fs.Length < HeaderSize) return false;

            using var br = new BinaryReader(fs, Encoding.UTF8, leaveOpen: true);
            var magic = br.ReadUInt32();
            if (magic != MAGIC) return false;

            var version = br.ReadUInt16();
            var timestamp = DateTime.FromBinary(br.ReadInt64());
            var dbType = (DatabaseType)br.ReadByte();
            var mode = (BackupMode)br.ReadByte();
            var hash = br.ReadBytes(32);
            var nonce = br.ReadBytes(NonceSize);
            var tag = br.ReadBytes(TagSize);
            var dataLen = br.ReadInt64();

            long expectedLen = HeaderSize + dataLen;
            if (fs.Length == expectedLen)
            {
                // 文件长度正确，尝试正常解密
                var cipher = br.ReadBytes((int)dataLen);
                var plain = new byte[dataLen];
                try
                {
                    using var aes = new AesGcm(_aesKey!, TagSize);
                    aes.Decrypt(nonce, cipher, tag, plain);
                    var currentHash = SHA256.HashData(plain);
                    return ConstantTimeEquals(currentHash, hash);
                }
                catch
                {
                    return false;
                }
            }

            // 文件长度不匹配，尝试截断到预期长度后重新解密
            if (fs.Length > expectedLen)
            {
                // 读取预期长度的密文
                fs.Position = HeaderSize;
                var cipher = new byte[dataLen];
                fs.ReadExactly(cipher);

                var plain = new byte[dataLen];
                try
                {
                    using var aes = new AesGcm(_aesKey!, TagSize);
                    aes.Decrypt(nonce, cipher, tag, plain);
                    var currentHash = SHA256.HashData(plain);
                    if (ConstantTimeEquals(currentHash, hash))
                    {
                        // 截断文件到正确长度
                        using var fsTrunc = new FileStream(backupPath, FileMode.Open, FileAccess.Write, FileShare.None);
                        fsTrunc.SetLength(expectedLen);
                        return true;
                    }
                }
                catch { }
            }

            return false;
        }
        catch
        {
            return false;
        }
    }

    #endregion

    #region SQLite 备份/还原

    /// <summary>
    /// SQLite 备份：直接复制数据库文件（支持 VSS 快照场景下的共享读取）
    /// </summary>
    private byte[] BackupSqlite(string connStr)
    {
        var dbPath = ExtractConnectionStringValue(connStr, "Data Source");
        if (string.IsNullOrEmpty(dbPath))
            throw new InvalidOperationException("SQLite 连接字符串中缺少 Data Source");

        if (!File.Exists(dbPath))
            throw new FileNotFoundException($"SQLite 数据库文件不存在：{dbPath}");

        var fileInfo = new FileInfo(dbPath);
        var totalBytes = fileInfo.Length;
        var copied = 0L;
        var sw = Stopwatch.StartNew();

        using var ms = new MemoryStream();
        // 使用 FileShare.ReadWrite 支持热备份（数据库正在使用时也能读取）
        using (var src = new FileStream(dbPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
        {
            var buffer = new byte[CopyBufferSize];
            int read;
            while ((read = src.Read(buffer, 0, buffer.Length)) > 0)
            {
                ms.Write(buffer, 0, read);
                copied += read;

                var percent = (int)(copied * 50 / totalBytes);
                var speed = copied / 1024.0 / 1024.0 / sw.Elapsed.TotalSeconds;
                ReportProgress(percent, "SQLite", 1, $"正在复制数据库文件... {copied / 1024}KB / {totalBytes / 1024}KB");
            }
        }

        return ms.ToArray();
    }

    /// <summary>
    /// SQLite 还原：将解密数据写回数据库文件
    /// </summary>
    private bool RestoreSqlite(string connStr, byte[] data)
    {
        var dbPath = ExtractConnectionStringValue(connStr, "Data Source");
        if (string.IsNullOrEmpty(dbPath))
        {
            ErrorReporter.Log("SQLite 还原失败：连接字符串中缺少 Data Source", "ERROR");
            return false;
        }

        var dir = Path.GetDirectoryName(dbPath);
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);

        File.WriteAllBytes(dbPath, data);

        // 尝试完整性检查与自动修复（需要 SQLite 提供程序）
        TrySqliteIntegrityCheck(dbPath);

        return true;
    }

    /// <summary>
    /// 尝试对 SQLite 数据库执行完整性检查与自动修复
    /// </summary>
    private void TrySqliteIntegrityCheck(string dbPath)
    {
        // 未引入 SQLite 提供程序包，完整性检查在此版本中跳过
        // 如需启用，请安装 Microsoft.Data.Sqlite 并在此处实现 PRAGMA integrity_check
        try
        {
            if (!File.Exists(dbPath)) return;
            // 简单文件头校验（SQLite 文件头以 "SQLite format 3\0" 开头）
            using var fs = new FileStream(dbPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            var header = new byte[16];
            if (fs.Read(header, 0, 16) == 16)
            {
                var magic = Encoding.ASCII.GetString(header, 0, 15);
                if (magic != "SQLite format 3")
                {
                    ErrorReporter.Log($"SQLite 文件头校验失败，文件可能损坏：{dbPath}", "WARN");
                    AuditLogSystem.LogWarning(LogCategory.Database,
                        "SQLite 文件头校验失败",
                        $"文件={dbPath}");
                }
            }
        }
        catch { }
    }

    #endregion

    #region MySQL/MariaDB 备份/还原

    /// <summary>
    /// MySQL/MariaDB 备份：调用 mysqldump 命令行工具
    /// </summary>
    private byte[] BackupMySql(DatabaseType dbType, string connStr, BackupMode mode, string? tableName)
    {
        var p = ParseMySqlConnection(connStr);
        var toolName = dbType == DatabaseType.MariaDB ? "mariadb-dump" : "mysqldump";

        var args = new StringBuilder();
        args.Append($"--host={p.Host}");
        args.Append($" --port={p.Port}");
        args.Append($" --user={p.User}");
        if (!string.IsNullOrEmpty(p.Password))
            args.Append($" --password={p.Password}");
        // 热备份：使用单事务模式（InnoDB），业务无需停机
        args.Append(" --single-transaction");
        args.Append(" --routines");
        args.Append(" --triggers");
        args.Append(" --default-character-set=utf8mb4");

        if (mode == BackupMode.SingleTable && !string.IsNullOrEmpty(tableName))
        {
            args.Append($" {p.Database} {tableName}");
            ReportProgress(10, tableName!, 1, $"正在导出表 {tableName}...");
        }
        else
        {
            args.Append($" {p.Database}");
            ReportProgress(10, string.Empty, 0, $"正在导出数据库 {p.Database}...");
        }

        var output = RunProcessCapture(toolName, args.ToString());
        if (output.ExitCode != 0)
            throw new InvalidOperationException($"mysqldump 失败（退出码 {output.ExitCode}）：{output.Error}");

        ReportProgress(50, string.Empty, 0, "数据库导出完成");

        return Encoding.UTF8.GetBytes(output.Output);
    }

    /// <summary>
    /// MySQL/MariaDB 还原：将 SQL 脚本通过 mysql 命令导入
    /// </summary>
    private bool RestoreMySql(DatabaseType dbType, string connStr, byte[] data)
    {
        var p = ParseMySqlConnection(connStr);
        var toolName = dbType == DatabaseType.MariaDB ? "mariadb" : "mysql";

        var args = new StringBuilder();
        args.Append($"--host={p.Host}");
        args.Append($" --port={p.Port}");
        args.Append($" --user={p.User}");
        if (!string.IsNullOrEmpty(p.Password))
            args.Append($" --password={p.Password}");
        args.Append($" --default-character-set=utf8mb4");
        args.Append($" {p.Database}");

        var sqlScript = Encoding.UTF8.GetString(data);

        var result = RunProcessWithStdin(toolName, args.ToString(), sqlScript);
        if (result.ExitCode != 0)
        {
            ErrorReporter.Log($"MySQL 还原失败（退出码 {result.ExitCode}）：{result.Error}", "ERROR");
            return false;
        }

        return true;
    }

    #endregion

    #region SqlServer 备份/还原

    /// <summary>
    /// SqlServer 备份：通过 sqlcmd 执行 T-SQL BACKUP 命令
    /// </summary>
    private byte[] BackupSqlServer(string connStr, BackupMode mode, string? tableName)
    {
        var p = ParseSqlServerConnection(connStr);
        var tempPath = Path.Combine(Path.GetTempPath(), $"lg_sqlserver_{DateTime.Now:yyyyMMdd_HHmmss}.bak");

        var sql = new StringBuilder();
        if (mode == BackupMode.TransactionLog)
        {
            sql.Append($"BACKUP LOG [{p.Database}] TO DISK = '{tempPath}' WITH FORMAT, INIT, COMPRESSION;");
            ReportProgress(10, string.Empty, 0, $"正在备份事务日志 {p.Database}...");
        }
        else if (mode == BackupMode.SingleTable && !string.IsNullOrEmpty(tableName))
        {
            // SqlServer 不支持单表 BACKUP，改用 BCP 导出
            return BackupSqlServerTable(p, tableName!);
        }
        else
        {
            sql.Append($"BACKUP DATABASE [{p.Database}] TO DISK = '{tempPath}' WITH FORMAT, INIT, COMPRESSION;");
            ReportProgress(10, string.Empty, 0, $"正在备份数据库 {p.Database}...");
        }

        var args = BuildSqlCmdArgs(p, sql.ToString());
        var result = RunProcessCapture("sqlcmd", args);

        if (result.ExitCode != 0)
            throw new InvalidOperationException($"sqlcmd BACKUP 失败（退出码 {result.ExitCode}）：{result.Error}");

        ReportProgress(40, string.Empty, 0, "T-SQL 备份命令执行完成，正在读取备份文件...");

        if (!File.Exists(tempPath))
            throw new InvalidOperationException("SqlServer 备份文件未生成");

        var data = File.ReadAllBytes(tempPath);

        // 清理临时文件
        try { File.Delete(tempPath); } catch { }

        ReportProgress(50, string.Empty, 0, "备份文件读取完成");

        return data;
    }

    /// <summary>
    /// SqlServer 单表备份：使用 BCP 导出表数据
    /// </summary>
    private byte[] BackupSqlServerTable(SqlServerConnInfo p, string tableName)
    {
        ReportProgress(10, tableName, 1, $"正在导出表 {tableName}...");
        var tempPath = Path.Combine(Path.GetTempPath(), $"lg_sqlserver_table_{tableName}_{DateTime.Now:yyyyMMdd_HHmmss}.dat");

        var args = new StringBuilder();
        args.Append($"-S \"{p.Server},{p.Port}\"");
        args.Append($" -U \"{p.User}\"");
        args.Append($" -P \"{p.Password}\"");
        args.Append($" -d \"{p.Database}\"");
        args.Append($" -c");  // 字符模式
        args.Append($" -t \"\\t\"");  // 制表符分隔
        args.Append($" -r \"\\n\"");  // 换行符
        args.Append($" out \"{tempPath}\"");
        args.Append($" \"{tableName}\"");

        var result = RunProcessCapture("bcp", args.ToString());
        if (result.ExitCode != 0)
            throw new InvalidOperationException($"BCP 导出失败（退出码 {result.ExitCode}）：{result.Error}");

        if (!File.Exists(tempPath))
            throw new InvalidOperationException("BCP 导出文件未生成");

        var data = File.ReadAllBytes(tempPath);
        try { File.Delete(tempPath); } catch { }

        return data;
    }

    /// <summary>
    /// SqlServer 还原：通过 sqlcmd 执行 T-SQL RESTORE 命令
    /// </summary>
    private bool RestoreSqlServer(string connStr, byte[] data)
    {
        var p = ParseSqlServerConnection(connStr);
        var tempPath = Path.Combine(Path.GetTempPath(), $"lg_sqlserver_restore_{DateTime.Now:yyyyMMdd_HHmmss}.bak");

        // 写入临时备份文件
        File.WriteAllBytes(tempPath, data);

        ReportProgress(60, string.Empty, 0, "正在执行 RESTORE 命令...");

        var sql = $"RESTORE DATABASE [{p.Database}] FROM DISK = '{tempPath}' WITH REPLACE, RECOVERY;";
        var args = BuildSqlCmdArgs(p, sql);
        var result = RunProcessCapture("sqlcmd", args);

        // 清理临时文件
        try { File.Delete(tempPath); } catch { }

        if (result.ExitCode != 0)
        {
            ErrorReporter.Log($"SqlServer 还原失败（退出码 {result.ExitCode}）：{result.Error}", "ERROR");
            return false;
        }

        return true;
    }

    /// <summary>构建 sqlcmd 命令行参数</summary>
    private static string BuildSqlCmdArgs(SqlServerConnInfo p, string sql)
    {
        var sb = new StringBuilder();
        sb.Append($"-S \"{p.Server},{p.Port}\"");
        sb.Append($" -U \"{p.User}\"");
        sb.Append($" -P \"{p.Password}\"");
        sb.Append($" -Q \"{sql}\"");
        sb.Append(" -b");  // 出错时返回非零退出码
        return sb.ToString();
    }

    #endregion

    #region Access 备份/还原

    /// <summary>
    /// Access 备份：直接复制 mdb/accdb 文件
    /// </summary>
    private byte[] BackupAccess(string connStr)
    {
        var dbPath = ExtractConnectionStringValue(connStr, "Data Source");
        if (string.IsNullOrEmpty(dbPath))
            throw new InvalidOperationException("Access 连接字符串中缺少 Data Source");

        if (!File.Exists(dbPath))
            throw new FileNotFoundException($"Access 数据库文件不存在：{dbPath}");

        var fileInfo = new FileInfo(dbPath);
        var totalBytes = fileInfo.Length;
        var copied = 0L;
        var sw = Stopwatch.StartNew();

        using var ms = new MemoryStream();
        using (var src = new FileStream(dbPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
        {
            var buffer = new byte[CopyBufferSize];
            int read;
            while ((read = src.Read(buffer, 0, buffer.Length)) > 0)
            {
                ms.Write(buffer, 0, read);
                copied += read;
                var percent = (int)(copied * 50 / totalBytes);
                ReportProgress(percent, "Access", 1, $"正在复制数据库文件... {copied / 1024}KB / {totalBytes / 1024}KB");
            }
        }

        return ms.ToArray();
    }

    /// <summary>
    /// Access 还原：将解密数据写回数据库文件
    /// </summary>
    private bool RestoreAccess(string connStr, byte[] data)
    {
        var dbPath = ExtractConnectionStringValue(connStr, "Data Source");
        if (string.IsNullOrEmpty(dbPath))
        {
            ErrorReporter.Log("Access 还原失败：连接字符串中缺少 Data Source", "ERROR");
            return false;
        }

        var dir = Path.GetDirectoryName(dbPath);
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);

        File.WriteAllBytes(dbPath, data);
        return true;
    }

    #endregion

    #region 加密文件读写

    /// <summary>备份文件头</summary>
    private sealed class BackupHeader
    {
        public uint Magic { get; set; }
        public ushort Version { get; set; }
        public DateTime Timestamp { get; set; }
        public DatabaseType DbType { get; set; }
        public BackupMode Mode { get; set; }
        public byte[] BodyHash { get; set; } = Array.Empty<byte>();
        public byte[] Nonce { get; set; } = Array.Empty<byte>();
        public byte[] Tag { get; set; } = Array.Empty<byte>();
        public long DataLength { get; set; }
    }

    /// <summary>
    /// 读取并解密备份文件
    /// </summary>
    private (byte[]? data, BackupHeader? header) ReadAndDecryptBackup(string backupPath)
    {
        try
        {
            using var fs = new FileStream(backupPath, FileMode.Open, FileAccess.Read, FileShare.Read);
            if (fs.Length < HeaderSize) return (null, null);

            using var br = new BinaryReader(fs, Encoding.UTF8, leaveOpen: true);
            var header = new BackupHeader
            {
                Magic = br.ReadUInt32(),
                Version = br.ReadUInt16(),
                Timestamp = DateTime.FromBinary(br.ReadInt64()),
                DbType = (DatabaseType)br.ReadByte(),
                Mode = (BackupMode)br.ReadByte(),
                BodyHash = br.ReadBytes(32),
                Nonce = br.ReadBytes(NonceSize),
                Tag = br.ReadBytes(TagSize),
                DataLength = br.ReadInt64()
            };

            if (header.Magic != MAGIC) return (null, null);
            if (header.DataLength <= 0 || header.DataLength > fs.Length) return (null, null);

            var cipher = br.ReadBytes((int)header.DataLength);
            if (cipher.Length < header.DataLength) return (null, null);

            var plain = new byte[header.DataLength];
            using var aes = new AesGcm(_aesKey!, TagSize);
            aes.Decrypt(header.Nonce, cipher, header.Tag, plain);

            return (plain, header);
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, $"读取解密备份文件失败：{backupPath}");
            return (null, null);
        }
    }

    #endregion

    #region AES-256-GCM 密钥管理（DPAPI 保护）

    /// <summary>确保存在 AES-256 密钥</summary>
    private byte[] EnsureKey()
    {
        var existing = LoadKey();
        if (existing != null && existing.Length == AesKeySize) return existing;

        var key = RandomNumberGenerator.GetBytes(AesKeySize);
        SaveKey(key);
        return key;
    }

    /// <summary>使用 DPAPI 保护密钥并保存</summary>
    private void SaveKey(byte[] key)
    {
        try
        {
            var protectedKey = ProtectedData.Protect(key, null, DataProtectionScope.CurrentUser);
            File.WriteAllBytes(_keyPath, protectedKey);
            Win32.SetFileAsSystemHidden(_keyPath);
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, "保存数据库备份密钥失败");
        }
    }

    /// <summary>从本地读取并用 DPAPI 解密密钥</summary>
    private byte[]? LoadKey()
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

    #region 进程执行

    /// <summary>运行外部进程并捕获标准输出</summary>
    private (int ExitCode, string Output, string Error) RunProcessCapture(string fileName, string args)
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = fileName,
                Arguments = args,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
                StandardOutputEncoding = Encoding.UTF8,
                StandardErrorEncoding = Encoding.UTF8
            };

            using var proc = Process.Start(psi);
            if (proc == null) return (-1, string.Empty, "无法启动进程");

            var output = proc.StandardOutput.ReadToEnd();
            var error = proc.StandardError.ReadToEnd();
            proc.WaitForExit();

            return (proc.ExitCode, output, error);
        }
        catch (Exception ex)
        {
            return (-1, string.Empty, ex.Message);
        }
    }

    /// <summary>运行外部进程并通过标准输入传入数据</summary>
    private (int ExitCode, string Output, string Error) RunProcessWithStdin(string fileName, string args, string stdin)
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = fileName,
                Arguments = args,
                UseShellExecute = false,
                RedirectStandardInput = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
                StandardOutputEncoding = Encoding.UTF8,
                StandardErrorEncoding = Encoding.UTF8
            };

            using var proc = Process.Start(psi);
            if (proc == null) return (-1, string.Empty, "无法启动进程");

            proc.StandardInput.Write(stdin);
            proc.StandardInput.Close();

            var output = proc.StandardOutput.ReadToEnd();
            var error = proc.StandardError.ReadToEnd();
            proc.WaitForExit();

            return (proc.ExitCode, output, error);
        }
        catch (Exception ex)
        {
            return (-1, string.Empty, ex.Message);
        }
    }

    #endregion

    #region 连接字符串解析

    /// <summary>从连接字符串中提取指定键的值</summary>
    private static string ExtractConnectionStringValue(string connStr, string key)
    {
        var pairs = connStr.Split(';', StringSplitOptions.RemoveEmptyEntries);
        foreach (var pair in pairs)
        {
            var idx = pair.IndexOf('=');
            if (idx > 0)
            {
                var k = pair.Substring(0, idx).Trim();
                var v = pair.Substring(idx + 1).Trim();
                if (string.Equals(k, key, StringComparison.OrdinalIgnoreCase))
                    return v.Trim('"', '\'');
            }
        }
        return string.Empty;
    }

    /// <summary>MySQL 连接参数</summary>
    private sealed class MySqlConnInfo
    {
        public string Host { get; set; } = "localhost";
        public int Port { get; set; } = 3306;
        public string Database { get; set; } = "";
        public string User { get; set; } = "";
        public string Password { get; set; } = "";
    }

    /// <summary>SqlServer 连接参数</summary>
    private sealed class SqlServerConnInfo
    {
        public string Server { get; set; } = "localhost";
        public int Port { get; set; } = 1433;
        public string Database { get; set; } = "";
        public string User { get; set; } = "";
        public string Password { get; set; } = "";
    }

    /// <summary>解析 MySQL/MariaDB 连接字符串</summary>
    private static MySqlConnInfo ParseMySqlConnection(string connStr)
    {
        var info = new MySqlConnInfo();
        info.Host = ExtractConnectionStringValue(connStr, "Server");
        if (string.IsNullOrEmpty(info.Host)) info.Host = ExtractConnectionStringValue(connStr, "Host");

        var portStr = ExtractConnectionStringValue(connStr, "Port");
        if (int.TryParse(portStr, out var port)) info.Port = port;

        info.Database = ExtractConnectionStringValue(connStr, "Database");
        if (string.IsNullOrEmpty(info.Database)) info.Database = ExtractConnectionStringValue(connStr, "db");

        info.User = ExtractConnectionStringValue(connStr, "Uid");
        if (string.IsNullOrEmpty(info.User)) info.User = ExtractConnectionStringValue(connStr, "User Id");
        if (string.IsNullOrEmpty(info.User)) info.User = ExtractConnectionStringValue(connStr, "User");

        info.Password = ExtractConnectionStringValue(connStr, "Pwd");
        if (string.IsNullOrEmpty(info.Password)) info.Password = ExtractConnectionStringValue(connStr, "Password");

        return info;
    }

    /// <summary>解析 SqlServer 连接字符串</summary>
    private static SqlServerConnInfo ParseSqlServerConnection(string connStr)
    {
        var info = new SqlServerConnInfo();
        var server = ExtractConnectionStringValue(connStr, "Server");
        if (string.IsNullOrEmpty(server)) server = ExtractConnectionStringValue(connStr, "Data Source");

        // Server 可能包含端号：server,port
        if (server.Contains(','))
        {
            var parts = server.Split(',', 2);
            info.Server = parts[0].Trim();
            if (int.TryParse(parts[1].Trim(), out var port)) info.Port = port;
        }
        else
        {
            info.Server = server;
        }

        info.Database = ExtractConnectionStringValue(connStr, "Database");
        if (string.IsNullOrEmpty(info.Database)) info.Database = ExtractConnectionStringValue(connStr, "Initial Catalog");

        info.User = ExtractConnectionStringValue(connStr, "User Id");
        if (string.IsNullOrEmpty(info.User)) info.User = ExtractConnectionStringValue(connStr, "Uid");

        info.Password = ExtractConnectionStringValue(connStr, "Password");
        if (string.IsNullOrEmpty(info.Password)) info.Password = ExtractConnectionStringValue(connStr, "Pwd");

        return info;
    }

    #endregion

    #region 辅助方法

    /// <summary>报告进度</summary>
    private void ReportProgress(int percent, string currentTable, int totalTables, string status)
    {
        ProgressChanged?.Invoke(new DatabaseBackupProgress
        {
            Percent = percent,
            CurrentTable = currentTable,
            TotalTables = totalTables,
            Status = status
        });
    }

    /// <summary>常量时间字节比较（防时序攻击）</summary>
    private static bool ConstantTimeEquals(byte[] a, byte[] b)
    {
        if (a.Length != b.Length) return false;
        int diff = 0;
        for (int i = 0; i < a.Length; i++) diff |= a[i] ^ b[i];
        return diff == 0;
    }

    #endregion
}
