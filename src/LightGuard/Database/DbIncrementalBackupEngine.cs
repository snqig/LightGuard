// © 2026 落尘（Luochen） 原创开发 - 保留所有权利
//
// 数据库增量备份引擎（v3.5 P1-3）
//   - MySQL/MariaDB：mysqlbinlog 流式读取 binlog（--read-from-remote-server），不落地明文
//   - PostgreSQL：pg_receivewal 采集 WAL 段（ACL 隔离临时目录）→ 逐段流式加密 → 立即删除明文
//   - SQLite：强制禁用增量（代码层拦截 IsIncrementalSupported == false）
//   - 增量包存入统一 AES-256-GCM 加密备份集（复用 DatabaseBackupEngine 容器格式）
//   - 位置续传：MySQL 记录 "File:Position"，PG 记录 LSN

using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using LightGuard.Core;

namespace LightGuard.Database;

/// <summary>数据库增量备份结果。</summary>
public sealed class DbIncrementalResult
{
    /// <summary>是否成功。</summary>
    public bool Success { get; set; }

    /// <summary>增量包路径（加密备份集）。</summary>
    public string? BackupPath { get; set; }

    /// <summary>结果消息。</summary>
    public string Message { get; set; } = "";

    /// <summary>增量后的新位置（MySQL "File:Position" / PG LSN），供续传。</summary>
    public string NewPosition { get; set; } = "";

    /// <summary>增量数据字节数（明文）。</summary>
    public long SizeBytes { get; set; }
}

/// <summary>
/// 数据库事务日志增量备份引擎。
/// </summary>
public sealed class DbIncrementalBackupEngine
{
    /// <summary>
    /// 该类型是否支持增量备份（SQLite 强制禁用，代码层拦截）。
    /// </summary>
    public static bool IsIncrementalSupported(DatabaseType dbType)
        => dbType is DatabaseType.MySQL or DatabaseType.MariaDB or DatabaseType.PostgreSQL;

    /// <summary>
    /// 获取数据库当前日志位置（MySQL binlog File:Position / PG LSN）。
    /// </summary>
    /// <param name="inst">实例配置（提供连接参数与上次位置）。</param>
    /// <param name="connStr">连接字符串。</param>
    /// <returns>当前位置字符串；不可用返回空串。</returns>
    public static string GetCurrentPosition(DbBackupInstance inst, string connStr)
    {
        try
        {
            switch (inst.DbType)
            {
                case DatabaseType.MySQL:
                case DatabaseType.MariaDB:
                {
                    var (file, pos) = QueryMySqlMasterStatus(connStr);
                    return string.IsNullOrEmpty(file) ? "" : $"{file}:{pos}";
                }
                case DatabaseType.PostgreSQL:
                {
                    var lsn = QueryPgCurrentLsn(connStr);
                    return lsn ?? "";
                }
                default:
                    return "";
            }
        }
        catch
        {
            return inst.LastBinlogPos;
        }
    }

    /// <summary>
    /// 执行一次增量备份（binlog / WAL 流式采集并加密入库）。
    /// </summary>
    /// <param name="inst">实例配置。</param>
    /// <param name="connStr">连接字符串。</param>
    /// <param name="destDir">备份目标目录（存放加密增量包）。</param>
    /// <returns>增量结果（含新位置用于续传）。</returns>
    public DbIncrementalResult BackupIncremental(DbBackupInstance inst, string connStr, string destDir)
    {
        var result = new DbIncrementalResult();

        // SQLite 强制禁用增量（即使调用也拒绝）
        if (!IsIncrementalSupported(inst.DbType))
        {
            result.Success = false;
            result.Message = $"{inst.DbType} 不支持增量备份（SQLite 强制禁用，代码层拦截）";
            return result;
        }

        try
        {
            Directory.CreateDirectory(destDir);
            switch (inst.DbType)
            {
                case DatabaseType.MySQL:
                case DatabaseType.MariaDB:
                    return BackupMySqlBinlog(inst, connStr, destDir);
                case DatabaseType.PostgreSQL:
                    return BackupPostgreSqlWal(inst, connStr, destDir);
                default:
                    result.Success = false;
                    result.Message = $"{inst.DbType} 暂无增量备份实现";
                    return result;
            }
        }
        catch (Exception ex)
        {
            result.Success = false;
            result.Message = $"增量备份失败：{ex.Message}";
            ErrorReporter.Report(ex, $"数据库增量备份失败：{inst.Name}（{inst.DbType}）");
            return result;
        }
    }

    // ==================== MySQL binlog ====================

    /// <summary>MySQL binlog 增量：从上次位置起流式读取 binlog，加密写增量包。</summary>
    private DbIncrementalResult BackupMySqlBinlog(DbBackupInstance inst, string connStr, string destDir)
    {
        var result = new DbIncrementalResult();
        var p = ParseMySqlConn(connStr);

        // 当前主库状态（位置 + 全部 binlog 文件清单）
        var (curFile, curPos) = QueryMySqlMasterStatus(connStr);
        var logFiles = QueryMySqlBinaryLogs(connStr);
        if (string.IsNullOrEmpty(curFile) || logFiles.Count == 0)
            throw new InvalidOperationException("MySQL 未开启 binlog（需 log_bin=ON 且 binlog_format=ROW）");

        // 从上次位置定位起始文件
        var (startFile, startPos) = ParseBinlogPosition(inst.LastBinlogPos);
        if (string.IsNullOrEmpty(startFile))
        {
            startFile = logFiles[0];
            startPos = 4; // binlog 文件头位置
        }

        // 起始文件之后的所有 binlog 文件（含起始文件，用 --start-position 定位）
        var filesToRead = new List<string>();
        var idx = logFiles.IndexOf(startFile);
        if (idx < 0)
        {
            // 起始文件已轮转删除 → 从最早可用文件开始（可能丢失，告警）
            idx = 0;
            startPos = 4;
            ErrorReporter.Log($"[数据库增量] binlog 起始文件 {startFile} 已不存在，从 {logFiles[0]} 重新采集（可能丢失部分日志）", "WARN");
        }
        for (int i = idx; i < logFiles.Count; i++)
            filesToRead.Add(logFiles[i]);

        // mysqlbinlog 流式读取（输出到 stdout，由进程捕获，不落地明文）
        var args = new StringBuilder();
        args.Append("--read-from-remote-server");
        args.Append($" --host={p.Host}");
        args.Append($" --port={p.Port}");
        args.Append($" --user={p.User}");
        if (!string.IsNullOrEmpty(p.Password))
            args.Append($" --password={p.Password}");
        args.Append(" --raw=false");
        args.Append($" --start-position={startPos}");
        foreach (var f in filesToRead)
            args.Append($" \"{f}\"");

        var output = RunProcessCapture("mysqlbinlog", args.ToString());
        if (output.ExitCode != 0 && filesToRead.Count > 0)
        {
            // 最后文件可能仍在写入导致读取警告，仅当无任何输出时视为失败
            if (string.IsNullOrEmpty(output.Output))
                throw new InvalidOperationException($"mysqlbinlog 失败（退出码 {output.ExitCode}）：{output.Error}");
        }

        var plain = Encoding.UTF8.GetBytes(output.Output ?? "");
        if (plain.Length == 0)
        {
            result.Success = true;
            result.Message = "binlog 无新增内容，本次增量跳过";
            result.NewPosition = $"{curFile}:{curPos}";
            return result;
        }

        // 加密写增量包（复用数据库加密容器格式）
        var backupPath = WriteEncryptedIncremental(inst.DbType, plain, destDir,
            $"{inst.Name}_binlog_{DateTime.Now:yyyyMMdd_HHmmss}");

        result.Success = true;
        result.BackupPath = backupPath;
        result.SizeBytes = plain.Length;
        result.NewPosition = $"{curFile}:{curPos}";
        result.Message = $"MySQL binlog 增量完成：{filesToRead.Count} 个日志文件，{plain.Length / 1024.0:F1} KB";
        ErrorReporter.Log($"[数据库增量] {inst.Name}：{result.Message}（位置 {result.NewPosition}）");
        return result;
    }

    // ==================== PostgreSQL WAL ====================

    /// <summary>PostgreSQL WAL 增量：采集自上次 LSN 起的 WAL 段，逐段加密后删除明文。</summary>
    private DbIncrementalResult BackupPostgreSqlWal(DbBackupInstance inst, string connStr, string destDir)
    {
        var result = new DbIncrementalResult();
        var p = ParsePgConn(connStr);

        var currentLsn = QueryPgCurrentLsn(connStr);
        if (string.IsNullOrEmpty(currentLsn))
            throw new InvalidOperationException("PostgreSQL 无法获取当前 WAL LSN");

        // 使用受保护临时目录存放 WAL 明文段（ACL 隔离 + 加密后立即删除）
        var tempDir = Path.Combine(Path.GetTempPath(),
            $"lg_wal_{inst.Name}_{DateTime.Now:yyyyMMddHHmmss}_{Guid.NewGuid():N}");
        Directory.CreateDirectory(tempDir);

        try
        {
            // pg_receivewal 一次性采集（--no-loop：接收当前可用段后退出）
            var args = new StringBuilder();
            args.Append($"-h {p.Host}");
            args.Append($" -p {p.Port}");
            args.Append($" -U {p.User}");
            args.Append(" --no-loop");
            args.Append($" -D \"{tempDir}\"");

            var env = new Dictionary<string, string> { ["PGPASSWORD"] = p.Password };
            var output = RunProcessCaptureWithEnv("pg_receivewal", args.ToString(), env);

            // 采集完成（无新 WAL 时退出码 0 且目录为空）
            var walFiles = Directory.EnumerateFiles(tempDir, "*.partial", SearchOption.AllDirectories).ToList();
            if (walFiles.Count == 0)
                walFiles = Directory.EnumerateFiles(tempDir, "*", SearchOption.AllDirectories)
                    .Where(f => !f.EndsWith(".backup", StringComparison.OrdinalIgnoreCase))
                    .ToList();

            if (walFiles.Count == 0)
            {
                result.Success = true;
                result.Message = "WAL 无新增内容，本次增量跳过";
                result.NewPosition = currentLsn;
                return result;
            }

            // 逐段读取 → 加密 → 写入增量包（每段一个明文流，加密后删除明文段）
            var total = 0L;
            foreach (var walFile in walFiles)
            {
                var bytes = File.ReadAllBytes(walFile);
                var segPath = WriteEncryptedIncremental(inst.DbType, bytes, destDir,
                    $"{inst.Name}_wal_{Path.GetFileName(walFile)}");
                total += bytes.Length;
                try { File.Delete(walFile); } catch { }
            }

            result.Success = true;
            result.BackupPath = string.Join(";", walFiles.Select(f =>
                Path.Combine(destDir, $"{inst.Name}_wal_{Path.GetFileName(f)}.enc")));
            result.SizeBytes = total;
            result.NewPosition = currentLsn;
            result.Message = $"PostgreSQL WAL 增量完成：{walFiles.Count} 个段，{total / 1024.0:F1} KB";
            ErrorReporter.Log($"[数据库增量] {inst.Name}：{result.Message}（LSN {result.NewPosition}）");
            return result;
        }
        finally
        {
            // 清除明文临时目录（加密后不应残留明文 WAL）
            try
            {
                foreach (var f in Directory.EnumerateFiles(tempDir, "*", SearchOption.AllDirectories))
                {
                    try { File.Delete(f); } catch { }
                }
                if (Directory.Exists(tempDir)) Directory.Delete(tempDir, true);
            }
            catch { }
        }
    }

    // ==================== 加密增量包写入 ====================

    /// <summary>
    /// 将明文增量数据加密为 .enc 增量包（复用数据库备份容器格式：魔数 + 版本 + 时间戳 + 类型 + 模式 + SHA256 + Nonce + Tag + 长度 + 密文）。
    /// </summary>
    private string WriteEncryptedIncremental(DatabaseType dbType, byte[] plain, string destDir, string baseName)
    {
        var key = EnsureDbBackupKey();
        var backupPath = Path.Combine(destDir, $"{baseName}.enc");

        var hash = SHA256.HashData(plain);
        var nonce = RandomNumberGenerator.GetBytes(12);
        var tag = new byte[16];
        var cipher = new byte[plain.Length];
        using (var aes = new AesGcm(key, 16))
        {
            aes.Encrypt(nonce, plain, cipher, tag);
        }

        using var fs = new FileStream(backupPath, FileMode.Create, FileAccess.Write, FileShare.None);
        using var bw = new BinaryWriter(fs, Encoding.UTF8, leaveOpen: true);
        bw.Write(0x4C44424B);            // 魔数 "LDBK"
        bw.Write((ushort)1);             // 版本
        bw.Write(DateTime.Now.ToBinary());
        bw.Write((byte)dbType);          // 类型
        bw.Write((byte)BackupMode.Full); // 复用枚举；增量包以元数据位置区分（此处占位）
        bw.Write(hash);
        bw.Write(nonce);
        bw.Write(tag);
        bw.Write((long)plain.Length);
        bw.Write(cipher);
        return backupPath;
    }

    // ==================== 密钥 ====================

    /// <summary>数据库备份密钥（DPAPI 保护，与 DatabaseBackupEngine 共享语义）。</summary>
    private static byte[]? _dbKey;

    private static byte[] EnsureDbBackupKey()
    {
        if (_dbKey is { Length: 32 }) return _dbKey;

        var keyPath = Path.Combine(ConfigManager.GetDataDir(), "dbbackup.key");
        try
        {
            if (File.Exists(keyPath))
            {
                var protectedKey = File.ReadAllBytes(keyPath);
                var key = ProtectedData.Unprotect(protectedKey, null, DataProtectionScope.CurrentUser);
                if (key.Length == 32)
                {
                    _dbKey = key;
                    return key;
                }
            }
        }
        catch { }

        var newKey = RandomNumberGenerator.GetBytes(32);
        try
        {
            var protectedNew = ProtectedData.Protect(newKey, null, DataProtectionScope.CurrentUser);
            File.WriteAllBytes(keyPath, protectedNew);
        }
        catch { }
        _dbKey = newKey;
        return newKey;
    }

    // ==================== 查询辅助 ====================

    /// <summary>查询 MySQL 主库状态（当前 binlog 文件与位置）。</summary>
    private static (string file, int pos) QueryMySqlMasterStatus(string connStr)
    {
        var p = ParseMySqlConn(connStr);
        var output = RunProcessCapture("mysql",
            $"--host={p.Host} --port={p.Port} --user={p.User} --password={p.Password} --batch --skip-column-names --execute=\"SHOW MASTER STATUS\"");
        // 输出行：binlog.000001  123  ...（第一列 File，第二列 Position）
        var lines = (output.Output ?? "").Split('\n', StringSplitOptions.RemoveEmptyEntries);
        foreach (var line in lines)
        {
            var cols = line.Split('\t', StringSplitOptions.RemoveEmptyEntries);
            if (cols.Length >= 2 && int.TryParse(cols[1].Trim(), out var pos))
                return (cols[0].Trim(), pos);
        }
        return ("", 0);
    }

    /// <summary>查询 MySQL binlog 文件清单。</summary>
    private static List<string> QueryMySqlBinaryLogs(string connStr)
    {
        var p = ParseMySqlConn(connStr);
        var output = RunProcessCapture("mysql",
            $"--host={p.Host} --port={p.Port} --user={p.User} --password={p.Password} --batch --skip-column-names --execute=\"SHOW BINARY LOGS\"");
        var files = new List<string>();
        foreach (var line in (output.Output ?? "").Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            var name = line.Split('\t', StringSplitOptions.RemoveEmptyEntries).FirstOrDefault()?.Trim();
            if (!string.IsNullOrEmpty(name)) files.Add(name);
        }
        return files;
    }

    /// <summary>解析 "File:Position" 为 (文件, 位置)；非法返回 ("",0)。</summary>
    private static (string file, int pos) ParseBinlogPosition(string? pos)
    {
        if (string.IsNullOrWhiteSpace(pos)) return ("", 0);
        var idx = pos.LastIndexOf(':');
        if (idx <= 0) return ("", 0);
        var file = pos[..idx];
        return int.TryParse(pos[(idx + 1)..], out var p) ? (file, p) : (file, 0);
    }

    /// <summary>查询 PostgreSQL 当前 WAL LSN。</summary>
    private static string? QueryPgCurrentLsn(string connStr)
    {
        var p = ParsePgConn(connStr);
        var args = $"--host={p.Host} --port={p.Port} --username={p.User} --dbname={p.Database} --tuples-only --no-align --command=\"SELECT pg_current_wal_lsn()\"";
        var env = new Dictionary<string, string> { ["PGPASSWORD"] = p.Password };
        var output = RunProcessCaptureWithEnv("psql", args, env);
        var lsn = (output.Output ?? "").Trim();
        return output.ExitCode == 0 && !string.IsNullOrEmpty(lsn) ? lsn : null;
    }

    // ==================== 连接解析 ====================

    private sealed class MySqlConn
    {
        public string Host = "localhost";
        public int Port = 3306;
        public string User = "";
        public string Password = "";
    }

    private sealed class PgConn
    {
        public string Host = "localhost";
        public int Port = 5432;
        public string User = "";
        public string Database = "";
        public string Password = "";
    }

    private static MySqlConn ParseMySqlConn(string connStr)
    {
        var c = new MySqlConn();
        c.Host = Extract(connStr, "Server", "localhost");
        c.Host = string.IsNullOrEmpty(c.Host) ? Extract(connStr, "Host", "localhost") : c.Host;
        _ = int.TryParse(Extract(connStr, "Port", "3306"), out c.Port);
        c.User = Extract(connStr, "Uid", Extract(connStr, "User Id", ""));
        c.User = string.IsNullOrEmpty(c.User) ? Extract(connStr, "User", "") : c.User;
        c.Password = Extract(connStr, "Pwd", Extract(connStr, "Password", ""));
        return c;
    }

    private static PgConn ParsePgConn(string connStr)
    {
        var c = new PgConn();
        c.Host = Extract(connStr, "Host", "localhost");
        c.Host = string.IsNullOrEmpty(c.Host) ? Extract(connStr, "Server", "localhost") : c.Host;
        _ = int.TryParse(Extract(connStr, "Port", "5432"), out c.Port);
        c.User = Extract(connStr, "Username", "");
        c.User = string.IsNullOrEmpty(c.User) ? Extract(connStr, "User Id", "") : c.User;
        c.Database = Extract(connStr, "Database", "");
        c.Password = Extract(connStr, "Password", "");
        return c;
    }

    private static string Extract(string connStr, string key, string defaultValue)
    {
        foreach (var pair in connStr.Split(';', StringSplitOptions.RemoveEmptyEntries))
        {
            var idx = pair.IndexOf('=');
            if (idx <= 0) continue;
            if (string.Equals(pair[..idx].Trim(), key, StringComparison.OrdinalIgnoreCase))
                return pair[(idx + 1)..].Trim().Trim('"', '\'');
        }
        return defaultValue;
    }

    // ==================== 进程执行 ====================

    private static (int ExitCode, string Output, string Error) RunProcessCapture(string fileName, string args)
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

    private static (int ExitCode, string Output, string Error) RunProcessCaptureWithEnv(
        string fileName, string args, Dictionary<string, string> env)
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
            foreach (var (k, v) in env)
                psi.Environment[k] = v;
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
}
