// © 2026 落尘（Luochen） 原创开发 - 保留所有权利

using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using LightGuard.Core;

namespace LightGuard.Backup;

/// <summary>
/// 备份执行引擎 - 支持 5 层粒度（文件 / 目录 / 分区 / 整盘 / 数据库）的加密抗勒索备份。
/// <para>统一流程：读取源 →（VSS 快照）→ 分片 → AES-256-GCM/ChaCha20 加密 → SHA256 校验 → 写入 .lgbackup → 日志。</para>
/// <para>支持增量备份（对比上次清单文件哈希）、SMB 网络目标写入。</para>
/// </summary>
public sealed class BackupExecutor
{
    private readonly BackupCryptoEngine _crypto;
    private readonly int _shardSize;

    /// <summary>
    /// 初始化备份执行引擎。
    /// </summary>
    /// <param name="appState">全局应用状态（用于硬件自适应选择加密算法）。</param>
    /// <param name="shardSize">分片大小（字节），默认 4MB。</param>
    public BackupExecutor(AppState appState, int shardSize = BackupShardEngine.DefaultShardSize)
    {
        ArgumentNullException.ThrowIfNull(appState);
        _crypto = new BackupCryptoEngine(appState.Hardware);
        _shardSize = shardSize > 0 ? shardSize : BackupShardEngine.DefaultShardSize;
    }

    /// <summary>当前加密算法名称。</summary>
    public string AlgorithmName => _crypto.AlgorithmName;

    /// <summary>
    /// 备份单个文件。
    /// </summary>
    /// <param name="filePath">源文件路径。</param>
    /// <param name="password">加密口令。</param>
    /// <param name="destDir">目标目录（本地或 SMB UNC 路径）。</param>
    /// <param name="progress">进度跟踪器（可选）。</param>
    /// <returns>备份清单。</returns>
    public BackupManifest BackupSingleFile(string filePath, string password, string destDir, BackupProgress? progress = null)
    {
        if (!File.Exists(filePath))
            throw new FileNotFoundException("待备份文件不存在。", filePath);

        ErrorReporter.Log($"开始单文件备份：{filePath}");
        var data = File.ReadAllBytes(filePath);
        return ExecuteDataBackup(data, BackupType.File, filePath, password, destDir, 1, progress, null);
    }

    /// <summary>
    /// 备份整个目录（支持黑名单过滤与增量）。
    /// </summary>
    /// <param name="dirPath">源目录路径。</param>
    /// <param name="password">加密口令。</param>
    /// <param name="destDir">目标目录（本地或 SMB UNC 路径）。</param>
    /// <param name="excludePatterns">排除模式（如 "*.tmp"、"node_modules"）。</param>
    /// <param name="incremental">是否增量备份（对比 baseline 文件哈希）。</param>
    /// <param name="baseline">增量基准清单（其 Metadata["FileHashes"] 作为对比依据）。</param>
    /// <param name="progress">进度跟踪器（可选）。</param>
    /// <param name="skipFiles">跳过文件集合（P1-6：备份前查杀发现的恶意文件跳过备份）。</param>
    /// <returns>备份清单（含本次全量文件哈希映射，可作为下次增量基准）。</returns>
    public BackupManifest BackupDirectory(string dirPath, string password, string destDir,
        string[]? excludePatterns = null, bool incremental = false, BackupManifest? baseline = null,
        BackupProgress? progress = null, IReadOnlyCollection<string>? skipFiles = null)
    {
        if (!Directory.Exists(dirPath))
            throw new DirectoryNotFoundException("待备份目录不存在：" + dirPath);

        ErrorReporter.Log($"开始目录备份：{dirPath}（增量={incremental}，跳过恶意文件={skipFiles?.Count ?? 0}）");

        var baselineHashes = incremental && baseline != null
            ? ParseHashMap(baseline.Metadata)
            : null;

        var (archive, fileCount, hashes) = BuildDirectoryArchive(dirPath, excludePatterns, baselineHashes, incremental, progress, skipFiles);

        var metadata = new Dictionary<string, string>
        {
            ["Strategy"] = incremental ? "Incremental" : "Full",
            ["FileHashes"] = SerializeHashMap(hashes)
        };

        return ExecuteDataBackup(archive, BackupType.Directory, dirPath, password, destDir, fileCount, progress, metadata);
    }

    /// <summary>
    /// 分区镜像备份 - 使用 VSS 卷影副本热备份（无需关机）。
    /// <para>VSS 不可用时回退到实时卷原始读取（需管理员权限）。</para>
    /// </summary>
    /// <param name="driveLetter">盘符（如 "C"）。</param>
    /// <param name="password">加密口令。</param>
    /// <param name="destDir">目标目录（本地或 SMB UNC 路径）。</param>
    /// <param name="progress">进度跟踪器（可选）。</param>
    /// <returns>备份清单。</returns>
    public BackupManifest BackupPartition(string driveLetter, string password, string destDir, BackupProgress? progress = null)
    {
        var letter = NormalizeDriveLetter(driveLetter);
        ErrorReporter.Log($"开始分区备份：{letter}:（尝试 VSS 卷影副本）");

        var stream = OpenPartitionStream(letter, out var usedPath, out var vssNote);
        try
        {
            var metadata = new Dictionary<string, string>
            {
                ["DriveLetter"] = letter,
                ["VssShadow"] = vssNote
            };
            return ExecuteStreamBackup(stream, BackupType.Partition, usedPath, password, destDir, progress, metadata);
        }
        finally
        {
            stream.Dispose();
        }
    }

    /// <summary>
    /// 整块硬盘扇区级镜像备份（需管理员权限）。
    /// </summary>
    /// <param name="diskNumber">物理磁盘编号（0 表示第一块磁盘）。</param>
    /// <param name="password">加密口令。</param>
    /// <param name="destDir">目标目录（本地或 SMB UNC 路径）。</param>
    /// <param name="progress">进度跟踪器（可选）。</param>
    /// <returns>备份清单。</returns>
    public BackupManifest BackupDisk(int diskNumber, string password, string destDir, BackupProgress? progress = null)
    {
        if (diskNumber < 0) throw new ArgumentOutOfRangeException(nameof(diskNumber), "磁盘编号不能为负。");
        var device = $@"\\.\PHYSICALDRIVE{diskNumber}";
        ErrorReporter.Log($"开始整盘扇区级镜像备份：{device}");

        var stream = OpenRawDevice(device);
        try
        {
            var metadata = new Dictionary<string, string>
            {
                ["DiskNumber"] = diskNumber.ToString(),
                ["DevicePath"] = device
            };
            return ExecuteStreamBackup(stream, BackupType.Disk, device, password, destDir, progress, metadata);
        }
        finally
        {
            stream.Dispose();
        }
    }

    /// <summary>
    /// 数据库备份 - 调用数据库备份引擎导出后加密。
    /// <para>支持 SQLite/Access（文件直读）、MySQL/MariaDB（mysqldump）、SQL Server（.bak/.mdf 文件）。</para>
    /// </summary>
    /// <param name="connStr">连接串或文件路径。</param>
    /// <param name="dbType">数据库类型：sqlite/access/mysql/mariadb/sqlserver。</param>
    /// <param name="password">加密口令。</param>
    /// <param name="destDir">目标目录（本地或 SMB UNC 路径）。</param>
    /// <param name="progress">进度跟踪器（可选）。</param>
    /// <returns>备份清单。</returns>
    public BackupManifest BackupDatabase(string connStr, string dbType, string password, string destDir, BackupProgress? progress = null)
    {
        ArgumentNullException.ThrowIfNull(connStr);
        ErrorReporter.Log($"开始数据库备份：类型={dbType}");

        var data = DumpDatabase(connStr, dbType);
        var metadata = new Dictionary<string, string>
        {
            ["DbType"] = dbType ?? string.Empty,
            ["Source"] = connStr
        };
        return ExecuteDataBackup(data, BackupType.Database, connStr, password, destDir, 1, progress, metadata);
    }

    #region 核心执行流程

    /// <summary>
    /// 基于内存数据的备份流程（适用于文件 / 目录 / 数据库，数据可完整载入内存）。
    /// </summary>
    private BackupManifest ExecuteDataBackup(byte[] data, BackupType type, string sourcePath, string password,
        string destDir, int fileCount, BackupProgress? progress, Dictionary<string, string>? metadata)
    {
        var salt = _crypto.GenerateSalt();
        var key = _crypto.DeriveKey(password, salt);

        var shards = BackupShardEngine.ShardData(data, _shardSize);
        var globalHash = BackupShardEngine.ComputeGlobalHash(shards);

        progress?.SetTotal(fileCount, data.Length);

        var encrypted = new List<EncryptedShard>(shards.Count);
        long processed = 0;
        for (int i = 0; i < shards.Count; i++)
        {
            progress?.ThrowIfCancellationRequested();
            var s = shards[i];
            var (cipher, nonce, tag) = _crypto.Encrypt(s.Data, key);
            encrypted.Add(new EncryptedShard
            {
                Index = s.Index,
                Cipher = cipher,
                Nonce = nonce,
                Tag = tag,
                PlainHash = s.Hash
            });
            processed += s.Length;
            progress?.UpdateProgress(fileCount, processed, sourcePath, true, BackupPhase.Backup);
        }

        var manifest = new BackupManifest
        {
            BackupType = type,
            SourcePath = sourcePath,
            BackupTime = DateTime.Now,
            ShardSize = _shardSize,
            EncryptedAlgorithm = _crypto.AlgorithmName,
            Salt = Convert.ToBase64String(salt),
            TotalSize = data.Length,
            ShardCount = shards.Count,
            FileCount = fileCount,
            GlobalHash = Convert.ToHexString(globalHash)
        };
        if (metadata != null)
        {
            foreach (var kv in metadata)
                manifest.Metadata[kv.Key] = kv.Value;
        }

        var outputPath = GenerateOutputPath(destDir, type, manifest.BackupId);
        Directory.CreateDirectory(destDir);

        progress?.UpdateProgress(fileCount, data.Length, sourcePath, false, BackupPhase.Verify);
        LgBackupFormat.WriteBackup(outputPath, manifest, encrypted);

        if (!LgBackupFormat.VerifyBackup(outputPath))
            throw new InvalidDataException("备份包写入后结构性校验失败，请重试。");

        progress?.UpdateProgress(fileCount, data.Length, outputPath, false, BackupPhase.Upload);
        ErrorReporter.Log($"数据备份完成：[{type}] {sourcePath} -> {outputPath} | 文件 {fileCount} | 分片 {shards.Count} | {data.Length} 字节 | 算法 {manifest.EncryptedAlgorithm}");
        return manifest;
    }

    /// <summary>
    /// 基于流的备份流程（适用于分区 / 整盘，源可能远超内存容量）。
    /// 采用「先写本地临时包体，再拼接清单头部」的单遍流式方案，内存占用恒定。
    /// </summary>
    private BackupManifest ExecuteStreamBackup(Stream source, BackupType type, string sourcePath, string password,
        string destDir, BackupProgress? progress, Dictionary<string, string>? metadata)
    {
        var salt = _crypto.GenerateSalt();
        var key = _crypto.DeriveKey(password, salt);
        var backupId = Guid.NewGuid();
        var tempBody = Path.Combine(Path.GetTempPath(), $"lgbackup_body_{backupId:N}.tmp");

        long totalSize = 0;
        int shardCount = 0;

        using var sha = SHA256.Create();
        try
        {
            using (var bw = new BinaryWriter(File.Create(tempBody), Encoding.UTF8))
            {
                var buffer = new byte[_shardSize];
                while (true)
                {
                    progress?.ThrowIfCancellationRequested();
                    int read;
                    try
                    {
                        read = source.Read(buffer, 0, buffer.Length);
                    }
                    catch (IOException)
                    {
                        // 设备读取到末尾或遇到边界，视为结束
                        break;
                    }
                    if (read <= 0) break;

                    var chunk = new byte[read];
                    Buffer.BlockCopy(buffer, 0, chunk, 0, read);

                    sha.TransformBlock(chunk, 0, chunk.Length, null, 0);
                    var plainHash = SHA256.HashData(chunk);

                    var (cipher, nonce, tag) = _crypto.Encrypt(chunk, key);
                    LgBackupFormat.WriteShardRecord(bw, new EncryptedShard
                    {
                        Index = shardCount,
                        Cipher = cipher,
                        Nonce = nonce,
                        Tag = tag,
                        PlainHash = plainHash
                    });

                    totalSize += read;
                    shardCount++;
                    progress?.UpdateProgress(shardCount, totalSize, sourcePath, true, BackupPhase.Backup);

                    // 安全上限：约 4TB（4MB * 1M 分片），防止异常设备无限读取
                    if (shardCount > 1_000_000) break;
                }
            }

            sha.TransformFinalBlock(Array.Empty<byte>(), 0, 0);

            var manifest = new BackupManifest
            {
                BackupId = backupId,
                BackupType = type,
                SourcePath = sourcePath,
                BackupTime = DateTime.Now,
                ShardSize = _shardSize,
                EncryptedAlgorithm = _crypto.AlgorithmName,
                Salt = Convert.ToBase64String(salt),
                TotalSize = totalSize,
                ShardCount = shardCount,
                FileCount = 1,
                GlobalHash = Convert.ToHexString(sha.Hash ?? Array.Empty<byte>())
            };
            if (metadata != null)
            {
                foreach (var kv in metadata)
                    manifest.Metadata[kv.Key] = kv.Value;
            }

            var outputPath = GenerateOutputPath(destDir, type, manifest.BackupId);
            Directory.CreateDirectory(destDir);

            // 拼接最终包：头部（魔数 + 版本 + 清单 JSON）+ 临时包体
            using (var fout = File.Create(outputPath))
            using (var bwOut = new BinaryWriter(fout, Encoding.UTF8))
            {
                LgBackupFormat.WriteHeader(bwOut, manifest);
                using var tempIn = File.OpenRead(tempBody);
                tempIn.CopyTo(fout);
            }

            if (!LgBackupFormat.VerifyBackup(outputPath))
                throw new InvalidDataException("备份包写入后结构性校验失败，请重试。");

            progress?.UpdateProgress(shardCount, totalSize, outputPath, false, BackupPhase.Upload);
            ErrorReporter.Log($"流式备份完成：[{type}] {sourcePath} -> {outputPath} | 分片 {shardCount} | {totalSize} 字节 | 算法 {manifest.EncryptedAlgorithm}");
            return manifest;
        }
        finally
        {
            try { if (File.Exists(tempBody)) File.Delete(tempBody); } catch { }
        }
    }

    #endregion

    #region 目录归档与增量

    /// <summary>
    /// 将目录序列化为内存归档字节流。
    /// </summary>
    private (byte[] Archive, int FileCount, Dictionary<string, string> Hashes) BuildDirectoryArchive(
        string dirPath, string[]? excludePatterns, Dictionary<string, string>? baselineHashes,
        bool incremental, BackupProgress? progress, IReadOnlyCollection<string>? skipFiles = null)
    {
        var entries = new List<(string RelPath, byte[] Data)>();
        var hashes = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        IEnumerable<string> files;
        try
        {
            files = Directory.EnumerateFiles(dirPath, "*", SearchOption.AllDirectories);
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, $"枚举目录失败：{dirPath}");
            files = Array.Empty<string>();
        }

        int skippedMalicious = 0;
        foreach (var file in files)
        {
            string relPath;
            try
            {
                relPath = Path.GetRelativePath(dirPath, file).Replace('\\', '/');
            }
            catch
            {
                continue;
            }

            var fileName = Path.GetFileName(file);
            if (excludePatterns != null && excludePatterns.Any(p => MatchesPattern(relPath, fileName, p)))
                continue;

            // P1-6：备份前查杀发现的恶意文件跳过备份
            if (skipFiles != null && skipFiles.Contains(file))
            {
                skippedMalicious++;
                continue;
            }

            byte[] data;
            try
            {
                data = File.ReadAllBytes(file);
            }
            catch (Exception ex)
            {
                ErrorReporter.Log($"跳过无法读取的文件 {file}：{ex.Message}");
                continue;
            }

            var hashHex = Convert.ToHexString(SHA256.HashData(data));
            hashes[relPath] = hashHex;

            bool include = true;
            if (incremental && baselineHashes != null
                && baselineHashes.TryGetValue(relPath, out var baseHash)
                && string.Equals(baseHash, hashHex, StringComparison.OrdinalIgnoreCase))
            {
                include = false;
            }

            if (include)
                entries.Add((relPath, data));
        }

        using var ms = new MemoryStream();
        using (var bw = new BinaryWriter(ms, Encoding.UTF8, leaveOpen: true))
        {
            bw.Write((long)entries.Count);
            foreach (var (rel, data) in entries)
            {
                var relBytes = Encoding.UTF8.GetBytes(rel);
                bw.Write(relBytes.Length);
                bw.Write(relBytes);
                bw.Write((long)data.Length);
                bw.Write(data);
            }
        }

        if (skippedMalicious > 0)
            ErrorReporter.Log($"备份前查杀联动：已跳过 {skippedMalicious} 个恶意文件（{dirPath}）", "WARN");

        return (ms.ToArray(), entries.Count, hashes);
    }

    /// <summary>
    /// 从归档字节流还原文件条目列表。
    /// </summary>
    internal static List<(string RelPath, byte[] Data)> ExtractDirectoryArchive(byte[] archive)
    {
        var list = new List<(string RelPath, byte[] Data)>();
        using var ms = new MemoryStream(archive);
        using var br = new BinaryReader(ms, Encoding.UTF8, leaveOpen: true);
        var count = br.ReadInt64();
        for (long i = 0; i < count; i++)
        {
            var relLen = br.ReadInt32();
            var rel = Encoding.UTF8.GetString(br.ReadBytes(relLen));
            var dataLen = br.ReadInt64();
            var data = br.ReadBytes((int)dataLen);
            list.Add((rel, data));
        }
        return list;
    }

    /// <summary>
    /// 简单通配符匹配（支持 * 与精确段匹配）。
    /// </summary>
    private static bool MatchesPattern(string relPath, string fileName, string pattern)
    {
        if (string.IsNullOrWhiteSpace(pattern)) return false;
        pattern = pattern.Replace('\\', '/').Trim();

        // 精确匹配文件名或路径段
        if (!pattern.Contains('*'))
        {
            return string.Equals(fileName, pattern, StringComparison.OrdinalIgnoreCase)
                || relPath.Equals(pattern, StringComparison.OrdinalIgnoreCase)
                || relPath.Split('/').Any(seg => string.Equals(seg, pattern, StringComparison.OrdinalIgnoreCase));
        }

        // 通配符：转义为正则
        var regexPattern = "^" + Regex.Escape(pattern).Replace("\\*", ".*") + "$";
        return Regex.IsMatch(relPath, regexPattern, RegexOptions.IgnoreCase)
            || Regex.IsMatch(fileName, regexPattern, RegexOptions.IgnoreCase);
    }

    private static string SerializeHashMap(Dictionary<string, string> hashes)
        => JsonSerializer.Serialize(hashes);

    private static Dictionary<string, string> ParseHashMap(Dictionary<string, string>? metadata)
    {
        if (metadata == null) return new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (!metadata.TryGetValue("FileHashes", out var json) || string.IsNullOrEmpty(json))
            return new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            var dict = JsonSerializer.Deserialize<Dictionary<string, string>>(json);
            return dict != null
                ? new Dictionary<string, string>(dict, StringComparer.OrdinalIgnoreCase)
                : new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        }
        catch
        {
            return new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        }
    }

    #endregion

    #region VSS / 原始设备读取

    /// <summary>
    /// 打开分区读取流：优先 VSS 卷影副本（一致性快照），失败回退到实时卷原始读取。
    /// </summary>
    private Stream OpenPartitionStream(string letter, out string usedPath, out string vssNote)
    {
        var shadow = TryCreateVssShadow(letter);
        if (!string.IsNullOrEmpty(shadow))
        {
            try
            {
                usedPath = shadow;
                vssNote = shadow;
                return new FileStream(shadow, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            }
            catch (Exception ex)
            {
                ErrorReporter.Log($"VSS 卷影设备打开失败，回退到实时卷读取：{ex.Message}");
            }
        }

        usedPath = $@"\\.\{letter}:";
        vssNote = "None(fallback-live)";
        return OpenRawDevice(usedPath);
    }

    /// <summary>
    /// 打开原始设备（卷 / 物理盘）读取流，需管理员权限。
    /// </summary>
    private static FileStream OpenRawDevice(string devicePath)
        => new(devicePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);

    /// <summary>
    /// 尝试通过 vssadmin 创建 VSS 卷影副本并返回卷影设备路径。
    /// 失败（非管理员 / 服务未运行）返回 null。
    /// </summary>
    private static string? TryCreateVssShadow(string letter)
    {
        try
        {
            var psi = new ProcessStartInfo("vssadmin.exe", $"create shadow /for={letter}:")
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
                Verb = "runas"
            };
            using var p = Process.Start(psi);
            if (p == null) return null;
            var output = p.StandardOutput.ReadToEnd() + Environment.NewLine + p.StandardError.ReadToEnd();
            p.WaitForExit(30000);
            if (p.ExitCode != 0) return null;

            // 解析 "Shadow Copy Volume Name: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyN"
            var match = Regex.Match(output, @"Shadow Copy Volume Name:\s*(\\[?].*?HarddiskVolumeShadowCopy\d+)", RegexOptions.IgnoreCase);
            return match.Success ? match.Groups[1].Value : null;
        }
        catch (Exception ex)
        {
            ErrorReporter.Log($"VSS 卷影副本创建失败（需管理员权限）：{ex.Message}");
            return null;
        }
    }

    #endregion

    #region 数据库导出

    /// <summary>
    /// 数据库备份引擎：依据类型导出数据库为字节。
    /// </summary>
    private static byte[] DumpDatabase(string connStr, string dbType)
    {
        var type = (dbType ?? string.Empty).Trim().ToLowerInvariant();
        switch (type)
        {
            case "sqlite":
            case "access":
                if (!File.Exists(connStr))
                    throw new FileNotFoundException("数据库文件不存在：" + connStr);
                return File.ReadAllBytes(connStr);

            case "mysql":
            case "mariadb":
                return DumpMysql(connStr);

            case "sqlserver":
            case "mssql":
                // SQL Server：优先读取 .bak/.mdf 文件；在线备份请先在服务端生成 .bak
                if (File.Exists(connStr))
                    return File.ReadAllBytes(connStr);
                throw new NotSupportedException(
                    "SQL Server 在线备份需先在服务端执行 BACKUP DATABASE ... TO DISK 生成 .bak 文件，再将文件路径作为连接串传入。");

            default:
                throw new NotSupportedException($"暂不支持的数据库类型：{dbType}（支持 sqlite/access/mysql/mariadb/sqlserver）");
        }
    }

    /// <summary>
    /// 使用 mysqldump 导出 MySQL/MariaDB 数据库。
    /// </summary>
    private static byte[] DumpMysql(string connStr)
    {
        var p = ParseConnStr(connStr);
        var server = Get(p, "server", "host") ?? "localhost";
        var port = Get(p, "port") ?? "3306";
        var user = Get(p, "uid", "user", "username") ?? "root";
        var pwd = Get(p, "pwd", "password") ?? string.Empty;
        var db = Get(p, "database", "db");
        if (string.IsNullOrEmpty(db))
            throw new ArgumentException("MySQL 连接串缺少 database 参数。");

        var args = $"--host={server} --port={port} --user=\"{user}\" --password=\"{pwd}\" --single-transaction --routines --triggers \"{db}\"";
        return RunToolCapture("mysqldump", args);
    }

    /// <summary>
    /// 运行命令行工具并捕获标准输出字节。
    /// </summary>
    private static byte[] RunToolCapture(string tool, string args)
    {
        var psi = new ProcessStartInfo(tool, args)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };
        using var p = Process.Start(psi)
            ?? throw new InvalidOperationException($"无法启动 {tool}，请确认已安装并加入 PATH。");
        using var ms = new MemoryStream();
        p.StandardOutput.BaseStream.CopyTo(ms);
        var err = p.StandardError.ReadToEnd();
        p.WaitForExit();
        if (p.ExitCode != 0)
            throw new InvalidOperationException($"{tool} 执行失败（ExitCode={p.ExitCode}）：{err}");
        return ms.ToArray();
    }

    private static Dictionary<string, string> ParseConnStr(string connStr)
    {
        var dict = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var part in connStr.Split(';', StringSplitOptions.RemoveEmptyEntries))
        {
            var eq = part.IndexOf('=');
            if (eq > 0)
                dict[part[..eq].Trim()] = part[(eq + 1)..].Trim();
        }
        return dict;
    }

    private static string? Get(IReadOnlyDictionary<string, string> d, params string[] keys)
    {
        foreach (var k in keys)
        {
            if (d.TryGetValue(k, out var v) && !string.IsNullOrEmpty(v))
                return v;
        }
        return null;
    }

    #endregion

    #region 辅助

    private static string GenerateOutputPath(string destDir, BackupType type, Guid id)
        => Path.Combine(destDir, $"{type}_{DateTime.Now:yyyyMMdd_HHmmss}_{id.ToString("N")[..8]}{LgBackupFormat.Extension}");

    private static string NormalizeDriveLetter(string driveLetter)
    {
        if (string.IsNullOrWhiteSpace(driveLetter))
            throw new ArgumentException("盘符不能为空。", nameof(driveLetter));
        var c = char.ToUpperInvariant(driveLetter.Trim()[0]);
        if (c < 'A' || c > 'Z')
            throw new ArgumentException("无效盘符：" + driveLetter, nameof(driveLetter));
        return c.ToString();
    }

    #endregion
}
