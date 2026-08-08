// © 2026 落尘（Luochen） 原创开发 - 保留所有权利
//
// 客户端 C/S 备份服务（CsBackupService）
//   - 本地完成：文件扫描、分块、SHA256 哈希、AES-256-GCM 加密（块在客户端完成加密）
//   - 只向服务端发送 hash 摘要列表；服务端返回缺失块；仅上传缺失块（不重复传输已存在块）
//   - 禁止读取远端备份集做 hash 比对（避免大量无效网络 IO）
//   - 快照：客户端构建条目（路径 → 块 hash 序列）→ 服务端保存
//   - 恢复：客户端拉取快照元数据 → 分片下载块密文 → 本地解密 → 写回文件

using System.Security.Cryptography;
using System.Text;
using LightGuard.Backup;
using LightGuard.Shared;

namespace LightGuard.ClientServer;

/// <summary>C/S 备份进度回调。</summary>
public sealed class CsBackupProgress
{
    /// <summary>阶段描述。</summary>
    public string? Stage { get; set; }

    /// <summary>已处理条目。</summary>
    public int Processed { get; set; }

    /// <summary>总条目。</summary>
    public int Total { get; set; }

    /// <summary>已上传字节。</summary>
    public long UploadedBytes { get; set; }

    /// <summary>已复用块数（服务端已存在）。</summary>
    public int ReusedBlocks { get; set; }
}

/// <summary>C/S 备份结果。</summary>
public sealed class CsBackupResult
{
    /// <summary>是否成功。</summary>
    public bool Success { get; set; }

    /// <summary>消息。</summary>
    public string? Message { get; set; }

    /// <summary>快照 ID（备份成功时）。</summary>
    public string? SnapshotId { get; set; }

    /// <summary>文件数。</summary>
    public int FileCount { get; set; }

    /// <summary>总字节。</summary>
    public long TotalBytes { get; set; }

    /// <summary>新增块数。</summary>
    public int NewBlocks { get; set; }

    /// <summary>复用块数（服务端已存在，未传输）。</summary>
    public int ReusedBlocks { get; set; }
}

/// <summary>
/// 客户端 C/S 备份服务门面：文件备份 / 数据库备份 / 恢复。
/// </summary>
public sealed class CsBackupService : IDisposable
{
    /// <summary>块大小（字节）。</summary>
    public int BlockSize { get; }

    private readonly ClientServerConfig _config;
    private readonly byte[] _key;
    private readonly CsBackupClient _client;

    /// <summary>底层网络客户端（供恢复/清理等操作）。</summary>
    public CsBackupClient Client => _client;

    /// <summary>认证密码引用名（供日志）。</summary>
    public string ClientId { get; }

    /// <summary>
    /// 创建 C/S 备份服务。
    /// </summary>
    /// <param name="config">客户端 C/S 配置。</param>
    /// <param name="backupPassword">本地备份加密口令（用于派生块加密密钥，永不过网）。</param>
    public CsBackupService(ClientServerConfig config, string backupPassword)
    {
        _config = config;
        BlockSize = Math.Max(64 * 1024, config.BlockSize);
        ClientId = string.IsNullOrEmpty(config.ClientId) ? Environment.MachineName : config.ClientId;

        // 块加密密钥：本地从备份口令派生（HKDF-SHA256），密钥永不过网
        var salt = Encoding.UTF8.GetBytes("LightGuard-CS-v3.6-blockkey");
        _key = KeyDerivation.DeriveKey(backupPassword, salt, "cs-block", 32);

        _client = new CsBackupClient(config);
    }

    /// <summary>建立连接（供手动连接 / 清理等操作）。</summary>
    public Task<CsSessionResult> ConnectAsync(CancellationToken ct = default) => _client.ConnectAsync(ct);

    /// <summary>断开连接。</summary>
    public void Disconnect() => _client.Disconnect();

    // ==================== 文件备份 ====================

    /// <summary>
    /// 执行文件/目录 C/S 备份。
    /// <para>流程：扫描 → 分块 → SHA256 → AES-256-GCM 加密 → 发送 hash 摘要列表 → 仅上传缺失块 → 创建快照。</para>
    /// </summary>
    /// <param name="sourcePath">源路径（文件或目录）。</param>
    /// <param name="name">快照名称（如 File_20260808_120000）。</param>
    /// <param name="progress">进度回调（可选）。</param>
    public async Task<CsBackupResult> BackupAsync(string sourcePath, string name, Action<CsBackupProgress>? progress = null, CancellationToken ct = default)
    {
        var result = new CsBackupResult();
        var connect = await _client.ConnectAsync(ct).ConfigureAwait(false);
        if (!connect.Success)
        {
            result.Success = false;
            result.Message = connect.Message;
            return result;
        }

        try
        {
            var files = CollectFiles(sourcePath);
            result.FileCount = files.Count;

            // 阶段 1：分块 + hash + 加密（本地完成）
            progress?.Invoke(new CsBackupProgress { Stage = "本地分块与加密", Total = files.Count });
            var entries = new List<CsSnapshotEntry>();
            var allHashes = new List<string>();
            var blockData = new Dictionary<string, (byte[] Package, int PlainLen)>(StringComparer.OrdinalIgnoreCase);
            var totalBytes = 0L;

            foreach (var file in files)
            {
                ct.ThrowIfCancellationRequested();
                // 相对路径基于源路径本身（文件 → 文件名；目录 → 目录内相对路径），恢复时落回目标根
                var rel = File.Exists(sourcePath)
                    ? Path.GetFileName(file)
                    : Path.GetRelativePath(sourcePath, file).Replace('\\', '/');
                var (entryHashes, fileSize) = ProcessFile(file, rel, blockData, allHashes);
                totalBytes += fileSize;
                entries.Add(entryHashes);
            }
            result.TotalBytes = totalBytes;

            // 阶段 2：发送 hash 摘要列表 → 服务端返回缺失 → 仅上传缺失块
            progress?.Invoke(new CsBackupProgress { Stage = "查询缺失块", Total = blockData.Count });
            var missing = await _client.FindMissingAsync(allHashes, ct).ConfigureAwait(false);
            var missingSet = missing.ToHashSet(StringComparer.OrdinalIgnoreCase);
            result.ReusedBlocks = allHashes.Count - missingSet.Count;

            var uploaded = 0L;
            foreach (var kv in blockData)
            {
                ct.ThrowIfCancellationRequested();
                if (!missingSet.Contains(kv.Key)) continue; // 服务端已存在：不重复传输
                await _client.UploadBlockAsync(kv.Key, kv.Value.Package, kv.Value.PlainLen, ct).ConfigureAwait(false);
                uploaded += kv.Value.Package.Length;
                result.NewBlocks++;
                progress?.Invoke(new CsBackupProgress
                {
                    Stage = $"上传缺失块（{result.NewBlocks}/{missingSet.Count}）",
                    UploadedBytes = uploaded
                });
            }

            // 阶段 3：创建快照（客户端只上报条目 + 块引用，服务端本地持有块）
            progress?.Invoke(new CsBackupProgress { Stage = "创建快照" });
            var create = await _client.CreateSnapshotAsync(new CsSnapshotCreate
            {
                Name = name,
                SourcePath = sourcePath,
                Entries = entries,
                AllBlockHashes = allHashes.Distinct(StringComparer.OrdinalIgnoreCase).ToList(),
                Cipher = "AES-256-GCM",
                CreatedUtc = DateTimeOffset.UtcNow.ToUnixTimeSeconds()
            }, ct).ConfigureAwait(false);

            if (!create.Ok)
            {
                result.Success = false;
                result.Message = create.Message;
                return result;
            }

            // 快照回收（保留策略）
            await _client.CleanupAsync(_config.MaxSnapshotsPerClient, ClientId, ct).ConfigureAwait(false);

            result.Success = true;
            result.SnapshotId = create.SnapshotId;
            result.Message = $"C/S 备份完成：{result.FileCount} 文件，新增 {result.NewBlocks} 块，复用 {result.ReusedBlocks} 块";
            return result;
        }
        catch (Exception ex)
        {
            result.Success = false;
            result.Message = $"C/S 备份失败：{ex.Message}";
            return result;
        }
    }

    /// <summary>收集源路径下的文件列表。</summary>
    private static List<string> CollectFiles(string sourcePath)
    {
        if (File.Exists(sourcePath)) return new List<string> { sourcePath };
        if (Directory.Exists(sourcePath))
            return Directory.EnumerateFiles(sourcePath, "*", SearchOption.AllDirectories).ToList();
        throw new DirectoryNotFoundException($"源路径不存在：{sourcePath}");
    }

    /// <summary>分块 + SHA256 + AES-256-GCM 加密单个文件，返回快照条目。</summary>
    private (CsSnapshotEntry Entry, long Size) ProcessFile(
        string file, string relPath,
        Dictionary<string, (byte[] Package, int PlainLen)> blockData,
        List<string> allHashes)
    {
        var entry = new CsSnapshotEntry
        {
            Path = relPath,
            ModifiedUtc = new DateTimeOffset(File.GetLastWriteTimeUtc(file)).ToUnixTimeSeconds()
        };
        var hashes = new List<string>();

        using var fs = File.OpenRead(file);
        var buffer = new byte[BlockSize];
        int read;
        while ((read = fs.Read(buffer, 0, buffer.Length)) > 0)
        {
            var plain = read == buffer.Length ? buffer : buffer[..read];
            var hash = Convert.ToHexString(SHA256.HashData(plain)).ToLowerInvariant();

            if (!blockData.ContainsKey(hash))
            {
                // 客户端本地加密：AES-256-GCM（nonce+tag+cipher 拼接为密文包）
                var nonce = RandomNumberGenerator.GetBytes(12);
                var tag = new byte[16];
                var cipher = new byte[plain.Length];
                using var aes = new AesGcm(_key, 16);
                aes.Encrypt(nonce, plain, cipher, tag);

                var package = new byte[12 + 16 + cipher.Length];
                Buffer.BlockCopy(nonce, 0, package, 0, 12);
                Buffer.BlockCopy(tag, 0, package, 12, 16);
                Buffer.BlockCopy(cipher, 0, package, 28, cipher.Length);
                blockData[hash] = (package, plain.Length);
            }

            hashes.Add(hash);
            allHashes.Add(hash);
        }

        entry.Size = new FileInfo(file).Length;
        entry.BlockHashes = hashes;
        return (entry, entry.Size);
    }

    // ==================== 数据库备份 ====================

    /// <summary>
    /// 数据库备份 C/S 流程：客户端本地 dump → 生成加密备份流分片上传（不落地明文临时文件）。
    /// </summary>
    /// <param name="dbType">数据库类型。</param>
    /// <param name="dbName">实例名（快照条目标识）。</param>
    /// <param name="dumpPlain">数据库 dump 明文流（调用方本地 dump，如 mysqldump/pg_dump 输出）。</param>
    /// <param name="name">快照名称。</param>
    public async Task<CsBackupResult> BackupDatabaseStreamAsync(
        string dbType, string dbName, Stream dumpPlain, string name,
        Action<CsBackupProgress>? progress = null, CancellationToken ct = default)
    {
        var result = new CsBackupResult { FileCount = 1 };
        var connect = await _client.ConnectAsync(ct).ConfigureAwait(false);
        if (!connect.Success)
        {
            result.Success = false;
            result.Message = connect.Message;
            return result;
        }

        try
        {
            // 分片加密上传：每个 1MB 明文分片作为一个块
            var entryHashes = new List<string>();
            var allHashes = new List<string>();
            var blockData = new Dictionary<string, (byte[] Package, int PlainLen)>(StringComparer.OrdinalIgnoreCase);
            var buffer = new byte[1024 * 1024];
            long total = 0;
            int chunkIndex = 0;

            int read;
            while ((read = await dumpPlain.ReadAsync(buffer, ct).ConfigureAwait(false)) > 0)
            {
                ct.ThrowIfCancellationRequested();
                var plain = read == buffer.Length ? buffer : buffer[..read];
                var hash = Convert.ToHexString(SHA256.HashData(plain)).ToLowerInvariant();

                if (!blockData.ContainsKey(hash))
                {
                    var nonce = RandomNumberGenerator.GetBytes(12);
                    var tag = new byte[16];
                    var cipher = new byte[plain.Length];
                    using var aes = new AesGcm(_key, 16);
                    aes.Encrypt(nonce, plain, cipher, tag);

                    var package = new byte[12 + 16 + cipher.Length];
                    Buffer.BlockCopy(nonce, 0, package, 0, 12);
                    Buffer.BlockCopy(tag, 0, package, 12, 16);
                    Buffer.BlockCopy(cipher, 0, package, 28, cipher.Length);
                    blockData[hash] = (package, plain.Length);
                }

                entryHashes.Add(hash);
                allHashes.Add(hash);
                total += read;
                chunkIndex++;
            }

            // 查询缺失 + 仅上传缺失块
            var missing = await _client.FindMissingAsync(allHashes, ct).ConfigureAwait(false);
            var missingSet = missing.ToHashSet(StringComparer.OrdinalIgnoreCase);
            result.ReusedBlocks = allHashes.Count - missingSet.Count;

            var uploaded = 0L;
            foreach (var kv in blockData)
            {
                ct.ThrowIfCancellationRequested();
                if (!missingSet.Contains(kv.Key)) continue;
                await _client.UploadBlockAsync(kv.Key, kv.Value.Package, kv.Value.PlainLen, ct).ConfigureAwait(false);
                uploaded += kv.Value.Package.Length;
                result.NewBlocks++;
            }

            // 创建快照（单个数据库流条目）
            var create = await _client.CreateSnapshotAsync(new CsSnapshotCreate
            {
                Name = name,
                SourcePath = $"{dbType}:{dbName}",
                Entries = new List<CsSnapshotEntry>
                {
                    new CsSnapshotEntry
                    {
                        Path = $"{dbType}:{dbName}",
                        Size = total,
                        IsDbStream = true,
                        DbType = dbType,
                        DbName = dbName,
                        BlockHashes = entryHashes,
                        ModifiedUtc = DateTimeOffset.UtcNow.ToUnixTimeSeconds()
                    }
                },
                AllBlockHashes = allHashes.Distinct(StringComparer.OrdinalIgnoreCase).ToList(),
                Cipher = "AES-256-GCM",
                CreatedUtc = DateTimeOffset.UtcNow.ToUnixTimeSeconds()
            }, ct).ConfigureAwait(false);

            if (!create.Ok)
            {
                result.Success = false;
                result.Message = create.Message;
                return result;
            }

            await _client.CleanupAsync(20, ClientId, ct).ConfigureAwait(false);

            result.Success = true;
            result.SnapshotId = create.SnapshotId;
            result.TotalBytes = total;
            result.Message = $"C/S 数据库备份完成：{dbType}:{dbName}，{total / 1024.0:F1} KB，新增 {result.NewBlocks} 块";
            return result;
        }
        catch (Exception ex)
        {
            result.Success = false;
            result.Message = $"C/S 数据库备份失败：{ex.Message}";
            return result;
        }
    }

    // ==================== 恢复 ====================

    /// <summary>
    /// 从快照恢复：拉取快照元数据 → 分片下载块密文 → 本地解密 → 写回目标路径。
    /// </summary>
    /// <param name="snapshotId">快照 ID。</param>
    /// <param name="destDir">恢复目标目录。</param>
    public async Task<CsBackupResult> RestoreAsync(string snapshotId, string destDir, Action<CsBackupProgress>? progress = null, CancellationToken ct = default)
    {
        var result = new CsBackupResult();
        var connect = await _client.ConnectAsync(ct).ConfigureAwait(false);
        if (!connect.Success)
        {
            result.Success = false;
            result.Message = connect.Message;
            return result;
        }

        try
        {
            var meta = await _client.GetSnapshotAsync(snapshotId, ct).ConfigureAwait(false);
            if (meta?.Entries == null)
            {
                result.Success = false;
                result.Message = $"快照不存在：{snapshotId}";
                return result;
            }

            Directory.CreateDirectory(destDir);
            var restoredBytes = 0L;

            // 数据库流恢复：写出为单个文件
            foreach (var entry in meta.Entries)
            {
                ct.ThrowIfCancellationRequested();
                if (entry.BlockHashes == null) continue;

                string outPath;
                if (entry.IsDbStream)
                {
                    outPath = Path.Combine(destDir, $"restore_{Path.GetFileName(entry.Path ?? "dbstream")}.sql");
                }
                else
                {
                    outPath = Path.Combine(destDir, entry.Path!.Replace('/', Path.DirectorySeparatorChar));
                }
                var dir = Path.GetDirectoryName(outPath);
                if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);

                // 按顺序下载块 → 解密 → 写回
                using (var outFs = new FileStream(outPath, FileMode.Create, FileAccess.Write, FileShare.None))
                {
                    foreach (var hash in entry.BlockHashes)
                    {
                        ct.ThrowIfCancellationRequested();
                        var package = await _client.DownloadBlockAsync(hash, 0, ct).ConfigureAwait(false);
                        if (package.Length <= 28) continue; // 空块

                        var plain = DecryptPackage(package);
                        await outFs.WriteAsync(plain, ct).ConfigureAwait(false);
                        restoredBytes += plain.Length;
                        progress?.Invoke(new CsBackupProgress { Stage = $"恢复 {entry.Path}", UploadedBytes = restoredBytes });
                    }
                }

                // 恢复修改时间
                if (!entry.IsDbStream && entry.ModifiedUtc > 0)
                {
                    try { File.SetLastWriteTimeUtc(outPath, DateTimeOffset.FromUnixTimeSeconds(entry.ModifiedUtc).UtcDateTime); } catch { }
                }
                result.FileCount++;
            }

            result.Success = true;
            result.TotalBytes = restoredBytes;
            result.Message = $"C/S 恢复完成：{result.FileCount} 条目，{restoredBytes / 1024.0:F1} KB → {destDir}";
            return result;
        }
        catch (Exception ex)
        {
            result.Success = false;
            result.Message = $"C/S 恢复失败：{ex.Message}";
            return result;
        }
    }

    /// <summary>解密密文包（nonce+tag+cipher）。</summary>
    private byte[] DecryptPackage(byte[] package)
    {
        if (package.Length <= 28) return Array.Empty<byte>();
        var nonce = package[..12];
        var tag = package[12..28];
        var cipher = package[28..];
        var plain = new byte[cipher.Length];
        using var aes = new AesGcm(_key, 16);
        aes.Decrypt(nonce, cipher, tag, plain);
        return plain;
    }

    /// <summary>列出快照（供恢复选择）。</summary>
    public Task<List<CsSnapshotSummary>> ListSnapshotsAsync(CancellationToken ct = default)
    {
        return _client.ListSnapshotsAsync(ClientId, ct);
    }

    /// <summary>清理过期快照。</summary>
    public Task<CsSnapshotCleanupResult> CleanupAsync(int maxPerClient, CancellationToken ct = default)
    {
        return _client.CleanupAsync(maxPerClient, ClientId, ct);
    }

    /// <summary>释放资源。</summary>
    public void Dispose() => _client.Dispose();
}
