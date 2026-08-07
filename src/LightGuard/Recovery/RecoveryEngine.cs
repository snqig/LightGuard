// © 2026 落尘（Luochen） 原创开发 - 保留所有权利

using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using LightGuard.Backup;
using LightGuard.Core;

namespace LightGuard.Recovery;

/// <summary>
/// 灾难恢复引擎 - 从 .lgbackup 加密备份包精准恢复数据。
/// <para>强制固定流程：读取备份包 → 输入密钥 → AES/ChaCha 解密 → SHA256 完整性校验 → 磁盘空间检测 → 按模式恢复。</para>
/// <para>支持三种恢复模式、跨设备 SMB 远程恢复、在线预览、版本回溯。</para>
/// </summary>
public sealed class RecoveryEngine
{
    /// <summary>恢复进度变更事件。</summary>
    public event Action<RecoveryProgressInfo>? ProgressChanged;

    private readonly AppState? _appState;

    /// <summary>
    /// 初始化恢复引擎。
    /// </summary>
    /// <param name="appState">全局应用状态（可选，用于硬件自适应）。</param>
    public RecoveryEngine(AppState? appState = null)
    {
        _appState = appState;
    }

    /// <summary>
    /// 从加密备份包恢复数据。
    /// </summary>
    /// <param name="backupPath">.lgbackup 备份包路径（本地或 SMB UNC）。</param>
    /// <param name="password">解密口令。</param>
    /// <param name="destDir">恢复目标目录（本地或 SMB UNC）。</param>
    /// <param name="mode">恢复模式。</param>
    /// <returns>恢复结果。</returns>
    public RecoveryResult Recover(string backupPath, string password, string destDir, RecoveryMode mode)
    {
        var result = new RecoveryResult();
        try
        {
            ErrorReporter.Log($"开始恢复：{backupPath} -> {destDir}（模式={mode}）");

            // 1. 读取备份包
            var (manifest, shards) = LgBackupFormat.ReadBackup(backupPath);
            result.Manifest = manifest;

            // 2. 派生密钥（按备份时记录的算法）
            var salt = Convert.FromBase64String(manifest.Salt);
            var crypto = new BackupCryptoEngine(manifest.EncryptedAlgorithm);
            var key = crypto.DeriveKey(password, salt);

            // 3. 解密 + 分片级 SHA256 校验
            var plainShards = new List<BackupShard>(shards.Count);
            using var sha = SHA256.Create();
            int decrypted = 0;
            foreach (var s in shards.OrderBy(x => x.Index))
            {
                // GCM 认证失败会抛出 AuthenticationTagMismatchException
                var plain = crypto.Decrypt(s.Cipher, key, s.Nonce, s.Tag);

                // 分片级哈希校验
                var actualHash = SHA256.HashData(plain);
                if (!ConstantTimeEquals(actualHash, s.PlainHash))
                    throw new InvalidDataException($"分片 {s.Index} 哈希校验失败，数据可能已损坏。");

                sha.TransformBlock(plain, 0, plain.Length, null, 0);
                plainShards.Add(new BackupShard { Index = s.Index, Length = plain.Length, Data = plain });
                decrypted++;
                RaiseProgress(decrypt: decrypted * 100.0 / shards.Count, current: manifest.SourcePath);
            }
            sha.TransformFinalBlock(Array.Empty<byte>(), 0, 0);

            // 4. 整包 SHA256 完整性校验
            var globalHash = Convert.ToHexString(sha.Hash ?? Array.Empty<byte>());
            if (!string.Equals(globalHash, manifest.GlobalHash, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("整包 SHA256 完整性校验失败，备份数据已被篡改或损坏。");
            RaiseProgress(verify: 100);

            // 5. 磁盘空间检测
            EnsureDiskSpace(destDir, manifest.TotalSize);

            // 6. 合并分片
            var data = BackupShardEngine.MergeShards(plainShards);

            // 7. 按备份类型恢复
            result = manifest.BackupType switch
            {
                BackupType.File => RecoverSingleFile(data, manifest, destDir, mode),
                BackupType.Directory => RecoverDirectory(data, manifest, destDir, mode),
                BackupType.Partition => RecoverPartition(data, manifest, destDir, mode),
                BackupType.Disk => RecoverDisk(data, manifest, destDir, mode),
                BackupType.Database => RecoverDatabase(data, manifest, destDir, mode),
                _ => throw new NotSupportedException($"不支持的备份类型：{manifest.BackupType}")
            };
            result.Manifest = manifest;

            ErrorReporter.Log($"恢复完成：{manifest.BackupType} | 文件 {result.FileCount} | {result.TotalBytes} 字节 -> {destDir}");
        }
        catch (AuthenticationTagMismatchException ex)
        {
            result.Success = false;
            result.Message = "解密认证失败：密钥错误或备份已被篡改。";
            ErrorReporter.Report(ex, $"恢复认证失败：{backupPath}");
        }
        catch (Exception ex)
        {
            result.Success = false;
            result.Message = $"恢复失败：{ex.Message}";
            ErrorReporter.Report(ex, $"恢复失败：{backupPath}");
        }
        return result;
    }

    /// <summary>
    /// 恢复单文件。
    /// </summary>
    public RecoveryResult RecoverSingleFile(byte[] data, BackupManifest manifest, string destDir, RecoveryMode mode)
    {
        var targetDir = ResolveTargetDir(destDir, mode, manifest);
        Directory.CreateDirectory(targetDir);

        var fileName = !string.IsNullOrEmpty(manifest.SourcePath)
            ? Path.GetFileName(manifest.SourcePath)
            : "recovered_file";
        if (string.IsNullOrEmpty(fileName)) fileName = "recovered_file";

        var outPath = Path.Combine(targetDir, fileName);
        int written = WriteFileWithMode(outPath, data, mode, manifest.BackupTime);

        return new RecoveryResult
        {
            Success = true,
            Message = written > 0 ? $"已恢复文件到 {outPath}" : $"文件未变更，跳过 {outPath}",
            FileCount = written,
            TotalBytes = written > 0 ? data.Length : 0,
            Manifest = manifest
        };
    }

    /// <summary>
    /// 恢复目录（从归档还原全部文件）。
    /// </summary>
    public RecoveryResult RecoverDirectory(byte[] data, BackupManifest manifest, string destDir, RecoveryMode mode)
    {
        var targetDir = ResolveTargetDir(destDir, mode, manifest);
        Directory.CreateDirectory(targetDir);

        var entries = BackupExecutor.ExtractDirectoryArchive(data);
        int written = 0;
        long bytes = 0;
        int idx = 0;

        foreach (var (relPath, fileData) in entries)
        {
            var outPath = Path.Combine(targetDir, relPath);
            var dir = Path.GetDirectoryName(outPath);
            if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);

            int w = WriteFileWithMode(outPath, fileData, mode, manifest.BackupTime);
            if (w > 0) { written++; bytes += fileData.Length; }
            idx++;
            RaiseProgress(write: idx * 100.0 / Math.Max(1, entries.Count), current: relPath);
        }

        return new RecoveryResult
        {
            Success = true,
            Message = $"已恢复 {written} 个文件到 {targetDir}",
            FileCount = written,
            TotalBytes = bytes,
            Manifest = manifest
        };
    }

    /// <summary>
    /// 恢复分区镜像（写入镜像文件，裸机恢复到设备需在 PE 环境执行）。
    /// </summary>
    public RecoveryResult RecoverPartition(byte[] data, BackupManifest manifest, string destDir, RecoveryMode mode)
    {
        var targetDir = ResolveTargetDir(destDir, mode, manifest);
        Directory.CreateDirectory(targetDir);

        var drive = manifest.Metadata != null && manifest.Metadata.TryGetValue("DriveLetter", out var dl) ? dl : "X";
        var outPath = Path.Combine(targetDir, $"Partition_{drive}_image.bin");
        int written = WriteFileWithMode(outPath, data, mode, manifest.BackupTime);

        ErrorReporter.Log($"分区镜像已写入 {outPath}（{data.Length} 字节）。恢复到原始设备为破坏性操作，请在 PE 环境执行。");
        return new RecoveryResult
        {
            Success = true,
            Message = $"分区镜像已恢复到 {outPath}（恢复到设备需在 PE 环境）",
            FileCount = written,
            TotalBytes = written > 0 ? data.Length : 0,
            Manifest = manifest
        };
    }

    /// <summary>
    /// 恢复整盘镜像（写入镜像文件，裸机恢复到设备需在 PE 环境执行）。
    /// </summary>
    public RecoveryResult RecoverDisk(byte[] data, BackupManifest manifest, string destDir, RecoveryMode mode)
    {
        var targetDir = ResolveTargetDir(destDir, mode, manifest);
        Directory.CreateDirectory(targetDir);

        var diskNo = manifest.Metadata != null && manifest.Metadata.TryGetValue("DiskNumber", out var dn) ? dn : "0";
        var outPath = Path.Combine(targetDir, $"Disk_{diskNo}_image.bin");
        int written = WriteFileWithMode(outPath, data, mode, manifest.BackupTime);

        ErrorReporter.Log($"整盘镜像已写入 {outPath}（{data.Length} 字节）。恢复到原始设备为破坏性操作，请在 PE 环境执行。");
        return new RecoveryResult
        {
            Success = true,
            Message = $"整盘镜像已恢复到 {outPath}（恢复到设备需在 PE 环境）",
            FileCount = written,
            TotalBytes = written > 0 ? data.Length : 0,
            Manifest = manifest
        };
    }

    /// <summary>
    /// 恢复数据库（写出数据库文件 / 转储文件）。
    /// </summary>
    public RecoveryResult RecoverDatabase(byte[] data, BackupManifest manifest, string destDir, RecoveryMode mode)
    {
        var targetDir = ResolveTargetDir(destDir, mode, manifest);
        Directory.CreateDirectory(targetDir);

        var fileName = !string.IsNullOrEmpty(manifest.SourcePath)
            ? Path.GetFileName(manifest.SourcePath)
            : "database_backup";
        if (string.IsNullOrEmpty(fileName)) fileName = "database_backup";

        var outPath = Path.Combine(targetDir, fileName);
        int written = WriteFileWithMode(outPath, data, mode, manifest.BackupTime);

        return new RecoveryResult
        {
            Success = true,
            Message = $"数据库已恢复到 {outPath}",
            FileCount = written,
            TotalBytes = written > 0 ? data.Length : 0,
            Manifest = manifest
        };
    }

    /// <summary>
    /// 备份包在线预览（不完整下载 / 不解密，仅读取清单与分片索引）。
    /// </summary>
    /// <param name="backupPath">备份包路径。</param>
    /// <returns>预览信息。</returns>
    public BackupPreview PreviewBackup(string backupPath)
    {
        var (manifest, shardCount, packageSize) = LgBackupFormat.ReadManifestOnly(backupPath);
        return new BackupPreview
        {
            Manifest = manifest,
            ShardCount = shardCount,
            PackageSize = packageSize,
            TotalSize = manifest.TotalSize
        };
    }

    // ==================== 选择性还原（浏览 + 批量恢复） ====================

    /// <summary>
    /// 异步加载备份包清单（仅读取头部与清单区块，不解密文件数据体）。
    /// <para>通过解密首个分片认证标签快速校验密钥正确性：密钥错误抛出 <see cref="AuthenticationTagMismatchException"/>。</para>
    /// </summary>
    /// <param name="backupPath">.lgbackup 备份包路径。</param>
    /// <param name="password">解密口令。</param>
    /// <param name="progress">进度回调（0-100）。</param>
    /// <param name="ct">取消令牌。</param>
    /// <returns>备份清单。</returns>
    public Task<BackupManifest> LoadBackupManifestAsync(
        string backupPath, string password,
        IProgress<double>? progress = null, CancellationToken ct = default)
    {
        return Task.Run(() =>
        {
            ct.ThrowIfCancellationRequested();
            var (manifest, _, _) = LgBackupFormat.ReadManifestOnly(backupPath);

            if (!string.IsNullOrEmpty(password))
            {
                var salt = Convert.FromBase64String(manifest.Salt);
                var crypto = new BackupCryptoEngine(manifest.EncryptedAlgorithm);
                var key = crypto.DeriveKey(password, salt);
                ValidateKeyByFirstShard(backupPath, crypto, key);
            }

            progress?.Report(100);
            return manifest;
        }, ct);
    }

    /// <summary>
    /// 异步解密备份包归档并解析文件条目（选择性还原浏览的数据源）。
    /// <para>逐分片解密 + 分片级 SHA256 校验 + 整包哈希校验；条目含归档物理偏移，
    /// 供批量还原按偏移顺序读取（减少随机 IO）。</para>
    /// </summary>
    public Task<RecoveryArchive> LoadArchiveEntriesAsync(
        string backupPath, string password,
        IProgress<double>? progress = null, CancellationToken ct = default)
    {
        return Task.Run(() => LoadArchiveEntries(backupPath, password, progress, ct), ct);
    }

    /// <summary>
    /// 解密备份包归档并解析文件条目（同步核心实现）。
    /// </summary>
    public RecoveryArchive LoadArchiveEntries(
        string backupPath, string password,
        IProgress<double>? progress = null, CancellationToken ct = default)
    {
        var (manifest, shards) = LgBackupFormat.ReadBackup(backupPath);
        var salt = Convert.FromBase64String(manifest.Salt);
        var crypto = new BackupCryptoEngine(manifest.EncryptedAlgorithm);
        var key = crypto.DeriveKey(password, salt);

        using var sha = SHA256.Create();
        using var ms = new MemoryStream();
        int total = shards.Count;
        int done = 0;
        foreach (var s in shards.OrderBy(x => x.Index))
        {
            ct.ThrowIfCancellationRequested();
            // GCM 认证失败抛 AuthenticationTagMismatchException（密钥错误/被篡改）
            var plain = crypto.Decrypt(s.Cipher, key, s.Nonce, s.Tag);

            // 分片级哈希校验
            var actualHash = SHA256.HashData(plain);
            if (!ConstantTimeEquals(actualHash, s.PlainHash))
                throw new InvalidDataException($"分片 {s.Index} 哈希校验失败，数据可能已损坏。");

            sha.TransformBlock(plain, 0, plain.Length, null, 0);
            ms.Write(plain, 0, plain.Length);
            done++;
            progress?.Report(done * 100.0 / total);
        }
        sha.TransformFinalBlock(Array.Empty<byte>(), 0, 0);

        // 整包 SHA256 完整性校验
        var globalHash = Convert.ToHexString(sha.Hash ?? Array.Empty<byte>());
        if (!string.Equals(globalHash, manifest.GlobalHash, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("整包 SHA256 完整性校验失败，备份数据已被篡改或损坏。");

        var archiveBytes = ms.ToArray();
        return new RecoveryArchive(archiveBytes, ParseArchiveEntries(archiveBytes), manifest);
    }

    /// <summary>
    /// 预计算选中项的总大小与文件数（目录选中自动递归展开）。
    /// </summary>
    /// <returns>(总字节数, 文件数)。</returns>
    public (long TotalSize, int FileCount) CalculateSelectedSize(
        RecoveryArchive archive, IReadOnlyCollection<string> selectedPaths)
    {
        var selected = ExpandSelection(archive.Entries, selectedPaths);
        return (selected.Sum(e => e.Length), selected.Count);
    }

    /// <summary>
    /// 批量选择性还原（异步）：按选中路径列表还原文件 / 目录。
    /// <para>目录选中自动递归展开为所有子文件；单文件失败不中断整体任务，
    /// 全部异常捕获写入结果明细；选中项按归档物理偏移排序顺序写入。</para>
    /// </summary>
    /// <param name="archive">已解密归档（由 <see cref="LoadArchiveEntries"/> 获得）。</param>
    /// <param name="manifest">备份清单。</param>
    /// <param name="selectedPaths">选中路径列表（相对路径，文件或目录）。</param>
    /// <param name="destDir">恢复目标目录。</param>
    /// <param name="mode">恢复模式。</param>
    /// <returns>批量还原结果（成功/失败明细）。</returns>
    public Task<RecoveryBatchResult> RecoverSelectedItemsAsync(
        RecoveryArchive archive, BackupManifest manifest,
        IReadOnlyCollection<string> selectedPaths, string destDir, RecoveryMode mode,
        IProgress<RecoveryProgressInfo>? progress = null, CancellationToken ct = default)
    {
        return Task.Run(
            () => RecoverSelectedItems(archive, manifest, selectedPaths, destDir, mode, progress, ct),
            ct);
    }

    /// <summary>
    /// 批量选择性还原（同步核心实现）。
    /// </summary>
    public RecoveryBatchResult RecoverSelectedItems(
        RecoveryArchive archive, BackupManifest manifest,
        IReadOnlyCollection<string> selectedPaths, string destDir, RecoveryMode mode,
        IProgress<RecoveryProgressInfo>? progress = null, CancellationToken ct = default)
    {
        var result = new RecoveryBatchResult();
        try
        {
            // 1. 展开选中项（目录递归展开为文件）
            var selected = ExpandSelection(archive.Entries, selectedPaths);
            if (selected.Count == 0)
            {
                result.Message = "所选路径在备份包中未找到任何文件。";
                return result;
            }

            // 2. 资源预校验：磁盘空间 + 写入权限（任务启动前拦截，避免半截文件）
            long totalSize = selected.Sum(e => e.Length);
            var precheck = PrecheckTarget(destDir, totalSize, mode);
            if (precheck != null)
            {
                result.Message = precheck;
                return result;
            }

            // 3. 按归档物理偏移排序（顺序读取，减少随机磁盘 IO）
            selected = selected.OrderBy(e => e.ArchiveOffset).ToList();

            // 4. 逐个还原（单文件失败容错，不中断整体）
            long processed = 0;
            int fileIdx = 0;
            var startedAt = DateTime.Now;
            foreach (var entry in selected)
            {
                ct.ThrowIfCancellationRequested();
                fileIdx++;
                try
                {
                    var data = archive.GetEntryData(entry);
                    var targetDir = ResolveTargetDir(destDir, mode, manifest);
                    var outPath = Path.Combine(targetDir, entry.RelPath.Replace('/', Path.DirectorySeparatorChar));
                    var dir = Path.GetDirectoryName(outPath);
                    if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);

                    int w = WriteFileWithMode(outPath, data, mode, manifest.BackupTime);
                    if (w > 0)
                    {
                        result.SuccessCount++;
                        result.TotalBytes += data.Length;
                    }
                    else
                    {
                        result.SkippedCount++;
                    }
                }
                catch (Exception ex)
                {
                    result.FailCount++;
                    result.Failures.Add(new RecoveryFailure { RelPath = entry.RelPath, Error = ex.Message });
                    AuditLogSystem.LogError(LogCategory.SelectiveRecovery,
                        $"选择性还原失败：{entry.RelPath}", ex.Message);
                }

                processed += entry.Length;
                var pct = totalSize > 0 ? processed * 100.0 / totalSize : 100;
                var elapsed = (DateTime.Now - startedAt).TotalSeconds;
                var speed = elapsed > 0 ? processed / elapsed : 0;
                var remainingSec = speed > 0 ? (totalSize - processed) / speed : 0;
                progress?.Report(new RecoveryProgressInfo
                {
                    WriteProgress = pct,
                    Percent = pct,
                    CurrentFile = entry.RelPath,
                    TotalFiles = selected.Count,
                    ProcessedFiles = fileIdx,
                    BytesProcessed = processed,
                    SpeedBytesPerSec = speed,
                    RemainingTime = TimeSpan.FromSeconds(Math.Max(0, remainingSec))
                });
            }

            result.Message = result.FailCount == 0
                ? $"已还原 {result.SuccessCount} 个文件（跳过 {result.SkippedCount}）"
                : $"完成：成功 {result.SuccessCount} / 失败 {result.FailCount}（跳过 {result.SkippedCount}）";

            ErrorReporter.Log(
                $"选择性还原完成：成功 {result.SuccessCount}，跳过 {result.SkippedCount}，失败 {result.FailCount}，" +
                $"{result.TotalBytes} 字节 -> {destDir}（模式={mode}，耗时 {result.Elapsed.TotalSeconds:F1}s）");
        }
        catch (Exception ex)
        {
            result.FailCount++;
            result.Failures.Add(new RecoveryFailure { RelPath = "(任务)", Error = ex.Message });
            result.Message = $"选择性还原任务异常：{ex.Message}";
            ErrorReporter.Report(ex, "选择性还原任务异常");
        }
        return result;
    }

    /// <summary>将选中路径列表展开为匹配的归档条目（目录递归展开，忽略大小写，去重）</summary>
    private static List<RecoveryArchiveEntry> ExpandSelection(
        IReadOnlyList<RecoveryArchiveEntry> entries, IReadOnlyCollection<string> paths)
    {
        var result = new List<RecoveryArchiveEntry>();
        foreach (var path in paths)
        {
            if (string.IsNullOrWhiteSpace(path)) continue;
            var p = path.Replace('\\', '/').Trim('/');
            foreach (var e in entries)
            {
                var rel = e.RelPath.Replace('\\', '/');
                if (string.Equals(rel, p, StringComparison.OrdinalIgnoreCase) ||
                    rel.StartsWith(p + "/", StringComparison.OrdinalIgnoreCase))
                {
                    result.Add(e);
                }
            }
        }
        return result
            .DistinctBy(e => e.RelPath, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    /// <summary>
    /// 还原前资源预校验：磁盘剩余空间 + 目标写入权限。
    /// </summary>
    /// <returns>null 表示通过；否则返回拒绝原因。</returns>
    internal static string? PrecheckTarget(string destDir, long required, RecoveryMode mode)
    {
        try
        {
            var root = Path.GetPathRoot(destDir);
            if (!string.IsNullOrEmpty(root) && root.Contains(':'))
            {
                var drive = new DriveInfo(root);
                if (drive.AvailableFreeSpace < required)
                {
                    return $"目标磁盘空间不足：需要 {required / 1024.0 / 1024:F1} MB，" +
                           $"可用 {drive.AvailableFreeSpace / 1024.0 / 1024:F1} MB。";
                }
            }

            // 写入权限探测（在目标或其父目录创建临时文件后删除）
            var probeBase = Directory.Exists(destDir) ? destDir : Path.GetDirectoryName(destDir);
            if (!string.IsNullOrEmpty(probeBase) && Directory.Exists(probeBase))
            {
                var probe = Path.Combine(probeBase, $".lg_write_probe_{Guid.NewGuid():N}.tmp");
                File.WriteAllBytes(probe, Array.Empty<byte>());
                File.Delete(probe);
            }
            return null;
        }
        catch (UnauthorizedAccessException)
        {
            return $"目标路径无写入权限：{destDir}";
        }
        catch (IOException ex)
        {
            return $"目标路径不可写：{destDir}（{ex.Message}）";
        }
        catch (Exception ex)
        {
            ErrorReporter.Log($"写入权限探测异常，跳过：{ex.Message}");
            return null;
        }
    }

    /// <summary>通过解密首个分片快速校验密钥正确性（不解密整个数据体）</summary>
    private static void ValidateKeyByFirstShard(string backupPath, BackupCryptoEngine crypto, byte[] key)
    {
        using var fs = new FileStream(backupPath, FileMode.Open, FileAccess.Read, FileShare.Read);
        using var br = new BinaryReader(fs, Encoding.UTF8, leaveOpen: true);
        br.ReadBytes(LgBackupFormat.Magic.Length);
        br.ReadInt32();                    // 版本
        var manifestLen = br.ReadInt32();
        br.ReadBytes(manifestLen);         // 跳过清单

        var shard = LgBackupFormat.ReadShardRecord(br, 0);
        // GCM 认证失败抛 AuthenticationTagMismatchException
        crypto.Decrypt(shard.Cipher, key, shard.Nonce, shard.Tag);
    }

    /// <summary>解析归档条目（含数据物理偏移，条目数据按需读取不复制）</summary>
    private static List<RecoveryArchiveEntry> ParseArchiveEntries(byte[] archive)
    {
        var list = new List<RecoveryArchiveEntry>();
        using var ms = new MemoryStream(archive, false);
        using var br = new BinaryReader(ms, Encoding.UTF8, leaveOpen: true);

        var count = br.ReadInt64();
        for (long i = 0; i < count; i++)
        {
            var relLen = br.ReadInt32();
            var rel = Encoding.UTF8.GetString(br.ReadBytes(relLen));
            var dataOffset = ms.Position;
            var dataLen = br.ReadInt64();
            br.ReadBytes((int)dataLen);    // 跳过数据，条目仅保留引用与偏移
            list.Add(new RecoveryArchiveEntry
            {
                RelPath = rel,
                Name = Path.GetFileName(rel.Replace('/', Path.DirectorySeparatorChar)),
                ArchiveOffset = dataOffset,
                Length = dataLen
            });
        }
        return list;
    }

    /// <summary>
    /// 版本回溯：根据时间点查找最近的备份包路径。
    /// </summary>
    /// <param name="destDir">备份目录。</param>
    /// <param name="pointInTime">时间点。</param>
    /// <returns>不晚于该时间点的最近备份包路径；无则 null。</returns>
    public string? FindBackupByTime(string destDir, DateTime pointInTime)
    {
        string? best = null;
        DateTime bestTime = DateTime.MinValue;

        if (string.IsNullOrEmpty(destDir) || !Directory.Exists(destDir)) return null;
        foreach (var file in Directory.EnumerateFiles(destDir, "*" + LgBackupFormat.Extension))
        {
            try
            {
                var (manifest, _, _) = LgBackupFormat.ReadManifestOnly(file);
                if (manifest.BackupTime <= pointInTime && manifest.BackupTime > bestTime)
                {
                    bestTime = manifest.BackupTime;
                    best = file;
                }
            }
            catch (Exception ex)
            {
                ErrorReporter.Log($"版本回溯跳过无法读取的备份 {file}：{ex.Message}");
            }
        }
        return best;
    }

    /// <summary>
    /// 跨设备 SMB 远程恢复（destDir 为 UNC 路径时自动适用）。
    /// </summary>
    public RecoveryResult RecoverRemote(string backupPath, string password, string smbDestDir, RecoveryMode mode)
        => Recover(backupPath, password, smbDestDir, mode);

    #region 私有辅助

    private static string ResolveTargetDir(string destDir, RecoveryMode mode, BackupManifest manifest)
    {
        if (mode == RecoveryMode.Isolated)
            return Path.Combine(destDir, $"Recovery_{manifest.BackupId.ToString("N")[..8]}");
        return destDir;
    }

    /// <summary>
    /// 按模式写入文件，返回 1=已写入，0=跳过。
    /// </summary>
    private static int WriteFileWithMode(string outPath, byte[] data, RecoveryMode mode, DateTime timestamp)
    {
        if (File.Exists(outPath))
        {
            if (mode == RecoveryMode.Incremental)
            {
                // 仅恢复变更文件：哈希相同则跳过
                try
                {
                    var existing = File.ReadAllBytes(outPath);
                    if (ConstantTimeEquals(SHA256.HashData(existing), SHA256.HashData(data)))
                        return 0;
                }
                catch { }
            }
            else if (mode != RecoveryMode.ForceOverwrite && mode != RecoveryMode.Isolated)
            {
                return 0;
            }
        }

        File.WriteAllBytes(outPath, data);
        try { File.SetLastWriteTime(outPath, timestamp); } catch { }
        return 1;
    }

    private static void EnsureDiskSpace(string destDir, long required)
    {
        try
        {
            var root = Path.GetPathRoot(destDir);
            if (string.IsNullOrEmpty(root) || !root.Contains(':'))
            {
                ErrorReporter.Log($"目标为网络路径，跳过磁盘空间检测：{destDir}");
                return;
            }
            var drive = new DriveInfo(root);
            if (drive.AvailableFreeSpace < required)
                throw new IOException($"目标磁盘空间不足：需要 {required / 1024.0 / 1024:F1} MB，可用 {drive.AvailableFreeSpace / 1024.0 / 1024:F1} MB");
        }
        catch (IOException) { throw; }
        catch (Exception ex)
        {
            ErrorReporter.Log($"磁盘空间检测失败，跳过：{ex.Message}");
        }
    }

    private static bool ConstantTimeEquals(byte[] a, byte[] b)
    {
        if (a.Length != b.Length) return false;
        int diff = 0;
        for (int i = 0; i < a.Length; i++) diff |= a[i] ^ b[i];
        return diff == 0;
    }

    private void RaiseProgress(double decrypt = 0, double shard = 0, double write = 0, double verify = 0, string? current = null)
    {
        try
        {
            ProgressChanged?.Invoke(new RecoveryProgressInfo
            {
                DecryptProgress = decrypt,
                ShardProgress = shard,
                WriteProgress = write,
                VerifyProgress = verify,
                Percent = (decrypt + shard + write + verify) / 4.0,
                CurrentFile = current ?? string.Empty
            });
        }
        catch { }
    }

    #endregion
}

/// <summary>
/// 恢复执行结果。
/// </summary>
public sealed class RecoveryResult
{
    /// <summary>是否成功。</summary>
    public bool Success { get; set; }

    /// <summary>结果消息。</summary>
    public string Message { get; set; } = string.Empty;

    /// <summary>已恢复文件数。</summary>
    public int FileCount { get; set; }

    /// <summary>已恢复字节数。</summary>
    public long TotalBytes { get; set; }

    /// <summary>对应的备份清单。</summary>
    public BackupManifest? Manifest { get; set; }
}

/// <summary>
/// 备份包在线预览信息。
/// </summary>
public sealed class BackupPreview
{
    /// <summary>备份清单。</summary>
    public BackupManifest Manifest { get; set; } = new();

    /// <summary>分片数量。</summary>
    public int ShardCount { get; set; }

    /// <summary>备份包文件大小（字节）。</summary>
    public long PackageSize { get; set; }

    /// <summary>原始数据总大小（字节）。</summary>
    public long TotalSize { get; set; }
}

/// <summary>
/// 已解密备份归档（选择性还原浏览 / 批量恢复的数据源）。
/// <para>保留完整明文归档字节，条目仅记录相对路径与物理偏移，
/// 需要时按偏移读取对应数据，避免全量复制造成双倍内存。</para>
/// </summary>
public sealed class RecoveryArchive
{
    private readonly byte[] _data;

    /// <summary>归档条目列表（按归档物理顺序）。</summary>
    public IReadOnlyList<RecoveryArchiveEntry> Entries { get; }

    /// <summary>归档原始数据总大小（字节）。</summary>
    public long TotalSize { get; }

    /// <summary>对应备份清单（源路径 / 备份时间 / 恢复模式适配用）。</summary>
    public BackupManifest Manifest { get; }

    internal RecoveryArchive(byte[] data, List<RecoveryArchiveEntry> entries, BackupManifest manifest)
    {
        _data = data;
        Entries = entries;
        TotalSize = data.LongLength;
        Manifest = manifest;
    }

    /// <summary>
    /// 按条目物理偏移读取文件数据（顺序读取，减少随机磁盘 IO）。
    /// </summary>
    public byte[] GetEntryData(RecoveryArchiveEntry entry)
    {
        using var ms = new MemoryStream(_data, false);
        ms.Position = entry.ArchiveOffset;
        using var br = new BinaryReader(ms, Encoding.UTF8, leaveOpen: true);
        var dataLen = br.ReadInt64();
        return br.ReadBytes((int)dataLen);
    }
}

/// <summary>
/// 归档文件条目（相对路径 + 物理偏移，不含数据本体）。
/// </summary>
public sealed class RecoveryArchiveEntry
{
    /// <summary>相对路径（以 '/' 分隔）。</summary>
    public string RelPath { get; init; } = "";

    /// <summary>文件名。</summary>
    public string Name { get; init; } = "";

    /// <summary>文件数据在归档流中的物理偏移（用于顺序读取）。</summary>
    public long ArchiveOffset { get; init; }

    /// <summary>文件数据长度（字节）。</summary>
    public long Length { get; init; }
}

/// <summary>
/// 批量选择性还原结果（成功 / 失败明细汇总）。
/// </summary>
public sealed class RecoveryBatchResult
{
    /// <summary>是否整体成功（无失败项）。</summary>
    public bool Success => FailCount == 0;

    /// <summary>成功还原文件数。</summary>
    public int SuccessCount { get; set; }

    /// <summary>跳过文件数（增量模式文件未变更等）。</summary>
    public int SkippedCount { get; set; }

    /// <summary>失败文件数。</summary>
    public int FailCount { get; set; }

    /// <summary>已还原字节数。</summary>
    public long TotalBytes { get; set; }

    /// <summary>开始时间。</summary>
    public DateTime StartedAt { get; } = DateTime.Now;

    /// <summary>结束时间。</summary>
    public DateTime FinishedAt { get; set; } = DateTime.Now;

    /// <summary>总耗时。</summary>
    public TimeSpan Elapsed => FinishedAt - StartedAt;

    /// <summary>失败明细（相对路径 + 错误信息）。</summary>
    public List<RecoveryFailure> Failures { get; } = new();

    /// <summary>结果消息。</summary>
    public string Message { get; set; } = "";

    /// <summary>选中文件总数（含跳过与失败）。</summary>
    public int TotalSelected => SuccessCount + SkippedCount + FailCount;
}

/// <summary>
/// 单个文件还原失败明细。
/// </summary>
public sealed class RecoveryFailure
{
    /// <summary>失败文件相对路径。</summary>
    public string RelPath { get; init; } = "";

    /// <summary>错误信息。</summary>
    public string Error { get; init; } = "";
}
