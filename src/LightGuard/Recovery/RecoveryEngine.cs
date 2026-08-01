// © 2026 落尘（Luochen） 原创开发 - 保留所有权利

using System.IO;
using System.Linq;
using System.Security.Cryptography;
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
