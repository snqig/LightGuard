// © 2026 落尘（Luochen） 原创开发 - 保留所有权利

using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using LightGuard.Core;
using Microsoft.Win32.SafeHandles;

namespace LightGuard.Backup;

/// <summary>
/// 备份策略类型。
/// </summary>
public enum BackupStrategy
{
    /// <summary>全量备份：备份所有文件。</summary>
    Full,

    /// <summary>增量备份：仅备份自上次任意备份（全量或增量）以来变化的文件（链式依赖，空间最小）。</summary>
    Incremental,

    /// <summary>差异备份：仅备份自上次全量备份以来所有变化的文件（仅依赖全量，恢复简单）。</summary>
    Differential
}

/// <summary>
/// USN 变更记录 - 表示 NTFS USN 日志中的一条文件变更条目。
/// </summary>
public sealed class UsnChangeRecord
{
    /// <summary>文件名（不含路径）。</summary>
    public string FileName { get; set; } = string.Empty;

    /// <summary>完整路径（基于扫描基准路径拼接；无法解析时为文件名）。</summary>
    public string FullPath { get; set; } = string.Empty;

    /// <summary>变更记录的 USN 序号。</summary>
    public long Usn { get; set; }

    /// <summary>变更原因标志位（USN_REASON_* 的位掩码）。</summary>
    public uint Reason { get; set; }

    /// <summary>变更时间。</summary>
    public DateTime Time { get; set; }

    /// <summary>是否为删除操作。</summary>
    public bool IsDelete { get; set; }

    /// <summary>文件引用编号（NTFS MFT 文件参考号，内部用于路径解析）。</summary>
    public long FileReferenceNumber { get; set; }

    /// <summary>父目录文件引用编号（内部用于路径解析）。</summary>
    public long ParentFileReferenceNumber { get; set; }
}

/// <summary>
/// 增量 + 差异备份引擎 - 基于 NTFS USN 日志的高效变更检测与增量/差异备份。
/// <para>增量备份：仅备份自上次任意备份以来变化的文件（链式依赖，空间最小，恢复需全链）。</para>
/// <para>差异备份：仅备份自上次全量备份以来所有变化的文件（仅依赖全量，恢复简单，空间较大）。</para>
/// <para>变更检测优先使用 NTFS USN 日志（O(1) 检测，无需全盘哈希扫描）；USN 不可用时回退到 SHA256 哈希比对。</para>
/// <para>归档二进制格式与 <see cref="BackupExecutor"/> 一致：[条目数 int64] 每条目 [路径长度 int32][路径 UTF8][数据长度 int64][数据]。</para>
/// <para>加密采用 AES-256-GCM / ChaCha20-Poly1305，写入 .lgbackup 私有加密格式。</para>
/// </summary>
public sealed class IncrementalDifferentialEngine
{
    private readonly BackupCryptoEngine _crypto;
    private readonly int _shardSize;

    /// <summary>
    /// 初始化增量/差异备份引擎。
    /// </summary>
    /// <param name="appState">全局应用状态（用于硬件自适应选择加密算法）。</param>
    /// <param name="shardSize">分片大小（字节），默认 4MB。</param>
    public IncrementalDifferentialEngine(AppState appState, int shardSize = BackupShardEngine.DefaultShardSize)
    {
        ArgumentNullException.ThrowIfNull(appState);
        _crypto = new BackupCryptoEngine(appState.Hardware);
        _shardSize = shardSize > 0 ? shardSize : BackupShardEngine.DefaultShardSize;
    }

    /// <summary>当前加密算法名称。</summary>
    public string AlgorithmName => _crypto.AlgorithmName;

    #region 公开备份方法

    /// <summary>
    /// 增量备份 - 仅备份自上次基准备份（全量或增量）以来变化的文件。
    /// <para>变更检测优先使用 USN 日志（若基准清单记录了 UsnEnd），否则回退到 SHA256 哈希比对。</para>
    /// </summary>
    /// <param name="dirPath">源目录路径。</param>
    /// <param name="password">加密口令。</param>
    /// <param name="destDir">目标目录（本地或 SMB UNC 路径）。</param>
    /// <param name="lastFullBaseline">上次基准备份清单（全量或增量；为 null 时等同于全量备份）。</param>
    /// <param name="progress">进度跟踪器（可选）。</param>
    /// <returns>备份清单（含本次变更文件哈希映射，可作为下次增量基准）。</returns>
    public BackupManifest BackupIncremental(string dirPath, string password, string destDir,
        BackupManifest? lastFullBaseline, BackupProgress? progress = null)
    {
        return ExecuteStrategyBackup(dirPath, password, destDir, lastFullBaseline, progress, BackupStrategy.Incremental);
    }

    /// <summary>
    /// 差异备份 - 仅备份自上次全量备份以来所有变化的文件。
    /// <para>变更检测优先使用 USN 日志（若全量基准清单记录了 UsnEnd），否则回退到 SHA256 哈希比对。</para>
    /// </summary>
    /// <param name="dirPath">源目录路径。</param>
    /// <param name="password">加密口令。</param>
    /// <param name="destDir">目标目录（本地或 SMB UNC 路径）。</param>
    /// <param name="lastFullBaseline">上次全量备份清单（为 null 时等同于全量备份）。</param>
    /// <param name="progress">进度跟踪器（可选）。</param>
    /// <returns>备份清单（含本次变更文件哈希映射）。</returns>
    public BackupManifest BackupDifferential(string dirPath, string password, string destDir,
        BackupManifest? lastFullBaseline, BackupProgress? progress = null)
    {
        return ExecuteStrategyBackup(dirPath, password, destDir, lastFullBaseline, progress, BackupStrategy.Differential);
    }

    /// <summary>
    /// 合并差异链 - 将全量备份 + 所有基于它的差异备份合并为新的全量备份（每周自动合并）。
    /// <para>流程：定位最新全量 → 读取解密全量归档 → 按时间顺序读取解密每个差异归档并叠加变更 → 写入新全量 .lgbackup。</para>
    /// <para>合并后新全量备份锁定保护，旧差异链可由生命周期管理器清理。</para>
    /// </summary>
    /// <param name="destDir">目标目录。</param>
    /// <param name="password">加密口令（用于解密旧备份与加密新备份）。</param>
    /// <param name="progress">进度跟踪器（可选）。</param>
    /// <returns>合并后的新全量备份清单。</returns>
    /// <exception cref="InvalidOperationException">未找到全量备份作为合并基准。</exception>
    public BackupManifest MergeDifferentialChain(string destDir, string password, BackupProgress? progress = null)
    {
        ArgumentNullException.ThrowIfNull(destDir);
        if (string.IsNullOrWhiteSpace(password))
            throw new ArgumentException("加密口令不能为空。", nameof(password));

        ErrorReporter.Log($"开始差异链合并：目录 {destDir}");

        var history = LoadBackupHistory(destDir);
        if (history.Count == 0)
            throw new InvalidOperationException("目标目录中未找到任何备份包。");

        // 定位最新的全量备份（Strategy 为 "Full" 或无 Strategy 标记的旧备份）
        var fullItem = history
            .FirstOrDefault(x => IsFullStrategy(x.Manifest));
        if (fullItem == default)
            throw new InvalidOperationException("未找到全量备份作为合并基准。");

        var fullId = fullItem.Manifest.BackupId;
        ErrorReporter.Log($"合并基准全量备份：{fullId}（{fullItem.Path}）");

        // 查找基于该全量的所有差异备份（按时间正序）
        var differentials = history
            .Where(x => string.Equals(GetStrategy(x.Manifest), "Differential", StringComparison.OrdinalIgnoreCase)
                        && TryGetBaseBackupId(x.Manifest, out var bid)
                        && bid == fullId)
            .OrderBy(x => x.Manifest.BackupTime)
            .ToList();

        if (differentials.Count == 0)
        {
            ErrorReporter.Log("未找到差异备份链，无需合并，直接返回全量备份清单。");
            return fullItem.Manifest;
        }

        ErrorReporter.Log($"找到 {differentials.Count} 个差异备份待合并。");

        // 读取并解密全量归档，构建文件映射
        progress?.SetTotal(differentials.Count + 1, 0);

        var fileMap = new Dictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase);
        try
        {
            var fullArchive = DecryptBackupArchive(fullItem.Path, password);
            foreach (var entry in BackupExecutor.ExtractDirectoryArchive(fullArchive))
            {
                fileMap[entry.RelPath] = entry.Data;
            }
            ErrorReporter.Log($"全量基准归档已加载：{fileMap.Count} 个文件。");
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, $"解密全量备份失败：{fullItem.Path}");
            throw new InvalidOperationException("解密全量备份失败，请检查口令是否正确。", ex);
        }

        progress?.UpdateProgress(1, 0, fullItem.Path, false, BackupPhase.Backup);

        // 按时间顺序叠加每个差异备份的变更
        for (int i = 0; i < differentials.Count; i++)
        {
            progress?.ThrowIfCancellationRequested();
            var diff = differentials[i];

            try
            {
                var diffArchive = DecryptBackupArchive(diff.Path, password);
                var entries = BackupExecutor.ExtractDirectoryArchive(diffArchive);
                int applied = 0;
                foreach (var entry in entries)
                {
                    fileMap[entry.RelPath] = entry.Data;
                    applied++;
                }
                ErrorReporter.Log($"差异备份 [{i + 1}/{differentials.Count}] 已合并：{Path.GetFileName(diff.Path)} | 叠加 {applied} 个文件变更。");
            }
            catch (Exception ex)
            {
                ErrorReporter.Report(ex, $"解密差异备份失败：{diff.Path}");
                throw new InvalidOperationException($"解密差异备份失败（{Path.GetFileName(diff.Path)}），请检查口令是否正确。", ex);
            }

            progress?.UpdateProgress(i + 2, 0, diff.Path, false, BackupPhase.Backup);
        }

        // 构建合并后的归档
        var mergedArchive = BuildArchiveFromMap(fileMap);

        var metadata = new Dictionary<string, string>
        {
            ["Strategy"] = "Full",
            ["MergedFrom"] = fullId.ToString(),
            ["MergedDifferentialCount"] = differentials.Count.ToString(),
            ["MergedTime"] = DateTime.Now.ToString("O")
        };

        // 写入新的全量备份
        var manifest = WriteEncryptedBackup(mergedArchive, BackupType.Directory,
            fullItem.Manifest.SourcePath, destDir, fileMap.Count, password, metadata, progress);

        // 锁定新合并的全量备份，防止生命周期清理误删
        manifest.IsLocked = true;

        ErrorReporter.Log($"差异链合并完成：全量 {fullId} + {differentials.Count} 个差异 → 新全量 {manifest.BackupId} | 文件 {fileMap.Count} | {mergedArchive.Length} 字节");
        return manifest;
    }

    /// <summary>
    /// 使用 USN 日志扫描变更文件 - 返回自上次 USN 以来发生变更的文件路径列表。
    /// <para>USN 日志不可用时回退到全量枚举（返回 basePath 下所有文件，由调用方做哈希比对）。</para>
    /// </summary>
    /// <param name="driveLetter">盘符（如 "C"）。</param>
    /// <param name="lastUsn">上次记录的最大 USN（从该 USN 之后开始扫描）。</param>
    /// <param name="basePath">基准目录路径（用于将 USN 记录解析为完整路径）。</param>
    /// <returns>变更文件完整路径列表（已去重，仅包含当前仍存在的文件）。</returns>
    public List<string> ScanWithUsn(string driveLetter, long lastUsn, string basePath)
    {
        var letter = NormalizeDriveLetter(driveLetter);
        ErrorReporter.Log($"USN 变更扫描：盘符 {letter}: | 起始 USN {lastUsn} | 基准路径 {basePath}");

        List<UsnChangeRecord> records;
        try
        {
            records = UsnJournalScanner.ScanChanges(letter, lastUsn);
            ErrorReporter.Log($"USN 日志扫描完成：{records.Count} 条变更记录。");
        }
        catch (Exception ex)
        {
            ErrorReporter.Log($"USN 日志扫描失败，回退到全量枚举：{ex.Message}", "WARN");
            return FallbackEnumerateAllFiles(basePath);
        }

        // 构建基准目录下 文件名 → 完整路径 的映射（用于将 USN 记录解析为实际路径）
        var nameToPaths = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
        try
        {
            foreach (var file in Directory.EnumerateFiles(basePath, "*", SearchOption.AllDirectories))
            {
                var name = Path.GetFileName(file);
                if (!nameToPaths.TryGetValue(name, out var list))
                {
                    list = new List<string>();
                    nameToPaths[name] = list;
                }
                list.Add(file);
            }
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, $"枚举基准目录失败：{basePath}");
        }

        // 根据变更记录确定变更文件集合
        var changedFiles = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var record in records)
        {
            if (record.IsDelete)
                continue; // 删除的文件不包含在备份中

            // 优先使用记录中的 FullPath（若已被解析）
            if (!string.IsNullOrEmpty(record.FullPath) && File.Exists(record.FullPath))
            {
                // 仅包含基准目录下的文件
                if (FullPathContains(basePath, record.FullPath))
                    changedFiles.Add(record.FullPath);
                continue;
            }

            // 回退到按文件名匹配
            if (nameToPaths.TryGetValue(record.FileName, out var candidates))
            {
                foreach (var candidate in candidates)
                    changedFiles.Add(candidate);
            }
        }

        // 如果 USN 扫描未返回任何变更（可能日志已覆盖或无变更），回退到全量枚举
        if (changedFiles.Count == 0 && records.Count == 0)
        {
            ErrorReporter.Log("USN 未检测到变更，但记录为空，回退到全量枚举以保安全。", "WARN");
            return FallbackEnumerateAllFiles(basePath);
        }

        ErrorReporter.Log($"USN 变更扫描确定 {changedFiles.Count} 个变更文件。");
        return changedFiles.ToList();
    }

    /// <summary>
    /// 获取指定卷的当前最大 USN（即 NextUsn）。
    /// <para>备份完成后记录此值，下次增量/差异备份时作为起始 USN 传入。</para>
    /// </summary>
    /// <param name="driveLetter">盘符（如 "C"）。</param>
    /// <returns>当前最大 USN；USN 日志不可用返回 -1。</returns>
    public long GetLastUsn(string driveLetter)
    {
        var letter = NormalizeDriveLetter(driveLetter);
        try
        {
            var usn = UsnJournalScanner.GetNextUsn(letter);
            ErrorReporter.Log($"获取卷 {letter}: 当前 USN = {usn}");
            return usn;
        }
        catch (Exception ex)
        {
            ErrorReporter.Log($"获取 USN 失败（卷 {letter}:）：{ex.Message}", "WARN");
            return -1;
        }
    }

    #endregion

    #region 核心执行流程

    /// <summary>
    /// 增量/差异备份的共享执行流程。
    /// </summary>
    private BackupManifest ExecuteStrategyBackup(string dirPath, string password, string destDir,
        BackupManifest? baseline, BackupProgress? progress, BackupStrategy strategy)
    {
        if (!Directory.Exists(dirPath))
            throw new DirectoryNotFoundException("待备份目录不存在：" + dirPath);
        if (string.IsNullOrWhiteSpace(password))
            throw new ArgumentException("加密口令不能为空。", nameof(password));
        ArgumentNullException.ThrowIfNull(destDir);

        var strategyName = strategy.ToString();
        ErrorReporter.Log($"开始{strategyName}备份：{dirPath}");

        // 确定 UsnStart（基准备份记录的 UsnEnd）
        long usnStart = 0;
        if (baseline != null && baseline.Metadata.TryGetValue("UsnEnd", out var usnEndStr)
            && long.TryParse(usnEndStr, out var usnEndVal))
        {
            usnStart = usnEndVal;
        }

        // 确定变更文件集合与文件哈希映射
        var (changedFiles, currentHashes, usnUsed) = DetermineChangedFiles(dirPath, baseline, usnStart, progress);

        // 获取 UsnEnd（当前最大 USN）
        long usnEnd = -1;
        try
        {
            var letter = ExtractDriveLetter(dirPath);
            usnEnd = GetLastUsn(letter);
        }
        catch (Exception ex)
        {
            ErrorReporter.Log($"获取 UsnEnd 失败：{ex.Message}", "WARN");
        }

        // 构建变更文件归档（与 BackupExecutor 相同的二进制格式）
        var (archive, fileCount) = BuildChangedArchive(dirPath, changedFiles, currentHashes, progress);

        // 构建元数据
        var metadata = new Dictionary<string, string>
        {
            ["Strategy"] = strategyName,
            ["FileHashes"] = SerializeHashMap(currentHashes),
            ["UsnUsed"] = usnUsed.ToString(),
            ["UsnStart"] = usnStart.ToString(),
            ["UsnEnd"] = (usnEnd >= 0 ? usnEnd : 0).ToString()
        };

        if (baseline != null)
        {
            metadata["BaseBackupId"] = baseline.BackupId.ToString();
            metadata["BaseBackupTime"] = baseline.BackupTime.ToString("O");
        }
        else
        {
            metadata["BaseBackupId"] = Guid.Empty.ToString();
            metadata["BaseBackupTime"] = DateTime.MinValue.ToString("O");
        }

        var manifest = WriteEncryptedBackup(archive, BackupType.Directory, dirPath, destDir,
            fileCount, password, metadata, progress);

        ErrorReporter.Log($"{strategyName}备份完成：{dirPath} -> {manifest.BackupId} | 变更文件 {fileCount} | USN {usnStart}->{usnEnd} | 检测方式 {(usnUsed ? "USN" : "Hash")}");
        return manifest;
    }

    /// <summary>
    /// 确定变更文件集合 - 优先使用 USN 日志，不可用时回退到 SHA256 哈希比对。
    /// </summary>
    /// <returns>(变更文件完整路径列表, 当前全量文件哈希映射, 是否使用了 USN 检测)。</returns>
    private (List<string> ChangedFiles, Dictionary<string, string> CurrentHashes, bool UsnUsed) DetermineChangedFiles(
        string dirPath, BackupManifest? baseline, long usnStart, BackupProgress? progress)
    {
        var currentHashes = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        // 尝试 USN 日志检测
        if (baseline != null && usnStart > 0)
        {
            try
            {
                var letter = ExtractDriveLetter(dirPath);
                var usnChanged = ScanWithUsn(letter, usnStart, dirPath);

                // 对 USN 检测到的变更文件计算哈希，同时构建全量哈希映射
                foreach (var file in usnChanged)
                {
                    progress?.ThrowIfCancellationRequested();
                    string relPath;
                    try
                    {
                        relPath = Path.GetRelativePath(dirPath, file).Replace('\\', '/');
                    }
                    catch
                    {
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

                    currentHashes[relPath] = Convert.ToHexString(SHA256.HashData(data));
                }

                if (usnChanged.Count > 0)
                {
                    ErrorReporter.Log($"USN 检测到 {usnChanged.Count} 个变更文件。");
                    return (usnChanged, currentHashes, true);
                }

                // USN 未检测到变更 - 可能无变化，返回空列表
                ErrorReporter.Log("USN 检测未发现变更文件。");
                return (new List<string>(), currentHashes, true);
            }
            catch (Exception ex)
            {
                ErrorReporter.Log($"USN 变更检测失败，回退到哈希比对：{ex.Message}", "WARN");
            }
        }

        // 回退：全量枚举 + SHA256 哈希比对
        var baselineHashes = ParseHashMap(baseline?.Metadata);
        var changedFiles = new List<string>();

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

        foreach (var file in files)
        {
            progress?.ThrowIfCancellationRequested();

            string relPath;
            try
            {
                relPath = Path.GetRelativePath(dirPath, file).Replace('\\', '/');
            }
            catch
            {
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
            currentHashes[relPath] = hashHex;

            // 与基准哈希比对：不同或新增则视为变更
            bool changed = true;
            if (baselineHashes.TryGetValue(relPath, out var baseHash)
                && string.Equals(baseHash, hashHex, StringComparison.OrdinalIgnoreCase))
            {
                changed = false;
            }

            if (changed)
                changedFiles.Add(file);
        }

        ErrorReporter.Log($"哈希比对完成：{changedFiles.Count} 个变更文件（共 {currentHashes.Count} 个文件）。");
        return (changedFiles, currentHashes, false);
    }

    /// <summary>
    /// 构建变更文件归档字节流。
    /// <para>格式与 <see cref="BackupExecutor"/> 一致：[条目数 int64] 每条目 [路径长度 int32][路径 UTF8][数据长度 int64][数据]。</para>
    /// </summary>
    private (byte[] Archive, int FileCount) BuildChangedArchive(
        string dirPath, List<string> changedFiles,
        Dictionary<string, string> currentHashes, BackupProgress? progress)
    {
        var entries = new List<(string RelPath, byte[] Data)>();
        long processed = 0;

        foreach (var file in changedFiles)
        {
            progress?.ThrowIfCancellationRequested();

            string relPath;
            try
            {
                relPath = Path.GetRelativePath(dirPath, file).Replace('\\', '/');
            }
            catch
            {
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

            entries.Add((relPath, data));
            processed += data.Length;
            progress?.UpdateProgress(entries.Count, processed, file, false, BackupPhase.Backup);
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

        return (ms.ToArray(), entries.Count);
    }

    /// <summary>
    /// 加密归档数据并写入 .lgbackup 备份包。
    /// <para>流程：派生密钥 → 分片 → AES-256-GCM/ChaCha20 加密 → 写入 → 结构性校验。</para>
    /// </summary>
    private BackupManifest WriteEncryptedBackup(byte[] data, BackupType type, string sourcePath, string destDir,
        int fileCount, string password, Dictionary<string, string>? metadata, BackupProgress? progress)
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
        ErrorReporter.Log($"备份包写入完成：[{type}] {sourcePath} -> {outputPath} | 文件 {fileCount} | 分片 {shards.Count} | {data.Length} 字节 | 算法 {manifest.EncryptedAlgorithm}");
        return manifest;
    }

    /// <summary>
    /// 读取并解密备份包，还原归档字节流。
    /// </summary>
    /// <param name="backupPath">.lgbackup 文件路径。</param>
    /// <param name="password">加密口令。</param>
    /// <returns>解密后的归档字节流。</returns>
    private static byte[] DecryptBackupArchive(string backupPath, string password)
    {
        var (manifest, shards) = LgBackupFormat.ReadBackup(backupPath);
        var salt = Convert.FromBase64String(manifest.Salt);
        var crypto = new BackupCryptoEngine(manifest.EncryptedAlgorithm);
        var key = crypto.DeriveKey(password, salt);

        using var ms = new MemoryStream();
        foreach (var shard in shards.OrderBy(s => s.Index))
        {
            var plain = crypto.Decrypt(shard.Cipher, key, shard.Nonce, shard.Tag);
            ms.Write(plain, 0, plain.Length);
        }
        return ms.ToArray();
    }

    /// <summary>
    /// 从文件映射构建归档字节流（用于差异链合并）。
    /// </summary>
    private static byte[] BuildArchiveFromMap(Dictionary<string, byte[]> fileMap)
    {
        using var ms = new MemoryStream();
        using (var bw = new BinaryWriter(ms, Encoding.UTF8, leaveOpen: true))
        {
            bw.Write((long)fileMap.Count);
            foreach (var kv in fileMap)
            {
                var relBytes = Encoding.UTF8.GetBytes(kv.Key);
                bw.Write(relBytes.Length);
                bw.Write(relBytes);
                bw.Write((long)kv.Value.Length);
                bw.Write(kv.Value);
            }
        }
        return ms.ToArray();
    }

    #endregion

    #region USN 日志扫描器

    /// <summary>
    /// NTFS USN（更新序列号）日志扫描器 - 通过读取 USN 日志高效检测卷上文件变更。
    /// <para>使用 P/Invoke 调用 <c>DeviceIoControl</c> 发送 <c>FSCTL_READ_USN_JOURNAL</c> / <c>FSCTL_QUERY_USN_JOURNAL</c> 控制码。</para>
    /// <para>USN 日志不可用（非 NTFS 卷 / 日志未启用 / 权限不足）时抛出异常，由调用方回退到哈希比对。</para>
    /// </summary>
    public static class UsnJournalScanner
    {
        #region Win32 常量

        /// <summary>读取 USN 日志记录的控制码：FSCTL_READ_USN_JOURNAL = 0x000900BB。</summary>
        private const uint FSCTL_READ_USN_JOURNAL = 0x000900BB;

        /// <summary>查询 USN 日志信息的控制码：FSCTL_QUERY_USN_JOURNAL = 0x000900F4。</summary>
        private const uint FSCTL_QUERY_USN_JOURNAL = 0x000900F4;

        // CreateFileW 访问模式与标志
        private const uint GENERIC_READ = 0x80000000;
        private const uint FILE_SHARE_READ = 0x00000001;
        private const uint FILE_SHARE_WRITE = 0x00000002;
        private const uint OPEN_EXISTING = 3;

        // USN 变更原因标志位
        private const uint USN_REASON_DATA_OVERWRITE = 0x00000001;
        private const uint USN_REASON_DATA_EXTEND = 0x00000002;
        private const uint USN_REASON_DATA_TRUNCATION = 0x00000004;
        private const uint USN_REASON_NAMED_DATA_OVERWRITE = 0x00000010;
        private const uint USN_REASON_NAMED_DATA_EXTEND = 0x00000020;
        private const uint USN_REASON_NAMED_DATA_TRUNCATION = 0x00000040;
        private const uint USN_REASON_FILE_CREATE = 0x00000100;
        private const uint USN_REASON_FILE_DELETE = 0x00000200;
        private const uint USN_REASON_EA_CHANGE = 0x00000400;
        private const uint USN_REASON_SECURITY_CHANGE = 0x00000800;
        private const uint USN_REASON_RENAME_OLD_NAME = 0x00001000;
        private const uint USN_REASON_RENAME_NEW_NAME = 0x00002000;
        private const uint USN_REASON_INDEXABLE_CHANGE = 0x00004000;
        private const uint USN_REASON_BASIC_INFO_CHANGE = 0x00008000;
        private const uint USN_REASON_HARD_LINK_CHANGE = 0x00010000;
        private const uint USN_REASON_COMPRESSION_CHANGE = 0x00020000;
        private const uint USN_REASON_ENCRYPTION_CHANGE = 0x00040000;
        private const uint USN_REASON_OBJECT_ID_CHANGE = 0x00080000;
        private const uint USN_REASON_REPARSE_POINT_CHANGE = 0x00100000;
        private const uint USN_REASON_STREAM_CHANGE = 0x00200000;
        private const uint USN_REASON_CLOSE = 0x80000000;

        /// <summary>关注的变更原因掩码（数据变更 + 创建 + 删除 + 重命名 + 属性变更 + 关闭）。</summary>
        private const uint REASON_MASK_OF_INTEREST =
            USN_REASON_DATA_OVERWRITE | USN_REASON_DATA_EXTEND | USN_REASON_DATA_TRUNCATION |
            USN_REASON_NAMED_DATA_OVERWRITE | USN_REASON_NAMED_DATA_EXTEND | USN_REASON_NAMED_DATA_TRUNCATION |
            USN_REASON_FILE_CREATE | USN_REASON_FILE_DELETE |
            USN_REASON_RENAME_OLD_NAME | USN_REASON_RENAME_NEW_NAME |
            USN_REASON_BASIC_INFO_CHANGE | USN_REASON_SECURITY_CHANGE |
            USN_REASON_CLOSE;

        /// <summary>USN 日志读取缓冲区大小（64KB）。</summary>
        private const int READ_BUFFER_SIZE = 64 * 1024;

        #endregion

        #region Win32 结构体

        /// <summary>FSCTL_QUERY_USN_JOURNAL 的输出结构体，描述 USN 日志当前状态。</summary>
        [StructLayout(LayoutKind.Sequential)]
        private struct USN_JOURNAL_DATA
        {
            /// <summary>USN 日志唯一标识符。</summary>
            public long UsnJournalID;

            /// <summary>日志中第一条记录的 USN。</summary>
            public long FirstUsn;

            /// <summary>下一条将被写入的 USN（即当前最大 USN）。</summary>
            public long NextUsn;

            /// <summary>日志最大容量（字节）。</summary>
            public long MaximumSize;

            /// <summary>日志分配增量（字节）。</summary>
            public long AllocationDelta;

            /// <summary>支持的最小主版本号。</summary>
            public long MinSupportedMajorVersion;

            /// <summary>支持的最大主版本号。</summary>
            public long MaxSupportedMajorVersion;
        }

        /// <summary>FSCTL_READ_USN_JOURNAL 的输入结构体，指定读取范围与过滤条件。</summary>
        [StructLayout(LayoutKind.Sequential)]
        private struct READ_USN_JOURNAL_DATA
        {
            /// <summary>起始读取的 USN（从该 USN 之后开始读取）。</summary>
            public long StartUsn;

            /// <summary>变更原因过滤掩码。</summary>
            public uint ReasonMask;

            /// <summary>是否仅在文件关闭时返回（0 = 实时返回）。</summary>
            public uint ReturnOnlyOnClose;

            /// <summary>超时时间（100 纳秒单位，0 = 不等待）。</summary>
            public long Timeout;

            /// <summary>等待的字节数（0 = 立即返回已有记录）。</summary>
            public long BytesToWaitFor;

            /// <summary>目标 USN 日志 ID（必须与当前卷日志 ID 匹配）。</summary>
            public long UsnJournalID;

            /// <summary>请求的最小记录主版本号。</summary>
            public ushort MinMajorVersion;

            /// <summary>请求的最大记录主版本号。</summary>
            public ushort MaxMajorVersion;
        }

        #endregion

        #region P/Invoke 声明

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern SafeFileHandle CreateFileW(
            string lpFileName,
            uint dwDesiredAccess,
            uint dwShareMode,
            IntPtr lpSecurityAttributes,
            uint dwCreationDisposition,
            uint dwFlagsAndAttributes,
            IntPtr hTemplateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool DeviceIoControl(
            SafeFileHandle hDevice,
            uint dwIoControlCode,
            IntPtr lpInBuffer,
            uint nInBufferSize,
            IntPtr lpOutBuffer,
            uint nOutBufferSize,
            out uint lpBytesReturned,
            IntPtr lpOverlapped);

        #endregion

        #region 公开方法

        /// <summary>
        /// 获取指定卷的 USN 日志 ID。
        /// </summary>
        /// <param name="driveLetter">盘符（如 "C"）。</param>
        /// <returns>USN 日志 ID；日志不存在或不可用抛出异常。</returns>
        /// <exception cref="IOException">USN 日志不可用（非 NTFS / 未启用 / 权限不足）。</exception>
        public static long GetJournalId(string driveLetter)
        {
            var letter = NormalizeDriveLetter(driveLetter);
            using var handle = OpenVolumeHandle(letter);
            var journal = QueryJournal(handle);
            return journal.UsnJournalID;
        }

        /// <summary>
        /// 获取指定卷的当前最大 USN（NextUsn）。
        /// </summary>
        /// <param name="driveLetter">盘符（如 "C"）。</param>
        /// <returns>当前最大 USN。</returns>
        /// <exception cref="IOException">USN 日志不可用。</exception>
        public static long GetNextUsn(string driveLetter)
        {
            var letter = NormalizeDriveLetter(driveLetter);
            using var handle = OpenVolumeHandle(letter);
            var journal = QueryJournal(handle);
            return journal.NextUsn;
        }

        /// <summary>
        /// 扫描 USN 日志，获取自 <paramref name="lastUsn"/> 以来的所有文件变更记录。
        /// <para>循环读取日志缓冲区直到无更多记录，解析每条 USN_RECORD V2 结构。</para>
        /// </summary>
        /// <param name="driveLetter">盘符（如 "C"）。</param>
        /// <param name="lastUsn">上次记录的最大 USN（从该 USN 之后开始扫描）。</param>
        /// <returns>USN 变更记录列表。</returns>
        /// <exception cref="IOException">USN 日志不可用（非 NTFS / 未启用 / 权限不足）。</exception>
        public static List<UsnChangeRecord> ScanChanges(string driveLetter, long lastUsn)
        {
            var letter = NormalizeDriveLetter(driveLetter);
            var results = new List<UsnChangeRecord>();

            using var handle = OpenVolumeHandle(letter);
            var journal = QueryJournal(handle);

            ErrorReporter.Log($"USN 日志信息：ID={journal.UsnJournalID} | FirstUsn={journal.FirstUsn} | NextUsn={journal.NextUsn} | 版本 {journal.MinSupportedMajorVersion}-{journal.MaxSupportedMajorVersion}");

            var readData = new READ_USN_JOURNAL_DATA
            {
                StartUsn = lastUsn,
                ReasonMask = REASON_MASK_OF_INTEREST,
                ReturnOnlyOnClose = 0,
                Timeout = 0,
                BytesToWaitFor = 0,
                UsnJournalID = journal.UsnJournalID,
                MinMajorVersion = 2,
                MaxMajorVersion = 2
            };

            int inputSize = Marshal.SizeOf<READ_USN_JOURNAL_DATA>();
            IntPtr inBuf = Marshal.AllocHGlobal(inputSize);
            var outBuf = new byte[READ_BUFFER_SIZE];
            var outPin = GCHandle.Alloc(outBuf, GCHandleType.Pinned);

            try
            {
                Marshal.StructureToPtr(readData, inBuf, false);
                long currentUsn = lastUsn;
                bool hasMore = true;

                while (hasMore)
                {
                    // 更新起始 USN
                    readData.StartUsn = currentUsn;
                    Marshal.StructureToPtr(readData, inBuf, false);

                    bool ok = DeviceIoControl(
                        handle,
                        FSCTL_READ_USN_JOURNAL,
                        inBuf, (uint)inputSize,
                        outPin.AddrOfPinnedObject(), (uint)outBuf.Length,
                        out uint bytesReturned, IntPtr.Zero);

                    if (!ok || bytesReturned < 8)
                        break;

                    // 输出缓冲区前 8 字节为下一次读取的起始 USN
                    long nextUsn = BitConverter.ToInt64(outBuf, 0);
                    if (nextUsn <= currentUsn)
                    {
                        // 没有更多新记录
                        hasMore = false;
                        break;
                    }

                    // 解析 USN_RECORD 记录（从偏移 8 开始）
                    int offset = 8;
                    int dataLen = (int)bytesReturned;
                    while (offset + 4 <= dataLen)
                    {
                        int recordLen = BitConverter.ToInt32(outBuf, offset);
                        if (recordLen <= 0 || offset + recordLen > dataLen)
                            break;

                        var record = ParseUsnRecord(outBuf, offset, recordLen, letter);
                        if (record != null)
                            results.Add(record);

                        offset += recordLen;
                    }

                    currentUsn = nextUsn;

                    // 若本次返回数据不足一个完整记录，视为读取完毕
                    if (bytesReturned <= 8)
                        hasMore = false;
                }
            }
            finally
            {
                outPin.Free();
                Marshal.FreeHGlobal(inBuf);
            }

            return results;
        }

        /// <summary>
        /// 检查指定卷的 USN 日志是否可用。
        /// </summary>
        /// <param name="driveLetter">盘符（如 "C"）。</param>
        /// <returns>USN 日志可用返回 true。</returns>
        public static bool IsJournalAvailable(string driveLetter)
        {
            try
            {
                var letter = NormalizeDriveLetter(driveLetter);
                using var handle = OpenVolumeHandle(letter);
                QueryJournal(handle);
                return true;
            }
            catch
            {
                return false;
            }
        }

        #endregion

        #region 私有方法

        /// <summary>
        /// 打开卷设备句柄（需管理员权限）。
        /// </summary>
        private static SafeFileHandle OpenVolumeHandle(string driveLetter)
        {
            var devicePath = $@"\\.\{driveLetter}:";
            var handle = CreateFileW(
                devicePath,
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                IntPtr.Zero,
                OPEN_EXISTING,
                0,
                IntPtr.Zero);

            if (handle.IsInvalid)
            {
                var err = Marshal.GetLastWin32Error();
                throw new IOException(
                    $"无法打开卷设备句柄 {devicePath}（Win32 错误 {err}）。请确认以管理员权限运行且盘符有效。",
                    new System.ComponentModel.Win32Exception(err));
            }

            return handle;
        }

        /// <summary>
        /// 查询 USN 日志信息（FSCTL_QUERY_USN_JOURNAL）。
        /// </summary>
        private static USN_JOURNAL_DATA QueryJournal(SafeFileHandle handle)
        {
            int outSize = Marshal.SizeOf<USN_JOURNAL_DATA>();
            IntPtr outBuf = Marshal.AllocHGlobal(outSize);
            try
            {
                bool ok = DeviceIoControl(
                    handle,
                    FSCTL_QUERY_USN_JOURNAL,
                    IntPtr.Zero, 0,
                    outBuf, (uint)outSize,
                    out uint bytesReturned, IntPtr.Zero);

                if (!ok || bytesReturned < outSize)
                {
                    var err = Marshal.GetLastWin32Error();
                    throw new IOException(
                        $"查询 USN 日志失败（Win32 错误 {err}）。可能该卷非 NTFS 或 USN 日志未启用。",
                        new System.ComponentModel.Win32Exception(err));
                }

                return Marshal.PtrToStructure<USN_JOURNAL_DATA>(outBuf);
            }
            finally
            {
                Marshal.FreeHGlobal(outBuf);
            }
        }

        /// <summary>
        /// 解析单条 USN_RECORD V2 结构。
        /// <para>V2 结构布局：</para>
        /// <para>[0] DWORD RecordLength | [4] WORD MajorVersion | [6] WORD MinorVersion</para>
        /// <para>[8] DWORDLONG FileReferenceNumber | [16] DWORDLONG ParentFileReferenceNumber</para>
        /// <para>[24] USN Usn | [32] LARGE_INTEGER TimeStamp | [40] DWORD Reason</para>
        /// <para>[44] DWORD SourceInfo | [48] DWORD SecurityId | [52] DWORD FileAttributes</para>
        /// <para>[56] WORD FileNameLength | [58] WORD FileNameOffset | [60] WCHAR FileName[]</para>
        /// </summary>
        private static UsnChangeRecord? ParseUsnRecord(byte[] buf, int offset, int recordLen, string driveLetter)
        {
            try
            {
                // 至少需要 60 字节的头部
                if (offset + 60 > buf.Length)
                    return null;

                int majorVersion = BitConverter.ToUInt16(buf, offset + 4);
                long fileRefNum = BitConverter.ToInt64(buf, offset + 8);
                long parentRefNum = BitConverter.ToInt64(buf, offset + 16);
                long usn = BitConverter.ToInt64(buf, offset + 24);
                long timeStamp = BitConverter.ToInt64(buf, offset + 32);
                uint reason = BitConverter.ToUInt32(buf, offset + 40);
                ushort fileNameLength = BitConverter.ToUInt16(buf, offset + 56);
                ushort fileNameOffset = BitConverter.ToUInt16(buf, offset + 58);

                // 提取文件名（Unicode）
                string fileName;
                int nameStart = offset + fileNameOffset;
                if (fileNameLength > 0 && nameStart + fileNameLength <= buf.Length && nameStart + fileNameLength <= offset + recordLen)
                {
                    fileName = Encoding.Unicode.GetString(buf, nameStart, fileNameLength);
                }
                else
                {
                    fileName = string.Empty;
                }

                var record = new UsnChangeRecord
                {
                    FileName = fileName,
                    FullPath = fileName, // 暂存文件名，由调用方解析完整路径
                    Usn = usn,
                    Reason = reason,
                    Time = DateTime.FromFileTimeUtc(timeStamp),
                    IsDelete = (reason & USN_REASON_FILE_DELETE) != 0,
                    FileReferenceNumber = fileRefNum,
                    ParentFileReferenceNumber = parentRefNum
                };

                // 记录主版本号非 2 时记录警告（仍尝试解析）
                if (majorVersion != 2)
                {
                    ErrorReporter.Log($"USN 记录主版本号为 {majorVersion}（预期 2），尝试兼容解析。", "WARN");
                }

                return record;
            }
            catch (Exception ex)
            {
                ErrorReporter.Log($"解析 USN 记录失败：{ex.Message}", "WARN");
                return null;
            }
        }

        #endregion
    }

    #endregion

    #region 辅助方法

    /// <summary>
    /// 全量枚举目录下所有文件（USN 不可用时的回退方案）。
    /// </summary>
    private static List<string> FallbackEnumerateAllFiles(string basePath)
    {
        try
        {
            return Directory.EnumerateFiles(basePath, "*", SearchOption.AllDirectories).ToList();
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, $"回退全量枚举失败：{basePath}");
            return new List<string>();
        }
    }

    /// <summary>
    /// 加载目标目录中所有 .lgbackup 备份的清单信息（按时间倒序）。
    /// </summary>
    private static List<(string Path, BackupManifest Manifest)> LoadBackupHistory(string destDir)
    {
        var list = new List<(string Path, BackupManifest Manifest)>();
        if (string.IsNullOrEmpty(destDir) || !Directory.Exists(destDir))
            return list;

        foreach (var file in Directory.EnumerateFiles(destDir, "*" + LgBackupFormat.Extension))
        {
            try
            {
                var (manifest, _, _) = LgBackupFormat.ReadManifestOnly(file);
                list.Add((file, manifest));
            }
            catch (Exception ex)
            {
                ErrorReporter.Log($"读取备份清单失败，跳过 {file}：{ex.Message}");
            }
        }

        return list.OrderByDescending(x => x.Manifest.BackupTime).ToList();
    }

    /// <summary>
    /// 判断清单是否为全量备份策略。
    /// </summary>
    private static bool IsFullStrategy(BackupManifest manifest)
    {
        var strategy = GetStrategy(manifest);
        return string.IsNullOrEmpty(strategy)
               || string.Equals(strategy, "Full", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// 获取清单的备份策略标记。
    /// </summary>
    private static string GetStrategy(BackupManifest manifest)
        => manifest.Metadata.TryGetValue("Strategy", out var s) ? s : string.Empty;

    /// <summary>
    /// 尝试从清单元数据解析基准备份 ID。
    /// </summary>
    private static bool TryGetBaseBackupId(BackupManifest manifest, out Guid baseId)
    {
        baseId = Guid.Empty;
        return manifest.Metadata.TryGetValue("BaseBackupId", out var idStr)
               && Guid.TryParse(idStr, out baseId);
    }

    /// <summary>
    /// 判断 fullPath 是否包含在 basePath 目录下（不区分大小写）。
    /// </summary>
    private static bool FullPathContains(string basePath, string fullPath)
    {
        try
        {
            var baseFull = Path.GetFullPath(basePath).TrimEnd('\\', '/') + "\\";
            var full = Path.GetFullPath(fullPath);
            return full.StartsWith(baseFull, StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// 序列化文件哈希映射为 JSON 字符串。
    /// </summary>
    private static string SerializeHashMap(Dictionary<string, string> hashes)
        => JsonSerializer.Serialize(hashes);

    /// <summary>
    /// 从清单元数据解析文件哈希映射。
    /// </summary>
    private static Dictionary<string, string> ParseHashMap(Dictionary<string, string>? metadata)
    {
        if (metadata == null)
            return new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

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

    /// <summary>
    /// 生成 .lgbackup 输出路径。
    /// </summary>
    private static string GenerateOutputPath(string destDir, BackupType type, Guid id)
        => Path.Combine(destDir, $"{type}_{DateTime.Now:yyyyMMdd_HHmmss}_{id.ToString("N")[..8]}{LgBackupFormat.Extension}");

    /// <summary>
    /// 规范化盘符为大写单字符（如 "c:\" → "C"）。
    /// </summary>
    private static string NormalizeDriveLetter(string driveLetter)
    {
        if (string.IsNullOrWhiteSpace(driveLetter))
            throw new ArgumentException("盘符不能为空。", nameof(driveLetter));
        var c = char.ToUpperInvariant(driveLetter.Trim()[0]);
        if (c < 'A' || c > 'Z')
            throw new ArgumentException("无效盘符：" + driveLetter, nameof(driveLetter));
        return c.ToString();
    }

    /// <summary>
    /// 从路径解析盘符（如 "C:\Users\..." → "C"）。
    /// </summary>
    private static string ExtractDriveLetter(string path)
    {
        var root = Path.GetPathRoot(path);
        if (string.IsNullOrEmpty(root) || root.Length < 2 || root[1] != ':')
            throw new ArgumentException($"无法从路径解析盘符：{path}", nameof(path));
        return char.ToUpperInvariant(root[0]).ToString();
    }

    #endregion
}
