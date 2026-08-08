// © 2026 落尘（Luochen） 原创开发 - 保留所有权利

using System.Security.Cryptography;
using System.Text.Json;
using LightGuard.Core;

namespace LightGuard.Backup;

/// <summary>
/// 增量链条目（一个增量包 = 一个版本点）。
/// </summary>
public sealed class IncrementalChainEntry
{
    /// <summary>增量包路径。</summary>
    public string Path { get; init; } = "";

    /// <summary>备份时间（头部 Metadata BackupTime；缺失回退文件修改时间）。</summary>
    public DateTime BackupTime { get; init; }

    /// <summary>USN 游标（头部 Metadata UsnEnd；无则 -1）。</summary>
    public long UsnEnd { get; init; } = -1;

    /// <summary>版本序号（1 起；链上第 N 个版本点）。</summary>
    public int VersionIndex { get; init; }
}

/// <summary>
/// 增量链合并结果。
/// </summary>
public sealed class ChainMergeResult
{
    /// <summary>合并后的新全量包路径。</summary>
    public string MergedPath { get; set; } = "";

    /// <summary>合并文件数。</summary>
    public int FileCount { get; set; }

    /// <summary>合并数据总字节。</summary>
    public long TotalBytes { get; set; }

    /// <summary>合并时间。</summary>
    public DateTime MergedTime { get; set; }

    /// <summary>合并后的 USN 游标（取链尾增量包）。</summary>
    public long UsnEnd { get; set; } = -1;

    /// <summary>合并的增量包数。</summary>
    public int MergedDeltaCount { get; set; }
}

/// <summary>
/// 版本点恢复结果。
/// </summary>
public sealed class ChainRestoreResult
{
    /// <summary>恢复文件数。</summary>
    public int RestoredFiles { get; set; }

    /// <summary>恢复数据总字节。</summary>
    public long RestoredBytes { get; set; }

    /// <summary>恢复到的版本序号（0 = 仅基础包；N = 应用前 N 个增量后的状态）。</summary>
    public int VersionIndex { get; set; }

    /// <summary>恢复到的版本时间点。</summary>
    public DateTime RestorePoint { get; set; }
}

/// <summary>
/// 增量链管理服务：多级增量链的合基（基础包 + 增量包链 → 新全量包）与链上任意版本点恢复。
/// <para>链模型：基础包（全量，Chunked）为版本 0，其后每个增量包为一个版本点（版本 1..N）。
/// 版本点恢复 = 应用基础包 + 链上前 k 个增量包的块级重建，恢复到第 k 个版本时刻的文件内容。</para>
/// <para>合并 = 恢复链尾版本并写为新全量包（Chunked），新包可继续作为下一轮增量链的基础。</para>
/// </summary>
public static class IncrementalChainService
{
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = false };

    /// <summary>合并后全量包的策略标记。</summary>
    public const string FullStrategy = "Full";

    /// <summary>增量包策略标记。</summary>
    public const string IncrementalStrategy = "BlockIncremental";

    // ==================== 链加载 ====================

    /// <summary>
    /// 加载增量链：读取每个增量包头元数据（备份时间 / USN 游标），按备份时间升序排列并编号。
    /// </summary>
    /// <param name="password">备份口令。</param>
    /// <param name="deltaPaths">增量包路径列表（乱序也可，按时间排序）。</param>
    /// <param name="ct">取消令牌。</param>
    /// <returns>排序后的链条目（VersionIndex = 1..N）。</returns>
    public static async Task<List<IncrementalChainEntry>> LoadChainAsync(
        string password, IEnumerable<string> deltaPaths, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(deltaPaths);
        if (string.IsNullOrWhiteSpace(password))
            throw new ArgumentException("备份口令不能为空。", nameof(password));

        var entries = new List<IncrementalChainEntry>();
        foreach (var path in deltaPaths.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            ct.ThrowIfCancellationRequested();
            if (string.IsNullOrEmpty(path) || !File.Exists(path))
                continue;

            long usnEnd = -1;
            DateTime? backupTime = null;
            try
            {
                using var archive = (V3PrivateContainerArchive)BackupArchiveFactory.Open(path, password);
                if (archive.Metadata != null)
                {
                    if (archive.Metadata.TryGetValue("BackupTime", out var t) && DateTime.TryParse(t, out var dt))
                        backupTime = dt;
                    if (archive.Metadata.TryGetValue("UsnEnd", out var u) && long.TryParse(u, out var val))
                        usnEnd = val;
                }
            }
            catch (AuthenticationTagMismatchException)
            {
                throw new InvalidDataException($"增量包口令错误：{path}");
            }

            entries.Add(new IncrementalChainEntry
            {
                Path = path,
                BackupTime = backupTime ?? File.GetLastWriteTime(path),
                UsnEnd = usnEnd,
                VersionIndex = 0 // 排序后统一编号
            });
        }

        var ordered = entries
            .OrderBy(e => e.BackupTime)
            .Select((e, i) => new IncrementalChainEntry
            {
                Path = e.Path,
                BackupTime = e.BackupTime,
                UsnEnd = e.UsnEnd,
                VersionIndex = i + 1
            })
            .ToList();

        ErrorReporter.Log($"增量链加载完成：{ordered.Count} 个版本点。");
        return ordered;
    }

    // ==================== 链合并 ====================

    /// <summary>
    /// 合并增量链为新全量包：恢复链尾最新版本 → 写 Chunked 全量包（可继续作为下一轮增量基准）。
    /// </summary>
    /// <param name="basePath">基础包路径。</param>
    /// <param name="password">备份口令。</param>
    /// <param name="mergedPath">合并后新全量包输出路径。</param>
    /// <param name="deltaPaths">增量包路径列表。</param>
    /// <param name="options">写入参数（合并包按 Chunked 模式，块大小沿用 options.ChunkSize）。</param>
    /// <param name="progress">进度跟踪（可选）。</param>
    /// <param name="ct">取消令牌。</param>
    public static async Task<ChainMergeResult> MergeToFullAsync(
        string basePath, string password, string mergedPath,
        IEnumerable<string> deltaPaths, BackupArchiveOptions options,
        IProgress<BackupProgressInfo>? progress = null, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(basePath) || !File.Exists(basePath))
            throw new FileNotFoundException("基础包不存在。", basePath);
        if (string.IsNullOrWhiteSpace(mergedPath))
            throw new ArgumentException("合并包路径不能为空。", nameof(mergedPath));
        ArgumentNullException.ThrowIfNull(options);

        var chain = await LoadChainAsync(password, deltaPaths, ct).ConfigureAwait(false);

        // 1. 恢复链尾最新版本到内存映射
        var fileMap = await BuildMapUpToVersionAsync(basePath, password, chain, chain.Count, ct).ConfigureAwait(false);

        // 2. 写新全量包（Chunked：供下一轮增量复用块元数据）
        var mergedOptions = new BackupArchiveOptions
        {
            SourcePath = options.SourcePath,
            CompressionLevel = options.CompressionLevel,
            DictionarySizeMb = options.DictionarySizeMb,
            CompressionMode = BackupArchiveCompressionMode.Chunked,
            ChunkSize = options.ChunkSize,
            EncryptFileNames = options.EncryptFileNames
        };
        var metadata = new Dictionary<string, string>
        {
            ["Strategy"] = FullStrategy,
            ["MergedFrom"] = Path.GetFileName(basePath),
            ["MergedDeltaCount"] = chain.Count.ToString(),
            ["MergedTime"] = DateTime.Now.ToString("O"),
            ["UsnEnd"] = Math.Max(0, chain.LastOrDefault()?.UsnEnd ?? -1).ToString()
        };

        var dir = Path.GetDirectoryName(mergedPath);
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);

        using var outArchive = BackupArchiveFactory.Create(mergedPath, password, mergedOptions, metadata);
        var now = DateTime.Now;
        await outArchive.WriteAsync(
            fileMap.Select(kv => (kv.Key, (Stream)new MemoryStream(kv.Value), now)),
            mergedOptions, progress, ct).ConfigureAwait(false);

        var total = fileMap.Values.Sum(v => (long)v.Length);
        ErrorReporter.Log($"增量链合并完成：{basePath} + {chain.Count} 增量 → {mergedPath} | 文件 {fileMap.Count} | {total} 字节");

        // WORM：合并包写入完成后自动施加三层防删除锁（抗勒索只读隔离）
        WormManager.AutoLock(mergedPath);

        return new ChainMergeResult
        {
            MergedPath = mergedPath,
            FileCount = fileMap.Count,
            TotalBytes = total,
            MergedTime = DateTime.Now,
            UsnEnd = chain.LastOrDefault()?.UsnEnd ?? -1,
            MergedDeltaCount = chain.Count
        };
    }

    // ==================== 版本点恢复 ====================

    /// <summary>
    /// 恢复到指定版本点（0 = 仅基础包；N = 链上第 N 个增量后的状态，即版本 N）。
    /// </summary>
    /// <param name="basePath">基础包路径。</param>
    /// <param name="password">备份口令。</param>
    /// <param name="deltaPaths">增量包路径列表（乱序也可，内部按时间排序）。</param>
    /// <param name="restoreDir">恢复输出目录（按相对路径重建结构，同名覆盖）。</param>
    /// <param name="versionIndex">目标版本序号：0 起（0=基础包, 1..chain.Count=对应增量后状态）。</param>
    /// <param name="progress">进度跟踪（可选）。</param>
    /// <param name="ct">取消令牌。</param>
    public static async Task<ChainRestoreResult> RestoreToVersionAsync(
        string basePath, string password, IEnumerable<string> deltaPaths,
        string restoreDir, int versionIndex,
        IProgress<BackupProgressInfo>? progress = null, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(basePath) || !File.Exists(basePath))
            throw new FileNotFoundException("基础包不存在。", basePath);
        if (string.IsNullOrWhiteSpace(restoreDir))
            throw new ArgumentException("恢复目录不能为空。", nameof(restoreDir));
        if (versionIndex < 0)
            throw new ArgumentOutOfRangeException(nameof(versionIndex), "版本序号不能为负。");

        var chain = await LoadChainAsync(password, deltaPaths, ct).ConfigureAwait(false);
        if (versionIndex > chain.Count)
            throw new ArgumentOutOfRangeException(nameof(versionIndex),
                $"链上仅 {chain.Count} 个增量版本点，无法恢复到版本 {versionIndex}。");

        var fileMap = await BuildMapUpToVersionAsync(basePath, password, chain, versionIndex, ct).ConfigureAwait(false);

        // 写目录（按相对路径重建结构）
        Directory.CreateDirectory(restoreDir);
        long total = 0;
        foreach (var (rel, data) in fileMap)
        {
            ct.ThrowIfCancellationRequested();
            var target = Path.Combine(restoreDir, rel.Replace('/', Path.DirectorySeparatorChar));
            Directory.CreateDirectory(Path.GetDirectoryName(target) ?? restoreDir);
            await File.WriteAllBytesAsync(target, data, ct).ConfigureAwait(false);
            total += data.Length;
        }

        DateTime restorePoint = chain.Count > 0
            ? (versionIndex > 0 ? chain[versionIndex - 1].BackupTime : DateTime.MinValue)
            : DateTime.MinValue;
        ErrorReporter.Log($"版本点恢复完成：版本 {versionIndex} | 文件 {fileMap.Count} | {total} 字节 → {restoreDir}");
        return new ChainRestoreResult
        {
            RestoredFiles = fileMap.Count,
            RestoredBytes = total,
            VersionIndex = versionIndex,
            RestorePoint = restorePoint
        };
    }

    /// <summary>
    /// 恢复到指定时间点的最新版本（最后一个 备份时间 ≤ targetTime 的增量包后的状态；无匹配则恢复基础包）。
    /// </summary>
    public static async Task<ChainRestoreResult> RestoreToTimeAsync(
        string basePath, string password, IEnumerable<string> deltaPaths,
        string restoreDir, DateTime targetTime,
        IProgress<BackupProgressInfo>? progress = null, CancellationToken ct = default)
    {
        // 加载链 → 计算命中版本 → 复用版本点恢复
        var chain = await LoadChainAsync(password, deltaPaths, ct).ConfigureAwait(false);
        int versionIndex = 0;
        for (int i = 0; i < chain.Count; i++)
        {
            if (chain[i].BackupTime <= targetTime)
                versionIndex = i + 1;
            else
                break;
        }
        return await RestoreToVersionAsync(basePath, password, chain.Select(c => c.Path),
            restoreDir, versionIndex, progress, ct).ConfigureAwait(false);
    }

    // ==================== 内部实现 ====================

    /// <summary>
    /// 构建「恢复到版本 versionIndex」的文件内容映射：
    /// 基础包全量 + 顺序应用链上前 versionIndex 个增量包的块级重建（后包覆盖同名文件）。
    /// </summary>
    private static async Task<Dictionary<string, byte[]>> BuildMapUpToVersionAsync(
        string basePath, string password, List<IncrementalChainEntry> chain,
        int versionIndex, CancellationToken ct)
    {
        var fileMap = new Dictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase);

        using var baseArchive = BackupArchiveFactory.Open(basePath, password);

        // 1. 加载基础包全部条目
        var baseEntries = await baseArchive.ListEntriesAsync(ct).ConfigureAwait(false);
        foreach (var entry in baseEntries)
        {
            ct.ThrowIfCancellationRequested();
            using var s = await baseArchive.OpenEntryAsync(entry.RelPath, ct).ConfigureAwait(false);
            using var ms = new MemoryStream();
            await s.CopyToAsync(ms, ct).ConfigureAwait(false);
            fileMap[entry.RelPath] = ms.ToArray();
        }

        // 2. 顺序应用增量（0..versionIndex）
        int applied = 0;
        foreach (var entry in chain.Take(versionIndex))
        {
            ct.ThrowIfCancellationRequested();
            using var deltaArchive = BackupArchiveFactory.Open(entry.Path, password);
            var map = await BlockIncrementalService.ReadBlockMapAsync(deltaArchive, ct).ConfigureAwait(false);
            if (map.Files == null) continue;

            foreach (var rel in map.Files.Keys)
            {
                ct.ThrowIfCancellationRequested();
                fileMap[rel] = await BlockIncrementalService.RebuildFileCore(baseArchive, deltaArchive, map, rel, ct)
                    .ConfigureAwait(false);
            }
            applied++;
        }

        ErrorReporter.Log($"版本映射构建完成：版本 {versionIndex}（应用 {applied} 个增量）| 文件 {fileMap.Count}");
        return fileMap;
    }
}
