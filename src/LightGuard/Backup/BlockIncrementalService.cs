// © 2026 落尘（Luochen） 原创开发 - 保留所有权利

using System.Text.Json;
using LightGuard.Core;

namespace LightGuard.Backup;

/// <summary>
/// 块级增量备份结果指标。
/// </summary>
public sealed class BlockIncrementalResult
{
    /// <summary>变更文件数。</summary>
    public int ChangedFiles { get; set; }

    /// <summary>新增块数 / 字节（写入增量包）。</summary>
    public int NewBlocks { get; set; }

    /// <summary>复用块数 / 字节（引用基础包，未重复存储）。</summary>
    public long NewBytes { get; set; }

    /// <summary>复用块数。</summary>
    public int ReusedBlocks { get; set; }

    /// <summary>复用字节（= 节省的存储）。</summary>
    public long ReusedBytes { get; set; }

    /// <summary>省空间字节数（= 复用字节）。</summary>
    public long SavedBytes => ReusedBytes;

    /// <summary>块复用率（0-1）。</summary>
    public double SavingsRatio => (NewBytes + ReusedBytes) > 0 ? ReusedBytes / (double)(NewBytes + ReusedBytes) : 0;

    /// <summary>增量备份包路径。</summary>
    public string DeltaPath { get; set; } = "";

    /// <summary>本次增量结束后的 USN 游标（供下次增量作为起始 USN；USN 不可用为 -1）。</summary>
    public long NextUsn { get; set; } = -1;

    /// <summary>块映射条目在增量包中的相对路径。</summary>
    public const string BlockMapEntry = ".lgblockmap";
}

/// <summary>
/// 块级增量备份服务：基础包（全量，Chunked）+ 增量包（仅存新块 + 块映射）。
/// <para>恢复时用 基础数据 + 增量新块 重建最新版本；未变更文件直接来自基础包。</para>
/// <para>变更检测：<see cref="UsnChangeDetector"/>（NTFS USN）或调用方直接提供变更清单。</para>
/// </summary>
public static class BlockIncrementalService
{
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = false };

    // ==================== 增量备份 ====================

    /// <summary>
    /// 创建块级增量备份包。
    /// </summary>
    /// <param name="basePath">基础包路径（上次全量；null 表示无基准，全部块新增）。</param>
    /// <param name="basePassword">基础包口令。</param>
    /// <param name="deltaPath">增量包输出路径。</param>
    /// <param name="deltaPassword">增量包口令。</param>
    /// <param name="changedFiles">变更文件：(相对路径 → 当前内容)。未在此列表中的文件视为未变更（来自基础包）。</param>
    /// <param name="options">写入参数（ChunkSize 决定块大小；增量包条目按 PerFile 存储）。</param>
    public static async Task<BlockIncrementalResult> CreateIncrementalAsync(
        string? basePath, string basePassword,
        string deltaPath, string deltaPassword,
        IReadOnlyDictionary<string, byte[]> changedFiles,
        BackupArchiveOptions options, CancellationToken ct = default,
        Dictionary<string, string>? metadata = null)
    {
        ArgumentNullException.ThrowIfNull(changedFiles);
        ArgumentNullException.ThrowIfNull(options);
        if (string.IsNullOrWhiteSpace(deltaPassword))
            throw new ArgumentException("增量包口令不能为空。", nameof(deltaPassword));

        var chunkSize = (int)Math.Max(1, options.ChunkSize);

        // 1. 打开基础包：构建块索引（Chunked 元数据加速）+ 按文件读取基准数据（同偏移差分）
        IBackupArchive? baseArchive = null;
        BlockChunkIndex? baseIndex = null;
        var result = new BlockIncrementalResult { DeltaPath = deltaPath, ChangedFiles = changedFiles.Count };
        try
        {
            if (!string.IsNullOrEmpty(basePath) && File.Exists(basePath))
            {
                baseArchive = BackupArchiveFactory.Open(basePath, basePassword);
                var baseEntries = await baseArchive.ListEntriesAsync(ct).ConfigureAwait(false);
                baseIndex = BuildBaseIndex(baseArchive, baseEntries, chunkSize, ct);
            }

            // 2. 逐文件块级差分 → 新块拼接数据 + 块映射
            var entries = new List<(string RelPath, Stream Data, DateTime ModifiedTime)>();
            var map = new BlockMapRoot { ChunkSize = chunkSize, Files = new Dictionary<string, BlockMapFile>(StringComparer.OrdinalIgnoreCase) };

            foreach (var (rel, data) in changedFiles)
            {
                ct.ThrowIfCancellationRequested();

                // 基准数据（同文件旧版本；新文件无基准 → null，全部块新增）
                byte[]? baseData = null;
                if (baseArchive != null)
                {
                    try
                    {
                        using var bs = await baseArchive.OpenEntryAsync(rel, ct).ConfigureAwait(false);
                        using var bms = new MemoryStream();
                        await bs.CopyToAsync(bms, ct).ConfigureAwait(false);
                        baseData = bms.ToArray();
                    }
                    catch (FileNotFoundException) { /* 新文件无基准 */ }
                }

                var delta = BlockIncrementalEngine.ComputeDelta(data, baseData, baseIndex, chunkSize);

                // 新块拼接（复用块不落盘）
                using var newMs = new MemoryStream();
                var mapFile = new BlockMapFile { TotalLen = data.Length, Blocks = new List<BlockMapBlock>() };
                long dpos = 0;
                foreach (var block in delta.Blocks)
                {
                    if (block.Reused)
                    {
                        mapFile.Blocks.Add(new BlockMapBlock { Off = block.Offset, Len = block.Length, Hash = block.Hash, Reused = true });
                    }
                    else
                    {
                        newMs.Write(block.Data!, 0, block.Data!.Length);
                        mapFile.Blocks.Add(new BlockMapBlock { Off = block.Offset, Len = block.Length, Hash = block.Hash, Reused = false, Dpos = dpos });
                        dpos += block.Length;
                    }
                }
                map.Files[rel] = mapFile;
                entries.Add((rel, new MemoryStream(newMs.ToArray()), DateTime.Now));

                result.NewBlocks += delta.NewCount;
                result.NewBytes += delta.NewBytes;
                result.ReusedBlocks += delta.ReusedCount;
                result.ReusedBytes += delta.ReusedBytes;
            }

            // 3. 块映射条目（恢复时定位复用/新块）
            entries.Add((BlockIncrementalResult.BlockMapEntry,
                new MemoryStream(JsonSerializer.SerializeToUtf8Bytes(map, JsonOptions)), DateTime.Now));

            // 4. 写增量包（条目按 PerFile 单记录存储）
            var deltaOptions = new BackupArchiveOptions
            {
                SourcePath = options.SourcePath,
                CompressionLevel = options.CompressionLevel,
                DictionarySizeMb = options.DictionarySizeMb,
                CompressionMode = BackupArchiveCompressionMode.PerFile,
                EncryptFileNames = options.EncryptFileNames
            };
            using var deltaArchive = BackupArchiveFactory.Create(deltaPath, deltaPassword, deltaOptions, metadata);
            await deltaArchive.WriteAsync(entries, deltaOptions, null, ct).ConfigureAwait(false);
        }
        finally
        {
            baseArchive?.Dispose();
        }

        // WORM：增量包写入完成后自动施加三层防删除锁（写句柄已随作用域释放）
        WormManager.AutoLock(deltaPath);

        return result;
    }

    /// <summary>
    /// 基于 USN 变更检测创建块级增量备份包（高层入口）。
    /// <para>流程：USN 日志检测自上次备份以来的变更文件（USN 不可用回退全量枚举）→
    /// 逐文件块级差分（一致块复用基础包，变更块写入增量包）→ 组装新块 + 块映射写入增量包。</para>
    /// <para>增量包头部记录 USN 游标元数据（UsnStart / UsnEnd / Strategy=BlockIncremental），
    /// 下次增量可直接读取本包 USN 游标作为起始位置。</para>
    /// </summary>
    /// <param name="sourceDir">源目录。</param>
    /// <param name="basePath">基础包路径（上次全量；null 或不存在 = 无基准，全部块视为新增）。</param>
    /// <param name="basePassword">基础包口令。</param>
    /// <param name="deltaPath">增量包输出路径。</param>
    /// <param name="deltaPassword">增量包口令。</param>
    /// <param name="options">写入参数（ChunkSize 决定块大小）。</param>
    /// <param name="lastUsn">上次记录的 USN 游标（0 = 无基准，全量枚举；从基础/增量包头读取）。</param>
    /// <param name="progress">进度跟踪（可选）。</param>
    /// <param name="ct">取消令牌。</param>
    public static async Task<BlockIncrementalResult> CreateIncrementalFromDirectoryAsync(
        string sourceDir, string? basePath, string basePassword,
        string deltaPath, string deltaPassword,
        BackupArchiveOptions options, long lastUsn = 0,
        IProgress<BackupProgressInfo>? progress = null, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(sourceDir) || !Directory.Exists(sourceDir))
            throw new DirectoryNotFoundException("源目录不存在：" + sourceDir);

        // 1. USN 变更检测（无基准 / USN 不可用 → 全量枚举，保证不遗漏）
        long usnStart = Math.Max(0, lastUsn);
        List<string> changedFull;
        long nextUsn = -1;
        if (usnStart > 0)
        {
            (changedFull, nextUsn) = UsnChangeDetector.Detect(sourceDir, usnStart);
        }
        else
        {
            changedFull = Directory.EnumerateFiles(sourceDir, "*", SearchOption.AllDirectories).ToList();
            nextUsn = -1;
        }

        // 2. 读取变更文件内容（沿用现有内存管线；超大文件后续走分块流式）
        var changed = new Dictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase);
        foreach (var file in changedFull)
        {
            ct.ThrowIfCancellationRequested();
            string rel;
            try
            {
                rel = Path.GetRelativePath(sourceDir, file).Replace('\\', '/');
            }
            catch
            {
                continue;
            }
            try
            {
                var data = await File.ReadAllBytesAsync(file, ct).ConfigureAwait(false);
                changed[rel] = data;
                progress?.Report(new BackupProgressInfo
                {
                    ProcessedFiles = changed.Count,
                    TotalFiles = changedFull.Count,
                    ProcessedBytes = data.Length,
                    TotalBytes = 0,
                    CurrentFile = rel,
                    Phase = BackupPhase.Backup
                });
            }
            catch (Exception ex)
            {
                ErrorReporter.Log($"跳过无法读取的文件 {file}：{ex.Message}", "WARN");
            }
        }

        // 3. 增量包头部元数据（USN 游标 + 备份时间，供增量链排序/版本点恢复）
        var metadata = new Dictionary<string, string>
        {
            ["Strategy"] = "BlockIncremental",
            ["BackupTime"] = DateTime.Now.ToString("O"),
            ["UsnStart"] = usnStart.ToString(),
            ["UsnEnd"] = Math.Max(0, nextUsn).ToString(),
            ["SourcePath"] = Path.GetFullPath(sourceDir)
        };

        // 4. 块级差分 + 写增量包
        var result = await CreateIncrementalAsync(basePath, basePassword, deltaPath, deltaPassword,
            changed, options, ct, metadata).ConfigureAwait(false);
        result.NextUsn = nextUsn;
        return result;
    }

    /// <summary>
    /// 重建文件最新内容：复用块取自基础包，新块取自增量包；未在增量包中的文件直接返回基础包数据。
    /// </summary>
    public static async Task<byte[]> RebuildFileAsync(
        string basePath, string basePassword,
        string deltaPath, string deltaPassword,
        string relPath, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(relPath))
            throw new ArgumentException("相对路径不能为空。", nameof(relPath));

        using var baseArchive = BackupArchiveFactory.Open(basePath, basePassword);
        using var deltaArchive = BackupArchiveFactory.Open(deltaPath, deltaPassword);
        var map = await ReadBlockMapAsync(deltaArchive, ct).ConfigureAwait(false);
        return await RebuildFileCore(baseArchive, deltaArchive, map, relPath, ct).ConfigureAwait(false);
    }

    /// <summary>读取增量包块映射（.lgblockmap 条目）。</summary>
    internal static async Task<BlockMapRoot> ReadBlockMapAsync(IBackupArchive deltaArchive, CancellationToken ct)
    {
        using var mapStream = await deltaArchive.OpenEntryAsync(BlockIncrementalResult.BlockMapEntry, ct).ConfigureAwait(false);
        using var mapMs = new MemoryStream();
        await mapStream.CopyToAsync(mapMs, ct).ConfigureAwait(false);
        return JsonSerializer.Deserialize<BlockMapRoot>(mapMs.ToArray(), JsonOptions)
               ?? throw new InvalidDataException("增量包块映射解析失败。");
    }

    /// <summary>
    /// 单文件重建核心（基础包 + 增量包已打开的场景，供链合并/版本点恢复批量复用）。
    /// <para>复用块取自基础包同偏移；新块取自增量包条目数据；未在增量包中的文件直接返回基础包数据。</para>
    /// </summary>
    internal static async Task<byte[]> RebuildFileCore(
        IBackupArchive baseArchive, IBackupArchive deltaArchive, BlockMapRoot map,
        string relPath, CancellationToken ct)
    {
        // 未在增量包中 → 直接来自基础包
        if (map.Files == null || !map.Files.TryGetValue(relPath, out var mapFile))
        {
            using var baseStream = await baseArchive.OpenEntryAsync(relPath, ct).ConfigureAwait(false);
            using var baseMs = new MemoryStream();
            await baseStream.CopyToAsync(baseMs, ct).ConfigureAwait(false);
            return baseMs.ToArray();
        }

        // 基准数据（可能不存在 → 全部依赖新块）
        byte[]? baseData = null;
        try
        {
            using var baseStream = await baseArchive.OpenEntryAsync(relPath, ct).ConfigureAwait(false);
            using var baseMs = new MemoryStream();
            await baseStream.CopyToAsync(baseMs, ct).ConfigureAwait(false);
            baseData = baseMs.ToArray();
        }
        catch (FileNotFoundException) { /* 新文件无基准 */ }

        // 增量数据（新块拼接）
        byte[] deltaData;
        using (var deltaStream = await deltaArchive.OpenEntryAsync(relPath, ct).ConfigureAwait(false))
        using (var deltaMs = new MemoryStream())
        {
            await deltaStream.CopyToAsync(deltaMs, ct).ConfigureAwait(false);
            deltaData = deltaMs.ToArray();
        }

        // 逐块重建
        using var outMs = new MemoryStream();
        foreach (var block in mapFile.Blocks)
        {
            ct.ThrowIfCancellationRequested();
            if (block.Reused)
            {
                if (baseData == null || block.Off + block.Len > baseData.Length)
                    throw new InvalidDataException($"复用块 {block.Hash[..Math.Min(16, block.Hash.Length)]} 缺少基准数据。");
                outMs.Write(baseData, (int)block.Off, (int)block.Len);
            }
            else
            {
                if (block.Dpos < 0 || block.Dpos + block.Len > deltaData.Length)
                    throw new InvalidDataException($"增量块 {block.Hash[..Math.Min(16, block.Hash.Length)]} 数据越界。");
                outMs.Write(deltaData, (int)block.Dpos, (int)block.Len);
            }
        }
        return outMs.ToArray();
    }

    /// <summary>
    /// 从 v3 备份包头读取 USN 游标（UsnEnd），供下次增量备份作为起始 USN。
    /// </summary>
    /// <param name="archivePath">备份包路径（基础包或增量包均可）。</param>
    /// <param name="password">备份口令。</param>
    /// <returns>USN 游标；包不存在 / 非 v3 / 无 USN 元数据返回 -1。</returns>
    public static long TryReadUsnEnd(string? archivePath, string password)
    {
        if (string.IsNullOrEmpty(archivePath) || !File.Exists(archivePath))
            return -1;
        try
        {
            using var archive = (V3PrivateContainerArchive)BackupArchiveFactory.Open(archivePath, password);
            if (archive.Metadata != null
                && archive.Metadata.TryGetValue("UsnEnd", out var usnEnd)
                && long.TryParse(usnEnd, out var val))
            {
                return val;
            }
        }
        catch
        {
            // 口令错误 / 格式异常均视为无游标，由调用方决定回退策略
        }
        return -1;
    }

    /// <summary>构建基础块索引：优先复用 Chunked 块元数据，缺失则读取条目数据现算。</summary>
    private static BlockChunkIndex BuildBaseIndex(
        IBackupArchive baseArchive, IReadOnlyList<BackupArchiveEntryInfo> entries,
        int chunkSize, CancellationToken ct)
    {
        var index = BlockIncrementalEngine.BuildIndexFromChunks(
            entries.Where(e => e.Chunks != null && e.Chunks.Count > 0)
                   .SelectMany(e => e.Chunks!)
                   .Select(c => (c.Hash, c.Length)),
            chunkSize);

        // 无块元数据的条目（如 PerFile / v1 风格）→ 读数据现算索引
        foreach (var entry in entries.Where(e => e.Chunks == null || e.Chunks.Count == 0))
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                using var s = baseArchive.OpenEntryAsync(entry.RelPath, ct).GetAwaiter().GetResult();
                using var ms = new MemoryStream();
                s.CopyTo(ms);
                index.MergeFrom(BlockIncrementalEngine.BuildIndex(ms.ToArray(), chunkSize));
            }
            catch { /* 单条目失败跳过，不阻断增量 */ }
        }
        return index;
    }
}

/// <summary>
/// USN 变更检测门面（直接使用 <see cref="IncrementalDifferentialEngine.UsnJournalScanner"/>，无 AppState 副作用）。
/// <para>返回相对路径变更清单与最新 USN（供下次增量作为起始 USN）。</para>
/// <para>USN 日志不可用 / 盘符解析失败 → 回退全量枚举，保证不遗漏变更。</para>
/// </summary>
public static class UsnChangeDetector
{
    /// <summary>
    /// 基于 USN 检测源目录下的变更文件（相对路径）。
    /// </summary>
    /// <param name="sourceDir">源目录。</param>
    /// <param name="lastUsn">上次记录的起始 USN（0 = 无基准，调用方应全量枚举）。</param>
    /// <returns>(变更文件相对路径列表, 最新 USN；USN 不可用 NextUsn = -1)。</returns>
    public static (List<string> ChangedRelPaths, long NextUsn) Detect(string sourceDir, long lastUsn = 0)
    {
        if (string.IsNullOrEmpty(sourceDir) || !Directory.Exists(sourceDir))
            throw new DirectoryNotFoundException("源目录不存在：" + sourceDir);

        var letter = ExtractDriveLetter(sourceDir);
        long nextUsn = -1;
        if (letter == null)
        {
            // 非盘符路径（如 UNC）→ 全量枚举
            return (EnumerateAll(sourceDir), -1);
        }

        List<UsnChangeRecord> records;
        try
        {
            records = IncrementalDifferentialEngine.UsnJournalScanner.ScanChanges(letter, lastUsn);
        }
        catch (Exception ex)
        {
            ErrorReporter.Log($"USN 日志扫描失败，回退到全量枚举：{ex.Message}", "WARN");
            return (EnumerateAll(sourceDir), -1);
        }

        // 预构建 源目录下 文件名 → 完整路径 映射（USN 记录仅含文件名）
        var nameToPaths = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
        try
        {
            foreach (var file in Directory.EnumerateFiles(sourceDir, "*", SearchOption.AllDirectories))
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
            ErrorReporter.Report(ex, $"枚举源目录失败：{sourceDir}");
        }

        // 变更文件去重（仅保留当前仍存在、且在源目录下的文件）
        var changedFull = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var record in records)
        {
            if (record.IsDelete || string.IsNullOrEmpty(record.FileName))
                continue;

            if (nameToPaths.TryGetValue(record.FileName, out var candidates))
            {
                foreach (var candidate in candidates)
                    changedFull.Add(candidate);
            }
        }

        try { nextUsn = IncrementalDifferentialEngine.UsnJournalScanner.GetNextUsn(letter); }
        catch { nextUsn = -1; }

        // USN 无任何匹配记录 → 回退全量枚举（防日志覆盖导致遗漏）
        if (changedFull.Count == 0)
        {
            ErrorReporter.Log("USN 未匹配到变更文件，回退到全量枚举以保安全。", "WARN");
            return (EnumerateAll(sourceDir), nextUsn);
        }

        var rels = changedFull
            .Select(f => Path.GetRelativePath(sourceDir, f).Replace('\\', '/'))
            .ToList();
        return (rels, nextUsn);
    }

    /// <summary>全量枚举目录下所有文件（USN 回退）。</summary>
    private static List<string> EnumerateAll(string sourceDir)
    {
        try
        {
            return Directory.EnumerateFiles(sourceDir, "*", SearchOption.AllDirectories).ToList();
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, $"回退全量枚举失败：{sourceDir}");
            return new List<string>();
        }
    }

    /// <summary>从路径解析盘符（"C:\..." → "C"）；非盘符路径返回 null。</summary>
    private static string? ExtractDriveLetter(string path)
    {
        var root = Path.GetPathRoot(path);
        if (string.IsNullOrEmpty(root) || root.Length < 2 || root[1] != ':')
            return null;
        var c = char.ToUpperInvariant(root[0]);
        return c is >= 'A' and <= 'Z' ? c.ToString() : null;
    }
}

// ==================== 块映射 JSON 模型 ====================

internal sealed class BlockMapRoot
{
    public long ChunkSize { get; set; }
    public Dictionary<string, BlockMapFile>? Files { get; set; }
}

internal sealed class BlockMapFile
{
    public long TotalLen { get; set; }
    public List<BlockMapBlock> Blocks { get; set; } = new();
}

internal sealed class BlockMapBlock
{
    public long Off { get; set; }
    public long Len { get; set; }
    public string Hash { get; set; } = "";
    public bool Reused { get; set; }

    /// <summary>新块在增量条目数据中的偏移（Reused=false 时有效）。</summary>
    public long Dpos { get; set; } = -1;
}
