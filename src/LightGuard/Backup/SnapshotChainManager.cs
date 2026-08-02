// © 2026 落尘（Luochen） 原创开发 - 保留所有权利

using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Serialization;
using LightGuard.Core;
using LightGuard.Recovery;

namespace LightGuard.Backup;

/// <summary>
/// 快照调度类型 - 标识快照的创建周期与保留类别。
/// </summary>
public enum SnapshotType
{
    /// <summary>小时级快照（高频，保留份数最少）。</summary>
    Hourly,

    /// <summary>日级快照。</summary>
    Daily,

    /// <summary>周级快照。</summary>
    Weekly,

    /// <summary>月级快照（低频，通常长期保留，不参与自动清理）。</summary>
    Monthly,

    /// <summary>手动快照（不参与自动清理）。</summary>
    Manual
}

/// <summary>
/// 快照节点 - 链中一个版本点，关联一个 .lgbackup 备份包。
/// <para>首个节点（<see cref="ParentNodeId"/> 为 null）为全量根备份，后续节点为增量，依父指针串成链。</para>
/// </summary>
public sealed class SnapshotNode
{
    /// <summary>节点唯一标识（GUID）。</summary>
    public Guid NodeId { get; set; } = Guid.NewGuid();

    /// <summary>关联的备份唯一标识（指向 .lgbackup 包清单中的 BackupId）。</summary>
    public Guid BackupId { get; set; }

    /// <summary>快照时间（取自备份清单 BackupTime）。</summary>
    public DateTime SnapshotTime { get; set; } = DateTime.Now;

    /// <summary>快照调度类型。</summary>
    public SnapshotType Type { get; set; } = SnapshotType.Manual;

    /// <summary>关联的 .lgbackup 备份包文件名（相对链目录或绝对路径）。</summary>
    public string BackupFileName { get; set; } = string.Empty;

    /// <summary>备份包体积（字节）。</summary>
    public long SizeBytes { get; set; }

    /// <summary>父快照节点 ID（全量根备份为 null）。</summary>
    public string? ParentNodeId { get; set; }

    /// <summary>快照描述。</summary>
    public string? Description { get; set; }

    /// <summary>附加元数据（继承自备份清单）。</summary>
    public Dictionary<string, string> Metadata { get; set; } = new();
}

/// <summary>
/// 快照链 - 同一源路径的多版本时间快照序列，以 .lgchain 文件持久化。
/// <para>JSON 布局：chainId / sourcePath / createdAt / nodes / rootNodeId。</para>
/// <para>NodeCount / TotalSizeBytes / LastSnapshotTime 为派生属性，不持久化。</para>
/// </summary>
public sealed class SnapshotChain
{
    /// <summary>链唯一标识。</summary>
    public string ChainId { get; set; } = string.Empty;

    /// <summary>被备份的源路径。</summary>
    public string SourcePath { get; set; } = string.Empty;

    /// <summary>链创建时间。</summary>
    public DateTime CreatedAt { get; set; } = DateTime.Now;

    /// <summary>快照节点集合（按加入顺序）。</summary>
    public List<SnapshotNode> Nodes { get; set; } = new();

    /// <summary>首个全量根备份节点 ID（空链为 null）。</summary>
    public string? RootNodeId { get; set; }

    /// <summary>节点总数（派生，不持久化）。</summary>
    [JsonIgnore]
    public int NodeCount => Nodes.Count;

    /// <summary>所有快照累计体积（派生，不持久化）。</summary>
    [JsonIgnore]
    public long TotalSizeBytes => Nodes.Sum(n => n.SizeBytes);

    /// <summary>最后快照时间（派生，不持久化）。</summary>
    [JsonIgnore]
    public DateTime? LastSnapshotTime => Nodes.Count > 0 ? Nodes.Max(n => n.SnapshotTime) : null;
}

/// <summary>
/// 快照链管理器 - 维护多版本时间快照链（.lgchain），支持时间点恢复、保留策略清理与增量合并。
/// <para>链文件命名：chain_{chainId}.lgchain；链目录同时存放关联的 .lgbackup 备份包。</para>
/// <para>全量根备份（ParentNodeId 为 null）永不删除；已锁定快照（备份清单 IsLocked）跳过清理。</para>
/// </summary>
public sealed class SnapshotChainManager
{
    /// <summary>.lgchain 文件扩展名。</summary>
    public const string ChainFileExtension = ".lgchain";

    private readonly AppState? _appState;

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Converters = { new JsonStringEnumConverter() }
    };

    /// <summary>
    /// 初始化快照链管理器。
    /// </summary>
    /// <param name="appState">全局应用状态（合并快照创建新全量备份时必需；其他操作可省略）。</param>
    public SnapshotChainManager(AppState? appState = null)
    {
        _appState = appState;
    }

    /// <summary>
    /// 创建新的快照链。
    /// </summary>
    /// <param name="sourcePath">被备份的源路径。</param>
    /// <param name="chainDir">链目录（存放 .lgchain 与关联 .lgbackup）。</param>
    /// <returns>新建的空快照链。</returns>
    public SnapshotChain CreateChain(string sourcePath, string chainDir)
    {
        ArgumentException.ThrowIfNullOrEmpty(sourcePath);
        ArgumentException.ThrowIfNullOrEmpty(chainDir);

        Directory.CreateDirectory(chainDir);

        var chain = new SnapshotChain
        {
            ChainId = $"ch_{DateTime.Now:yyyyMMddHHmmss}_{Guid.NewGuid().ToString("N")[..8]}",
            SourcePath = sourcePath,
            CreatedAt = DateTime.Now,
            Nodes = new List<SnapshotNode>(),
            RootNodeId = null
        };

        SaveChain(chain, chainDir);
        ErrorReporter.Log($"已创建快照链：{chain.ChainId}（源 {sourcePath}，目录 {chainDir}）");
        return chain;
    }

    /// <summary>
    /// 将一个备份加入快照链。
    /// <para>链为空时作为全量根节点；否则链接到上一个节点作为增量快照。</para>
    /// </summary>
    /// <param name="chainId">链标识。</param>
    /// <param name="chainDir">链目录。</param>
    /// <param name="manifest">备份清单（来自刚完成的 .lgbackup）。</param>
    /// <param name="type">快照调度类型。</param>
    /// <param name="description">快照描述（可选）。</param>
    /// <returns>新增的快照节点。</returns>
    public SnapshotNode AddSnapshot(string chainId, string chainDir, BackupManifest manifest, SnapshotType type, string? description)
    {
        ArgumentNullException.ThrowIfNull(manifest);
        ArgumentException.ThrowIfNullOrEmpty(chainId);
        ArgumentException.ThrowIfNullOrEmpty(chainDir);

        var chain = GetChain(chainId, chainDir);
        var isRoot = chain.Nodes.Count == 0;
        var parentNodeId = isRoot ? null : chain.Nodes[^1].NodeId.ToString();

        // 解析关联的 .lgbackup 文件名
        var backupFileName = FindBackupFileName(chainDir, manifest.BackupId)
                              ?? $"{manifest.BackupId.ToString("N")}{LgBackupFormat.Extension}";

        // 体积：优先取实际备份包大小，回退到清单 TotalSize
        long sizeBytes = manifest.TotalSize;
        var backupPath = ResolveBackupPath(chainDir, backupFileName);
        if (File.Exists(backupPath))
        {
            try { sizeBytes = new FileInfo(backupPath).Length; }
            catch (Exception ex) { ErrorReporter.Log($"读取备份包大小失败，回退清单值：{ex.Message}"); }
        }

        var node = new SnapshotNode
        {
            NodeId = Guid.NewGuid(),
            BackupId = manifest.BackupId,
            SnapshotTime = manifest.BackupTime,
            Type = type,
            BackupFileName = backupFileName,
            SizeBytes = sizeBytes,
            ParentNodeId = parentNodeId,
            Description = description,
            Metadata = manifest.Metadata != null
                ? new Dictionary<string, string>(manifest.Metadata)
                : new Dictionary<string, string>()
        };

        chain.Nodes.Add(node);
        if (isRoot)
        {
            chain.RootNodeId = node.NodeId.ToString();
        }

        SaveChain(chain, chainDir);
        ErrorReporter.Log($"快照已入链 {chainId}：节点 {node.NodeId}（类型={type}，{(isRoot ? "全量根" : "增量，父=" + parentNodeId)}）");
        return node;
    }

    /// <summary>
    /// 从 .lgchain 文件加载快照链。
    /// </summary>
    /// <param name="chainId">链标识。</param>
    /// <param name="chainDir">链目录。</param>
    /// <returns>快照链实例。</returns>
    /// <exception cref="FileNotFoundException">链文件不存在。</exception>
    /// <exception cref="InvalidDataException">链文件损坏。</exception>
    public SnapshotChain GetChain(string chainId, string chainDir)
    {
        ArgumentException.ThrowIfNullOrEmpty(chainId);
        ArgumentException.ThrowIfNullOrEmpty(chainDir);

        var path = GetChainFilePath(chainDir, chainId);
        if (!File.Exists(path))
            throw new FileNotFoundException($"快照链文件不存在：{path}", path);

        var json = File.ReadAllText(path);
        var chain = JsonSerializer.Deserialize<SnapshotChain>(json, JsonOptions);
        if (chain == null)
            throw new InvalidDataException($"快照链文件损坏，无法解析：{path}");
        return chain;
    }

    /// <summary>
    /// 列出链目录下所有快照链。
    /// </summary>
    /// <param name="chainDir">链目录。</param>
    /// <returns>快照链列表（无法解析的链文件将被跳过并记录日志）。</returns>
    public List<SnapshotChain> ListChains(string chainDir)
    {
        var list = new List<SnapshotChain>();
        if (string.IsNullOrEmpty(chainDir) || !Directory.Exists(chainDir)) return list;

        foreach (var file in Directory.EnumerateFiles(chainDir, "*" + ChainFileExtension))
        {
            try
            {
                var chain = JsonSerializer.Deserialize<SnapshotChain>(File.ReadAllText(file), JsonOptions);
                if (chain != null) list.Add(chain);
            }
            catch (Exception ex)
            {
                ErrorReporter.Log($"跳过无法解析的快照链 {file}：{ex.Message}");
            }
        }
        return list;
    }

    /// <summary>
    /// 删除快照链（仅删除 .lgchain 文件，不删除关联的 .lgbackup 备份包）。
    /// </summary>
    /// <param name="chainId">链标识。</param>
    /// <param name="chainDir">链目录。</param>
    /// <returns>删除成功返回 true。</returns>
    public bool DeleteChain(string chainId, string chainDir)
    {
        var path = GetChainFilePath(chainDir, chainId);
        if (!File.Exists(path))
        {
            ErrorReporter.Log($"快照链不存在，无法删除：{path}");
            return false;
        }
        try
        {
            File.Delete(path);
            ErrorReporter.Log($"快照链已删除（关联 .lgbackup 备份包保留）：{path}");
            return true;
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, $"删除快照链失败：{path}");
            return false;
        }
    }

    /// <summary>
    /// 查找不晚于指定时间点的最近快照节点。
    /// </summary>
    /// <param name="chainId">链标识。</param>
    /// <param name="chainDir">链目录。</param>
    /// <param name="pointInTime">目标时间点。</param>
    /// <returns>最近的快照节点；无匹配或出错返回 null。</returns>
    public SnapshotNode? FindSnapshotByTime(string chainId, string chainDir, DateTime pointInTime)
    {
        try
        {
            var chain = GetChain(chainId, chainDir);
            return chain.Nodes
                .Where(n => n.SnapshotTime <= pointInTime)
                .OrderByDescending(n => n.SnapshotTime)
                .FirstOrDefault();
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, $"按时间查找快照失败：链 {chainId}");
            return null;
        }
    }

    /// <summary>
    /// 时间点恢复：恢复到不晚于指定时间的状态。
    /// <para>流程：定位不晚于目标时间的最近全量基准备份 → 沿父指针依次应用其增量链到目标时间点 → 全程日志。</para>
    /// <para>全量基准用 <see cref="RecoveryMode.ForceOverwrite"/> 写入，增量用 <see cref="RecoveryMode.Incremental"/> 叠加。</para>
    /// </summary>
    /// <param name="chainId">链标识。</param>
    /// <param name="chainDir">链目录。</param>
    /// <param name="pointInTime">目标时间点。</param>
    /// <param name="password">解密口令。</param>
    /// <param name="destDir">恢复目标目录。</param>
    /// <returns>恢复结果（含累计文件数与字节数）。</returns>
    public RecoveryResult RestoreToPointInTime(string chainId, string chainDir, DateTime pointInTime, string password, string destDir)
    {
        var result = new RecoveryResult();
        try
        {
            ArgumentException.ThrowIfNullOrEmpty(password);
            ArgumentException.ThrowIfNullOrEmpty(destDir);

            var chain = GetChain(chainId, chainDir);
            ErrorReporter.Log($"开始时间点恢复：链 {chainId} -> {destDir}，目标时间 {pointInTime:yyyy-MM-dd HH:mm:ss}");

            // 1. 定位不晚于目标时间的最近全量根备份
            var root = chain.Nodes
                .Where(n => string.IsNullOrEmpty(n.ParentNodeId) && n.SnapshotTime <= pointInTime)
                .OrderByDescending(n => n.SnapshotTime)
                .FirstOrDefault();

            if (root == null)
            {
                result.Success = false;
                result.Message = $"未找到不晚于 {pointInTime:yyyy-MM-dd HH:mm:ss} 的全量基准备份，无法恢复。";
                ErrorReporter.Log(result.Message);
                return result;
            }

            ErrorReporter.Log($"定位全量基准备份：节点 {root.NodeId}（{root.SnapshotTime:yyyy-MM-dd HH:mm:ss}）");

            // 2. 沿父指针正向收集增量链，直到目标时间点
            var sequence = new List<SnapshotNode> { root };
            var current = root;
            while (true)
            {
                var child = chain.Nodes.FirstOrDefault(n => IsChildOf(n, current.NodeId));
                if (child == null) break;
                if (child.SnapshotTime > pointInTime) break;
                sequence.Add(child);
                current = child;
            }

            ErrorReporter.Log($"恢复序列：{sequence.Count} 个节点（1 全量 + {sequence.Count - 1} 增量）");

            // 3. 恢复全量基准备份
            Directory.CreateDirectory(destDir);
            var engine = new RecoveryEngine(_appState);

            var rootPath = ResolveBackupPath(chainDir, root.BackupFileName);
            ErrorReporter.Log($"恢复全量基准备份：{rootPath}");
            var baseResult = engine.Recover(rootPath, password, destDir, RecoveryMode.ForceOverwrite);
            if (!baseResult.Success)
            {
                ErrorReporter.Log($"全量基准备份恢复失败：{baseResult.Message}");
                return baseResult;
            }
            result = baseResult;

            // 4. 依次应用增量备份（仅写入变更文件）
            for (int i = 1; i < sequence.Count; i++)
            {
                var node = sequence[i];
                var incPath = ResolveBackupPath(chainDir, node.BackupFileName);
                ErrorReporter.Log($"应用增量备份 [{i}/{sequence.Count - 1}]：{incPath}（{node.SnapshotTime:yyyy-MM-dd HH:mm:ss}）");
                var incResult = engine.Recover(incPath, password, destDir, RecoveryMode.Incremental);
                if (!incResult.Success)
                {
                    ErrorReporter.Log($"增量备份应用失败，停止后续应用：{incResult.Message}");
                    break;
                }
                result.FileCount += incResult.FileCount;
                result.TotalBytes += incResult.TotalBytes;
            }

            result.Success = true;
            result.Message = $"时间点恢复完成：{sequence.Count} 个快照，已恢复 {result.FileCount} 个文件 / {FormatSize(result.TotalBytes)} 到 {destDir}";
            ErrorReporter.Log(result.Message);
        }
        catch (Exception ex)
        {
            result.Success = false;
            result.Message = $"时间点恢复失败：{ex.Message}";
            ErrorReporter.Report(ex, $"时间点恢复失败：链 {chainId}");
        }
        return result;
    }

    /// <summary>
    /// 按保留策略清理旧快照。
    /// <para>策略：分别保留最近 N 个小时级、M 个日级、K 个周级快照（按时间倒序保留最新）。</para>
    /// <para>全量根备份（ParentNodeId 为 null）永不删除；已锁定快照（备份清单 IsLocked）跳过；</para>
    /// <para>月级（Monthly）与手动（Manual）快照不参与自动清理；被删节点的子节点重链到其父节点以保持链连续。</para>
    /// </summary>
    /// <param name="chainId">链标识。</param>
    /// <param name="chainDir">链目录。</param>
    /// <param name="maxHourly">保留的小时级快照数（负数表示不限制）。</param>
    /// <param name="maxDaily">保留的日级快照数（负数表示不限制）。</param>
    /// <param name="maxWeekly">保留的周级快照数（负数表示不限制）。</param>
    /// <returns>实际移除的节点数。</returns>
    public int CleanupOldSnapshots(string chainId, string chainDir, int maxHourly, int maxDaily, int maxWeekly)
    {
        var removed = 0;
        try
        {
            var chain = GetChain(chainId, chainDir);
            var toRemove = new HashSet<Guid>();

            // 全量根节点永不删除
            var fullIds = chain.Nodes
                .Where(n => string.IsNullOrEmpty(n.ParentNodeId))
                .Select(n => n.NodeId)
                .ToHashSet();

            ApplyRetentionByType(chain.Nodes, SnapshotType.Hourly, maxHourly, toRemove);
            ApplyRetentionByType(chain.Nodes, SnapshotType.Daily, maxDaily, toRemove);
            ApplyRetentionByType(chain.Nodes, SnapshotType.Weekly, maxWeekly, toRemove);

            foreach (var node in chain.Nodes.Where(n => toRemove.Contains(n.NodeId)).ToList())
            {
                if (fullIds.Contains(node.NodeId))
                {
                    ErrorReporter.Log($"跳过全量根节点（永不删除）：{node.NodeId}");
                    continue;
                }
                if (IsSnapshotLocked(chainDir, node))
                {
                    ErrorReporter.Log($"跳过已锁定快照节点：{node.NodeId}（{node.SnapshotTime:yyyy-MM-dd HH:mm:ss}）");
                    continue;
                }

                // 重链被删节点的子节点到其父节点，保持链连续
                var orphanParent = node.ParentNodeId;
                foreach (var child in chain.Nodes.Where(n => IsChildOf(n, node.NodeId)).ToList())
                {
                    child.ParentNodeId = orphanParent;
                }

                chain.Nodes.Remove(node);
                removed++;
                ErrorReporter.Log($"已按策略移除快照节点：{node.NodeId}（类型={node.Type}，{node.SnapshotTime:yyyy-MM-dd HH:mm:ss}）");
            }

            SaveChain(chain, chainDir);
            ErrorReporter.Log($"快照链清理完成：链 {chainId}，移除 {removed} 个节点");
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, $"快照链清理失败：链 {chainId}");
        }
        return removed;
    }

    /// <summary>
    /// 合并增量快照为新的全量备份。
    /// <para>将最近一次全量及其全部增量恢复到临时目录后重新打包为 .lgbackup，作为新全量根节点加入链。</para>
    /// <para>需要构造时传入 <see cref="AppState"/>（用于创建 <see cref="BackupExecutor"/>）。</para>
    /// </summary>
    /// <param name="chainId">链标识。</param>
    /// <param name="chainDir">链目录。</param>
    /// <param name="password">解密口令。</param>
    /// <returns>新全量快照节点；无可合并内容或失败返回 null。</returns>
    public SnapshotNode? MergeSnapshots(string chainId, string chainDir, string password)
    {
        string? tempDir = null;
        try
        {
            ArgumentException.ThrowIfNullOrEmpty(password);

            if (_appState == null)
            {
                ErrorReporter.Log("合并快照需要应用状态（AppState），请在构造 SnapshotChainManager 时传入。");
                return null;
            }

            var chain = GetChain(chainId, chainDir);

            // 定位最近一次全量根备份
            var latestFull = chain.Nodes
                .Where(n => string.IsNullOrEmpty(n.ParentNodeId))
                .OrderByDescending(n => n.SnapshotTime)
                .FirstOrDefault();
            if (latestFull == null)
            {
                ErrorReporter.Log($"链 {chainId} 无全量备份，无法合并。");
                return null;
            }

            // 正向收集其全部增量
            var mergeSequence = new List<SnapshotNode> { latestFull };
            var current = latestFull;
            while (true)
            {
                var child = chain.Nodes.FirstOrDefault(n => IsChildOf(n, current.NodeId));
                if (child == null) break;
                mergeSequence.Add(child);
                current = child;
            }

            if (mergeSequence.Count <= 1)
            {
                ErrorReporter.Log($"链 {chainId} 最近全量无增量快照，无需合并。");
                return null;
            }

            ErrorReporter.Log($"开始合并 {mergeSequence.Count} 个快照为新的全量备份（链 {chainId}）");

            // 恢复到临时目录
            tempDir = Path.Combine(Path.GetTempPath(), $"lgmerge_{chainId}_{Guid.NewGuid():N}");
            Directory.CreateDirectory(tempDir);

            var engine = new RecoveryEngine(_appState);
            var rootPath = ResolveBackupPath(chainDir, latestFull.BackupFileName);
            var baseResult = engine.Recover(rootPath, password, tempDir, RecoveryMode.ForceOverwrite);
            if (!baseResult.Success)
                throw new InvalidOperationException($"合并基础恢复失败：{baseResult.Message}");

            for (int i = 1; i < mergeSequence.Count; i++)
            {
                var incPath = ResolveBackupPath(chainDir, mergeSequence[i].BackupFileName);
                var r = engine.Recover(incPath, password, tempDir, RecoveryMode.Incremental);
                if (!r.Success)
                    ErrorReporter.Log($"合并中增量应用警告 [{i}/{mergeSequence.Count - 1}]：{r.Message}");
            }

            // 重新打包为新的全量备份
            var executor = new BackupExecutor(_appState);
            var manifest = executor.BackupDirectory(tempDir, password, chainDir);
            manifest.Metadata["MergeSource"] = string.Join(",", mergeSequence.Select(n => n.NodeId.ToString()));
            manifest.Metadata["Strategy"] = "Full";
            // 回写以记录合并来源元数据（保留分片密文不变）
            RewriteManifest(chainDir, manifest);

            var backupFileName = FindBackupFileName(chainDir, manifest.BackupId)
                                 ?? $"{manifest.BackupId.ToString("N")}{LgBackupFormat.Extension}";

            long sizeBytes = manifest.TotalSize;
            var bp = ResolveBackupPath(chainDir, backupFileName);
            if (File.Exists(bp))
            {
                try { sizeBytes = new FileInfo(bp).Length; } catch { }
            }

            var merged = new SnapshotNode
            {
                NodeId = Guid.NewGuid(),
                BackupId = manifest.BackupId,
                SnapshotTime = manifest.BackupTime,
                Type = SnapshotType.Manual,
                BackupFileName = backupFileName,
                SizeBytes = sizeBytes,
                ParentNodeId = null, // 新全量根，作为新子链起点
                Description = $"合并 {mergeSequence.Count} 个快照生成的新全量备份",
                Metadata = new Dictionary<string, string>(manifest.Metadata)
            };

            chain.Nodes.Add(merged);
            // RootNodeId 保持首个根不变
            SaveChain(chain, chainDir);

            ErrorReporter.Log($"快照合并完成：链 {chainId}，新全量节点 {merged.NodeId}（{FormatSize(sizeBytes)}）");
            return merged;
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, $"合并快照失败：链 {chainId}");
            return null;
        }
        finally
        {
            if (tempDir != null)
            {
                try { if (Directory.Exists(tempDir)) Directory.Delete(tempDir, recursive: true); }
                catch (Exception ex) { ErrorReporter.Log($"清理合并临时目录失败：{ex.Message}"); }
            }
        }
    }

    /// <summary>
    /// 获取快照链统计摘要。
    /// </summary>
    /// <param name="chainId">链标识。</param>
    /// <param name="chainDir">链目录。</param>
    /// <returns>统计文本；出错返回错误信息。</returns>
    public string GetChainStatistics(string chainId, string chainDir)
    {
        try
        {
            var chain = GetChain(chainId, chainDir);
            var lines = new List<string>
            {
                "===== 快照链统计 =====",
                $"链标识：{chain.ChainId}",
                $"源路径：{chain.SourcePath}",
                $"创建时间：{chain.CreatedAt:yyyy-MM-dd HH:mm:ss}",
                $"节点总数：{chain.NodeCount}",
                $"根节点：{chain.RootNodeId ?? "无"}",
                $"总大小：{FormatSize(chain.TotalSizeBytes)}",
                $"最后快照：{(chain.LastSnapshotTime?.ToString("yyyy-MM-dd HH:mm:ss") ?? "无")}"
            };

            var fullCount = chain.Nodes.Count(n => string.IsNullOrEmpty(n.ParentNodeId));
            lines.Add($"全量备份：{fullCount} 个 / 增量备份：{chain.NodeCount - fullCount} 个");

            foreach (var g in chain.Nodes.GroupBy(n => n.Type).OrderBy(g => g.Key))
            {
                lines.Add($"  {g.Key} 快照：{g.Count()} 个 / {FormatSize(g.Sum(n => n.SizeBytes))}");
            }

            return string.Join(Environment.NewLine, lines);
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, $"获取快照链统计失败：{chainId}");
            return $"获取统计失败：{ex.Message}";
        }
    }

    #region 私有辅助

    private static string GetChainFilePath(string chainDir, string chainId)
        => Path.Combine(chainDir, $"chain_{chainId}{ChainFileExtension}");

    /// <summary>
    /// 原子写入快照链文件（临时文件 + 覆盖移动）。
    /// </summary>
    private static void SaveChain(SnapshotChain chain, string chainDir)
    {
        Directory.CreateDirectory(chainDir);
        var path = GetChainFilePath(chainDir, chain.ChainId);
        var json = JsonSerializer.Serialize(chain, JsonOptions);
        var tmp = path + ".tmp";
        File.WriteAllText(tmp, json);
        File.Move(tmp, path, overwrite: true);
    }

    /// <summary>
    /// 解析备份包绝对路径（支持绝对路径或相对链目录的文件名）。
    /// </summary>
    private static string ResolveBackupPath(string chainDir, string backupFileName)
    {
        if (string.IsNullOrEmpty(backupFileName)) return string.Empty;
        return Path.IsPathRooted(backupFileName) ? backupFileName : Path.Combine(chainDir, backupFileName);
    }

    /// <summary>
    /// 在链目录中查找与 BackupId 匹配的 .lgbackup 文件名。
    /// <para>先按 BackupId 前 8 位缩小范围，再读清单精确比对；失败回退全量扫描。</para>
    /// </summary>
    private static string? FindBackupFileName(string chainDir, Guid backupId)
    {
        if (string.IsNullOrEmpty(chainDir) || !Directory.Exists(chainDir)) return null;

        var id8 = backupId.ToString("N")[..8];
        foreach (var file in Directory.EnumerateFiles(chainDir, $"*{id8}*{LgBackupFormat.Extension}"))
        {
            if (ManifestMatches(file, backupId)) return Path.GetFileName(file);
        }
        // 全量兜底扫描
        foreach (var file in Directory.EnumerateFiles(chainDir, "*" + LgBackupFormat.Extension))
        {
            if (ManifestMatches(file, backupId)) return Path.GetFileName(file);
        }
        return null;
    }

    private static bool ManifestMatches(string path, Guid backupId)
    {
        try
        {
            var (manifest, _, _) = LgBackupFormat.ReadManifestOnly(path);
            return manifest.BackupId == backupId;
        }
        catch (Exception ex)
        {
            ErrorReporter.Log($"比对备份清单失败，跳过 {path}：{ex.Message}");
            return false;
        }
    }

    /// <summary>
    /// 判断 node 是否为 parentId 的直接子节点（兼容不同 Guid 字符串格式）。
    /// </summary>
    private static bool IsChildOf(SnapshotNode node, Guid parentId)
    {
        if (string.IsNullOrEmpty(node.ParentNodeId)) return false;
        return Guid.TryParse(node.ParentNodeId, out var pid) && pid == parentId;
    }

    /// <summary>
    /// 读取关联备份清单判定是否锁定；文件缺失或读取异常时视为锁定（保护性，避免误删悬空节点）。
    /// </summary>
    private static bool IsSnapshotLocked(string chainDir, SnapshotNode node)
    {
        try
        {
            var path = ResolveBackupPath(chainDir, node.BackupFileName);
            if (!File.Exists(path)) return true;
            var (manifest, _, _) = LgBackupFormat.ReadManifestOnly(path);
            return manifest.IsLocked;
        }
        catch (Exception ex)
        {
            ErrorReporter.Log($"读取快照锁定状态失败，视为锁定以保护：{node.NodeId}（{ex.Message}）");
            return true;
        }
    }

    /// <summary>
    /// 按类型应用保留策略：按时间倒序保留前 maxKeep 个增量，余者标记删除。
    /// <para>全量根节点（ParentNodeId 为 null）不参与，永不删除。</para>
    /// </summary>
    private static void ApplyRetentionByType(List<SnapshotNode> nodes, SnapshotType type, int maxKeep, HashSet<Guid> toRemove)
    {
        if (maxKeep < 0) return; // 负数表示不限制
        var typed = nodes
            .Where(n => n.Type == type && !string.IsNullOrEmpty(n.ParentNodeId))
            .OrderByDescending(n => n.SnapshotTime)
            .ToList();
        foreach (var node in typed.Skip(Math.Max(0, maxKeep)))
        {
            toRemove.Add(node.NodeId);
        }
    }

    /// <summary>
    /// 回写更新后的清单到现有 .lgbackup 包（保留分片密文不变）。
    /// </summary>
    private static void RewriteManifest(string chainDir, BackupManifest manifest)
    {
        var fileName = FindBackupFileName(chainDir, manifest.BackupId);
        if (fileName == null) return;
        var path = ResolveBackupPath(chainDir, fileName);
        if (!File.Exists(path)) return;

        var (_, shards) = LgBackupFormat.ReadBackup(path);
        var tmp = path + ".tmp";
        LgBackupFormat.WriteBackup(tmp, manifest, shards);
        File.Move(tmp, path, overwrite: true);
    }

    /// <summary>
    /// 将字节数格式化为人类可读大小。
    /// </summary>
    private static string FormatSize(long bytes)
    {
        if (bytes < 1024) return $"{bytes} B";
        if (bytes < 1024 * 1024) return $"{bytes / 1024.0:F1} KB";
        if (bytes < 1024L * 1024 * 1024) return $"{bytes / 1024.0 / 1024.0:F1} MB";
        return $"{bytes / 1024.0 / 1024.0 / 1024.0:F2} GB";
    }

    #endregion
}
