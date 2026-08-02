// © 2026 落尘（Luochen） 原创开发 - 保留所有权利

using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using LightGuard.Core;

namespace LightGuard.Backup;

/// <summary>
/// 文件变更类型 - 两次备份快照之间单个文件条目的变更分类。
/// </summary>
public enum FileChangeType
{
    /// <summary>新增：旧快照不存在、新快照存在。</summary>
    Added,

    /// <summary>删除：旧快照存在、新快照不存在。</summary>
    Deleted,

    /// <summary>修改：新旧快照均存在但内容哈希不同。</summary>
    Modified,

    /// <summary>重命名：内容哈希相同但文件路径改变（由"删除+新增"按哈希匹配推导）。</summary>
    Renamed,

    /// <summary>未变更：新旧快照均存在且内容哈希相同。</summary>
    Unchanged
}

/// <summary>
/// 单个文件的变更记录 - 描述两次备份之间某一文件条目的新旧状态差异。
/// </summary>
public sealed class FileChangeRecord
{
    /// <summary>文件相对路径（重命名时为重命名后的新路径）。</summary>
    public string FilePath { get; set; } = string.Empty;

    /// <summary>变更类型。</summary>
    public FileChangeType ChangeType { get; set; }

    /// <summary>旧快照中的文件大小（字节）；新增时为 0，未知时为 0。</summary>
    public long OldSize { get; set; }

    /// <summary>新快照中的文件大小（字节）；删除时为 0，未知时为 0。</summary>
    public long NewSize { get; set; }

    /// <summary>旧快照中的内容 SHA256（大写十六进制）；新增时为 null。</summary>
    public string? OldHash { get; set; }

    /// <summary>新快照中的内容 SHA256（大写十六进制）；删除时为 null。</summary>
    public string? NewHash { get; set; }

    /// <summary>最后修改时间（尽力而为，仅当新备份源仍可访问时填充）；未知为 null。</summary>
    public DateTime? LastModified { get; set; }

    /// <summary>
    /// 重命名前的旧文件相对路径；仅在 <see cref="ChangeType"/> 为 <see cref="FileChangeType.Renamed"/> 时填充，
    /// 其余类型为 null。用于勒索扩展名变更检测。
    /// </summary>
    public string? OldFilePath { get; set; }
}

/// <summary>
/// 差异审计报告 - 汇总两次备份之间的全部文件变更与勒索软件风险评估结果。
/// </summary>
public sealed class AuditReport
{
    /// <summary>报告生成时间（本地时间）。</summary>
    public DateTime GeneratedAt { get; set; } = DateTime.Now;

    /// <summary>被审计的源路径。</summary>
    public string SourcePath { get; set; } = string.Empty;

    /// <summary>新增文件数。</summary>
    public int AddedCount { get; set; }

    /// <summary>删除文件数。</summary>
    public int DeletedCount { get; set; }

    /// <summary>修改文件数。</summary>
    public int ModifiedCount { get; set; }

    /// <summary>未变更文件数。</summary>
    public int UnchangedCount { get; set; }

    /// <summary>新增文件累计字节数。</summary>
    public long AddedBytes { get; set; }

    /// <summary>删除文件累计字节数。</summary>
    public long DeletedBytes { get; set; }

    /// <summary>逐条变更记录（含 Renamed）。</summary>
    public List<FileChangeRecord> Changes { get; set; } = new();

    /// <summary>是否疑似遭受勒索软件攻击。</summary>
    public bool IsRansomwareSuspect { get; set; }

    /// <summary>风险评估描述（含命中特征说明）。</summary>
    public string? RiskAssessment { get; set; }

    /// <summary>重命名文件数（不在 AddedCount/DeletedCount 中重复计数）。</summary>
    public int RenamedCount => Changes.Count(c => c.ChangeType == FileChangeType.Renamed);

    /// <summary>
    /// 返回人类可读的汇总摘要。
    /// </summary>
    /// <returns>汇总文本。</returns>
    public string ToSummary()
    {
        var sb = new StringBuilder();
        sb.AppendLine("=== 备份差异审计报告 ===");
        sb.AppendLine($"生成时间：{GeneratedAt:yyyy-MM-dd HH:mm:ss}");
        sb.AppendLine($"源路径：{SourcePath}");
        sb.AppendLine($"新增：{AddedCount} 个（{FormatBytes(AddedBytes)}）");
        sb.AppendLine($"删除：{DeletedCount} 个（{FormatBytes(DeletedBytes)}）");
        sb.AppendLine($"修改：{ModifiedCount} 个");
        sb.AppendLine($"重命名：{RenamedCount} 个");
        sb.AppendLine($"未变更：{UnchangedCount} 个");
        sb.AppendLine($"勒索疑似：{(IsRansomwareSuspect ? "是" : "否")}");
        if (!string.IsNullOrEmpty(RiskAssessment))
            sb.AppendLine($"风险评估：{RiskAssessment}");
        return sb.ToString();
    }

    /// <summary>
    /// 将字节数格式化为易读字符串（KB/MB/GB）。
    /// </summary>
    /// <param name="bytes">字节数。</param>
    /// <returns>易读字符串。</returns>
    public static string FormatBytes(long bytes)
    {
        if (bytes < 0) bytes = 0;
        if (bytes < 1024) return $"{bytes} B";
        if (bytes < 1024L * 1024) return $"{bytes / 1024.0:F1} KB";
        if (bytes < 1024L * 1024 * 1024) return $"{bytes / (1024.0 * 1024):F1} MB";
        return $"{bytes / (1024.0 * 1024 * 1024):F2} GB";
    }
}

/// <summary>
/// 备份差异审计报告器 - 解密两次备份包并对比文件清单，生成变更审计与勒索软件行为检测。
/// <para>工作流程：解密备份 → 提取文件清单与哈希 → 对比变更 → 勒索模式分析 → 导出 CSV 审计报告。</para>
/// <para>勒索检测信号：单次备份大量文件被修改、多数被修改文件体积骤降、大量文件被重命名且扩展名改变。</para>
/// </summary>
public sealed class BackupAuditReporter
{
    /// <summary>单次备份中被修改文件数的可疑阈值（超过即视为大规模加密）。</summary>
    private const int RansomwareMassModifyThreshold = 100;

    /// <summary>被修改文件体积下降比例阈值（&gt;30% 视为异常）。</summary>
    private const double RansomwareSizeDecreaseRatio = 0.30;

    /// <summary>扩展名改变的重命名文件数可疑阈值。</summary>
    private const int RansomwareRenameThreshold = 20;

    private static readonly JsonSerializerOptions JsonOpts = new() { WriteIndented = false };

    /// <summary>
    /// 对比两次备份包，生成差异审计报告。
    /// <para>解密新旧备份、提取文件清单（优先使用清单 <c>Metadata["FileHashes"]</c> 中的完整哈希表，
    /// 再以解密归档补充文件大小），逐条比对生成变更记录，并自动执行勒索模式评估。</para>
    /// </summary>
    /// <param name="oldManifest">旧备份清单；为 null 表示首次备份（全部记为新增）。</param>
    /// <param name="newManifest">新备份清单。</param>
    /// <param name="oldBackupPath">旧备份包路径（oldManifest 非 null 时必须存在）。</param>
    /// <param name="newBackupPath">新备份包路径。</param>
    /// <param name="password">加密口令（用于派生解密密钥）。</param>
    /// <returns>差异审计报告。</returns>
    /// <exception cref="ArgumentNullException">newManifest/newBackupPath/password 为 null。</exception>
    /// <exception cref="FileNotFoundException">newBackupPath 不存在。</exception>
    public AuditReport CompareBackups(BackupManifest? oldManifest, BackupManifest newManifest,
        string oldBackupPath, string newBackupPath, string password)
    {
        ArgumentNullException.ThrowIfNull(newManifest);
        ArgumentException.ThrowIfNullOrWhiteSpace(newBackupPath, nameof(newBackupPath));
        ArgumentException.ThrowIfNullOrWhiteSpace(password, nameof(password));

        // 解密新备份（失败为致命错误，无法审计）
        var newMap = DecryptBackupToFileMap(newBackupPath, password);

        // 解密旧备份（失败非致命：记为空基线，全部记为新增）
        Dictionary<string, FileSnapshot> oldMap;
        if (oldManifest != null && File.Exists(oldBackupPath))
        {
            try
            {
                oldMap = DecryptBackupToFileMap(oldBackupPath, password);
            }
            catch (Exception ex)
            {
                ErrorReporter.Report(ex, $"旧备份解密失败，按空基线处理：{oldBackupPath}");
                oldMap = new Dictionary<string, FileSnapshot>(StringComparer.OrdinalIgnoreCase);
            }
        }
        else
        {
            oldMap = new Dictionary<string, FileSnapshot>(StringComparer.OrdinalIgnoreCase);
        }

        var report = new AuditReport
        {
            GeneratedAt = DateTime.Now,
            SourcePath = newManifest.SourcePath
        };

        var changes = new List<FileChangeRecord>();
        var sourceDir = newManifest.BackupType == BackupType.Directory && Directory.Exists(newManifest.SourcePath)
            ? newManifest.SourcePath
            : null;

        // 新快照中存在的文件：新增 / 修改 / 未变更
        foreach (var kv in newMap)
        {
            var rel = kv.Key;
            var snap = kv.Value;
            if (oldMap.TryGetValue(rel, out var oldSnap))
            {
                bool sameContent = !string.IsNullOrEmpty(snap.Hash)
                    && string.Equals(oldSnap.Hash, snap.Hash, StringComparison.OrdinalIgnoreCase);
                if (sameContent)
                {
                    changes.Add(new FileChangeRecord
                    {
                        FilePath = rel,
                        ChangeType = FileChangeType.Unchanged,
                        OldSize = NormalizeSize(oldSnap.Size),
                        NewSize = NormalizeSize(snap.Size),
                        OldHash = oldSnap.Hash,
                        NewHash = snap.Hash
                    });
                }
                else
                {
                    changes.Add(new FileChangeRecord
                    {
                        FilePath = rel,
                        ChangeType = FileChangeType.Modified,
                        OldSize = NormalizeSize(oldSnap.Size),
                        NewSize = NormalizeSize(snap.Size),
                        OldHash = string.IsNullOrEmpty(oldSnap.Hash) ? null : oldSnap.Hash,
                        NewHash = string.IsNullOrEmpty(snap.Hash) ? null : snap.Hash,
                        LastModified = TryGetLastModified(sourceDir, rel)
                    });
                }
            }
            else
            {
                changes.Add(new FileChangeRecord
                {
                    FilePath = rel,
                    ChangeType = FileChangeType.Added,
                    OldSize = 0,
                    NewSize = NormalizeSize(snap.Size),
                    OldHash = null,
                    NewHash = string.IsNullOrEmpty(snap.Hash) ? null : snap.Hash,
                    LastModified = TryGetLastModified(sourceDir, rel)
                });
            }
        }

        // 旧快照中存在、新快照中不存在的文件：删除
        foreach (var kv in oldMap)
        {
            if (!newMap.ContainsKey(kv.Key))
            {
                changes.Add(new FileChangeRecord
                {
                    FilePath = kv.Key,
                    ChangeType = FileChangeType.Deleted,
                    OldSize = NormalizeSize(kv.Value.Size),
                    NewSize = 0,
                    OldHash = string.IsNullOrEmpty(kv.Value.Hash) ? null : kv.Value.Hash,
                    NewHash = null
                });
            }
        }

        // 重命名检测：内容哈希相同的"删除+新增"对合并为 Renamed
        ReclassifyRenames(changes);

        // 汇总计数（从最终变更列表派生，自动排除 Renamed 重复计数）
        report.AddedCount = changes.Count(c => c.ChangeType == FileChangeType.Added);
        report.DeletedCount = changes.Count(c => c.ChangeType == FileChangeType.Deleted);
        report.ModifiedCount = changes.Count(c => c.ChangeType == FileChangeType.Modified);
        report.UnchangedCount = changes.Count(c => c.ChangeType == FileChangeType.Unchanged);
        report.AddedBytes = changes.Where(c => c.ChangeType == FileChangeType.Added).Sum(c => c.NewSize);
        report.DeletedBytes = changes.Where(c => c.ChangeType == FileChangeType.Deleted).Sum(c => c.OldSize);

        // 勒索模式评估，填充 IsRansomwareSuspect 与 RiskAssessment
        DetectRansomwarePattern(report);

        ErrorReporter.Log($"差异审计完成：源={report.SourcePath} | 新增 {report.AddedCount} 删除 {report.DeletedCount} " +
            $"修改 {report.ModifiedCount} 重命名 {report.RenamedCount} 未变 {report.UnchangedCount} | 勒索疑似={report.IsRansomwareSuspect}");
        return report;
    }

    /// <summary>
    /// 将审计报告导出为 CSV 文件。
    /// <para>列格式：「文件路径,变更类型,旧大小,新大小,旧哈希,新哈希,最后修改时间」，UTF-8(BOM) 编码以兼容 Excel。</para>
    /// </summary>
    /// <param name="report">审计报告。</param>
    /// <param name="outputPath">输出 CSV 路径。</param>
    /// <exception cref="ArgumentNullException">参数为 null。</exception>
    public void GenerateReport(AuditReport report, string outputPath)
    {
        ArgumentNullException.ThrowIfNull(report);
        ArgumentException.ThrowIfNullOrWhiteSpace(outputPath, nameof(outputPath));

        try
        {
            var dir = Path.GetDirectoryName(outputPath);
            if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);

            var sb = new StringBuilder();
            sb.AppendLine("文件路径,变更类型,旧大小,新大小,旧哈希,新哈希,最后修改时间");
            foreach (var c in report.Changes)
            {
                sb.AppendLine(string.Join(',',
                    CsvEscape(c.FilePath),
                    c.ChangeType.ToString(),
                    c.OldSize.ToString(),
                    c.NewSize.ToString(),
                    CsvEscape(c.OldHash ?? string.Empty),
                    CsvEscape(c.NewHash ?? string.Empty),
                    c.LastModified.HasValue ? c.LastModified.Value.ToString("yyyy-MM-dd HH:mm:ss") : string.Empty));
            }

            File.WriteAllText(outputPath, sb.ToString(), new UTF8Encoding(encoderShouldEmitUTF8Identifier: true));
            ErrorReporter.Log($"审计报告已导出 CSV：{outputPath}（{report.Changes.Count} 条记录）");
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, $"导出审计报告 CSV 失败：{outputPath}");
            throw;
        }
    }

    /// <summary>
    /// 分析变更记录是否匹配勒索软件行为模式，并据此设置 <see cref="AuditReport.IsRansomwareSuspect"/> 与 <see cref="AuditReport.RiskAssessment"/>。
    /// <para>检测信号：</para>
    /// <list type="bullet">
    /// <item>单次备份被修改文件数 &gt; 100（大规模加密）。</item>
    /// <item>多数被修改文件体积下降 &gt; 30%（加密改变体积）。</item>
    /// <item>扩展名改变的重命名文件数 &gt; 20（勒索扩展名追加）。</item>
    /// </list>
    /// </summary>
    /// <param name="report">待分析的审计报告（将被原地更新）。</param>
    /// <returns>是否疑似勒索软件攻击。</returns>
    public bool DetectRansomwarePattern(AuditReport report)
    {
        ArgumentNullException.ThrowIfNull(report);
        var reasons = new List<string>();

        var modified = report.Changes.Where(c => c.ChangeType == FileChangeType.Modified).ToList();
        var renamed = report.Changes.Where(c => c.ChangeType == FileChangeType.Renamed).ToList();

        // 信号 1：单次备份大量文件被修改
        if (modified.Count > RansomwareMassModifyThreshold)
        {
            reasons.Add($"单次备份中 {modified.Count} 个文件被修改（超过阈值 {RansomwareMassModifyThreshold}），疑似大规模加密行为");
        }

        // 信号 2：多数被修改文件体积下降 > 30%
        if (modified.Count > 0)
        {
            int sizeDecreasers = modified.Count(c =>
                c.OldSize > 0 && c.NewSize > 0 && c.NewSize < c.OldSize * (1 - RansomwareSizeDecreaseRatio));
            if (sizeDecreasers > modified.Count / 2)
            {
                reasons.Add($"{sizeDecreasers}/{modified.Count} 个被修改文件体积下降超过 {(int)(RansomwareSizeDecreaseRatio * 100)}%，疑似加密导致体积变化");
            }
        }

        // 信号 3：大量文件被重命名且扩展名改变
        int renamedWithExtChange = renamed.Count(c =>
            !string.IsNullOrEmpty(c.OldFilePath)
            && !string.Equals(Path.GetExtension(c.OldFilePath), Path.GetExtension(c.FilePath), StringComparison.OrdinalIgnoreCase));
        if (renamedWithExtChange > RansomwareRenameThreshold)
        {
            reasons.Add($"{renamedWithExtChange} 个文件被重命名且扩展名发生改变（超过阈值 {RansomwareRenameThreshold}），疑似勒索扩展名追加");
        }

        report.IsRansomwareSuspect = reasons.Count > 0;
        report.RiskAssessment = reasons.Count > 0
            ? "检测到 " + reasons.Count + " 项勒索软件特征：" + string.Join("；", reasons)
            : "未检测到勒索软件特征，变更模式正常";
        return report.IsRansomwareSuspect;
    }

    /// <summary>
    /// 返回审计报告的快速统计摘要（单行）。
    /// </summary>
    /// <param name="report">审计报告。</param>
    /// <returns>单行统计文本。</returns>
    public string GetQuickStats(AuditReport report)
    {
        ArgumentNullException.ThrowIfNull(report);
        var sb = new StringBuilder();
        sb.Append($"审计快照 @ {report.GeneratedAt:yyyy-MM-dd HH:mm:ss} | 源：{report.SourcePath}");
        sb.Append($" | 新增 {report.AddedCount}（+{AuditReport.FormatBytes(report.AddedBytes)}）");
        sb.Append($" | 删除 {report.DeletedCount}（-{AuditReport.FormatBytes(report.DeletedBytes)}）");
        sb.Append($" | 修改 {report.ModifiedCount}");
        sb.Append($" | 重命名 {report.RenamedCount}");
        sb.Append($" | 未变 {report.UnchangedCount}");
        sb.Append(report.IsRansomwareSuspect ? " | [疑似勒索]" : " | 风险正常");
        return sb.ToString();
    }

    #region 私有辅助

    /// <summary>
    /// 解密备份包并构建「相对路径 → 文件快照」映射。
    /// <para>优先采用清单 <c>Metadata["FileHashes"]</c> 中的完整哈希表（含增量备份中未变更文件），
    /// 再用解密归档数据补充文件大小（仅能覆盖归档中实际包含的文件）。</para>
    /// </summary>
    private Dictionary<string, FileSnapshot> DecryptBackupToFileMap(string backupPath, string password)
    {
        var (manifest, shards) = LgBackupFormat.ReadBackup(backupPath);
        var crypto = new BackupCryptoEngine(manifest.EncryptedAlgorithm);
        var salt = Convert.FromBase64String(manifest.Salt);
        var key = crypto.DeriveKey(password, salt);

        // 按分片序重组明文数据
        using var ms = new MemoryStream();
        foreach (var shard in shards.OrderBy(s => s.Index))
        {
            var plain = crypto.Decrypt(shard.Cipher, key, shard.Nonce, shard.Tag);
            ms.Write(plain, 0, plain.Length);
        }
        var data = ms.ToArray();

        return BuildFileMap(manifest, data);
    }

    /// <summary>
    /// 由清单与已解密的归档数据构建文件快照映射。
    /// </summary>
    private static Dictionary<string, FileSnapshot> BuildFileMap(BackupManifest manifest, byte[] decryptedData)
    {
        var map = new Dictionary<string, FileSnapshot>(StringComparer.OrdinalIgnoreCase);

        // 1. 优先载入清单记录的完整哈希表
        foreach (var kv in ParseFileHashes(manifest))
        {
            map[kv.Key] = new FileSnapshot { RelPath = kv.Key, Hash = kv.Value, Size = -1 };
        }

        // 2. 目录备份：从归档补充文件大小与缺失哈希
        if (manifest.BackupType == BackupType.Directory)
        {
            List<(string RelPath, byte[] Data)> entries;
            try
            {
                entries = BackupExecutor.ExtractDirectoryArchive(decryptedData);
            }
            catch (Exception ex)
            {
                ErrorReporter.Report(ex, $"解析目录归档失败：{manifest.SourcePath}");
                return map;
            }

            foreach (var (rel, fileData) in entries)
            {
                var key = rel.Replace('\\', '/');
                var hash = Convert.ToHexString(SHA256.HashData(fileData));
                if (map.TryGetValue(key, out var snap))
                {
                    snap.Size = fileData.Length;
                    if (string.IsNullOrEmpty(snap.Hash)) snap.Hash = hash;
                }
                else
                {
                    map[key] = new FileSnapshot { RelPath = key, Size = fileData.Length, Hash = hash };
                }
            }
        }
        else
        {
            // 非目录备份：作为单个不透明数据块处理
            var name = !string.IsNullOrWhiteSpace(manifest.SourcePath)
                ? Path.GetFileName(manifest.SourcePath)
                : manifest.BackupType.ToString();
            if (string.IsNullOrEmpty(name)) name = "data.bin";
            var blobHash = Convert.ToHexString(SHA256.HashData(decryptedData));

            if (map.Count == 0)
            {
                map[name] = new FileSnapshot { RelPath = name, Size = decryptedData.Length, Hash = blobHash };
            }
            else
            {
                foreach (var snap in map.Values)
                    if (snap.Size < 0) snap.Size = decryptedData.Length;
            }
        }

        return map;
    }

    /// <summary>
    /// 解析清单 <c>Metadata["FileHashes"]</c> 中的相对路径 → 哈希映射。
    /// </summary>
    private static Dictionary<string, string> ParseFileHashes(BackupManifest manifest)
    {
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (manifest.Metadata == null) return result;
        if (!manifest.Metadata.TryGetValue("FileHashes", out var json) || string.IsNullOrEmpty(json))
            return result;

        try
        {
            var dict = JsonSerializer.Deserialize<Dictionary<string, string>>(json, JsonOpts);
            if (dict != null)
            {
                foreach (var kv in dict)
                    result[kv.Key.Replace('\\', '/')] = kv.Value;
            }
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, "解析清单 FileHashes 失败");
        }
        return result;
    }

    /// <summary>
    /// 将内容哈希相同的"删除+新增"对重分类为 Renamed。
    /// </summary>
    private static void ReclassifyRenames(List<FileChangeRecord> changes)
    {
        var added = changes.Where(c => c.ChangeType == FileChangeType.Added).ToList();
        var deletedByHash = changes
            .Where(c => c.ChangeType == FileChangeType.Deleted && !string.IsNullOrEmpty(c.OldHash))
            .GroupBy(c => c.OldHash!, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => new List<FileChangeRecord>(g), StringComparer.OrdinalIgnoreCase);

        foreach (var a in added)
        {
            if (string.IsNullOrEmpty(a.NewHash)) continue;
            if (!deletedByHash.TryGetValue(a.NewHash!, out var pool) || pool.Count == 0) continue;

            var d = pool[0];
            pool.RemoveAt(0);

            // 重分类：Added -> Renamed，记录旧路径用于扩展名比对
            a.ChangeType = FileChangeType.Renamed;
            a.OldFilePath = d.FilePath;
            a.OldSize = d.OldSize;
            a.OldHash = d.OldHash;
            // FilePath / NewHash / NewSize 保持为重命名后的新文件

            changes.Remove(d);
        }
    }

    /// <summary>
    /// 规范化文件大小：未知（-1）统一为 0。
    /// </summary>
    private static long NormalizeSize(long size) => size < 0 ? 0 : size;

    /// <summary>
    /// 尽力获取源目录中某文件最后修改时间；不可访问时返回 null。
    /// </summary>
    private static DateTime? TryGetLastModified(string? sourceDir, string relPath)
    {
        if (string.IsNullOrEmpty(sourceDir)) return null;
        try
        {
            var full = Path.Combine(sourceDir, relPath.Replace('/', Path.DirectorySeparatorChar));
            return File.Exists(full) ? File.GetLastWriteTime(full) : null;
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// CSV 字段转义：含逗号、引号或换行时用双引号包裹并转义内部引号。
    /// </summary>
    private static string CsvEscape(string field)
    {
        if (field.Contains(',') || field.Contains('"') || field.Contains('\n') || field.Contains('\r'))
            return "\"" + field.Replace("\"", "\"\"") + "\"";
        return field;
    }

    /// <summary>
    /// 文件快照（内部用）：相对路径、大小、内容哈希。
    /// </summary>
    private sealed class FileSnapshot
    {
        public string RelPath { get; set; } = string.Empty;
        public long Size { get; set; } = -1;
        public string Hash { get; set; } = string.Empty;
    }

    #endregion
}
