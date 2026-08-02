// © 2026 落尘（Luochen） 原创开发 - 保留所有权利

using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using LightGuard.Core;

namespace LightGuard.Backup;

/// <summary>
/// 备份健康检查级别 - 表示对备份包执行健康验证时所达到的最深层级。
/// </summary>
public enum HealthCheckLevel
{
    /// <summary>基础结构级：校验文件存在性、文件头魔数、清单 JSON 可解析。</summary>
    Structure,

    /// <summary>分片完整性级：在基础结构级之上，校验分片数量与清单一致、全部分片可读。</summary>
    Integrity,

    /// <summary>深度级：在分片完整性级之上，使用密钥解密全部分片并校验全局 SHA256 哈希。</summary>
    Deep
}

/// <summary>
/// 单个备份包的健康验证报告。
/// <para>记录验证时间、文件大小、分片数、MD5 防篡改指纹以及逐项检查明细。</para>
/// </summary>
public sealed class HealthReport
{
    /// <summary>备份文件路径。</summary>
    public string BackupPath { get; set; } = string.Empty;

    /// <summary>是否健康（全部校验通过）。</summary>
    public bool IsHealthy { get; set; }

    /// <summary>本次验证所达到的最深检查级别。</summary>
    public HealthCheckLevel CheckLevel { get; set; }

    /// <summary>失败原因（健康时为 null）。</summary>
    public string? ErrorMessage { get; set; }

    /// <summary>验证时间（本地时间）。</summary>
    public DateTime VerifiedAt { get; set; }

    /// <summary>备份文件大小（字节）。</summary>
    public long FileSize { get; set; }

    /// <summary>分片数量。</summary>
    public int ShardCount { get; set; }

    /// <summary>整包 MD5 哈希（大写十六进制），用于防篡改指纹比对。</summary>
    public string Md5Hash { get; set; } = string.Empty;

    /// <summary>逐项检查明细（每项形如「[通过]/[失败] 检查名：描述」）。</summary>
    public List<string> CheckDetails { get; set; } = new();
}

/// <summary>
/// 批量备份健康报告 - 汇总一个目录下全部备份包的验证结果。
/// </summary>
public sealed class BatchHealthReport
{
    /// <summary>备份总数。</summary>
    public int TotalBackups { get; set; }

    /// <summary>健康备份数。</summary>
    public int HealthyCount { get; set; }

    /// <summary>损坏备份数。</summary>
    public int CorruptedCount { get; set; }

    /// <summary>各备份的详细报告列表。</summary>
    public List<HealthReport> Reports { get; set; } = new();

    /// <summary>报告生成时间（本地时间）。</summary>
    public DateTime GeneratedAt { get; set; }

    /// <summary>
    /// 返回人类可读的汇总摘要。
    /// <para>示例：「备份健康报告：共 10 个备份，健康 9 个，损坏 1 个。损坏文件：xxx.lgbackup（原因：分片结构不完整）」</para>
    /// </summary>
    /// <returns>汇总摘要文本。</returns>
    public string ToSummary()
    {
        var sb = new StringBuilder();
        sb.Append($"备份健康报告：共 {TotalBackups} 个备份，健康 {HealthyCount} 个，损坏 {CorruptedCount} 个。");

        var corrupted = Reports.Where(r => !r.IsHealthy).ToList();
        if (corrupted.Count > 0)
        {
            sb.Append("损坏文件：");
            sb.Append(string.Join("；", corrupted.Select(r =>
                $"{Path.GetFileName(r.BackupPath)}（原因：{r.ErrorMessage ?? "未知错误"}）")));
        }

        return sb.ToString();
    }
}

/// <summary>
/// 备份健康验证器 - 备份创建后自动执行多级完整性校验，损坏时支持自动重新备份。
/// <para>校验顺序：文件存在性 → 魔数 → 清单解析 → 分片数量 → 结构完整性 → 全局哈希（需密钥）→ MD5 指纹。</para>
/// <para>结合 <see cref="LgBackupFormat"/>、<see cref="BackupCryptoEngine"/>、<see cref="BackupShardEngine"/> 与 <see cref="BackupExecutor"/> 完成端到端健康保障。</para>
/// </summary>
public sealed class BackupHealthVerifier
{
    private readonly AppState? _appState;

    /// <summary>
    /// 初始化备份健康验证器。
    /// </summary>
    /// <param name="appState">全局应用状态（用于自动重新备份时创建 <see cref="BackupExecutor"/>）；为 null 时回退到 <see cref="AppState.Instance"/>。</param>
    public BackupHealthVerifier(AppState? appState = null)
    {
        _appState = appState;
    }

    /// <summary>
    /// 对单个备份包执行完整健康校验（不含解密，达到 <see cref="HealthCheckLevel.Integrity"/> 级别）。
    /// </summary>
    /// <param name="backupPath">备份包路径。</param>
    /// <returns>健康报告。</returns>
    public HealthReport VerifyBackup(string backupPath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(backupPath, nameof(backupPath));
        return RunVerification(backupPath, key: null);
    }

    /// <summary>
    /// 对单个备份包执行深度健康校验（使用密钥解密全部分片并校验全局 SHA256 哈希，达到 <see cref="HealthCheckLevel.Deep"/> 级别）。
    /// </summary>
    /// <param name="backupPath">备份包路径。</param>
    /// <param name="key">32 字节解密密钥。</param>
    /// <returns>健康报告。</returns>
    public HealthReport VerifyBackupWithKey(string backupPath, byte[] key)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(backupPath, nameof(backupPath));
        ArgumentNullException.ThrowIfNull(key);
        return RunVerification(backupPath, key);
    }

    /// <summary>
    /// 批量校验目标目录下全部 .lgbackup 备份包。
    /// </summary>
    /// <param name="destDir">备份目标目录。</param>
    /// <returns>批量健康报告。</returns>
    public BatchHealthReport VerifyAllBackups(string destDir)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(destDir, nameof(destDir));

        var batch = new BatchHealthReport { GeneratedAt = DateTime.Now };
        var reports = new List<HealthReport>();

        foreach (var file in EnumerateBackupFiles(destDir))
        {
            reports.Add(VerifyBackup(file));
        }

        batch.Reports = reports;
        batch.TotalBackups = reports.Count;
        batch.HealthyCount = reports.Count(r => r.IsHealthy);
        batch.CorruptedCount = reports.Count - batch.HealthyCount;

        ErrorReporter.Log($"批量健康校验完成：目录 {destDir}，共 {batch.TotalBackups} 个，健康 {batch.HealthyCount} 个，损坏 {batch.CorruptedCount} 个");
        return batch;
    }

    /// <summary>
    /// 若备份损坏则自动重新备份，并返回最终健康报告。
    /// <para>损坏时通过 <see cref="BackupExecutor"/> 重新执行备份（单文件或目录），全程记录日志。</para>
    /// </summary>
    /// <param name="backupPath">待检测的备份包路径。</param>
    /// <param name="sourcePath">原始源路径（文件或目录）。</param>
    /// <param name="password">加密口令。</param>
    /// <param name="destDir">重新备份的目标目录。</param>
    /// <returns>原始备份健康时返回其报告；损坏且重新备份成功时返回新备份的健康报告；否则返回原始报告（含失败明细）。</returns>
    public HealthReport AutoRebackupIfNeeded(string backupPath, string sourcePath, string password, string destDir)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(backupPath, nameof(backupPath));
        ArgumentException.ThrowIfNullOrWhiteSpace(sourcePath, nameof(sourcePath));
        ArgumentException.ThrowIfNullOrWhiteSpace(password, nameof(password));
        ArgumentException.ThrowIfNullOrWhiteSpace(destDir, nameof(destDir));

        var report = VerifyBackup(backupPath);

        if (report.IsHealthy)
        {
            ErrorReporter.Log($"备份健康校验通过，无需重新备份：{backupPath}");
            return report;
        }

        ErrorReporter.Log($"检测到备份损坏，启动自动重新备份：{backupPath}（原因：{report.ErrorMessage}）", "WARN");

        try
        {
            var appState = _appState ?? AppState.Instance;
            var executor = new BackupExecutor(appState);

            BackupManifest newManifest;
            if (File.Exists(sourcePath))
            {
                newManifest = executor.BackupSingleFile(sourcePath, password, destDir);
            }
            else if (Directory.Exists(sourcePath))
            {
                newManifest = executor.BackupDirectory(sourcePath, password, destDir);
            }
            else
            {
                ErrorReporter.Log($"自动重新备份失败：源路径不存在 {sourcePath}", "ERROR");
                report.CheckDetails.Add($"[失败] 自动重新备份：源路径不存在 {sourcePath}");
                return report;
            }

            var newPath = FindBackupPathById(destDir, newManifest.BackupId);
            if (string.IsNullOrEmpty(newPath))
            {
                ErrorReporter.Log("自动重新备份完成，但无法定位新生成的备份文件", "ERROR");
                report.CheckDetails.Add("[失败] 自动重新备份：无法定位新生成的备份文件");
                return report;
            }

            ErrorReporter.Log($"自动重新备份成功：{sourcePath} -> {newPath}");

            var newReport = VerifyBackup(newPath);
            newReport.CheckDetails.Insert(0,
                $"[信息] 自动重新备份：原备份 {Path.GetFileName(backupPath)} 已损坏（{report.ErrorMessage}），已重新生成 {Path.GetFileName(newPath)}");
            return newReport;
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, $"自动重新备份异常：{backupPath} <- {sourcePath}");
            report.CheckDetails.Add($"[失败] 自动重新备份异常：{ex.Message}");
            return report;
        }
    }

    /// <summary>
    /// 生成目标目录下全部备份的人类可读健康摘要。
    /// </summary>
    /// <param name="destDir">备份目标目录。</param>
    /// <returns>汇总摘要文本（见 <see cref="BatchHealthReport.ToSummary"/>）。</returns>
    public string GenerateHealthReport(string destDir)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(destDir, nameof(destDir));
        return VerifyAllBackups(destDir).ToSummary();
    }

    /// <summary>
    /// 执行多级健康校验核心流程（按 a→g 顺序逐项检查）。
    /// <para>a.文件存在性与大小 b.魔数 c.清单可解析 d.分片数量 e.结构完整性 f.全局哈希（需密钥）g.MD5 指纹</para>
    /// </summary>
    /// <param name="backupPath">备份包路径。</param>
    /// <param name="key">解密密钥；为 null 时跳过深度校验。</param>
    /// <returns>健康报告。</returns>
    private HealthReport RunVerification(string backupPath, byte[]? key)
    {
        var details = new List<string>();
        var report = new HealthReport
        {
            BackupPath = backupPath,
            VerifiedAt = DateTime.Now,
            CheckLevel = HealthCheckLevel.Structure
        };

        // (a) 文件存在性与大小检查
        if (!File.Exists(backupPath))
        {
            details.Add("[失败] 文件存在性检查：备份文件不存在");
            return FinalizeReport(report, details, false, "备份文件不存在");
        }
        var fi = new FileInfo(backupPath);
        report.FileSize = fi.Length;
        if (fi.Length <= 0)
        {
            details.Add("[失败] 文件大小检查：文件大小为 0 字节");
            return FinalizeReport(report, details, false, "备份文件大小为 0 字节");
        }
        details.Add($"[通过] 文件存在性检查：文件存在，{fi.Length} 字节");

        // (b) 魔数检查（LgBackupFormat.Magic）
        try
        {
            if (!VerifyMagic(backupPath))
            {
                report.Md5Hash = ComputeMd5(backupPath);
                details.Add("[失败] 魔数检查：文件头与 LGBACKUP 魔数不匹配");
                details.Add($"[信息] MD5 防篡改指纹：{report.Md5Hash}");
                return FinalizeReport(report, details, false, "魔数不匹配，非有效 LightGuard 备份或已被篡改");
            }
            details.Add("[通过] 魔数检查：LGBACKUP\\x01 匹配");
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, $"备份魔数读取失败：{backupPath}");
            report.Md5Hash = ComputeMd5(backupPath);
            details.Add($"[失败] 魔数检查：{ex.Message}");
            details.Add($"[信息] MD5 防篡改指纹：{report.Md5Hash}");
            return FinalizeReport(report, details, false, "魔数读取失败：" + ex.Message);
        }

        // (c) 清单 JSON 可解析（LgBackupFormat.ReadManifestOnly）
        BackupManifest manifest;
        int actualShardCount;
        try
        {
            (manifest, actualShardCount, _) = LgBackupFormat.ReadManifestOnly(backupPath);
            details.Add("[通过] 清单解析检查：备份清单 JSON 可解析");
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, $"备份清单解析失败：{backupPath}");
            report.Md5Hash = ComputeMd5(backupPath);
            details.Add($"[失败] 清单解析检查：{ex.Message}");
            details.Add($"[信息] MD5 防篡改指纹：{report.Md5Hash}");
            return FinalizeReport(report, details, false, "备份清单 JSON 解析失败");
        }

        report.CheckLevel = HealthCheckLevel.Integrity; // 进入分片级校验

        // (d) 分片数量与清单匹配
        if (actualShardCount != manifest.ShardCount)
        {
            report.ShardCount = actualShardCount;
            report.Md5Hash = ComputeMd5(backupPath);
            details.Add($"[失败] 分片数量检查：实际 {actualShardCount} 个，清单声明 {manifest.ShardCount} 个");
            details.Add($"[信息] MD5 防篡改指纹：{report.Md5Hash}");
            return FinalizeReport(report, details, false, $"分片数量不匹配（实际 {actualShardCount}，清单 {manifest.ShardCount}）");
        }
        report.ShardCount = actualShardCount;
        details.Add($"[通过] 分片数量检查：{actualShardCount} 个分片与清单一致");

        // (e) 结构完整性（全分片可读，LgBackupFormat.VerifyBackup）
        if (!LgBackupFormat.VerifyBackup(backupPath))
        {
            report.Md5Hash = ComputeMd5(backupPath);
            details.Add("[失败] 结构完整性检查：分片结构不可读或不完整（详见错误日志）");
            details.Add($"[信息] MD5 防篡改指纹：{report.Md5Hash}");
            return FinalizeReport(report, details, false, "分片结构不完整");
        }
        details.Add($"[通过] 结构完整性检查：全部 {report.ShardCount} 个分片可读");

        // (f) 全局哈希校验（深度级，仅当提供密钥时执行：解密 + SHA256 比对）
        if (key is not null)
        {
            report.CheckLevel = HealthCheckLevel.Deep;
            try
            {
                var (deepManifest, shards) = LgBackupFormat.ReadBackup(backupPath);
                var crypto = new BackupCryptoEngine(deepManifest.EncryptedAlgorithm);
                var plainShards = new List<BackupShard>(shards.Count);

                for (int i = 0; i < shards.Count; i++)
                {
                    var s = shards[i];
                    // GCM/Poly1305 认证标签校验（标签不匹配将抛出 AuthenticationTagMismatchException）
                    var plain = crypto.Decrypt(s.Cipher, key, s.Nonce, s.Tag);

                    // 分片级 SHA256 校验（直接使用 System.Security.Cryptography.SHA256）
                    var plainHash = SHA256.HashData(plain);
                    if (!plainHash.SequenceEqual(s.PlainHash))
                        throw new InvalidDataException($"分片 {s.Index} 明文 SHA256 与记录值不匹配，数据可能已被篡改。");

                    plainShards.Add(new BackupShard { Index = s.Index, Data = plain, Length = plain.Length });
                }
                details.Add("[通过] GCM 解密校验：全部分片认证标签与明文哈希校验通过");

                // 全局哈希校验（BackupShardEngine.ComputeGlobalHash，内部使用 SHA256）
                var globalHashHex = Convert.ToHexString(BackupShardEngine.ComputeGlobalHash(plainShards));
                if (string.Equals(globalHashHex, deepManifest.GlobalHash, StringComparison.OrdinalIgnoreCase))
                {
                    details.Add("[通过] 全局哈希校验：解密后 SHA256 与清单一致");
                }
                else
                {
                    report.Md5Hash = ComputeMd5(backupPath);
                    details.Add($"[失败] 全局哈希校验：计算值 {globalHashHex} 与清单 {deepManifest.GlobalHash} 不一致");
                    details.Add($"[信息] MD5 防篡改指纹：{report.Md5Hash}");
                    return FinalizeReport(report, details, false, "全局 SHA256 哈希不匹配，数据可能已被篡改");
                }
            }
            catch (Exception ex)
            {
                ErrorReporter.Report(ex, $"备份深度解密校验失败：{backupPath}");
                report.Md5Hash = ComputeMd5(backupPath);
                details.Add($"[失败] 深度解密校验：{ex.Message}");
                details.Add($"[信息] MD5 防篡改指纹：{report.Md5Hash}");
                return FinalizeReport(report, details, false, "深度解密校验失败");
            }
        }

        // (g) MD5 防篡改指纹（整包 MD5，用于篡改检测）
        report.Md5Hash = ComputeMd5(backupPath);
        details.Add($"[通过] MD5 防篡改指纹：{report.Md5Hash}");

        return FinalizeReport(report, details, true, null);
    }

    /// <summary>
    /// 校验文件头魔数是否与 <see cref="LgBackupFormat.Magic"/> 一致。
    /// </summary>
    /// <param name="path">备份包路径。</param>
    /// <returns>魔数匹配返回 true。</returns>
    private static bool VerifyMagic(string path)
    {
        using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        var buffer = new byte[LgBackupFormat.Magic.Length];
        int read = fs.Read(buffer, 0, buffer.Length);
        if (read != LgBackupFormat.Magic.Length) return false;
        return buffer.SequenceEqual(LgBackupFormat.Magic);
    }

    /// <summary>
    /// 计算整包 MD5 哈希（大写十六进制）。
    /// </summary>
    /// <param name="path">备份包路径。</param>
    /// <returns>MD5 十六进制字符串。</returns>
    private static string ComputeMd5(string path)
    {
        using var stream = File.OpenRead(path);
        return Convert.ToHexString(MD5.HashData(stream));
    }

    /// <summary>
    /// 在目标目录中按备份唯一标识定位备份文件路径。
    /// </summary>
    /// <param name="destDir">备份目标目录。</param>
    /// <param name="backupId">备份唯一标识。</param>
    /// <returns>匹配的备份文件路径；未找到返回 null。</returns>
    private static string? FindBackupPathById(string destDir, Guid backupId)
    {
        foreach (var file in Directory.EnumerateFiles(destDir, "*" + LgBackupFormat.Extension))
        {
            try
            {
                var (manifest, _, _) = LgBackupFormat.ReadManifestOnly(file);
                if (manifest.BackupId == backupId) return file;
            }
            catch
            {
                // 跳过无法解析清单的残留文件
            }
        }
        return null;
    }

    /// <summary>
    /// 枚举目标目录下全部 .lgbackup 文件。
    /// </summary>
    /// <param name="destDir">备份目标目录。</param>
    /// <returns>备份文件路径集合。</returns>
    private static IEnumerable<string> EnumerateBackupFiles(string destDir)
    {
        if (string.IsNullOrEmpty(destDir) || !Directory.Exists(destDir))
        {
            ErrorReporter.Log($"批量校验目录不存在或为空：{destDir}", "WARN");
            return Array.Empty<string>();
        }
        return Directory.EnumerateFiles(destDir, "*" + LgBackupFormat.Extension);
    }

    /// <summary>
    /// 填充并返回健康报告，同时记录验证结果日志。
    /// </summary>
    /// <param name="report">待填充的健康报告。</param>
    /// <param name="details">逐项检查明细。</param>
    /// <param name="healthy">是否健康。</param>
    /// <param name="errorMessage">失败原因。</param>
    /// <returns>已填充的健康报告。</returns>
    private static HealthReport FinalizeReport(HealthReport report, List<string> details, bool healthy, string? errorMessage)
    {
        report.IsHealthy = healthy;
        report.ErrorMessage = errorMessage;
        report.CheckDetails = details;

        if (healthy)
            ErrorReporter.Log($"备份健康校验通过[{report.CheckLevel}]：{report.BackupPath}");
        else
            ErrorReporter.Log($"备份健康校验未通过[{report.CheckLevel}]：{report.BackupPath} - {errorMessage ?? "未知原因"}", "WARN");

        return report;
    }
}
