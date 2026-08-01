// © 2026 落尘（Luochen） 原创开发 - 保留所有权利

using System.IO;
using System.Linq;
using LightGuard.Core;

namespace LightGuard.Backup;

/// <summary>
/// 备份生命周期管理 - 按保留份数 / 年龄自动清理，核心备份锁定保护，全程日志审计。
/// <para>清理时自动跳过 <see cref="BackupManifest.IsLocked"/> = true 的备份，防止误删核心备份。</para>
/// </summary>
public sealed class BackupLifecycle
{
    private readonly string? _defaultDestDir;

    /// <summary>
    /// 初始化生命周期管理器。
    /// </summary>
    /// <param name="defaultDestDir">默认目标目录（供 <see cref="LockBackup"/> / <see cref="UnlockBackup"/> 使用）。</param>
    public BackupLifecycle(string? defaultDestDir = null)
    {
        _defaultDestDir = defaultDestDir;
    }

    /// <summary>
    /// 按保留份数清理：保留最新 N 套全量备份 + M 天内的增量备份。
    /// </summary>
    /// <param name="destDir">目标目录。</param>
    /// <param name="maxFullBackups">最大保留全量备份数。</param>
    /// <param name="maxIncrementalDays">增量备份保留天数。</param>
    /// <returns>释放空间（字节）。</returns>
    public long CleanupByRetention(string destDir, int maxFullBackups, int maxIncrementalDays)
    {
        long freed = 0;
        try
        {
            var items = LoadHistoryWithPaths(destDir);
            if (items.Count == 0) return 0;

            var now = DateTime.Now;

            // 全量备份：按时间倒序保留前 N 个（跳过锁定）
            var fulls = items
                .Where(x => !IsIncremental(x.Manifest))
                .OrderByDescending(x => x.Manifest.BackupTime)
                .ToList();
            foreach (var item in fulls.Skip(Math.Max(0, maxFullBackups)))
            {
                freed += DeleteIfNotLocked(item);
            }

            // 增量备份：删除超过 M 天的（跳过锁定）
            var incrementals = items.Where(x => IsIncremental(x.Manifest)).ToList();
            foreach (var item in incrementals)
            {
                if (now - item.Manifest.BackupTime > TimeSpan.FromDays(maxIncrementalDays))
                {
                    freed += DeleteIfNotLocked(item);
                }
            }

            ErrorReporter.Log($"按保留份数清理完成：释放 {freed / 1024.0:F1} KB，目录 {destDir}");
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, $"按保留份数清理失败：{destDir}");
        }
        return freed;
    }

    /// <summary>
    /// 按年龄清理：删除超过指定天数的备份（跳过锁定）。
    /// </summary>
    /// <param name="destDir">目标目录。</param>
    /// <param name="maxAgeDays">最大保留天数。</param>
    /// <returns>释放空间（字节）。</returns>
    public long CleanupByAge(string destDir, int maxAgeDays)
    {
        long freed = 0;
        try
        {
            var items = LoadHistoryWithPaths(destDir);
            if (items.Count == 0) return 0;

            var now = DateTime.Now;
            foreach (var item in items)
            {
                if (now - item.Manifest.BackupTime > TimeSpan.FromDays(maxAgeDays))
                {
                    freed += DeleteIfNotLocked(item);
                }
            }
            ErrorReporter.Log($"按年龄清理完成（{maxAgeDays} 天）：释放 {freed / 1024.0:F1} KB，目录 {destDir}");
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, $"按年龄清理失败：{destDir}");
        }
        return freed;
    }

    /// <summary>
    /// 锁定核心备份（防止生命周期清理删除）。使用构造时指定的默认目录。
    /// </summary>
    /// <param name="backupId">备份唯一标识。</param>
    /// <returns>成功返回 true。</returns>
    public bool LockBackup(Guid backupId) => SetLock(backupId, true);

    /// <summary>
    /// 解锁核心备份。
    /// </summary>
    /// <param name="backupId">备份唯一标识。</param>
    /// <returns>成功返回 true。</returns>
    public bool UnlockBackup(Guid backupId) => SetLock(backupId, false);

    /// <summary>
    /// 获取备份历史（按时间倒序）。
    /// </summary>
    /// <param name="destDir">目标目录。</param>
    /// <returns>备份清单列表。</returns>
    public List<BackupManifest> GetBackupHistory(string destDir)
        => LoadHistoryWithPaths(destDir).Select(x => x.Manifest).ToList();

    #region 私有

    private bool SetLock(Guid backupId, bool locked)
    {
        if (string.IsNullOrEmpty(_defaultDestDir))
            throw new InvalidOperationException("未配置默认目标目录，无法定位备份。");

        try
        {
            foreach (var file in EnumerateBackupFiles(_defaultDestDir))
            {
                var (manifest, shards) = LgBackupFormat.ReadBackup(file);
                if (manifest.BackupId == backupId)
                {
                    if (manifest.IsLocked == locked) return true;
                    manifest.IsLocked = locked;
                    var tmp = file + ".tmp";
                    LgBackupFormat.WriteBackup(tmp, manifest, shards);
                    File.Delete(file);
                    File.Move(tmp, file);
                    ErrorReporter.Log($"备份 {backupId} 锁定状态已设为 {locked}：{file}");
                    return true;
                }
            }
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, $"设置备份锁定状态失败：{backupId}");
        }
        return false;
    }

    private long DeleteIfNotLocked((string Path, BackupManifest Manifest) item)
    {
        if (item.Manifest.IsLocked)
        {
            ErrorReporter.Log($"跳过已锁定的核心备份：{Path.GetFileName(item.Path)}（{item.Manifest.BackupId}）");
            return 0;
        }

        try
        {
            var size = new FileInfo(item.Path).Length;
            File.Delete(item.Path);
            ErrorReporter.Log($"已删除过期备份：{Path.GetFileName(item.Path)}（{item.Manifest.BackupId}），释放 {size / 1024.0:F1} KB");
            return size;
        }
        catch (Exception ex)
        {
            ErrorReporter.Log($"删除备份失败 {item.Path}：{ex.Message}");
            return 0;
        }
    }

    private static bool IsIncremental(BackupManifest manifest)
        => manifest.Metadata != null
           && manifest.Metadata.TryGetValue("Strategy", out var s)
           && string.Equals(s, "Incremental", StringComparison.OrdinalIgnoreCase);

    private List<(string Path, BackupManifest Manifest)> LoadHistoryWithPaths(string destDir)
    {
        var list = new List<(string Path, BackupManifest Manifest)>();
        foreach (var file in EnumerateBackupFiles(destDir))
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

    private static IEnumerable<string> EnumerateBackupFiles(string destDir)
    {
        if (string.IsNullOrEmpty(destDir) || !Directory.Exists(destDir))
            return Array.Empty<string>();
        return Directory.EnumerateFiles(destDir, "*" + LgBackupFormat.Extension);
    }

    #endregion
}
