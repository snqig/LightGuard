// © 2026 落尘（Luochen） 原创开发 - 保留所有权利
//
// 全局单套 Cron 定时备份调度线程（v3.5 P0-4 / P1-4）
//   - System.Threading.Timer 每分钟 tick（对齐需求"全局单套 Cron 定时线程"）
//   - 统一调度：文件定时全量 / 文件定时增量 / 每个数据库实例独立全量+增量 cron
//   - 任务防重入：文件任务锁 + 每个数据库实例独立锁，运行中定时触发直接跳过
//   - 授权联动：未授权状态即使配置开启也不执行
//   - SQLite 增量强制拦截（代码层）；数据库增量前置校验存在全量快照

using LightGuard.Core;
using LightGuard.Database;
using Timer = System.Threading.Timer;

namespace LightGuard.Backup;

/// <summary>
/// 备份定时调度结果（供日志/状态展示）。
/// </summary>
public sealed class BackupScheduleRunResult
{
    /// <summary>调度键（文件任务名 / db:实例名）。</summary>
    public string TaskKey { get; set; } = "";

    /// <summary>调度类型（Full / Incremental / DbFull / DbIncremental）。</summary>
    public string RunType { get; set; } = "";

    /// <summary>是否成功触发。</summary>
    public bool Triggered { get; set; }

    /// <summary>结果消息。</summary>
    public string Message { get; set; } = "";
}

/// <summary>
/// 全局 Cron 定时备份调度器。
/// <para>生命周期与 AppState 一致：Start() 启动、Stop()/Dispose() 停止。</para>
/// </summary>
public sealed class BackupCronScheduler : IDisposable
{
    /// <summary>调度 tick 间隔（分钟）。</summary>
    public const int TickIntervalMinutes = 1;

    private readonly AppState _appState;
    private readonly BackupReentryLock _lock;
    private Timer? _timer;
    private readonly object _sync = new();
    private volatile bool _stopped = true;
    private DateTime _lastTick;

    /// <summary>最近一次调度执行结果（供状态展示）。</summary>
    public IReadOnlyList<BackupScheduleRunResult> LastRuns { get; private set; } = Array.Empty<BackupScheduleRunResult>();

    /// <summary>
    /// 创建调度器。
    /// </summary>
    /// <param name="appState">全局应用状态（配置读取 + 模块执行）。</param>
    /// <param name="lock">任务防重入锁（可传入共享实例；默认新建）。</param>
    public BackupCronScheduler(AppState appState, BackupReentryLock? @lock = null)
    {
        _appState = appState ?? throw new ArgumentNullException(nameof(appState));
        _lock = @lock ?? new BackupReentryLock();
    }

    /// <summary>防重入锁（供外部 / 实时监控共享同一锁池）。</summary>
    public BackupReentryLock ReentryLock => _lock;

    /// <summary>启动调度线程（每分钟 tick）。</summary>
    public void Start()
    {
        lock (_sync)
        {
            if (!_stopped) return;
            _stopped = false;
            _timer = new Timer(OnTick, null, TimeSpan.FromSeconds(5), TimeSpan.FromMinutes(TickIntervalMinutes));
            ErrorReporter.Log("备份定时调度已启动（全局 Cron，每分钟检查）");
        }
    }

    /// <summary>停止调度线程。</summary>
    public void Stop()
    {
        lock (_sync)
        {
            if (_stopped) return;
            _stopped = true;
            _timer?.Dispose();
            _timer = null;
            ErrorReporter.Log("备份定时调度已停止");
        }
    }

    /// <summary>立即触发一次检查（手动/测试入口）。</summary>
    public void TriggerNow()
    {
        OnTick(null);
    }

    /// <summary>调度 tick：遍历文件任务与数据库实例，命中 cron 则执行。</summary>
    private void OnTick(object? state)
    {
        if (_stopped) return;
        var now = DateTime.Now;
        if (now - _lastTick < TimeSpan.FromSeconds(30)) return; // 防抖（手动触发）
        _lastTick = now;

        // 授权联动：未授权状态全部禁用
        if (!LicenseGuard.IsBackupEnabled())
        {
            ErrorReporter.Log("备份定时调度跳过：未授权状态，备份/定时/实时/数据库功能禁用");
            return;
        }

        var runs = new List<BackupScheduleRunResult>();
        try
        {
            var config = _appState.Config;

            // ---- 文件备份任务 ----
            foreach (var job in config.FileBackupJobs.Where(j => j.Enabled))
            {
                if (string.IsNullOrWhiteSpace(job.SourcePath)) continue;

                // 定时全量
                if (!string.IsNullOrWhiteSpace(job.FullCron))
                {
                    try
                    {
                        if (CronExpression.Parse(job.FullCron).IsDue(now, job.LastFullAt))
                        {
                            runs.Add(RunFileBackup(job, isFull: true));
                        }
                    }
                    catch (Exception ex)
                    {
                        ErrorReporter.Log($"文件任务 {job.Name} 全量 cron 无效：{job.FullCron}（{ex.Message}）");
                    }
                }

                // 定时增量
                if (!string.IsNullOrWhiteSpace(job.IncrementalCron))
                {
                    try
                    {
                        if (CronExpression.Parse(job.IncrementalCron).IsDue(now, job.LastIncrementalAt))
                        {
                            runs.Add(RunFileBackup(job, isFull: false));
                        }
                    }
                    catch (Exception ex)
                    {
                        ErrorReporter.Log($"文件任务 {job.Name} 增量 cron 无效：{job.IncrementalCron}（{ex.Message}）");
                    }
                }
            }

            // ---- 数据库备份实例（每实例独立 cron）----
            foreach (var inst in config.DbBackupInstances.Where(i => i.Enabled))
            {
                // 定时全量
                if (!string.IsNullOrWhiteSpace(inst.FullCron))
                {
                    try
                    {
                        if (CronExpression.Parse(inst.FullCron).IsDue(now, inst.LastFullAt))
                        {
                            runs.Add(RunDbFullBackup(inst));
                        }
                    }
                    catch (Exception ex)
                    {
                        ErrorReporter.Log($"数据库实例 {inst.Name} 全量 cron 无效：{inst.FullCron}（{ex.Message}）");
                    }
                }

                // 定时增量（SQLite 强制禁用，代码层拦截）
                if (!string.IsNullOrWhiteSpace(inst.IncrementalCron) && DbIncrementalBackupEngine.IsIncrementalSupported(inst.DbType))
                {
                    try
                    {
                        if (CronExpression.Parse(inst.IncrementalCron).IsDue(now, inst.LastIncrementalAt))
                        {
                            runs.Add(RunDbIncrementalBackup(inst));
                        }
                    }
                    catch (Exception ex)
                    {
                        ErrorReporter.Log($"数据库实例 {inst.Name} 增量 cron 无效：{inst.IncrementalCron}（{ex.Message}）");
                    }
                }
                else if (!string.IsNullOrWhiteSpace(inst.IncrementalCron)
                         && !DbIncrementalBackupEngine.IsIncrementalSupported(inst.DbType))
                {
                    ErrorReporter.Log($"数据库实例 {inst.Name}（{inst.DbType}）不支持增量备份，定时增量已强制忽略");
                }
            }
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, "备份定时调度 tick 异常");
        }

        LastRuns = runs;
    }

    /// <summary>解析备份口令：优先运行时凭据（HKDF 派生），回退默认口令。</summary>
    private string ResolveBackupPassword(string? credentialRef)
    {
        // 运行时凭据（dbconfig/UI 输入，不落盘）：credentialRef → 派生密钥 hex
        var password = BackupCredentialStore.Get(credentialRef);
        return password ?? BackupCredentialStore.DefaultPassword;
    }

    /// <summary>执行文件任务备份（全量或增量）并挂接快照链。</summary>
    private BackupScheduleRunResult RunFileBackup(FileBackupJob job, bool isFull)
    {
        var taskKey = job.ScheduleKey;
        var result = new BackupScheduleRunResult
        {
            TaskKey = taskKey,
            RunType = isFull ? "FileFull" : "FileIncremental"
        };

        // 防重入：任务运行中直接跳过
        if (!_lock.TryEnter(taskKey))
        {
            result.Triggered = false;
            result.Message = "任务正在运行，本次定时触发跳过（防重入）";
            ErrorReporter.Log($"[文件定时] {job.Name}：{result.Message}");
            return result;
        }

        try
        {
            var password = ResolveBackupPassword(job.PasswordRef);
            var chainDir = string.IsNullOrWhiteSpace(job.ChainDir)
                ? Path.Combine(ConfigManager.GetBackupDir(), "jobs", SanitizeName(job.Name))
                : job.ChainDir;
            Directory.CreateDirectory(chainDir);

            var chainMgr = new SnapshotChainManager(_appState);
            var chainId = job.ChainId;

            // 全量：无链则建链；执行全量备份后作为全量根节点入链
            if (isFull)
            {
                if (string.IsNullOrEmpty(chainId))
                {
                    chainId = chainMgr.CreateChain(job.SourcePath, chainDir).ChainId;
                    job.ChainId = chainId;
                }

                var executor = new BackupExecutor(_appState);
                BackupManifest? manifest;
                if (job.IsSingleFile)
                {
                    if (!File.Exists(job.SourcePath))
                        throw new FileNotFoundException("待备份文件不存在：" + job.SourcePath);
                    manifest = executor.BackupSingleFile(job.SourcePath, password, chainDir);
                }
                else
                {
                    manifest = executor.BackupDirectory(job.SourcePath, password, chainDir);
                }

                chainMgr.AddSnapshot(chainId, chainDir, manifest, SnapshotType.Weekly, $"定时全量 {DateTime.Now:yyyy-MM-dd HH:mm}");
                job.LastFullAt = DateTime.Now;
                job.RealtimeCount = 0; // 全量截断增量链计数
            }
            else
            {
                // 增量：需要存在基础全量（快照链根），否则告警跳过
                var chain = LoadChainSafe(chainMgr, chainId, chainDir);
                var root = chain?.Nodes.FirstOrDefault(n => string.IsNullOrEmpty(n.ParentNodeId));
                if (chain == null || root == null)
                {
                    result.Triggered = false;
                    result.Message = "无全量基础快照，增量备份跳过（请先执行一次定时/手动全量）";
                    ErrorReporter.Log($"[文件定时] {job.Name}：{result.Message}");
                    return result;
                }

                var basePath = Path.Combine(chainDir, root.BackupFileName);
                var deltaName = $"delta_{DateTime.Now:yyyyMMdd_HHmmss}{LgBackupFormat.Extension}";
                var deltaPath = Path.Combine(chainDir, deltaName);

                var options = new BackupArchiveOptions
                {
                    SourcePath = job.SourcePath,
                    ChunkSize = 64 * 1024,
                    CompressionLevel = 6,
                    EncryptFileNames = true
                };

                if (job.IsSingleFile)
                {
                    // 单文件增量：以文件内容为变更集
                    var data = File.ReadAllBytes(job.SourcePath);
                    var changed = new Dictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase)
                    {
                        [Path.GetFileName(job.SourcePath)] = data
                    };
                    var incResult = BlockIncrementalService.CreateIncrementalAsync(
                        basePath, password, deltaPath, password, changed, options).GetAwaiter().GetResult();
                    AddIncrementalSnapshot(chainMgr, chainId, chainDir, incResult.DeltaPath, password);
                }
                else
                {
                    var incResult = BlockIncrementalService.CreateIncrementalFromDirectoryAsync(
                        job.SourcePath, basePath, password, deltaPath, password, options,
                        lastUsn: BlockIncrementalService.TryReadUsnEnd(basePath, password)).GetAwaiter().GetResult();
                    AddIncrementalSnapshot(chainMgr, chainId, chainDir, incResult.DeltaPath, password);
                }

                job.LastIncrementalAt = DateTime.Now;
            }

            // 快照链保留策略清理
            ApplyRetention(chainMgr, chainId, chainDir, job);

            // 持久化任务状态
            ConfigManager.Save(_appState.Config);

            result.Triggered = true;
            result.Message = isFull ? "定时全量备份完成" : "定时增量备份完成";
            ErrorReporter.Log($"[文件定时] {job.Name}：{result.Message}");
            return result;
        }
        catch (Exception ex)
        {
            result.Triggered = false;
            result.Message = $"备份失败：{ex.Message}";
            ErrorReporter.Report(ex, $"文件定时备份失败：{job.Name}（{job.SourcePath}）");
            return result;
        }
        finally
        {
            _lock.Exit(taskKey);
        }
    }

    /// <summary>将增量包作为快照节点入链（链根不存在时回退：无法入链仅记录）。</summary>
    private static void AddIncrementalSnapshot(SnapshotChainManager chainMgr, string chainId, string chainDir, string deltaPath, string password)
    {
        try
        {
            var (manifest, _, _) = LgBackupFormat.ReadManifestOnly(deltaPath);
            chainMgr.AddSnapshot(chainId, chainDir, manifest, SnapshotType.Hourly, $"定时增量 {DateTime.Now:yyyy-MM-dd HH:mm}");
        }
        catch (Exception ex)
        {
            ErrorReporter.Log($"增量包入链失败（{deltaPath}）：{ex.Message}");
        }
    }

    /// <summary>安全加载快照链（不存在/损坏返回 null）。</summary>
    private static SnapshotChain? LoadChainSafe(SnapshotChainManager chainMgr, string chainId, string chainDir)
    {
        if (string.IsNullOrEmpty(chainId)) return null;
        try { return chainMgr.GetChain(chainId, chainDir); }
        catch { return null; }
    }

    /// <summary>应用快照保留策略清理。</summary>
    private static void ApplyRetention(SnapshotChainManager chainMgr, string chainId, string chainDir, FileBackupJob job)
    {
        if (string.IsNullOrEmpty(chainId)) return;
        try
        {
            chainMgr.CleanupOldSnapshots(chainId, chainDir,
                job.Retention.Hourly, job.Retention.Daily, job.Retention.Weekly);
        }
        catch (Exception ex)
        {
            ErrorReporter.Log($"快照保留策略清理失败：{ex.Message}");
        }
    }

    /// <summary>执行数据库实例全量备份。</summary>
    private BackupScheduleRunResult RunDbFullBackup(DbBackupInstance inst)
    {
        var taskKey = inst.ScheduleKey;
        var result = new BackupScheduleRunResult { TaskKey = taskKey, RunType = "DbFull" };

        if (!_lock.TryEnter(taskKey))
        {
            result.Triggered = false;
            result.Message = "任务正在运行，本次定时触发跳过（防重入）";
            ErrorReporter.Log($"[数据库定时] {inst.Name}：{result.Message}");
            return result;
        }

        try
        {
            var connStr = DatabaseConnectionHelper.BuildConnectionString(
                inst.DbType, inst.Host, inst.Port, inst.Database, inst.User,
                BackupCredentialStore.Get(inst.CredentialRef) ?? "");

            var destDir = Path.Combine(ConfigManager.GetBackupDir(), "databases", SanitizeName(inst.Name));
            Directory.CreateDirectory(destDir);

            var engine = new DatabaseBackupEngine();
            var dbResult = engine.BackupDatabase(inst.DbType, connStr, destDir);

            if (dbResult.Success)
            {
                // 记录最近全量快照（增量前置校验依据：记录备份时间戳标识）
                inst.FullSnapshotNodeId = $"full_{dbResult.BackupPath}";
                inst.LastFullAt = DateTime.Now;
                inst.LastBinlogPos = DbIncrementalBackupEngine.GetCurrentPosition(inst, connStr);
                CleanupOldDbBackups(destDir, inst.MaxBackupCount);
                ConfigManager.Save(_appState.Config);

                result.Triggered = true;
                result.Message = $"数据库全量备份完成：{dbResult.Message}";
            }
            else
            {
                result.Triggered = false;
                result.Message = $"数据库全量备份失败：{dbResult.Message}";
            }
            ErrorReporter.Log($"[数据库定时] {inst.Name}：{result.Message}");
            return result;
        }
        catch (Exception ex)
        {
            result.Triggered = false;
            result.Message = $"全量备份异常：{ex.Message}";
            ErrorReporter.Report(ex, $"数据库定时全量备份失败：{inst.Name}");
            return result;
        }
        finally
        {
            _lock.Exit(taskKey);
        }
    }

    /// <summary>执行数据库实例增量备份（binlog/WAL，SQLite 已被上层拦截）。</summary>
    private BackupScheduleRunResult RunDbIncrementalBackup(DbBackupInstance inst)
    {
        var taskKey = inst.ScheduleKey;
        var result = new BackupScheduleRunResult { TaskKey = taskKey, RunType = "DbIncremental" };

        if (!_lock.TryEnter(taskKey))
        {
            result.Triggered = false;
            result.Message = "任务正在运行，本次定时触发跳过（防重入）";
            ErrorReporter.Log($"[数据库定时] {inst.Name}：{result.Message}");
            return result;
        }

        try
        {
            // 增量前置校验：必须存在最近全量快照
            if (string.IsNullOrEmpty(inst.FullSnapshotNodeId))
            {
                result.Triggered = false;
                result.Message = "无全量快照，增量备份跳过（请先执行一次全量备份）";
                ErrorReporter.Log($"[数据库定时] {inst.Name}：{result.Message}");
                return result;
            }

            var connStr = DatabaseConnectionHelper.BuildConnectionString(
                inst.DbType, inst.Host, inst.Port, inst.Database, inst.User,
                BackupCredentialStore.Get(inst.CredentialRef) ?? "");

            var destDir = Path.Combine(ConfigManager.GetBackupDir(), "databases", SanitizeName(inst.Name));
            Directory.CreateDirectory(destDir);

            var engine = new DbIncrementalBackupEngine();
            var incResult = engine.BackupIncremental(inst, connStr, destDir);

            if (incResult.Success)
            {
                inst.LastIncrementalAt = DateTime.Now;
                inst.LastBinlogPos = incResult.NewPosition;
                ConfigManager.Save(_appState.Config);

                result.Triggered = true;
                result.Message = $"数据库增量备份完成：{incResult.Message}";
            }
            else
            {
                result.Triggered = false;
                result.Message = $"数据库增量备份失败：{incResult.Message}";
            }
            ErrorReporter.Log($"[数据库定时] {inst.Name}：{result.Message}");
            return result;
        }
        catch (Exception ex)
        {
            result.Triggered = false;
            result.Message = $"增量备份异常：{ex.Message}";
            ErrorReporter.Report(ex, $"数据库定时增量备份失败：{inst.Name}");
            return result;
        }
        finally
        {
            _lock.Exit(taskKey);
        }
    }

    /// <summary>清理过期数据库备份（按数量保留）。</summary>
    private static void CleanupOldDbBackups(string dir, int maxCount)
    {
        try
        {
            if (maxCount <= 0 || !Directory.Exists(dir)) return;
            var files = Directory.EnumerateFiles(dir, "*.enc")
                .Select(f => new FileInfo(f))
                .OrderByDescending(f => f.CreationTime)
                .ToList();
            foreach (var file in files.Skip(maxCount))
            {
                try { file.Delete(); } catch { }
            }
        }
        catch { }
    }

    /// <summary>文件名安全化（去除非法字符）。</summary>
    private static string SanitizeName(string name)
    {
        var invalid = Path.GetInvalidFileNameChars();
        var sb = new System.Text.StringBuilder(name.Length);
        foreach (var c in name)
            sb.Append(invalid.Contains(c) ? '_' : c);
        return sb.Length == 0 ? "task" : sb.ToString();
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        Stop();
    }
}
