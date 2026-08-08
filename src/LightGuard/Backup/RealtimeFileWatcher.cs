// © 2026 落尘（Luochen） 原创开发 - 保留所有权利
//
// 实时文件监控增量备份服务（v3.5 P0-5）
//   - 基于 FileSystemWatcher（Win32 ReadDirectoryChangesW 封装）
//   - 事件防抖：watchDebounceMs 窗口内合并事件 → 触发一次块级增量快照
//   - 单文件任务监控父目录 + 文件名过滤；目录任务递归监控
//   - 实时增量计数达到阈值自动合并为新全量（截断过长增量链）
//   - 授权联动：未授权不启动监控

using LightGuard.Core;

namespace LightGuard.Backup;

/// <summary>
/// 实时监控增量备份服务：监听源路径文件改动，防抖后触发块级增量快照。
/// </summary>
public sealed class RealtimeFileWatcher : IDisposable
{
    private readonly AppState _appState;
    private readonly FileBackupJob _job;
    private readonly BackupReentryLock _lock;
    private FileSystemWatcher? _watcher;
    private readonly object _sync = new();
    private readonly System.Threading.Timer _debounceTimer;
    private volatile bool _debounceArmed;
    private DateTime _lastDebounceTrigger;

    /// <summary>实时监控是否正在运行。</summary>
    public bool IsRunning => _watcher != null;

    /// <summary>实时增量累计触发次数（本次运行内）。</summary>
    public int RealtimeTriggerCount { get; private set; }

    /// <summary>
    /// 创建实时监控服务。
    /// </summary>
    /// <param name="appState">全局应用状态。</param>
    /// <param name="job">文件备份任务（RealtimeWatch 需为 true）。</param>
    /// <param name="lock">防重入锁（与定时调度共享同一锁池）。</param>
    public RealtimeFileWatcher(AppState appState, FileBackupJob job, BackupReentryLock @lock)
    {
        _appState = appState;
        _job = job;
        _lock = @lock;
        _debounceTimer = new System.Threading.Timer(OnDebounceElapsed, null, Timeout.Infinite, Timeout.Infinite);
    }

    /// <summary>
    /// 启动监控（授权联动：未授权不启动）。
    /// </summary>
    /// <returns>是否成功启动。</returns>
    public bool Start()
    {
        lock (_sync)
        {
            // 授权联动：未授权状态不启动实时监控
            if (!LicenseGuard.IsBackupEnabled())
            {
                ErrorReporter.Log($"[实时监控] {_job.Name} 未启动：未授权状态，实时备份禁用");
                return false;
            }
            if (_watcher != null) return true;

            var path = _job.SourcePath;
            var watchDir = _job.IsSingleFile ? Path.GetDirectoryName(path) : path;
            if (string.IsNullOrEmpty(watchDir) || !Directory.Exists(watchDir))
            {
                ErrorReporter.Log($"[实时监控] {_job.Name} 监控目录不存在：{watchDir}");
                return false;
            }

            _watcher = new FileSystemWatcher(watchDir)
            {
                IncludeSubdirectories = !_job.IsSingleFile,
                NotifyFilter = NotifyFilters.FileName
                            | NotifyFilters.LastWrite
                            | NotifyFilters.Size
                            | NotifyFilters.CreationTime
            };
            if (_job.IsSingleFile)
            {
                _watcher.Filter = Path.GetFileName(path);
            }

            _watcher.Changed += OnFileEvent;
            _watcher.Created += OnFileEvent;
            _watcher.Renamed += OnFileEvent;
            _watcher.Deleted += OnFileEvent;
            _watcher.EnableRaisingEvents = true;

            ErrorReporter.Log($"[实时监控] {_job.Name} 已启动，监控 {watchDir}（防抖 {_job.WatchDebounceMs}ms）");
            return true;
        }
    }

    /// <summary>停止监控。</summary>
    public void Stop()
    {
        lock (_sync)
        {
            if (_watcher == null) return;
            _watcher.EnableRaisingEvents = false;
            _watcher.Changed -= OnFileEvent;
            _watcher.Created -= OnFileEvent;
            _watcher.Renamed -= OnFileEvent;
            _watcher.Deleted -= OnFileEvent;
            _watcher.Dispose();
            _watcher = null;
            ErrorReporter.Log($"[实时监控] {_job.Name} 已停止");
        }
    }

    /// <summary>文件事件 → 防抖合并。</summary>
    private void OnFileEvent(object sender, FileSystemEventArgs e)
    {
        lock (_sync)
        {
            if (_watcher == null) return; // 已停止
            if (!_debounceArmed)
            {
                _debounceArmed = true;
                var ms = Math.Max(500, _job.WatchDebounceMs);
                _debounceTimer.Change(ms, Timeout.Infinite);
            }
        }
    }

    /// <summary>防抖窗口结束 → 触发一次块级增量快照。</summary>
    private void OnDebounceElapsed(object? state)
    {
        _debounceArmed = false;
        _lastDebounceTrigger = DateTime.Now;

        // 授权联动：未授权不执行实时增量
        if (!LicenseGuard.IsBackupEnabled())
        {
            ErrorReporter.Log($"[实时监控] {_job.Name} 跳过：未授权状态，实时备份禁用");
            return;
        }

        _ = Task.Run(() => RunRealtimeIncremental());
    }

    /// <summary>执行一次实时块级增量快照（与定时增量共用快照链）。</summary>
    private void RunRealtimeIncremental()
    {
        var taskKey = _job.ScheduleKey;
        if (!_lock.TryEnter(taskKey))
        {
            ErrorReporter.Log($"[实时监控] {_job.Name}：任务正在运行，本次实时触发跳过（防重入）");
            return;
        }

        try
        {
            var password = BackupCredentialStore.Get(_job.PasswordRef) ?? BackupCredentialStore.DefaultPassword;
            var chainDir = string.IsNullOrWhiteSpace(_job.ChainDir)
                ? Path.Combine(ConfigManager.GetBackupDir(), "jobs", SanitizeName(_job.Name))
                : _job.ChainDir;
            Directory.CreateDirectory(chainDir);

            var chainMgr = new SnapshotChainManager(_appState);
            var chainId = _job.ChainId;

            var chain = LoadChainSafe(chainMgr, chainId, chainDir);
            var root = chain?.Nodes.FirstOrDefault(n => string.IsNullOrEmpty(n.ParentNodeId));
            if (chain == null || root == null)
            {
                ErrorReporter.Log($"[实时监控] {_job.Name}：无全量基础快照，实时增量跳过（请先执行一次全量备份）");
                return;
            }

            var basePath = Path.Combine(chainDir, root.BackupFileName);
            var deltaName = $"rt_{DateTime.Now:yyyyMMdd_HHmmss}{LgBackupFormat.Extension}";
            var deltaPath = Path.Combine(chainDir, deltaName);

            var options = new BackupArchiveOptions
            {
                SourcePath = _job.SourcePath,
                ChunkSize = 64 * 1024,
                CompressionLevel = 6,
                EncryptFileNames = true
            };

            BlockIncrementalResult? incResult;
            if (_job.IsSingleFile)
            {
                var data = File.Exists(_job.SourcePath) ? File.ReadAllBytes(_job.SourcePath) : Array.Empty<byte>();
                var changed = new Dictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase)
                {
                    [Path.GetFileName(_job.SourcePath)] = data
                };
                incResult = BlockIncrementalService.CreateIncrementalAsync(
                    basePath, password, deltaPath, password, changed, options).GetAwaiter().GetResult();
            }
            else
            {
                incResult = BlockIncrementalService.CreateIncrementalFromDirectoryAsync(
                    _job.SourcePath, basePath, password, deltaPath, password, options,
                    lastUsn: BlockIncrementalService.TryReadUsnEnd(basePath, password)).GetAwaiter().GetResult();
            }

            // 增量包入链
            try
            {
                var (manifest, _, _) = LgBackupFormat.ReadManifestOnly(deltaPath);
                chainMgr.AddSnapshot(chainId, chainDir, manifest, SnapshotType.Hourly, $"实时增量 {DateTime.Now:yyyy-MM-dd HH:mm}");
            }
            catch (Exception ex)
            {
                ErrorReporter.Log($"[实时监控] 增量包入链失败：{ex.Message}");
            }

            _job.LastRealtimeAt = DateTime.Now;
            _job.RealtimeCount++;
            RealtimeTriggerCount++;
            ConfigManager.Save(_appState.Config);

            // 实时增量计数达到阈值 → 合并为新全量（截断过长增量链）
            if (_job.RealtimeCount >= Math.Max(2, _job.MaxRealtimeBeforeMerge))
            {
                ErrorReporter.Log($"[实时监控] {_job.Name} 实时增量已达 {_job.RealtimeCount} 次，自动合并为新全量快照");
                chainMgr.MergeSnapshots(chainId, chainDir, password);
                _job.RealtimeCount = 0;
                ConfigManager.Save(_appState.Config);
            }

            ErrorReporter.Log($"[实时监控] {_job.Name}：实时增量完成（新增 {incResult.NewBlocks} 块 / {incResult.NewBytes}B，复用 {incResult.ReusedBytes}B）");
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, $"实时监控增量备份失败：{_job.Name}");
        }
        finally
        {
            _lock.Exit(taskKey);
        }
    }

    /// <summary>安全加载快照链（不存在/损坏返回 null）。</summary>
    private static SnapshotChain? LoadChainSafe(SnapshotChainManager chainMgr, string chainId, string chainDir)
    {
        if (string.IsNullOrEmpty(chainId)) return null;
        try { return chainMgr.GetChain(chainId, chainDir); }
        catch { return null; }
    }

    /// <summary>文件名安全化。</summary>
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
        _debounceTimer.Dispose();
    }
}
