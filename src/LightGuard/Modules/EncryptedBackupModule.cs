// © 2026 落尘（Luochen） 原创开发 - 保留所有权利

using System.IO;
using LightGuard.Core;
using LightGuard.Core.Interfaces;

// 通过命名空间别名引用新增的 Backup 命名空间类型，
// 避免与同程序集 LightGuard.Modules 中既有同名类型（BackupManifest/BackupProgress）产生歧义。
using LgBackup = LightGuard.Backup;

// 显式别名为线程池定时器，避免与 WinForms 的 System.Windows.Forms.Timer 冲突。
using Timer = System.Threading.Timer;

namespace LightGuard.Modules;

/// <summary>
/// 加密抗勒索备份模块（EncryptedBackupModule）- 替换原 BackupModule。
/// <para>持有 <see cref="LgBackup.BackupExecutor"/> 与 <see cref="LgBackup.BackupLifecycle"/> 实例。</para>
/// <para>启用后启动生命周期定时清理；支持 .lgbackup 私有加密格式、AES-256-GCM/ChaCha20 自动切换、5 层粒度备份。</para>
/// </summary>
public sealed class EncryptedBackupModule : ModuleBase
{
    private LgBackup.BackupExecutor? _executor;
    private LgBackup.BackupLifecycle? _lifecycle;
    private Timer? _cleanupTimer;
    private readonly string _destDir;

    /// <summary>
    /// 初始化加密备份模块。
    /// </summary>
    /// <param name="appState">全局应用状态。</param>
    public EncryptedBackupModule(AppState appState) : base(appState)
    {
        _destDir = Path.Combine(ConfigManager.GetDataDir(), "encrypted_backups");
        try { Directory.CreateDirectory(_destDir); } catch { }
    }

    /// <inheritdoc/>
    public override string Id => "encrypted-backup";

    /// <inheritdoc/>
    public override string DisplayName => "加密抗勒索备份";

    /// <inheritdoc/>
    public override string Description =>
        ".lgbackup 私有加密抗勒索备份：AES-256-GCM/ChaCha20 自动切换、PBKDF2 密钥派生、5 层粒度（文件/目录/分区/整盘/数据库）、增量备份、SMB 容灾、生命周期自动清理。";

    /// <inheritdoc/>
    public override ModuleCategory Category => ModuleCategory.Backup;

    /// <summary>备份用户自身数据不需要管理员权限（分区/整盘备份在执行时按需提权）。</summary>
    public override bool RequiresAdmin => false;

    /// <summary>
    /// 获取备份执行引擎实例（初始化后可用）。
    /// </summary>
    public LgBackup.BackupExecutor? Executor => _executor;

    /// <summary>
    /// 获取备份生命周期管理器实例（初始化后可用）。
    /// </summary>
    public LgBackup.BackupLifecycle? Lifecycle => _lifecycle;

    /// <summary>
    /// 获取默认备份目标目录。
    /// </summary>
    public string DestinationDirectory => _destDir;

    /// <inheritdoc/>
    protected override Task OnInitializeAsync()
    {
        _executor = new LgBackup.BackupExecutor(AppState);
        _lifecycle = new LgBackup.BackupLifecycle(_destDir);
        ErrorReporter.Log("加密抗勒索备份模块初始化完成");
        return Task.CompletedTask;
    }

    /// <inheritdoc/>
    protected override Task OnEnableAsync()
    {
        _cleanupTimer?.Dispose();
        // 每 24 小时执行一次生命周期清理，首次延迟 6 小时
        _cleanupTimer = new Timer(OnCleanupTick, null, TimeSpan.FromHours(6), TimeSpan.FromHours(24));
        ErrorReporter.Log("加密抗勒索备份模块已启用，生命周期定时清理已启动");
        return Task.CompletedTask;
    }

    /// <inheritdoc/>
    protected override Task OnDisableAsync()
    {
        _cleanupTimer?.Dispose();
        _cleanupTimer = null;
        ErrorReporter.Log("加密抗勒索备份模块已禁用");
        return Task.CompletedTask;
    }

    /// <inheritdoc/>
    protected override void OnReleaseResources()
    {
        _cleanupTimer?.Dispose();
        _cleanupTimer = null;
        _executor = null;
        _lifecycle = null;
    }

    /// <inheritdoc/>
    protected override string GetStatusSummary()
    {
        if (!IsEnabled) return "已禁用";
        try
        {
            var history = _lifecycle?.GetBackupHistory(_destDir);
            if (history == null || history.Count == 0)
                return "运行中 | 暂无备份";

            var last = history[0];
            var locked = history.Count(h => h.IsLocked);
            return $"运行中 | 共 {history.Count} 个备份 | 最近：{last.BackupTime:yyyy-MM-dd HH:mm} | 算法：{last.EncryptedAlgorithm} | 锁定：{locked}";
        }
        catch
        {
            return "运行中";
        }
    }

    private void OnCleanupTick(object? state)
    {
        try
        {
            // 保留最新 5 套全量 + 30 天内增量，并清理超过 90 天的备份
            _lifecycle?.CleanupByRetention(_destDir, 5, 30);
            _lifecycle?.CleanupByAge(_destDir, 90);
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, "加密备份自动清理任务失败");
        }
    }
}
