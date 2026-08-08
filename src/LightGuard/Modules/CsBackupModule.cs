// © 2026 落尘（Luochen） 原创开发 - 保留所有权利
//
// C/S 备份模块（v3.6）
//   - 根据 AppConfig.ClientServer.WorkMode 切换备份执行路径：
//     local / smb → 原有本地/SMB 备份（完全保留）
//     client_server → C/S 自定义 TCP 备份（文件分块增量 + 数据库流分片上传）
//   - 提供文件备份 / 数据库备份 / 快照恢复 / 快照列表 / 清理 的统一门面
//   - 授权联动：未授权状态 C/S 备份禁用

using LightGuard.Backup;
using LightGuard.ClientServer;
using LightGuard.Core;
using LightGuard.Core.Interfaces;
using LightGuard.Database;
using LightGuard.Shared;

namespace LightGuard.Modules;

/// <summary>
/// Client-Server 备份模块（v3.6）。
/// <para>保留原有本地/SMB 备份模式不变；WorkMode=ClientServer 时走 C/S 网络备份。</para>
/// </summary>
public sealed class CsBackupModule : ModuleBase
{
    private CsBackupService? _service;
    private readonly object _sync = new();

    /// <summary>当前 C/S 服务实例（未激活时为 null）。</summary>
    public CsBackupService? Service => _service;

    /// <summary>是否处于 C/S 模式。</summary>
    public bool IsClientServerMode => AppState.Config.ClientServer.WorkMode == BackupWorkMode.ClientServer;

    public CsBackupModule(AppState appState) : base(appState)
    {
    }

    /// <inheritdoc/>
    public override string Id => "cs-backup";

    /// <inheritdoc/>
    public override string DisplayName => "C/S 备份";

    /// <inheritdoc/>
    public override string Description =>
        "Client-Server 自定义 TCP 备份：客户端本地分块+SHA256+AES-256-GCM 加密，仅上传缺失块，支持断线重连/断点续传/快照恢复；保留本地/SMB 模式";

    /// <inheritdoc/>
    public override ModuleCategory Category => ModuleCategory.Backup;

    /// <summary>C/S 备份不强制管理员权限。</summary>
    public override bool RequiresAdmin => false;

    /// <inheritdoc/>
    protected override Task OnInitializeAsync() => Task.CompletedTask;

    /// <inheritdoc/>
    protected override Task OnEnableAsync()
    {
        LicenseGuard.SetConfigProvider(() => AppState.Config.License);
        ErrorReporter.Log($"C/S 备份模块已启用（工作模式：{AppState.Config.ClientServer.WorkMode}）");
        return Task.CompletedTask;
    }

    /// <inheritdoc/>
    protected override Task OnDisableAsync()
    {
        lock (_sync)
        {
            _service?.Dispose();
            _service = null;
        }
        return Task.CompletedTask;
    }

    /// <inheritdoc/>
    protected override void OnReleaseResources()
    {
        lock (_sync)
        {
            _service?.Dispose();
            _service = null;
        }
    }

    /// <inheritdoc/>
    protected override string GetStatusSummary()
    {
        if (!IsEnabled) return "已禁用";
        var cfg = AppState.Config.ClientServer;
        return cfg.WorkMode == BackupWorkMode.ClientServer
            ? $"C/S 模式 | 服务端 {cfg.ServerHost}:{cfg.ServerPort}"
            : "本地/SMB 模式（C/S 未启用）";
    }

    /// <summary>获取或创建 C/S 服务实例（懒加载）。</summary>
    private CsBackupService GetService()
    {
        lock (_sync)
        {
            if (_service != null) return _service;
            var cfg = AppState.Config.ClientServer;
            // 备份口令：优先运行时凭据，回退默认
            var password = BackupCredentialStore.Get("cs_backup")
                           ?? BackupCredentialStore.DefaultPassword;
            _service = new CsBackupService(cfg, password);
            return _service;
        }
    }

    /// <summary>校验 C/S 配置完整性。</summary>
    private string? ValidateConfig()
    {
        var cfg = AppState.Config.ClientServer;
        if (string.IsNullOrWhiteSpace(cfg.ServerHost))
            return "未配置服务端地址（ClientServer.ServerHost）";
        if (cfg.ServerPort <= 0 || cfg.ServerPort > 65535)
            return $"端口无效：{cfg.ServerPort}";
        return null;
    }

    // ==================== 文件备份 ====================

    /// <summary>
    /// 按工作模式执行文件/目录备份。
    /// <para>local/smb → 原有 BackupExecutor 全量备份；client_server → C/S 块级增量备份。</para>
    /// </summary>
    /// <returns>(是否走 C/S, C/S 结果或 null)。</returns>
    public async Task<(bool UsedCs, CsBackupResult? CsResult)> BackupFileAsync(
        string sourcePath, string? snapshotName = null, Action<CsBackupProgress>? progress = null,
        CancellationToken ct = default)
    {
        var cfg = AppState.Config.ClientServer;
        if (cfg.WorkMode != BackupWorkMode.ClientServer)
            return (false, null); // 走原有本地/SMB 逻辑

        // 授权联动：未授权禁用 C/S 备份
        if (!LicenseGuard.IsBackupEnabled())
            return (true, new CsBackupResult { Success = false, Message = "未授权状态，C/S 备份禁用" });

        var configError = ValidateConfig();
        if (configError != null)
            return (true, new CsBackupResult { Success = false, Message = configError });

        var name = snapshotName ?? $"File_{DateTime.Now:yyyyMMdd_HHmmss}";
        var service = GetService();
        var result = await service.BackupAsync(sourcePath, name, progress, ct).ConfigureAwait(false);
        return (true, result);
    }

    /// <summary>手动触发一次 C/S 备份（供 UI/定时调度调用）。</summary>
    public async Task<CsBackupResult> BackupNowAsync(string sourcePath, CancellationToken ct = default)
    {
        var (usedCs, result) = await BackupFileAsync(sourcePath, null, null, ct).ConfigureAwait(false);
        return usedCs && result != null ? result : new CsBackupResult
        {
            Success = false,
            Message = "当前非 C/S 模式，请切换到 client_server 工作模式"
        };
    }

    // ==================== 数据库备份 ====================

    /// <summary>
    /// 数据库备份 C/S 流程：客户端本地 dump → 加密流分片上传（不落地明文临时文件）。
    /// <para>dump 明文流由调用方提供（本地执行 mysqldump/pg_dump/sqlite 复制）。</para>
    /// </summary>
    public async Task<CsBackupResult> BackupDatabaseAsync(
        DatabaseType dbType, string dbName, Stream dumpPlainStream,
        CancellationToken ct = default)
    {
        var cfg = AppState.Config.ClientServer;
        if (cfg.WorkMode != BackupWorkMode.ClientServer)
            return new CsBackupResult { Success = false, Message = "当前非 C/S 模式" };

        if (!LicenseGuard.IsBackupEnabled())
            return new CsBackupResult { Success = false, Message = "未授权状态，C/S 数据库备份禁用" };

        var configError = ValidateConfig();
        if (configError != null)
            return new CsBackupResult { Success = false, Message = configError };

        var name = $"Db_{dbType}_{DateTime.Now:yyyyMMdd_HHmmss}";
        var service = GetService();
        return await service.BackupDatabaseStreamAsync(dbType.ToString(), dbName, dumpPlainStream, name, null, ct).ConfigureAwait(false);
    }

    // ==================== 恢复 ====================

    /// <summary>列出服务端快照（供恢复选择）。</summary>
    public async Task<List<CsSnapshotSummary>> ListSnapshotsAsync(CancellationToken ct = default)
    {
        if (!LicenseGuard.IsBackupEnabled()) return new List<CsSnapshotSummary>();
        var service = GetService();
        var connect = await service.ConnectAsync(ct).ConfigureAwait(false);
        return connect.Success ? await service.ListSnapshotsAsync(ct).ConfigureAwait(false) : new List<CsSnapshotSummary>();
    }

    /// <summary>从快照恢复到目标目录。</summary>
    public async Task<CsBackupResult> RestoreAsync(string snapshotId, string destDir, Action<CsBackupProgress>? progress = null, CancellationToken ct = default)
    {
        if (!LicenseGuard.IsBackupEnabled())
            return new CsBackupResult { Success = false, Message = "未授权状态，C/S 恢复禁用" };
        var service = GetService();
        return await service.RestoreAsync(snapshotId, destDir, progress, ct).ConfigureAwait(false);
    }

    /// <summary>触发服务端快照回收清理。</summary>
    public async Task<CsSnapshotCleanupResult> CleanupAsync(CancellationToken ct = default)
    {
        var service = GetService();
        var connect = await service.ConnectAsync(ct).ConfigureAwait(false);
        if (!connect.Success)
            return new CsSnapshotCleanupResult { Ok = false, Message = connect.Message };
        return await service.CleanupAsync(AppState.Config.ClientServer.MaxSnapshotsPerClient, ct).ConfigureAwait(false);
    }

    /// <inheritdoc/>
    public override void Dispose()
    {
        lock (_sync)
        {
            _service?.Dispose();
            _service = null;
        }
        base.Dispose();
    }
}
