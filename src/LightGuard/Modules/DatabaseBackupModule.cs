// © 2026 落尘（Luochen） 原创开发 - 保留所有权利

using System.Text.Json;
using LightGuard.Core;
using LightGuard.Core.Interfaces;
using LightGuard.Database;

// 项目启用 WinForms（System.Windows.Forms.Timer）会与 System.Threading.Timer 冲突，
// 此处显式别名为线程池定时器，用于定时备份调度。
using Timer = System.Threading.Timer;

namespace LightGuard.Modules;

/// <summary>
/// 数据库冷热备份模块
/// <para>支持 SQLite / MySQL / MariaDB / SqlServer / Access 五种数据库的定时加密备份，</para>
/// <para>所有备份包使用 AES-256-GCM 加密，支持热备份（业务无需停机）。</para>
/// </summary>
public sealed class DatabaseBackupModule : ModuleBase
{
    #region 字段

    private readonly DatabaseBackupEngine _engine;
    private readonly string _configPath;
    private readonly string _backupDir;
    private Timer? _scheduleTimer;
    private DateTime _lastScheduleRun;
    private DatabaseBackupConfig _config = new();

    /// <summary>调度检查间隔（分钟）</summary>
    private const int ScheduleCheckMinutes = 30;

    #endregion

    #region 构造与模块信息

    /// <summary>
    /// 创建数据库备份模块实例
    /// </summary>
    /// <param name="appState">全局应用状态</param>
    public DatabaseBackupModule(AppState appState) : base(appState)
    {
        _engine = new DatabaseBackupEngine();
        _backupDir = Path.Combine(ConfigManager.GetBackupDir(), "databases");
        _configPath = Path.Combine(ConfigManager.GetDataDir(), "dbbackup_config.json");
    }

    /// <inheritdoc/>
    public override string Id => "database-backup";

    /// <inheritdoc/>
    public override string DisplayName => "数据库冷热备份";

    /// <inheritdoc/>
    public override string Description =>
        "支持 SQLite/MySQL/MariaDB/SqlServer/Access 五种数据库的定时加密备份，AES-256-GCM 加密，热备份无需停机，完整性校验与自动修复";

    /// <inheritdoc/>
    public override ModuleCategory Category => ModuleCategory.DatabaseBackup;

    /// <inheritdoc/>
    public override bool RequiresAdmin => true;

    #endregion

    #region 生命周期

    /// <inheritdoc/>
    protected override Task OnInitializeAsync()
    {
        _config = LoadConfig();
        Directory.CreateDirectory(_backupDir);
        ErrorReporter.Log("数据库备份模块初始化完成");
        return Task.CompletedTask;
    }

    /// <inheritdoc/>
    protected override Task OnEnableAsync()
    {
        SetupSchedule();
        ErrorReporter.Log($"数据库备份模块已启用，共 {_config.Targets.Count} 个备份目标");
        return Task.CompletedTask;
    }

    /// <inheritdoc/>
    protected override Task OnDisableAsync()
    {
        StopSchedule();
        ErrorReporter.Log("数据库备份模块已禁用");
        return Task.CompletedTask;
    }

    /// <inheritdoc/>
    protected override void OnReleaseResources()
    {
        StopSchedule();
    }

    /// <inheritdoc/>
    protected override string GetStatusSummary()
    {
        if (!IsEnabled) return "已禁用";

        var targetCount = _config.Targets.Count(t => t.Enabled);
        var backups = GetBackupList();
        var lastBackup = backups.Count > 0 ? backups[0].Timestamp : (DateTime?)null;

        return lastBackup.HasValue
            ? $"运行中 | {targetCount} 个目标 | {backups.Count} 个备份 | 最近：{lastBackup:yyyy-MM-dd HH:mm}"
            : $"运行中 | {targetCount} 个目标 | 暂无备份";
    }

    #endregion

    #region 定时调度

    /// <summary>启动定时备份调度</summary>
    private void SetupSchedule()
    {
        StopSchedule();
        var interval = TimeSpan.FromMinutes(ScheduleCheckMinutes);
        _scheduleTimer = new Timer(OnScheduleTick, null, interval, interval);
    }

    /// <summary>停止定时调度</summary>
    private void StopSchedule()
    {
        _scheduleTimer?.Dispose();
        _scheduleTimer = null;
    }

    /// <summary>定时调度回调</summary>
    private void OnScheduleTick(object? state)
    {
        // 避免重复触发
        if (DateTime.Now - _lastScheduleRun < TimeSpan.FromMinutes(10)) return;
        _lastScheduleRun = DateTime.Now;

        try
        {
            _config = LoadConfig();
            var now = DateTime.Now;

            foreach (var target in _config.Targets)
            {
                if (!target.Enabled) continue;

                var interval = GetScheduleInterval(target.Schedule);
                if (target.LastBackup.HasValue && now - target.LastBackup.Value < interval)
                    continue;

                // 异步执行备份，避免阻塞定时器
                _ = Task.Run(() => BackupTargetInternal(target));
            }
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, "数据库定时备份调度异常");
        }
    }

    /// <summary>获取调度间隔</summary>
    private static TimeSpan GetScheduleInterval(BackupSchedule schedule)
    {
        return schedule switch
        {
            BackupSchedule.Hourly => TimeSpan.FromHours(1),
            BackupSchedule.Daily => TimeSpan.FromHours(24),
            BackupSchedule.Weekly => TimeSpan.FromDays(7),
            _ => TimeSpan.FromHours(24)
        };
    }

    #endregion

    #region 备份操作

    /// <summary>
    /// 立即备份指定目标
    /// </summary>
    /// <param name="targetName">目标名称</param>
    /// <returns>备份结果</returns>
    public DatabaseBackupResult BackupTargetNow(string targetName)
    {
        var target = _config.Targets.FirstOrDefault(t => t.Name == targetName);
        if (target == null)
            return new DatabaseBackupResult { Success = false, Message = $"未找到备份目标：{targetName}" };

        return BackupTargetInternal(target);
    }

    /// <summary>
    /// 立即备份所有已启用的目标
    /// </summary>
    /// <returns>各目标的备份结果列表</returns>
    public List<(string TargetName, DatabaseBackupResult Result)> BackupAllNow()
    {
        var results = new List<(string, DatabaseBackupResult)>();
        foreach (var target in _config.Targets.Where(t => t.Enabled))
        {
            var result = BackupTargetInternal(target);
            results.Add((target.Name, result));
        }
        return results;
    }

    /// <summary>执行单个目标的备份</summary>
    private DatabaseBackupResult BackupTargetInternal(DatabaseBackupTarget target)
    {
        try
        {
            var destDir = Path.Combine(_backupDir, target.Name);
            Directory.CreateDirectory(destDir);

            var result = _engine.BackupDatabase(
                target.DbType,
                target.ConnectionString,
                destDir,
                target.Mode,
                target.TableName);

            if (result.Success)
            {
                target.LastBackup = DateTime.Now;
                SaveConfig(_config);

                // 清理过期备份
                CleanupOldBackups(destDir);
            }

            return result;
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, $"数据库备份执行失败：{target.Name}");
            return new DatabaseBackupResult
            {
                Success = false,
                Message = $"备份失败：{ex.Message}"
            };
        }
    }

    /// <summary>
    /// 从加密备份文件还原数据库
    /// </summary>
    /// <param name="dbType">数据库类型</param>
    /// <param name="connStr">目标连接字符串</param>
    /// <param name="backupPath">备份文件路径</param>
    /// <returns>是否还原成功</returns>
    public bool RestoreFromBackup(DatabaseType dbType, string connStr, string backupPath)
    {
        return _engine.RestoreDatabase(dbType, connStr, backupPath);
    }

    /// <summary>
    /// 校验备份文件完整性
    /// </summary>
    /// <param name="backupPath">备份文件路径</param>
    /// <returns>是否通过校验</returns>
    public bool VerifyBackup(string backupPath)
    {
        return _engine.VerifyBackup(backupPath);
    }

    #endregion

    #region 备份列表

    /// <summary>
    /// 获取所有数据库备份文件列表（按时间倒序）
    /// </summary>
    public List<DatabaseBackupInfo> GetBackupList()
    {
        var list = new List<DatabaseBackupInfo>();
        try
        {
            if (!Directory.Exists(_backupDir)) return list;

            var files = Directory.EnumerateFiles(_backupDir, "*.enc", SearchOption.AllDirectories);
            foreach (var file in files)
            {
                try
                {
                    var info = new FileInfo(file);
                    // 从文件名解析数据库类型和时间
                    var fileName = Path.GetFileNameWithoutExtension(file);
                    // 文件名格式：dbbackup_{DbType}_{timestamp}{ext}
                    var dbTypeStr = ExtractDbTypeFromFileName(fileName);
                    var timestamp = ExtractTimestampFromFileName(fileName);

                    list.Add(new DatabaseBackupInfo
                    {
                        FilePath = file,
                        FileName = Path.GetFileName(file),
                        DbType = dbTypeStr,
                        Timestamp = timestamp,
                        SizeBytes = info.Length
                    });
                }
                catch { }
            }
        }
        catch { }
        return list.OrderByDescending(x => x.Timestamp).ToList();
    }

    /// <summary>从文件名解析数据库类型</summary>
    private static string ExtractDbTypeFromFileName(string fileName)
    {
        // 格式：dbbackup_SQLite_20260801_120000.sqlite
        var parts = fileName.Split('_');
        if (parts.Length >= 2) return parts[1];
        return "Unknown";
    }

    /// <summary>从文件名解析时间戳</summary>
    private static DateTime ExtractTimestampFromFileName(string fileName)
    {
        // 格式：dbbackup_SQLite_20260801_120000.sqlite
        var parts = fileName.Split('_');
        if (parts.Length >= 4)
        {
            var dateStr = parts[2];
            var timeStr = parts[3];
            if (DateTime.TryParseExact($"{dateStr}_{timeStr}", "yyyyMMdd_HHmmss",
                null, System.Globalization.DateTimeStyles.None, out var dt))
                return dt;
        }
        return DateTime.MinValue;
    }

    #endregion

    #region 过期清理

    /// <summary>清理过期数据库备份</summary>
    private void CleanupOldBackups(string dir)
    {
        try
        {
            var max = _config.MaxBackupCount;
            if (max <= 0) return;

            var files = Directory.EnumerateFiles(dir, "*.enc")
                .Select(f => new FileInfo(f))
                .OrderByDescending(f => f.CreationTime)
                .ToList();

            if (files.Count <= max) return;

            foreach (var file in files.Skip(max))
            {
                try { file.Delete(); } catch { }
            }
        }
        catch { }
    }

    #endregion

    #region 配置管理

    /// <summary>获取当前配置（供 UI 调用）</summary>
    public DatabaseBackupConfig GetConfig() => _config;

    /// <summary>保存配置</summary>
    public void SaveConfig(DatabaseBackupConfig config)
    {
        _config = config;
        try
        {
            var json = JsonSerializer.Serialize(config, new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(_configPath, json);
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, "保存数据库备份配置失败");
        }
    }

    /// <summary>加载配置</summary>
    private DatabaseBackupConfig LoadConfig()
    {
        try
        {
            if (!File.Exists(_configPath)) return new DatabaseBackupConfig();
            var json = File.ReadAllText(_configPath);
            return JsonSerializer.Deserialize<DatabaseBackupConfig>(json) ?? new DatabaseBackupConfig();
        }
        catch { return new DatabaseBackupConfig(); }
    }

    #endregion
}

#region 公共数据类型（供 UI / 调用方使用）

/// <summary>
/// 数据库备份目标配置
/// </summary>
public sealed class DatabaseBackupTarget
{
    /// <summary>目标名称（唯一标识）</summary>
    public string Name { get; set; } = string.Empty;

    /// <summary>数据库类型</summary>
    public DatabaseType DbType { get; set; }

    /// <summary>连接字符串</summary>
    public string ConnectionString { get; set; } = string.Empty;

    /// <summary>备份模式</summary>
    public Database.BackupMode Mode { get; set; } = Database.BackupMode.Full;

    /// <summary>单表备份时的表名</summary>
    public string? TableName { get; set; }

    /// <summary>定时计划</summary>
    public BackupSchedule Schedule { get; set; } = BackupSchedule.Daily;

    /// <summary>是否启用</summary>
    public bool Enabled { get; set; } = true;

    /// <summary>最近备份时间</summary>
    public DateTime? LastBackup { get; set; }
}

/// <summary>
/// 数据库备份全局配置
/// </summary>
public sealed class DatabaseBackupConfig
{
    /// <summary>备份目标列表</summary>
    public List<DatabaseBackupTarget> Targets { get; set; } = new();

    /// <summary>每个目标最大保留备份数</summary>
    public int MaxBackupCount { get; set; } = 20;
}

/// <summary>
/// 数据库备份信息（UI 展示用）
/// </summary>
public sealed class DatabaseBackupInfo
{
    /// <summary>备份文件路径</summary>
    public string FilePath { get; set; } = string.Empty;

    /// <summary>文件名</summary>
    public string FileName { get; set; } = string.Empty;

    /// <summary>数据库类型</summary>
    public string DbType { get; set; } = string.Empty;

    /// <summary>备份时间</summary>
    public DateTime Timestamp { get; set; }

    /// <summary>文件大小（字节）</summary>
    public long SizeBytes { get; set; }
}

#endregion
