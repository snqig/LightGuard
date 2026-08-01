// © 2026 落尘（Luochen） 原创开发 - 保留所有权利

using System.Text.Json;
using LightGuard.Core;
using LightGuard.Core.Interfaces;

namespace LightGuard.Modules;

/// <summary>
/// 全局日志审计模块
/// <para>封装 AuditLogSystem 静态服务的模块化生命周期管理，</para>
/// <para>负责初始化、启停定时刷盘与 SMB 远程同步，并提供查询/导出能力。</para>
/// </summary>
public sealed class AuditLogModule : ModuleBase
{
    #region 字段

    private readonly string _configPath;

    #endregion

    #region 构造与模块信息

    /// <summary>
    /// 创建日志审计模块实例
    /// </summary>
    /// <param name="appState">全局应用状态</param>
    public AuditLogModule(AppState appState) : base(appState)
    {
        _configPath = Path.Combine(ConfigManager.GetDataDir(), "audit_config.json");
    }

    /// <inheritdoc/>
    public override string Id => "audit-log";

    /// <inheritdoc/>
    public override string DisplayName => "全局日志审计";

    /// <inheritdoc/>
    public override string Description =>
        "AES-256-GCM 加密审计日志系统：按天滚动、线程安全缓冲刷盘、SMB 远程双副本同步、90 天保留策略、CSV/TXT 报表导出";

    /// <inheritdoc/>
    public override ModuleCategory Category => ModuleCategory.Core;

    /// <summary>审计日志属于核心系统，需要管理员权限</summary>
    public override bool RequiresAdmin => true;

    #endregion

    #region 生命周期

    /// <inheritdoc/>
    protected override Task OnInitializeAsync()
    {
        // 加载审计配置
        var config = LoadAuditConfig();

        // 初始化审计日志系统（加载密钥 + 历史日志索引）
        AuditLogSystem.Initialize(
            smbSyncPath: config.SmbSyncPath,
            retentionDays: config.RetentionDays);

        ErrorReporter.Log("日志审计模块初始化完成");
        return Task.CompletedTask;
    }

    /// <inheritdoc/>
    protected override Task OnEnableAsync()
    {
        // 启动定时刷盘 + 过期清理 + SMB 同步
        AuditLogSystem.Start();

        // 记录系统启动审计日志
        AuditLogSystem.LogInfo(LogCategory.System, "LightGuard 审计日志系统已启动");

        ErrorReporter.Log("日志审计模块已启用");
        return Task.CompletedTask;
    }

    /// <inheritdoc/>
    protected override Task OnDisableAsync()
    {
        // 记录系统停止审计日志
        AuditLogSystem.LogWarning(LogCategory.System, "LightGuard 审计日志系统正在停止");

        // 停止定时器并刷盘剩余缓冲
        AuditLogSystem.Stop();

        ErrorReporter.Log("日志审计模块已禁用");
        return Task.CompletedTask;
    }

    /// <inheritdoc/>
    protected override void OnReleaseResources()
    {
        // AuditLogSystem 是静态服务，模块释放时确保停止
        if (AuditLogSystem.IsRunning)
            AuditLogSystem.Stop();
    }

    /// <inheritdoc/>
    protected override string GetStatusSummary()
    {
        if (!IsEnabled) return "已禁用";

        var count = AuditLogSystem.TotalEntries;
        var sync = string.IsNullOrEmpty(AuditLogSystem.SmbSyncPath) ? "本地" : "本地+SMB";

        return $"运行中 | {count} 条日志 | {sync} | 保留 {AuditLogSystem.RetentionDays} 天";
    }

    #endregion

    #region 日志查询与导出（供 UI 调用）

    /// <summary>
    /// 查询指定时间范围内的日志
    /// </summary>
    /// <param name="startTime">起始时间</param>
    /// <param name="endTime">结束时间</param>
    /// <param name="level">日志级别筛选（null 不筛选）</param>
    /// <param name="category">日志分类筛选（null 不筛选）</param>
    /// <returns>匹配的日志条目列表</returns>
    public List<AuditLogEntry> QueryLogs(DateTime startTime, DateTime endTime, LogLevel? level = null, LogCategory? category = null)
    {
        return AuditLogSystem.Query(startTime, endTime, level, category);
    }

    /// <summary>
    /// 获取所有日志条目
    /// </summary>
    public List<AuditLogEntry> GetAllLogs()
    {
        return AuditLogSystem.QueryAll();
    }

    /// <summary>
    /// 获取最近的 N 条日志
    /// </summary>
    /// <param name="count">条数</param>
    public List<AuditLogEntry> GetRecentLogs(int count)
    {
        return AuditLogSystem.GetRecent(count);
    }

    /// <summary>
    /// 按条件筛选日志
    /// </summary>
    /// <param name="startTime">起始时间（null 不限制）</param>
    /// <param name="endTime">结束时间（null 不限制）</param>
    /// <param name="level">日志级别（null 不筛选）</param>
    /// <param name="category">日志分类（null 不筛选）</param>
    /// <param name="keyword">关键词搜索（null 不搜索）</param>
    public List<AuditLogEntry> FilterLogs(
        DateTime? startTime = null,
        DateTime? endTime = null,
        LogLevel? level = null,
        LogCategory? category = null,
        string? keyword = null)
    {
        var entries = AuditLogSystem.QueryAll();
        return AuditLogExporter.Filter(entries, startTime, endTime, level, category, keyword);
    }

    /// <summary>
    /// 导出日志为 CSV 报表
    /// </summary>
    /// <param name="entries">要导出的日志条目</param>
    /// <param name="filePath">目标文件路径</param>
    /// <returns>是否导出成功</returns>
    public bool ExportToCsv(List<AuditLogEntry> entries, string filePath)
    {
        return AuditLogExporter.ExportToCsv(entries, filePath);
    }

    /// <summary>
    /// 导出日志为 TXT 报表
    /// </summary>
    /// <param name="entries">要导出的日志条目</param>
    /// <param name="filePath">目标文件路径</param>
    /// <returns>是否导出成功</returns>
    public bool ExportToTxt(List<AuditLogEntry> entries, string filePath)
    {
        return AuditLogExporter.ExportToTxt(entries, filePath);
    }

    /// <summary>
    /// 生成日志统计摘要
    /// </summary>
    /// <param name="entries">要统计的日志条目</param>
    /// <returns>统计摘要文本</returns>
    public string GetLogSummary(List<AuditLogEntry> entries)
    {
        return AuditLogExporter.ExportSummary(entries);
    }

    /// <summary>
    /// 手动触发刷盘（将缓冲队列中的日志写入加密文件）
    /// </summary>
    public void FlushLogs()
    {
        AuditLogSystem.FlushBuffer();
    }

    #endregion

    #region 配置管理

    /// <summary>
    /// 设置 SMB 远程同步路径
    /// </summary>
    /// <param name="path">SMB 共享路径（如 \\server\audit-logs）</param>
    public void SetSmbSyncPath(string? path)
    {
        AuditLogSystem.SmbSyncPath = path;

        var config = LoadAuditConfig();
        config.SmbSyncPath = path;
        SaveAuditConfig(config);

        AuditLogSystem.LogInfo(LogCategory.SmbConnection,
            $"SMB 日志同步路径已更新：{(string.IsNullOrEmpty(path) ? "未配置" : path)}");
    }

    /// <summary>
    /// 设置日志保留天数
    /// </summary>
    /// <param name="days">保留天数</param>
    public void SetRetentionDays(int days)
    {
        AuditLogSystem.RetentionDays = days;

        var config = LoadAuditConfig();
        config.RetentionDays = days;
        SaveAuditConfig(config);

        AuditLogSystem.LogInfo(LogCategory.AutoCleanup,
            $"日志保留策略已更新：{days} 天");
    }

    /// <summary>
    /// 手动触发过期日志清理
    /// </summary>
    public void CleanupOldLogs()
    {
        AuditLogSystem.CleanupOldLogs();
    }

    /// <summary>加载审计配置</summary>
    private AuditModuleConfig LoadAuditConfig()
    {
        try
        {
            if (!File.Exists(_configPath)) return new AuditModuleConfig();
            var json = File.ReadAllText(_configPath);
            return JsonSerializer.Deserialize<AuditModuleConfig>(json) ?? new AuditModuleConfig();
        }
        catch { return new AuditModuleConfig(); }
    }

    /// <summary>保存审计配置</summary>
    private void SaveAuditConfig(AuditModuleConfig config)
    {
        try
        {
            var json = JsonSerializer.Serialize(config, new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(_configPath, json);
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, "保存审计配置失败");
        }
    }

    #endregion
}

#region 公共数据类型

/// <summary>
/// 审计日志模块配置
/// </summary>
public sealed class AuditModuleConfig
{
    /// <summary>SMB 远程同步路径（双副本归档目标，留空表示不启用）</summary>
    public string? SmbSyncPath { get; set; }

    /// <summary>日志保留天数（默认 90 天）</summary>
    public int RetentionDays { get; set; } = 90;
}

#endregion
