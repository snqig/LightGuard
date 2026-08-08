// © 2026 落尘（Luochen） 原创开发 - 保留所有权利
//
// 数据库备份实例配置模型（v3.5 P1-1）
//   - 分字段连接参数（dbconfig 引导录入，内部拼接连接字符串，不要求用户手写）
//   - 每实例独立的定时全量 cron / 定时增量 cron
//   - SQLite 用 DbFilePath；MySQL/PG 用 Host/Port/User/Database
//   - 密码凭据引用 + 盐（不落盘明文密码）
//   - 增量前置校验（FullSnapshotNodeId）+ binlog/LSN 续传位置

namespace LightGuard.Database;

/// <summary>
/// 数据库备份实例（v3.5 定时调度单元）。
/// <para>存于 AppConfig.DbBackupInstances（JSON 节，等价需求"DB_BACKUP 段"）。</para>
/// </summary>
public sealed class DbBackupInstance
{
    /// <summary>实例名（唯一标识）。</summary>
    public string Name { get; set; } = "";

    /// <summary>数据库类型（SQLite / MySQL / MariaDB / PostgreSQL / SqlServer / Access）。</summary>
    public DatabaseType DbType { get; set; } = DatabaseType.MySQL;

    // —— 分字段连接参数（dbconfig 引导录入，内部拼接连接字符串）——

    /// <summary>主机地址（SQLite 忽略）。</summary>
    public string Host { get; set; } = "";

    /// <summary>端口（SQLite 忽略）。</summary>
    public int Port { get; set; }

    /// <summary>用户名（SQLite 忽略）。</summary>
    public string User { get; set; } = "";

    /// <summary>数据库名（SQLite 忽略）。</summary>
    public string Database { get; set; } = "";

    /// <summary>SQLite 专用：db 文件路径。</summary>
    public string DbFilePath { get; set; } = "";

    /// <summary>是否启用。</summary>
    public bool Enabled { get; set; } = true;

    /// <summary>定时全量 cron；空 = 禁用。</summary>
    public string FullCron { get; set; } = "";

    /// <summary>定时增量 cron；SQLite 强制忽略（代码层拦截）。</summary>
    public string IncrementalCron { get; set; } = "";

    /// <summary>每个实例最大保留备份数。</summary>
    public int MaxBackupCount { get; set; } = 20;

    /// <summary>密码凭据引用（密码经 HKDF 派生，不落盘明文）。</summary>
    public string CredentialRef { get; set; } = "";

    /// <summary>派生盐（Base64，可落盘）。</summary>
    public string SaltBase64 { get; set; } = "";

    /// <summary>最近定时全量时间。</summary>
    public DateTime? LastFullAt { get; set; }

    /// <summary>最近定时增量时间。</summary>
    public DateTime? LastIncrementalAt { get; set; }

    /// <summary>MySQL binlog 位置 / PG LSN（增量续传游标）。</summary>
    public string LastBinlogPos { get; set; } = "";

    /// <summary>最近全量快照节点 ID（增量前置校验：为空则增量跳过）。</summary>
    public string? FullSnapshotNodeId { get; set; }

    /// <summary>生成定时调度防重入键（每实例独立锁）。</summary>
    public string ScheduleKey => $"db:{Name}";
}
