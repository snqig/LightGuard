// © 2026 落尘（Luochen）原创开发 - 保留所有权利

using System.Diagnostics;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using LightGuard.Core;
using LightGuard.Native;

namespace LightGuard.Security;

/// <summary>
/// 快照类型
/// </summary>
public enum SnapshotType
{
    /// <summary>注册表</summary>
    Registry,

    /// <summary>Hosts 文件</summary>
    Hosts,

    /// <summary>防火墙规则</summary>
    Firewall,

    /// <summary>服务/计划任务</summary>
    Service,

    /// <summary>系统配置</summary>
    SystemConfig
}

/// <summary>
/// 快照记录
/// </summary>
public sealed class SnapshotRecord
{
    /// <summary>快照唯一标识</summary>
    public string Id { get; set; } = Guid.NewGuid().ToString("N");

    /// <summary>快照类型</summary>
    public SnapshotType Type { get; set; }

    /// <summary>描述信息</summary>
    public string Description { get; set; } = "";

    /// <summary>创建时间</summary>
    public DateTime CreatedAt { get; set; } = DateTime.Now;

    /// <summary>快照数据文件路径</summary>
    public string DataPath { get; set; } = "";

    /// <summary>创建快照的模块来源</summary>
    public string ModuleSource { get; set; } = "";

    /// <summary>是否已回滚</summary>
    public bool IsRestored { get; set; }
}

/// <summary>
/// 系统操作快照管理器
/// <para>核心特性：</para>
/// <para>1. 支持注册表、Hosts、防火墙、服务等多种系统修改的快照与回滚</para>
/// <para>2. 快照存储在 %APPDATA%\LightGuard\snapshots\ 目录</para>
/// <para>3. 回滚操作记录审计日志</para>
/// <para>4. 自动清理超过 7 天的快照</para>
/// </summary>
public sealed class SystemSnapshotManager : IDisposable
{
    #region 常量

    /// <summary>快照目录名</summary>
    private const string SnapshotFolderName = "snapshots";

    /// <summary>快照元数据索引文件名</summary>
    private const string MetaFileName = "snapshots_index.json";

    /// <summary>注册表快照文件扩展名</summary>
    private const string RegFileExt = ".reg";

    /// <summary>Hosts 快照文件扩展名</summary>
    private const string HostsFileExt = ".hosts";

    /// <summary>防火墙快照文件扩展名</summary>
    private const string FirewallFileExt = ".json";

    /// <summary>通用快照文件扩展名</summary>
    private const string GenericFileExt = ".json";

    /// <summary>LightGuard 防火墙规则前缀</summary>
    private const string FirewallRulePrefix = "LightGuard";

    #endregion

    #region 字段

    private readonly string _snapshotDir;
    private readonly string _metaDataPath;
    private readonly object _lock = new();
    private List<SnapshotRecord> _records;
    private bool _disposed;

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = null,
        Converters = { new JsonStringEnumConverter() },
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    #endregion

    #region 构造与初始化

    /// <summary>
    /// 初始化快照管理器，加载历史快照记录。
    /// </summary>
    public SystemSnapshotManager()
    {
        var configDir = ConfigManager.GetConfigDir();
        _snapshotDir = Path.Combine(configDir, SnapshotFolderName);
        _metaDataPath = Path.Combine(_snapshotDir, MetaFileName);
        _records = new List<SnapshotRecord>();

        try
        {
            Directory.CreateDirectory(_snapshotDir);
            LoadRecords();

            AuditLogSystem.Log(LogLevel.Info, LogCategory.System,
                "快照管理器初始化完成", $"快照记录数: {_records.Count}");
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, "SystemSnapshotManager 初始化失败");
        }
    }

    #endregion

    #region 注册表快照

    /// <summary>
    /// 创建注册表快照，导出指定注册表路径到 .reg 文件。
    /// <para>支持 HKLM/HKCU/HKCR/HKU/HKCC 缩写或完整路径。</para>
    /// </summary>
    /// <param name="regPath">注册表路径（如 HKEY_LOCAL_MACHINE\SOFTWARE\LightGuard 或 HKLM\SOFTWARE\LightGuard）</param>
    /// <param name="description">描述信息</param>
    /// <returns>快照记录 ID；失败返回空字符串</returns>
    public string CreateRegistrySnapshot(string regPath, string description = "")
    {
        try
        {
            if (string.IsNullOrWhiteSpace(regPath))
            {
                AuditLogSystem.LogWarning(LogCategory.System,
                    "注册表快照失败：注册表路径为空");
                return "";
            }

            // 规范化注册表路径
            var normalizedPath = NormalizeRegPath(regPath);
            if (string.IsNullOrEmpty(normalizedPath))
            {
                AuditLogSystem.LogWarning(LogCategory.System,
                    $"注册表快照失败：无法识别的路径 - {regPath}");
                return "";
            }

            var record = new SnapshotRecord
            {
                Type = SnapshotType.Registry,
                Description = string.IsNullOrEmpty(description)
                    ? $"注册表快照: {regPath}"
                    : description
            };

            record.DataPath = Path.Combine(_snapshotDir,
                $"{record.Id}{RegFileExt}");

            // 使用 reg.exe export 导出
            var process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = "reg.exe",
                    Arguments = $"export \"{normalizedPath}\" \"{record.DataPath}\" /y",
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                }
            };

            process.Start();
            process.WaitForExit(10000);
            process.Close();

            if (!File.Exists(record.DataPath))
            {
                AuditLogSystem.LogError(LogCategory.System,
                    $"注册表快照失败：导出文件未生成 - {regPath}");
                return "";
            }

            lock (_lock)
            {
                _records.Add(record);
                SaveRecords();
            }

            AuditLogSystem.Log(LogLevel.Info, LogCategory.System,
                $"注册表快照已创建: {regPath}",
                $"ID={record.Id}, 文件={record.DataPath}");

            return record.Id;
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, $"创建注册表快照失败: {regPath}");
            AuditLogSystem.LogError(LogCategory.System,
                $"创建注册表快照失败: {regPath}", ex.Message);
            return "";
        }
    }

    #endregion

    #region Hosts 快照

    /// <summary>
    /// 创建 Hosts 文件快照，备份当前 hosts 文件内容。
    /// </summary>
    /// <param name="description">描述信息</param>
    /// <returns>快照记录 ID；失败返回空字符串</returns>
    public string CreateHostsSnapshot(string description = "")
    {
        try
        {
            var hostsPath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.System),
                "drivers", "etc", "hosts");

            if (!File.Exists(hostsPath))
            {
                AuditLogSystem.LogWarning(LogCategory.System,
                    "Hosts 快照失败：Hosts 文件不存在");
                return "";
            }

            var record = new SnapshotRecord
            {
                Type = SnapshotType.Hosts,
                Description = string.IsNullOrEmpty(description)
                    ? "Hosts 文件快照"
                    : description
            };

            record.DataPath = Path.Combine(_snapshotDir,
                $"{record.Id}{HostsFileExt}");

            // 复制 hosts 文件内容
            var content = File.ReadAllText(hostsPath, Encoding.UTF8);
            File.WriteAllText(record.DataPath, content, Encoding.UTF8);

            lock (_lock)
            {
                _records.Add(record);
                SaveRecords();
            }

            AuditLogSystem.Log(LogLevel.Info, LogCategory.System,
                "Hosts 文件快照已创建",
                $"ID={record.Id}, 文件={record.DataPath}");

            return record.Id;
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, "创建 Hosts 快照失败");
            AuditLogSystem.LogError(LogCategory.System,
                "创建 Hosts 快照失败", ex.Message);
            return "";
        }
    }

    #endregion

    #region 防火墙快照

    /// <summary>
    /// 创建防火墙规则快照，导出所有 LightGuard 规则到 JSON。
    /// </summary>
    /// <param name="description">描述信息</param>
    /// <returns>快照记录 ID；失败返回空字符串</returns>
    public string CreateFirewallSnapshot(string description = "")
    {
        try
        {
            var record = new SnapshotRecord
            {
                Type = SnapshotType.Firewall,
                Description = string.IsNullOrEmpty(description)
                    ? "防火墙规则快照"
                    : description
            };

            record.DataPath = Path.Combine(_snapshotDir,
                $"{record.Id}{FirewallFileExt}");

            // 获取所有 LightGuard 防火墙规则
            var allRules = FirewallHelper.GetAllRules();
            var lgRules = allRules
                .Where(r => r.Name.Contains(FirewallRulePrefix, StringComparison.OrdinalIgnoreCase))
                .ToList();

            var json = JsonSerializer.Serialize(lgRules, JsonOptions);
            File.WriteAllText(record.DataPath, json, Encoding.UTF8);

            lock (_lock)
            {
                _records.Add(record);
                SaveRecords();
            }

            AuditLogSystem.Log(LogLevel.Info, LogCategory.System,
                "防火墙规则快照已创建",
                $"ID={record.Id}, 规则数={lgRules.Count}, 文件={record.DataPath}");

            return record.Id;
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, "创建防火墙快照失败");
            AuditLogSystem.LogError(LogCategory.System,
                "创建防火墙快照失败", ex.Message);
            return "";
        }
    }

    #endregion

    #region 通用快照创建

    /// <summary>
    /// 创建通用快照，将任意 JSON 数据保存为快照。
    /// <para>用于服务/计划任务、系统配置等自定义类型的快照。</para>
    /// </summary>
    /// <param name="type">快照类型</param>
    /// <param name="description">描述信息</param>
    /// <param name="dataJson">快照数据（JSON 格式）</param>
    /// <param name="moduleSource">模块来源</param>
    /// <returns>快照记录 ID；失败返回空字符串</returns>
    public string CreateSnapshot(SnapshotType type, string description,
        string dataJson, string moduleSource = "")
    {
        try
        {
            if (string.IsNullOrEmpty(dataJson))
            {
                AuditLogSystem.LogWarning(LogCategory.System,
                    $"通用快照失败：数据为空 - 类型={type}");
                return "";
            }

            var record = new SnapshotRecord
            {
                Type = type,
                Description = string.IsNullOrEmpty(description)
                    ? $"{type} 快照"
                    : description,
                ModuleSource = moduleSource
            };

            record.DataPath = Path.Combine(_snapshotDir,
                $"{record.Id}{GenericFileExt}");

            File.WriteAllText(record.DataPath, dataJson, Encoding.UTF8);

            lock (_lock)
            {
                _records.Add(record);
                SaveRecords();
            }

            AuditLogSystem.Log(LogLevel.Info, LogCategory.System,
                $"{type} 快照已创建: {record.Description}",
                $"ID={record.Id}, 文件={record.DataPath}, 来源={moduleSource}");

            return record.Id;
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, $"创建通用快照失败: {type}");
            AuditLogSystem.LogError(LogCategory.System,
                $"创建通用快照失败: {type}", ex.Message);
            return "";
        }
    }

    #endregion

    #region 回滚

    /// <summary>
    /// 回滚到指定快照。
    /// <para>根据快照类型执行不同的回滚操作：</para>
    /// <para>- Registry: 使用 reg.exe import 还原注册表</para>
    /// <para>- Hosts: 将备份的 hosts 内容写回</para>
    /// <para>- Firewall: 删除当前 LightGuard 规则后恢复快照规则</para>
    /// <para>- Service/SystemConfig: 验证快照数据可读</para>
    /// </summary>
    /// <param name="snapshotId">快照记录 ID</param>
    /// <returns>回滚成功返回 true；失败返回 false</returns>
    public bool Rollback(string snapshotId)
    {
        try
        {
            SnapshotRecord? record;
            lock (_lock)
            {
                record = _records.FirstOrDefault(r => r.Id == snapshotId);
            }

            if (record == null)
            {
                AuditLogSystem.LogWarning(LogCategory.System,
                    $"回滚失败：快照不存在 - {snapshotId}");
                return false;
            }

            if (!File.Exists(record.DataPath))
            {
                AuditLogSystem.LogError(LogCategory.System,
                    $"回滚失败：快照数据文件不存在 - {record.DataPath}");
                return false;
            }

            var success = record.Type switch
            {
                SnapshotType.Registry => RollbackRegistry(record),
                SnapshotType.Hosts => RollbackHosts(record),
                SnapshotType.Firewall => RollbackFirewall(record),
                SnapshotType.Service => RollbackService(record),
                SnapshotType.SystemConfig => RollbackSystemConfig(record),
                _ => false
            };

            if (success)
            {
                lock (_lock)
                {
                    record.IsRestored = true;
                    SaveRecords();
                }

                AuditLogSystem.Log(LogLevel.Info, LogCategory.Recovery,
                    $"快照回滚成功: {record.Description}",
                    $"ID={record.Id}, 类型={record.Type}");
            }
            else
            {
                AuditLogSystem.LogError(LogCategory.Recovery,
                    $"快照回滚失败: {record.Description}",
                    $"ID={record.Id}, 类型={record.Type}");
            }

            return success;
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, $"快照回滚失败: {snapshotId}");
            AuditLogSystem.LogError(LogCategory.Recovery,
                $"快照回滚失败: {snapshotId}", ex.Message);
            return false;
        }
    }

    /// <summary>
    /// 回滚最近一次指定类型的快照。
    /// </summary>
    /// <param name="type">快照类型（null 表示回滚最近一次任意类型的快照）</param>
    /// <returns>回滚成功返回 true；失败返回 false</returns>
    public bool RollbackLatest(SnapshotType? type = null)
    {
        try
        {
            SnapshotRecord? latest;
            lock (_lock)
            {
                var query = _records.AsEnumerable();
                if (type.HasValue)
                    query = query.Where(r => r.Type == type.Value);

                latest = query
                    .OrderByDescending(r => r.CreatedAt)
                    .FirstOrDefault();
            }

            if (latest == null)
            {
                AuditLogSystem.LogWarning(LogCategory.System,
                    $"回滚失败：未找到匹配的快照 - 类型={type}");
                return false;
            }

            return Rollback(latest.Id);
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, "回滚最新快照失败");
            AuditLogSystem.LogError(LogCategory.Recovery,
                "回滚最新快照失败", ex.Message);
            return false;
        }
    }

    #endregion

    #region 回滚实现

    /// <summary>注册表回滚：使用 reg.exe import 还原</summary>
    private bool RollbackRegistry(SnapshotRecord record)
    {
        try
        {
            if (!File.Exists(record.DataPath))
                return false;

            var psi = new ProcessStartInfo
            {
                FileName = "reg.exe",
                Arguments = $"import \"{record.DataPath}\"",
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };

            using var proc = Process.Start(psi);
            proc?.WaitForExit(15000);
            return proc?.ExitCode == 0;
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, $"注册表回滚失败: {record.Id}");
            return false;
        }
    }

    /// <summary>Hosts 回滚：将备份内容写回 hosts 文件</summary>
    private bool RollbackHosts(SnapshotRecord record)
    {
        try
        {
            var hostsPath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.System),
                "drivers", "etc", "hosts");

            var content = File.ReadAllText(record.DataPath, Encoding.UTF8);
            File.WriteAllText(hostsPath, content, Encoding.UTF8);
            return true;
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, $"Hosts 回滚失败: {record.Id}");
            return false;
        }
    }

    /// <summary>防火墙回滚：删除当前 LightGuard 规则后恢复快照规则</summary>
    private bool RollbackFirewall(SnapshotRecord record)
    {
        try
        {
            // 读取快照数据
            var json = File.ReadAllText(record.DataPath, Encoding.UTF8);
            var savedRules = JsonSerializer.Deserialize<List<FirewallRule>>(json, JsonOptions);
            if (savedRules == null)
                return false;

            // 删除当前所有 LightGuard 规则
            var currentRules = FirewallHelper.GetAllRules();
            foreach (var rule in currentRules)
            {
                if (rule.Name.Contains(FirewallRulePrefix, StringComparison.OrdinalIgnoreCase))
                {
                    FirewallHelper.RemoveRule(rule.Name);
                }
            }

            // 恢复快照中的规则
            var restoredCount = 0;
            foreach (var rule in savedRules)
            {
                try
                {
                    if (RestoreFirewallRule(rule))
                        restoredCount++;
                }
                catch { }
            }

            AuditLogSystem.Log(LogLevel.Info, LogCategory.Recovery,
                $"防火墙规则回滚完成",
                $"恢复 {restoredCount}/{savedRules.Count} 条规则");

            return true;
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, $"防火墙回滚失败: {record.Id}");
            return false;
        }
    }

    /// <summary>服务回滚：读取快照数据（具体恢复由调用方处理）</summary>
    private bool RollbackService(SnapshotRecord record)
    {
        try
        {
            // 读取快照数据，具体的服务状态恢复由调用方根据 JSON 内容处理
            var json = File.ReadAllText(record.DataPath, Encoding.UTF8);
            return !string.IsNullOrEmpty(json);
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, $"服务回滚失败: {record.Id}");
            return false;
        }
    }

    /// <summary>系统配置回滚：验证快照数据可读</summary>
    private bool RollbackSystemConfig(SnapshotRecord record)
    {
        try
        {
            // 系统配置的回滚依赖具体配置类型
            // 此处验证快照数据文件可读，具体恢复由调用方处理
            var json = File.ReadAllText(record.DataPath, Encoding.UTF8);
            return !string.IsNullOrEmpty(json);
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, $"系统配置回滚失败: {record.Id}");
            return false;
        }
    }

    #endregion

    #region 快照管理

    /// <summary>
    /// 列出所有快照记录。
    /// </summary>
    /// <returns>快照记录列表（副本）</returns>
    public List<SnapshotRecord> ListSnapshots()
    {
        lock (_lock)
        {
            return _records.ToList();
        }
    }

    /// <summary>
    /// 获取指定快照记录。
    /// </summary>
    /// <param name="id">快照 ID</param>
    /// <returns>快照记录；不存在返回 null</returns>
    public SnapshotRecord? GetSnapshot(string id)
    {
        lock (_lock)
        {
            return _records.FirstOrDefault(r => r.Id == id);
        }
    }

    /// <summary>
    /// 删除指定快照。
    /// </summary>
    /// <param name="id">快照 ID</param>
    /// <returns>删除成功返回 true；失败返回 false</returns>
    public bool DeleteSnapshot(string id)
    {
        try
        {
            SnapshotRecord? record;
            lock (_lock)
            {
                record = _records.FirstOrDefault(r => r.Id == id);
            }

            if (record == null)
            {
                AuditLogSystem.LogWarning(LogCategory.System,
                    $"删除失败：快照不存在 - {id}");
                return false;
            }

            // 删除快照数据文件
            if (File.Exists(record.DataPath))
            {
                Win32.ResetFileAttributes(record.DataPath);
                File.Delete(record.DataPath);
            }

            lock (_lock)
            {
                _records.Remove(record);
                SaveRecords();
            }

            AuditLogSystem.Log(LogLevel.Info, LogCategory.System,
                $"快照已删除: {record.Description}",
                $"ID={record.Id}, 类型={record.Type}");

            return true;
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, $"删除快照失败: {id}");
            AuditLogSystem.LogError(LogCategory.System,
                $"删除快照失败: {id}", ex.Message);
            return false;
        }
    }

    /// <summary>
    /// 自动清理超过指定天数的快照。
    /// </summary>
    /// <param name="maxAgeDays">最大保留天数（默认 7 天）</param>
    /// <returns>清理的快照数量</returns>
    public int CleanupExpired(int maxAgeDays = 7)
    {
        try
        {
            var cutoff = DateTime.Now.AddDays(-maxAgeDays);
            List<SnapshotRecord> expired;

            lock (_lock)
            {
                expired = _records
                    .Where(r => r.CreatedAt < cutoff)
                    .ToList();
            }

            var deletedCount = 0;
            foreach (var record in expired)
            {
                try
                {
                    if (File.Exists(record.DataPath))
                    {
                        Win32.ResetFileAttributes(record.DataPath);
                        File.Delete(record.DataPath);
                    }

                    lock (_lock)
                    {
                        _records.Remove(record);
                    }
                    deletedCount++;
                }
                catch { }
            }

            if (deletedCount > 0)
            {
                lock (_lock)
                {
                    SaveRecords();
                }

                AuditLogSystem.Log(LogLevel.Info, LogCategory.AutoCleanup,
                    "快照自动清理完成",
                    $"清理 {deletedCount} 个过期快照（超过 {maxAgeDays} 天）");
            }

            return deletedCount;
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, "清理过期快照失败");
            return 0;
        }
    }

    #endregion

    #region 辅助方法

    /// <summary>
    /// 规范化注册表路径，支持 HKLM/HKCU 等缩写。
    /// </summary>
    /// <param name="regPath">原始注册表路径</param>
    /// <returns>完整注册表路径；无法识别返回空字符串</returns>
    private static string NormalizeRegPath(string regPath)
    {
        if (string.IsNullOrWhiteSpace(regPath))
            return "";

        var path = regPath.Trim();

        // 支持缩写形式
        var replacements = new (string Prefix, string Full)[]
        {
            ("HKLM\\", "HKEY_LOCAL_MACHINE\\"),
            ("HKCU\\", "HKEY_CURRENT_USER\\"),
            ("HKCR\\", "HKEY_CLASSES_ROOT\\"),
            ("HKU\\", "HKEY_USERS\\"),
            ("HKCC\\", "HKEY_CURRENT_CONFIG\\")
        };

        foreach (var (prefix, full) in replacements)
        {
            if (path.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            {
                return full + path.Substring(prefix.Length);
            }
        }

        // 如果已经是完整路径，直接返回
        if (path.StartsWith("HKEY_", StringComparison.OrdinalIgnoreCase))
            return path;

        return "";
    }

    /// <summary>
    /// 使用 netsh 命令恢复单条防火墙规则。
    /// </summary>
    /// <param name="rule">防火墙规则</param>
    /// <returns>恢复成功返回 true</returns>
    private static bool RestoreFirewallRule(FirewallRule rule)
    {
        try
        {
            var dir = rule.Direction == "Inbound" ? "in" : "out";
            var action = rule.Action == "Block" ? "block" : "allow";
            var enabled = rule.Enabled ? "yes" : "no";

            var sb = new StringBuilder();
            sb.Append($"advfirewall firewall add rule name=\"{rule.Name}\" ");
            sb.Append($"dir={dir} action={action} ");
            sb.Append($"enable={enabled}");

            if (!string.IsNullOrEmpty(rule.Program) &&
                !string.Equals(rule.Program, "Any", StringComparison.OrdinalIgnoreCase) &&
                !string.Equals(rule.Program, "Any:", StringComparison.OrdinalIgnoreCase))
            {
                sb.Append($" program=\"{rule.Program}\"");
            }

            var psi = new ProcessStartInfo
            {
                FileName = "netsh.exe",
                Arguments = sb.ToString(),
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                StandardOutputEncoding = Encoding.Unicode
            };

            using var proc = Process.Start(psi);
            proc?.WaitForExit(10000);
            return proc?.ExitCode == 0;
        }
        catch { return false; }
    }

    #endregion

    #region 元数据读写

    /// <summary>从 JSON 文件加载快照记录</summary>
    private void LoadRecords()
    {
        try
        {
            if (!File.Exists(_metaDataPath))
            {
                _records = new List<SnapshotRecord>();
                return;
            }

            var json = File.ReadAllText(_metaDataPath, Encoding.UTF8);
            _records = JsonSerializer.Deserialize<List<SnapshotRecord>>(json, JsonOptions)
                       ?? new List<SnapshotRecord>();
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, "加载快照记录失败");
            _records = new List<SnapshotRecord>();
        }
    }

    /// <summary>保存快照记录到 JSON 文件</summary>
    private void SaveRecords()
    {
        try
        {
            var json = JsonSerializer.Serialize(_records, JsonOptions);
            File.WriteAllText(_metaDataPath, json, Encoding.UTF8);
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, "保存快照记录失败");
        }
    }

    #endregion

    #region IDisposable

    /// <summary>
    /// 释放资源，保存元数据。
    /// </summary>
    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;

        try
        {
            lock (_lock)
            {
                SaveRecords();
            }
        }
        catch { }

        GC.SuppressFinalize(this);
    }

    #endregion
}
