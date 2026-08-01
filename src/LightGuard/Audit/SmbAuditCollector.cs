// © 2026 落尘（Luochen） 原创开发 - 保留所有权利

using System.Diagnostics;
using System.Diagnostics.Tracing;
using System.Management;
using System.Text;
using LightGuard.Core;

// 项目启用 WinForms（System.Windows.Forms.Timer）会与 System.Threading.Timer 冲突，
// 此处显式别名为线程池定时器，用于事件轮询调度。
using Timer = System.Threading.Timer;

namespace LightGuard.Audit;

/// <summary>
/// SMB 文件服务器审计采集器
/// <para>双采集融合：NTFS SACL 安全事件日志（EventLog）+ ETW 实时事件（EventListener）。</para>
/// <para>监控行为：SMB 远程登录、文件读取/写入/修改/删除/移动/重命名、权限篡改、越权访问。</para>
/// <para>支持一键配置服务器安全策略（auditpol 开启文件审核）。</para>
/// </summary>
public sealed class SmbAuditCollector : IDisposable
{
    #region 常量

    /// <summary>安全事件日志名称</summary>
    private const string SecurityLogName = "Security";

    /// <summary>系统事件日志名称</summary>
    private const string SystemLogName = "System";

    /// <summary>SMB 相关事件日志名称</summary>
    private const string SmbServerLogName = "Microsoft-Windows-SmbServer/Operational";

    /// <summary>事件轮询间隔（秒）</summary>
    private const int PollIntervalSec = 3;

    /// <summary>最大审计记录保留数</summary>
    private const int MaxAuditRecords = 10000;

    /// <summary>安全审核事件 ID 映射</summary>
    private static readonly Dictionary<int, SmbOperation> EventIdToOperation = new()
    {
        { 4624, SmbOperation.Login },        // 成功登录
        { 4625, SmbOperation.AccessDenied }, // 登录失败（越权访问）
        { 4663, SmbOperation.Read },         // 尝试访问对象
        { 4656, SmbOperation.Read },         // 请求对象句柄
        { 4660, SmbOperation.Delete },        // 对象已删除
        { 4670, SmbOperation.PermissionChange }, // 权限变更
    };

    #endregion

    #region 字段

    private readonly object _lock = new();
    private readonly List<SmbAuditEntry> _records = new();

    private EventLog? _securityLog;
    private SmbEventListener? _etwListener;
    private Timer? _pollTimer;
    private long _lastReadIndex;
    private bool _isEnabled;

    #endregion

    #region 事件

    /// <summary>
    /// 新审计记录产生时触发
    /// </summary>
    public event Action<SmbAuditEntry>? AuditEntryRecorded;

    #endregion

    #region 生命周期

    /// <summary>
    /// 启动 SMB 审计采集
    /// </summary>
    public void Start()
    {
        if (_isEnabled) return;
        _isEnabled = true;

        // 启动安全事件日志监听
        try
        {
            _securityLog = new EventLog(SecurityLogName);
            _securityLog.EntryWritten += OnSecurityEntryWritten;
            _securityLog.EnableRaisingEvents = true;
            _lastReadIndex = _securityLog.Entries.Count > 0
                ? _securityLog.Entries[_securityLog.Entries.Count - 1].Index
                : 0;
            ErrorReporter.Log("[SmbAuditCollector] 安全事件日志监听已启动");
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, "[SmbAuditCollector] 安全事件日志监听启动失败，降级为轮询模式");
        }

        // 启动 ETW 实时事件监听
        try
        {
            _etwListener = new SmbEventListener();
            _etwListener.OnSmbEvent += OnEtwSmbEvent;
            ErrorReporter.Log("[SmbAuditCollector] ETW SMB 事件监听已启动");
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, "[SmbAuditCollector] ETW 监听启动失败");
        }

        // 启动轮询定时器（补充实时事件遗漏的记录）
        _pollTimer = new Timer(
            callback: _ => PollSecurityLog(),
            state: null,
            dueTime: TimeSpan.FromSeconds(PollIntervalSec),
            period: TimeSpan.FromSeconds(PollIntervalSec));

        ErrorReporter.Log("[SmbAuditCollector] SMB 审计采集器已启动");
    }

    /// <summary>
    /// 停止 SMB 审计采集
    /// </summary>
    public void Stop()
    {
        if (!_isEnabled) return;
        _isEnabled = false;

        try
        {
            if (_securityLog != null)
            {
                _securityLog.EnableRaisingEvents = false;
                _securityLog.EntryWritten -= OnSecurityEntryWritten;
                _securityLog.Dispose();
            }
        }
        catch { }
        _securityLog = null;

        try { _etwListener?.Dispose(); } catch { }
        _etwListener = null;

        _pollTimer?.Dispose();
        _pollTimer = null;

        ErrorReporter.Log("[SmbAuditCollector] SMB 审计采集器已停止");
    }

    #endregion

    #region 安全事件日志处理

    /// <summary>
    /// 安全事件日志写入回调
    /// </summary>
    private void OnSecurityEntryWritten(object sender, EntryWrittenEventArgs e)
    {
        try
        {
            var entry = e.Entry;
            if (entry == null) return;

            var entryObj = ParseSecurityEvent(entry);
            if (entryObj != null)
            {
                AddRecord(entryObj);
            }
        }
        catch { }
    }

    /// <summary>
    /// 轮询安全事件日志（补充实时事件遗漏）
    /// </summary>
    private void PollSecurityLog()
    {
        if (!_isEnabled || _securityLog == null) return;

        try
        {
            var entries = _securityLog.Entries;
            if (entries.Count == 0) return;

            // 从上次读取位置开始扫描新事件
            for (int i = entries.Count - 1; i >= 0; i--)
            {
                try
                {
                    var entry = entries[i];
                    if (entry.Index <= _lastReadIndex) break;

                    var entryObj = ParseSecurityEvent(entry);
                    if (entryObj != null)
                    {
                        AddRecord(entryObj);
                    }
                }
                catch { }
            }

            _lastReadIndex = entries[entries.Count - 1].Index;
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, "[SmbAuditCollector] 轮询安全日志异常");
        }
    }

    /// <summary>
    /// 解析安全事件日志条目为 SMB 审计记录
    /// </summary>
    private SmbAuditEntry? ParseSecurityEvent(EventLogEntry entry)
    {
        try
        {
            if (!EventIdToOperation.TryGetValue((int)entry.InstanceId, out var operation))
                return null;

            var strings = entry.ReplacementStrings;
            if (strings == null || strings.Length == 0) return null;

            var record = new SmbAuditEntry
            {
                Time = entry.TimeGenerated,
                Operation = operation,
                RiskTag = DetermineRiskTag(operation, entry)
            };

            // 根据事件 ID 解析不同字段
            switch (entry.InstanceId)
            {
                case 4624: // 成功登录
                case 4625: // 登录失败
                    record.UserName = GetStringSafe(strings, 5);
                    record.ClientIp = GetStringSafe(strings, 18);
                    record.HostName = GetStringSafe(strings, 11);
                    record.IsRemote = IsRemoteLogon(GetStringSafe(strings, 8));
                    record.FilePath = "";
                    record.RiskTag = entry.InstanceId == 4625 ? "登录失败" : "登录成功";
                    break;

                case 4663: // 尝试访问对象
                case 4656: // 请求对象句柄
                    record.UserName = GetStringSafe(strings, 1);
                    record.ClientIp = ExtractIpFromLogonId(GetStringSafe(strings, 3));
                    record.HostName = GetStringSafe(strings, 2);
                    record.FilePath = GetStringSafe(strings, 6);
                    record.IsRemote = true;
                    // 根据访问掩码判断操作类型
                    var accessMask = GetStringSafe(strings, 4);
                    if (!string.IsNullOrEmpty(accessMask))
                    {
                        record.Operation = RefineOperationFromAccessMask(accessMask, operation);
                    }
                    break;

                case 4660: // 对象已删除
                    record.UserName = GetStringSafe(strings, 1);
                    record.HostName = GetStringSafe(strings, 2);
                    record.FilePath = GetStringSafe(strings, 6);
                    record.Operation = SmbOperation.Delete;
                    record.IsRemote = true;
                    record.RiskTag = "文件删除";
                    break;

                case 4670: // 权限变更
                    record.UserName = GetStringSafe(strings, 1);
                    record.HostName = GetStringSafe(strings, 2);
                    record.FilePath = GetStringSafe(strings, 6);
                    record.Operation = SmbOperation.PermissionChange;
                    record.IsRemote = true;
                    record.RiskTag = "权限篡改";
                    break;
            }

            return record;
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// 安全获取 ReplacementStrings 中的指定索引值
    /// </summary>
    private static string GetStringSafe(string[]? strings, int index)
    {
        if (strings == null || index < 0 || index >= strings.Length)
            return "";
        return strings[index] ?? "";
    }

    /// <summary>
    /// 根据访问掩码细化操作类型
    /// </summary>
    private static SmbOperation RefineOperationFromAccessMask(string accessMask, SmbOperation defaultOp)
    {
        try
        {
            var mask = Convert.ToUInt32(accessMask, 16);
            // 0x2 = Read, 0x4 = Write/Modify, 0x6 = Read+Write, 0x10000 = Delete
            if ((mask & 0x10000) != 0) return SmbOperation.Delete;
            if ((mask & 0x6) == 0x6) return SmbOperation.Modify;
            if ((mask & 0x4) != 0) return SmbOperation.Write;
            if ((mask & 0x2) != 0) return SmbOperation.Read;
            return defaultOp;
        }
        catch
        {
            return defaultOp;
        }
    }

    /// <summary>
    /// 判断是否为远程登录（Logon Type 3 = Network/SMB）
    /// </summary>
    private static bool IsRemoteLogon(string logonType)
    {
        return logonType == "3" || logonType == "10" || logonType == "11";
    }

    /// <summary>
    /// 从 LogonId 提取 IP（简化实现，实际需查询登录会话表）
    /// </summary>
    private static string ExtractIpFromLogonId(string logonId)
    {
        // 简化：LogonId 字段不包含 IP，这里返回空，实际 IP 在其他字段
        return "";
    }

    /// <summary>
    /// 根据操作类型确定风险标签
    /// </summary>
    private static string DetermineRiskTag(SmbOperation operation, EventLogEntry entry)
    {
        return operation switch
        {
            SmbOperation.Login => "登录",
            SmbOperation.AccessDenied => "越权访问",
            SmbOperation.Delete => "文件删除",
            SmbOperation.PermissionChange => "权限篡改",
            SmbOperation.Write => "文件写入",
            SmbOperation.Modify => "文件修改",
            SmbOperation.Move => "文件移动",
            SmbOperation.Rename => "文件重命名",
            _ => ""
        };
    }

    #endregion

    #region ETW SMB 事件处理

    /// <summary>
    /// ETW SMB 事件回调
    /// </summary>
    private void OnEtwSmbEvent(EventWrittenEventArgs eventData)
    {
        if (!_isEnabled || eventData == null) return;

        try
        {
            var record = new SmbAuditEntry
            {
                Time = DateTime.Now,
                Operation = SmbOperation.Read,
                IsRemote = true,
                RiskTag = "ETW实时"
            };

            var payload = eventData.Payload;
            if (payload != null)
            {
                // 尝试从 payload 提取信息
                foreach (var item in payload)
                {
                    var str = item?.ToString() ?? "";
                    if (str.Contains('\\') || str.Contains('/'))
                    {
                        record.FilePath = str;
                    }
                    else if (str.Contains('@') || str.Split('.').Length == 4)
                    {
                        // 可能是 IP 地址
                        record.ClientIp = str;
                    }
                }
            }

            // 根据事件名确定操作类型
            var eventName = (eventData.EventName ?? "").ToLowerInvariant();
            if (eventName.Contains("read"))
                record.Operation = SmbOperation.Read;
            else if (eventName.Contains("write"))
                record.Operation = SmbOperation.Write;
            else if (eventName.Contains("delete"))
                record.Operation = SmbOperation.Delete;
            else if (eventName.Contains("rename") || eventName.Contains("move"))
                record.Operation = SmbOperation.Rename;

            if (!string.IsNullOrEmpty(record.FilePath))
            {
                AddRecord(record);
            }
        }
        catch { }
    }

    #endregion

    #region 记录管理

    /// <summary>
    /// 添加审计记录
    /// </summary>
    private void AddRecord(SmbAuditEntry record)
    {
        lock (_lock)
        {
            _records.Add(record);
            if (_records.Count > MaxAuditRecords)
            {
                _records.RemoveAt(0);
            }
        }

        AuditEntryRecorded?.Invoke(record);
    }

    /// <summary>
    /// 获取所有审计记录
    /// </summary>
    public List<SmbAuditEntry> GetRecords()
    {
        lock (_lock) return _records.ToList();
    }

    /// <summary>
    /// 获取最近 N 条审计记录
    /// </summary>
    public List<SmbAuditEntry> GetRecentRecords(int count)
    {
        lock (_lock)
        {
            var skip = Math.Max(0, _records.Count - count);
            return _records.Skip(skip).ToList();
        }
    }

    /// <summary>
    /// 获取审计记录总数
    /// </summary>
    public int GetRecordCount()
    {
        lock (_lock) return _records.Count;
    }

    /// <summary>
    /// 清空审计记录
    /// </summary>
    public void ClearRecords()
    {
        lock (_lock) _records.Clear();
    }

    #endregion

    #region 安全策略配置

    /// <summary>
    /// 一键配置服务器安全策略（使用 auditpol 开启文件审核）
    /// </summary>
    /// <returns>配置是否成功</returns>
    public bool ConfigureSecurityPolicy()
    {
        try
        {
            var commands = new[]
            {
                "auditpol /set /subcategory:\"File System\" /success:enable /failure:enable",
                "auditpol /set /subcategory:\"Logon\" /success:enable /failure:enable",
                "auditpol /set /subcategory:\"Logoff\" /success:enable /failure:enable",
                "auditpol /set /subcategory:\"File System\" /success:enable /failure:enable",
                "auditpol /set /subcategory:\"Sensitive Privilege Use\" /success:enable /failure:enable",
                "auditpol /set /subcategory:\"Authorization Policy Change\" /success:enable /failure:enable",
            };

            bool allSuccess = true;
            foreach (var cmd in commands)
            {
                var success = RunAuditPolCommand(cmd);
                if (!success) allSuccess = false;
            }

            ErrorReporter.Log(allSuccess
                ? "[SmbAuditCollector] 服务器安全策略配置完成（auditpol 全部成功）"
                : "[SmbAuditCollector] 服务器安全策略配置部分失败");

            return allSuccess;
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, "[SmbAuditCollector] 配置安全策略异常");
            return false;
        }
    }

    /// <summary>
    /// 查询当前审核策略状态
    /// </summary>
    public string GetAuditPolicyStatus()
    {
        try
        {
            var output = RunAuditPolCommandWithOutput("auditpol /get /category:*");
            return output;
        }
        catch (Exception ex)
        {
            return $"查询失败: {ex.Message}";
        }
    }

    /// <summary>
    /// 执行 auditpol 命令
    /// </summary>
    private static bool RunAuditPolCommand(string args)
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "auditpol.exe",
                Arguments = args,
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
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// 执行 auditpol 命令并获取输出
    /// </summary>
    private static string RunAuditPolCommandWithOutput(string args)
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "auditpol.exe",
                Arguments = args,
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                StandardOutputEncoding = Encoding.Unicode
            };

            using var proc = Process.Start(psi);
            var output = proc?.StandardOutput.ReadToEnd() ?? "";
            proc?.WaitForExit(10000);
            return output;
        }
        catch (Exception ex)
        {
            return $"执行失败: {ex.Message}";
        }
    }

    #endregion

    #region IDisposable

    /// <summary>
    /// 释放资源
    /// </summary>
    public void Dispose()
    {
        Stop();
        GC.SuppressFinalize(this);
    }

    #endregion
}

#region ETW 事件监听器

/// <summary>
/// SMB ETW 事件监听器
/// <para>继承 EventListener，订阅 SMB Server / SMB Client 相关 EventSource。</para>
/// </summary>
internal sealed class SmbEventListener : EventListener
{
    /// <summary>SMB 事件转发委托</summary>
    public event Action<EventWrittenEventArgs>? OnSmbEvent;

    protected override void OnEventSourceCreated(EventSource eventSource)
    {
        try
        {
            var name = eventSource.Name;
            if (name.Contains("Smb", StringComparison.OrdinalIgnoreCase) ||
                name.Contains("SMB", StringComparison.OrdinalIgnoreCase) ||
                name.Contains("File", StringComparison.OrdinalIgnoreCase) ||
                name.Contains("Kernel-File", StringComparison.OrdinalIgnoreCase))
            {
                EnableEvents(eventSource, EventLevel.Informational, EventKeywords.All);
            }
        }
        catch { }
    }

    protected override void OnEventWritten(EventWrittenEventArgs eventData)
    {
        try
        {
            OnSmbEvent?.Invoke(eventData);
        }
        catch { }
    }
}

#endregion

#region 数据类型

/// <summary>
/// SMB 审计操作类型枚举
/// </summary>
public enum SmbOperation
{
    /// <summary>SMB 远程登录</summary>
    Login,

    /// <summary>文件读取</summary>
    Read,

    /// <summary>文件写入</summary>
    Write,

    /// <summary>文件修改</summary>
    Modify,

    /// <summary>文件删除</summary>
    Delete,

    /// <summary>批量删除</summary>
    BatchDelete,

    /// <summary>文件移动</summary>
    Move,

    /// <summary>文件重命名</summary>
    Rename,

    /// <summary>权限篡改</summary>
    PermissionChange,

    /// <summary>越权访问（被拒绝）</summary>
    AccessDenied
}

/// <summary>
/// SMB 审计记录
/// </summary>
public sealed class SmbAuditEntry
{
    /// <summary>操作时间</summary>
    public DateTime Time { get; set; }

    /// <summary>用户名</summary>
    public string UserName { get; set; } = "";

    /// <summary>客户端 IP 地址</summary>
    public string ClientIp { get; set; } = "";

    /// <summary>主机名</summary>
    public string HostName { get; set; } = "";

    /// <summary>文件路径</summary>
    public string FilePath { get; set; } = "";

    /// <summary>操作类型</summary>
    public SmbOperation Operation { get; set; }

    /// <summary>是否为远程操作</summary>
    public bool IsRemote { get; set; }

    /// <summary>风险标签</summary>
    public string RiskTag { get; set; } = "";

    public override string ToString()
    {
        return $"[{Time:HH:mm:ss}] {UserName}@{ClientIp} | {Operation} | {FilePath} | {RiskTag}";
    }
}

#endregion
