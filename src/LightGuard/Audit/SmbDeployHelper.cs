// © 2026 落尘（Luochen） 原创开发 - 保留所有权利

using System.Diagnostics;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using LightGuard.Core;

namespace LightGuard.Audit;

/// <summary>
/// SMB 审计一键部署工具
/// <para>自动化配置：NTFS SACL 审核策略 + 共享目录 SACL 规则 + ETW 文件监控会话 + 事件日志源。</para>
/// <para>P0-2 要求：所有外部进程启动前调用 AntiFalsePositive.ThrottleProcessLaunch() 节流。</para>
/// </summary>
public sealed class SmbDeployHelper
{
    #region 常量

    /// <summary>ETW 文件监控会话名称</summary>
    private const string EtwSessionName = "LightGuardSmbAudit";

    /// <summary>事件日志源名称</summary>
    private const string EventLogSourceName = "LightGuardSmbAudit";

    /// <summary>事件日志名称</summary>
    private const string EventLogName = "Application";

    /// <summary>部署状态记录文件名</summary>
    private const string StateFileName = "smb_deploy_state.json";

    /// <summary>已配置 SACL 的目录记录文件名</summary>
    private const string SaclListFileName = "smb_sacl_dirs.json";

    #endregion

    #region 字段

    private readonly string _stateFilePath;
    private readonly string _saclListFilePath;

    #endregion

    #region 构造函数

    /// <summary>
    /// 初始化 SMB 部署助手
    /// </summary>
    public SmbDeployHelper()
    {
        var stateDir = ConfigManager.GetDataDir();
        _stateFilePath = Path.Combine(stateDir, StateFileName);
        _saclListFilePath = Path.Combine(stateDir, SaclListFileName);
    }

    #endregion

    #region 主部署方法

    /// <summary>
    /// 一键部署 SMB 审计环境
    /// <para>步骤：a. 启用审核策略 b. 配置 SACL c. 启动 ETW d. 创建事件日志源</para>
    /// </summary>
    /// <param name="config">部署配置</param>
    /// <returns>部署结果，包含每一步的状态</returns>
    public SmbDeployResult Deploy(SmbDeployConfig config)
    {
        var sw = Stopwatch.StartNew();
        var result = new SmbDeployResult();
        var errors = new List<string>();

        ErrorReporter.Log("[SmbDeployHelper] 开始一键部署 SMB 审计环境");

        // a. 启用 Windows 审核策略
        try
        {
            result.AuditPolicyEnabled = EnableAuditPolicy();
            if (!result.AuditPolicyEnabled)
                errors.Add("启用 NTFS 审核策略失败（auditpol 执行失败，可能需要管理员权限）");
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, "[SmbDeployHelper] 启用审核策略异常");
            errors.Add($"启用审核策略异常: {ex.Message}");
        }

        // b. 配置 SACL 审核规则
        try
        {
            int saclOkCount = 0;
            var auditUsers = config.AuditAllUsers
                ? new[] { "Everyone", @"BUILTIN\Users" }
                : Array.Empty<string>();

            foreach (var dir in config.SharedDirectories)
            {
                if (string.IsNullOrWhiteSpace(dir)) continue;
                if (ConfigureSacl(dir, auditUsers))
                    saclOkCount++;
                else
                    errors.Add($"配置 SACL 失败: {dir}");
            }

            result.SaclConfigured = saclOkCount > 0;
            SaveSaclDirectories(config.SharedDirectories
                .Where(d => !string.IsNullOrWhiteSpace(d))
                .ToList());
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, "[SmbDeployHelper] 配置 SACL 异常");
            errors.Add($"配置 SACL 异常: {ex.Message}");
        }

        // c. 启动 ETW 文件监控会话
        if (config.EnableEtwMonitor)
        {
            try
            {
                result.EtwStarted = StartEtwMonitoring(
                    config.SharedDirectories.Where(d => !string.IsNullOrWhiteSpace(d)).ToArray());
                if (!result.EtwStarted)
                    errors.Add("启动 ETW 文件监控会话失败");
            }
            catch (Exception ex)
            {
                ErrorReporter.Report(ex, "[SmbDeployHelper] 启动 ETW 异常");
                errors.Add($"启动 ETW 异常: {ex.Message}");
            }
        }
        else
        {
            result.EtwStarted = false;
        }

        // d. 创建事件日志源
        try
        {
            result.EventLogCreated = CreateEventLogSource();
            if (!result.EventLogCreated)
                errors.Add("创建事件日志源失败");
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, "[SmbDeployHelper] 创建事件日志源异常");
            errors.Add($"创建事件日志源异常: {ex.Message}");
        }

        // e. 记录部署时间
        SaveLastDeployTime(DateTime.Now);

        result.Errors = errors;
        result.Success = result.AuditPolicyEnabled &&
                         result.SaclConfigured &&
                         (!config.EnableEtwMonitor || result.EtwStarted) &&
                         result.EventLogCreated;
        sw.Stop();
        result.Duration = sw.Elapsed;

        ErrorReporter.Log(
            $"[SmbDeployHelper] 部署完成: Success={result.Success}, " +
            $"耗时={result.Duration.TotalMilliseconds:F0}ms, 错误数={errors.Count}");

        return result;
    }

    #endregion

    #region 审核策略

    /// <summary>
    /// 启用 NTFS SACL 审核策略（通过 auditpol 开启文件系统成功/失败审核）
    /// </summary>
    /// <returns>是否成功</returns>
    public bool EnableAuditPolicy()
    {
        try
        {
            // P0-2: 进程启动前节流
            AntiFalsePositive.ThrottleProcessLaunch();

            var psi = new ProcessStartInfo
            {
                FileName = "auditpol.exe",
                Arguments = "/set /subcategory:\"File System\" /success:enable /failure:enable",
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                StandardOutputEncoding = Encoding.Unicode
            };

            using var proc = Process.Start(psi);
            if (proc == null)
            {
                ErrorReporter.Log("[SmbDeployHelper] auditpol 启动失败：进程为空", "ERROR");
                return false;
            }
            proc.WaitForExit(10000);

            var success = proc.ExitCode == 0;
            ErrorReporter.Log(
                $"[SmbDeployHelper] auditpol 文件系统审核策略启用: {(success ? "成功" : "失败")}");
            return success;
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, "[SmbDeployHelper] EnableAuditPolicy 异常");
            return false;
        }
    }

    /// <summary>
    /// 查询文件系统审核策略是否已启用
    /// </summary>
    private bool IsAuditPolicyEnabled()
    {
        try
        {
            AntiFalsePositive.ThrottleProcessLaunch();

            var psi = new ProcessStartInfo
            {
                FileName = "auditpol.exe",
                Arguments = "/get /subcategory:\"File System\"",
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                StandardOutputEncoding = Encoding.Unicode
            };

            using var proc = Process.Start(psi);
            if (proc == null) return false;
            var output = proc.StandardOutput.ReadToEnd();
            proc.WaitForExit(10000);

            // 输出中包含 "Success" 表示已启用成功审核
            return output.Contains("Success", StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }
    }

    #endregion

    #region SACL 配置

    /// <summary>
    /// 配置目录的 SACL 审核规则
    /// <para>为指定用户添加审核规则：读取、写入、删除、修改、创建文件、删除子目录及文件。</para>
    /// <para>审核规则应用于 Everyone 和 Users 组，同时包含成功和失败审核。</para>
    /// </summary>
    /// <param name="dirPath">目录路径</param>
    /// <param name="auditUsers">需审核的用户/组名称数组（如 Everyone, BUILTIN\Users）</param>
    /// <returns>是否配置成功</returns>
    public bool ConfigureSacl(string dirPath, string[] auditUsers)
    {
        if (string.IsNullOrWhiteSpace(dirPath))
            return false;

        if (!Directory.Exists(dirPath))
        {
            ErrorReporter.Log($"[SmbDeployHelper] SACL 配置失败：目录不存在 {dirPath}", "ERROR");
            return false;
        }

        try
        {
            var di = new DirectoryInfo(dirPath);
            var ds = di.GetAccessControl(AccessControlSections.Audit);

            // 默认审核用户：Everyone + Users
            var users = (auditUsers == null || auditUsers.Length == 0)
                ? new[] { "Everyone", @"BUILTIN\Users" }
                : auditUsers;

            var rightsToAdd = new[]
            {
                FileSystemRights.Read,
                FileSystemRights.Write,
                FileSystemRights.Delete,
                FileSystemRights.Modify,
                FileSystemRights.CreateFiles,
                FileSystemRights.DeleteSubdirectoriesAndFiles
            };

            foreach (var userName in users)
            {
                if (string.IsNullOrWhiteSpace(userName)) continue;

                NTAccount identity;
                try
                {
                    identity = new NTAccount(userName);
                    // 验证身份可翻译为 SID
                    identity.Translate(typeof(SecurityIdentifier));
                }
                catch
                {
                    ErrorReporter.Log(
                        $"[SmbDeployHelper] 无法解析用户身份: {userName}，跳过", "WARN");
                    continue;
                }

                foreach (var right in rightsToAdd)
                {
                    // 审核成功
                    var ruleSuccess = new FileSystemAuditRule(
                        identity, right,
                        InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                        PropagationFlags.None,
                        AuditFlags.Success);

                    // 审核失败
                    var ruleFailure = new FileSystemAuditRule(
                        identity, right,
                        InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                        PropagationFlags.None,
                        AuditFlags.Failure);

                    ds.AddAuditRule(ruleSuccess);
                    ds.AddAuditRule(ruleFailure);
                }
            }

            di.SetAccessControl(ds);
            ErrorReporter.Log(
                $"[SmbDeployHelper] SACL 配置完成: {dirPath}" +
                $"（审核用户: {string.Join(", ", users)}）");
            return true;
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, $"[SmbDeployHelper] ConfigureSacl 异常: {dirPath}");
            return false;
        }
    }

    /// <summary>
    /// 移除目录的所有 SACL 审核规则
    /// </summary>
    private bool RemoveSacl(string dirPath)
    {
        if (string.IsNullOrWhiteSpace(dirPath) || !Directory.Exists(dirPath))
            return false;

        try
        {
            var di = new DirectoryInfo(dirPath);
            var ds = di.GetAccessControl(AccessControlSections.Audit);

            var auditRules = ds.GetAuditRules(true, true, typeof(NTAccount));
            foreach (FileSystemAuditRule rule in auditRules)
            {
                ds.RemoveAuditRuleSpecific(rule);
            }

            di.SetAccessControl(ds);
            ErrorReporter.Log($"[SmbDeployHelper] SACL 审核规则已移除: {dirPath}");
            return true;
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, $"[SmbDeployHelper] RemoveSacl 异常: {dirPath}");
            return false;
        }
    }

    #endregion

    #region ETW 文件监控

    /// <summary>
    /// 启动 ETW 文件监控会话
    /// <para>使用 logman 创建实时 ETW 跟踪会话，订阅 Kernel-File 提供程序。</para>
    /// </summary>
    /// <param name="watchDirs">监控目录列表（用于日志记录，实际监控范围由 ETW 提供程序决定）</param>
    /// <returns>是否启动成功</returns>
    public bool StartEtwMonitoring(string[] watchDirs)
    {
        try
        {
            // P0-2: 高危操作延时初始化 + ETW 节流
            AntiFalsePositive.DelayedInit("SmbEtwMonitor");
            AntiFalsePositive.ThrottleEtw();
            AntiFalsePositive.ThrottleProcessLaunch();

            // 先停止已存在的同名会话（忽略错误）
            StopEtwSession();

            var outputDir = Path.Combine(ConfigManager.GetDataDir(), "etw");
            Directory.CreateDirectory(outputDir);
            var outputPath = Path.Combine(outputDir, "smb_file_monitor.etl");

            // 使用 logman 启动 Kernel-File 提供程序的实时会话
            var psi = new ProcessStartInfo
            {
                FileName = "logman.exe",
                Arguments =
                    $"start \"{EtwSessionName}\" -p Microsoft-Windows-Kernel-File -o \"{outputPath}\" -ets",
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };

            using var proc = Process.Start(psi);
            if (proc == null)
            {
                ErrorReporter.Log("[SmbDeployHelper] logman 启动失败：进程为空", "ERROR");
                return false;
            }
            proc.WaitForExit(10000);

            var success = proc.ExitCode == 0;
            if (success)
            {
                ErrorReporter.Log(
                    $"[SmbDeployHelper] ETW 文件监控会话已启动: {EtwSessionName}, " +
                    $"监控目录: {string.Join(", ", watchDirs)}");
            }
            else
            {
                var err = proc.StandardError.ReadToEnd();
                ErrorReporter.Log($"[SmbDeployHelper] ETW 会话启动失败: {err}", "ERROR");
            }

            return success;
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, "[SmbDeployHelper] StartEtwMonitoring 异常");
            return false;
        }
    }

    /// <summary>
    /// 停止 ETW 文件监控会话
    /// </summary>
    private bool StopEtwSession()
    {
        try
        {
            AntiFalsePositive.ThrottleProcessLaunch();

            var psi = new ProcessStartInfo
            {
                FileName = "logman.exe",
                Arguments = $"stop \"{EtwSessionName}\" -ets",
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };

            using var proc = Process.Start(psi);
            proc?.WaitForExit(5000);
            return proc?.ExitCode == 0;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// 检查 ETW 会话是否正在运行
    /// </summary>
    private bool IsEtwRunning()
    {
        try
        {
            AntiFalsePositive.ThrottleProcessLaunch();

            var psi = new ProcessStartInfo
            {
                FileName = "logman.exe",
                Arguments = "query",
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true
            };

            using var proc = Process.Start(psi);
            if (proc == null) return false;
            var output = proc.StandardOutput.ReadToEnd();
            proc.WaitForExit(5000);

            return output.Contains(EtwSessionName, StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }
    }

    #endregion

    #region 事件日志源

    /// <summary>
    /// 创建事件日志源 "LightGuardSmbAudit"（如果不存在）
    /// <para>创建后可通过 EventLog.WriteEntry 写入 Windows 事件日志。</para>
    /// </summary>
    /// <returns>是否成功（已存在也返回 true）</returns>
    public bool CreateEventLogSource()
    {
        try
        {
            if (EventLog.SourceExists(EventLogSourceName))
            {
                ErrorReporter.Log($"[SmbDeployHelper] 事件日志源已存在: {EventLogSourceName}");
                return true;
            }

            // 创建事件日志源需要管理员权限
            EventLog.CreateEventSource(EventLogSourceName, EventLogName);
            ErrorReporter.Log(
                $"[SmbDeployHelper] 事件日志源已创建: {EventLogSourceName} -> {EventLogName}");
            return true;
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, "[SmbDeployHelper] CreateEventLogSource 异常");
            return false;
        }
    }

    /// <summary>
    /// 检查事件日志源是否存在
    /// </summary>
    private static bool IsEventLogSourceExists()
    {
        try
        {
            return EventLog.SourceExists(EventLogSourceName);
        }
        catch
        {
            return false;
        }
    }

    #endregion

    #region 部署状态查询

    /// <summary>
    /// 获取当前部署状态
    /// <para>检查审核策略、SACL 目录数、ETW 运行状态、事件日志源是否存在。</para>
    /// </summary>
    /// <returns>部署状态快照</returns>
    public SmbDeployStatus GetDeployStatus()
    {
        try
        {
            var status = new SmbDeployStatus
            {
                AuditPolicyEnabled = IsAuditPolicyEnabled(),
                SaclDirectoriesCount = LoadSaclDirectories().Count,
                EtwRunning = IsEtwRunning(),
                EventLogSourceExists = IsEventLogSourceExists(),
                LastDeployTime = LoadLastDeployTime()
            };
            return status;
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, "[SmbDeployHelper] GetDeployStatus 异常");
            return new SmbDeployStatus();
        }
    }

    #endregion

    #region 撤销部署

    /// <summary>
    /// 撤销 SMB 审计部署
    /// <para>移除 SACL 规则、停止 ETW 会话、重置审核策略、清除状态记录。</para>
    /// </summary>
    /// <returns>是否全部撤销成功</returns>
    public bool UndoDeployment()
    {
        try
        {
            ErrorReporter.Log("[SmbDeployHelper] 开始撤销 SMB 审计部署");
            bool allOk = true;

            // 1. 移除 SACL 规则
            var saclDirs = LoadSaclDirectories();
            foreach (var dir in saclDirs)
            {
                if (!RemoveSacl(dir))
                    allOk = false;
            }
            SaveSaclDirectories(new List<string>());

            // 2. 停止 ETW 会话
            if (!StopEtwSession())
            {
                // ETW 会话可能本来就没运行，不算严重错误
                ErrorReporter.Log("[SmbDeployHelper] ETW 会话停止失败或未运行", "WARN");
            }

            // 3. 重置审核策略
            AntiFalsePositive.ThrottleProcessLaunch();
            var psi = new ProcessStartInfo
            {
                FileName = "auditpol.exe",
                Arguments = "/set /subcategory:\"File System\" /success:disable /failure:disable",
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                StandardOutputEncoding = Encoding.Unicode
            };
            using var proc = Process.Start(psi);
            proc?.WaitForExit(10000);
            if (proc is null || proc.ExitCode != 0)
            {
                allOk = false;
                ErrorReporter.Log("[SmbDeployHelper] 重置审核策略失败", "ERROR");
            }

            // 4. 清除部署时间记录
            try { if (File.Exists(_stateFilePath)) File.Delete(_stateFilePath); } catch { }

            ErrorReporter.Log($"[SmbDeployHelper] 撤销部署完成: {(allOk ? "全部成功" : "部分失败")}");
            return allOk;
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, "[SmbDeployHelper] UndoDeployment 异常");
            return false;
        }
    }

    #endregion

    #region 状态持久化

    /// <summary>
    /// 保存上次部署时间到状态文件
    /// </summary>
    private void SaveLastDeployTime(DateTime time)
    {
        try
        {
            var json = JsonSerializer.Serialize(new { LastDeployTime = time });
            File.WriteAllText(_stateFilePath, json);
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, "[SmbDeployHelper] SaveLastDeployTime 异常");
        }
    }

    /// <summary>
    /// 从状态文件加载上次部署时间
    /// </summary>
    private DateTime? LoadLastDeployTime()
    {
        try
        {
            if (!File.Exists(_stateFilePath)) return null;
            var json = File.ReadAllText(_stateFilePath);
            using var doc = JsonDocument.Parse(json);
            if (doc.RootElement.TryGetProperty("LastDeployTime", out var prop))
                return prop.GetDateTime();
            return null;
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// 保存已配置 SACL 的目录列表
    /// </summary>
    private void SaveSaclDirectories(List<string> dirs)
    {
        try
        {
            var json = JsonSerializer.Serialize(dirs);
            File.WriteAllText(_saclListFilePath, json);
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, "[SmbDeployHelper] SaveSaclDirectories 异常");
        }
    }

    /// <summary>
    /// 加载已配置 SACL 的目录列表
    /// </summary>
    private List<string> LoadSaclDirectories()
    {
        try
        {
            if (!File.Exists(_saclListFilePath)) return new List<string>();
            var json = File.ReadAllText(_saclListFilePath);
            return JsonSerializer.Deserialize<List<string>>(json) ?? new List<string>();
        }
        catch
        {
            return new List<string>();
        }
    }

    #endregion
}

#region 配置与结果类型

/// <summary>
/// SMB 审计部署配置
/// </summary>
public sealed class SmbDeployConfig
{
    /// <summary>需要配置 SACL 审核的共享目录列表</summary>
    public List<string> SharedDirectories { get; set; } = new();

    /// <summary>是否审核所有用户（true: Everyone + Users 组）</summary>
    public bool AuditAllUsers { get; set; } = true;

    /// <summary>是否启用 ETW 文件监控</summary>
    public bool EnableEtwMonitor { get; set; } = true;

    /// <summary>日志保留天数</summary>
    public int LogRetentionDays { get; set; } = 90;
}

/// <summary>
/// SMB 审计部署结果
/// </summary>
public sealed class SmbDeployResult
{
    /// <summary>整体是否成功</summary>
    public bool Success { get; set; }

    /// <summary>审核策略是否已启用</summary>
    public bool AuditPolicyEnabled { get; set; }

    /// <summary>SACL 是否已配置</summary>
    public bool SaclConfigured { get; set; }

    /// <summary>ETW 会话是否已启动</summary>
    public bool EtwStarted { get; set; }

    /// <summary>事件日志源是否已创建</summary>
    public bool EventLogCreated { get; set; }

    /// <summary>错误信息列表</summary>
    public List<string> Errors { get; set; } = new();

    /// <summary>部署耗时</summary>
    public TimeSpan Duration { get; set; }

    public override string ToString()
    {
        return $"部署结果: Success={Success}, 审核策略={AuditPolicyEnabled}, " +
               $"SACL={SaclConfigured}, ETW={EtwStarted}, 事件日志={EventLogCreated}, " +
               $"耗时={Duration.TotalMilliseconds:F0}ms, 错误数={Errors.Count}";
    }
}

/// <summary>
/// SMB 审计部署状态
/// </summary>
public sealed class SmbDeployStatus
{
    /// <summary>审核策略是否已启用</summary>
    public bool AuditPolicyEnabled { get; set; }

    /// <summary>已配置 SACL 的目录数量</summary>
    public int SaclDirectoriesCount { get; set; }

    /// <summary>ETW 会话是否正在运行</summary>
    public bool EtwRunning { get; set; }

    /// <summary>事件日志源是否存在</summary>
    public bool EventLogSourceExists { get; set; }

    /// <summary>上次部署时间</summary>
    public DateTime? LastDeployTime { get; set; }

    public override string ToString()
    {
        return $"部署状态: 审核策略={AuditPolicyEnabled}, SACL目录数={SaclDirectoriesCount}, " +
               $"ETW运行={EtwRunning}, 事件日志源={EventLogSourceExists}, " +
               $"上次部署={LastDeployTime:yyyy-MM-dd HH:mm:ss}";
    }
}

#endregion
