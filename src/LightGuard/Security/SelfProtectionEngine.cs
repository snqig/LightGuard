// © 2026 落尘（Luochen）原创开发 - 保留所有权利

using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using LightGuard.Core;

// 项目启用 WinForms（System.Windows.Forms.Timer）会与 System.Threading.Timer 冲突，
// 此处显式别名为线程池定时器，用于自我保护周期检查。
using Timer = System.Threading.Timer;

namespace LightGuard.Security;

/// <summary>
/// 自我保护告警级别
/// </summary>
public enum ProtectionLevel
{
    /// <summary>信息级别（常规保护事件）</summary>
    Info,

    /// <summary>警告级别（可疑行为，需关注）</summary>
    Warning,

    /// <summary>严重级别（检测到调试器或二进制篡改，需立即处理）</summary>
    Critical
}

/// <summary>
/// 程序自我保护引擎
/// <para>核心能力：</para>
/// <para>1. 反调试：定期检测 IsDebuggerPresent / CheckRemoteDebuggerPresent，发现调试器附加即告警。</para>
/// <para>2. 进程 DACL 加固：通过 SDDL 对自身进程设置 DACL，仅 SYSTEM 可终止，拒绝非 SYSTEM 进程的 PROCESS_TERMINATE。</para>
/// <para>3. 进程守护看门狗：后台定时器周期检查调试器与可疑注入行为，触发 SelfProtectionAlert 事件。</para>
/// <para>4. 进程缓解策略：通过 SetProcessMitigationPolicy 启用 DEP、ASLR、CFG。</para>
/// <para>5. 自身完整性校验：启动时计算 LightGuard.exe 的 SHA-256 基线哈希，运行中定期校验防止二进制篡改。</para>
/// </summary>
public sealed class SelfProtectionEngine : IDisposable
{
    #region P/Invoke — 反调试

    [DllImport("kernel32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool IsDebuggerPresent();

    [DllImport("kernel32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CheckRemoteDebuggerPresent(IntPtr hProcess, [In, Out] ref bool isPresent);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    #endregion

    #region P/Invoke — 进程缓解策略

    /// <summary>缓解策略：DEP（数据执行保护）</summary>
    private const int ProcessDEPPolicy = 0;

    /// <summary>缓解策略：ASLR（地址空间布局随机化）</summary>
    private const int ProcessASLRPolicy = 1;

    /// <summary>缓解策略：CFG（控制流防护）</summary>
    private const int ProcessControlFlowGuardPolicy = 6;

    /// <summary>DEP 缓解策略结构体：DWORD Flags + BYTE Permanent</summary>
    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESS_MITIGATION_DEP_POLICY
    {
        public uint Flags;
        public byte Permanent;
    }

    /// <summary>ASLR 缓解策略结构体：DWORD Flags</summary>
    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESS_MITIGATION_ASLR_POLICY
    {
        public uint Flags;
    }

    /// <summary>CFG 缓解策略结构体：DWORD Flags</summary>
    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY
    {
        public uint Flags;
    }

    [DllImport("kernel32.dll", SetLastError = true, EntryPoint = "SetProcessMitigationPolicy")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetProcessMitigationPolicyDep(
        int policy, ref PROCESS_MITIGATION_DEP_POLICY lpArgs, IntPtr dwLength);

    [DllImport("kernel32.dll", SetLastError = true, EntryPoint = "SetProcessMitigationPolicy")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetProcessMitigationPolicyAslr(
        int policy, ref PROCESS_MITIGATION_ASLR_POLICY lpArgs, IntPtr dwLength);

    [DllImport("kernel32.dll", SetLastError = true, EntryPoint = "SetProcessMitigationPolicy")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetProcessMitigationPolicyCfg(
        int policy, ref PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY lpArgs, IntPtr dwLength);

    #endregion

    #region P/Invoke — 进程 DACL 加固

    private const uint READ_CONTROL = 0x00080000;
    private const uint WRITE_DAC = 0x00040000;

    /// <summary>DACL 安全信息标志</summary>
    private const int DACL_SECURITY_INFORMATION = 0x00000004;

    /// <summary>SDDL 修订版本</summary>
    private const int SDDL_REVISION_1 = 1;

    /// <summary>当前进程伪句柄（-1）</summary>
    private static readonly IntPtr PseudoProcessHandle = new(-1);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetKernelObjectSecurity(
        IntPtr handle, int securityInformation, IntPtr pSecurityDescriptor);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(
        string sddl, int revision, out IntPtr pSecurityDescriptor, IntPtr pSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr LocalFree(IntPtr hMem);

    #endregion

    #region 常量

    /// <summary>保护检查间隔（毫秒，10 秒）</summary>
    private const int CheckIntervalMs = 10_000;

    /// <summary>完整性校验间隔（检查周期数，每 6 个周期即 60 秒校验一次）</summary>
    private const int IntegrityCheckEveryNTicks = 6;

    /// <summary>可疑模块注入判定阈值：已加载模块数超出基线该值时告警</summary>
    private const int InjectionThreshold = 20;

    #endregion

    #region 字段

    private readonly object _lock = new();
    private Timer? _checkTimer;
    private bool _running;
    private bool _disposed;

    /// <summary>自身可执行文件的 SHA-256 基线哈希（小写十六进制）</summary>
    private string? _baselineHash;

    /// <summary>启动时已加载模块数基线</summary>
    private int _baselineModuleCount;

    /// <summary>检查周期计数器（用于降低完整性校验频率）</summary>
    private int _tickCount;

    #endregion

    #region 事件

    /// <summary>
    /// 自我保护告警事件。
    /// <para>参数 1：告警消息描述；参数 2：告警级别。</para>
    /// </summary>
    public event Action<string, ProtectionLevel>? SelfProtectionAlert;

    #endregion

    #region 属性

    /// <summary>保护引擎是否正在运行</summary>
    public bool IsRunning => _running;

    #endregion

    #region 启动 / 停止

    /// <summary>
    /// 启动自我保护引擎。
    /// <para>1. 应用进程缓解策略（DEP / ASLR / CFG）；</para>
    /// <para>2. 加固进程 DACL（拒绝非 SYSTEM 进程终止）；</para>
    /// <para>3. 计算自身完整性基线哈希与模块数基线；</para>
    /// <para>4. 启动后台定时器，每 10 秒执行一次保护检查。</para>
    /// </summary>
    public void Start()
    {
        lock (_lock)
        {
            if (_running || _disposed) return;
            _running = true;
        }

        // 一次性加固
        ApplyProcessMitigations();
        HardenProcessDacl();
        ComputeBaselineHash();
        ComputeBaselineModuleCount();

        // 启动周期检查定时器
        _tickCount = 0;
        _checkTimer = new Timer(OnCheckTick, null, CheckIntervalMs, CheckIntervalMs);

        AuditLogSystem.Log(LogLevel.Info, LogCategory.System,
            "自我保护引擎已启动", "反调试 | 进程DACL | 缓解策略 | 完整性校验");
        SelfProtectionAlert?.Invoke("自我保护引擎已启动", ProtectionLevel.Info);
    }

    /// <summary>
    /// 停止自我保护引擎（停止周期检查定时器）。
    /// </summary>
    public void Stop()
    {
        lock (_lock)
        {
            if (!_running) return;
            _running = false;
        }

        _checkTimer?.Dispose();
        _checkTimer = null;

        AuditLogSystem.Log(LogLevel.Info, LogCategory.System, "自我保护引擎已停止");
    }

    #endregion

    #region 周期检查

    /// <summary>定时检查回调</summary>
    private void OnCheckTick(object? state)
    {
        if (!_running) return;

        try
        {
            CheckDebugger();
            CheckModuleInjection();

            // 每 N 个周期执行一次完整性校验（降低文件 I/O 频率）
            _tickCount++;
            if (_tickCount >= IntegrityCheckEveryNTicks)
            {
                _tickCount = 0;
                VerifyIntegrity();
            }
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, "自我保护周期检查异常");
        }
    }

    /// <summary>
    /// 反调试检查：检测用户态调试器与远程调试器附加。
    /// </summary>
    private void CheckDebugger()
    {
        bool detected = false;
        var details = new StringBuilder();

        try
        {
            if (IsDebuggerPresent())
            {
                detected = true;
                details.Append("IsDebuggerPresent 检测到用户态调试器附加");
            }
        }
        catch { /* 忽略 P/Invoke 异常 */ }

        try
        {
            bool remotePresent = false;
            if (CheckRemoteDebuggerPresent(GetCurrentProcess(), ref remotePresent) && remotePresent)
            {
                detected = true;
                if (details.Length > 0)
                    details.Append("；");
                details.Append("CheckRemoteDebuggerPresent 检测到远程调试器附加");
            }
        }
        catch { /* 忽略 P/Invoke 异常 */ }

        if (detected)
        {
            var msg = details.ToString();
            AuditLogSystem.Log(LogLevel.Warning, LogCategory.System,
                "检测到调试器附加", msg);
            SelfProtectionAlert?.Invoke($"检测到调试器附加：{msg}", ProtectionLevel.Critical);
        }
    }

    /// <summary>
    /// 可疑模块注入检查（启发式）：监控已加载模块数是否异常增长。
    /// <para>超过基线阈值时触发 Warning 级别告警。</para>
    /// </summary>
    private void CheckModuleInjection()
    {
        if (_baselineModuleCount <= 0) return;

        try
        {
            using var proc = Process.GetCurrentProcess();
            var current = proc.Modules.Count;

            if (current > _baselineModuleCount + InjectionThreshold)
            {
                var msg = $"检测到可疑模块注入行为（已加载模块数: 基线 {_baselineModuleCount} → 当前 {current}）";
                AuditLogSystem.Log(LogLevel.Warning, LogCategory.System, msg);
                SelfProtectionAlert?.Invoke(msg, ProtectionLevel.Warning);
            }
        }
        catch
        {
            // 模块枚举失败时静默忽略（不影响其他检查）
        }
    }

    #endregion

    #region 进程缓解策略

    /// <summary>
    /// 通过 SetProcessMitigationPolicy 启用 DEP、ASLR、CFG 缓解策略。
    /// <para>部分策略需在进程创建时启用，运行时调用可能失败，失败仅记录日志不中断。</para>
    /// </summary>
    private void ApplyProcessMitigations()
    {
        int applied = 0;

        // DEP：Enable=1, Permanent=1
        try
        {
            var dep = new PROCESS_MITIGATION_DEP_POLICY { Flags = 0x1, Permanent = 1 };
            if (SetProcessMitigationPolicyDep(ProcessDEPPolicy, ref dep,
                (IntPtr)Marshal.SizeOf(typeof(PROCESS_MITIGATION_DEP_POLICY))))
            {
                applied++;
            }
            else
            {
                ErrorReporter.Log(
                    $"[SelfProtection] 启用 DEP 缓解策略失败，错误码: {Marshal.GetLastWin32Error()}", "WARN");
            }
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, "启用 DEP 缓解策略异常");
        }

        // ASLR：EnableBottomUpRandomization=1 | EnableForceRelocateImages=1 | EnableHighEntropy=1
        try
        {
            var aslr = new PROCESS_MITIGATION_ASLR_POLICY { Flags = 0x7 };
            if (SetProcessMitigationPolicyAslr(ProcessASLRPolicy, ref aslr,
                (IntPtr)Marshal.SizeOf(typeof(PROCESS_MITIGATION_ASLR_POLICY))))
            {
                applied++;
            }
            else
            {
                ErrorReporter.Log(
                    $"[SelfProtection] 启用 ASLR 缓解策略失败，错误码: {Marshal.GetLastWin32Error()}", "WARN");
            }
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, "启用 ASLR 缓解策略异常");
        }

        // CFG：EnableControlFlowGuard=1
        try
        {
            var cfg = new PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY { Flags = 0x1 };
            if (SetProcessMitigationPolicyCfg(ProcessControlFlowGuardPolicy, ref cfg,
                (IntPtr)Marshal.SizeOf(typeof(PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY))))
            {
                applied++;
            }
            else
            {
                ErrorReporter.Log(
                    $"[SelfProtection] 启用 CFG 缓解策略失败，错误码: {Marshal.GetLastWin32Error()}", "WARN");
            }
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, "启用 CFG 缓解策略异常");
        }

        AuditLogSystem.Log(LogLevel.Info, LogCategory.System,
            "进程缓解策略已应用", $"成功启用 {applied}/3 项（DEP/ASLR/CFG）");
    }

    #endregion

    #region 进程 DACL 加固

    /// <summary>
    /// 通过 SDDL 对自身进程设置 DACL：
    /// <para>1. 授予 SYSTEM 完全控制（GA，包含 PROCESS_TERMINATE）；</para>
    /// <para>2. 授予当前用户除 PROCESS_TERMINATE 外的全部权限（0x1FFFFE）；</para>
    /// <para>3. 其他主体无 ACE → 隐式拒绝所有访问。</para>
    /// <para>效果：Task Manager 等非 SYSTEM 进程无法终止 LightGuard，仅 SYSTEM 与进程自身可终止。</para>
    /// </summary>
    /// <returns>加固成功返回 true；失败返回 false。</returns>
    private bool HardenProcessDacl()
    {
        try
        {
            var currentSid = WindowsIdentity.GetCurrent().User?.Value;
            if (string.IsNullOrEmpty(currentSid))
            {
                ErrorReporter.Log("[SelfProtection] 无法获取当前用户 SID，跳过进程 DACL 加固", "WARN");
                return false;
            }

            // SDDL: D:(A;;GA;;;SY)(A;;0x1FFFFE;;;<currentSid>)
            // GA = GENERIC_ALL（进程对象映射为 0x1FFFFF）
            // 0x1FFFFE = 0x1FFFFF - 0x1（PROCESS_TERMINATE）
            string sddl = "D:(A;;GA;;;SY)(A;;0x1FFFFE;;;" + currentSid + ")";

            if (!ConvertStringSecurityDescriptorToSecurityDescriptor(
                    sddl, SDDL_REVISION_1, out IntPtr pSD, IntPtr.Zero))
            {
                ErrorReporter.Log(
                    $"[SelfProtection] SDDL 转换安全描述符失败，错误码: {Marshal.GetLastWin32Error()}", "WARN");
                return false;
            }

            try
            {
                // 尝试用 OpenProcess 获取带 WRITE_DAC 的真实句柄
                IntPtr hProcess = OpenProcess(WRITE_DAC | READ_CONTROL, false, Environment.ProcessId);
                bool openedRealHandle = hProcess != IntPtr.Zero;

                // 回退到伪句柄（拥有全部权限）
                if (!openedRealHandle)
                    hProcess = GetCurrentProcess();

                bool ok = SetKernelObjectSecurity(hProcess, DACL_SECURITY_INFORMATION, pSD);

                if (openedRealHandle)
                    CloseHandle(hProcess);

                if (ok)
                {
                    AuditLogSystem.Log(LogLevel.Info, LogCategory.System,
                        "进程 DACL 已加固", "仅 SYSTEM 可终止；非 SYSTEM 进程拒绝 PROCESS_TERMINATE");
                }
                else
                {
                    ErrorReporter.Log(
                        $"[SelfProtection] 设置进程 DACL 失败，错误码: {Marshal.GetLastWin32Error()}", "WARN");
                }

                return ok;
            }
            finally
            {
                LocalFree(pSD);
            }
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, "进程 DACL 加固失败");
            return false;
        }
    }

    #endregion

    #region 自身完整性校验

    /// <summary>
    /// 计算自身可执行文件的 SHA-256 基线哈希并存储。
    /// </summary>
    private void ComputeBaselineHash()
    {
        try
        {
            var exePath = Environment.ProcessPath;
            if (string.IsNullOrEmpty(exePath) || !File.Exists(exePath))
            {
                ErrorReporter.Log("[SelfProtection] 无法定位可执行文件路径，完整性基线未建立", "WARN");
                return;
            }

            using var stream = new FileStream(exePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            _baselineHash = Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant();

            AuditLogSystem.Log(LogLevel.Info, LogCategory.Verify,
                "自身完整性基线哈希已记录", $"SHA-256: {_baselineHash}");
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, "计算自身完整性基线哈希失败");
        }
    }

    /// <summary>
    /// 重新计算自身可执行文件 SHA-256 并与基线比对，防止二进制篡改。
    /// </summary>
    private void VerifyIntegrity()
    {
        if (string.IsNullOrEmpty(_baselineHash))
            return;

        try
        {
            var exePath = Environment.ProcessPath;
            if (string.IsNullOrEmpty(exePath) || !File.Exists(exePath))
                return;

            using var stream = new FileStream(exePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            var hash = Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant();

            if (!string.Equals(hash, _baselineHash, StringComparison.OrdinalIgnoreCase))
            {
                var msg = "检测到可执行文件二进制完整性异常（SHA-256 哈希不匹配）";
                AuditLogSystem.Log(LogLevel.Critical, LogCategory.Verify,
                    msg, $"基线: {_baselineHash} | 当前: {hash}");
                SelfProtectionAlert?.Invoke(msg, ProtectionLevel.Critical);
            }
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, "完整性校验异常");
        }
    }

    /// <summary>
    /// 记录启动时已加载模块数基线，用于可疑注入启发式检测。
    /// </summary>
    private void ComputeBaselineModuleCount()
    {
        try
        {
            using var proc = Process.GetCurrentProcess();
            _baselineModuleCount = proc.Modules.Count;
        }
        catch
        {
            _baselineModuleCount = 0;
        }
    }

    #endregion

    #region IDisposable

    /// <summary>
    /// 释放资源：停止定时器。
    /// </summary>
    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        Stop();
        GC.SuppressFinalize(this);
    }

    #endregion
}
