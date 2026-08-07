// © 2026 落尘（Luochen） 原创开发 - 保留所有权利

using System.Diagnostics;
using LightGuard.Core;
using LightGuard.Core.Interfaces;
using LightGuard.Defender;
using LightGuard.Ransomware;

namespace LightGuard.Modules;

/// <summary>
/// ETW+YARA 双层勒索防御模块
/// <para>整合 ETW 行为监控与 YARA 特征核验，提供双层勒索软件防御能力。</para>
/// <para>第一层：ETW 实时监控高危行为（批量加密、目录遍历、VSS 删除等）。</para>
/// <para>第二层：YARA 对 ETW 触发的目标文件按需匹配已知勒索特征。</para>
/// <para>双层确认后执行风险响应链：挂起进程 → 断网 → 告警 → 锁定 VSS。</para>
/// </summary>
public sealed class EtwYaraModule : ModuleBase
{
    #region 字段

    /// <summary>双层防御协调器引擎实例</summary>
    private RansomDefenseEngine? _defenseEngine;

    /// <summary>累计告警数</summary>
    private int _alertCount;

    /// <summary>累计双层确认（Critical）告警数</summary>
    private int _dualConfirmCount;

    #endregion

    #region 构造与模块信息

    /// <summary>
    /// 构造 ETW+YARA 双层勒索防御模块
    /// </summary>
    /// <param name="appState">全局应用状态</param>
    public EtwYaraModule(AppState appState) : base(appState)
    {
    }

    /// <inheritdoc/>
    public override string Id => "etw-yara-defense";

    /// <inheritdoc/>
    public override string DisplayName => "ETW+YARA双层勒索防御";

    /// <inheritdoc/>
    public override string Description =>
        "ETW 行为监控 + YARA 特征核验双层防御：实时捕获勒索行为，按需匹配已知特征，" +
        "双层确认后自动挂起进程、断网、告警、锁定 VSS 备份";

    /// <inheritdoc/>
    public override ModuleCategory Category => ModuleCategory.Ransomware;

    /// <inheritdoc/>
    public override bool RequiresAdmin => true;

    #endregion

    #region 生命周期

    /// <summary>
    /// 初始化双层防御引擎
    /// </summary>
    protected override Task OnInitializeAsync()
    {
        _defenseEngine = new RansomDefenseEngine();
        _defenseEngine.AlertRaised += OnDefenseAlert;

        ErrorReporter.Log(
            $"[EtwYaraModule] 初始化完成 | YARA 规则: {_defenseEngine.GetYaraEngine().GetRuleCount()} 条");

        return Task.CompletedTask;
    }

    /// <summary>
    /// 启动双层防御引擎
    /// </summary>
    protected override Task OnEnableAsync()
    {
        _defenseEngine?.Start();

        ErrorReporter.Log("[EtwYaraModule] ETW+YARA 双层防御引擎已启动");

        return Task.CompletedTask;
    }

    /// <summary>
    /// 停止双层防御引擎
    /// </summary>
    protected override Task OnDisableAsync()
    {
        _defenseEngine?.Stop();

        ErrorReporter.Log("[EtwYaraModule] ETW+YARA 双层防御引擎已停止");

        return Task.CompletedTask;
    }

    /// <summary>
    /// 释放资源
    /// </summary>
    protected override void OnReleaseResources()
    {
        _defenseEngine?.Dispose();
        _defenseEngine = null;
    }

    #endregion

    #region 事件处理

    /// <summary>
    /// 防御告警回调
    /// </summary>
    private void OnDefenseAlert(DefenseAlert alert)
    {
        _alertCount++;

        if (alert.Layer == DefenseLayer.Dual)
        {
            _dualConfirmCount++;
        }

        ErrorReporter.Log(
            $"[EtwYaraModule] 防御告警 #{_alertCount}: {alert}",
            alert.RiskLevel >= RiskLevel.Critical ? "ERROR" : "WARN");

        // P1-6：勒索告警弹窗 — 增加【扫描可疑进程目录】按钮（Defender 联动查杀）
        // 服务器适配：关闭桌面弹窗，仅留存审计日志
        if (DistributionProfile.IsServerEdition)
        {
            AuditLogSystem.Log(LogLevel.Critical, LogCategory.RansomwareAlert,
                $"勒索防御告警（服务器模式，仅记录）：{alert.Summary}",
                alert.ToString());
            return;
        }

        // 客户端模式：仅在 UI 线程弹出告警窗（告警本身来自后台线程）
        var pid = alert.EtwAlert?.ProcessId ?? 0;
        try
        {
            var uiThread = Application.OpenForms.Cast<Form>().FirstOrDefault(f => f.Visible);
            if (uiThread == null || uiThread.IsDisposed)
                return;

            uiThread.BeginInvoke(() =>
            {
                using var dlg = new LightGuard.UI.RansomwareAlertDialog(alert, pid);
                if (dlg.ShowDialog(uiThread) == DialogResult.OK && dlg.RequestedScan)
                {
                    // 用户点击【扫描可疑进程目录】→ 对可疑进程所在目录执行 Defender 按需查杀
                    var exeDir = GetProcessDirectory(pid);
                    if (!string.IsNullOrEmpty(exeDir))
                    {
                        _ = DefenderIntegrationService.ScanPathAsync(exeDir, true, "勒索告警");
                    }
                    else
                    {
                        ErrorReporter.Log($"[EtwYaraModule] 无法定位可疑进程目录 PID={pid}", "WARN");
                    }
                }
            });
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, "勒索告警弹窗异常");
        }
    }

    /// <summary>获取进程可执行文件所在目录</summary>
    private static string? GetProcessDirectory(int pid)
    {
        if (pid <= 0) return null;
        try
        {
            using var p = Process.GetProcessById(pid);
            var path = p.MainModule?.FileName;
            if (string.IsNullOrEmpty(path)) return null;
            return Path.GetDirectoryName(path);
        }
        catch
        {
            return null;
        }
    }

    #endregion

    #region 状态摘要

    /// <summary>
    /// 获取监控状态摘要
    /// </summary>
    protected override string GetStatusSummary()
    {
        if (!IsEnabled || _defenseEngine == null)
            return "已停止";

        var yaraRules = _defenseEngine.GetYaraEngine().GetRuleCount();
        var alerts = _defenseEngine.GetAlertHistory();
        var criticalCount = alerts.Count(a => a.RiskLevel >= RiskLevel.Critical);

        return $"运行中 | YARA 规则 {yaraRules} 条 | " +
               $"告警 {alerts.Count} 次（Critical {criticalCount}）| " +
               $"双层确认 {_dualConfirmCount} 次";
    }

    #endregion

    #region 公共接口

    /// <summary>
    /// 获取防御引擎实例（供 UI 调用）
    /// </summary>
    public RansomDefenseEngine? GetDefenseEngine() => _defenseEngine;

    /// <summary>
    /// 获取告警历史记录
    /// </summary>
    public List<DefenseAlert> GetAlertHistory()
    {
        return _defenseEngine?.GetAlertHistory() ?? new List<DefenseAlert>();
    }

    #endregion
}
