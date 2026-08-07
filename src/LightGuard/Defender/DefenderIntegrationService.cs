// © 2026 落尘（Luochen） 原创开发 - 保留所有权利

using LightGuard.Core;
using LightGuard.Security;

namespace LightGuard.Defender;

/// <summary>
/// Defender 查杀全局集成服务（P1-6 业务联动）。
/// <para>为勒索告警、备份、解密、SMB 审计等模块提供统一的查杀调度入口：</para>
/// <list type="bullet">
///   <item>风险处置：发现威胁后弹出处置窗（隔离 / 删除 / 仅告警），服务器版仅记日志不弹窗。</item>
///   <item>审计日志：扫描事件完整写入全局审计日志（LogCategory.DefenderScan），支持报表导出。</item>
///   <item>兼容性检查：第三方杀毒导致 Defender 禁用时给出原因，UI 据此置灰按钮。</item>
///   <item>服务器适配：DistributionProfile.IsServerEdition 下关闭桌面弹窗。</item>
/// </list>
/// </summary>
public static class DefenderIntegrationService
{
    /// <summary>获取当前生效的扫描助手（未启用模块时返回 null）</summary>
    public static DefenderScannerHelper? ResolveScanner()
    {
        try
        {
            var module = AppState.Instance.Modules.GetModule("defender-scan") as Modules.DefenderScanModule;
            return module?.Scanner;
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// 检查 Defender 是否可用，返回是否可执行查杀。
    /// <para>用于第三方杀毒导致 Defender 禁用时 UI 置灰按钮并提示原因。</para>
    /// </summary>
    /// <param name="reason">不可用原因（中文描述，供 UI 展示）</param>
    /// <param name="detailed">详细原因（用于日志/审计）</param>
    public static bool IsAvailable(out string reason, out string detailed)
    {
        // 1. 模块必须已启用
        var module = AppState.Instance.Modules.GetModule("defender-scan") as Modules.DefenderScanModule;
        if (module == null || module.Scanner == null)
        {
            reason = "Defender 查杀模块未启用，请先在设置中启用。";
            detailed = "defender-scan module disabled";
            return false;
        }

        // 2. MpCmdRun.exe 存在且 WinDefend 服务运行
        try
        {
            using var probe = new DefenderScannerHelper();
            if (!probe.IsDefenderAvailable())
            {
                reason = "Microsoft Defender 不可用（可能已被第三方杀毒软件接管或系统精简）。";
                detailed = "MpCmdRun unavailable or WinDefend service stopped";
                return false;
            }
        }
        catch
        {
            reason = "Microsoft Defender 状态检测失败。";
            detailed = "Defender availability probe failed";
            return false;
        }

        // 3. 实时保护关闭时仍可执行按需扫描（仅提示）
        reason = string.Empty;
        detailed = string.Empty;
        return true;
    }

    /// <summary>
    /// 对单个文件/目录执行查杀，发现威胁时按用户选择处置，并将扫描事件写入审计日志。
    /// <para>服务器模式下不弹窗，自动执行隔离并仅记日志。</para>
    /// </summary>
    /// <param name="path">文件或目录路径</param>
    /// <param name="isDirectory">是否为目录</param>
    /// <param name="source">触发来源（如 "勒索告警" / "备份前检查" / "SMB审计"），用于审计日志标识</param>
    /// <param name="ct">取消令牌</param>
    /// <returns>扫描结果（未执行时返回 null）</returns>
    public static async Task<DefenderScanResult?> ScanPathAsync(string path, bool isDirectory, string source, CancellationToken ct = default)
    {
        var scanner = ResolveScanner();
        if (scanner == null)
        {
            AuditLogSystem.Log(LogLevel.Warning, LogCategory.DefenderScan,
                "查杀未执行：Defender 查杀模块未启用",
                $"来源={source} 目标={path}");
            return null;
        }

        var type = isDirectory ? DefenderScanType.Directory : DefenderScanType.SingleFile;
        DefenderScanResult result;
        try
        {
            result = isDirectory
                ? await scanner.ScanDirectoryAsync(path, ct)
                : await scanner.ScanFileAsync(path, ct);
        }
        catch (OperationCanceledException)
        {
            AuditLogSystem.Log(LogLevel.Info, LogCategory.DefenderScan,
                "查杀已取消", $"来源={source} 目标={path}");
            return null;
        }
        catch (Exception ex)
        {
            AuditLogSystem.Log(LogLevel.Error, LogCategory.DefenderScan,
                $"查杀执行异常：{ex.Message}", $"来源={source} 目标={path}");
            return null;
        }

        // 写入审计日志
        WriteScanAudit(result, source);

        // 发现威胁 → 风险处置
        if (result.Success && result.Threats.Count > 0)
            await RemediateAsync(result.Threats, source);

        return result;
    }

    /// <summary>
    /// 静默扫描目录并收集恶意文件路径集合（备份前联动：恶意文件跳过备份）。
    /// <para>不弹处置窗，仅写审计日志；Defender 不可用或扫描失败时返回空集合（不阻断备份）。</para>
    /// </summary>
    /// <param name="dirPath">待备份源目录</param>
    /// <param name="ct">取消令牌</param>
    /// <returns>恶意文件绝对路径集合</returns>
    public static async Task<HashSet<string>> CollectMaliciousFilesAsync(string dirPath, CancellationToken ct = default)
    {
        var malicious = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var scanner = ResolveScanner();
        if (scanner == null)
            return malicious;

        try
        {
            var result = await scanner.ScanDirectoryAsync(dirPath, ct);
            WriteScanAudit(result, "备份前查杀");

            foreach (var t in result.Threats)
            {
                if (!string.IsNullOrEmpty(t.FilePath))
                    malicious.Add(t.FilePath);
            }

            if (malicious.Count > 0)
            {
                AuditLogSystem.Log(LogLevel.Critical, LogCategory.DefenderScan,
                    $"备份前查杀发现 {malicious.Count} 个恶意文件，已跳过备份",
                    string.Join(" | ", malicious.Take(50)));
            }
        }
        catch (OperationCanceledException)
        {
            // 用户取消扫描，不阻断备份
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, "备份前查杀失败（备份继续执行）");
        }

        return malicious;
    }

    /// <summary>
    /// 风险处置：弹出处置窗让用户选择（隔离 / 删除 / 仅告警）。
    /// <para>服务器模式：不弹窗，自动隔离并记录审计日志。</para>
    /// </summary>
    /// <param name="threats">威胁列表</param>
    /// <param name="source">触发来源</param>
    public static async Task RemediateAsync(List<DefenderThreat> threats, string source)
    {
        if (threats == null || threats.Count == 0) return;

        // 服务器模式：静默处置（自动隔离），仅记日志
        if (DistributionProfile.IsServerEdition)
        {
            foreach (var t in threats)
            {
                var id = QuarantineFile(t, source);
                t.ActionTaken = id.Length > 0 ? ThreatAction.Quarantine : ThreatAction.None;
            }
            AuditLogSystem.Log(LogLevel.Critical, LogCategory.DefenderScan,
                $"服务器模式自动隔离 {threats.Count} 个威胁",
                string.Join(" | ", threats.Select(t => $"{t.ThreatName}@{t.FilePath}")));
            return;
        }

        // 客户端模式：弹出处置窗（在 UI 线程执行）
        try
        {
            ThreatAction action = ThreatAction.None;
            await Task.Run(() =>
            {
                using var dlg = new UI.ThreatRemediationDialog(threats, source);
                var owner = Application.OpenForms.Cast<Form>().FirstOrDefault(f => f.Visible);
                action = dlg.ShowDialog(owner) == DialogResult.OK ? dlg.SelectedAction : ThreatAction.None;
            });

            // 应用用户选择
            foreach (var t in threats)
            {
                t.ActionTaken = action;
                switch (action)
                {
                    case ThreatAction.Quarantine:
                        QuarantineFile(t, source);
                        break;
                    case ThreatAction.Remove:
                        TryDeleteFile(t);
                        break;
                    case ThreatAction.Allow:
                        AuditLogSystem.Log(LogLevel.Warning, LogCategory.DefenderScan,
                            "用户选择仅告警（不处置）", $"{t.ThreatName}@{t.FilePath} 来源={source}");
                        break;
                }
            }
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, "风险处置窗异常，改为仅记录");
        }
    }

    /// <summary>将威胁文件加入隔离区（复用 QuarantineManager）</summary>
    private static string QuarantineFile(DefenderThreat threat, string source)
    {
        try
        {
            if (string.IsNullOrEmpty(threat.FilePath) || !File.Exists(threat.FilePath))
            {
                AuditLogSystem.Log(LogLevel.Warning, LogCategory.DefenderScan,
                    "隔离失败：威胁文件不存在", $"{threat.ThreatName}@{threat.FilePath}");
                return "";
            }

            using var qm = new QuarantineManager();
            var id = qm.QuarantineFile(threat.FilePath,
                $"Defender 查杀联动隔离（来源={source}）", threat.ThreatName);
            AuditLogSystem.Log(LogLevel.Critical, LogCategory.DefenderScan,
                $"威胁已隔离：{threat.ThreatName}",
                $"文件={threat.FilePath} 隔离ID={id} 来源={source}");
            return id;
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, "隔离威胁文件失败");
            return "";
        }
    }

    /// <summary>永久删除威胁文件</summary>
    private static void TryDeleteFile(DefenderThreat threat)
    {
        try
        {
            if (string.IsNullOrEmpty(threat.FilePath) || !File.Exists(threat.FilePath))
                return;
            File.Delete(threat.FilePath);
            AuditLogSystem.Log(LogLevel.Critical, LogCategory.DefenderScan,
                $"威胁已删除：{threat.ThreatName}", $"文件={threat.FilePath}");
        }
        catch (Exception ex)
        {
            AuditLogSystem.Log(LogLevel.Error, LogCategory.DefenderScan,
                $"删除威胁文件失败：{ex.Message}", threat.FilePath);
        }
    }

    /// <summary>将扫描事件写入全局审计日志（支持报表导出）</summary>
    private static void WriteScanAudit(DefenderScanResult result, string source)
    {
        try
        {
            var target = string.IsNullOrEmpty(result.TargetPath) ? TypeName(result.ScanType) : result.TargetPath;
            var detail = $"来源={source} | 类型={TypeName(result.ScanType)} | 目标={target} | " +
                         $"耗时={result.ScanDuration.TotalSeconds:F1}s | 扫描项={result.ScannedItems} | " +
                         $"退出码={result.ExitCode}";

            if (!result.Success)
            {
                AuditLogSystem.Log(LogLevel.Error, LogCategory.DefenderScan,
                    $"Defender 扫描失败：{result.ErrorMessage}", detail);
                return;
            }

            if (result.ThreatsFound == 0)
            {
                AuditLogSystem.Log(LogLevel.Info, LogCategory.DefenderScan,
                    $"Defender 扫描完成，未发现威胁", detail);
                return;
            }

            AuditLogSystem.Log(LogLevel.Critical, LogCategory.DefenderScan,
                $"Defender 扫描发现 {result.ThreatsFound} 个威胁",
                detail + " | 威胁：" + string.Join("; ",
                    result.Threats.Select(t => $"{t.ThreatName}@{t.FilePath}")));
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, "写入 Defender 扫描审计日志失败");
        }
    }

    /// <summary>扫描类型显示名</summary>
    public static string TypeName(DefenderScanType type) => type switch
    {
        DefenderScanType.SingleFile => "单文件扫描",
        DefenderScanType.Directory => "目录扫描",
        DefenderScanType.QuickScan => "快速扫描",
        DefenderScanType.FullScan => "全盘扫描",
        _ => "扫描"
    };
}
