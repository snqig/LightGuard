using LightGuard.Core;
using LightGuard.Core.Interfaces;
using LightGuard.Defender;

namespace LightGuard.Modules;

/// <summary>
/// Defender 查杀调度模块（P0-4）
/// 封装 Microsoft Defender MpCmdRun.exe 的按需查杀能力，统一对外暴露：
///   - 引擎/病毒库健康状态查询
///   - 单文件 / 目录 / 快速 / 全盘扫描
///   - 病毒库签名更新
///   - 扫描历史与威胁清单管理
/// 模块生命周期与 DefenderScannerHelper 绑定：启用时创建、禁用时释放。
/// </summary>
public sealed class DefenderScanModule : ModuleBase
{
    /// <summary>核心扫描助手（启用后非空）</summary>
    private DefenderScannerHelper? _scanner;

    /// <summary>扫描历史记录（最近的扫描结果）</summary>
    private readonly List<DefenderScanResult> _history = new();

    /// <summary>累计发现的威胁清单</summary>
    private readonly List<DefenderThreat> _threats = new();

    /// <summary>缓存的状态信息（避免频繁拉起 PowerShell）</summary>
    private LightGuard.Defender.DefenderStatusInfo? _cachedStatus;

    public DefenderScanModule(AppState appState) : base(appState)
    {
    }

    /// <inheritdoc/>
    public override string Id => "defender-scan";

    /// <inheritdoc/>
    public override string DisplayName => "Defender查杀调度";

    /// <inheritdoc/>
    public override string Description => "Microsoft Defender 按需查杀调度引擎：单文件/目录/快速/全盘扫描、病毒库更新、威胁与历史管理";

    /// <inheritdoc/>
    public override ModuleCategory Category => ModuleCategory.Core;

    /// <inheritdoc/>
    public override bool RequiresAdmin => true;

    /// <summary>对外暴露的扫描助手（其他模块可复用，例如备份前自动查杀）</summary>
    public DefenderScannerHelper? Scanner => _scanner;

    // ==================== 生命周期 ====================

    /// <inheritdoc/>
    protected override async Task OnInitializeAsync()
    {
        await Task.Run(() =>
        {
            // 探测 Defender 是否可用并记录状态
            using var probe = new DefenderScannerHelper();
            var available = probe.IsDefenderAvailable();
            var isAdmin = probe.IsRunningAsAdmin();

            ErrorReporter.Log($"Defender 查杀模块初始化 - MpCmdRun可用:{available} 管理员:{isAdmin}");

            if (available)
            {
                try
                {
                    _cachedStatus = probe.GetDefenderStatus();
                    ErrorReporter.Log(
                        $"Defender 状态 - 实时保护:{_cachedStatus.RealTimeProtectionEnabled} " +
                        $"反病毒:{_cachedStatus.AntivirusEnabled} " +
                        $"病毒库:{_cachedStatus.SignatureVersion} " +
                        $"引擎:{_cachedStatus.EngineVersion} " +
                        $"健康:{_cachedStatus.IsHealthy}");
                }
                catch (Exception ex)
                {
                    ErrorReporter.Report(ex, "初始化时获取 Defender 状态失败");
                }
            }
            else
            {
                ErrorReporter.Log("Microsoft Defender 不可用，查杀模块将以降级模式运行", "WARN");
            }
        });
    }

    /// <inheritdoc/>
    protected override async Task OnEnableAsync()
    {
        await Task.Run(() =>
        {
            _scanner = new DefenderScannerHelper();
            ErrorReporter.Log("Defender 查杀模块已启用，扫描助手已就绪");
        });
    }

    /// <inheritdoc/>
    protected override async Task OnDisableAsync()
    {
        await Task.Run(() =>
        {
            _scanner?.Dispose();
            _scanner = null;
            ErrorReporter.Log("Defender 查杀模块已禁用，扫描助手已释放");
        });
    }

    /// <inheritdoc/>
    protected override void OnReleaseResources()
    {
        _scanner?.Dispose();
        _scanner = null;
        _history.Clear();
        _threats.Clear();
    }

    // ==================== 对外查询/操作 ====================

    /// <summary>获取当前 Defender 状态（启用时实时查询，未启用时返回缓存）</summary>
    public LightGuard.Defender.DefenderStatusInfo GetDefenderStatus()
    {
        if (_scanner != null)
        {
            try
            {
                _cachedStatus = _scanner.GetDefenderStatus();
            }
            catch (Exception ex)
            {
                ErrorReporter.Report(ex, "DefenderScanModule 获取状态失败");
            }
        }
        return _cachedStatus ?? new LightGuard.Defender.DefenderStatusInfo { ErrorMessage = "模块未启用" };
    }

    /// <summary>获取扫描历史副本</summary>
    public List<DefenderScanResult> GetScanHistory()
    {
        lock (_history)
        {
            return _history.ToList();
        }
    }

    /// <summary>获取累计威胁清单副本</summary>
    public List<DefenderThreat> GetThreatList()
    {
        lock (_threats)
        {
            return _threats.ToList();
        }
    }

    /// <summary>记录一次扫描结果，并合并其威胁到累计清单</summary>
    public void RecordScan(DefenderScanResult result)
    {
        if (result == null) return;

        lock (_history)
        {
            _history.Add(result);
            // 仅保留最近 200 条
            if (_history.Count > 200)
                _history.RemoveAt(0);
        }

        if (result.Threats.Count > 0)
        {
            lock (_threats)
            {
                _threats.AddRange(result.Threats);
                if (_threats.Count > 1000)
                    _threats.RemoveRange(0, _threats.Count - 1000);
            }
        }
    }

    /// <summary>清空扫描历史</summary>
    public void ClearHistory()
    {
        lock (_history) _history.Clear();
    }

    /// <summary>触发病毒库签名更新</summary>
    public async Task UpdateSignaturesAsync()
    {
        if (_scanner == null)
        {
            ErrorReporter.Log("病毒库更新失败：Defender 查杀模块未启用", "WARN");
            return;
        }
        await _scanner.UpdateSignaturesAsync();
        // 更新后刷新缓存状态
        _cachedStatus = _scanner.GetDefenderStatus();
    }

    /// <inheritdoc/>
    protected override string GetStatusSummary()
    {
        if (_scanner == null)
            return "未启用";

        var status = _cachedStatus;
        if (status == null || !status.IsValid)
            return "运行中（状态未知）";

        var health = status.IsHealthy ? "健康" : "需关注";
        return $"实时保护:{(status.RealTimeProtectionEnabled ? "开" : "关")} " +
               $"病毒库:{(string.IsNullOrEmpty(status.SignatureVersion) ? "未知" : status.SignatureVersion)} " +
               $"| {health} | 历史:{_history.Count} 条";
    }

    /// <inheritdoc/>
    public override void Dispose()
    {
        _scanner?.Dispose();
        _scanner = null;
        base.Dispose();
    }
}
