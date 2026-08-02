// © 2026 落尘（Luochen）原创开发 - 保留所有权利

using LightGuard.Core;
using LightGuard.Core.Interfaces;
using LightGuard.Security;

namespace LightGuard.Modules;

/// <summary>
/// 程序自我保护模块
/// <para>集成反调试、进程DACL加固、进程缓解策略、自身完整性校验</para>
/// <para>同时负责配置文件加密与NTFS权限加固</para>
/// </summary>
public class SelfProtectionModule : ModuleBase
{
    private SelfProtectionEngine? _engine;
    private ConfigProtector? _configProtector;
    private bool _configHardened;

    public SelfProtectionModule(AppState appState) : base(appState)
    {
    }

    /// <inheritdoc/>
    public override string Id => "self-protection";

    /// <inheritdoc/>
    public override string DisplayName => "程序自我保护";

    /// <inheritdoc/>
    public override string Description =>
        "反调试 + 进程DACL加固 + 进程缓解策略(DEP/ASLR/CFG) + 自身完整性校验 + 配置加密存储";

    /// <inheritdoc/>
    public override ModuleCategory Category => ModuleCategory.Core;

    /// <inheritdoc/>
    public override bool RequiresAdmin => true;

    /// <summary>获取保护引擎实例（供外部查询保护状态）</summary>
    public SelfProtectionEngine? GetEngine() => _engine;

    protected override Task OnInitializeAsync()
    {
        _engine = new SelfProtectionEngine();
        _engine.SelfProtectionAlert += OnProtectionAlert;
        _configProtector = new ConfigProtector();

        // 启动时加固配置目录NTFS权限并加密敏感配置
        try
        {
            if (!_configHardened && _configProtector != null)
            {
                _configProtector.HardenConfigDirectoryNtfs();
                var result = _configProtector.EnsureConfigProtected(AppState.Config);
                _configHardened = true;
                ErrorReporter.Log($"[SelfProtection] 配置保护完成: {result}");
                AuditLogSystem.Log(LogLevel.Info, LogCategory.System,
                    "配置目录NTFS加固完成", $"结果: {result}");
            }
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, "[SelfProtection] 配置加固失败");
        }

        ErrorReporter.Log("[SelfProtection] 自我保护模块初始化完成");
        return Task.CompletedTask;
    }

    protected override Task OnEnableAsync()
    {
        _engine?.Start();
        ErrorReporter.Log("[SelfProtection] 自我保护引擎已启动（反调试+DACL+完整性校验）");
        AuditLogSystem.Log(LogLevel.Info, LogCategory.System,
            "程序自我保护已启动", "反调试 + DACL加固 + 进程缓解策略 + 完整性校验");
        return Task.CompletedTask;
    }

    protected override Task OnDisableAsync()
    {
        _engine?.Stop();
        ErrorReporter.Log("[SelfProtection] 自我保护引擎已停止");
        return Task.CompletedTask;
    }

    protected override void OnReleaseResources()
    {
        _engine?.Dispose();
        _engine = null;
    }

    private void OnProtectionAlert(string message, ProtectionLevel level)
    {
        var logLevel = level switch
        {
            ProtectionLevel.Critical => LogLevel.Critical,
            ProtectionLevel.Warning => LogLevel.Warning,
            _ => LogLevel.Info
        };

        AuditLogSystem.Log(logLevel, LogCategory.System,
            $"自我保护告警: {message}", $"级别: {level}");

        if (level == ProtectionLevel.Critical)
        {
            ErrorReporter.Log($"[SelfProtection][CRITICAL] {message}", "ERROR");
        }
    }

    protected override string GetStatusSummary()
    {
        if (!IsEnabled) return "已禁用";
        if (_engine == null) return "未初始化";
        return _configHardened
            ? "运行中 | 反调试+DACL+CFG+完整性校验 | 配置已加密"
            : "运行中 | 反调试+DACL+CFG+完整性校验";
    }
}
