using LightGuard.Core;
using LightGuard.Core.CloudUpdate;
using LightGuard.Core.Interfaces;

namespace LightGuard.Modules;

/// <summary>
/// 云端规则自动更新模块
/// <para>基于 RSA-2048 签名校验的云端规则自动更新系统，</para>
/// <para>支持 YARA 勒索规则、广告拦截规则、解密工具索引、病毒特征库的增量更新。</para>
/// <para>所有更新包均经过 SHA256 + RSA 双重验证，防止服务器劫持下发恶意规则。</para>
/// </summary>
public sealed class CloudUpdateModule : ModuleBase
{
    /// <summary>云端更新客户端</summary>
    public CloudUpdateClient? Client { get; private set; }

    /// <summary>规则更新调度器</summary>
    public RuleUpdateScheduler? Scheduler { get; private set; }

    public CloudUpdateModule(AppState appState) : base(appState)
    {
    }

    /// <inheritdoc/>
    public override string Id => "cloud-update";

    /// <inheritdoc/>
    public override string DisplayName => "云端规则更新";

    /// <inheritdoc/>
    public override string Description => "RSA 签名校验的云端规则自动增量更新：YARA 勒索规则、广告拦截规则、解密工具索引、病毒特征库";

    /// <inheritdoc/>
    public override ModuleCategory Category => ModuleCategory.Update;

    /// <inheritdoc/>
    protected override async Task OnInitializeAsync()
    {
        await Task.Run(() =>
        {
            // 从配置加载服务器地址
            var serverUrl = AppState.Config.CloudUpdate.ServerUrl;

            // 创建客户端和调度器
            Client = new CloudUpdateClient(serverUrl);
            Scheduler = new RuleUpdateScheduler(Client);

            // 从配置加载调度参数
            Scheduler.LoadFromConfig(AppState.Config);

            // P1-3：订阅规则应用事件（YARA 规则同步生效 + 引擎热重载）
            Client.RuleApplied += OnRuleApplied;

            ErrorReporter.Log($"[CloudUpdate] 模块初始化完成 - 服务器: {Client.BaseUrl} | 间隔: {Scheduler.CheckInterval.TotalHours:F1}h | 通道: {Scheduler.Channel}");
        });
    }

    /// <inheritdoc/>
    protected override async Task OnEnableAsync()
    {
        await Task.Run(() =>
        {
            if (!AppState.Config.CloudUpdate.Enabled)
            {
                ErrorReporter.Log("[CloudUpdate] 云端更新已在配置中关闭，仅手动检查");
                return;
            }

            Scheduler?.Start();
        });
    }

    /// <inheritdoc/>
    protected override async Task OnDisableAsync()
    {
        await Task.Run(() =>
        {
            Scheduler?.Stop();
            ErrorReporter.Log("[CloudUpdate] 模块已禁用，调度器已停止");
        });
    }

    /// <inheritdoc/>
    protected override void OnReleaseResources()
    {
        if (Client != null)
        {
            Client.RuleApplied -= OnRuleApplied;
        }
        Scheduler?.Dispose();
        Client?.Dispose();
    }

    /// <summary>
    /// 规则应用成功联动（P1-3）：YARA 勒索规则同步到 YaraEngine 加载目录并热重载。
    /// <para>CloudUpdateClient 下载目录（cloudupdate/）与 YaraEngine 加载目录（yararules/）不同，
    /// 必须在此处同步文件 + 签名，并触发引擎热重载使新规则立即生效。</para>
    /// </summary>
    private void OnRuleApplied(LightGuard.Core.CloudUpdate.RuleType ruleType, string finalPath, string signature)
    {
        try
        {
            // 仅 YARA 勒索规则需要联动生效（其余规则由各自消费方按需加载）
            if (ruleType != LightGuard.Core.CloudUpdate.RuleType.YaraRansomware) return;
            if (string.IsNullOrEmpty(finalPath) || !File.Exists(finalPath)) return;

            var yaraDir = Path.Combine(ConfigManager.GetDataDir(), "yararules");
            Directory.CreateDirectory(yaraDir);

            // 同步规则文件到 YaraEngine 加载目录
            File.Copy(finalPath, Path.Combine(yaraDir, "online_rules.json"), true);

            // 同步签名文件（无签名则清除旧签名，YaraEngine 将直接加载规则文件）
            var sigPath = Path.Combine(yaraDir, "online_rules.sig");
            if (!string.IsNullOrEmpty(signature))
            {
                File.WriteAllText(sigPath, signature);
            }
            else if (File.Exists(sigPath))
            {
                File.Delete(sigPath);
            }

            // 引擎热重载（EtwYaraModule 持有 RansomDefenseEngine）
            var etw = AppState.Modules.GetModule("etw-yara-defense") as EtwYaraModule;
            var engine = etw?.GetDefenseEngine()?.GetYaraEngine();
            if (engine != null)
            {
                var loaded = engine.ReloadOnlineRules();
                ErrorReporter.Log($"[CloudUpdate] YARA 在线规则已同步并热重载：{loaded} 条");
            }
            else
            {
                ErrorReporter.Log("[CloudUpdate] YARA 规则已同步到 yararules（防御引擎未运行，下次启动生效）");
            }
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, "[CloudUpdate] YARA 规则联动失败");
        }
    }

    /// <inheritdoc/>
    protected override string GetStatusSummary()
    {
        if (Scheduler == null)
            return "未初始化";

        var status = Scheduler.GetStatus();
        if (!status.IsRunning)
            return "已停止";

        var lastCheck = status.LastCheckTime?.ToString("MM-dd HH:mm") ?? "从未";
        var lastUpdate = status.LastUpdateTime?.ToString("MM-dd HH:mm") ?? "从未";
        return $"运行中 | 检查 {status.TotalChecks} 次 | 更新 {status.TotalUpdatesApplied} 次 | 最后检查: {lastCheck} | 最后更新: {lastUpdate}";
    }

    /// <inheritdoc/>
    public override void Dispose()
    {
        Scheduler?.Dispose();
        Client?.Dispose();
        base.Dispose();
    }
}
