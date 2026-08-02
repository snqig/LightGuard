using LightGuard.Core;
using LightGuard.Core.Interfaces;
using LightGuard.Decryption;

namespace LightGuard.Modules;

/// <summary>
/// 勒索解密模块（P0-1）
/// 整合勒索家族检测、官方解密工具下载/校验/执行，提供应急解密能力
/// 支持单文件和批量目录解密，解密前自动备份，执行节流降低启发式风险
/// </summary>
public sealed class RansomwareDecryptionModule : ModuleBase
{
    /// <summary>解密工具管理器</summary>
    private readonly DecryptionToolManager _toolManager;

    /// <summary>勒索解密引擎</summary>
    private readonly RansomwareDecryptor _decryptor;

    /// <summary>当前加载的工具索引</summary>
    private DecryptionToolIndex? _toolIndex;

    /// <summary>可用解密器数量缓存</summary>
    private int _availableDecryptorCount;

    /// <summary>
    /// 构造函数
    /// </summary>
    public RansomwareDecryptionModule(AppState appState) : base(appState)
    {
        _toolManager = new DecryptionToolManager();
        _decryptor = new RansomwareDecryptor(_toolManager);
    }

    /// <inheritdoc/>
    public override string Id => "ransomware-decrypt";

    /// <inheritdoc/>
    public override string DisplayName => "勒索解密";

    /// <inheritdoc/>
    public override string Description =>
        "自动识别勒索家族，匹配官方解密工具，支持单文件/批量目录应急解密，解密前自动备份";

    /// <inheritdoc/>
    public override ModuleCategory Category => ModuleCategory.Ransomware;

    /// <inheritdoc/>
    public override bool RequiresAdmin => true;

    #region 公共属性

    /// <summary>获取解密引擎实例（供 UI 和其他模块调用）</summary>
    public RansomwareDecryptor Decryptor => _decryptor;

    /// <summary>获取工具管理器实例（供 UI 调用下载/校验）</summary>
    public DecryptionToolManager ToolManager => _toolManager;

    /// <summary>获取当前工具索引</summary>
    public DecryptionToolIndex? ToolIndex => _toolIndex;

    /// <summary>获取已下载且可用的解密器数量</summary>
    public int AvailableDecryptorCount => _availableDecryptorCount;

    #endregion

    #region 生命周期

    protected override async Task OnInitializeAsync()
    {
        // 加载本地工具索引
        _toolIndex = _toolManager.LoadLocalIndex();

        // 统计可用解密器
        _availableDecryptorCount = CountAvailableDecryptors();

        // 记录已知家族和解密器状态
        var totalFamilies = _toolIndex.Families.Count;
        var familiesWithDecryptor = _toolIndex.Families.Count(f => f.HasDecryptor);
        var downloadedTools = _toolIndex.Families.Count(f =>
            f.HasDecryptor && _toolManager.IsToolAvailable(f.Family));

        ErrorReporter.Log($"[勒索解密] 模块初始化完成 | 已知家族 {totalFamilies} 个 | " +
                          $"有解密器 {familiesWithDecryptor} 个 | 已下载工具 {downloadedTools} 个");

        // 后台尝试更新索引（不阻塞初始化）
        _ = Task.Run(async () =>
        {
            try
            {
                await _toolManager.UpdateToolIndexAsync();
                _toolIndex = _toolManager.LoadLocalIndex();
                _availableDecryptorCount = CountAvailableDecryptors();
                ErrorReporter.Log("[勒索解密] 工具索引后台更新完成");
            }
            catch (Exception ex)
            {
                ErrorReporter.Report(ex, "[勒索解密] 工具索引后台更新失败（不影响使用内置索引）");
            }
        });

        await Task.CompletedTask;
    }

    protected override Task OnEnableAsync()
    {
        ErrorReporter.Log("[勒索解密] 模块已启用，解密引擎就绪");
        return Task.CompletedTask;
    }

    protected override Task OnDisableAsync()
    {
        ErrorReporter.Log("[勒索解密] 模块已禁用");
        return Task.CompletedTask;
    }

    protected override void OnReleaseResources()
    {
        _decryptor.Dispose();
        ErrorReporter.Log("[勒索解密] 模块资源已释放");
    }

    protected override string GetStatusSummary()
    {
        if (!IsEnabled) return "已禁用";
        var totalFamilies = _toolIndex?.Families.Count ?? 0;
        return $"运行中 | 已知家族 {totalFamilies} 个 | 可用解密器 {_availableDecryptorCount} 个";
    }

    #endregion

    #region 公共方法

    /// <summary>
    /// 获取可用解密器数量（重新统计）
    /// </summary>
    public int GetAvailableDecryptorCount()
    {
        _availableDecryptorCount = CountAvailableDecryptors();
        return _availableDecryptorCount;
    }

    /// <summary>
    /// 刷新工具索引并重新统计
    /// </summary>
    public void RefreshIndex()
    {
        _toolIndex = _toolManager.LoadLocalIndex();
        _availableDecryptorCount = CountAvailableDecryptors();
    }

    /// <summary>
    /// 获取所有已知家族信息列表
    /// </summary>
    public List<RansomwareFamilyInfo> GetKnownFamilies()
    {
        return _toolIndex?.Families ?? _decryptor.GetDetector().GetKnownFamilies();
    }

    #endregion

    #region 私有方法

    /// <summary>统计已下载且可用的解密器数量</summary>
    private int CountAvailableDecryptors()
    {
        try
        {
            var families = _toolIndex?.Families ?? _decryptor.GetDetector().GetKnownFamilies();
            return families.Count(f => f.HasDecryptor && _toolManager.IsToolAvailable(f.Family));
        }
        catch
        {
            return 0;
        }
    }

    #endregion
}
