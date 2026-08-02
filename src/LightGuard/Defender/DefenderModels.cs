namespace LightGuard.Defender;

// ============================================================================
// Microsoft Defender 查杀调度模块 - 数据模型
// P0-4：Defender 按需查杀调度
// 所有与 MpCmdRun.exe 交互的状态、结果、进度均使用以下模型
// ============================================================================

/// <summary>
/// Defender 扫描类型
/// </summary>
public enum DefenderScanType
{
    /// <summary>单文件扫描（-Scan -ScanType 3 -File）</summary>
    SingleFile,

    /// <summary>目录扫描（-Scan -ScanType 3 -File 目录）</summary>
    Directory,

    /// <summary>快速扫描（-Scan -ScanType 1）</summary>
    QuickScan,

    /// <summary>全盘扫描（-Scan -ScanType 2）</summary>
    FullScan
}

/// <summary>
/// 威胁严重等级
/// </summary>
public enum ThreatSeverity
{
    Low,
    Medium,
    High,
    Severe
}

/// <summary>
/// 威胁处置动作
/// </summary>
public enum ThreatAction
{
    None,
    Quarantine,
    Remove,
    Allow,
    Block
}

/// <summary>
/// Defender 引擎与病毒库健康状态信息（对应 Get-MpComputerStatus）
/// </summary>
public sealed class DefenderStatusInfo
{
    /// <summary>实时保护是否启用</summary>
    public bool RealTimeProtectionEnabled { get; set; }

    /// <summary>反病毒是否启用</summary>
    public bool AntivirusEnabled { get; set; }

    /// <summary>反间谍软件是否启用</summary>
    public bool AntispywareEnabled { get; set; }

    /// <summary>病毒库最后更新时间</summary>
    public DateTime SignatureLastUpdated { get; set; }

    /// <summary>病毒库版本号</summary>
    public string SignatureVersion { get; set; } = string.Empty;

    /// <summary>引擎版本号</summary>
    public string EngineVersion { get; set; } = string.Empty;

    /// <summary>产品版本号</summary>
    public string ProductVersion { get; set; } = string.Empty;

    /// <summary>整体是否健康（实时保护开启 + 病毒库不过期）</summary>
    public bool IsHealthy { get; set; }

    /// <summary>状态获取是否成功</summary>
    public bool IsValid { get; set; }

    /// <summary>状态获取失败时的错误信息</summary>
    public string ErrorMessage { get; set; } = string.Empty;
}

/// <summary>
/// 单次 Defender 扫描结果
/// </summary>
public sealed class DefenderScanResult
{
    /// <summary>发现的威胁数量</summary>
    public int ThreatsFound { get; set; }

    /// <summary>发现的威胁名称列表</summary>
    public List<string> ThreatNames { get; set; } = new();

    /// <summary>详细的威胁信息列表</summary>
    public List<DefenderThreat> Threats { get; set; } = new();

    /// <summary>扫描耗时</summary>
    public TimeSpan ScanDuration { get; set; }

    /// <summary>扫描的文件/项目数量</summary>
    public int ScannedItems { get; set; }

    /// <summary>MpCmdRun 进程退出码（0=干净, 2=发现威胁, 其他=错误）</summary>
    public int ExitCode { get; set; }

    /// <summary>扫描是否成功执行</summary>
    public bool Success { get; set; }

    /// <summary>失败时的错误信息</summary>
    public string ErrorMessage { get; set; } = string.Empty;

    /// <summary>扫描类型</summary>
    public DefenderScanType ScanType { get; set; }

    /// <summary>扫描目标路径（文件/目录扫描时有效）</summary>
    public string? TargetPath { get; set; }

    /// <summary>扫描完成时间</summary>
    public DateTime CompletedAt { get; set; } = DateTime.Now;

    /// <summary>MpCmdRun 原始输出（调试用）</summary>
    public string RawOutput { get; set; } = string.Empty;
}

/// <summary>
/// 单个威胁详情
/// </summary>
public sealed class DefenderThreat
{
    /// <summary>威胁名称</summary>
    public string ThreatName { get; set; } = string.Empty;

    /// <summary>受影响的文件路径</summary>
    public string FilePath { get; set; } = string.Empty;

    /// <summary>严重等级</summary>
    public ThreatSeverity Severity { get; set; } = ThreatSeverity.Medium;

    /// <summary>已采取的处置动作</summary>
    public ThreatAction ActionTaken { get; set; } = ThreatAction.None;

    /// <summary>发现时间</summary>
    public DateTime DetectedAt { get; set; } = DateTime.Now;
}

/// <summary>
/// 扫描进度信息（实时上报）
/// </summary>
public sealed class DefenderScanProgress
{
    /// <summary>完成百分比（0-100，-1 表示无法估算，UI 应使用滚动条样式）</summary>
    public double PercentComplete { get; set; }

    /// <summary>当前正在扫描的文件路径</summary>
    public string CurrentFile { get; set; } = string.Empty;

    /// <summary>已扫描的文件数量</summary>
    public int FilesScanned { get; set; }

    /// <summary>本次扫描累计发现的威胁数</summary>
    public int ThreatsFound { get; set; }

    /// <summary>扫描是否仍在运行</summary>
    public bool IsRunning { get; set; }
}
