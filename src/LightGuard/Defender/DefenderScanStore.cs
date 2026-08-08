using System.Text.Json;
using System.Text.Json.Serialization;
using LightGuard.Core;

namespace LightGuard.Defender;

/// <summary>
/// Defender 扫描历史与威胁清单持久化存储（P1-5 Defender 全业务集成）。
/// <para>将扫描历史与累计威胁写入 DataDir/defender/defender_data.json，
/// 进程重启后由 DefenderScanModule 加载恢复，避免重启丢失。</para>
/// <para>持久化条数上限与内存保持一致（历史 200 条、威胁 1000 条），
/// RawOutput 原始输出截断保存以控制文件体积。</para>
/// </summary>
public static class DefenderScanStore
{
    /// <summary>持久化目录名（DataDir/defender）</summary>
    public const string FolderName = "defender";

    /// <summary>持久化文件名</summary>
    public const string FileName = "defender_data.json";

    /// <summary>RawOutput 截断长度（原始 MpCmdRun 输出仅调试用）</summary>
    private const int MaxRawOutputLength = 2000;

    /// <summary>历史记录上限（与 DefenderScanModule 内存上限一致）</summary>
    public const int MaxHistory = 200;

    /// <summary>威胁记录上限（与 DefenderScanModule 内存上限一致）</summary>
    public const int MaxThreats = 1000;

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = false,
        PropertyNameCaseInsensitive = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    /// <summary>
    /// 保存扫描历史与威胁清单（幂等；失败仅记日志不抛出，不影响主流程）。
    /// </summary>
    /// <param name="history">扫描历史（内部按上限裁剪）</param>
    /// <param name="threats">累计威胁清单（内部按上限裁剪）</param>
    public static void Save(IReadOnlyList<DefenderScanResult> history, IReadOnlyList<DefenderThreat> threats)
    {
        try
        {
            var dir = Path.Combine(ConfigManager.GetDataDir(), FolderName);
            Directory.CreateDirectory(dir);

            var snapshot = new DefenderPersistedData
            {
                SavedAt = DateTime.Now,
                History = history.Select(TrimRawOutput).TakeLast(MaxHistory).ToList(),
                Threats = threats.TakeLast(MaxThreats).ToList()
            };

            var json = JsonSerializer.Serialize(snapshot, JsonOpts);
            var path = Path.Combine(dir, FileName);
            var tmp = path + ".tmp";
            File.WriteAllText(tmp, json);
            File.Move(tmp, path, true); // 原子替换，防半写

            ErrorReporter.Log($"[DefenderScanStore] 已持久化：历史 {snapshot.History.Count} 条 / 威胁 {snapshot.Threats.Count} 条");
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, "[DefenderScanStore] 保存失败");
        }
    }

    /// <summary>
    /// 加载持久化的扫描历史与威胁清单；文件不存在或损坏时返回空集合。
    /// </summary>
    /// <returns>(历史, 威胁) 元组</returns>
    public static (List<DefenderScanResult> History, List<DefenderThreat> Threats) Load()
    {
        var empty = (new List<DefenderScanResult>(), new List<DefenderThreat>());
        try
        {
            var path = Path.Combine(ConfigManager.GetDataDir(), FolderName, FileName);
            if (!File.Exists(path)) return empty;

            var json = File.ReadAllText(path);
            var data = JsonSerializer.Deserialize<DefenderPersistedData>(json, JsonOpts);
            if (data == null) return empty;

            ErrorReporter.Log($"[DefenderScanStore] 已加载：历史 {data.History.Count} 条 / 威胁 {data.Threats.Count} 条");
            return (data.History.TakeLast(MaxHistory).ToList(), data.Threats.TakeLast(MaxThreats).ToList());
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, "[DefenderScanStore] 加载失败（使用空数据）");
            return empty;
        }
    }

    /// <summary>删除持久化文件（清空历史时调用）。</summary>
    public static void Clear()
    {
        try
        {
            var path = Path.Combine(ConfigManager.GetDataDir(), FolderName, FileName);
            if (File.Exists(path)) File.Delete(path);
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, "[DefenderScanStore] 清理失败");
        }
    }

    /// <summary>复制结果并截断原始输出（避免大 JSON）。</summary>
    private static DefenderScanResult TrimRawOutput(DefenderScanResult r)
    {
        if (string.IsNullOrEmpty(r.RawOutput) || r.RawOutput.Length <= MaxRawOutputLength)
            return r;

        return new DefenderScanResult
        {
            ThreatsFound = r.ThreatsFound,
            ThreatNames = r.ThreatNames,
            Threats = r.Threats,
            ScanDuration = r.ScanDuration,
            ScannedItems = r.ScannedItems,
            ExitCode = r.ExitCode,
            Success = r.Success,
            ErrorMessage = r.ErrorMessage,
            ScanType = r.ScanType,
            TargetPath = r.TargetPath,
            CompletedAt = r.CompletedAt,
            RawOutput = r.RawOutput[..MaxRawOutputLength]
        };
    }

    /// <summary>持久化数据根对象。</summary>
    private sealed class DefenderPersistedData
    {
        /// <summary>保存时间</summary>
        public DateTime SavedAt { get; set; }

        /// <summary>扫描历史</summary>
        public List<DefenderScanResult> History { get; set; } = new();

        /// <summary>累计威胁清单</summary>
        public List<DefenderThreat> Threats { get; set; } = new();
    }
}
