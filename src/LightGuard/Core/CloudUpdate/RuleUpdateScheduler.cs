using System.Text.Json;
using System.Text.Json.Serialization;
using LightGuard.Core;

namespace LightGuard.Core.CloudUpdate;

/// <summary>
/// 规则更新调度器状态
/// </summary>
public sealed class UpdateSchedulerStatus
{
    /// <summary>调度器是否正在运行</summary>
    public bool IsRunning { get; set; }

    /// <summary>最后检查时间</summary>
    public DateTime? LastCheckTime { get; set; }

    /// <summary>最后更新时间</summary>
    public DateTime? LastUpdateTime { get; set; }

    /// <summary>累计检查次数</summary>
    public int TotalChecks { get; set; }

    /// <summary>累计成功更新次数</summary>
    public int TotalUpdatesApplied { get; set; }

    /// <summary>最后错误信息</summary>
    public string? LastError { get; set; }

    public override string ToString()
        => IsRunning
            ? $"运行中 | 检查 {TotalChecks} 次 | 更新 {TotalUpdatesApplied} 次 | 最后检查: {LastCheckTime:MM-dd HH:mm}"
            : "已停止";
}

/// <summary>
/// 规则更新调度器
/// <para>在后台定时检查云端规则更新，自动下载并验签应用。</para>
/// <para>使用 System.Threading.Timer 进行周期性检查，所有操作通过 ErrorReporter 记录日志。</para>
/// </summary>
public sealed class RuleUpdateScheduler : IDisposable
{
    #region 字段

    private readonly CloudUpdateClient _client;
    private readonly object _stateLock = new();
    private System.Threading.Timer? _checkTimer;
    private bool _isRunning;
    private bool _isChecking;

    /// <summary>调度器状态文件路径</summary>
    private readonly string _stateFilePath;

    /// <summary>更新历史文件路径</summary>
    private readonly string _historyFilePath;

    /// <summary>持久化状态</summary>
    private DateTime? _lastCheckTime;
    private DateTime? _lastUpdateTime;
    private int _totalChecks;
    private int _totalUpdatesApplied;
    private string? _lastError;

    /// <summary>JSON 序列化选项</summary>
    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    #endregion

    #region 属性

    /// <summary>检查间隔（默认 12 小时）</summary>
    public TimeSpan CheckInterval { get; set; } = TimeSpan.FromHours(12);

    /// <summary>更新通道（默认 Stable）</summary>
    public UpdateChannel Channel { get; set; } = UpdateChannel.Stable;

    /// <summary>是否自动应用更新</summary>
    public bool AutoApply { get; set; } = true;

    /// <summary>最后检查时间</summary>
    public DateTime? LastCheckTime => _lastCheckTime;

    /// <summary>最后更新时间</summary>
    public DateTime? LastUpdateTime => _lastUpdateTime;

    #endregion

    #region 事件

    /// <summary>发现可用更新时触发</summary>
    public event Action<UpdateCheckResult>? UpdateAvailable;

    /// <summary>更新应用完成时触发</summary>
    public event Action<UpdateApplyResult>? UpdateCompleted;

    #endregion

    #region 构造函数

    /// <summary>
    /// 创建规则更新调度器
    /// </summary>
    /// <param name="client">云端更新客户端</param>
    public RuleUpdateScheduler(CloudUpdateClient client)
    {
        _client = client;

        _stateFilePath = Path.Combine(client.BaseDir, "scheduler_state.json");
        _historyFilePath = Path.Combine(client.BaseDir, "update_history.json");

        // 加载持久化状态
        LoadState();
    }

    #endregion

    #region 启停控制

    /// <summary>
    /// 启动后台定时检查
    /// </summary>
    public void Start()
    {
        if (_isRunning) return;

        _isRunning = true;
        _checkTimer = new System.Threading.Timer(
            callback: async _ => await TimerCallbackAsync(),
            state: null,
            dueTime: TimeSpan.FromMinutes(1),      // 启动 1 分钟后首次检查
            period: CheckInterval);

        ErrorReporter.Log($"[CloudUpdate] 调度器已启动，检查间隔: {CheckInterval.TotalHours:F1} 小时，通道: {Channel}");
    }

    /// <summary>
    /// 停止定时检查
    /// </summary>
    public void Stop()
    {
        if (!_isRunning) return;

        _isRunning = false;
        _checkTimer?.Dispose();
        _checkTimer = null;

        ErrorReporter.Log("[CloudUpdate] 调度器已停止");
    }

    #endregion

    #region 检查与应用

    /// <summary>
    /// 定时器回调：检查并应用所有规则更新
    /// </summary>
    private async Task TimerCallbackAsync()
    {
        if (_isChecking) return;
        await CheckAndApplyAllAsync();
    }

    /// <summary>
    /// 检查所有规则并应用更新
    /// </summary>
    /// <returns>所有规则类型的更新应用结果</returns>
    public async Task<List<UpdateApplyResult>> CheckAndApplyAllAsync()
    {
        var results = new List<UpdateApplyResult>();

        if (_isChecking)
        {
            ErrorReporter.Log("[CloudUpdate] 上一次检查尚未完成，跳过本次", "WARN");
            return results;
        }

        _isChecking = true;

        try
        {
            ErrorReporter.Log("[CloudUpdate] ===== 开始全量规则更新检查 =====");

            lock (_stateLock)
            {
                _lastCheckTime = DateTime.Now;
                _totalChecks++;
            }

            // 拉取清单
            var manifest = await _client.FetchManifestAsync(Channel);
            if (manifest == null)
            {
                lock (_stateLock)
                {
                    _lastError = "无法获取更新清单";
                }
                ErrorReporter.Log("[CloudUpdate] 清单获取失败，跳过本次检查", "WARN");
                SaveState();
                return results;
            }

            // 检查每种规则类型
            foreach (RuleType rt in Enum.GetValues<RuleType>())
            {
                var currentVersion = _client.GetLocalVersion(rt);
                var checkResult = await _client.CheckUpdateAsync(rt, currentVersion);

                if (checkResult.HasUpdate && checkResult.ManifestEntry != null)
                {
                    ErrorReporter.Log($"[CloudUpdate] 发现 {rt} 更新: {checkResult.CurrentVersion} -> {checkResult.LatestVersion}");
                    UpdateAvailable?.Invoke(checkResult);

                    if (AutoApply)
                    {
                        var targetDir = _client.GetTargetDir(rt);
                        var applyResult = await _client.DownloadAndApplyAsync(
                            rt, checkResult.ManifestEntry, targetDir, CancellationToken.None);

                        results.Add(applyResult);
                        AddHistoryEntry(applyResult);
                        UpdateCompleted?.Invoke(applyResult);

                        if (applyResult.Success)
                        {
                            lock (_stateLock)
                            {
                                _lastUpdateTime = DateTime.Now;
                                _totalUpdatesApplied++;
                            }
                        }
                    }
                }
                else if (checkResult.Error != null)
                {
                    ErrorReporter.Log($"[CloudUpdate] {rt} 检查失败: {checkResult.Error}", "WARN");
                }
            }

            lock (_stateLock)
            {
                _lastError = null;
            }

            SaveState();
            ErrorReporter.Log($"[CloudUpdate] ===== 全量规则更新检查完成，成功应用 {results.Count} 项更新 =====");

            return results;
        }
        catch (Exception ex)
        {
            lock (_stateLock)
            {
                _lastError = ex.Message;
            }
            ErrorReporter.Report(ex, "[CloudUpdate] 全量规则更新检查异常");
            SaveState();
            return results;
        }
        finally
        {
            _isChecking = false;
        }
    }

    /// <summary>
    /// 检查并应用单个规则更新
    /// </summary>
    /// <param name="ruleType">规则类型</param>
    /// <returns>是否成功应用更新</returns>
    public async Task<bool> CheckAndApplyAsync(RuleType ruleType)
    {
        try
        {
            // 确保清单已缓存
            var manifest = await _client.FetchManifestAsync(Channel);
            if (manifest == null)
            {
                ErrorReporter.Log("[CloudUpdate] 清单获取失败", "WARN");
                return false;
            }

            var currentVersion = _client.GetLocalVersion(ruleType);
            var checkResult = await _client.CheckUpdateAsync(ruleType, currentVersion);

            if (!checkResult.HasUpdate || checkResult.ManifestEntry == null)
            {
                ErrorReporter.Log($"[CloudUpdate] {ruleType} 无可用更新（当前: {currentVersion}）");
                return false;
            }

            UpdateAvailable?.Invoke(checkResult);

            var targetDir = _client.GetTargetDir(ruleType);
            var applyResult = await _client.DownloadAndApplyAsync(
                ruleType, checkResult.ManifestEntry, targetDir, CancellationToken.None);

            AddHistoryEntry(applyResult);
            UpdateCompleted?.Invoke(applyResult);

            if (applyResult.Success)
            {
                lock (_stateLock)
                {
                    _lastUpdateTime = DateTime.Now;
                    _totalUpdatesApplied++;
                }
                SaveState();
                return true;
            }

            return false;
        }
        catch (Exception ex)
        {
            lock (_stateLock)
            {
                _lastError = ex.Message;
            }
            ErrorReporter.Report(ex, $"[CloudUpdate] {ruleType} 更新失败");
            return false;
        }
    }

    #endregion

    #region 状态查询

    /// <summary>
    /// 获取调度器当前状态
    /// </summary>
    public UpdateSchedulerStatus GetStatus()
    {
        lock (_stateLock)
        {
            return new UpdateSchedulerStatus
            {
                IsRunning = _isRunning,
                LastCheckTime = _lastCheckTime,
                LastUpdateTime = _lastUpdateTime,
                TotalChecks = _totalChecks,
                TotalUpdatesApplied = _totalUpdatesApplied,
                LastError = _lastError
            };
        }
    }

    #endregion

    #region 历史记录管理

    /// <summary>
    /// 获取更新历史记录
    /// </summary>
    /// <param name="maxCount">最大返回条数（0 表示全部）</param>
    /// <returns>历史记录列表（按时间倒序）</returns>
    public List<UpdateHistoryEntry> GetHistory(int maxCount = 100)
    {
        try
        {
            if (!File.Exists(_historyFilePath))
                return new List<UpdateHistoryEntry>();

            var json = File.ReadAllText(_historyFilePath);
            var entries = JsonSerializer.Deserialize<List<UpdateHistoryEntry>>(json, JsonOpts);
            if (entries == null)
                return new List<UpdateHistoryEntry>();

            var sorted = entries.OrderByDescending(e => e.Timestamp).ToList();
            return maxCount > 0 ? sorted.Take(maxCount).ToList() : sorted;
        }
        catch
        {
            return new List<UpdateHistoryEntry>();
        }
    }

    /// <summary>
    /// 添加历史记录条目
    /// </summary>
    private void AddHistoryEntry(UpdateApplyResult result)
    {
        try
        {
            var entries = GetHistory(0);
            entries.Add(new UpdateHistoryEntry
            {
                Timestamp = result.Timestamp,
                RuleType = result.RuleType,
                OldVersion = result.OldVersion,
                NewVersion = result.NewVersion,
                Success = result.Success,
                Error = result.Error
            });

            // 限制历史记录最多 500 条
            if (entries.Count > 500)
                entries = entries.OrderByDescending(e => e.Timestamp).Take(500).ToList();

            var json = JsonSerializer.Serialize(entries, JsonOpts);
            File.WriteAllText(_historyFilePath, json);
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, "[CloudUpdate] 保存更新历史失败");
        }
    }

    /// <summary>
    /// 导出更新历史为 CSV 格式
    /// </summary>
    /// <param name="outputPath">输出文件路径</param>
    /// <returns>是否导出成功</returns>
    public bool ExportHistoryToCsv(string outputPath)
    {
        try
        {
            var entries = GetHistory(0);
            var sb = new System.Text.StringBuilder();

            sb.AppendLine("时间,规则类型,旧版本,新版本,状态,错误信息");

            foreach (var e in entries)
            {
                var ruleName = CloudUpdateClient.GetRuleDisplayName(e.RuleType);
                var status = e.Success ? "成功" : "失败";
                var error = (e.Error ?? "").Replace("\"", "\"\"");
                sb.AppendLine($"\"{e.Timestamp:yyyy-MM-dd HH:mm:ss}\",\"{ruleName}\",\"{e.OldVersion}\",\"{e.NewVersion}\",\"{status}\",\"{error}\"");
            }

            // 添加 BOM 以便 Excel 正确识别 UTF-8
            var bom = new byte[] { 0xEF, 0xBB, 0xBF };
            var content = System.Text.Encoding.UTF8.GetBytes(sb.ToString());
            var fullContent = new byte[bom.Length + content.Length];
            Buffer.BlockCopy(bom, 0, fullContent, 0, bom.Length);
            Buffer.BlockCopy(content, 0, fullContent, bom.Length, content.Length);

            File.WriteAllBytes(outputPath, fullContent);
            return true;
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, "[CloudUpdate] 导出历史记录失败");
            return false;
        }
    }

    #endregion

    #region 状态持久化

    /// <summary>
    /// 从配置加载调度参数
    /// </summary>
    public void LoadFromConfig(AppConfig config)
    {
        var cu = config.CloudUpdate;
        CheckInterval = TimeSpan.FromHours(cu.CheckIntervalHours > 0 ? cu.CheckIntervalHours : 12);

        Channel = cu.Channel?.ToLowerInvariant() switch
        {
            "beta" => UpdateChannel.Beta,
            "nightly" => UpdateChannel.Nightly,
            _ => UpdateChannel.Stable
        };

        AutoApply = cu.AutoApply;
    }

    /// <summary>
    /// 将调度参数保存到配置
    /// </summary>
    public void SaveToConfig(AppConfig config)
    {
        config.CloudUpdate.CheckIntervalHours = (int)CheckInterval.TotalHours;
        config.CloudUpdate.Channel = Channel.ToString();
        config.CloudUpdate.AutoApply = AutoApply;
        ConfigManager.Save(config);
    }

    /// <summary>
    /// 加载持久化状态（检查时间、更新次数等）
    /// </summary>
    private void LoadState()
    {
        try
        {
            if (!File.Exists(_stateFilePath))
                return;

            var json = File.ReadAllText(_stateFilePath);
            var state = JsonSerializer.Deserialize<SchedulerPersistentState>(json, JsonOpts);
            if (state != null)
            {
                _lastCheckTime = state.LastCheckTime;
                _lastUpdateTime = state.LastUpdateTime;
                _totalChecks = state.TotalChecks;
                _totalUpdatesApplied = state.TotalUpdatesApplied;
            }
        }
        catch { }
    }

    /// <summary>
    /// 保存持久化状态
    /// </summary>
    private void SaveState()
    {
        try
        {
            var state = new SchedulerPersistentState
            {
                LastCheckTime = _lastCheckTime,
                LastUpdateTime = _lastUpdateTime,
                TotalChecks = _totalChecks,
                TotalUpdatesApplied = _totalUpdatesApplied
            };
            var json = JsonSerializer.Serialize(state, JsonOpts);
            File.WriteAllText(_stateFilePath, json);
        }
        catch { }
    }

    #endregion

    #region IDisposable

    public void Dispose()
    {
        Stop();
    }

    #endregion

    #region 持久化状态数据结构

    private sealed class SchedulerPersistentState
    {
        [JsonPropertyName("lastCheckTime")]
        public DateTime? LastCheckTime { get; set; }

        [JsonPropertyName("lastUpdateTime")]
        public DateTime? LastUpdateTime { get; set; }

        [JsonPropertyName("totalChecks")]
        public int TotalChecks { get; set; }

        [JsonPropertyName("totalUpdatesApplied")]
        public int TotalUpdatesApplied { get; set; }
    }

    #endregion
}
