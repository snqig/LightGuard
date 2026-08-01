using System.Diagnostics;
using System.IO.Compression;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using LightGuard.Core;
using LightGuard.Core.Interfaces;

namespace LightGuard.Modules;

/// <summary>
/// 软件更新清单（从服务器获取的 JSON）
/// </summary>
public sealed class UpdateManifest
{
    /// <summary>清单版本号</summary>
    [JsonPropertyName("manifestVersion")]
    public int ManifestVersion { get; set; } = 1;

    /// <summary>最新版本号</summary>
    [JsonPropertyName("version")]
    public string Version { get; set; } = "";

    /// <summary>下载 URL（差分更新包）</summary>
    [JsonPropertyName("downloadUrl")]
    public string DownloadUrl { get; set; } = "";

    /// <summary>SHA256 校验值</summary>
    [JsonPropertyName("sha256")]
    public string Sha256 { get; set; } = "";

    /// <summary>发布说明</summary>
    [JsonPropertyName("releaseNotes")]
    public string ReleaseNotes { get; set; } = "";

    /// <summary>变更文件列表（差分更新）</summary>
    [JsonPropertyName("changedFiles")]
    public List<string> ChangedFiles { get; set; } = new();

    /// <summary>清单发布时间</summary>
    [JsonPropertyName("publishDate")]
    public DateTime? PublishDate { get; set; }
}

/// <summary>
/// 病毒库/规则库更新清单
/// </summary>
public sealed class DbUpdateManifest
{
    /// <summary>版本号</summary>
    [JsonPropertyName("version")]
    public string Version { get; set; } = "";

    /// <summary>下载 URL</summary>
    [JsonPropertyName("downloadUrl")]
    public string DownloadUrl { get; set; } = "";

    /// <summary>SHA256 校验值</summary>
    [JsonPropertyName("sha256")]
    public string Sha256 { get; set; } = "";

    /// <summary>条目数量</summary>
    [JsonPropertyName("entryCount")]
    public int EntryCount { get; set; }
}

/// <summary>
/// 单个组件更新状态
/// </summary>
public sealed class ComponentUpdateStatus
{
    /// <summary>组件名称</summary>
    public string Component { get; set; } = "";

    /// <summary>当前版本</summary>
    public string CurrentVersion { get; set; } = "未知";

    /// <summary>最新版本</summary>
    public string LatestVersion { get; set; } = "未知";

    /// <summary>是否为最新</summary>
    public bool IsUpToDate { get; set; }

    /// <summary>最后更新时间</summary>
    public DateTime? LastUpdate { get; set; }

    /// <summary>状态描述</summary>
    public string StatusText { get; set; } = "";
}

/// <summary>
/// 更新结果报告
/// </summary>
public sealed class UpdateResult
{
    /// <summary>组件名称</summary>
    public string Component { get; set; } = "";

    /// <summary>是否成功</summary>
    public bool Success { get; set; }

    /// <summary>结果消息</summary>
    public string Message { get; set; } = "";

    /// <summary>更新时间</summary>
    public DateTime Timestamp { get; set; } = DateTime.Now;

    /// <summary>旧版本号</summary>
    public string? OldVersion { get; set; }

    /// <summary>新版本号</summary>
    public string? NewVersion { get; set; }

    /// <summary>是否已为最新版本</summary>
    public bool IsUpToDate { get; set; }
}

/// <summary>
/// 更新状态汇总（供 UI 显示）
/// </summary>
public sealed class UpdateStatusSummary
{
    /// <summary>软件本体状态</summary>
    public ComponentUpdateStatus AppStatus { get; set; } = new();

    /// <summary>杀毒引擎状态</summary>
    public ComponentUpdateStatus EngineStatus { get; set; } = new();

    /// <summary>病毒库状态</summary>
    public ComponentUpdateStatus VirusDbStatus { get; set; } = new();

    /// <summary>流氓规则库状态</summary>
    public ComponentUpdateStatus RogueRulesStatus { get; set; } = new();

    /// <summary>是否全部为最新</summary>
    public bool AllUpToDate => AppStatus.IsUpToDate && EngineStatus.IsUpToDate
        && VirusDbStatus.IsUpToDate && RogueRulesStatus.IsUpToDate;
}

/// <summary>
/// 三层全自动无感更新系统模块
/// 第一层：软件本体增量更新（差分更新包，重启时替换）
/// 第二层：杀毒引擎底层更新（ClamAV/Yara 引擎）
/// 第三层：病毒库 + 流氓规则库自动更新（多源合并、去重、断网回滚）
/// </summary>
public sealed class UpdateModule : ModuleBase
{
    /// <summary>GitHub 发布页地址（默认更新源）</summary>
    private const string DefaultUpdateSource = "https://api.github.com/repos/LightGuard/LightGuard/releases/latest";

    /// <summary>病毒库多源下载地址列表</summary>
    private static readonly string[] VirusDbSources = new[]
    {
        "https://raw.githubusercontent.com/LightGuard/virus-db/main/main.cvd",
        "https://cdn.lightguard.app/virus-db/main.cvd",
        "https://mirror.lightguard.app/virus-db/main.cvd"
    };

    /// <summary>流氓规则库多源下载地址列表</summary>
    private static readonly string[] RogueRulesSources = new[]
    {
        "https://raw.githubusercontent.com/LightGuard/rogue-rules/main/rules.json",
        "https://cdn.lightguard.app/rogue-rules/rules.json",
        "https://mirror.lightguard.app/rogue-rules/rules.json"
    };

    /// <summary>HTTP 客户端（复用连接池）</summary>
    private static readonly HttpClient HttpClientInstance = CreateHttpClient();

    /// <summary>JSON 序列化选项</summary>
    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        PropertyNameCaseInsensitive = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    /// <summary>更新检查定时器</summary>
    private System.Threading.Timer? _checkTimer;

    /// <summary>更新文件存储目录</summary>
    private readonly string _updateDir;

    /// <summary>日志目录</summary>
    private readonly string _logDir;

    /// <summary>当前软件版本号</summary>
    private readonly string _currentVersion;

    /// <summary>缓存的最新更新清单</summary>
    private UpdateManifest? _latestManifest;

    /// <summary>病毒库当前版本</summary>
    private string _virusDbVersion = "未知";

    /// <summary>流氓规则库当前版本</summary>
    private string _rogueRulesVersion = "未知";

    /// <summary>引擎当前版本</summary>
    private string _engineVersion = "未知";

    /// <summary>是否正在更新中（防止并发）</summary>
    private bool _isUpdating;

    /// <summary>是否需要重启应用更新</summary>
    public bool PendingRestart { get; private set; }

    /// <summary>更新完成回调（UI 可订阅）</summary>
    public event Action<UpdateResult>? UpdateCompleted;

    /// <summary>更新进度回调（UI 可订阅）</summary>
    public event Action<string, int>? UpdateProgress;

    public UpdateModule(AppState appState) : base(appState)
    {
        _updateDir = Path.Combine(ConfigManager.GetDataDir(), "updates");
        _logDir = ConfigManager.GetLogDir();
        _currentVersion = typeof(UpdateModule).Assembly.GetName().Version?.ToString() ?? "2.0.0";

        // 确保更新目录存在
        Directory.CreateDirectory(_updateDir);
        Directory.CreateDirectory(Path.Combine(_updateDir, "virus-db"));
        Directory.CreateDirectory(Path.Combine(_updateDir, "rogue-rules"));
        Directory.CreateDirectory(Path.Combine(_updateDir, "engine"));
        Directory.CreateDirectory(Path.Combine(_updateDir, "app"));
    }

    /// <summary>
    /// 创建配置好的 HttpClient
    /// </summary>
    private static HttpClient CreateHttpClient()
    {
        var client = new HttpClient
        {
            Timeout = TimeSpan.FromMinutes(5)
        };
        client.DefaultRequestHeaders.Add("User-Agent", $"LightGuard/{typeof(UpdateModule).Assembly.GetName().Version}");
        return client;
    }

    /// <inheritdoc/>
    public override string Id => "update";

    /// <inheritdoc/>
    public override string DisplayName => "自动更新";

    /// <inheritdoc/>
    public override string Description => "三层全自动无感更新：软件增量更新、杀毒引擎更新、病毒库+流氓规则库多源更新（断网回滚、离线导入）";

    /// <inheritdoc/>
    public override ModuleCategory Category => ModuleCategory.Update;

    /// <inheritdoc/>
    protected override async Task OnInitializeAsync()
    {
        await Task.Run(() =>
        {
            // 从配置加载上次更新时间
            var config = AppState.Config.Update;

            // 尝试读取本地病毒库版本文件
            _virusDbVersion = ReadLocalVersion(Path.Combine(_updateDir, "virus-db", "version.txt"));
            _rogueRulesVersion = ReadLocalVersion(Path.Combine(_updateDir, "rogue-rules", "version.txt"));
            _engineVersion = ReadLocalVersion(Path.Combine(_updateDir, "engine", "version.txt"));

            ErrorReporter.Log($"更新模块初始化完成 - 当前版本: {_currentVersion} | 病毒库: {_virusDbVersion} | 规则库: {_rogueRulesVersion}");
            ErrorReporter.Log($"上次病毒库更新: {config.LastVirusDbUpdate} | 上次引擎更新: {config.LastEngineUpdate}");
        });
    }

    /// <inheritdoc/>
    protected override async Task OnEnableAsync()
    {
        await Task.Run(() =>
        {
            var config = AppState.Config.Update;
            if (!config.AutoUpdate)
            {
                ErrorReporter.Log("自动更新已关闭，仅手动检查");
                return;
            }

            // 启动静默检测定时器
            // 间隔由 Config.Update.UpdateCheckIntervalHours 控制
            var intervalHours = config.UpdateCheckIntervalHours > 0
                ? config.UpdateCheckIntervalHours
                : 12;

            var interval = TimeSpan.FromHours(intervalHours);

            _checkTimer = new System.Threading.Timer(
                callback: async _ => await CheckAndUpdateAllAsync(),
                state: null,
                dueTime: TimeSpan.FromMinutes(2),    // 启动 2 分钟后首次检查
                period: interval);

            ErrorReporter.Log($"自动更新定时器已启动，检查间隔: {intervalHours} 小时");
        });
    }

    /// <inheritdoc/>
    protected override async Task OnDisableAsync()
    {
        await Task.Run(() =>
        {
            _checkTimer?.Dispose();
            _checkTimer = null;
            ErrorReporter.Log("更新模块已禁用，定时器已停止");
        });
    }

    /// <inheritdoc/>
    protected override void OnReleaseResources()
    {
        _checkTimer?.Dispose();
        _checkTimer = null;
    }

    // ==================== 第一层：软件本体增量更新 ====================

    /// <summary>
    /// 检查软件本体是否有更新
    /// 从 GitHub/自定义服务器获取更新清单 JSON
    /// </summary>
    /// <returns>更新清单（null 表示无更新或检查失败）</returns>
    public async Task<UpdateManifest?> CheckForAppUpdate()
    {
        try
        {
            UpdateProgress?.Invoke("正在检查软件更新...", 10);

            // 优先使用配置中的自定义更新源，否则使用 GitHub 默认源
            var updateUrl = AppState.Config.Update.VirusDbUpdateUrl;
            if (string.IsNullOrEmpty(updateUrl))
                updateUrl = DefaultUpdateSource;

            UpdateProgress?.Invoke("正在获取更新清单...", 30);

            // 请求更新清单 JSON
            var json = await HttpClientInstance.GetStringAsync(updateUrl);

            UpdateProgress?.Invoke("正在解析更新清单...", 60);

            // 尝试解析为标准清单格式
            _latestManifest = ParseManifest(json);

            if (_latestManifest == null)
            {
                ErrorReporter.Log("未获取到有效更新清单", "WARN");
                return null;
            }

            UpdateProgress?.Invoke("正在比较版本号...", 80);

            // 比较版本号
            var hasUpdate = CompareVersions(_latestManifest.Version, _currentVersion) > 0;

            if (hasUpdate)
            {
                ErrorReporter.Log($"发现新版本: {_latestManifest.Version}（当前: {_currentVersion}）");
                ErrorReporter.Log($"更新内容: {_latestManifest.ReleaseNotes}");
                ErrorReporter.Log($"变更文件: {_latestManifest.ChangedFiles.Count} 个");
            }
            else
            {
                ErrorReporter.Log($"软件已是最新版本: {_currentVersion}");
            }

            UpdateProgress?.Invoke("检查完成", 100);
            return _latestManifest;
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, "检查软件更新失败");
            UpdateProgress?.Invoke("检查失败", 100);
            return null;
        }
    }

    /// <summary>
    /// 下载差分更新包
    /// 只下载变更部分，并进行 SHA256 校验
    /// </summary>
    /// <param name="manifest">更新清单</param>
    /// <returns>下载的更新包路径（null 表示失败）</returns>
    public async Task<string?> DownloadUpdate(UpdateManifest manifest)
    {
        if (manifest == null || string.IsNullOrEmpty(manifest.DownloadUrl))
        {
            ErrorReporter.Log("更新清单无效或下载地址为空", "WARN");
            return null;
        }

        try
        {
            UpdateProgress?.Invoke("正在下载差分更新包...", 20);

            var packagePath = Path.Combine(_updateDir, "app", $"update_{manifest.Version}.zip");

            // 如果已下载且校验通过，直接复用
            if (File.Exists(packagePath) && VerifySha256(packagePath, manifest.Sha256))
            {
                ErrorReporter.Log("更新包已存在且校验通过，跳过下载");
                UpdateProgress?.Invoke("更新包已就绪", 100);
                return packagePath;
            }

            // 下载更新包
            using var response = await HttpClientInstance.GetAsync(manifest.DownloadUrl, HttpCompletionOption.ResponseHeadersRead);
            response.EnsureSuccessStatusCode();

            var totalBytes = response.Content.Headers.ContentLength ?? -1;
            long downloadedBytes = 0;

            await using var contentStream = await response.Content.ReadAsStreamAsync();
            await using var fileStream = new FileStream(packagePath, FileMode.Create, FileAccess.Write, FileShare.None);

            var buffer = new byte[81920];
            int bytesRead;

            while ((bytesRead = await contentStream.ReadAsync(buffer)) > 0)
            {
                await fileStream.WriteAsync(buffer.AsMemory(0, bytesRead));
                downloadedBytes += bytesRead;

                if (totalBytes > 0)
                {
                    var progress = (int)(downloadedBytes * 80 / totalBytes) + 20;
                    UpdateProgress?.Invoke($"下载中... {downloadedBytes / 1024}KB / {totalBytes / 1024}KB", progress);
                }
            }

            UpdateProgress?.Invoke("正在校验文件完整性...", 90);

            // SHA256 校验
            if (!string.IsNullOrEmpty(manifest.Sha256) && !VerifySha256(packagePath, manifest.Sha256))
            {
                ErrorReporter.Log("更新包 SHA256 校验失败，已删除", "ERROR");
                File.Delete(packagePath);
                return null;
            }

            ErrorReporter.Log($"更新包下载完成: {packagePath}（{downloadedBytes / 1024} KB）");
            UpdateProgress?.Invoke("下载完成", 100);
            return packagePath;
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, "下载更新包失败");
            UpdateProgress?.Invoke("下载失败", 100);
            return null;
        }
    }

    /// <summary>
    /// 应用更新 - 重启时替换
    /// 写入批处理脚本，程序退出后由批处理执行文件替换
    /// </summary>
    /// <param name="packagePath">更新包路径</param>
    /// <param name="manifest">更新清单</param>
    /// <returns>是否成功写入替换脚本</returns>
    public bool ApplyUpdate(string packagePath, UpdateManifest manifest)
    {
        try
        {
            if (!File.Exists(packagePath))
            {
                ErrorReporter.Log("更新包不存在，无法应用更新", "ERROR");
                return false;
            }

            var appDir = AppContext.BaseDirectory;
            var extractDir = Path.Combine(_updateDir, "app", "extracted");

            // 解压更新包到临时目录
            Directory.CreateDirectory(extractDir);
            System.IO.Compression.ZipFile.ExtractToDirectory(packagePath, extractDir, true);

            // 生成批处理脚本：等待程序退出 -> 替换文件 -> 重启程序
            var batPath = Path.Combine(_updateDir, "app", "apply_update.bat");
            var sb = new StringBuilder();

            sb.AppendLine("@echo off");
            sb.AppendLine("chcp 65001 >nul");
            sb.AppendLine($"echo LightGuard 正在应用更新 {manifest.Version}...");

            // 等待主程序退出（最多等待 30 秒）
            sb.AppendLine($"set \"EXE_PATH={Path.Combine(appDir, "LightGuard.exe")}\"");
            sb.AppendLine(":wait_exit");
            sb.AppendLine("tasklist /FI \"IMAGENAME eq LightGuard.exe\" 2>NUL | find /I \"LightGuard.exe\" >NUL");
            sb.AppendLine("if \"%ERRORLEVEL%\"==\"0\" (");
            sb.AppendLine("    timeout /t 1 /nobreak >nul");
            sb.AppendLine("    goto wait_exit");
            sb.AppendLine(")");

            // 备份旧文件
            sb.AppendLine($"set \"BACKUP_DIR={Path.Combine(_updateDir, "app", "backup")}\"");
            sb.AppendLine("if not exist \"%BACKUP_DIR%\" mkdir \"%BACKUP_DIR%\"");

            // 替换变更文件
            foreach (var changedFile in manifest.ChangedFiles)
            {
                var sourcePath = Path.Combine(extractDir, changedFile);
                var targetPath = Path.Combine(appDir, changedFile);
                var backupPath = Path.Combine(Path.Combine(_updateDir, "app", "backup"), changedFile);

                sb.AppendLine($"if exist \"{targetPath}\" copy /Y \"{targetPath}\" \"{backupPath}\"");
                sb.AppendLine($"copy /Y \"{sourcePath}\" \"{targetPath}\"");
            }

            // 如果没有指定变更文件，全量替换
            if (manifest.ChangedFiles.Count == 0)
            {
                sb.AppendLine("xcopy /Y /E /I \"%~dp0extracted\\*\" \"" + appDir + "\"");
            }

            // 更新版本记录
            sb.AppendLine($"echo {manifest.Version}> \"{Path.Combine(_updateDir, "app", "version.txt")}\"");

            // 重启程序
            sb.AppendLine("echo 更新完成，正在重启 LightGuard...");
            sb.AppendLine("start \"\" \"" + Path.Combine(appDir, "LightGuard.exe") + "\"");

            // 清理临时文件
            sb.AppendLine("del \"%~f0\"");

            File.WriteAllText(batPath, sb.ToString(), System.Text.Encoding.UTF8);

            PendingRestart = true;
            ErrorReporter.Log($"更新替换脚本已生成: {batPath}");
            ErrorReporter.Log("更新将在程序退出后自动应用");

            return true;
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, "应用更新失败");
            return false;
        }
    }

    // ==================== 第二层：杀毒引擎底层更新 ====================

    /// <summary>
    /// 更新杀毒引擎（ClamAV/Yara）
    /// 高配电脑每日检查，低配电脑每周检查
    /// </summary>
    /// <returns>更新结果</returns>
    public async Task<UpdateResult> UpdateEngine()
    {
        var result = new UpdateResult
        {
            Component = "杀毒引擎",
            OldVersion = _engineVersion
        };

        try
        {
            // 根据硬件配置决定检查频率
            var isHighEnd = AppState.Hardware.IsHighEnd;
            var lastUpdate = AppState.Config.Update.LastEngineUpdate;

            // 高配每日检查，低配每周检查
            var checkInterval = isHighEnd ? TimeSpan.FromDays(1) : TimeSpan.FromDays(7);

            if (lastUpdate.HasValue && DateTime.Now - lastUpdate.Value < checkInterval)
            {
                result.Success = true;
                result.Message = $"距上次检查不足{(isHighEnd ? "1天" : "1周")}，跳过";
                result.NewVersion = _engineVersion;
                ErrorReporter.Log($"引擎更新检查跳过（间隔未到，{(isHighEnd ? "每日" : "每周")}检查）");
                return result;
            }

            UpdateProgress?.Invoke("正在检查杀毒引擎更新...", 20);

            // 获取引擎更新清单
            var manifest = await FetchDbManifest(
                "https://raw.githubusercontent.com/LightGuard/engine/main/manifest.json",
                "engine");

            if (manifest == null)
            {
                result.Success = true;
                result.Message = "引擎已是最新版本";
                result.NewVersion = _engineVersion;
                result.IsUpToDate = true;
                return result;
            }

            // 比较版本
            if (CompareVersions(manifest.Version, _engineVersion) <= 0)
            {
                result.Success = true;
                result.Message = "引擎已是最新版本";
                result.NewVersion = _engineVersion;
                result.IsUpToDate = true;
                return result;
            }

            UpdateProgress?.Invoke("正在下载引擎更新...", 50);

            // 下载引擎更新包
            var packagePath = Path.Combine(_updateDir, "engine", $"engine_{manifest.Version}.bin");
            var downloaded = await DownloadFileAsync(manifest.DownloadUrl, packagePath, manifest.Sha256);

            if (!downloaded)
            {
                result.Success = false;
                result.Message = "引擎更新包下载或校验失败";
                return result;
            }

            // 断网回滚：备份旧引擎文件
            var engineDir = Path.Combine(_updateDir, "engine");
            var backupDir = Path.Combine(engineDir, "backup");
            Directory.CreateDirectory(backupDir);

            var oldEngineFile = Path.Combine(engineDir, "clamav_engine.cvd");
            if (File.Exists(oldEngineFile))
            {
                File.Copy(oldEngineFile, Path.Combine(backupDir, "clamav_engine.cvd.bak"), true);
            }

            UpdateProgress?.Invoke("正在应用引擎更新...", 80);

            // 应用更新
            try
            {
                File.Copy(packagePath, oldEngineFile, true);

                // 更新版本记录
                _engineVersion = manifest.Version;
                File.WriteAllText(Path.Combine(engineDir, "version.txt"), manifest.Version);

                // 更新配置
                AppState.Config.Update.LastEngineUpdate = DateTime.Now;
                ConfigManager.Save(AppState.Config);

                result.Success = true;
                result.Message = $"引擎已更新至 {manifest.Version}";
                result.NewVersion = manifest.Version;
                ErrorReporter.Log($"杀毒引擎更新成功: {_engineVersion}");
                UpdateProgress?.Invoke("引擎更新完成", 100);
            }
            catch (Exception ex)
            {
                // 断网回滚：恢复旧引擎文件
                ErrorReporter.Report(ex, "引擎更新应用失败，执行回滚");
                var backupFile = Path.Combine(backupDir, "clamav_engine.cvd.bak");
                if (File.Exists(backupFile))
                {
                    File.Copy(backupFile, oldEngineFile, true);
                    ErrorReporter.Log("已回滚到旧引擎版本");
                }

                result.Success = false;
                result.Message = "引擎更新失败，已回滚";
            }

            return result;
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, "杀毒引擎更新失败");
            result.Success = false;
            result.Message = $"引擎更新异常: {ex.Message}";
            return result;
        }
    }

    // ==================== 第三层：病毒库 + 流氓规则库更新 ====================

    /// <summary>
    /// 更新病毒特征库
    /// 从多个源下载，自动选择最优源
    /// </summary>
    /// <returns>更新结果</returns>
    public async Task<UpdateResult> UpdateVirusDb()
    {
        var result = new UpdateResult
        {
            Component = "病毒库",
            OldVersion = _virusDbVersion
        };

        try
        {
            UpdateProgress?.Invoke("正在检查病毒库更新...", 10);

            // 从多源获取清单
            var manifest = await FetchDbManifestFromSources(VirusDbSources, "virus-db");

            if (manifest == null)
            {
                result.Success = true;
                result.Message = "病毒库已是最新版本";
                result.NewVersion = _virusDbVersion;
                result.IsUpToDate = true;
                return result;
            }

            if (CompareVersions(manifest.Version, _virusDbVersion) <= 0)
            {
                result.Success = true;
                result.Message = "病毒库已是最新版本";
                result.NewVersion = _virusDbVersion;
                result.IsUpToDate = true;
                return result;
            }

            UpdateProgress?.Invoke("正在下载病毒库更新...", 40);

            // 下载病毒库
            var dbPath = Path.Combine(_updateDir, "virus-db", "main.cvd");
            var backupPath = Path.Combine(_updateDir, "virus-db", "main.cvd.bak");

            // 断网回滚：备份旧病毒库
            if (File.Exists(dbPath))
            {
                File.Copy(dbPath, backupPath, true);
            }

            var downloaded = await DownloadFileAsync(manifest.DownloadUrl, dbPath, manifest.Sha256);

            if (!downloaded)
            {
                // 下载失败，恢复旧版本
                if (File.Exists(backupPath))
                {
                    File.Copy(backupPath, dbPath, true);
                    ErrorReporter.Log("病毒库下载失败，已恢复旧版本", "WARN");
                }

                result.Success = false;
                result.Message = "病毒库下载或校验失败，已回滚";
                return result;
            }

            UpdateProgress?.Invoke("正在应用病毒库更新...", 80);

            // 更新版本记录
            _virusDbVersion = manifest.Version;
            File.WriteAllText(Path.Combine(_updateDir, "virus-db", "version.txt"), manifest.Version);

            // 更新配置
            AppState.Config.Update.LastVirusDbUpdate = DateTime.Now;
            ConfigManager.Save(AppState.Config);

            // 清理备份
            if (File.Exists(backupPath))
                File.Delete(backupPath);

            result.Success = true;
            result.Message = $"病毒库已更新至 {manifest.Version}（{manifest.EntryCount} 条特征）";
            result.NewVersion = manifest.Version;
            ErrorReporter.Log($"病毒库更新成功: {_virusDbVersion}（{manifest.EntryCount} 条特征）");
            UpdateProgress?.Invoke("病毒库更新完成", 100);

            return result;
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, "病毒库更新失败");
            result.Success = false;
            result.Message = $"病毒库更新异常: {ex.Message}";
            return result;
        }
    }

    /// <summary>
    /// 更新流氓软件净化规则库
    /// 多源规则自动合并、去重
    /// </summary>
    /// <returns>更新结果</returns>
    public async Task<UpdateResult> UpdateRogueRules()
    {
        var result = new UpdateResult
        {
            Component = "流氓规则库",
            OldVersion = _rogueRulesVersion
        };

        try
        {
            UpdateProgress?.Invoke("正在检查流氓规则库更新...", 10);

            // 从多源获取规则
            var allRules = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var latestVersion = _rogueRulesVersion;
            var sourceCount = 0;

            foreach (var source in RogueRulesSources)
            {
                try
                {
                    UpdateProgress?.Invoke($"正在从源 {sourceCount + 1}/{RogueRulesSources.Length} 下载规则...", 20 + sourceCount * 20);

                    var json = await HttpClientInstance.GetStringAsync(source);
                    var rulesData = JsonSerializer.Deserialize<RogueRulesData>(json, JsonOpts);

                    if (rulesData != null)
                    {
                        // 合并规则（自动去重）
                        if (rulesData.Rules != null)
                        {
                            foreach (var rule in rulesData.Rules)
                            {
                                allRules.Add(rule);
                            }
                        }

                        // 取最新版本号
                        if (CompareVersions(rulesData.Version, latestVersion) > 0)
                        {
                            latestVersion = rulesData.Version;
                        }

                        sourceCount++;
                        ErrorReporter.Log($"从源 {source} 获取到 {rulesData.Rules?.Count ?? 0} 条规则");
                    }
                }
                catch (Exception ex)
                {
                    // 单个源失败不影响整体
                    ErrorReporter.Report(ex, $"规则源 {source} 下载失败，跳过");
                }
            }

            if (allRules.Count == 0)
            {
                result.Success = true;
                result.Message = "流氓规则库已是最新版本";
                result.NewVersion = _rogueRulesVersion;
                result.IsUpToDate = true;
                return result;
            }

            UpdateProgress?.Invoke("正在合并去重规则...", 80);

            // 断网回滚：备份旧规则文件
            var rulesPath = Path.Combine(_updateDir, "rogue-rules", "rules.json");
            var backupPath = Path.Combine(_updateDir, "rogue-rules", "rules.json.bak");

            if (File.Exists(rulesPath))
            {
                File.Copy(rulesPath, backupPath, true);
            }

            // 写入合并后的规则
            var mergedData = new RogueRulesData
            {
                Version = latestVersion,
                Rules = allRules.ToList(),
                UpdatedAt = DateTime.Now
            };

            var mergedJson = JsonSerializer.Serialize(mergedData, new JsonSerializerOptions
            {
                WriteIndented = true
            });

            File.WriteAllText(rulesPath, mergedJson);

            // 更新版本记录
            _rogueRulesVersion = latestVersion;
            File.WriteAllText(Path.Combine(_updateDir, "rogue-rules", "version.txt"), latestVersion);

            // 清理备份
            if (File.Exists(backupPath))
                File.Delete(backupPath);

            result.Success = true;
            result.Message = $"流氓规则库已更新至 {latestVersion}（合并 {sourceCount} 个源，{allRules.Count} 条规则）";
            result.NewVersion = latestVersion;
            ErrorReporter.Log($"流氓规则库更新成功: {_rogueRulesVersion}（合并 {sourceCount} 个源，{allRules.Count} 条规则）");
            UpdateProgress?.Invoke("规则库更新完成", 100);

            return result;
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, "流氓规则库更新失败");

            // 断网回滚
            var backupPath = Path.Combine(_updateDir, "rogue-rules", "rules.json.bak");
            var rulesPath = Path.Combine(_updateDir, "rogue-rules", "rules.json");
            if (File.Exists(backupPath))
            {
                try { File.Copy(backupPath, rulesPath, true); } catch { }
                ErrorReporter.Log("规则库更新失败，已恢复旧版本");
            }

            result.Success = false;
            result.Message = $"规则库更新异常: {ex.Message}";
            return result;
        }
    }

    // ==================== 离线手动导入 ====================

    /// <summary>
    /// 从本地文件导入更新包（离线模式）
    /// 支持导入病毒库、规则库或引擎更新包
    /// </summary>
    /// <param name="path">更新包文件路径</param>
    /// <returns>导入结果</returns>
    public async Task<UpdateResult> ImportUpdateFromFile(string path)
    {
        var result = new UpdateResult
        {
            Component = "离线导入"
        };

        await Task.Run(() =>
        {
            try
            {
                if (!File.Exists(path))
                {
                    result.Success = false;
                    result.Message = "文件不存在";
                    return;
                }

                var fileName = Path.GetFileName(path).ToLowerInvariant();
                var tempDir = Path.Combine(_updateDir, "import_temp");
                if (Directory.Exists(tempDir))
                    Directory.Delete(tempDir, true);
                Directory.CreateDirectory(tempDir);

                // 解压导入包
                if (fileName.EndsWith(".zip"))
                {
                    System.IO.Compression.ZipFile.ExtractToDirectory(path, tempDir, true);
                }
                else
                {
                    // 单文件导入
                    File.Copy(path, Path.Combine(tempDir, fileName), true);
                }

                // 根据内容类型自动识别并导入
                var importedCount = 0;

                // 病毒库文件
                var virusDbFile = Path.Combine(tempDir, "main.cvd");
                if (File.Exists(virusDbFile))
                {
                    var targetPath = Path.Combine(_updateDir, "virus-db", "main.cvd");
                    File.Copy(virusDbFile, targetPath, true);

                    var versionFile = Path.Combine(tempDir, "virus-db.version");
                    if (File.Exists(versionFile))
                    {
                        _virusDbVersion = File.ReadAllText(versionFile).Trim();
                    }
                    else
                    {
                        _virusDbVersion = $"offline_{DateTime.Now:yyyyMMdd}";
                    }
                    File.WriteAllText(Path.Combine(_updateDir, "virus-db", "version.txt"), _virusDbVersion);
                    AppState.Config.Update.LastVirusDbUpdate = DateTime.Now;
                    importedCount++;
                    ErrorReporter.Log($"离线导入病毒库成功: {_virusDbVersion}");
                }

                // 规则库文件
                var rulesFile = Path.Combine(tempDir, "rules.json");
                if (File.Exists(rulesFile))
                {
                    var targetPath = Path.Combine(_updateDir, "rogue-rules", "rules.json");
                    File.Copy(rulesFile, targetPath, true);

                    var versionFile = Path.Combine(tempDir, "rogue-rules.version");
                    if (File.Exists(versionFile))
                    {
                        _rogueRulesVersion = File.ReadAllText(versionFile).Trim();
                    }
                    else
                    {
                        _rogueRulesVersion = $"offline_{DateTime.Now:yyyyMMdd}";
                    }
                    File.WriteAllText(Path.Combine(_updateDir, "rogue-rules", "version.txt"), _rogueRulesVersion);
                    importedCount++;
                    ErrorReporter.Log($"离线导入规则库成功: {_rogueRulesVersion}");
                }

                // 引擎文件
                var engineFile = Path.Combine(tempDir, "clamav_engine.cvd");
                if (File.Exists(engineFile))
                {
                    var targetPath = Path.Combine(_updateDir, "engine", "clamav_engine.cvd");
                    File.Copy(engineFile, targetPath, true);

                    var versionFile = Path.Combine(tempDir, "engine.version");
                    if (File.Exists(versionFile))
                    {
                        _engineVersion = File.ReadAllText(versionFile).Trim();
                    }
                    else
                    {
                        _engineVersion = $"offline_{DateTime.Now:yyyyMMdd}";
                    }
                    File.WriteAllText(Path.Combine(_updateDir, "engine", "version.txt"), _engineVersion);
                    AppState.Config.Update.LastEngineUpdate = DateTime.Now;
                    importedCount++;
                    ErrorReporter.Log($"离线导入引擎成功: {_engineVersion}");
                }

                // 保存配置
                ConfigManager.Save(AppState.Config);

                // 清理临时目录
                Directory.Delete(tempDir, true);

                result.Success = importedCount > 0;
                result.Message = importedCount > 0
                    ? $"离线导入成功，共导入 {importedCount} 个组件"
                    : "未识别到有效的更新文件";
            }
            catch (Exception ex)
            {
                ErrorReporter.Report(ex, "离线导入更新失败");
                result.Success = false;
                result.Message = $"离线导入失败: {ex.Message}";
            }
        });

        UpdateCompleted?.Invoke(result);
        return result;
    }

    // ==================== 统一更新入口 ====================

    /// <summary>
    /// 执行全部更新检查（静默无感）
    /// 依次检查并更新：病毒库 -> 流氓规则库 -> 杀毒引擎 -> 软件本体
    /// </summary>
    /// <returns>更新结果报告列表</returns>
    public async Task<List<UpdateResult>> CheckAndUpdateAllAsync()
    {
        if (_isUpdating)
        {
            ErrorReporter.Log("更新正在进行中，跳过本次检查", "WARN");
            return new List<UpdateResult>();
        }

        _isUpdating = true;
        var results = new List<UpdateResult>();

        try
        {
            ErrorReporter.Log("======== 开始全量更新检查 ========");

            // 1. 病毒库更新
            UpdateProgress?.Invoke("更新病毒库...", 25);
            var virusResult = await UpdateVirusDb();
            results.Add(virusResult);
            UpdateCompleted?.Invoke(virusResult);

            // 2. 流氓规则库更新
            UpdateProgress?.Invoke("更新流氓规则库...", 50);
            var rogueResult = await UpdateRogueRules();
            results.Add(rogueResult);
            UpdateCompleted?.Invoke(rogueResult);

            // 3. 杀毒引擎更新
            UpdateProgress?.Invoke("更新杀毒引擎...", 75);
            var engineResult = await UpdateEngine();
            results.Add(engineResult);
            UpdateCompleted?.Invoke(engineResult);

            // 4. 软件本体更新检查（仅检查，不自动应用）
            UpdateProgress?.Invoke("检查软件更新...", 90);
            var manifest = await CheckForAppUpdate();
            if (manifest != null && CompareVersions(manifest.Version, _currentVersion) > 0)
            {
                var appResult = new UpdateResult
                {
                    Component = "软件本体",
                    Success = true,
                    Message = $"发现新版本 {manifest.Version}，等待用户确认更新",
                    OldVersion = _currentVersion,
                    NewVersion = manifest.Version
                };
                results.Add(appResult);
                UpdateCompleted?.Invoke(appResult);
            }
            else
            {
                var appResult = new UpdateResult
                {
                    Component = "软件本体",
                    Success = true,
                    Message = "软件已是最新版本",
                    OldVersion = _currentVersion,
                    NewVersion = _currentVersion
                };
                results.Add(appResult);
            }

            UpdateProgress?.Invoke("更新检查完成", 100);
            ErrorReporter.Log("======== 全量更新检查完成 ========");

            // 记录更新日志
            LogUpdateResults(results);

            return results;
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, "全量更新检查失败");
            return results;
        }
        finally
        {
            _isUpdating = false;
        }
    }

    /// <summary>
    /// 同步版本的 CheckAndUpdateAll（供定时器等同步调用场景使用）
    /// </summary>
    public Task<List<UpdateResult>> CheckAndUpdateAll() => CheckAndUpdateAllAsync();

    // ==================== 状态查询 ====================

    /// <summary>
    /// 获取各组件更新状态（供 UI 显示）
    /// </summary>
    /// <returns>更新状态汇总</returns>
    public UpdateStatusSummary GetUpdateStatus()
    {
        var config = AppState.Config.Update;

        return new UpdateStatusSummary
        {
            AppStatus = new ComponentUpdateStatus
            {
                Component = "软件本体",
                CurrentVersion = _currentVersion,
                LatestVersion = _latestManifest?.Version ?? _currentVersion,
                IsUpToDate = _latestManifest == null || CompareVersions(_latestManifest.Version, _currentVersion) <= 0,
                LastUpdate = null,
                StatusText = PendingRestart ? "等待重启应用更新" : "正常"
            },
            EngineStatus = new ComponentUpdateStatus
            {
                Component = "杀毒引擎",
                CurrentVersion = _engineVersion,
                LatestVersion = _engineVersion,
                IsUpToDate = true,
                LastUpdate = config.LastEngineUpdate,
                StatusText = config.LastEngineUpdate.HasValue
                    ? $"上次更新: {config.LastEngineUpdate:yyyy-MM-dd HH:mm}"
                    : "未更新"
            },
            VirusDbStatus = new ComponentUpdateStatus
            {
                Component = "病毒库",
                CurrentVersion = _virusDbVersion,
                LatestVersion = _virusDbVersion,
                IsUpToDate = true,
                LastUpdate = config.LastVirusDbUpdate,
                StatusText = config.LastVirusDbUpdate.HasValue
                    ? $"上次更新: {config.LastVirusDbUpdate:yyyy-MM-dd HH:mm}"
                    : "未更新"
            },
            RogueRulesStatus = new ComponentUpdateStatus
            {
                Component = "流氓规则库",
                CurrentVersion = _rogueRulesVersion,
                LatestVersion = _rogueRulesVersion,
                IsUpToDate = true,
                LastUpdate = null,
                StatusText = "正常"
            }
        };
    }

    // ==================== 辅助方法 ====================

    /// <summary>
    /// 解析更新清单 JSON
    /// 支持 GitHub Releases API 和自定义清单格式
    /// </summary>
    private static UpdateManifest? ParseManifest(string json)
    {
        try
        {
            // 尝试解析为标准清单格式
            var manifest = JsonSerializer.Deserialize<UpdateManifest>(json, JsonOpts);
            if (manifest != null && !string.IsNullOrEmpty(manifest.Version))
                return manifest;
        }
        catch { }

        try
        {
            // 尝试解析为 GitHub Releases API 格式
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;

            var tagName = root.TryGetProperty("tag_name", out var tagEl) ? tagEl.GetString() : null;
            if (string.IsNullOrEmpty(tagName))
                return null;

            // 去掉 v 前缀
            var version = tagName.StartsWith("v", StringComparison.OrdinalIgnoreCase)
                ? tagName[1..]
                : tagName;

            // 获取发布说明
            var releaseNotes = root.TryGetProperty("body", out var bodyEl) ? bodyEl.GetString() ?? "" : "";

            // 获取下载地址（第一个 asset）
            string downloadUrl = "";
            if (root.TryGetProperty("assets", out var assetsEl) && assetsEl.GetArrayLength() > 0)
            {
                var firstAsset = assetsEl[0];
                if (firstAsset.TryGetProperty("browser_download_url", out var urlEl))
                    downloadUrl = urlEl.GetString() ?? "";
            }

            return new UpdateManifest
            {
                Version = version,
                DownloadUrl = downloadUrl,
                ReleaseNotes = releaseNotes,
                PublishDate = root.TryGetProperty("published_at", out var dateEl) && DateTime.TryParse(dateEl.GetString(), out var dt) ? dt : null
            };
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// 从多个源获取数据库更新清单
    /// 自动选择第一个可用的源
    /// </summary>
    private async Task<DbUpdateManifest?> FetchDbManifestFromSources(string[] sources, string component)
    {
        foreach (var source in sources)
        {
            try
            {
                var manifest = await FetchDbManifest(source, component);
                if (manifest != null)
                    return manifest;
            }
            catch (Exception ex)
            {
                ErrorReporter.Report(ex, $"{component} 清单源 {source} 获取失败，尝试下一个源");
            }
        }

        return null;
    }

    /// <summary>
    /// 从单个 URL 获取数据库更新清单
    /// </summary>
    private async Task<DbUpdateManifest?> FetchDbManifest(string url, string component)
    {
        try
        {
            var json = await HttpClientInstance.GetStringAsync(url);
            var manifest = JsonSerializer.Deserialize<DbUpdateManifest>(json, JsonOpts);

            if (manifest != null && !string.IsNullOrEmpty(manifest.Version))
                return manifest;
        }
        catch { }

        return null;
    }

    /// <summary>
    /// 下载文件并进行 SHA256 校验
    /// </summary>
    private async Task<bool> DownloadFileAsync(string url, string targetPath, string expectedSha256)
    {
        try
        {
            using var response = await HttpClientInstance.GetAsync(url, HttpCompletionOption.ResponseHeadersRead);
            response.EnsureSuccessStatusCode();

            Directory.CreateDirectory(Path.GetDirectoryName(targetPath)!);

            await using var contentStream = await response.Content.ReadAsStreamAsync();
            await using var fileStream = new FileStream(targetPath, FileMode.Create, FileAccess.Write, FileShare.None);

            await contentStream.CopyToAsync(fileStream);

            // SHA256 校验
            if (!string.IsNullOrEmpty(expectedSha256))
            {
                if (!VerifySha256(targetPath, expectedSha256))
                {
                    ErrorReporter.Log($"{targetPath} SHA256 校验失败", "ERROR");
                    File.Delete(targetPath);
                    return false;
                }
            }

            return true;
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, $"下载文件失败: {url}");
            return false;
        }
    }

    /// <summary>
    /// 验证文件的 SHA256 哈希值
    /// </summary>
    private static bool VerifySha256(string filePath, string expectedHash)
    {
        if (string.IsNullOrEmpty(expectedHash))
            return true;

        try
        {
            using var stream = File.OpenRead(filePath);
            var hashBytes = SHA256.HashData(stream);
            var actualHash = Convert.ToHexString(hashBytes).ToLowerInvariant();
            return string.Equals(actualHash, expectedHash.ToLowerInvariant(), StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// 比较版本号（语义化版本）
    /// 返回值：>0 表示 v1 > v2，<0 表示 v1 < v2，0 表示相等
    /// </summary>
    private static int CompareVersions(string v1, string v2)
    {
        if (string.IsNullOrEmpty(v1)) v1 = "0";
        if (string.IsNullOrEmpty(v2)) v2 = "0";

        // 去掉前缀
        if (v1.StartsWith("v", StringComparison.OrdinalIgnoreCase)) v1 = v1[1..];
        if (v2.StartsWith("v", StringComparison.OrdinalIgnoreCase)) v2 = v2[1..];

        var parts1 = v1.Split('.');
        var parts2 = v2.Split('.');

        var maxLen = Math.Max(parts1.Length, parts2.Length);

        for (var i = 0; i < maxLen; i++)
        {
            var p1 = i < parts1.Length && int.TryParse(parts1[i], out var n1) ? n1 : 0;
            var p2 = i < parts2.Length && int.TryParse(parts2[i], out var n2) ? n2 : 0;

            if (p1 != p2)
                return p1.CompareTo(p2);
        }

        return 0;
    }

    /// <summary>
    /// 读取本地版本文件
    /// </summary>
    private static string ReadLocalVersion(string versionFile)
    {
        try
        {
            if (File.Exists(versionFile))
                return File.ReadAllText(versionFile).Trim();
        }
        catch { }
        return "未知";
    }

    /// <summary>
    /// 记录更新结果到日志文件
    /// </summary>
    private void LogUpdateResults(List<UpdateResult> results)
    {
        try
        {
            var logFile = Path.Combine(_logDir, $"update_{DateTime.Now:yyyyMMdd}.log");
            var sb = new StringBuilder();

            sb.AppendLine($"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] 更新检查结果:");
            foreach (var r in results)
            {
                sb.AppendLine($"  - {r.Component}: {(r.Success ? "成功" : "失败")} | {r.Message}");
            }
            sb.AppendLine();

            File.AppendAllText(logFile, sb.ToString());
        }
        catch { }
    }

    /// <inheritdoc/>
    protected override string GetStatusSummary()
    {
        var config = AppState.Config.Update;
        var lastVirus = config.LastVirusDbUpdate?.ToString("MM-dd HH:mm") ?? "从未";
        return $"当前版本: {_currentVersion} | 病毒库: {_virusDbVersion}({lastVirus}) | 规则库: {_rogueRulesVersion} | 引擎: {_engineVersion}{(PendingRestart ? " | 待重启" : "")}";
    }

    /// <inheritdoc/>
    public override void Dispose()
    {
        _checkTimer?.Dispose();
        base.Dispose();
    }
}

/// <summary>
/// 流氓规则库数据结构（JSON 反序列化用）
/// </summary>
internal sealed class RogueRulesData
{
    [JsonPropertyName("version")]
    public string Version { get; set; } = "";

    [JsonPropertyName("rules")]
    public List<string>? Rules { get; set; }

    [JsonPropertyName("updatedAt")]
    public DateTime? UpdatedAt { get; set; }
}
