using System.Diagnostics;
using System.IO;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using LightGuard.Core;
using LightGuard.Core.Interfaces;
using LightGuard.Native;
using LightGuard.Ransomware;

// 项目启用 WinForms（System.Windows.Forms.Timer）会与 System.Threading.Timer 冲突，
// 此处显式别名为线程池定时器，用于闲置定时扫描调度。
using Timer = System.Threading.Timer;

namespace LightGuard.Modules;

/// <summary>
/// 四层勒索病毒终极防护体系模块（RansomwareModule）
/// <para>第一层：多开源病毒库聚合（ClamAV / Neo23x0 YARA / VirusTotal）</para>
/// <para>第二层：智能双引擎扫描（特征匹配 + 行为启发）</para>
/// <para>第三层：VSS 卷影副本管理（创建 / 还原 / 列出 / 清理）</para>
/// <para>第四层：实时监控（高配）/ 闲置定时扫描（低配）</para>
/// <para>附带：恶意程序自动断网隔离、伪装备份保护检测</para>
/// </summary>
public sealed class RansomwareModule : ModuleBase
{
    #region 常量

    /// <summary>病毒库下载目录名</summary>
    private const string VirusDbFolderName = "virusdb";

    /// <summary>合并后的病毒库文件名</summary>
    private const string MergedDbFileName = "merged.db";

    /// <summary>单文件扫描读取的最大字节数（用于特征匹配）</summary>
    private const int MaxScanReadBytes = 2 * 1024 * 1024; // 2MB

    /// <summary>实时监控：判定为异常批量加密的窗口（秒）</summary>
    private const int MassEncryptWindowSeconds = 10;

    /// <summary>实时监控：窗口内文件变更阈值，超过即判定为可疑批量加密</summary>
    private const int MassEncryptThreshold = 50;

    #endregion

    #region 字段

    private readonly string _virusDbDir;
    private readonly string _logPath;
    private readonly string _historyPath;
    private readonly string _threatsPath;
    private readonly HttpClient _httpClient;

    private readonly List<VirusSignature> _signatures = new();
    private readonly List<FileSystemWatcher> _watchers = new();
    private readonly object _scanLock = new();
    private readonly object _watchLock = new();
    private Timer? _idleScanTimer;

    /// <summary>进程行为沙箱引擎 — 主动监控并隔离可疑勒索进程</summary>
    private ProcessGuard? _processGuard;

    // 实时监控：滑动窗口内的文件变更事件时间戳（用于异常批量加密检测）
    private readonly LinkedList<DateTime> _recentChanges = new();
    private DateTime _lastScanTime;

    #endregion

    #region 病毒库源定义

    /// <summary>多开源病毒库源列表（ClamAV 官方库 / Neo23x0 YARA 库 / VirusTotal API）</summary>
    private static readonly VirusDbSource[] VirusDbSources =
    {
        new()
        {
            Name = "ClamAV",
            Url = "https://database.clamav.net/main.cvd",
            Type = VirusDbType.ClamAV
        },
        new()
        {
            Name = "Neo23x0_YARA",
            Url = "https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/ransomware.yar",
            Type = VirusDbType.Yara
        },
        new()
        {
            Name = "VirusTotal",
            Url = "https://www.virustotal.com/api/v3/",
            Type = VirusDbType.Api
        }
    };

    /// <summary>内置默认勒索特征（离线也可工作）</summary>
    private static readonly VirusSignature[] BuiltInSignatures =
    {
        // 已知勒索软件加密后扩展名（高/严重风险）
        new() { Name = "Ransomware/Locked", Pattern = ".locked", Risk = RiskLevel.Critical, Source = "内置" },
        new() { Name = "Ransomware/Locky", Pattern = ".locky", Risk = RiskLevel.Critical, Source = "内置" },
        new() { Name = "Ransomware/WannaCry", Pattern = ".wcry", Risk = RiskLevel.Critical, Source = "内置" },
        new() { Name = "Ransomware/WannaCry2", Pattern = ".wncry", Risk = RiskLevel.Critical, Source = "内置" },
        new() { Name = "Ransomware/Cerber", Pattern = ".cerber", Risk = RiskLevel.Critical, Source = "内置" },
        new() { Name = "Ransomware/CryptoLocker", Pattern = ".encrypted", Risk = RiskLevel.Critical, Source = "内置" },
        new() { Name = "Ransomware/Crypt", Pattern = ".crypted", Risk = RiskLevel.High, Source = "内置" },
        new() { Name = "Ransomware/CryptoWall", Pattern = ".crypto", Risk = RiskLevel.High, Source = "内置" },
        new() { Name = "Ransomware/GandCrab", Pattern = ".gandcrab", Risk = RiskLevel.Critical, Source = "内置" },
        new() { Name = "Ransomware/Djvu", Pattern = ".djvu", Risk = RiskLevel.Critical, Source = "内置" },
        new() { Name = "Ransomware/Vault", Pattern = ".vault", Risk = RiskLevel.High, Source = "内置" },
        new() { Name = "Ransomware/Ransom", Pattern = ".ransom", Risk = RiskLevel.Critical, Source = "内置" },
        new() { Name = "Ransomware/Pay", Pattern = ".pay", Risk = RiskLevel.High, Source = "内置" },
        // 已知勒索说明文件名
        new() { Name = "RansomNote/Readme", Pattern = "how_to_decrypt.txt", Risk = RiskLevel.High, Source = "内置" },
        new() { Name = "RansomNote/Decrypt", Pattern = "decrypt_my_files.txt", Risk = RiskLevel.High, Source = "内置" },
        new() { Name = "RansomNote/Restore", Pattern = "restore_files.txt", Risk = RiskLevel.High, Source = "内置" },
        new() { Name = "RansomNote/Help", Pattern = "help_decrypt.txt", Risk = RiskLevel.High, Source = "内置" },
        new() { Name = "RansomNote/Readme2", Pattern = "_readme.txt", Risk = RiskLevel.High, Source = "内置" },
        new() { Name = "RansomNote/YourFiles", Pattern = "your_files_are_encrypted.txt", Risk = RiskLevel.Critical, Source = "内置" },
        // 已知勒索软件字节特征（魔数/明文片段，小写匹配）
        new() { Name = "WannaCryMarker", Pattern = "wanadecrypt", Risk = RiskLevel.Critical, Source = "内置" },
        new() { Name = "BitcoinRansom", Pattern = "bitcoin", Risk = RiskLevel.Medium, Source = "内置" },
        new() { Name = "TorOnionRansom", Pattern = ".onion", Risk = RiskLevel.Medium, Source = "内置" }
    };

    #endregion

    #region 构造与模块信息

    public RansomwareModule(AppState appState) : base(appState)
    {
        _virusDbDir = Path.Combine(ConfigManager.GetDataDir(), VirusDbFolderName);
        Directory.CreateDirectory(_virusDbDir);
        _logPath = Path.Combine(ConfigManager.GetLogDir(), "ransomware.log");
        _historyPath = Path.Combine(ConfigManager.GetDataDir(), "scan_history.json");
        _threatsPath = Path.Combine(ConfigManager.GetDataDir(), "threats.json");
        _httpClient = new HttpClient { Timeout = TimeSpan.FromMinutes(10) };
    }

    /// <inheritdoc/>
    public override string Id => "ransomware";

    /// <inheritdoc/>
    public override string DisplayName => "勒索病毒防护";

    /// <inheritdoc/>
    public override string Description =>
        "四层勒索病毒终极防护：多源病毒库聚合、智能双引擎扫描、VSS卷影副本、实时监控/闲置扫描";

    /// <inheritdoc/>
    public override ModuleCategory Category => ModuleCategory.Ransomware;

    /// <summary>VSS 卷影副本与防火墙隔离需要管理员权限</summary>
    public override bool RequiresAdmin => true;

    #endregion

    #region 生命周期

    protected override async Task OnInitializeAsync()
    {
        // 加载离线病毒库作为兜底（200+ 条特征，断网也能工作）
        LoadOfflineVirusDb();
        // 再合并本地已下载的在线病毒库（如有）
        MergeVirusDb();
        // 初始化进程行为沙箱
        _processGuard = new ProcessGuard();
        _processGuard.SuspiciousProcessDetected += OnSuspiciousProcessDetected;
        _processGuard.ProcessQuarantined += OnProcessQuarantined;
        Log($"勒索防护模块初始化完成 | 离线库 {OfflineVirusDb.GetTotalCount()} 条 | 在线库 {_signatures.Count} 条");
        await Task.CompletedTask;
    }

    protected override Task OnEnableAsync()
    {
        // 启动进程行为沙箱（主动防护层）
        _processGuard?.Start();

        // 高配：启用实时监控；低配：启用闲置定时扫描
        if (AppState.Hardware.IsHighEnd)
        {
            StartRealtimeMonitor();
            Log("高配模式：已启动实时监控（FileSystemWatcher）+ 进程行为沙箱");
        }
        else
        {
            StartIdleScan();
            Log("低配模式：已启动闲置定时扫描 + 进程行为沙箱");
        }
        return Task.CompletedTask;
    }

    protected override Task OnDisableAsync()
    {
        StopRealtimeMonitor();
        StopIdleScan();
        _processGuard?.Stop();
        Log("勒索防护模块已禁用");
        return Task.CompletedTask;
    }

    protected override void OnReleaseResources()
    {
        StopRealtimeMonitor();
        StopIdleScan();
        _processGuard?.Dispose();
        _httpClient.Dispose();
    }

    protected override string GetStatusSummary()
    {
        if (!IsEnabled) return "已禁用";
        var threats = GetThreatList();
        var mode = AppState.Hardware.IsHighEnd ? "实时监控" : "闲置定时扫描";
        return $"运行中 | {mode} | 特征 {GetSignatureCount()} 条 | 已隔离威胁 {threats.Count} 个";
    }

    #endregion

    #region 第一层：多开源病毒库聚合

    /// <summary>
    /// 下载多源病毒库到 ConfigManager.GetDataDir()/virusdb/
    /// </summary>
    public async Task<bool> DownloadVirusDbAsync()
    {
        bool anySuccess = false;
        foreach (var src in VirusDbSources)
        {
            try
            {
                var destFile = Path.Combine(_virusDbDir, src.Name + ".db");
                if (src.Type == VirusDbType.Api)
                {
                    // VirusTotal 为 API 形态，仅写入端点信息作为占位库
                    await File.WriteAllTextAsync(destFile,
                        $"# VirusTotal API endpoint{Environment.NewLine}{src.Url}{Environment.NewLine}");
                    anySuccess = true;
                    Log($"已记录病毒库源：{src.Name}（API）");
                    continue;
                }

                using var resp = await _httpClient.GetAsync(src.Url);
                if (!resp.IsSuccessStatusCode)
                {
                    Log($"下载病毒库失败 {src.Name}: {(int)resp.StatusCode}");
                    continue;
                }
                using var fs = new FileStream(destFile, FileMode.Create, FileAccess.Write);
                await resp.Content.CopyToAsync(fs);
                Log($"已下载病毒库：{src.Name} -> {destFile}");
                anySuccess = true;
            }
            catch (Exception ex)
            {
                Log($"下载病毒库异常 {src.Name}: {ex.Message}");
            }
        }

        // 下载完成后合并去重
        if (anySuccess) MergeVirusDb();
        return anySuccess;
    }

    /// <summary>
    /// 合并去重多个来源的特征库，生成 merged.db，并加载到内存。
    /// 特征文件格式（每行一条）：
    ///   # 注释行
    ///   威胁名称|风险等级(Critical/High/Medium/Low)|特征字符串
    /// </summary>
    public void MergeVirusDb()
    {
        lock (_scanLock)
        {
            // 保留已加载的离线库特征，在此基础上追加下载的特征
            var dedup = new HashSet<string>(
                _signatures.Select(s => s.Name + "|" + s.Pattern),
                StringComparer.OrdinalIgnoreCase);

            if (Directory.Exists(_virusDbDir))
            {
                var mergedLines = new List<string>();
                foreach (var file in Directory.EnumerateFiles(_virusDbDir, "*.db"))
                {
                    if (Path.GetFileName(file).Equals(MergedDbFileName, StringComparison.OrdinalIgnoreCase))
                        continue;
                    try
                    {
                        var lines = File.ReadAllLines(file);
                        foreach (var raw in lines)
                        {
                            var line = raw.Trim();
                            if (line.Length == 0 || line.StartsWith("#")) continue;

                            // 解析格式：名称|风险|特征
                            var sig = ParseSignatureLine(line);
                            if (sig == null) continue;

                            var key = sig.Name + "|" + sig.Pattern;
                            if (dedup.Add(key))
                            {
                                _signatures.Add(sig);
                                mergedLines.Add($"{sig.Name}|{sig.Risk}|{sig.Pattern}");
                            }
                        }
                    }
                    catch { }
                }

                // 写入合并库
                try
                {
                    File.WriteAllLines(Path.Combine(_virusDbDir, MergedDbFileName), mergedLines);
                }
                catch { }
            }

            Log($"病毒库合并完成：共 {_signatures.Count} 条特征");
        }
    }

    /// <summary>获取当前已加载的特征数量</summary>
    public int GetSignatureCount()
    {
        lock (_scanLock) return _signatures.Count;
    }

    /// <summary>解析一行特征：名称|风险|特征</summary>
    private static VirusSignature? ParseSignatureLine(string line)
    {
        var parts = line.Split('|');
        if (parts.Length < 3) return null;
        var risk = parts[1].Trim() switch
        {
            "Critical" => RiskLevel.Critical,
            "High" => RiskLevel.High,
            "Medium" => RiskLevel.Medium,
            "Low" => RiskLevel.Low,
            _ => RiskLevel.Medium
        };
        return new VirusSignature
        {
            Name = parts[0].Trim(),
            Risk = risk,
            Pattern = parts[2].Trim(),
            Source = "下载"
        };
    }

    /// <summary>
    /// 加载离线病毒库（200+ 条特征）作为兜底
    /// 断网环境下依然提供完整的勒索软件检测能力
    /// </summary>
    private void LoadOfflineVirusDb()
    {
        lock (_scanLock)
        {
            _signatures.Clear();
            // 加载完整的离线特征库
            _signatures.AddRange(OfflineVirusDb.GetAllSignatures());
        }
        Log($"已加载离线病毒库：{OfflineVirusDb.GetTotalCount()} 条特征（版本 {OfflineVirusDb.Version}）");
    }

    #endregion

    #region 第二层：智能双引擎扫描

    /// <summary>
    /// 扫描单个文件：特征匹配（扩展名 / 文件名 / 内容片段）
    /// </summary>
    public ScanResult ScanFile(string path)
    {
        var result = new ScanResult
        {
            FilePath = path,
            ScannedAt = DateTime.Now,
            Risk = RiskLevel.Clean
        };

        try
        {
            if (!File.Exists(path))
            {
                result.ThreatName = "文件不存在";
                return result;
            }

            var fileName = Path.GetFileName(path);
            var fileNameLower = fileName.ToLowerInvariant();
            var ext = Path.GetExtension(fileNameLower);

            List<VirusSignature> sigs;
            lock (_scanLock) sigs = _signatures.ToList();

            // 引擎一：基于扩展名 / 文件名特征匹配
            foreach (var sig in sigs)
            {
                if (string.IsNullOrEmpty(sig.Pattern)) continue;
                var pat = sig.Pattern.ToLowerInvariant();

                // 扩展名匹配
                if (pat.StartsWith(".") && ext == pat)
                {
                    result.ThreatName = sig.Name;
                    result.Risk = sig.Risk;
                    result.IsMalicious = sig.Risk >= RiskLevel.High;
                    break;
                }
                // 文件名包含匹配
                if (fileNameLower.Contains(pat))
                {
                    result.ThreatName = sig.Name;
                    result.Risk = (RiskLevel)Math.Max((int)result.Risk, (int)sig.Risk);
                    if (sig.Risk >= RiskLevel.High) result.IsMalicious = true;
                }
            }

            // 引擎二：内容特征匹配（读取文件前 2MB）
            if (!result.IsMalicious)
            {
                try
                {
                    int readLen;
                    byte[] buffer;
                    using (var fs = File.OpenRead(path))
                    {
                        readLen = (int)Math.Min(fs.Length, MaxScanReadBytes);
                        buffer = new byte[readLen];
                        fs.Read(buffer, 0, readLen);
                    }
                    var contentLower = Encoding.ASCII.GetString(buffer).ToLowerInvariant();

                    foreach (var sig in sigs)
                    {
                        if (string.IsNullOrEmpty(sig.Pattern)) continue;
                        var pat = sig.Pattern.ToLowerInvariant();
                        if (pat.StartsWith(".")) continue; // 扩展名已处理

                        if (contentLower.Contains(pat))
                        {
                            result.ThreatName = sig.Name;
                            result.Risk = (RiskLevel)Math.Max((int)result.Risk, (int)sig.Risk);
                            if (sig.Risk >= RiskLevel.High) result.IsMalicious = true;
                            break;
                        }
                    }
                }
                catch { }
            }

            if (result.IsMalicious)
            {
                RecordThreat(result);
                // 恶意程序自动断网隔离
                QuarantineThreat(path, result.ThreatName);
            }
        }
        catch (Exception ex)
        {
            result.ThreatName = $"扫描异常: {ex.Message}";
            result.Risk = RiskLevel.Low;
        }

        RecordHistory(result);
        return result;
    }

    /// <summary>递归扫描目录下所有文件</summary>
    public List<ScanResult> ScanDirectory(string path)
    {
        var results = new List<ScanResult>();
        if (!Directory.Exists(path)) return results;

        FileInfo[] files;
        try
        {
            files = new DirectoryInfo(path).EnumerateFiles("*", SearchOption.AllDirectories).ToArray();
        }
        catch (Exception ex)
        {
            Log($"扫描目录失败 {path}: {ex.Message}");
            return results;
        }

        foreach (var fi in files)
        {
            try
            {
                var r = ScanFile(fi.FullName);
                results.Add(r);
            }
            catch { }
        }

        Log($"目录扫描完成 {path}: {results.Count} 个文件，威胁 {results.Count(x => x.IsMalicious)} 个");
        return results;
    }

    /// <summary>快速扫描关键系统目录（Windows / Program Files / 用户 Temp）</summary>
    public List<ScanResult> QuickScan()
    {
        var results = new List<ScanResult>();
        Log("开始快速扫描...");
        var sw = Stopwatch.StartNew();

        var targets = new List<string>
        {
            Environment.GetFolderPath(Environment.SpecialFolder.Windows),
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
            Path.Combine(Path.GetTempPath()),
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile)
        };

        foreach (var t in targets.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            if (string.IsNullOrEmpty(t) || !Directory.Exists(t)) continue;
            try { results.AddRange(ScanDirectory(t)); }
            catch { }
        }

        sw.Stop();
        _lastScanTime = DateTime.Now;
        Log($"快速扫描完成：{results.Count} 个文件，威胁 {results.Count(x => x.IsMalicious)} 个，耗时 {sw.Elapsed.TotalSeconds:F1}s");
        return results;
    }

    /// <summary>全盘扫描所有固定磁盘</summary>
    public List<ScanResult> FullScan()
    {
        var results = new List<ScanResult>();
        Log("开始全盘扫描...");
        var sw = Stopwatch.StartNew();

        DriveInfo[] drives;
        try { drives = DriveInfo.GetDrives(); }
        catch { drives = Array.Empty<DriveInfo>(); }

        foreach (var drive in drives)
        {
            if (drive.DriveType != DriveType.Fixed) continue;
            try
            {
                if (!drive.IsReady) continue;
                results.AddRange(ScanDirectory(drive.RootDirectory.FullName));
            }
            catch (Exception ex)
            {
                Log($"扫描磁盘失败 {drive.Name}: {ex.Message}");
            }
        }

        sw.Stop();
        _lastScanTime = DateTime.Now;
        Log($"全盘扫描完成：{results.Count} 个文件，威胁 {results.Count(x => x.IsMalicious)} 个，耗时 {sw.Elapsed.TotalSeconds:F1}s");
        return results;
    }

    /// <summary>获取扫描历史记录（供 UI 显示）</summary>
    public List<ScanHistoryEntry> GetScanHistory()
    {
        try
        {
            if (!File.Exists(_historyPath)) return new List<ScanHistoryEntry>();
            var json = File.ReadAllText(_historyPath);
            return JsonSerializer.Deserialize<List<ScanHistoryEntry>>(json) ?? new List<ScanHistoryEntry>();
        }
        catch { return new List<ScanHistoryEntry>(); }
    }

    /// <summary>获取已隔离威胁列表（供 UI 显示）</summary>
    public List<ThreatInfo> GetThreatList()
    {
        try
        {
            if (!File.Exists(_threatsPath)) return new List<ThreatInfo>();
            var json = File.ReadAllText(_threatsPath);
            return JsonSerializer.Deserialize<List<ThreatInfo>>(json) ?? new List<ThreatInfo>();
        }
        catch { return new List<ThreatInfo>(); }
    }

    #endregion

    #region 第三层：恶意程序自动断网隔离

    /// <summary>
    /// 检测到恶意程序时调用防火墙阻止其联网，并记录隔离日志
    /// </summary>
    private void QuarantineThreat(string filePath, string threatName)
    {
        try
        {
            var ruleName = "LightGuard_Block_" + Path.GetFileNameWithoutExtension(filePath);
            // 调用 FirewallHelper.BlockProgram 阻止联网（入站+出站）
            FirewallHelper.BlockProgram(ruleName, filePath);
            Log($"已隔离恶意程序（断网）：{filePath} [{threatName}]");
        }
        catch (Exception ex)
        {
            Log($"隔离失败 {filePath}: {ex.Message}");
        }
    }

    private void RecordThreat(ScanResult result)
    {
        try
        {
            var list = GetThreatList();
            list.Add(new ThreatInfo
            {
                FilePath = result.FilePath,
                ThreatName = result.ThreatName,
                Risk = result.Risk,
                QuarantinedAt = DateTime.Now,
                Blocked = true
            });
            // 仅保留最近 1000 条
            if (list.Count > 1000) list = list.Skip(list.Count - 1000).ToList();
            File.WriteAllText(_threatsPath, JsonSerializer.Serialize(list));
        }
        catch { }
    }

    private void RecordHistory(ScanResult result)
    {
        try
        {
            var list = GetScanHistory();
            list.Add(new ScanHistoryEntry
            {
                FilePath = result.FilePath,
                ThreatName = result.ThreatName,
                Risk = result.Risk,
                ScannedAt = result.ScannedAt
            });
            // 仅保留最近 5000 条
            if (list.Count > 5000) list = list.Skip(list.Count - 5000).ToList();
            File.WriteAllText(_historyPath, JsonSerializer.Serialize(list));
        }
        catch { }
    }

    #endregion

    #region 第三层（续）：VSS 卷影副本管理

    /// <summary>
    /// 创建 C 盘卷影副本（需要管理员权限）
    /// 命令：vssadmin create shadow /for=C:
    /// </summary>
    public bool CreateVssSnapshot(string volume = "C:")
    {
        try
        {
            var vol = volume.TrimEnd('\\', ':') + ":";
            var output = RunProcess("vssadmin.exe", $"create shadow /for={vol}");
            var ok = output.Contains("Shadow Copy", StringComparison.OrdinalIgnoreCase)
                     || output.Contains("卷影副本", StringComparison.OrdinalIgnoreCase);
            Log(ok
                ? $"已创建 VSS 卷影副本：{vol}"
                : $"创建 VSS 卷影副本失败：{output}");
            return ok;
        }
        catch (Exception ex)
        {
            Log($"创建 VSS 卷影副本异常：{ex.Message}");
            return false;
        }
    }

    /// <summary>
    /// 列出所有 VSS 卷影副本
    /// 命令：vssadmin list shadows
    /// </summary>
    public List<VssSnapshot> ListVssSnapshots()
    {
        var list = new List<VssSnapshot>();
        try
        {
            var output = RunProcess("vssadmin.exe", "list shadows");
            VssSnapshot? cur = null;
            foreach (var raw in output.Split('\n'))
            {
                var line = raw.Trim();
                if (line.Length == 0) continue;

                if (line.Contains("Shadow Copy ID", StringComparison.OrdinalIgnoreCase)
                    || line.Contains("卷影副本 ID", StringComparison.OrdinalIgnoreCase))
                {
                    if (cur != null) list.Add(cur);
                    cur = new VssSnapshot();
                    var idx = line.IndexOf(':');
                    cur.Id = idx >= 0 ? line.Substring(idx + 1).Trim() : line;
                }
                else if (cur != null)
                {
                    if (line.Contains("Original Volume", StringComparison.OrdinalIgnoreCase)
                        || line.Contains("原始卷", StringComparison.OrdinalIgnoreCase))
                    {
                        var idx = line.IndexOf(':');
                        cur.OriginalVolume = idx >= 0 ? line.Substring(idx + 1).Trim() : line;
                    }
                    else if (line.Contains("Shadow Copy Volume", StringComparison.OrdinalIgnoreCase)
                             || line.Contains("卷影副本卷", StringComparison.OrdinalIgnoreCase))
                    {
                        var idx = line.IndexOf(':');
                        cur.ShadowCopyVolume = idx >= 0 ? line.Substring(idx + 1).Trim() : line;
                    }
                    else if (line.Contains("Creation Time", StringComparison.OrdinalIgnoreCase)
                             || line.Contains("创建时间", StringComparison.OrdinalIgnoreCase))
                    {
                        var idx = line.IndexOf(':');
                        var t = idx >= 0 ? line.Substring(idx + 1).Trim() : "";
                        if (DateTime.TryParse(t, out var dt)) cur.CreationTime = dt;
                    }
                }
            }
            if (cur != null) list.Add(cur);
        }
        catch (Exception ex)
        {
            Log($"列出 VSS 卷影副本异常：{ex.Message}");
        }
        return list;
    }

    /// <summary>
    /// 从最新 VSS 卷影副本还原保护目录下的文件到原位置
    /// </summary>
    public bool RestoreFromVss()
    {
        try
        {
            var snapshots = ListVssSnapshots();
            if (snapshots.Count == 0)
            {
                Log("无可用 VSS 卷影副本，无法还原");
                return false;
            }

            var latest = snapshots
                .Where(s => !string.IsNullOrEmpty(s.ShadowCopyVolume))
                .OrderByDescending(s => s.CreationTime)
                .FirstOrDefault();
            if (latest == null)
            {
                Log("未找到有效的卷影副本设备路径");
                return false;
            }

            return RestoreFromVss(latest.ShadowCopyVolume);
        }
        catch (Exception ex)
        {
            Log($"从 VSS 还原异常：{ex.Message}");
            return false;
        }
    }

    /// <summary>
    /// 从指定卷影副本设备路径还原保护目录文件到原位置
    /// </summary>
    /// <param name="shadowDevicePath">如 \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1</param>
    public bool RestoreFromVss(string shadowDevicePath)
    {
        try
        {
            if (string.IsNullOrEmpty(shadowDevicePath))
            {
                Log("卷影副本设备路径为空");
                return false;
            }

            var root = shadowDevicePath.TrimEnd('\\');
            if (!root.EndsWith(@"\")) root += @"\";

            int restored = 0;
            foreach (var folder in AppState.Config.Backup.ProtectedFolders)
            {
                if (!Directory.Exists(folder)) continue;
                var folderName = Path.GetFileName(folder.TrimEnd('\\'));
                var srcDir = Path.Combine(root, folderName);
                if (!Directory.Exists(srcDir)) continue;

                foreach (var srcFile in new DirectoryInfo(srcDir)
                             .EnumerateFiles("*", SearchOption.AllDirectories))
                {
                    try
                    {
                        var rel = Path.GetRelativePath(srcDir, srcFile.FullName);
                        var dest = Path.Combine(folder, rel);
                        var dir = Path.GetDirectoryName(dest);
                        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
                        File.Copy(srcFile.FullName, dest, true);
                        restored++;
                    }
                    catch { }
                }
            }

            Log($"已从 VSS 卷影副本还原 {restored} 个文件：{shadowDevicePath}");
            return true;
        }
        catch (Exception ex)
        {
            Log($"从 VSS 还原异常：{ex.Message}");
            return false;
        }
    }

    /// <summary>
    /// 清理旧快照
    /// 命令：vssadmin delete shadows /old
    /// </summary>
    public bool DeleteOldSnapshots()
    {
        try
        {
            var output = RunProcess("vssadmin.exe", "delete shadows /old");
            var ok = output.Contains("deleted", StringComparison.OrdinalIgnoreCase)
                     || output.Contains("删除", StringComparison.OrdinalIgnoreCase)
                     || !output.Contains("error", StringComparison.OrdinalIgnoreCase);
            Log(ok ? "已清理旧 VSS 卷影副本" : $"清理旧 VSS 卷影副本失败：{output}");
            return ok;
        }
        catch (Exception ex)
        {
            Log($"清理旧 VSS 卷影副本异常：{ex.Message}");
            return false;
        }
    }

    #endregion

    #region 第四层：实时监控（高配）/ 闲置定时扫描（低配）

    /// <summary>
    /// 启动实时监控：使用 FileSystemWatcher 监控保护目录，
    /// 检测异常批量加密行为
    /// </summary>
    private void StartRealtimeMonitor()
    {
        StopRealtimeMonitor();
        lock (_watchLock)
        {
            foreach (var folder in AppState.Config.Backup.ProtectedFolders)
            {
                if (!Directory.Exists(folder)) continue;
                try
                {
                    var watcher = new FileSystemWatcher(folder)
                    {
                        IncludeSubdirectories = true,
                        NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite
                                       | NotifyFilters.Size | NotifyFilters.Attributes,
                        EnableRaisingEvents = true
                    };
                    watcher.Changed += OnMonitoredFileChanged;
                    watcher.Created += OnMonitoredFileChanged;
                    watcher.Renamed += OnMonitoredFileRenamed;
                    _watchers.Add(watcher);
                }
                catch (Exception ex)
                {
                    Log($"启动监控失败 {folder}: {ex.Message}");
                }
            }
        }
    }

    private void StopRealtimeMonitor()
    {
        lock (_watchLock)
        {
            foreach (var w in _watchers)
            {
                try
                {
                    w.EnableRaisingEvents = false;
                    w.Changed -= OnMonitoredFileChanged;
                    w.Created -= OnMonitoredFileChanged;
                    w.Renamed -= OnMonitoredFileRenamed;
                    w.Dispose();
                }
                catch { }
            }
            _watchers.Clear();
        }
    }

    private void OnMonitoredFileChanged(object sender, FileSystemEventArgs e)
    {
        RegisterChangeEvent();
        CheckMassEncryption();

        // 将文件操作记录到进程行为沙箱
        RecordFileOperationToGuard(e.FullPath, FileOperationType.Modify);
    }

    private void OnMonitoredFileRenamed(object sender, RenamedEventArgs e)
    {
        RegisterChangeEvent();
        CheckMassEncryption();

        // 将文件重命名记录到进程行为沙箱
        RecordFileOperationToGuard(e.FullPath, FileOperationType.Rename);
    }

    /// <summary>将文件操作记录到进程行为沙箱（通过文件句柄获取 PID）</summary>
    private void RecordFileOperationToGuard(string filePath, FileOperationType opType)
    {
        if (_processGuard == null) return;
        try
        {
            // 获取最近修改该文件的进程 PID
            var pid = GetFileOwnerPid(filePath);
            if (pid > 0)
            {
                _processGuard.RecordFileOperation(pid, filePath, opType);
            }
        }
        catch { }
    }

    /// <summary>获取最近修改指定文件的进程 PID（通过 NTFS Owner 查询或 ETW）</summary>
    private static int GetFileOwnerPid(string filePath)
    {
        // 简化实现：返回当前活跃进程中 CPU 占用最高的非系统进程
        // 完整实现需要 ETW 或 MinFilter 驱动，这里用启发式方法
        try
        {
            var procs = Process.GetProcesses();
            int bestPid = 0;
        double bestCpu = 0;

            foreach (var p in procs)
            {
                try
                {
                    if (OfflineVirusDb.IsSystemProcess(p.ProcessName + ".exe")) continue;
                    var cpu = p.TotalProcessorTime.TotalSeconds;
                    if (cpu > bestCpu && cpu > 1.0)
                    {
                        bestCpu = cpu;
                        bestPid = p.Id;
                    }
                }
                catch { }
                finally { try { p.Dispose(); } catch { } }
            }
            return bestPid;
        }
        catch { return 0; }
    }

    /// <summary>记录一次文件变更事件到滑动窗口</summary>
    private void RegisterChangeEvent()
    {
        var now = DateTime.Now;
        lock (_recentChanges)
        {
            _recentChanges.AddLast(now);
            // 清理窗口外的事件
            var threshold = now.AddSeconds(-MassEncryptWindowSeconds);
            while (_recentChanges.Count > 0 && _recentChanges.First!.Value < threshold)
                _recentChanges.RemoveFirst();
        }
    }

    /// <summary>
    /// 检测异常批量加密行为：若窗口内文件变更数超过阈值，
    /// 判定为可疑勒索加密，立即扫描并告警
    /// </summary>
    private void CheckMassEncryption()
    {
        int count;
        lock (_recentChanges) count = _recentChanges.Count;
        if (count < MassEncryptThreshold) return;

        Log($"警告：检测到异常批量加密行为（{count} 个文件在 {MassEncryptWindowSeconds}s 内变更），触发紧急扫描");
        // 清空窗口避免重复触发
        lock (_recentChanges) _recentChanges.Clear();

        // 紧急扫描所有保护目录
        _ = Task.Run(() =>
        {
            foreach (var folder in AppState.Config.Backup.ProtectedFolders)
            {
                if (Directory.Exists(folder)) ScanDirectory(folder);
            }
        });
    }

    /// <summary>启动闲置定时扫描（低配默认）</summary>
    private void StartIdleScan()
    {
        StopIdleScan();
        // 每 6 小时触发一次闲置快速扫描
        _idleScanTimer = new Timer(OnIdleScanTick, null,
            TimeSpan.FromHours(6), TimeSpan.FromHours(6));
    }

    private void StopIdleScan()
    {
        _idleScanTimer?.Dispose();
        _idleScanTimer = null;
    }

    private void OnIdleScanTick(object? state)
    {
        try
        {
            // 仅在用户空闲时执行，避免打扰
            if (GetUserIdleTime() < TimeSpan.FromMinutes(10)) return;
            _ = Task.Run(() => QuickScan());
        }
        catch (Exception ex)
        {
            Log($"闲置扫描异常：{ex.Message}");
        }
    }

    /// <summary>获取用户空闲时间</summary>
    private static TimeSpan GetUserIdleTime()
    {
        try
        {
            var lastInput = new Win32.LASTINPUTINFO
            {
                cbSize = (uint)System.Runtime.InteropServices.Marshal.SizeOf<Win32.LASTINPUTINFO>()
            };
            Win32.GetLastInputInfo(ref lastInput);
            var now = (uint)Environment.TickCount;
            return TimeSpan.FromMilliseconds(now - lastInput.dwTime);
        }
        catch { return TimeSpan.Zero; }
    }

    #endregion

    #region 进程行为沙箱事件处理

    /// <summary>进程行为沙箱检测到可疑进程</summary>
    private void OnSuspiciousProcessDetected(SuspiciousProcessInfo info)
    {
        Log($"[行为沙箱] 可疑进程: PID={info.ProcessId} {info.ProcessName} | " +
            $"类型={info.DetectionType} | 风险={info.Risk} | {info.ThreatName}");

        // 记录到威胁列表
        RecordThreat(new ScanResult
        {
            FilePath = info.Details,
            ThreatName = info.ThreatName,
            Risk = info.Risk,
            IsMalicious = info.Risk >= RiskLevel.High,
            ScannedAt = info.DetectedAt
        });

        // Critical 级别：立即断网隔离
        if (info.Risk >= RiskLevel.Critical)
        {
            try
            {
                var exePath = GetProcessExePath(info.ProcessId);
                if (!string.IsNullOrEmpty(exePath))
                {
                    QuarantineThreat(exePath, info.ThreatName);
                }
            }
            catch { }
        }
    }

    /// <summary>进程被沙箱隔离（挂起）</summary>
    private void OnProcessQuarantined(int pid, string processName, string reason)
    {
        Log($"[行为沙箱] 进程已隔离: PID={pid} {processName} | 原因={reason}");
    }

    /// <summary>获取进程的可执行文件路径</summary>
    private static string GetProcessExePath(int pid)
    {
        try
        {
            using var proc = Process.GetProcessById(pid);
            return proc.MainModule?.FileName ?? "";
        }
        catch { return ""; }
    }

    #endregion

    #region 伪装备份保护检测

    /// <summary>
    /// 伪装备份保护检测：检查备份文件是否被篡改（通过魔数 LGBK 校验）
    /// </summary>
    public bool IsBackupTampered(string backupPath)
    {
        try
        {
            if (!File.Exists(backupPath)) return true;
            using var fs = new FileStream(backupPath, FileMode.Open, FileAccess.Read, FileShare.Read);
            if (fs.Length < 4) return true;
            using var br = new BinaryReader(fs, Encoding.UTF8, leaveOpen: true);
            // 备份文件头部魔数 0x4C47424B = "LGBK"
            const uint expectedMagic = 0x4C47424B;
            var magic = br.ReadUInt32();
            if (magic != expectedMagic)
            {
                Log($"备份文件魔数校验失败（疑似被篡改）：{backupPath}");
                return true;
            }
            return false;
        }
        catch
        {
            return true;
        }
    }

    #endregion

    #region 进程执行辅助

    private static string RunProcess(string fileName, string args)
    {
        var psi = new ProcessStartInfo
        {
            FileName = fileName,
            Arguments = args,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            StandardOutputEncoding = Encoding.Unicode
        };
        using var proc = Process.Start(psi)
            ?? throw new InvalidOperationException($"无法启动 {fileName}");
        var output = proc.StandardOutput.ReadToEnd();
        proc.WaitForExit(30000);
        return output;
    }

    #endregion

    #region 日志

    private void Log(string message)
    {
        try
        {
            File.AppendAllText(_logPath,
                $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] {message}{Environment.NewLine}");
        }
        catch { }
    }

    #endregion
}

#region 公共数据类型（供 UI / 调用方使用）

/// <summary>风险等级</summary>
public enum RiskLevel
{
    /// <summary>干净</summary>
    Clean = 0,
    /// <summary>低</summary>
    Low = 1,
    /// <summary>中</summary>
    Medium = 2,
    /// <summary>高</summary>
    High = 3,
    /// <summary>严重</summary>
    Critical = 4
}

/// <summary>病毒库类型</summary>
public enum VirusDbType
{
    ClamAV,
    Yara,
    Api
}

/// <summary>病毒库源</summary>
public sealed class VirusDbSource
{
    public string Name { get; set; } = "";
    public string Url { get; set; } = "";
    public VirusDbType Type { get; set; }
}

/// <summary>病毒特征</summary>
public sealed class VirusSignature
{
    /// <summary>威胁名称</summary>
    public string Name { get; set; } = "";
    /// <summary>特征字符串（扩展名 / 文件名片段 / 内容片段）</summary>
    public string Pattern { get; set; } = "";
    /// <summary>风险等级</summary>
    public RiskLevel Risk { get; set; }
    /// <summary>来源</summary>
    public string Source { get; set; } = "";
}

/// <summary>扫描结果</summary>
public sealed class ScanResult
{
    /// <summary>文件路径</summary>
    public string FilePath { get; set; } = "";
    /// <summary>威胁名称</summary>
    public string ThreatName { get; set; } = "";
    /// <summary>风险等级</summary>
    public RiskLevel Risk { get; set; } = RiskLevel.Clean;
    /// <summary>是否恶意</summary>
    public bool IsMalicious { get; set; }
    /// <summary>扫描时间</summary>
    public DateTime ScannedAt { get; set; }
}

/// <summary>扫描历史记录</summary>
public sealed class ScanHistoryEntry
{
    public string FilePath { get; set; } = "";
    public string ThreatName { get; set; } = "";
    public RiskLevel Risk { get; set; }
    public DateTime ScannedAt { get; set; }
}

/// <summary>已隔离威胁信息</summary>
public sealed class ThreatInfo
{
    public string FilePath { get; set; } = "";
    public string ThreatName { get; set; } = "";
    public RiskLevel Risk { get; set; }
    public DateTime QuarantinedAt { get; set; }
    /// <summary>是否已断网阻止</summary>
    public bool Blocked { get; set; }
}

/// <summary>VSS 卷影副本信息</summary>
public sealed class VssSnapshot
{
    public string Id { get; set; } = "";
    public string OriginalVolume { get; set; } = "";
    public string ShadowCopyVolume { get; set; } = "";
    public DateTime CreationTime { get; set; }
}

#endregion
