// © 2026 落尘（Luochen） 原创开发 - 保留所有权利

using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using LightGuard.Core;
using LightGuard.Modules;
using LightGuard.Security;

namespace LightGuard.Ransomware;

/// <summary>
/// YARA 轻量特征核验引擎
/// <para>不做全盘扫描，仅在 ETW 触发异常后对目标文件按需扫描。</para>
/// <para>内置离线勒索规则库（复用 OfflineVirusDb 的 200+ 特征），断网环境也能工作。</para>
/// <para>支持规则在线更新（RSA 签名校验后加载），误报优化（白名单跳过）。</para>
/// </summary>
public sealed class YaraEngine : IDisposable
{
    #region 常量

    /// <summary>单文件扫描读取的最大字节数（文件头部 2MB）</summary>
    private const int MaxScanReadBytes = 2 * 1024 * 1024;

    /// <summary>YARA 规则更新目录名</summary>
    private const string YaraRulesFolderName = "yararules";

    /// <summary>在线规则文件名</summary>
    private const string OnlineRulesFileName = "online_rules.json";

    /// <summary>规则签名文件名</summary>
    private const string RulesSignatureFileName = "online_rules.sig";

    #endregion

    #region 字段

    private readonly object _lock = new();
    private readonly string _yaraRulesDir;
    private readonly List<VirusSignature> _rules = new();

    /// <summary>正常软件白名单 — 匹配的文件路径跳过扫描，降低误报</summary>
    private readonly HashSet<string> _whitelist = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>规则版本号</summary>
    public string RuleVersion { get; private set; } = OfflineVirusDb.Version;

    /// <summary>最后一次规则更新时间</summary>
    public DateTime? LastRuleUpdate { get; private set; }

    /// <summary>累计扫描文件数（线程安全计数）</summary>
    private long _totalScannedFiles;

    /// <summary>累计匹配威胁数（线程安全计数）</summary>
    private long _totalMatchedThreats;

    /// <summary>累计扫描文件数</summary>
    public long TotalScannedFiles => _totalScannedFiles;

    /// <summary>累计匹配威胁数</summary>
    public long TotalMatchedThreats => _totalMatchedThreats;

    #endregion

    #region 构造函数

    /// <summary>
    /// 初始化 YARA 轻量特征核验引擎
    /// </summary>
    public YaraEngine()
    {
        _yaraRulesDir = Path.Combine(ConfigManager.GetDataDir(), YaraRulesFolderName);
        Directory.CreateDirectory(_yaraRulesDir);

        // 加载离线规则库
        LoadOfflineRules();

        // 尝试加载在线更新规则
        LoadOnlineRules();

        // 初始化白名单
        InitializeWhitelist();
    }

    #endregion

    #region 规则加载

    /// <summary>
    /// 加载离线勒索规则库（复用 OfflineVirusDb 的 200+ 特征）
    /// </summary>
    private void LoadOfflineRules()
    {
        lock (_lock)
        {
            _rules.Clear();
            _rules.AddRange(OfflineVirusDb.GetAllSignatures());
        }
        ErrorReporter.Log($"[YaraEngine] 已加载离线规则库：{_rules.Count} 条特征（版本 {OfflineVirusDb.Version}）");
    }

    /// <summary>
    /// 加载在线更新规则（签名校验通过后合并加载）
    /// </summary>
    private void LoadOnlineRules()
    {
        try
        {
            var rulesPath = Path.Combine(_yaraRulesDir, OnlineRulesFileName);
            var sigPath = Path.Combine(_yaraRulesDir, RulesSignatureFileName);

            if (!File.Exists(rulesPath)) return;

            // 签名校验
            if (File.Exists(sigPath))
            {
                var signature = File.ReadAllText(sigPath).Trim();
                var verifyResult = UpdateSignatureVerifier.VerifyFileSignature(rulesPath, signature);
                if (!verifyResult.IsValid)
                {
                    ErrorReporter.Log($"[YaraEngine] 在线规则签名校验失败：{verifyResult.Error}，跳过加载");
                    return;
                }
                ErrorReporter.Log("[YaraEngine] 在线规则签名校验通过");
            }

            // 解析并加载规则
            var json = File.ReadAllText(rulesPath);
            var rulePack = JsonSerializer.Deserialize<YaraRulePack>(json);
            if (rulePack == null) return;

            lock (_lock)
            {
                // 去重合并
                var existingKeys = new HashSet<string>(
                    _rules.Select(r => r.Name + "|" + r.Pattern),
                    StringComparer.OrdinalIgnoreCase);

                foreach (var rule in rulePack.Rules)
                {
                    var key = rule.Name + "|" + rule.Pattern;
                    if (existingKeys.Add(key))
                    {
                        _rules.Add(new VirusSignature
                        {
                            Name = rule.Name,
                            Pattern = rule.Pattern,
                            Risk = rule.Risk,
                            Source = "在线更新"
                        });
                    }
                }

                if (!string.IsNullOrEmpty(rulePack.Version))
                    RuleVersion = rulePack.Version;
                LastRuleUpdate = rulePack.UpdatedAt;
            }

            ErrorReporter.Log($"[YaraEngine] 在线规则加载完成：共 {_rules.Count} 条特征");
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, "[YaraEngine] 加载在线规则异常");
        }
    }

    /// <summary>
    /// 初始化正常软件白名单
    /// </summary>
    private void InitializeWhitelist()
    {
        // Windows 系统目录
        var systemDirs = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.Windows),
            Environment.GetFolderPath(Environment.SpecialFolder.System),
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
        };

        foreach (var dir in systemDirs)
        {
            if (!string.IsNullOrEmpty(dir))
                _whitelist.Add(dir);
        }

        // 常见安全软件路径
        var securityPaths = new[]
        {
            @"C:\Program Files\Windows Defender",
            @"C:\ProgramData\Microsoft\Windows Defender",
            Path.Combine(ConfigManager.GetConfigDir(), "LightGuard.exe"),
        };

        foreach (var path in securityPaths)
        {
            _whitelist.Add(path);
        }

        ErrorReporter.Log($"[YaraEngine] 白名单已初始化：{_whitelist.Count} 条规则");
    }

    #endregion

    #region 文件扫描

    /// <summary>
    /// 扫描单个文件：读取文件头部 2MB + 文件名匹配 + 扩展名匹配
    /// </summary>
    /// <param name="filePath">目标文件路径</param>
    /// <returns>YARA 扫描结果</returns>
    public YaraScanResult ScanFile(string filePath)
    {
        var result = new YaraScanResult
        {
            FilePath = filePath,
            IsMatched = false,
            RiskLevel = RiskLevel.Clean,
            MatchedRules = new List<string>(),
            ScannedAt = DateTime.Now
        };

        try
        {
            if (string.IsNullOrEmpty(filePath) || !File.Exists(filePath))
            {
                result.Error = "文件不存在";
                return result;
            }

            // 白名单跳过
            if (IsWhitelisted(filePath))
            {
                result.Skipped = true;
                result.SkipReason = "文件在白名单中，跳过扫描";
                return result;
            }

            Interlocked.Increment(ref _totalScannedFiles);

            var fileName = Path.GetFileName(filePath);
            var fileNameLower = fileName.ToLowerInvariant();
            var ext = Path.GetExtension(fileNameLower);

            List<VirusSignature> rules;
            lock (_lock)
            {
                rules = _rules.ToList();
            }

            // 引擎一：扩展名匹配
            foreach (var rule in rules)
            {
                if (string.IsNullOrEmpty(rule.Pattern)) continue;
                var pattern = rule.Pattern.ToLowerInvariant();

                if (pattern.StartsWith(".") && ext == pattern)
                {
                    result.IsMatched = true;
                    result.MatchedRules.Add(rule.Name);
                    result.RiskLevel = (RiskLevel)Math.Max((int)result.RiskLevel, (int)rule.Risk);
                }
            }

            // 引擎二：文件名匹配
            foreach (var rule in rules)
            {
                if (string.IsNullOrEmpty(rule.Pattern)) continue;
                var pattern = rule.Pattern.ToLowerInvariant();

                if (!pattern.StartsWith(".") && fileNameLower.Contains(pattern))
                {
                    // 跳过已匹配的规则
                    if (result.MatchedRules.Contains(rule.Name)) continue;

                    result.IsMatched = true;
                    result.MatchedRules.Add(rule.Name);
                    result.RiskLevel = (RiskLevel)Math.Max((int)result.RiskLevel, (int)rule.Risk);
                }
            }

            // 引擎三：文件头部内容匹配（读取前 2MB）
            if (!result.IsMatched || result.RiskLevel < RiskLevel.High)
            {
                try
                {
                    byte[] buffer;
                    using (var fs = File.OpenRead(filePath))
                    {
                        var readLen = (int)Math.Min(fs.Length, MaxScanReadBytes);
                        buffer = new byte[readLen];
                        fs.Read(buffer, 0, readLen);
                    }

                    var contentLower = Encoding.ASCII.GetString(buffer).ToLowerInvariant();

                    foreach (var rule in rules)
                    {
                        if (string.IsNullOrEmpty(rule.Pattern)) continue;
                        var pattern = rule.Pattern.ToLowerInvariant();

                        // 扩展名规则已处理，跳过
                        if (pattern.StartsWith(".")) continue;
                        // 文件名规则已处理，跳过
                        if (fileNameLower.Contains(pattern)) continue;

                        if (contentLower.Contains(pattern))
                        {
                            result.IsMatched = true;
                            if (!result.MatchedRules.Contains(rule.Name))
                                result.MatchedRules.Add(rule.Name);
                            result.RiskLevel = (RiskLevel)Math.Max((int)result.RiskLevel, (int)rule.Risk);
                        }
                    }
                }
                catch (Exception ex)
                {
                    result.Error = $"文件内容读取失败: {ex.Message}";
                }
            }

            if (result.IsMatched)
            {
                Interlocked.Increment(ref _totalMatchedThreats);
                ErrorReporter.Log(
                    $"[YaraEngine] 威胁匹配: {filePath} | 规则: {string.Join(", ", result.MatchedRules)} | " +
                    $"风险: {result.RiskLevel}",
                    result.RiskLevel >= RiskLevel.Critical ? "ERROR" : "WARN");
            }
        }
        catch (Exception ex)
        {
            result.Error = $"扫描异常: {ex.Message}";
            ErrorReporter.Report(ex, $"[YaraEngine] 扫描文件异常: {filePath}");
        }

        return result;
    }

    /// <summary>
    /// 扫描进程关联的文件
    /// <para>获取进程的可执行文件路径和已打开的文件句柄，逐一扫描。</para>
    /// </summary>
    /// <param name="pid">进程 ID</param>
    /// <returns>该进程关联文件的扫描结果列表</returns>
    public List<YaraScanResult> ScanProcess(int pid)
    {
        var results = new List<YaraScanResult>();

        try
        {
            if (pid <= 0) return results;

            using var proc = Process.GetProcessById(pid);
            var processName = proc.ProcessName + ".exe";

            // 白名单进程跳过
            if (OfflineVirusDb.IsSystemProcess(processName))
            {
                results.Add(new YaraScanResult
                {
                    FilePath = processName,
                    IsMatched = false,
                    Skipped = true,
                    SkipReason = "系统进程，跳过扫描",
                    ScannedAt = DateTime.Now
                });
                return results;
            }

            // 扫描进程主模块（可执行文件）
            string? exePath = null;
            try
            {
                exePath = proc.MainModule?.FileName;
            }
            catch { }

            if (!string.IsNullOrEmpty(exePath) && File.Exists(exePath))
            {
                var exeResult = ScanFile(exePath);
                exeResult.ProcessId = pid;
                exeResult.ProcessName = processName;
                results.Add(exeResult);
            }

            // 扫描进程工作目录下的可疑文件
            var processFiles = GetProcessAssociatedFiles(proc);
            foreach (var file in processFiles)
            {
                try
                {
                    if (!File.Exists(file)) continue;
                    if (IsWhitelisted(file)) continue;

                    var fileResult = ScanFile(file);
                    fileResult.ProcessId = pid;
                    fileResult.ProcessName = processName;
                    results.Add(fileResult);

                    // 发现高危匹配后停止扫描
                    if (fileResult.IsMatched && fileResult.RiskLevel >= RiskLevel.High)
                        break;
                }
                catch { }
            }
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, $"[YaraEngine] 扫描进程异常 PID={pid}");
        }

        return results;
    }

    /// <summary>
    /// 获取进程关联的文件列表
    /// </summary>
    private static List<string> GetProcessAssociatedFiles(Process proc)
    {
        var files = new List<string>();

        try
        {
            // 获取进程可执行文件所在目录
            string? modulePath = null;
            try { modulePath = proc.MainModule?.FileName; } catch { }

            if (!string.IsNullOrEmpty(modulePath))
            {
                var dir = Path.GetDirectoryName(modulePath);
                if (!string.IsNullOrEmpty(dir) && Directory.Exists(dir))
                {
                    // 扫描同目录下的可疑文件（勒索说明文件等）
                    foreach (var file in Directory.EnumerateFiles(dir, "*.*", SearchOption.TopDirectoryOnly))
                    {
                        var name = Path.GetFileName(file).ToLowerInvariant();
                        if (name.Contains("readme") || name.Contains("decrypt") ||
                            name.Contains("how_to") || name.Contains("restore") ||
                            name.Contains("recover") || name.Contains("ransom"))
                        {
                            files.Add(file);
                        }
                    }
                }
            }
        }
        catch { }

        return files;
    }

    #endregion

    #region 规则在线更新

    /// <summary>
    /// 从在线服务器下载并更新 YARA 规则
    /// </summary>
    /// <param name="downloadUrl">规则包下载地址</param>
    /// <param name="signatureBase64">RSA 签名（Base64 编码）</param>
    /// <returns>更新是否成功</returns>
    public async Task<bool> UpdateRulesAsync(string downloadUrl, string signatureBase64)
    {
        try
        {
            using var httpClient = new HttpClient { Timeout = TimeSpan.FromMinutes(5) };
            var response = await httpClient.GetAsync(downloadUrl);
            if (!response.IsSuccessStatusCode)
            {
                ErrorReporter.Log($"[YaraEngine] 规则包下载失败: HTTP {(int)response.StatusCode}");
                return false;
            }

            var rulesPath = Path.Combine(_yaraRulesDir, OnlineRulesFileName);
            var sigPath = Path.Combine(_yaraRulesDir, RulesSignatureFileName);

            // 保存规则包
            using (var fs = new FileStream(rulesPath, FileMode.Create, FileAccess.Write))
            {
                await response.Content.CopyToAsync(fs);
            }

            // 保存签名
            await File.WriteAllTextAsync(sigPath, signatureBase64);

            // 签名校验
            var verifyResult = UpdateSignatureVerifier.VerifyFileSignature(rulesPath, signatureBase64);
            if (!verifyResult.IsValid)
            {
                ErrorReporter.Log($"[YaraEngine] 规则包签名校验失败: {verifyResult.Error}");
                // 删除无效文件
                try { File.Delete(rulesPath); } catch { }
                try { File.Delete(sigPath); } catch { }
                return false;
            }

            // 重新加载规则
            LoadOnlineRules();

            ErrorReporter.Log($"[YaraEngine] YARA 规则在线更新成功，当前版本: {RuleVersion}");
            return true;
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, "[YaraEngine] 规则在线更新异常");
            return false;
        }
    }

    /// <summary>
    /// 添加自定义白名单路径
    /// </summary>
    /// <param name="path">白名单文件或目录路径</param>
    public void AddToWhitelist(string path)
    {
        if (!string.IsNullOrEmpty(path))
        {
            _whitelist.Add(path);
        }
    }

    /// <summary>
    /// 检查文件是否在白名单中
    /// </summary>
    private bool IsWhitelisted(string filePath)
    {
        if (string.IsNullOrEmpty(filePath)) return false;
        var normalized = filePath;

        foreach (var whitelistPath in _whitelist)
        {
            if (normalized.StartsWith(whitelistPath, StringComparison.OrdinalIgnoreCase))
                return true;
        }

        // 系统进程白名单检查
        var fileName = Path.GetFileName(filePath);
        if (OfflineVirusDb.IsSystemProcess(fileName))
            return true;

        return false;
    }

    /// <summary>
    /// 获取当前规则总数
    /// </summary>
    public int GetRuleCount()
    {
        lock (_lock) return _rules.Count;
    }

    #endregion

    #region IDisposable

    /// <summary>
    /// 释放资源
    /// </summary>
    public void Dispose()
    {
        lock (_lock)
        {
            _rules.Clear();
        }
        _whitelist.Clear();
        GC.SuppressFinalize(this);
    }

    #endregion
}

#region 数据类型

/// <summary>
/// YARA 扫描结果
/// </summary>
public sealed class YaraScanResult
{
    /// <summary>扫描的文件路径</summary>
    public string FilePath { get; set; } = "";

    /// <summary>是否匹配到威胁规则</summary>
    public bool IsMatched { get; set; }

    /// <summary>匹配到的规则名称列表</summary>
    public List<string> MatchedRules { get; set; } = new();

    /// <summary>风险等级</summary>
    public RiskLevel RiskLevel { get; set; } = RiskLevel.Clean;

    /// <summary>关联进程 ID</summary>
    public int ProcessId { get; set; }

    /// <summary>关联进程名称</summary>
    public string ProcessName { get; set; } = "";

    /// <summary>是否被跳过（白名单等）</summary>
    public bool Skipped { get; set; }

    /// <summary>跳过原因</summary>
    public string SkipReason { get; set; } = "";

    /// <summary>错误信息</summary>
    public string Error { get; set; } = "";

    /// <summary>扫描时间</summary>
    public DateTime ScannedAt { get; set; }

    public override string ToString()
    {
        if (Skipped) return $"[跳过] {FilePath} - {SkipReason}";
        if (!IsMatched) return $"[安全] {FilePath}";
        return $"[威胁] {FilePath} | 规则: {string.Join(", ", MatchedRules)} | 风险: {RiskLevel}";
    }
}

/// <summary>
/// YARA 在线规则包（JSON 序列化用）
/// </summary>
public sealed class YaraRulePack
{
    /// <summary>规则包版本号</summary>
    public string Version { get; set; } = "";

    /// <summary>规则更新时间</summary>
    public DateTime? UpdatedAt { get; set; }

    /// <summary>规则列表</summary>
    public List<YaraRuleItem> Rules { get; set; } = new();
}

/// <summary>
/// YARA 规则条目
/// </summary>
public sealed class YaraRuleItem
{
    /// <summary>规则名称</summary>
    public string Name { get; set; } = "";

    /// <summary>特征模式（扩展名/文件名片段/内容片段）</summary>
    public string Pattern { get; set; } = "";

    /// <summary>风险等级</summary>
    public RiskLevel Risk { get; set; }
}

#endregion
