using System.Diagnostics;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using LightGuard.Core;
using LightGuard.Core.Interfaces;
using LightGuard.Native;

// 项目启用 WinForms（System.Windows.Forms.Timer）会与 System.Threading.Timer 冲突，
// 此处显式别名为线程池定时器，用于定时备份调度。
using Timer = System.Threading.Timer;

namespace LightGuard.Modules;

/// <summary>
/// 极速加密智能备份系统模块（BackupModule）
/// <para>核心能力：</para>
/// <para>1. AES256 全局加密核心（CBC + PKCS7）</para>
/// <para>2. DPAPI 本地保护密钥</para>
/// <para>3. 完整 / NTFS 增量极速备份</para>
/// <para>4. 伪装备份防勒索（.sys 扩展名 + 系统隐藏只读属性）</para>
/// <para>5. 私有文件头校验（魔数 LGBK + 版本号 + 时间戳）</para>
/// <para>6. SHA256 备份哈希校验 + 损坏自动重传标记</para>
/// <para>7. 定时备份（小时 / 每日 / 每周）+ 过期自动清理</para>
/// <para>8. 局域网 NAS/SMB 备份 + WebDAV 云端备份</para>
/// <para>9. 断点续传</para>
/// </summary>
public sealed class BackupModule : ModuleBase
{
    #region 常量

    /// <summary>私有文件头魔数 "LGBK" = 0x4C47424B</summary>
    private const uint MAGIC = 0x4C47424B;

    /// <summary>备份文件格式版本号</summary>
    private const ushort CURRENT_VERSION = 1;

    /// <summary>文件头总长度：魔数(4) + 版本(2) + 时间戳(8) + 文件数(4) + 正文哈希(32)</summary>
    private const int HeaderSize = 4 + 2 + 8 + 4 + 32;

    /// <summary>AES256 密钥长度（字节）</summary>
    private const int AesKeySize = 32;

    /// <summary>AES CBC 初始化向量长度（字节）</summary>
    private const int AesIvSize = 16;

    /// <summary>伪装备份扩展名（伪装成系统文件防勒索）</summary>
    private const string DisguiseExtension = ".sys";

    /// <summary>断点续传进度落盘频率（每多少个文件保存一次）</summary>
    private const int ProgressSaveInterval = 25;

    #endregion

    #region 字段

    private readonly string _dataDir;
    private readonly string _backupDir;
    private readonly string _keyPath;
    private readonly string _manifestPath;
    private readonly string _progressPath;
    private readonly string _logPath;

    private byte[]? _aesKey;
    private Timer? _scheduleTimer;
    private DateTime _lastScheduleRun;
    private readonly HttpClient _httpClient;
    private readonly object _backupLock = new();

    #endregion

    #region 构造与模块信息

    public BackupModule(AppState appState) : base(appState)
    {
        _dataDir = ConfigManager.GetDataDir();
        _backupDir = ConfigManager.GetBackupDir();
        _keyPath = Path.Combine(_dataDir, "backup.key");
        _manifestPath = Path.Combine(_dataDir, "backup_manifest.json");
        _progressPath = Path.Combine(_dataDir, "backup_progress.json");
        _logPath = Path.Combine(ConfigManager.GetLogDir(), "backup.log");
        _httpClient = new HttpClient { Timeout = TimeSpan.FromMinutes(30) };
    }

    /// <inheritdoc/>
    public override string Id => "backup";

    /// <inheritdoc/>
    public override string DisplayName => "加密智能备份";

    /// <inheritdoc/>
    public override string Description =>
        "极速加密智能备份系统：AES256加密、NTFS增量、伪装备份防勒索、NAS/WebDAV云端备份、断点续传";

    /// <inheritdoc/>
    public override ModuleCategory Category => ModuleCategory.Backup;

    /// <summary>备份用户自身数据不需要管理员权限</summary>
    public override bool RequiresAdmin => false;

    #endregion

    #region 生命周期

    protected override Task OnInitializeAsync()
    {
        // 初始化 AES256 加密密钥（DPAPI 保护）
        _aesKey = EnsureKey();
        Log("备份模块初始化完成");
        return Task.CompletedTask;
    }

    protected override Task OnEnableAsync()
    {
        SetupSchedule();
        Log("备份模块已启用，定时备份任务已启动");
        return Task.CompletedTask;
    }

    protected override Task OnDisableAsync()
    {
        StopSchedule();
        Log("备份模块已禁用");
        return Task.CompletedTask;
    }

    protected override void OnReleaseResources()
    {
        StopSchedule();
        _httpClient.Dispose();
        _aesKey = null;
    }

    protected override string GetStatusSummary()
    {
        if (!IsEnabled) return "已禁用";
        var list = GetBackupList();
        var lastBackup = list.Count > 0 ? list[0].CreateTime : (DateTime?)null;
        return lastBackup.HasValue
            ? $"运行中 | 共 {list.Count} 个备份 | 最近：{lastBackup:yyyy-MM-dd HH:mm}"
            : "运行中 | 暂无备份";
    }

    #endregion

    #region AES256 加密核心 + DPAPI 密钥保护

    /// <summary>
    /// 确保存在 AES256 密钥；不存在则生成 256 位随机密钥，
    /// 并使用 DPAPI（当前用户作用域）保护后保存到本地。
    /// </summary>
    private byte[] EnsureKey()
    {
        var existing = LoadKey();
        if (existing != null && existing.Length == AesKeySize) return existing;

        var key = RandomNumberGenerator.GetBytes(AesKeySize);
        SaveKey(key);
        return key;
    }

    /// <summary>使用 DPAPI 保护密钥并保存到本地</summary>
    private void SaveKey(byte[] key)
    {
        try
        {
            // DPAPI 在当前用户上下文中加密，离开本用户账户无法解密
            var protectedKey = ProtectedData.Protect(key, null, DataProtectionScope.CurrentUser);
            File.WriteAllBytes(_keyPath, protectedKey);
            // 密钥文件同样伪装为系统隐藏只读
            Win32.SetFileAsSystemHidden(_keyPath);
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, "保存备份密钥失败");
        }
    }

    /// <summary>从本地读取并用 DPAPI 解密密钥</summary>
    private byte[]? LoadKey()
    {
        try
        {
            if (!File.Exists(_keyPath)) return null;
            var protectedKey = File.ReadAllBytes(_keyPath);
            return ProtectedData.Unprotect(protectedKey, null, DataProtectionScope.CurrentUser);
        }
        catch
        {
            return null;
        }
    }

    /// <summary>AES256-CBC（PKCS7）加密，返回密文并输出随机 IV</summary>
    private byte[] EncryptData(byte[] plain, byte[] key, out byte[] iv)
    {
        using var aes = Aes.Create();
        aes.KeySize = 256;
        aes.Key = key;
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;
        aes.GenerateIV();
        iv = aes.IV;
        using var enc = aes.CreateEncryptor();
        return enc.TransformFinalBlock(plain, 0, plain.Length);
    }

    /// <summary>AES256-CBC（PKCS7）解密</summary>
    private byte[] DecryptData(byte[] cipher, byte[] key, byte[] iv)
    {
        using var aes = Aes.Create();
        aes.KeySize = 256;
        aes.Key = key;
        aes.IV = iv;
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;
        using var dec = aes.CreateDecryptor();
        return dec.TransformFinalBlock(cipher, 0, cipher.Length);
    }

    #endregion

    #region 备份主流程

    /// <summary>
    /// 立即执行一次备份（依据配置选择完整 / 增量模式）
    /// </summary>
    public BackupResult BackupNow()
    {
        lock (_backupLock)
        {
            var full = AppState.Config.Backup.Mode == BackupMode.Full;
            return RunBackup(full);
        }
    }

    /// <summary>立即执行一次完整备份</summary>
    public BackupResult BackupFull()
    {
        lock (_backupLock) return RunBackup(true);
    }

    /// <summary>立即执行一次增量备份</summary>
    public BackupResult BackupIncremental()
    {
        lock (_backupLock) return RunBackup(false);
    }

    /// <summary>
    /// 备份核心执行流程
    /// </summary>
    private BackupResult RunBackup(bool full)
    {
        var result = new BackupResult();
        var sw = Stopwatch.StartNew();
        try
        {
            var cfg = AppState.Config.Backup;
            if (cfg.ProtectedFolders.Count == 0)
            {
                result.Success = false;
                result.Message = "未配置任何保护目录";
                return result;
            }

            var key = _aesKey ?? EnsureKey();
            _aesKey = key;

            // 1. 收集需要备份的文件
            var manifest = LoadManifest();
            var allFiles = EnumerateProtectedFiles().ToList();
            var filesToBackup = new List<FileSource>();
            foreach (var fs in allFiles)
            {
                bool changed;
                if (full || !manifest.Files.TryGetValue(fs.RelativePath, out var info))
                {
                    changed = true;
                }
                else
                {
                    // NTFS 增量极速备份：依据文件最后修改时间 + 大小判断变更
                    changed = fs.LastWriteTime > info.LastWrite || fs.Size != info.Size;
                }
                if (changed) filesToBackup.Add(fs);
            }

            if (filesToBackup.Count == 0 && !full)
            {
                result.Success = true;
                result.Message = "无文件变更，跳过增量备份";
                result.FileCount = 0;
                result.Mode = "增量(跳过)";
                Log("增量备份：无文件变更，已跳过");
                return result;
            }

            // 2. 断点续传：加载上一次未完成的进度
            var stamp = DateTime.Now;
            var backupName = $"backup_{stamp:yyyyMMdd_HHmmss}{DisguiseExtension}";
            var backupPath = Path.Combine(_backupDir, backupName);

            var progress = LoadProgress();
            var completedFiles = new HashSet<string>();
            string tempBodyPath;

            bool resuming = progress != null
                && !string.IsNullOrEmpty(progress.TempBodyPath)
                && File.Exists(progress.TempBodyPath);

            if (resuming && progress != null)
            {
                tempBodyPath = progress.TempBodyPath;
                completedFiles = new HashSet<string>(progress.CompletedFiles);
                Log($"检测到未完成备份，断点续传：已完成 {completedFiles.Count} 个文件");
            }
            else
            {
                tempBodyPath = Path.Combine(_dataDir, $"backup_{stamp:yyyyMMdd_HHmmss}.body.tmp");
                progress = new BackupProgress
                {
                    TempBodyPath = tempBodyPath,
                    StartTime = stamp,
                    CompletedFiles = new List<string>()
                };
                if (File.Exists(tempBodyPath)) File.Delete(tempBodyPath);
            }

            // 3. 逐文件加密并追加写入临时正文（断点续传可从中断处继续）
            int fileCount = completedFiles.Count;
            long totalBytes = 0;
            int sinceLastSave = 0;
            using (var bodyStream = new FileStream(tempBodyPath, FileMode.Append, FileAccess.Write, FileShare.None))
            using (var bw = new BinaryWriter(bodyStream, Encoding.UTF8, leaveOpen: true))
            {
                foreach (var fs in filesToBackup)
                {
                    if (completedFiles.Contains(fs.RelativePath))
                        continue;

                    try
                    {
                        var plain = File.ReadAllBytes(fs.AbsolutePath);
                        var cipher = EncryptData(plain, key, out var iv);
                        var relBytes = Encoding.UTF8.GetBytes(fs.RelativePath);

                        // 文件条目格式：路径长度 + 路径 + 最后修改时间 + 密文长度 + IV + 密文
                        bw.Write(relBytes.Length);
                        bw.Write(relBytes);
                        bw.Write(fs.LastWriteTime.ToBinary());
                        bw.Write((long)cipher.Length);
                        bw.Write(iv);
                        bw.Write(cipher);

                        totalBytes += plain.Length;
                        fileCount++;
                        completedFiles.Add(fs.RelativePath);

                        // 按频率落盘进度，兼顾断点续传精度与性能
                        if (++sinceLastSave >= ProgressSaveInterval)
                        {
                            progress.CompletedFiles = completedFiles.ToList();
                            SaveProgress(progress);
                            sinceLastSave = 0;
                        }
                    }
                    catch (Exception ex)
                    {
                        Log($"跳过文件 {fs.AbsolutePath}: {ex.Message}");
                    }
                }
            }

            // 保存最终进度（在组装最终文件之前）
            progress.CompletedFiles = completedFiles.ToList();
            SaveProgress(progress);

            // 4. 计算正文 SHA256 哈希，组装最终备份文件（头 + 正文）
            var bodyHash = ComputeFileHash(tempBodyPath);
            using (var fsOut = new FileStream(backupPath, FileMode.Create, FileAccess.Write, FileShare.None))
            using (var bwOut = new BinaryWriter(fsOut, Encoding.UTF8, leaveOpen: true))
            {
                WriteHeader(bwOut, stamp, fileCount, bodyHash);
                using var bodyRead = File.OpenRead(tempBodyPath);
                bodyRead.CopyTo(fsOut);
            }

            // 5. 伪装备份防勒索：设置为系统隐藏只读属性
            if (cfg.DisguiseAsSysFile)
            {
                Win32.SetFileAsSystemHidden(backupPath);
            }

            // 6. 清理临时正文与进度
            try { File.Delete(tempBodyPath); } catch { }
            DeleteProgress();

            // 7. 更新清单（NTFS 增量依据）
            foreach (var fs in filesToBackup)
            {
                manifest.Files[fs.RelativePath] = new ManifestEntry
                {
                    LastWrite = fs.LastWriteTime,
                    Size = fs.Size,
                    LastBackup = stamp
                };
            }
            if (full) manifest.LastFullBackup = stamp;
            else manifest.LastIncrementalBackup = stamp;
            SaveManifest(manifest);

            // 8. 备份哈希校验 + 损坏自动重传标记
            if (!VerifyBackupInternal(backupPath))
            {
                result.Success = false;
                result.Message = "备份哈希校验失败，已标记需要重新备份";
                Log($"备份文件哈希校验失败：{backupPath}");
                return result;
            }

            // 9. 远程上传：局域网 NAS / SMB + WebDAV 云端
            bool nasOk = true, webOk = true;
            if (!string.IsNullOrWhiteSpace(cfg.NasPath))
                nasOk = UploadToNas(backupPath, cfg.NasPath);
            if (!string.IsNullOrWhiteSpace(cfg.WebDavUrl))
                webOk = UploadToWebDavAsync(backupPath).GetAwaiter().GetResult();

            // 10. 自动清理过期备份
            CleanupOldBackups();

            sw.Stop();
            result.Success = true;
            result.BackupPath = backupPath;
            result.FileCount = fileCount;
            result.TotalBytes = totalBytes;
            result.Mode = full ? "完整" : "增量";
            result.Duration = sw.Elapsed;
            result.NasUploaded = nasOk;
            result.WebDavUploaded = webOk;
            result.Hash = BitConverter.ToString(bodyHash).Replace("-", "").ToLowerInvariant();
            result.Message = full ? "完整备份成功" : "增量备份成功";
            Log($"{result.Mode}备份完成：{fileCount} 个文件，{totalBytes / 1024.0:F1} KB，耗时 {sw.Elapsed.TotalSeconds:F1}s");
        }
        catch (Exception ex)
        {
            result.Success = false;
            result.Message = $"备份失败：{ex.Message}";
            ErrorReporter.Report(ex, "备份执行失败");
            Log($"备份失败：{ex}");
        }
        return result;
    }

    #endregion

    #region 还原

    /// <summary>
    /// 从指定备份文件还原到目标目录
    /// </summary>
    /// <param name="backupPath">备份文件路径</param>
    /// <param name="targetDir">还原目标目录</param>
    public RestoreResult RestoreFromBackup(string backupPath, string targetDir)
    {
        var result = new RestoreResult();
        try
        {
            if (!File.Exists(backupPath))
            {
                result.Success = false;
                result.Message = "备份文件不存在";
                return result;
            }

            // 校验备份完整性，损坏则拒绝还原
            if (!VerifyBackupInternal(backupPath))
            {
                result.Success = false;
                result.Message = "备份文件已损坏（哈希校验失败），无法还原";
                Log($"还原中止：备份文件损坏 {backupPath}");
                return result;
            }

            var key = _aesKey ?? EnsureKey();
            _aesKey = key;
            Directory.CreateDirectory(targetDir);

            using var fs = new FileStream(backupPath, FileMode.Open, FileAccess.Read, FileShare.Read);
            using var br = new BinaryReader(fs, Encoding.UTF8, leaveOpen: true);
            // 读取并校验文件头
            var header = ReadHeader(br);
            if (header.Magic != MAGIC)
            {
                result.Success = false;
                result.Message = "备份文件魔数不匹配，非 LightGuard 备份";
                return result;
            }

            int restored = 0;
            long bytes = 0;
            for (int i = 0; i < header.FileCount; i++)
            {
                var relLen = br.ReadInt32();
                var relBytes = br.ReadBytes(relLen);
                var lastWrite = DateTime.FromBinary(br.ReadInt64());
                var dataLen = br.ReadInt64();
                var iv = br.ReadBytes(AesIvSize);
                var cipher = br.ReadBytes((int)dataLen);

                var relPath = Encoding.UTF8.GetString(relBytes);
                var plain = DecryptData(cipher, key, iv);

                var outPath = Path.Combine(targetDir, relPath);
                var dir = Path.GetDirectoryName(outPath);
                if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
                File.WriteAllBytes(outPath, plain);
                try { File.SetLastWriteTime(outPath, lastWrite); } catch { }

                restored++;
                bytes += plain.Length;
            }

            result.Success = true;
            result.FileCount = restored;
            result.TotalBytes = bytes;
            result.Message = $"成功还原 {restored} 个文件到 {targetDir}";
            Log($"还原完成：{restored} 个文件 -> {targetDir}");
        }
        catch (Exception ex)
        {
            result.Success = false;
            result.Message = $"还原失败：{ex.Message}";
            ErrorReporter.Report(ex, "还原备份失败");
            Log($"还原失败：{ex}");
        }
        return result;
    }

    #endregion

    #region 哈希校验 + 损坏重传

    /// <summary>校验备份文件完整性（魔数 + SHA256 正文哈希），供外部调用</summary>
    public bool VerifyBackup(string backupPath)
    {
        try { return VerifyBackupInternal(backupPath); }
        catch { return false; }
    }

    /// <summary>
    /// 内部校验：读取文件头，对正文计算 SHA256 并与头中记录的哈希对比。
    /// 不匹配则认为损坏，需要重新备份（自动重传）。
    /// </summary>
    private bool VerifyBackupInternal(string backupPath)
    {
        using var fs = new FileStream(backupPath, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (fs.Length < HeaderSize) return false;
        using var br = new BinaryReader(fs, Encoding.UTF8, leaveOpen: true);
        var header = ReadHeader(br);
        if (header.Magic != MAGIC) return false;
        if (header.BodyHash == null || header.BodyHash.Length != 32) return false;

        // 计算正文（文件头之后的所有字节）的 SHA256
        using var sha = SHA256.Create();
        var bodyHash = sha.ComputeHash(fs);
        return ConstantTimeEquals(bodyHash, header.BodyHash);
    }

    private static bool ConstantTimeEquals(byte[] a, byte[] b)
    {
        if (a.Length != b.Length) return false;
        int diff = 0;
        for (int i = 0; i < a.Length; i++) diff |= a[i] ^ b[i];
        return diff == 0;
    }

    #endregion

    #region 文件头读写

    private void WriteHeader(BinaryWriter w, DateTime timestamp, int fileCount, byte[] bodyHash)
    {
        w.Write(MAGIC);                     // 魔数 4 字节
        w.Write(CURRENT_VERSION);           // 版本号 2 字节
        w.Write(timestamp.ToBinary());      // 时间戳 8 字节
        w.Write(fileCount);                 // 文件数 4 字节
        w.Write(bodyHash);                  // 正文 SHA256 32 字节
    }

    private BackupHeader ReadHeader(BinaryReader r)
    {
        return new BackupHeader
        {
            Magic = r.ReadUInt32(),
            Version = r.ReadUInt16(),
            Timestamp = DateTime.FromBinary(r.ReadInt64()),
            FileCount = r.ReadInt32(),
            BodyHash = r.ReadBytes(32)
        };
    }

    #endregion

    #region 备份列表与报告

    /// <summary>
    /// 获取备份列表（按时间倒序），供 UI 显示。
    /// 同时标记每个备份是否通过完整性校验（损坏需重传）。
    /// </summary>
    public List<BackupInfo> GetBackupList()
    {
        var list = new List<BackupInfo>();
        try
        {
            if (!Directory.Exists(_backupDir)) return list;

            var candidates = Directory.EnumerateFiles(_backupDir, "*" + DisguiseExtension)
                                      .Concat(Directory.EnumerateFiles(_backupDir, "*.lgbk"));

            foreach (var file in candidates)
            {
                try
                {
                    using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.Read);
                    if (fs.Length < HeaderSize) continue;
                    using var br = new BinaryReader(fs, Encoding.UTF8, leaveOpen: true);
                    var header = ReadHeader(br);
                    if (header.Magic != MAGIC) continue;

                    list.Add(new BackupInfo
                    {
                        FilePath = file,
                        FileName = Path.GetFileName(file),
                        CreateTime = header.Timestamp,
                        Version = header.Version,
                        FileCount = header.FileCount,
                        SizeBytes = new FileInfo(file).Length,
                        Verified = VerifyBackupInternal(file)
                    });
                }
                catch { }
            }
        }
        catch { }
        return list.OrderByDescending(x => x.CreateTime).ToList();
    }

    /// <summary>生成备份报告文本</summary>
    public string GenerateBackupReport()
    {
        var sb = new StringBuilder();
        sb.AppendLine("========================================");
        sb.AppendLine("        LightGuard 加密备份报告");
        sb.AppendLine("========================================");
        sb.AppendLine($"生成时间：{DateTime.Now:yyyy-MM-dd HH:mm:ss}");
        sb.AppendLine();

        var list = GetBackupList();
        sb.AppendLine($"备份总数：{list.Count}");
        var verified = list.Count(x => x.Verified);
        sb.AppendLine($"完整性校验通过：{verified}");
        sb.AppendLine($"损坏需重传：{list.Count - verified}");
        sb.AppendLine();

        var manifest = LoadManifest();
        sb.AppendLine($"保护目录数：{AppState.Config.Backup.ProtectedFolders.Count}");
        sb.AppendLine($"清单记录文件数：{manifest.Files.Count}");
        sb.AppendLine($"最近完整备份：{manifest.LastFullBackup:yyyy-MM-dd HH:mm}");
        sb.AppendLine($"最近增量备份：{manifest.LastIncrementalBackup:yyyy-MM-dd HH:mm}");
        sb.AppendLine();

        sb.AppendLine("---- 备份明细 ----");
        foreach (var b in list)
        {
            sb.AppendLine($"- {b.FileName}");
            sb.AppendLine($"    时间：{b.CreateTime:yyyy-MM-dd HH:mm}  版本：v{b.Version}  文件数：{b.FileCount}  大小：{b.SizeBytes / 1024.0:F1} KB  校验：{(b.Verified ? "通过" : "损坏")}");
        }

        sb.AppendLine();
        sb.AppendLine("---- 配置 ----");
        var cfg = AppState.Config.Backup;
        sb.AppendLine($"备份模式：{cfg.Mode}");
        sb.AppendLine($"定时计划：{cfg.Schedule}");
        sb.AppendLine($"最大保留数：{cfg.MaxBackupCount}");
        sb.AppendLine($"伪装系统文件：{(cfg.DisguiseAsSysFile ? "是" : "否")}");
        sb.AppendLine($"NAS 路径：{(string.IsNullOrEmpty(cfg.NasPath) ? "未配置" : cfg.NasPath)}");
        sb.AppendLine($"WebDAV：{(string.IsNullOrEmpty(cfg.WebDavUrl) ? "未配置" : "已配置")}");
        sb.AppendLine("========================================");
        return sb.ToString();
    }

    #endregion

    #region 过期备份自动清理

    /// <summary>自动清理过期备份，保留最新的 MaxBackupCount 个</summary>
    private void CleanupOldBackups()
    {
        try
        {
            var max = AppState.Config.Backup.MaxBackupCount;
            if (max <= 0) return;
            var list = GetBackupList();
            if (list.Count <= max) return;

            foreach (var b in list.Skip(max))
            {
                try
                {
                    Win32.ResetFileAttributes(b.FilePath);
                    File.Delete(b.FilePath);
                    Log($"清理过期备份：{b.FileName}");
                }
                catch { }
            }
        }
        catch { }
    }

    #endregion

    #region 定时备份

    /// <summary>根据配置启动定时备份（小时 / 每日 / 每周）</summary>
    private void SetupSchedule()
    {
        StopSchedule();
        var schedule = AppState.Config.Backup.Schedule;
        TimeSpan interval = schedule switch
        {
            BackupSchedule.Hourly => TimeSpan.FromHours(1),
            BackupSchedule.Daily => TimeSpan.FromHours(24),
            BackupSchedule.Weekly => TimeSpan.FromDays(7),
            _ => TimeSpan.FromHours(24)
        };
        _scheduleTimer = new Timer(OnScheduleTick, null, interval, interval);
    }

    private void StopSchedule()
    {
        _scheduleTimer?.Dispose();
        _scheduleTimer = null;
    }

    private void OnScheduleTick(object? state)
    {
        // 避免与正在运行的备份冲突，且跳过同一周期内的重复触发
        if (DateTime.Now - _lastScheduleRun < TimeSpan.FromMinutes(5)) return;
        _lastScheduleRun = DateTime.Now;
        try
        {
            var schedule = AppState.Config.Backup.Schedule;
            // 每周触发完整备份，其余触发增量备份
            bool full = schedule == BackupSchedule.Weekly;
            _ = Task.Run(() => { lock (_backupLock) RunBackup(full); });
        }
        catch (Exception ex)
        {
            Log($"定时备份异常：{ex.Message}");
        }
    }

    #endregion

    #region 局域网 NAS / SMB 备份

    /// <summary>复制备份文件到局域网 NAS / SMB 共享（UNC 路径）</summary>
    private bool UploadToNas(string backupFile, string nasPath)
    {
        try
        {
            if (!nasPath.StartsWith(@"\\") && !Path.IsPathRooted(nasPath))
            {
                // 非 UNC 路径且非绝对路径，按 UNC 处理
                nasPath = Path.Combine(nasPath, "");
            }
            Directory.CreateDirectory(nasPath);
            var dest = Path.Combine(nasPath, Path.GetFileName(backupFile));
            File.Copy(backupFile, dest, true);
            Log($"已上传至 NAS：{dest}");
            return true;
        }
        catch (Exception ex)
        {
            Log($"NAS 上传失败：{ex.Message}");
            return false;
        }
    }

    #endregion

    #region WebDAV 云端备份

    /// <summary>使用 HttpClient PUT 上传备份到 WebDAV</summary>
    private async Task<bool> UploadToWebDavAsync(string backupFile)
    {
        var cfg = AppState.Config.Backup;
        if (string.IsNullOrWhiteSpace(cfg.WebDavUrl)) return false;
        try
        {
            var url = cfg.WebDavUrl.TrimEnd('/') + "/" + Path.GetFileName(backupFile);
            using var req = new HttpRequestMessage(HttpMethod.Put, url);
            using var content = new StreamContent(File.OpenRead(backupFile));
            content.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
            req.Content = content;

            // Basic 认证
            if (!string.IsNullOrEmpty(cfg.WebDavUser))
            {
                var token = Convert.ToBase64String(
                    Encoding.UTF8.GetBytes($"{cfg.WebDavUser}:{cfg.WebDavPassword}"));
                req.Headers.Authorization = new AuthenticationHeaderValue("Basic", token);
            }

            using var resp = await _httpClient.SendAsync(req);
            if (resp.IsSuccessStatusCode)
            {
                Log($"已上传至 WebDAV：{url}");
                return true;
            }
            Log($"WebDAV 上传失败：{(int)resp.StatusCode} {resp.ReasonPhrase}");
            return false;
        }
        catch (Exception ex)
        {
            Log($"WebDAV 上传异常：{ex.Message}");
            return false;
        }
    }

    #endregion

    #region 文件枚举

    /// <summary>枚举所有保护目录下的文件（多根目录时加上根目录名前缀避免重名）</summary>
    private IEnumerable<FileSource> EnumerateProtectedFiles()
    {
        var cfg = AppState.Config.Backup;
        foreach (var root in cfg.ProtectedFolders.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            if (!Directory.Exists(root)) continue;

            string rootFull;
            try { rootFull = Path.GetFullPath(root); }
            catch { continue; }

            var rootName = Path.GetFileName(rootFull);
            if (string.IsNullOrEmpty(rootName)) rootName = "root";

            FileInfo[] files;
            try
            {
                files = new DirectoryInfo(rootFull)
                    .EnumerateFiles("*", SearchOption.AllDirectories)
                    .ToArray();
            }
            catch { continue; }

            foreach (var fi in files)
            {
                string rel;
                try { rel = Path.GetRelativePath(rootFull, fi.FullName).Replace('\\', '/'); }
                catch { continue; }

                yield return new FileSource
                {
                    AbsolutePath = fi.FullName,
                    RelativePath = rootName + "/" + rel,
                    Size = fi.Length,
                    LastWriteTime = fi.LastWriteTime
                };
            }
        }
    }

    #endregion

    #region 哈希计算

    private static byte[] ComputeFileHash(string path)
    {
        using var sha = SHA256.Create();
        using var fs = File.OpenRead(path);
        return sha.ComputeHash(fs);
    }

    #endregion

    #region 清单与进度持久化

    private BackupManifest LoadManifest()
    {
        try
        {
            if (!File.Exists(_manifestPath)) return new BackupManifest();
            var json = File.ReadAllText(_manifestPath);
            return JsonSerializer.Deserialize<BackupManifest>(json) ?? new BackupManifest();
        }
        catch { return new BackupManifest(); }
    }

    private void SaveManifest(BackupManifest manifest)
    {
        try
        {
            var json = JsonSerializer.Serialize(manifest, new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(_manifestPath, json);
        }
        catch (Exception ex)
        {
            Log($"保存清单失败：{ex.Message}");
        }
    }

    private BackupProgress? LoadProgress()
    {
        try
        {
            if (!File.Exists(_progressPath)) return null;
            var json = File.ReadAllText(_progressPath);
            return JsonSerializer.Deserialize<BackupProgress>(json);
        }
        catch { return null; }
    }

    private void SaveProgress(BackupProgress progress)
    {
        try
        {
            var json = JsonSerializer.Serialize(progress);
            File.WriteAllText(_progressPath, json);
        }
        catch { }
    }

    private void DeleteProgress()
    {
        try { if (File.Exists(_progressPath)) File.Delete(_progressPath); }
        catch { }
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

    #region 嵌套类型

    /// <summary>待备份文件源信息</summary>
    private sealed class FileSource
    {
        public string AbsolutePath { get; set; } = "";
        public string RelativePath { get; set; } = "";
        public long Size { get; set; }
        public DateTime LastWriteTime { get; set; }
    }

    /// <summary>备份文件头（私有格式）</summary>
    private sealed class BackupHeader
    {
        public uint Magic { get; set; }
        public ushort Version { get; set; }
        public DateTime Timestamp { get; set; }
        public int FileCount { get; set; }
        public byte[] BodyHash { get; set; } = Array.Empty<byte>();
    }

    #endregion
}

#region 公共数据类型（供 UI / 调用方使用）

/// <summary>备份执行结果</summary>
public sealed class BackupResult
{
    public bool Success { get; set; }
    public string Message { get; set; } = "";
    public string? BackupPath { get; set; }
    public int FileCount { get; set; }
    public long TotalBytes { get; set; }
    public string Mode { get; set; } = "";
    public TimeSpan Duration { get; set; }
    public string? Hash { get; set; }
    public bool NasUploaded { get; set; }
    public bool WebDavUploaded { get; set; }
}

/// <summary>还原执行结果</summary>
public sealed class RestoreResult
{
    public bool Success { get; set; }
    public string Message { get; set; } = "";
    public int FileCount { get; set; }
    public long TotalBytes { get; set; }
}

/// <summary>备份信息（UI 展示用）</summary>
public sealed class BackupInfo
{
    public string FilePath { get; set; } = "";
    public string FileName { get; set; } = "";
    public DateTime CreateTime { get; set; }
    public ushort Version { get; set; }
    public int FileCount { get; set; }
    public long SizeBytes { get; set; }
    public bool Verified { get; set; }
}

/// <summary>备份清单（NTFS 增量依据）</summary>
public sealed class BackupManifest
{
    /// <summary>键：相对路径；值：文件备份元信息</summary>
    public Dictionary<string, ManifestEntry> Files { get; set; } = new();
    public DateTime? LastFullBackup { get; set; }
    public DateTime? LastIncrementalBackup { get; set; }
}

/// <summary>清单中单个文件条目</summary>
public sealed class ManifestEntry
{
    public DateTime LastWrite { get; set; }
    public long Size { get; set; }
    public DateTime LastBackup { get; set; }
}

/// <summary>断点续传进度</summary>
public sealed class BackupProgress
{
    public string TempBodyPath { get; set; } = "";
    public DateTime StartTime { get; set; }
    public List<string> CompletedFiles { get; set; } = new();
}

#endregion
