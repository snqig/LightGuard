// © 2026 落尘（Luochen） 原创开发 - 保留所有权利

using System.Diagnostics;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using LightGuard.Core;

namespace LightGuard.Backup;

/// <summary>
/// 增强型 VSS（卷影副本服务）引擎 - 为一致性备份创建卷影快照。
/// <para>用于热备份正在使用的文件、数据库与运行中的应用程序，避免读取到半写入状态的数据。</para>
/// <para>主方法：PowerShell <c>(Get-WmiObject -List Win32_ShadowCopy).Create("C:\","ClientAccessible")</c>。</para>
/// <para>回退方法：<c>vssadmin.exe create shadow /for=X:</c>。</para>
/// <para>需要管理员权限（应用清单已声明 requireAdministrator）且 VSS 服务运行中。</para>
/// </summary>
public sealed class VssShadowCopyEngine : IDisposable
{
    private readonly BackupCryptoEngine _crypto;
    private readonly int _shardSize;

    /// <summary>本引擎创建且尚未清理的卷影设备路径列表（Dispose 时统一删除）。</summary>
    private readonly List<string> _createdShadows = new();

    private bool _disposed;

    /// <summary>卷影设备路径正则：<c>\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyN</c>。</summary>
    private static readonly Regex ShadowDeviceRegex = new(
        @"\\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy\d+",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    /// <summary>vssadmin 输出中的卷影名称解析正则。</summary>
    private static readonly Regex VssadminShadowRegex = new(
        @"Shadow Copy Volume Name:\s*(\\[?].*?HarddiskVolumeShadowCopy\d+)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    /// <summary>阴影 ID（GUID）解析正则，匹配裸 GUID（不含花括号）。</summary>
    private static readonly Regex GuidRegex = new(
        @"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
        RegexOptions.Compiled);

    /// <summary>PowerShell 创建卷影脚本模板（__LETTER__ 替换为盘符）。</summary>
    private const string CreateShadowTemplate =
        "$r=(Get-WmiObject -List Win32_ShadowCopy).Create('__LETTER__:\\','ClientAccessible');" +
        " if($r.ReturnValue -eq 0){(Get-WmiObject Win32_ShadowCopy -Filter \"ID='$($r.ShadowID)'\").DeviceObject}";

    /// <summary>PowerShell 按设备路径解析卷影 ID 脚本模板（__PATH__ 替换为卷影设备路径）。</summary>
    private const string ResolveIdTemplate =
        @"$p='__PATH__'; $s=Get-WmiObject Win32_ShadowCopy | Where-Object { $_.DeviceObject -eq $p } | Select-Object -First 1; if($s){ $s.ID }";

    /// <summary>
    /// 初始化 VSS 卷影副本引擎。
    /// </summary>
    /// <param name="appState">全局应用状态（用于硬件自适应选择加密算法）。</param>
    /// <param name="shardSize">分片大小（字节），默认 4MB。</param>
    public VssShadowCopyEngine(AppState appState, int shardSize = BackupShardEngine.DefaultShardSize)
    {
        ArgumentNullException.ThrowIfNull(appState);
        _crypto = new BackupCryptoEngine(appState.Hardware);
        _shardSize = shardSize > 0 ? shardSize : BackupShardEngine.DefaultShardSize;
    }

    /// <summary>当前加密算法名称。</summary>
    public string AlgorithmName => _crypto.AlgorithmName;

    #region 卷影副本管理

    /// <summary>
    /// 为指定盘符创建 VSS 卷影副本。
    /// <para>优先使用 PowerShell WMI 方式创建，失败时回退到 vssadmin.exe。</para>
    /// </summary>
    /// <param name="driveLetter">盘符（如 "C"、"C:"、"C:\" 均可）。</param>
    /// <returns>卷影设备路径（<c>\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyN</c>）；创建失败返回 null。</returns>
    public string? CreateShadow(string driveLetter)
    {
        ThrowIfDisposed();
        var letter = NormalizeDriveLetter(driveLetter);
        ErrorReporter.Log($"创建 VSS 卷影副本：{letter}:");

        string? shadow = null;

        // 主方法：PowerShell WMI 创建卷影
        try
        {
            var script = CreateShadowTemplate.Replace("__LETTER__", letter);
            var output = RunPowerShell(script, 120000);
            var match = ShadowDeviceRegex.Match(output);
            if (match.Success)
            {
                shadow = match.Value;
            }
            else if (!string.IsNullOrWhiteSpace(output))
            {
                ErrorReporter.Log($"PowerShell 创建卷影未返回设备路径（ReturnValue 可能非 0）：{output.Trim()}", "WARN");
            }
        }
        catch (Exception ex)
        {
            ErrorReporter.Log($"PowerShell 创建卷影副本失败，尝试回退到 vssadmin：{ex.Message}", "WARN");
        }

        // 回退方法：vssadmin.exe
        if (string.IsNullOrEmpty(shadow))
        {
            shadow = TryCreateShadowVssadmin(letter);
        }

        if (!string.IsNullOrEmpty(shadow))
        {
            _createdShadows.Add(shadow);
            ErrorReporter.Log($"VSS 卷影副本创建成功：{shadow}");
        }
        else
        {
            ErrorReporter.Log("VSS 卷影副本创建失败（需管理员权限且 VSS 服务运行中）。", "WARN");
        }

        return shadow;
    }

    /// <summary>
    /// 删除指定的 VSS 卷影副本。
    /// <para>通过设备路径解析卷影 ID 后调用 <c>vssadmin.exe delete shadows</c> 删除。</para>
    /// </summary>
    /// <param name="shadowPath">卷影设备路径。</param>
    /// <returns>删除成功（或卷影已不存在）返回 true；删除失败返回 false。</returns>
    public bool DeleteShadow(string shadowPath)
    {
        ThrowIfDisposed();
        return DeleteShadowInternal(shadowPath);
    }

    /// <summary>
    /// 列出当前系统中所有已存在的 VSS 卷影副本。
    /// </summary>
    /// <returns>卷影设备路径列表。</returns>
    public List<string> ListShadows()
    {
        ThrowIfDisposed();
        var list = new List<string>();
        try
        {
            var output = RunPowerShell("(Get-WmiObject Win32_ShadowCopy).DeviceObject", 30000);
            foreach (Match m in ShadowDeviceRegex.Matches(output))
                list.Add(m.Value);
        }
        catch (Exception ex)
        {
            ErrorReporter.Log($"枚举卷影副本失败：{ex.Message}", "WARN");
        }
        return list;
    }

    /// <summary>
    /// 从卷影副本中读取指定文件内容。
    /// <para>卷影副本提供的是某时刻的一致性快照，可读取当时被占用的文件。</para>
    /// </summary>
    /// <param name="shadowPath">卷影设备路径。</param>
    /// <param name="relativeFilePath">相对于卷根的文件路径（如 "Users\test\file.txt"）。</param>
    /// <returns>文件字节内容；读取失败返回 null。</returns>
    public byte[]? CopyFromShadow(string shadowPath, string relativeFilePath)
    {
        ThrowIfDisposed();
        if (string.IsNullOrWhiteSpace(shadowPath) || string.IsNullOrWhiteSpace(relativeFilePath))
            return null;

        var rel = relativeFilePath.Replace('/', '\\').TrimStart('\\');
        var fullPath = shadowPath.TrimEnd('\\') + "\\" + rel;

        try
        {
            return ReadAllBytesFromPath(fullPath);
        }
        catch (Exception ex)
        {
            ErrorReporter.Log($"从卷影副本读取文件失败：{fullPath} | {ex.Message}", "WARN");
            return null;
        }
    }

    /// <summary>
    /// 删除卷影副本的内部实现（不检查释放状态，供 Dispose 复用）。
    /// </summary>
    private bool DeleteShadowInternal(string shadowPath)
    {
        if (string.IsNullOrWhiteSpace(shadowPath))
            return false;

        ErrorReporter.Log($"删除 VSS 卷影副本：{shadowPath}");
        try
        {
            var id = ResolveShadowId(shadowPath);
            if (string.IsNullOrEmpty(id))
            {
                // 卷影已不存在，视为已清理（幂等）
                _createdShadows.Remove(shadowPath);
                ErrorReporter.Log($"未找到卷影副本对应 ID，可能已被删除：{shadowPath}");
                return true;
            }

            var ok = RunVssadmin($"delete shadows /shadow={{{id}}} /quiet");
            if (ok)
            {
                _createdShadows.Remove(shadowPath);
                ErrorReporter.Log($"VSS 卷影副本已删除：{shadowPath}");
            }
            else
            {
                ErrorReporter.Log($"VSS 卷影副本删除失败：{shadowPath}", "WARN");
            }
            return ok;
        }
        catch (Exception ex)
        {
            ErrorReporter.Log($"删除 VSS 卷影副本异常：{ex.Message}", "WARN");
            return false;
        }
    }

    /// <summary>
    /// 通过卷影设备路径解析其 GUID 形式的卷影 ID。
    /// </summary>
    private string? ResolveShadowId(string shadowPath)
    {
        var script = ResolveIdTemplate.Replace("__PATH__", EscapePowerShellSingleQuote(shadowPath));
        var output = RunPowerShell(script, 30000);
        var m = GuidRegex.Match(output);
        return m.Success ? m.Value : null;
    }

    /// <summary>
    /// 回退方法：使用 vssadmin.exe 创建卷影副本并解析设备路径。
    /// </summary>
    private static string? TryCreateShadowVssadmin(string letter)
    {
        try
        {
            var psi = new ProcessStartInfo("vssadmin.exe", $"create shadow /for={letter}:")
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            using var p = Process.Start(psi);
            if (p == null) return null;

            var output = p.StandardOutput.ReadToEnd() + Environment.NewLine + p.StandardError.ReadToEnd();
            if (!p.WaitForExit(60000))
            {
                try { p.Kill(); } catch { }
                ErrorReporter.Log("vssadmin 创建卷影执行超时。", "WARN");
                return null;
            }
            if (p.ExitCode != 0)
            {
                ErrorReporter.Log($"vssadmin 创建卷影失败（ExitCode={p.ExitCode}）。", "WARN");
                return null;
            }

            var match = VssadminShadowRegex.Match(output);
            return match.Success ? match.Groups[1].Value : null;
        }
        catch (Exception ex)
        {
            ErrorReporter.Log($"vssadmin 创建卷影副本异常：{ex.Message}", "WARN");
            return null;
        }
    }

    #endregion

    #region VSS 目录备份

    /// <summary>
    /// 使用 VSS 卷影副本备份整个目录。
    /// <para>流程：创建卷影快照 → 从快照读取文件（一致性视图）→ 构建目录归档 → 加密分片 → 写入 .lgbackup → 清理卷影。</para>
    /// <para>VSS 不可用时返回 null，调用方可回退到 <see cref="BackupExecutor.BackupDirectory"/> 普通目录备份。</para>
    /// </summary>
    /// <param name="dirPath">源目录路径。</param>
    /// <param name="destDir">目标目录（本地或 SMB UNC 路径）。</param>
    /// <param name="password">加密口令。</param>
    /// <param name="progress">进度跟踪器（可选）。</param>
    /// <returns>备份清单；VSS 卷影创建失败时返回 null。</returns>
    public BackupManifest? BackupDirectoryWithVss(string dirPath, string destDir, string password, BackupProgress? progress = null)
    {
        ThrowIfDisposed();

        if (!Directory.Exists(dirPath))
            throw new DirectoryNotFoundException("待备份目录不存在：" + dirPath);
        ArgumentNullException.ThrowIfNull(destDir);
        if (string.IsNullOrWhiteSpace(password))
            throw new ArgumentException("加密口令不能为空。", nameof(password));

        var driveLetter = ExtractDriveLetter(dirPath);
        ErrorReporter.Log($"开始 VSS 目录备份：{dirPath}（盘符 {driveLetter}:）");

        var shadowPath = CreateShadow(driveLetter);
        if (string.IsNullOrEmpty(shadowPath))
        {
            ErrorReporter.Log("VSS 卷影副本创建失败，已跳过 VSS 备份（调用方可回退到普通目录备份）。", "WARN");
            return null;
        }

        try
        {
            // 枚举原始目录文件（仅用于路径解析，内容从卷影副本读取）
            var files = EnumerateFiles(dirPath);
            var volumeRoot = Path.GetPathRoot(dirPath) ?? string.Empty;

            // 预估总量用于进度展示
            long totalBytes = 0;
            foreach (var f in files)
            {
                try { totalBytes += new FileInfo(f).Length; } catch { }
            }
            progress?.SetTotal(files.Count, totalBytes);

            var (archive, fileCount) = BuildDirectoryArchiveFromShadow(
                dirPath, shadowPath, volumeRoot, files, progress);

            var metadata = new Dictionary<string, string>
            {
                ["Strategy"] = "VSS",
                ["VssShadow"] = shadowPath,
                ["DriveLetter"] = driveLetter
            };

            return WriteEncryptedBackup(archive, BackupType.Directory, dirPath, destDir,
                fileCount, password, metadata, progress);
        }
        finally
        {
            // 无论成功与否，清理本次创建的卷影副本
            DeleteShadowInternal(shadowPath);
        }
    }

    /// <summary>
    /// 从卷影副本读取文件内容并构建目录归档字节流。
    /// <para>归档二进制格式与 <see cref="BackupExecutor.BuildDirectoryArchive"/> 完全一致：</para>
    /// <para>[条目数 int64] 每条目 [相对路径长度 int32][相对路径 UTF8][数据长度 int64][数据]。</para>
    /// </summary>
    private (byte[] Archive, int FileCount) BuildDirectoryArchiveFromShadow(
        string dirPath, string shadowPath, string volumeRoot, List<string> files, BackupProgress? progress)
    {
        var entries = new List<(string RelPath, byte[] Data)>();
        long processed = 0;
        int processedFiles = 0;
        var shadowBase = shadowPath.TrimEnd('\\');

        foreach (var file in files)
        {
            progress?.ThrowIfCancellationRequested();

            string relPath;
            try
            {
                relPath = Path.GetRelativePath(dirPath, file).Replace('\\', '/');
            }
            catch
            {
                continue;
            }

            // 卷影副本内对应路径：去掉卷根前缀后拼接到卷影设备路径
            string volRel;
            try
            {
                volRel = file.Substring(volumeRoot.Length).Replace('/', '\\');
            }
            catch
            {
                continue;
            }
            var shadowFile = shadowBase + "\\" + volRel;

            byte[] data;
            try
            {
                data = ReadAllBytesFromPath(shadowFile);
            }
            catch (Exception ex)
            {
                ErrorReporter.Log($"跳过卷影中无法读取的文件 {relPath}：{ex.Message}");
                processedFiles++;
                continue;
            }

            entries.Add((relPath, data));
            processed += data.Length;
            processedFiles++;
            progress?.UpdateProgress(processedFiles, processed, file, false, BackupPhase.Backup);
        }

        // 序列化归档（与 BackupExecutor.BuildDirectoryArchive 相同的二进制格式）
        using var ms = new MemoryStream();
        using (var bw = new BinaryWriter(ms, Encoding.UTF8, leaveOpen: true))
        {
            bw.Write((long)entries.Count);
            foreach (var (rel, data) in entries)
            {
                var relBytes = Encoding.UTF8.GetBytes(rel);
                bw.Write(relBytes.Length);
                bw.Write(relBytes);
                bw.Write((long)data.Length);
                bw.Write(data);
            }
        }

        ErrorReporter.Log($"卷影目录归档构建完成：{dirPath} | 文件 {entries.Count} | {ms.Length} 字节");
        return (ms.ToArray(), entries.Count);
    }

    /// <summary>
    /// 加密归档数据并写入 .lgbackup 备份包。
    /// <para>流程：派生密钥 → 分片 → AES-256-GCM/ChaCha20 加密 → 写入 → 结构性校验。</para>
    /// </summary>
    private BackupManifest WriteEncryptedBackup(byte[] data, BackupType type, string sourcePath, string destDir,
        int fileCount, string password, Dictionary<string, string>? metadata, BackupProgress? progress)
    {
        var salt = _crypto.GenerateSalt();
        var key = _crypto.DeriveKey(password, salt);

        var shards = BackupShardEngine.ShardData(data, _shardSize);
        var globalHash = BackupShardEngine.ComputeGlobalHash(shards);

        progress?.SetTotal(fileCount, data.Length);

        var encrypted = new List<EncryptedShard>(shards.Count);
        long processed = 0;
        for (int i = 0; i < shards.Count; i++)
        {
            progress?.ThrowIfCancellationRequested();
            var s = shards[i];
            var (cipher, nonce, tag) = _crypto.Encrypt(s.Data, key);
            encrypted.Add(new EncryptedShard
            {
                Index = s.Index,
                Cipher = cipher,
                Nonce = nonce,
                Tag = tag,
                PlainHash = s.Hash
            });
            processed += s.Length;
            progress?.UpdateProgress(fileCount, processed, sourcePath, true, BackupPhase.Backup);
        }

        var manifest = new BackupManifest
        {
            BackupType = type,
            SourcePath = sourcePath,
            BackupTime = DateTime.Now,
            ShardSize = _shardSize,
            EncryptedAlgorithm = _crypto.AlgorithmName,
            Salt = Convert.ToBase64String(salt),
            TotalSize = data.Length,
            ShardCount = shards.Count,
            FileCount = fileCount,
            GlobalHash = Convert.ToHexString(globalHash)
        };
        if (metadata != null)
        {
            foreach (var kv in metadata)
                manifest.Metadata[kv.Key] = kv.Value;
        }

        var outputPath = GenerateOutputPath(destDir, type, manifest.BackupId);
        Directory.CreateDirectory(destDir);

        progress?.UpdateProgress(fileCount, data.Length, sourcePath, false, BackupPhase.Verify);
        LgBackupFormat.WriteBackup(outputPath, manifest, encrypted);

        if (!LgBackupFormat.VerifyBackup(outputPath))
            throw new InvalidDataException("备份包写入后结构性校验失败，请重试。");

        progress?.UpdateProgress(fileCount, data.Length, outputPath, false, BackupPhase.Upload);
        ErrorReporter.Log($"VSS 备份完成：[{type}] {sourcePath} -> {outputPath} | 文件 {fileCount} | 分片 {shards.Count} | {data.Length} 字节 | 算法 {manifest.EncryptedAlgorithm}");
        return manifest;
    }

    #endregion

    #region 进程执行

    /// <summary>
    /// 运行 PowerShell 脚本并捕获标准输出（使用 -EncodedCommand 规避引号转义问题）。
    /// </summary>
    /// <param name="script">PowerShell 脚本文本。</param>
    /// <param name="timeoutMs">超时时间（毫秒）。</param>
    /// <returns>标准输出文本。</returns>
    private static string RunPowerShell(string script, int timeoutMs = 60000)
    {
        var encoded = Convert.ToBase64String(Encoding.Unicode.GetBytes(script));
        var psi = new ProcessStartInfo("powershell.exe", $"-NoProfile -NonInteractive -EncodedCommand {encoded}")
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        using var p = Process.Start(psi) ?? throw new InvalidOperationException("无法启动 powershell.exe。");
        var stdout = p.StandardOutput.ReadToEnd();
        var stderr = p.StandardError.ReadToEnd();

        if (!p.WaitForExit(timeoutMs))
        {
            try { p.Kill(); } catch { }
            throw new TimeoutException($"PowerShell 执行超时（{timeoutMs}ms）：{script}");
        }

        if (p.ExitCode != 0 && !string.IsNullOrWhiteSpace(stderr))
            ErrorReporter.Log($"PowerShell 返回非零（ExitCode={p.ExitCode}）：{stderr.Trim()}", "WARN");

        return stdout ?? string.Empty;
    }

    /// <summary>
    /// 运行 vssadmin.exe 并返回是否成功（ExitCode == 0）。
    /// </summary>
    /// <param name="arguments">vssadmin 子命令参数。</param>
    /// <param name="timeoutMs">超时时间（毫秒）。</param>
    /// <returns>执行成功返回 true。</returns>
    private static bool RunVssadmin(string arguments, int timeoutMs = 60000)
    {
        try
        {
            var psi = new ProcessStartInfo("vssadmin.exe", arguments)
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            using var p = Process.Start(psi);
            if (p == null) return false;

            var stdout = p.StandardOutput.ReadToEnd();
            var stderr = p.StandardError.ReadToEnd();
            if (!p.WaitForExit(timeoutMs))
            {
                try { p.Kill(); } catch { }
                ErrorReporter.Log($"vssadmin 执行超时：{arguments}", "WARN");
                return false;
            }
            if (p.ExitCode != 0)
            {
                ErrorReporter.Log($"vssadmin 执行失败（ExitCode={p.ExitCode}）：{arguments} | {stderr.Trim()}", "WARN");
                return false;
            }
            return true;
        }
        catch (Exception ex)
        {
            ErrorReporter.Log($"vssadmin 执行异常：{arguments} | {ex.Message}", "WARN");
            return false;
        }
    }

    /// <summary>
    /// 以共享读方式读取文件全部字节（兼容被占用文件与卷影副本设备路径）。
    /// </summary>
    private static byte[] ReadAllBytesFromPath(string path)
    {
        using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
        if (fs.Length <= 0)
            return Array.Empty<byte>();

        var capacity = fs.Length < int.MaxValue ? (int)fs.Length : int.MaxValue;
        using var ms = new MemoryStream(capacity);
        fs.CopyTo(ms);
        return ms.ToArray();
    }

    #endregion

    #region 辅助

    /// <summary>
    /// 规范化盘符为大写单字符（如 "c:\" → "C"）。
    /// </summary>
    private static string NormalizeDriveLetter(string driveLetter)
    {
        if (string.IsNullOrWhiteSpace(driveLetter))
            throw new ArgumentException("盘符不能为空。", nameof(driveLetter));
        var c = char.ToUpperInvariant(driveLetter.Trim()[0]);
        if (c < 'A' || c > 'Z')
            throw new ArgumentException("无效盘符：" + driveLetter, nameof(driveLetter));
        return c.ToString();
    }

    /// <summary>
    /// 从路径解析盘符（如 "C:\Users\..." → "C"）。
    /// </summary>
    private static string ExtractDriveLetter(string path)
    {
        var root = Path.GetPathRoot(path);
        if (string.IsNullOrEmpty(root) || root.Length < 2 || root[1] != ':')
            throw new ArgumentException($"无法从路径解析盘符：{path}", nameof(path));
        return char.ToUpperInvariant(root[0]).ToString();
    }

    /// <summary>
    /// 转义 PowerShell 单引号字符串字面量中的单引号（' → ''）。
    /// </summary>
    private static string EscapePowerShellSingleQuote(string value)
        => value.Replace("'", "''");

    /// <summary>
    /// 生成 .lgbackup 输出路径。
    /// </summary>
    private static string GenerateOutputPath(string destDir, BackupType type, Guid id)
        => Path.Combine(destDir, $"{type}_{DateTime.Now:yyyyMMdd_HHmmss}_{id.ToString("N")[..8]}{LgBackupFormat.Extension}");

    /// <summary>
    /// 递归枚举目录下所有文件（失败时返回空列表并记录）。
    /// </summary>
    private static List<string> EnumerateFiles(string dirPath)
    {
        try
        {
            return Directory.EnumerateFiles(dirPath, "*", SearchOption.AllDirectories).ToList();
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, $"枚举目录失败：{dirPath}");
            return new List<string>();
        }
    }

    /// <summary>
    /// 若已释放则抛出 <see cref="ObjectDisposedException"/>。
    /// </summary>
    private void ThrowIfDisposed()
    {
        if (_disposed) throw new ObjectDisposedException(nameof(VssShadowCopyEngine));
    }

    #endregion

    #region IDisposable

    /// <summary>
    /// 释放资源：删除本引擎创建且尚未清理的所有卷影副本。
    /// </summary>
    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;

        foreach (var shadow in _createdShadows.ToList())
        {
            try { DeleteShadowInternal(shadow); } catch { }
        }
        _createdShadows.Clear();
        GC.SuppressFinalize(this);
    }

    #endregion
}
