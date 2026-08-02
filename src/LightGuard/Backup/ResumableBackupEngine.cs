// © 2026 落尘（Luochen） 原创开发 - 保留所有权利

using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using LightGuard.Core;

namespace LightGuard.Backup;

/// <summary>
/// 分块处理状态。
/// </summary>
public enum ChunkState
{
    /// <summary>待处理。</summary>
    Pending,

    /// <summary>处理中。</summary>
    InProcess,

    /// <summary>已完成（已加密落盘）。</summary>
    Completed,

    /// <summary>失败。</summary>
    Failed
}

/// <summary>
/// 分块信息 - 描述可续传备份中单个数据块的位置、长度与处理状态。
/// </summary>
public sealed class ChunkInfo
{
    /// <summary>分块序号（从 0 开始）。</summary>
    public int Index { get; set; }

    /// <summary>分块在源文件中的字节偏移。</summary>
    public long Offset { get; set; }

    /// <summary>分块数据长度（字节）。</summary>
    public long Length { get; set; }

    /// <summary>分块当前状态。</summary>
    public ChunkState State { get; set; }

    /// <summary>明文分块 SHA256（大写十六进制），分块完成后填充。</summary>
    public string Hash { get; set; } = string.Empty;

    /// <summary>分块完成时间；未完成为 null。</summary>
    public DateTime? CompletedAt { get; set; }
}

/// <summary>
/// 可续传备份会话 - 持久化为 .lgsession 文件，记录分块进度与加密参数。
/// <para>中断后可依据该会话从上一个已完成分块继续，全部完成后合并为标准 .lgbackup 备份包。</para>
/// </summary>
public sealed class ResumableSession
{
    /// <summary>会话唯一标识（GUID 的 32 位十六进制文本）。</summary>
    public string SessionId { get; set; } = string.Empty;

    /// <summary>源文件路径。</summary>
    public string SourcePath { get; set; } = string.Empty;

    /// <summary>目标目录（分块与会话文件的存放目录）。</summary>
    public string DestDir { get; set; } = string.Empty;

    /// <summary>源文件总大小（字节）。</summary>
    public long FileSize { get; set; }

    /// <summary>分块大小（字节）。</summary>
    public int ChunkSize { get; set; }

    /// <summary>总分块数。</summary>
    public int TotalChunks { get; set; }

    /// <summary>所有分块的处理信息。</summary>
    public List<ChunkInfo> Chunks { get; set; } = new();

    /// <summary>会话创建时间。</summary>
    public DateTime CreatedAt { get; set; }

    /// <summary>最近一次续传时间；从未续传为 null。</summary>
    public DateTime? ResumedAt { get; set; }

    /// <summary>全部分块完成时间；未全部完成为 null。</summary>
    public DateTime? CompletedAt { get; set; }

    /// <summary>是否全部分块已完成（尚未合并为 .lgbackup）。</summary>
    public bool IsCompleted { get; set; }

    /// <summary>PBKDF2 随机盐（与口令共同派生加密密钥）。</summary>
    public byte[] Salt { get; set; } = Array.Empty<byte>();

    /// <summary>加密算法名称："AES-256-GCM" 或 "ChaCha20-Poly1305"。</summary>
    public string Algorithm { get; set; } = "AES-256-GCM";
}

/// <summary>
/// 可断点续传大文件备份引擎 - 支持分块加密存储与中断恢复。
/// <para>将大文件切分为固定大小的数据块，每块独立加密写入 chunk_{sessionId}_{index}.lgchunk 文件；</para>
/// <para>会话状态持久化为 .lgsession（JSON）。中断后可从首个待处理分块继续；</para>
/// <para>全部完成后由 <see cref="CompleteSession"/> 合并所有分块为标准 .lgbackup 备份包。</para>
/// <para>密钥派生：PBKDF2-HMAC-SHA256，10 万次迭代 + 会话内随机盐，口令不落盘。</para>
/// </summary>
public sealed class ResumableBackupEngine
{
    /// <summary>会话状态文件扩展名。</summary>
    public const string SessionExtension = ".lgsession";

    /// <summary>分块文件扩展名。</summary>
    public const string ChunkExtension = ".lgchunk";

    /// <summary>分块文件格式版本。</summary>
    public const int ChunkFormatVersion = 1;

    /// <summary>分块文件头魔数："LGCHUNK\0"，共 8 字节。</summary>
    public static readonly byte[] ChunkMagic = { 0x4C, 0x47, 0x43, 0x48, 0x55, 0x4E, 0x4B, 0x00 };

    private const int DefaultChunkSize = 16 * 1024 * 1024; // 16MB

    private static readonly JsonSerializerOptions SessionJsonOptions = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Converters = { new JsonStringEnumConverter() }
    };

    private readonly BackupCryptoEngine _defaultCrypto;

    /// <summary>
    /// 初始化可续传备份引擎。
    /// </summary>
    /// <param name="appState">全局应用状态（用于硬件自适应选择加密算法）；为 null 时按当前环境自动检测。</param>
    public ResumableBackupEngine(AppState? appState = null)
    {
        _defaultCrypto = appState != null
            ? new BackupCryptoEngine(appState.Hardware)
            : new BackupCryptoEngine();
    }

    /// <summary>默认加密算法名称。</summary>
    public string AlgorithmName => _defaultCrypto.AlgorithmName;

    /// <summary>
    /// 启动一个新的可续传备份会话，写入会话状态文件并立即开始分块加密。
    /// <para>若处理过程中被取消或异常，会话状态已持久化，可调用 <see cref="ResumeBackup"/> 继续。</para>
    /// </summary>
    /// <param name="filePath">源文件路径。</param>
    /// <param name="password">加密口令（不落盘，仅用于派生密钥）。</param>
    /// <param name="destDir">目标目录。</param>
    /// <param name="chunkSize">分块大小（字节），默认 16MB。</param>
    /// <param name="progress">进度跟踪器（可选，支持取消）。</param>
    /// <returns>会话状态文件（.lgsession）路径。</returns>
    public string StartResumableBackup(string filePath, string password, string destDir,
        int chunkSize = DefaultChunkSize, BackupProgress? progress = null)
    {
        if (!File.Exists(filePath))
            throw new FileNotFoundException("待备份文件不存在。", filePath);
        if (string.IsNullOrWhiteSpace(password))
            throw new ArgumentException("加密口令不能为空。", nameof(password));
        if (string.IsNullOrWhiteSpace(destDir))
            throw new ArgumentException("目标目录不能为空。", nameof(destDir));
        if (chunkSize <= 0) chunkSize = DefaultChunkSize;

        Directory.CreateDirectory(destDir);

        var fileSize = new FileInfo(filePath).Length;
        var sessionId = Guid.NewGuid().ToString("N");
        var totalChunks = (int)((fileSize + chunkSize - 1) / chunkSize);
        if (totalChunks <= 0) totalChunks = 1; // 空文件至少保留一个空分块，保证可逆

        var salt = _defaultCrypto.GenerateSalt();
        var key = _defaultCrypto.DeriveKey(password, salt);

        var chunks = new List<ChunkInfo>(totalChunks);
        for (int i = 0; i < totalChunks; i++)
        {
            long offset = (long)i * chunkSize;
            long length = Math.Min(chunkSize, fileSize - offset);
            if (length < 0) length = 0;
            chunks.Add(new ChunkInfo
            {
                Index = i,
                Offset = offset,
                Length = length,
                State = ChunkState.Pending
            });
        }

        var session = new ResumableSession
        {
            SessionId = sessionId,
            SourcePath = filePath,
            DestDir = destDir,
            FileSize = fileSize,
            ChunkSize = chunkSize,
            TotalChunks = totalChunks,
            Chunks = chunks,
            CreatedAt = DateTime.Now,
            Salt = salt,
            Algorithm = _defaultCrypto.AlgorithmName
        };

        var sessionFile = GetSessionFilePath(destDir, sessionId);
        SaveSession(session, sessionFile);

        ErrorReporter.Log($"开始可续传备份：{filePath} -> {destDir} | 大小 {fileSize} 字节 | 分块 {totalChunks} 块 | 块大小 {chunkSize} 字节 | 算法 {session.Algorithm} | 会话 {sessionId}");

        ProcessPendingChunks(session, sessionFile, _defaultCrypto, key, progress);

        return sessionFile;
    }

    /// <summary>
    /// 从上一个已完成分块继续中断的备份。
    /// <para>已完成的分块会被跳过；失败/处理中状态的重置为待处理；已完成但分块文件缺失的将重新处理。</para>
    /// </summary>
    /// <param name="sessionFile">会话状态文件（.lgsession）路径。</param>
    /// <param name="password">加密口令（必须与启动时一致，否则后续合并解密将失败）。</param>
    /// <param name="progress">进度跟踪器（可选，支持取消）。</param>
    /// <returns>会话状态文件路径。</returns>
    public string ResumeBackup(string sessionFile, string password, BackupProgress? progress)
    {
        var session = LoadSession(sessionFile);

        if (session.IsCompleted && session.Chunks.All(c => c.State == ChunkState.Completed))
        {
            ErrorReporter.Log($"会话 {session.SessionId} 已完成全部分块，无需续传。");
            return sessionFile;
        }

        if (string.IsNullOrWhiteSpace(password))
            throw new ArgumentException("加密口令不能为空。", nameof(password));

        // 失败/处理中状态重置为待处理
        foreach (var c in session.Chunks.Where(c => c.State == ChunkState.Failed || c.State == ChunkState.InProcess))
        {
            c.State = ChunkState.Pending;
            c.CompletedAt = null;
        }

        // 已完成但分块文件缺失的，重新处理
        for (int i = 0; i < session.TotalChunks; i++)
        {
            var c = session.Chunks[i];
            if (c.State == ChunkState.Completed)
            {
                var chunkFile = GetChunkPath(session.DestDir, session.SessionId, i);
                if (!File.Exists(chunkFile))
                {
                    c.State = ChunkState.Pending;
                    c.Hash = string.Empty;
                    c.CompletedAt = null;
                }
            }
        }

        var crypto = new BackupCryptoEngine(session.Algorithm);
        var key = crypto.DeriveKey(password, session.Salt);

        var completedCount = session.Chunks.Count(c => c.State == ChunkState.Completed);
        ErrorReporter.Log($"续传备份：会话 {session.SessionId} | 已完成 {completedCount}/{session.TotalChunks} 块 | 算法 {session.Algorithm}");

        ProcessPendingChunks(session, sessionFile, crypto, key, progress);
        return sessionFile;
    }

    /// <summary>
    /// 读取会话状态信息（不执行任何处理）。
    /// </summary>
    /// <param name="sessionFile">会话状态文件（.lgsession）路径。</param>
    /// <returns>会话状态实例。</returns>
    public ResumableSession GetSessionInfo(string sessionFile) => LoadSession(sessionFile);

    /// <summary>
    /// 列出目标目录下所有未完成（分块尚未全部完成）的会话文件。
    /// </summary>
    /// <param name="destDir">目标目录。</param>
    /// <returns>未完成会话文件路径列表。</returns>
    public List<string> ListPendingSessions(string destDir)
    {
        var result = new List<string>();
        if (string.IsNullOrEmpty(destDir) || !Directory.Exists(destDir))
            return result;

        foreach (var file in Directory.EnumerateFiles(destDir, "*" + SessionExtension))
        {
            try
            {
                var session = LoadSession(file);
                if (!session.IsCompleted)
                    result.Add(file);
            }
            catch (Exception ex)
            {
                ErrorReporter.Log($"跳过无法解析的会话文件 {file}：{ex.Message}", "WARN");
            }
        }

        return result;
    }

    /// <summary>
    /// 中止会话，清理所有分块文件与会话状态文件。
    /// </summary>
    /// <param name="sessionFile">会话状态文件（.lgsession）路径。</param>
    public void AbortSession(string sessionFile)
    {
        var session = LoadSession(sessionFile);
        ErrorReporter.Log($"中止并清理续传会话：{session.SessionId}");

        DeleteChunkFiles(session);
        TryDeleteFile(sessionFile);

        ErrorReporter.Log($"续传会话 {session.SessionId} 已清理完毕。");
    }

    /// <summary>
    /// 合并所有已完成分块为标准 .lgbackup 备份包，并删除分块文件与会话状态文件。
    /// <para>调用前会话必须已完成全部分块（<see cref="ResumableSession.IsCompleted"/> 为 true）。</para>
    /// </summary>
    /// <param name="sessionFile">会话状态文件（.lgsession）路径。</param>
    /// <returns>合并后的 .lgbackup 备份包路径。</returns>
    public string CompleteSession(string sessionFile)
    {
        var session = LoadSession(sessionFile);

        if (!session.IsCompleted || session.Chunks.Any(c => c.State != ChunkState.Completed))
            throw new InvalidOperationException("会话尚未完成全部分块，无法合并。请先调用 ResumeBackup 完成剩余分块。");

        ErrorReporter.Log($"开始合并续传会话：{session.SessionId} | 共 {session.TotalChunks} 块 | {session.FileSize} 字节");

        // 读取所有分块为加密分片记录（按序）
        var shards = new List<EncryptedShard>(session.TotalChunks);
        for (int i = 0; i < session.TotalChunks; i++)
        {
            var chunkFile = GetChunkPath(session.DestDir, session.SessionId, i);
            if (!File.Exists(chunkFile))
                throw new FileNotFoundException($"分块文件缺失，无法合并：{chunkFile}", chunkFile);
            shards.Add(ReadChunkFile(chunkFile));
        }

        var manifest = new BackupManifest
        {
            BackupType = BackupType.File,
            SourcePath = session.SourcePath,
            BackupTime = DateTime.Now,
            ShardSize = session.ChunkSize,
            EncryptedAlgorithm = session.Algorithm,
            Salt = Convert.ToBase64String(session.Salt),
            TotalSize = session.FileSize,
            ShardCount = session.TotalChunks,
            FileCount = 1,
            GlobalHash = ComputeGlobalHash(session)
        };
        manifest.Metadata["Strategy"] = "Resumable";
        manifest.Metadata["ResumableSessionId"] = session.SessionId;

        Directory.CreateDirectory(session.DestDir);
        var outputPath = Path.Combine(session.DestDir,
            $"File_{DateTime.Now:yyyyMMdd_HHmmss}_{session.SessionId[..8]}{LgBackupFormat.Extension}");

        LgBackupFormat.WriteBackup(outputPath, manifest, shards);

        if (!LgBackupFormat.VerifyBackup(outputPath))
            throw new InvalidDataException("合并后的备份包结构性校验失败，文件可能已损坏。");

        ErrorReporter.Log($"续传会话合并完成：{session.SessionId} -> {outputPath} | 算法 {manifest.EncryptedAlgorithm}");

        // 合并成功后清理分块与会话文件
        DeleteChunkFiles(session);
        TryDeleteFile(sessionFile);

        return outputPath;
    }

    #region 核心处理流程

    /// <summary>
    /// 处理所有待处理分块：读取源文件 → 加密 → 写入分块文件 → 更新状态。
    /// <para>支持取消；取消时当前分块回退为待处理，已完成的分块保留。</para>
    /// </summary>
    private void ProcessPendingChunks(ResumableSession session, string sessionFile,
        BackupCryptoEngine crypto, byte[] key, BackupProgress? progress)
    {
        session.ResumedAt = DateTime.Now;
        SaveSession(session, sessionFile);

        progress?.SetTotal(1, session.FileSize);

        long processedBytes = session.Chunks
            .Where(c => c.State == ChunkState.Completed)
            .Sum(c => c.Length);

        var pending = session.Chunks
            .Where(c => c.State != ChunkState.Completed)
            .OrderBy(c => c.Index)
            .ToList();

        using var fs = new FileStream(session.SourcePath, FileMode.Open, FileAccess.Read, FileShare.Read);

        foreach (var chunk in pending)
        {
            progress?.ThrowIfCancellationRequested();

            chunk.State = ChunkState.InProcess;
            SaveSession(session, sessionFile);

            try
            {
                fs.Position = chunk.Offset;
                var buffer = new byte[(int)chunk.Length];
                int totalRead = 0;
                while (totalRead < buffer.Length)
                {
                    int read = fs.Read(buffer, totalRead, buffer.Length - totalRead);
                    if (read <= 0) break;
                    totalRead += read;
                }

                // 源文件缩短等异常情况下按实际读取长度处理
                if (totalRead < chunk.Length)
                {
                    Array.Resize(ref buffer, totalRead);
                }

                var plainHash = SHA256.HashData(buffer);
                var (cipher, nonce, tag) = crypto.Encrypt(buffer, key);

                var chunkFile = GetChunkPath(session.DestDir, session.SessionId, chunk.Index);
                WriteChunkFile(chunkFile, chunk.Index, cipher, nonce, tag, plainHash);

                chunk.Hash = Convert.ToHexString(plainHash);
                chunk.State = ChunkState.Completed;
                chunk.CompletedAt = DateTime.Now;
                processedBytes += chunk.Length;

                SaveSession(session, sessionFile);
                progress?.UpdateProgress(1, processedBytes, session.SourcePath, true, BackupPhase.Backup);
            }
            catch (OperationCanceledException)
            {
                chunk.State = ChunkState.Pending;
                chunk.CompletedAt = null;
                SaveSession(session, sessionFile);
                ErrorReporter.Log($"续传备份已取消：会话 {session.SessionId}，停在第 {chunk.Index} 块", "WARN");
                throw;
            }
            catch (Exception ex)
            {
                chunk.State = ChunkState.Failed;
                SaveSession(session, sessionFile);
                ErrorReporter.Report(ex, $"续传备份分块失败：会话 {session.SessionId}，块 {chunk.Index}");
                throw;
            }
        }

        // 全部分块完成
        if (session.Chunks.All(c => c.State == ChunkState.Completed))
        {
            session.IsCompleted = true;
            session.CompletedAt = DateTime.Now;
            SaveSession(session, sessionFile);
            progress?.UpdateProgress(1, session.FileSize, session.SourcePath, false, BackupPhase.Verify);
            ErrorReporter.Log($"续传备份全部分块完成：会话 {session.SessionId} | 共 {session.TotalChunks} 块 | 可调用 CompleteSession 合并为 .lgbackup");
        }
    }

    /// <summary>
    /// 计算整包总哈希（SHA256 十六进制）：读取源文件整体求哈希。
    /// <para>源文件不可用时返回空字符串并记录警告。</para>
    /// </summary>
    private static string ComputeGlobalHash(ResumableSession session)
    {
        try
        {
            if (!File.Exists(session.SourcePath))
            {
                ErrorReporter.Log($"源文件不存在，无法计算全局哈希：{session.SourcePath}", "WARN");
                return string.Empty;
            }

            using var fs = new FileStream(session.SourcePath, FileMode.Open, FileAccess.Read, FileShare.Read);
            return Convert.ToHexString(SHA256.HashData(fs));
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, $"计算全局哈希失败：{session.SourcePath}");
            return string.Empty;
        }
    }

    #endregion

    #region 分块文件读写

    /// <summary>
    /// 写入单个分块文件：[魔数 8][版本 4][序号 4][加密分片记录]。
    /// <para>加密分片记录复用 <see cref="LgBackupFormat.WriteShardRecord"/> 格式。</para>
    /// </summary>
    private static void WriteChunkFile(string path, int index, byte[] cipher, byte[] nonce, byte[] tag, byte[] plainHash)
    {
        using var fs = new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.None);
        using var bw = new BinaryWriter(fs, Encoding.UTF8, leaveOpen: true);

        bw.Write(ChunkMagic);
        bw.Write(ChunkFormatVersion);
        bw.Write(index);

        LgBackupFormat.WriteShardRecord(bw, new EncryptedShard
        {
            Index = index,
            Cipher = cipher,
            Nonce = nonce,
            Tag = tag,
            PlainHash = plainHash
        });
    }

    /// <summary>
    /// 读取单个分块文件并还原为加密分片记录。
    /// </summary>
    private static EncryptedShard ReadChunkFile(string path)
    {
        using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        using var br = new BinaryReader(fs, Encoding.UTF8, leaveOpen: true);

        var magic = br.ReadBytes(ChunkMagic.Length);
        if (magic.Length != ChunkMagic.Length || !magic.SequenceEqual(ChunkMagic))
            throw new InvalidDataException($"无效的 {ChunkExtension} 文件（魔数不匹配），可能已损坏：{path}");

        var version = br.ReadInt32();
        var index = br.ReadInt32();

        return LgBackupFormat.ReadShardRecord(br, index);
    }

    /// <summary>
    /// 删除会话的所有分块文件。
    /// </summary>
    private static void DeleteChunkFiles(ResumableSession session)
    {
        for (int i = 0; i < session.TotalChunks; i++)
        {
            TryDeleteFile(GetChunkPath(session.DestDir, session.SessionId, i));
        }
    }

    private static void TryDeleteFile(string path)
    {
        try { if (File.Exists(path)) File.Delete(path); }
        catch (Exception ex) { ErrorReporter.Log($"删除文件失败 {path}：{ex.Message}", "WARN"); }
    }

    #endregion

    #region 会话持久化与路径

    /// <summary>
    /// 序列化会话状态为 .lgsession（JSON）。
    /// </summary>
    private static void SaveSession(ResumableSession session, string sessionFile)
    {
        var dir = Path.GetDirectoryName(sessionFile);
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);

        var json = JsonSerializer.Serialize(session, SessionJsonOptions);
        File.WriteAllText(sessionFile, json, Encoding.UTF8);
    }

    /// <summary>
    /// 从 .lgsession（JSON）反序列化会话状态。
    /// </summary>
    private static ResumableSession LoadSession(string sessionFile)
    {
        if (!File.Exists(sessionFile))
            throw new FileNotFoundException("会话状态文件不存在。", sessionFile);

        var json = File.ReadAllText(sessionFile, Encoding.UTF8);
        return JsonSerializer.Deserialize<ResumableSession>(json, SessionJsonOptions)
            ?? throw new InvalidDataException($"会话状态文件解析失败：{sessionFile}");
    }

    /// <summary>
    /// 生成分块文件路径：chunk_{sessionId}_{index:D6}.lgchunk。
    /// </summary>
    private static string GetChunkPath(string destDir, string sessionId, int index)
        => Path.Combine(destDir, $"chunk_{sessionId}_{index:D6}{ChunkExtension}");

    /// <summary>
    /// 生成会话状态文件路径：session_{sessionId}.lgsession。
    /// </summary>
    private static string GetSessionFilePath(string destDir, string sessionId)
        => Path.Combine(destDir, $"session_{sessionId}{SessionExtension}");

    #endregion
}
