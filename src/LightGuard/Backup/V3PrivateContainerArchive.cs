// © 2026 落尘（Luochen） 原创开发 - 保留所有权利

using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using LightGuard.Core;
using SevenZip;
using LzmaEncoder = SevenZip.Compression.LZMA.Encoder;
using LzmaDecoder = SevenZip.Compression.LZMA.Decoder;

namespace LightGuard.Backup;

/// <summary>
/// v3 私有备份容器（V3PrivateContainerArchive）。
/// <para>双层架构：外层私有容器（自定义魔数 + AEAD 加密外壳），内层 7-Zip LZMA 压缩内核。</para>
/// <para>布局：</para>
/// <para>[魔数 6B "LGBK3\x01"][版本 4B][盐长度 4B][盐 16B][算法长度 4B][算法][头部负载长度 4B][nonce 12][tag 16][加密头][条目数据区...]</para>
/// <para>条目数据区（每项）：[压缩负载长度 Int64][nonce 12][tag 16][密文]</para>
/// <para>压缩负载 = [LZMA 属性 5B][LZMA 压缩流]；头部 JSON 含条目表（相对数据区偏移 + 解压后 SHA256）。</para>
/// <para>特性：纯用户态、无原生依赖、单文件发布兼容；第三方压缩软件无法识别；</para>
/// <para>旧格式 v1 通过只读适配器暴露同一 <see cref="IBackupArchive"/> 接口。</para>
/// </summary>
public sealed class V3PrivateContainerArchive : IBackupArchive
{
    /// <summary>v3 私有容器魔数："LGBK3" + 0x01。</summary>
    internal static readonly byte[] Magic = { 0x4C, 0x47, 0x42, 0x4B, 0x33, 0x01 };

    internal const int FormatVersion = 3;
    internal const int SaltSize = 16;
    internal const int NonceSize = 12;
    internal const int TagSize = 16;
    internal const int LzmaPropsSize = 5;

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = false,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        PropertyNameCaseInsensitive = true
    };

    private readonly string _filePath;
    private readonly byte[] _salt;
    private readonly string _algorithm;
    private readonly byte[] _key;
    private readonly BackupCryptoEngine _crypto;
    private long _bodyStart;
    private List<V3HeaderEntry> _entries;
    private string _sourcePath;
    private string _codec;
    private int _level;
    private int _dictMb;
    private string _mode;
    private string _globalHash;
    private Dictionary<string, string>? _metadata;

    private FileStream? _readStream;
    private bool _disposed;

    private V3PrivateContainerArchive(
        string filePath, byte[] salt, string algorithm, byte[] key,
        string sourcePath, string codec, int level, int dictMb, string mode, string globalHash,
        List<V3HeaderEntry> entries, long bodyStart, Dictionary<string, string>? metadata = null)
    {
        _filePath = filePath;
        _salt = salt;
        _algorithm = algorithm;
        _key = key;
        _crypto = new BackupCryptoEngine(algorithm);
        _sourcePath = sourcePath;
        _codec = codec;
        _level = level;
        _dictMb = dictMb;
        _mode = mode;
        _globalHash = globalHash;
        _entries = entries;
        _bodyStart = bodyStart;
        _metadata = metadata;
    }

    // ==================== IBackupArchive 元数据 ====================

    /// <inheritdoc/>
    public BackupArchiveFormat Format => BackupArchiveFormat.V3PrivateContainer;

    /// <inheritdoc/>
    public string SourcePath => _sourcePath;

    /// <summary>容器级元数据（增量游标 / 策略标记等；头部加密存储）。</summary>
    public IReadOnlyDictionary<string, string>? Metadata => _metadata;

    /// <inheritdoc/>
    public long TotalSize => _entries.Sum(e => e.Len);

    /// <inheritdoc/>
    public int EntryCount => _entries.Count;

    // ==================== 写入（备份） ====================

    /// <inheritdoc/>
    public Task<BackupArchiveWriteResult> WriteAsync(
        IEnumerable<(string RelPath, Stream Data, DateTime ModifiedTime)> entries,
        BackupArchiveOptions options,
        IProgress<BackupProgressInfo>? progress = null,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(entries);
        ArgumentNullException.ThrowIfNull(options);
        return Task.Run(() => WriteCoreAsync(entries, options, progress, ct), ct);
    }

    /// <inheritdoc/>
    public Task<BackupArchiveWriteResult> AppendAsync(
        IEnumerable<(string RelPath, Stream Data, DateTime ModifiedTime)> entries,
        BackupArchiveOptions options,
        IProgress<BackupProgressInfo>? progress = null,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(entries);
        return Task.Run(() => AppendCoreAsync(entries, options, progress, ct), ct);
    }

    // ==================== 读取（浏览 / 还原） ====================

    /// <inheritdoc/>
    public Task<IReadOnlyList<BackupArchiveEntryInfo>> ListEntriesAsync(CancellationToken ct = default)
    {
        var list = _entries.Select(e => new BackupArchiveEntryInfo
        {
            RelPath = e.Rel,
            Name = Path.GetFileName(e.Rel.Replace('/', Path.DirectorySeparatorChar)),
            Length = e.Len,
            ModifiedTime = e.Time,
            Hash = e.Hash,
            ArchiveOffset = _bodyStart + e.Off,
            ChunkIndex = e.Chunk,
            Chunks = e.Chunks is { Count: > 0 }
                ? e.Chunks.Select(c => new BackupChunkRef
                {
                    Hash = c.Hash,
                    Length = c.Len,
                    ArchiveOffset = _bodyStart + c.Off
                }).ToList()
                : new List<BackupChunkRef>
                {
                    new() { Hash = e.Hash, Length = e.Len, ArchiveOffset = _bodyStart + e.Off }
                }
        }).ToList();
        return Task.FromResult<IReadOnlyList<BackupArchiveEntryInfo>>(list);
    }

    /// <inheritdoc/>
    public Task<Stream> OpenEntryAsync(string relPath, CancellationToken ct = default)
    {
        var entry = _entries.FirstOrDefault(e =>
            string.Equals(e.Rel, relPath.Replace('\\', '/'), StringComparison.OrdinalIgnoreCase));
        if (entry == null)
            throw new FileNotFoundException($"归档中不存在条目：{relPath}");
        return Task.FromResult<Stream>(new MemoryStream(ReadEntryBytes(entry, ct)));
    }

    // ==================== 校验（健康检查） ====================

    /// <inheritdoc/>
    public Task<BackupArchiveVerifyResult> VerifyAsync(CancellationToken ct = default)
    {
        return Task.Run(() => VerifyCore(ct), ct);
    }

    // ==================== 核心实现 ====================

    private async Task<BackupArchiveWriteResult> WriteCoreAsync(
        IEnumerable<(string RelPath, Stream Data, DateTime ModifiedTime)> entries,
        BackupArchiveOptions options, IProgress<BackupProgressInfo>? progress, CancellationToken ct)
    {
        // 1. 物化条目（内存缓冲，与现有备份管线一致；超大文件后续走分块流式）
        var items = new List<(string Rel, byte[] Data, DateTime Time)>();
        long total = 0;
        foreach (var (rel, data, time) in entries)
        {
            ct.ThrowIfCancellationRequested();
            using var ms = new MemoryStream();
            await data.CopyToAsync(ms, ct).ConfigureAwait(false);
            var bytes = ms.ToArray();
            total += bytes.Length;
            items.Add((rel.Replace('\\', '/'), bytes, time));
        }

        // 2. 压缩 + 加密写临时数据区
        var dir = Path.GetDirectoryName(_filePath) ?? ".";
        Directory.CreateDirectory(dir);
        var tempBody = Path.Combine(dir, $".lg3_body_{Guid.NewGuid():N}.tmp");
        try
        {
            var newEntries = new List<V3HeaderEntry>(items.Count);
            using var sha = SHA256.Create();
            long processed = 0;

            // 数据区写入独立作用域：结束后立即关闭临时文件句柄，供后续只读拷贝
            {
                using var bodyFs = new FileStream(tempBody, FileMode.Create, FileAccess.Write, FileShare.Read);
                using var bw = new BinaryWriter(bodyFs, Encoding.UTF8, leaveOpen: true);

                for (int i = 0; i < items.Count; i++)
                {
                    ct.ThrowIfCancellationRequested();
                    var (rel, data, time) = items[i];
                    sha.TransformBlock(data, 0, data.Length, null, 0);

                    V3HeaderEntry entry;
                    if (options.CompressionMode == BackupArchiveCompressionMode.Chunked)
                    {
                        // 分块模式：每块独立 LZMA 流（块级增量 / 去重基础）
                        var chunks = new List<V3ChunkRef>();
                        long chunkSize = Math.Max(1, options.ChunkSize);
                        for (long pos = 0; pos < data.Length; pos += chunkSize)
                        {
                            var len = (int)Math.Min(chunkSize, data.Length - pos);
                            var chunk = data.AsSpan((int)pos, len).ToArray();
                            var (cipher, nonce, tag, compLen) = CompressAndEncrypt(chunk, options);
                            bw.Write((long)compLen);
                            bw.Write(nonce);
                            bw.Write(tag);
                            bw.Write(cipher);
                            chunks.Add(new V3ChunkRef
                            {
                                Off = bodyFs.Position - (8 + NonceSize + TagSize + cipher.Length),
                                CLen = compLen,
                                Len = len,
                                Hash = Convert.ToHexString(SHA256.HashData(chunk))
                            });
                        }
                        entry = new V3HeaderEntry
                        {
                            Rel = rel,
                            Len = data.Length,
                            Time = time,
                            Hash = Convert.ToHexString(SHA256.HashData(data)),
                            Chunk = 0,
                            Chunks = chunks
                        };
                    }
                    else if (options.CompressionMode == BackupArchiveCompressionMode.Solid)
                    {
                        throw new NotSupportedException("固实（Solid）模式暂未实现，请使用 PerFile 或 Chunked。");
                    }
                    else
                    {
                        // 非固实（默认）：单条记录
                        var (cipher, nonce, tag, compLen) = CompressAndEncrypt(data, options);
                        bw.Write((long)compLen);
                        bw.Write(nonce);
                        bw.Write(tag);
                        bw.Write(cipher);
                        entry = new V3HeaderEntry
                        {
                            Rel = rel,
                            Len = data.Length,
                            Time = time,
                            Hash = Convert.ToHexString(SHA256.HashData(data)),
                            Off = bodyFs.Position - (8 + NonceSize + TagSize + cipher.Length),
                            CLen = compLen,
                            Chunk = -1
                        };
                    }
                    newEntries.Add(entry);

                    processed += data.Length;
                    progress?.Report(new BackupProgressInfo
                    {
                        Percent = total > 0 ? processed * 100.0 / total : 100,
                        ProcessedFiles = i + 1,
                        TotalFiles = items.Count,
                        ProcessedBytes = processed,
                        TotalBytes = total,
                        CurrentFile = rel,
                        Phase = BackupPhase.Backup
                    });
                }
            }
            sha.TransformFinalBlock(Array.Empty<byte>(), 0, 0);

            // 3. 组装头部（条目表 + 全局哈希 + 压缩参数）
            var globalHash = Convert.ToHexString(sha.Hash ?? Array.Empty<byte>());
            var headerJson = BuildHeaderJson(newEntries, options, globalHash);
            var (hCipher, hNonce, hTag) = _crypto.Encrypt(headerJson, _key);

            // 4. 写最终文件：前缀 + 加密头 + 数据区
            var prefixSize = 6 + 4 + 4 + SaltSize + 4 + Encoding.UTF8.GetByteCount(_algorithm) + 4;
            var bodyStart = prefixSize + headerJson.Length + NonceSize + TagSize;
            using (var fs = new FileStream(_filePath, FileMode.Create, FileAccess.Write, FileShare.None))
            using (var fbw = new BinaryWriter(fs, Encoding.UTF8, leaveOpen: true))
            {
                WritePrefix(fbw, headerJson.Length);
                fbw.Write(hNonce);
                fbw.Write(hTag);
                fbw.Write(hCipher);
                using var bodyIn = File.OpenRead(tempBody);
                bodyIn.CopyTo(fs);
            }

            // 5. 同步实例状态（同一实例可直接 List / Open / Verify / 再次追加）
            _entries = newEntries;
            _bodyStart = bodyStart;
            _globalHash = globalHash;
            _codec = "LZMA1";
            _level = options.CompressionLevel;
            _dictMb = options.DictionarySizeMb;
            _mode = options.CompressionMode.ToString();
            _readStream?.Dispose();
            _readStream = null;

            return new BackupArchiveWriteResult
            {
                Format = BackupArchiveFormat.V3PrivateContainer,
                TotalBytes = total,
                CompressedBytes = bodyStart + new FileInfo(tempBody).Length,
                EntryCount = newEntries.Count,
                Elapsed = TimeSpan.Zero
            };
        }
        finally
        {
            try { if (File.Exists(tempBody)) File.Delete(tempBody); } catch { }
        }
    }

    private async Task<BackupArchiveWriteResult> AppendCoreAsync(
        IEnumerable<(string RelPath, Stream Data, DateTime ModifiedTime)> entries,
        BackupArchiveOptions options, IProgress<BackupProgressInfo>? progress, CancellationToken ct)
    {
        // 追加 = 全量重建：读取旧条目数据 + 新条目合并（同名新覆盖旧），再整包重写。
        // 当前管线每次备份生成独立文件、不频繁追加，重建成本可接受；块级增量阶段引入专用追加结构。
        var merged = new List<(string Rel, byte[] Data, DateTime Time)>();
        foreach (var e in _entries)
        {
            ct.ThrowIfCancellationRequested();
            merged.Add((e.Rel, ReadEntryBytes(e, ct), e.Time));
        }
        foreach (var (rel, data, time) in entries)
        {
            ct.ThrowIfCancellationRequested();
            using var ms = new MemoryStream();
            await data.CopyToAsync(ms, ct).ConfigureAwait(false);
            merged.Add((rel.Replace('\\', '/'), ms.ToArray(), time));
        }

        // 同名去重：新条目覆盖旧条目（取最后一个）
        var dedup = merged
            .GroupBy(x => x.Rel, StringComparer.OrdinalIgnoreCase)
            .Select(g => g.Last())
            .ToList();

        // 释放对原文件的读句柄，避免 FileMode.Create 写新文件时共享冲突
        _readStream?.Dispose();
        _readStream = null;

        return await WriteCoreAsync(dedup.Select(x => (x.Rel, (Stream)new MemoryStream(x.Data), x.Time)), options, progress, ct)
            .ConfigureAwait(false);
    }

    private BackupArchiveVerifyResult VerifyCore(CancellationToken ct)
    {
        var result = new BackupArchiveVerifyResult
        {
            EntryCount = _entries.Count,
            VerifiedBytes = 0
        };

        foreach (var e in _entries)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                var plain = ReadEntryBytes(e, ct);
                if (!string.Equals(Convert.ToHexString(SHA256.HashData(plain)), e.Hash, StringComparison.OrdinalIgnoreCase))
                {
                    result.Failures.Add($"{e.Rel}：SHA256 校验失败，数据损坏");
                }
                else
                {
                    result.VerifiedBytes += plain.Length;
                }
            }
            catch (AuthenticationTagMismatchException ex)
            {
                result.Failures.Add($"{e.Rel}：解密认证失败（{ex.Message}）");
            }
            catch (Exception ex)
            {
                result.Failures.Add($"{e.Rel}：{ex.Message}");
            }
        }

        result.Success = result.Failures.Count == 0;
        result.Message = result.Success
            ? $"校验通过：{_entries.Count} 个条目，{result.VerifiedBytes} 字节"
            : $"校验失败：{result.Failures.Count} 个条目异常";
        return result;
    }

    // ==================== 条目读写 ====================

    /// <summary>压缩（LZMA1）+ 加密单个条目数据。</summary>
    private (byte[] Cipher, byte[] Nonce, byte[] Tag, int CompLen) CompressAndEncrypt(byte[] data, BackupArchiveOptions options)
    {
        using var inMs = new MemoryStream(data);
        using var propsMs = new MemoryStream();
        using var outMs = new MemoryStream();

        var encoder = new LzmaEncoder();
        int dict = Math.Clamp(options.DictionarySizeMb, 1, 1024) * 1024 * 1024;
        int level = Math.Clamp(options.CompressionLevel, 0, 9);
        encoder.SetCoderProperties(
            new[] { CoderPropID.DictionarySize, CoderPropID.NumFastBytes, CoderPropID.Algorithm },
            new object[] { dict, 64 + level * 8, level >= 7 ? 1 : 0 });
        encoder.WriteCoderProperties(propsMs);
        encoder.Code(inMs, outMs, data.Length, -1, null);

        using var payload = new MemoryStream();
        payload.Write(propsMs.ToArray());
        outMs.Position = 0;
        outMs.CopyTo(payload);
        var comp = payload.ToArray();

        var (cipher, nonce, tag) = _crypto.Encrypt(comp, _key);
        return (cipher, nonce, tag, comp.Length);
    }

    /// <summary>按条目读取记录：定位 → 解密 → LZMA 解压，返回原始字节（Chunked 模式按块顺序拼接）。</summary>
    private byte[] ReadEntryBytes(V3HeaderEntry entry, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var stream = GetReadStream();
        lock (stream)
        {
            if (entry.Chunks is { Count: > 0 })
            {
                using var outMs = new MemoryStream();
                foreach (var chunk in entry.Chunks)
                {
                    ct.ThrowIfCancellationRequested();
                    var data = ReadChunkRecord(stream, _bodyStart + chunk.Off, chunk.CLen, chunk.Len);
                    outMs.Write(data, 0, data.Length);
                }
                return outMs.ToArray();
            }
            return ReadChunkRecord(stream, _bodyStart + entry.Off, entry.CLen, entry.Len);
        }
    }

    /// <summary>读取单条压缩记录（按绝对偏移）：[CLen][nonce][tag][密文] → 解密 → LZMA 解压。</summary>
    private byte[] ReadChunkRecord(Stream stream, long absOff, long expectedLen, long outLen)
    {
        stream.Position = absOff;
        using var br = new BinaryReader(stream, Encoding.UTF8, leaveOpen: true);
        var storedLen = br.ReadInt64();
        if (storedLen != expectedLen || expectedLen <= 0 || expectedLen > int.MaxValue)
            throw new InvalidDataException($"压缩负载长度异常（期望 {expectedLen}，实际 {storedLen}），容器可能已损坏。");
        var nonce = br.ReadBytes(NonceSize);
        var tag = br.ReadBytes(TagSize);
        var cipher = br.ReadBytes((int)expectedLen);

        var plain = _crypto.Decrypt(cipher, _key, nonce, tag);
        return LzmaDecompress(plain, outLen);
    }

    private static byte[] LzmaDecompress(byte[] propsAndData, long outLen)
    {
        if (propsAndData.Length < LzmaPropsSize)
            throw new InvalidDataException("压缩负载缺少 LZMA 属性头。");
        var props = propsAndData.AsSpan(0, LzmaPropsSize).ToArray();
        using var inMs = new MemoryStream(propsAndData, LzmaPropsSize, propsAndData.Length - LzmaPropsSize);
        using var outMs = new MemoryStream();
        var decoder = new LzmaDecoder();
        decoder.SetDecoderProperties(props);
        decoder.Code(inMs, outMs, inMs.Length, outLen, null);
        return outMs.ToArray();
    }

    // ==================== 头部序列化 ====================

    private byte[] BuildHeaderJson(List<V3HeaderEntry> entries, BackupArchiveOptions options, string globalHash)
    {
        var header = new V3Header
        {
            SourcePath = _sourcePath,
            Algorithm = _algorithm,
            Codec = "LZMA1",
            Level = options.CompressionLevel,
            DictMb = options.DictionarySizeMb,
            Mode = options.CompressionMode.ToString(),
            EncryptFileNames = options.EncryptFileNames,
            GlobalHash = globalHash,
            Metadata = _metadata,
            Entries = entries
        };
        return JsonSerializer.SerializeToUtf8Bytes(header, JsonOptions);
    }

    private void WritePrefix(BinaryWriter bw, int headerPayloadLength)
    {
        bw.Write(Magic);
        bw.Write(FormatVersion);
        bw.Write(SaltSize);
        bw.Write(_salt);
        var algo = Encoding.UTF8.GetBytes(_algorithm);
        bw.Write(algo.Length);
        bw.Write(algo);
        bw.Write(headerPayloadLength);
    }

    private FileStream GetReadStream()
    {
        if (_readStream == null || !_readStream.CanRead)
        {
            _readStream?.Dispose();
            _readStream = new FileStream(_filePath, FileMode.Open, FileAccess.Read, FileShare.Read);
        }
        return _readStream;
    }

    // ==================== 工厂（Create / Open） ====================

    /// <summary>
    /// 创建新 v3 容器（新写备份）。生成随机盐并派生密钥。
    /// </summary>
    internal static V3PrivateContainerArchive Create(string filePath, string password, BackupArchiveOptions options,
        Dictionary<string, string>? metadata = null)
    {
        ValidatePassword(password);
        ArgumentNullException.ThrowIfNull(options);

        var salt = RandomNumberGenerator.GetBytes(SaltSize);
        var algorithm = "AES-256-GCM";
        var crypto = new BackupCryptoEngine(algorithm);
        var key = crypto.DeriveKey(password, salt);

        return new V3PrivateContainerArchive(
            filePath, salt, algorithm, key,
            sourcePath: options.SourcePath ?? "", codec: "LZMA1",
            level: options.CompressionLevel, dictMb: options.DictionarySizeMb,
            mode: options.CompressionMode.ToString(), globalHash: "",
            entries: new List<V3HeaderEntry>(), bodyStart: 0, metadata: metadata);
    }

    /// <summary>
    /// 打开既有 v3 容器（浏览 / 校验 / 还原）。密钥错误抛 <see cref="AuthenticationTagMismatchException"/>。
    /// </summary>
    internal static V3PrivateContainerArchive Open(string filePath, string password)
    {
        ValidatePassword(password);
        if (!File.Exists(filePath))
            throw new FileNotFoundException("备份容器不存在。", filePath);

        using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read);
        using var br = new BinaryReader(fs, Encoding.UTF8, leaveOpen: true);

        var magic = br.ReadBytes(Magic.Length);
        if (magic.Length != Magic.Length || !magic.SequenceEqual(Magic))
            throw new InvalidDataException("无效的 v3 备份容器（魔数不匹配）。");

        var version = br.ReadInt32();
        if (version != FormatVersion)
            throw new NotSupportedException($"不支持的容器版本：v{version}（当前支持 v{FormatVersion}）。");

        var saltLen = br.ReadInt32();
        var salt = br.ReadBytes(saltLen);
        var algoLen = br.ReadInt32();
        var algorithm = Encoding.UTF8.GetString(br.ReadBytes(algoLen));
        var headerPayloadLen = br.ReadInt32();
        if (headerPayloadLen <= 0 || headerPayloadLen > 512 * 1024 * 1024)
            throw new InvalidDataException("头部负载长度异常，容器可能已损坏。");

        var nonce = br.ReadBytes(NonceSize);
        var tag = br.ReadBytes(TagSize);
        var cipher = br.ReadBytes(headerPayloadLen);

        var bodyStart = fs.Position;

        var crypto = new BackupCryptoEngine(algorithm);
        var key = crypto.DeriveKey(password, salt);
        var headerJson = crypto.Decrypt(cipher, key, nonce, tag);
        var header = JsonSerializer.Deserialize<V3Header>(headerJson, JsonOptions)
                     ?? throw new InvalidDataException("容器头部解析失败。");

        return new V3PrivateContainerArchive(
            filePath, salt, algorithm, key,
            header.SourcePath, header.Codec, header.Level, header.DictMb,
            header.Mode, header.GlobalHash,
            header.Entries, bodyStart, header.Metadata);
    }

    private static void ValidatePassword(string password)
    {
        if (string.IsNullOrEmpty(password))
            throw new ArgumentException("备份口令不能为空。", nameof(password));
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _readStream?.Dispose();
        _readStream = null;
        GC.SuppressFinalize(this);
    }
}

// ==================== 头部 JSON 模型 ====================

/// <summary>v3 容器头部（加密存储，含条目表）。</summary>
internal sealed class V3Header
{
    public string SourcePath { get; set; } = "";
    public string Algorithm { get; set; } = "AES-256-GCM";
    public string Codec { get; set; } = "LZMA1";
    public int Level { get; set; } = 6;
    public int DictMb { get; set; } = 64;
    public string Mode { get; set; } = "PerFile";
    public bool EncryptFileNames { get; set; } = true;
    public string GlobalHash { get; set; } = "";
    public List<V3HeaderEntry> Entries { get; set; } = new();

    /// <summary>容器级元数据（增量游标 / 策略标记等；旧包缺失为 null）。</summary>
    public Dictionary<string, string>? Metadata { get; set; }
}

/// <summary>v3 容器条目元信息。</summary>
internal sealed class V3HeaderEntry
{
    /// <summary>相对路径（'/' 分隔）。头部整体加密，路径不落明文。</summary>
    public string Rel { get; set; } = "";

    /// <summary>解压后大小（字节）。</summary>
    public long Len { get; set; }

    /// <summary>修改时间。</summary>
    public DateTime Time { get; set; }

    /// <summary>解压后 SHA256（十六进制）。</summary>
    public string Hash { get; set; } = "";

    /// <summary>压缩负载在数据区中的相对偏移（绝对偏移 = bodyStart + Off；PerFile 模式）。</summary>
    public long Off { get; set; }

    /// <summary>压缩负载长度（含 LZMA 属性头，密文等长；PerFile 模式）。</summary>
    public long CLen { get; set; }

    /// <summary>压缩块索引（Chunked 模式预留；PerFile 为 -1）。</summary>
    public int Chunk { get; set; } = -1;

    /// <summary>块记录列表（Chunked 模式；PerFile 为 null，回退用 Off/CLen 单记录）。</summary>
    public List<V3ChunkRef>? Chunks { get; set; }
}

/// <summary>v3 容器单块引用（Chunked 模式；块级增量 / 去重基础）。</summary>
internal sealed class V3ChunkRef
{
    /// <summary>块压缩负载在数据区中的相对偏移。</summary>
    public long Off { get; set; }

    /// <summary>块压缩负载长度（含 LZMA 属性头，密文等长）。</summary>
    public long CLen { get; set; }

    /// <summary>块解压后长度。</summary>
    public long Len { get; set; }

    /// <summary>块解压后 SHA256（块级去重索引基础）。</summary>
    public string Hash { get; set; } = "";
}
