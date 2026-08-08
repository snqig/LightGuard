// © 2026 落尘（Luochen） 原创开发 - 保留所有权利

using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using LightGuard.Core;

namespace LightGuard.Backup;

/// <summary>
/// 旧版 v1（AES 分片格式）只读兼容适配器。
/// <para>通过 <see cref="IBackupArchive"/> 暴露旧备份包，满足全局规范 1（统一存储抽象层）：
/// 仅支持 List / Open / Verify；Write / Append 抛 <see cref="NotSupportedException"/>（旧格式仅只读）。</para>
/// <para>内部复用 v1 读取管线：读包 → PBKDF2 派生密钥 → 逐分片解密 + 分片级 SHA256 → 整包 SHA256 → 解析归档条目。</para>
/// </summary>
public sealed class V1LegacyArchiveAdapter : IBackupArchive
{
    /// <summary>v1 归档条目引用（解密后的归档字节内偏移）。</summary>
    private sealed class EntryRef
    {
        public required string Rel { get; init; }
        public required long Offset { get; init; }
        public required long Length { get; init; }
    }

    private readonly BackupManifest _manifest;
    private readonly byte[] _archiveBytes;
    private readonly List<EntryRef> _entries;
    private readonly Dictionary<string, string> _fileHashes; // rel → SHA256 hex（清单元数据，可能为空）

    private V1LegacyArchiveAdapter(BackupManifest manifest, byte[] archiveBytes, List<EntryRef> entries, Dictionary<string, string> fileHashes)
    {
        _manifest = manifest;
        _archiveBytes = archiveBytes;
        _entries = entries;
        _fileHashes = fileHashes;
    }

    /// <summary>
    /// 打开旧版 v1 备份包（只读）。密钥错误抛 <see cref="AuthenticationTagMismatchException"/>。
    /// </summary>
    internal static V1LegacyArchiveAdapter Open(string backupPath, string password)
    {
        if (string.IsNullOrEmpty(password))
            throw new ArgumentException("备份口令不能为空。", nameof(password));
        if (!File.Exists(backupPath))
            throw new FileNotFoundException("备份包不存在。", backupPath);

        var (manifest, shards) = LgBackupFormat.ReadBackup(backupPath);

        // 派生密钥 + 逐分片解密（GCM 认证失败抛 AuthenticationTagMismatchException）
        var salt = Convert.FromBase64String(manifest.Salt);
        var crypto = new BackupCryptoEngine(manifest.EncryptedAlgorithm);
        var key = crypto.DeriveKey(password, salt);

        using var sha = SHA256.Create();
        using var ms = new MemoryStream();
        foreach (var s in shards.OrderBy(x => x.Index))
        {
            var plain = crypto.Decrypt(s.Cipher, key, s.Nonce, s.Tag);
            if (!ConstantTimeEquals(SHA256.HashData(plain), s.PlainHash))
                throw new InvalidDataException($"分片 {s.Index} 哈希校验失败，数据可能已损坏。");
            sha.TransformBlock(plain, 0, plain.Length, null, 0);
            ms.Write(plain, 0, plain.Length);
        }
        sha.TransformFinalBlock(Array.Empty<byte>(), 0, 0);

        // 整包 SHA256 完整性校验
        var globalHash = Convert.ToHexString(sha.Hash ?? Array.Empty<byte>());
        if (!string.Equals(globalHash, manifest.GlobalHash, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("整包 SHA256 完整性校验失败，备份数据已被篡改或损坏。");

        var archiveBytes = ms.ToArray();
        var entries = ParseEntries(archiveBytes);
        var fileHashes = ParseFileHashes(manifest);

        return new V1LegacyArchiveAdapter(manifest, archiveBytes, entries, fileHashes);
    }

    /// <inheritdoc/>
    public BackupArchiveFormat Format => BackupArchiveFormat.V1LegacySharded;

    /// <inheritdoc/>
    public string SourcePath => _manifest.SourcePath;

    /// <inheritdoc/>
    public long TotalSize => _entries.Sum(e => e.Length);

    /// <inheritdoc/>
    public int EntryCount => _entries.Count;

    /// <inheritdoc/>
    public Task<BackupArchiveWriteResult> WriteAsync(
        IEnumerable<(string RelPath, Stream Data, DateTime ModifiedTime)> entries,
        BackupArchiveOptions options,
        IProgress<BackupProgressInfo>? progress = null,
        CancellationToken ct = default)
        => throw new NotSupportedException("旧版 v1 格式仅只读兼容，不允许写入。");

    /// <inheritdoc/>
    public Task<BackupArchiveWriteResult> AppendAsync(
        IEnumerable<(string RelPath, Stream Data, DateTime ModifiedTime)> entries,
        BackupArchiveOptions options,
        IProgress<BackupProgressInfo>? progress = null,
        CancellationToken ct = default)
        => throw new NotSupportedException("旧版 v1 格式仅只读兼容，不允许追加。");

    /// <inheritdoc/>
    public Task<IReadOnlyList<BackupArchiveEntryInfo>> ListEntriesAsync(CancellationToken ct = default)
    {
        var list = _entries.Select(e => new BackupArchiveEntryInfo
        {
            RelPath = e.Rel,
            Name = Path.GetFileName(e.Rel.Replace('/', Path.DirectorySeparatorChar)),
            Length = e.Length,
            ModifiedTime = _manifest.BackupTime,
            Hash = _fileHashes.TryGetValue(e.Rel, out var h) ? h : "",
            ArchiveOffset = e.Offset,
            ChunkIndex = -1
        }).ToList();
        return Task.FromResult<IReadOnlyList<BackupArchiveEntryInfo>>(list);
    }

    /// <inheritdoc/>
    public Task<Stream> OpenEntryAsync(string relPath, CancellationToken ct = default)
    {
        ct.ThrowIfCancellationRequested();
        var entry = _entries.FirstOrDefault(e =>
            string.Equals(e.Rel, relPath.Replace('\\', '/'), StringComparison.OrdinalIgnoreCase));
        if (entry == null)
            throw new FileNotFoundException($"归档中不存在条目：{relPath}");

        var data = new byte[entry.Length];
        Array.Copy(_archiveBytes, entry.Offset, data, 0, entry.Length);
        return Task.FromResult<Stream>(new MemoryStream(data));
    }

    /// <inheritdoc/>
    public Task<BackupArchiveVerifyResult> VerifyAsync(CancellationToken ct = default)
    {
        return Task.Run(() =>
        {
            var result = new BackupArchiveVerifyResult { EntryCount = _entries.Count };

            // 整包级校验（解密与全局哈希在 Open 时已验；此处复核全局哈希）
            var actual = Convert.ToHexString(SHA256.HashData(_archiveBytes));
            if (!string.Equals(actual, _manifest.GlobalHash, StringComparison.OrdinalIgnoreCase))
            {
                result.Failures.Add("(整包)：SHA256 全局校验失败，数据被篡改");
            }

            // 条目级校验（清单记录了逐文件哈希时逐项比对）
            foreach (var e in _entries)
            {
                ct.ThrowIfCancellationRequested();
                if (!_fileHashes.TryGetValue(e.Rel, out var expected)) continue;
                var data = new byte[e.Length];
                Array.Copy(_archiveBytes, e.Offset, data, 0, e.Length);
                var actualHash = Convert.ToHexString(SHA256.HashData(data));
                if (!string.Equals(actualHash, expected, StringComparison.OrdinalIgnoreCase))
                    result.Failures.Add($"{e.Rel}：SHA256 校验失败");
                else
                    result.VerifiedBytes += e.Length;
            }

            result.Success = result.Failures.Count == 0;
            result.Message = result.Success
                ? $"校验通过：{_entries.Count} 个条目"
                : $"校验失败：{result.Failures.Count} 项异常";
            return result;
        }, ct);
    }

    /// <summary>解析 v1 归档条目（格式与 BackupExecutor 完全一致）。</summary>
    private static List<EntryRef> ParseEntries(byte[] archive)
    {
        var list = new List<EntryRef>();
        using var ms = new MemoryStream(archive, false);
        using var br = new BinaryReader(ms, Encoding.UTF8, leaveOpen: true);

        var count = br.ReadInt64();
        for (long i = 0; i < count; i++)
        {
            var relLen = br.ReadInt32();
            var rel = Encoding.UTF8.GetString(br.ReadBytes(relLen));
            var dataLen = br.ReadInt64();
            var dataOffset = ms.Position;   // dataLen 字段之后，即数据体起点
            br.ReadBytes((int)dataLen);
            list.Add(new EntryRef { Rel = rel, Offset = dataOffset, Length = dataLen });
        }
        return list;
    }

    private static Dictionary<string, string> ParseFileHashes(BackupManifest manifest)
    {
        if (manifest.Metadata == null ||
            !manifest.Metadata.TryGetValue("FileHashes", out var json) ||
            string.IsNullOrEmpty(json))
        {
            return new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        }
        try
        {
            var dict = JsonSerializer.Deserialize<Dictionary<string, string>>(json);
            return dict != null
                ? new Dictionary<string, string>(dict, StringComparer.OrdinalIgnoreCase)
                : new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        }
        catch
        {
            return new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        }
    }

    private static bool ConstantTimeEquals(byte[] a, byte[] b)
    {
        if (a.Length != b.Length) return false;
        int diff = 0;
        for (int i = 0; i < a.Length; i++) diff |= a[i] ^ b[i];
        return diff == 0;
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        GC.SuppressFinalize(this);
    }
}
