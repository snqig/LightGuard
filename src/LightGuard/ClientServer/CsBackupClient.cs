// © 2026 落尘（Luochen） 原创开发 - 保留所有权利
//
// 客户端 C/S 备份客户端（CsBackupClient）
//   - 连接 + challenge-response 认证（密码永不过网）
//   - 块存在性查询：只发送本地 hash 摘要列表，服务端返回缺失（不读取远端备份集比对）
//   - 上传缺失加密块（分片断点续传）
//   - 快照创建 / 列表 / 读取 / 删除 / 回收
//   - 下载块（恢复）分片拉取
//   - 断线重连：任一网络操作失败自动重连并重试

using System.Net.Sockets;
using LightGuard.Shared;

namespace LightGuard.ClientServer;

/// <summary>客户端网络会话结果。</summary>
public sealed class CsSessionResult
{
    /// <summary>是否成功。</summary>
    public bool Success { get; set; }

    /// <summary>消息。</summary>
    public string? Message { get; set; }
}

/// <summary>
/// C/S 备份客户端：封装与服务端的全部网络交互。
/// </summary>
public sealed class CsBackupClient : IDisposable
{
    private readonly ClientServerConfig _config;
    private TcpClient? _tcp;
    private NetworkStream? _stream;
    private uint _seq;
    private bool _authenticated;

    /// <summary>当前是否已连接并认证。</summary>
    public bool IsConnected => _tcp?.Connected == true && _authenticated;

    public CsBackupClient(ClientServerConfig config)
    {
        _config = config;
    }

    /// <summary>建立连接并完成认证（断线重连入口）。</summary>
    public async Task<CsSessionResult> ConnectAsync(CancellationToken ct = default)
    {
        var lastError = "";
        for (int attempt = 0; attempt <= Math.Max(0, _config.ReconnectAttempts); attempt++)
        {
            try
            {
                if (attempt > 0)
                    await Task.Delay(_config.ReconnectDelayMs, ct).ConfigureAwait(false);

                await ConnectOnceAsync(ct).ConfigureAwait(false);
                return new CsSessionResult { Success = true };
            }
            catch (Exception ex)
            {
                lastError = ex.Message;
                Disconnect();
                if (attempt >= Math.Max(0, _config.ReconnectAttempts))
                    break;
            }
        }
        return new CsSessionResult { Success = false, Message = $"连接失败（重试 {_config.ReconnectAttempts} 次）：{lastError}" };
    }

    /// <summary>单次连接 + 认证。</summary>
    private async Task ConnectOnceAsync(CancellationToken ct)
    {
        _tcp = new TcpClient();
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(TimeSpan.FromSeconds(Math.Max(1, _config.ConnectTimeoutSeconds)));
        await _tcp.ConnectAsync(_config.ServerHost, _config.ServerPort, cts.Token).ConfigureAwait(false);
        _stream = _tcp.GetStream();

        // 1. Hello（携带客户端标识 + 密码哈希）
        await SendAsync(CsCommand.Hello, new CsHello
        {
            ClientId = string.IsNullOrEmpty(_config.ClientId) ? Environment.MachineName : _config.ClientId,
            Version = CsProtocol.Version,
            PasswordHash = CsTransport.HashPassword(_config.AuthPassword)
        }, null, ct).ConfigureAwait(false);

        // 2. 读取挑战或直接放行
        var (h1, p1) = await CsTransport.ReceiveAsync(_stream, ct).ConfigureAwait(false);
        _seq = h1.Seq;

        if (h1.Cmd == CsCommand.AuthChallenge)
        {
            var challenge = CsTransport.DecodeJson<CsAuthChallenge>(p1);
            if (challenge?.Challenge == null)
                throw new InvalidDataException("认证挑战为空");

            var hmac = CsTransport.ComputeAuthHmac(
                CsTransport.HashPassword(_config.AuthPassword), challenge.Challenge);
            await SendAsync(CsCommand.AuthResponse, new CsAuthResponse { Hmac = hmac }, null, ct).ConfigureAwait(false);

            var (h2, p2) = await CsTransport.ReceiveAsync(_stream, ct).ConfigureAwait(false);
            var result = CsTransport.DecodeJson<CsAuthResult>(p2);
            if (h2.Cmd == CsCommand.Error || result == null || !result.Ok)
                throw new UnauthorizedAccessException($"认证失败：{result?.Message ?? "未知"}");
        }
        else if (h1.Cmd == CsCommand.AuthResult)
        {
            var result = CsTransport.DecodeJson<CsAuthResult>(p1);
            if (result == null || !result.Ok)
                throw new UnauthorizedAccessException($"认证失败：{result?.Message ?? "未知"}");
        }
        else
        {
            throw new InvalidDataException($"握手响应异常：0x{(byte)h1.Cmd:X2}");
        }

        _authenticated = true;
    }

    /// <summary>断开连接。</summary>
    public void Disconnect()
    {
        _authenticated = false;
        try { _stream?.Dispose(); } catch { }
        try { _tcp?.Dispose(); } catch { }
        _stream = null;
        _tcp = null;
    }

    /// <summary>带断线重连的执行包装：确保已连接后执行操作。</summary>
    private async Task<T> WithSessionAsync<T>(Func<NetworkStream, CancellationToken, Task<T>> action, CancellationToken ct)
    {
        if (!IsConnected)
        {
            var r = await ConnectAsync(ct).ConfigureAwait(false);
            if (!r.Success) throw new IOException(r.Message);
        }

        try
        {
            return await action(_stream!, ct).ConfigureAwait(false);
        }
        catch (IOException)
        {
            // 网络中断：重连一次后重试（断线重连）
            Disconnect();
            var r = await ConnectAsync(ct).ConfigureAwait(false);
            if (!r.Success) throw new IOException(r.Message);
            return await action(_stream!, ct).ConfigureAwait(false);
        }
    }

    // ==================== 块操作 ====================

    /// <summary>
    /// 块存在性查询：发送本地 hash 摘要列表，服务端返回缺失列表。
    /// <para>禁止读取远端备份集比对——只发送摘要，服务端本地索引判定。</para>
    /// </summary>
    public Task<List<string>> FindMissingAsync(IEnumerable<string> hashes, CancellationToken ct = default)
    {
        return WithSessionAsync(async (stream, token) =>
        {
            await SendAsync(CsCommand.BlockExistQuery, new CsBlockExistQuery { Hashes = hashes.ToList() }, null, token).ConfigureAwait(false);
            var (header, payload) = await CsTransport.ReceiveAsync(stream, token).ConfigureAwait(false);
            EnsureOk(header, payload);
            var result = CsTransport.DecodeJson<CsBlockExistResult>(payload);
            return result?.Missing ?? new List<string>();
        }, ct);
    }

    /// <summary>
    /// 上传加密块（分片断点续传）：每次发送一个分片，返回服务端已接收字节数。
    /// </summary>
    public Task<long> UploadBlockChunkAsync(string hash, byte[] chunk, int offset, bool isFinal, int plainLength, int chunkIndex, CancellationToken ct = default)
    {
        return WithSessionAsync(async (stream, token) =>
        {
            await SendAsync(CsCommand.UploadBlock, new CsUploadBlock
            {
                Hash = hash,
                PlainLength = plainLength,
                Offset = offset,
                RawLength = chunk.Length,
                IsFinal = isFinal,
                ChunkIndex = chunkIndex
            }, chunk, token).ConfigureAwait(false);

            var (header, payload) = await CsTransport.ReceiveAsync(stream, token).ConfigureAwait(false);
            EnsureOk(header, payload);
            var ack = CsTransport.DecodeJson<CsUploadBlockAck>(payload);
            if (ack == null || !ack.Ok)
                throw new IOException($"块上传失败：{ack?.Message ?? "未知"}");
            return ack.ReceivedBytes;
        }, ct);
    }

    /// <summary>
    /// 上传完整加密块（内部自动分片，支持断点续传）。
    /// </summary>
    /// <param name="hash">块 hash。</param>
    /// <param name="cipherPackage">完整密文包（nonce+tag+cipher 拼接，由客户端加密生成）。</param>
    /// <param name="plainLength">块明文长度。</param>
    public async Task UploadBlockAsync(string hash, byte[] cipherPackage, int plainLength, CancellationToken ct = default)
    {
        // 先查存在性（幂等：已存在则跳过，避免重复传输）
        var missing = await FindMissingAsync(new[] { hash }, ct).ConfigureAwait(false);
        if (missing.Count == 0) return;

        var chunkSize = CsProtocol.NetworkChunkSize;
        int idx = 0, offset = 0;
        while (offset < cipherPackage.Length)
        {
            var len = Math.Min(chunkSize, cipherPackage.Length - offset);
            var chunk = new byte[len];
            Buffer.BlockCopy(cipherPackage, offset, chunk, 0, len);
            var isFinal = offset + len >= cipherPackage.Length;
            var received = await UploadBlockChunkAsync(hash, chunk, offset, isFinal, plainLength, idx, ct).ConfigureAwait(false);
            // 断点续传：若服务端已接收超过当前偏移，直接跳到该处
            if (received > offset + len)
            {
                offset = (int)Math.Min(received, cipherPackage.Length);
                continue;
            }
            offset += len;
            idx++;
        }
    }

    // ==================== 快照操作 ====================

    /// <summary>创建快照。</summary>
    public Task<CsSnapshotCreateResult> CreateSnapshotAsync(CsSnapshotCreate req, CancellationToken ct = default)
    {
        return WithSessionAsync(async (stream, token) =>
        {
            await SendAsync(CsCommand.SnapshotCreate, req, null, token).ConfigureAwait(false);
            var (header, payload) = await CsTransport.ReceiveAsync(stream, token).ConfigureAwait(false);
            EnsureOk(header, payload);
            return CsTransport.DecodeJson<CsSnapshotCreateResult>(payload)
                   ?? new CsSnapshotCreateResult { Ok = false, Message = "响应为空" };
        }, ct);
    }

    /// <summary>列出快照。</summary>
    public Task<List<CsSnapshotSummary>> ListSnapshotsAsync(string? clientId = null, CancellationToken ct = default)
    {
        return WithSessionAsync(async (stream, token) =>
        {
            await SendAsync(CsCommand.SnapshotList, new CsSnapshotListQuery { ClientId = clientId }, null, token).ConfigureAwait(false);
            var (header, payload) = await CsTransport.ReceiveAsync(stream, token).ConfigureAwait(false);
            EnsureOk(header, payload);
            var result = CsTransport.DecodeJson<CsSnapshotListResult>(payload);
            return result?.Snapshots ?? new List<CsSnapshotSummary>();
        }, ct);
    }

    /// <summary>读取快照元数据（恢复用）。</summary>
    public Task<CsSnapshotMeta?> GetSnapshotAsync(string snapshotId, CancellationToken ct = default)
    {
        return WithSessionAsync(async (stream, token) =>
        {
            await SendAsync(CsCommand.SnapshotGet, new CsSnapshotGetQuery { SnapshotId = snapshotId }, null, token).ConfigureAwait(false);
            var (header, payload) = await CsTransport.ReceiveAsync(stream, token).ConfigureAwait(false);
            if (header.Cmd == CsCommand.Error) return (CsSnapshotMeta?)null;
            return CsTransport.DecodeJson<CsSnapshotMeta>(payload);
        }, ct);
    }

    /// <summary>下载块密文包（恢复：分片拉取）。</summary>
    public async Task<byte[]> DownloadBlockAsync(string hash, int plainLength, CancellationToken ct = default)
    {
        using var ms = new MemoryStream();
        int offset = 0;
        while (true)
        {
            var chunk = await DownloadBlockChunkAsync(hash, offset, CsProtocol.NetworkChunkSize, ct).ConfigureAwait(false);
            if (chunk.Length == 0) break;
            ms.Write(chunk, 0, chunk.Length);
            offset += chunk.Length;
            if (chunk.Length < CsProtocol.NetworkChunkSize) break;
        }
        return ms.ToArray();
    }

    /// <summary>下载块分片。</summary>
    private Task<byte[]> DownloadBlockChunkAsync(string hash, int offset, int length, CancellationToken ct)
    {
        return WithSessionAsync(async (stream, token) =>
        {
            await SendAsync(CsCommand.DownloadBlock, new CsDownloadBlock { Hash = hash, Offset = offset, Length = length }, null, token).ConfigureAwait(false);
            var (header, payload) = await CsTransport.ReceiveAsync(stream, token).ConfigureAwait(false);
            if (header.Cmd == CsCommand.Error) return Array.Empty<byte>();
            return payload.Raw ?? Array.Empty<byte>();
        }, ct);
    }

    /// <summary>删除快照。</summary>
    public Task<CsResult> DeleteSnapshotAsync(string snapshotId, CancellationToken ct = default)
    {
        return WithSessionAsync(async (stream, token) =>
        {
            await SendAsync(CsCommand.SnapshotDelete, new CsSnapshotDeleteQuery { SnapshotId = snapshotId }, null, token).ConfigureAwait(false);
            var (header, payload) = await CsTransport.ReceiveAsync(stream, token).ConfigureAwait(false);
            EnsureOk(header, payload);
            return CsTransport.DecodeJson<CsResult>(payload) ?? new CsResult { Ok = false };
        }, ct);
    }

    /// <summary>快照回收清理。</summary>
    public Task<CsSnapshotCleanupResult> CleanupAsync(int maxPerClient, string? clientId = null, CancellationToken ct = default)
    {
        return WithSessionAsync(async (stream, token) =>
        {
            await SendAsync(CsCommand.SnapshotCleanup, new CsSnapshotCleanupQuery { MaxSnapshotsPerClient = maxPerClient, ClientId = clientId }, null, token).ConfigureAwait(false);
            var (header, payload) = await CsTransport.ReceiveAsync(stream, token).ConfigureAwait(false);
            EnsureOk(header, payload);
            return CsTransport.DecodeJson<CsSnapshotCleanupResult>(payload)
                   ?? new CsSnapshotCleanupResult { Ok = false, Message = "响应为空" };
        }, ct);
    }

    /// <summary>心跳保活。</summary>
    public Task<bool> PingAsync(CancellationToken ct = default)
    {
        return WithSessionAsync(async (stream, token) =>
        {
            await SendAsync(CsCommand.Heartbeat, new CsResult { Ok = true }, null, token).ConfigureAwait(false);
            var (header, payload) = await CsTransport.ReceiveAsync(stream, token).ConfigureAwait(false);
            var r = CsTransport.DecodeJson<CsResult>(payload);
            return header.Cmd != CsCommand.Error && r?.Ok == true;
        }, ct);
    }

    // ==================== 内部辅助 ====================

    private async Task SendAsync(CsCommand cmd, object? json, byte[]? raw, CancellationToken ct)
    {
        _seq++;
        await CsTransport.SendAsync(_stream!, cmd, _seq, json, raw, ct).ConfigureAwait(false);
    }

    private static void EnsureOk(CsHeader header, CsPayload payload)
    {
        if (header.Cmd == CsCommand.Error)
        {
            var err = CsTransport.DecodeJson<CsError>(payload);
            throw new IOException($"服务端错误 [{err?.Code}]：{err?.Message ?? "未知"}");
        }
    }

    /// <inheritdoc/>
    public void Dispose() => Disconnect();
}
