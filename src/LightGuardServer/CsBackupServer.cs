// © 2026 落尘（Luochen） 原创开发 - 保留所有权利
//
// LightGuardServer TCP 服务（CsBackupServer）
//   - 监听自定义端口，每客户端独立会话 Task（并发安全）
//   - 认证：challenge-response（HMAC-SHA256(passwordHash, challenge)），密码永不过网
//   - 命令分发：块存在性查询 / 上传块（分片续传）/ 快照创建 / 列表 / 读取 / 删除 / 回收 / 下载块
//   - 未认证会话只能执行 Hello / Auth 命令

using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using LightGuard.Shared;

namespace LightGuardServer;

/// <summary>
/// C/S 备份 TCP 服务端。
/// </summary>
public sealed class CsBackupServer : IDisposable
{
    private readonly ServerConfig _config;
    private readonly BlockStore _blocks;
    private readonly SnapshotStore _snapshots;
    private TcpListener? _listener;
    private readonly ConcurrentDictionary<long, TcpClient> _clients = new();
    private long _nextClientId;
    private readonly CancellationTokenSource _cts = new();
    private readonly SemaphoreSlim _clientLimit;

    /// <summary>已认证客户端数。</summary>
    public int ClientCount => _clients.Count;

    /// <summary>当前会话是否在运行。</summary>
    public bool IsRunning => _listener != null;

    public CsBackupServer(ServerConfig config, BlockStore blocks, SnapshotStore snapshots)
    {
        _config = config;
        _blocks = blocks;
        _snapshots = snapshots;
        _clientLimit = new SemaphoreSlim(Math.Max(1, config.MaxClients));
    }

    /// <summary>启动监听。</summary>
    public async Task StartAsync()
    {
        var addr = IPAddress.TryParse(_config.BindAddress, out var ip)
            ? ip
            : IPAddress.Any;
        _listener = new TcpListener(addr, _config.Port);
        _listener.Start();
        Console.WriteLine($"[LightGuardServer] 监听 {_config.BindAddress}:{_config.Port}（数据目录 {_config.DataDir}）");
        Console.WriteLine($"[LightGuardServer] 认证已启用：密码哈希 {_config.PasswordHash[..Math.Min(8, _config.PasswordHash.Length)]}...");

        while (!_cts.IsCancellationRequested)
        {
            TcpClient client;
            try
            {
                client = await _listener.AcceptTcpClientAsync(_cts.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) { break; }
            catch (SocketException) { break; }

            // 并发上限控制（超过则直接拒绝）
            if (!await _clientLimit.WaitAsync(0, _cts.Token).ConfigureAwait(false))
            {
                try
                {
                    using var sw = new StreamWriter(client.GetStream()) { AutoFlush = true };
                    await sw.WriteLineAsync("busy").ConfigureAwait(false);
                }
                catch { }
                client.Dispose();
                continue;
            }

            var clientId = Interlocked.Increment(ref _nextClientId);
            _clients[clientId] = client;
            _ = Task.Run(() => HandleClientAsync(clientId, client, _cts.Token));
        }
    }

    /// <summary>处理单个客户端会话。</summary>
    private async Task HandleClientAsync(long clientId, TcpClient client, CancellationToken ct)
    {
        Console.WriteLine($"[会话#{clientId}] 客户端连接 {client.Client.RemoteEndPoint}");
        var session = new ClientSession(_config, _blocks, _snapshots, clientId, Console.WriteLine);
        try
        {
            using var stream = client.GetStream();
            stream.ReadTimeout = Timeout.Infinite;
            await session.RunAsync(stream, ct).ConfigureAwait(false);
        }
        catch (IOException ex)
        {
            Console.WriteLine($"[会话#{clientId}] 连接中断：{ex.Message}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[会话#{clientId}] 会话异常：{ex.Message}");
        }
        finally
        {
            _clients.TryRemove(clientId, out _);
            _clientLimit.Release();
            try { client.Dispose(); } catch { }
            Console.WriteLine($"[会话#{clientId}] 客户端断开");
        }
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        _cts.Cancel();
        _listener?.Stop();
        foreach (var c in _clients.Values) { try { c.Dispose(); } catch { } }
        _clients.Clear();
        _cts.Dispose();
        _clientLimit.Dispose();
    }
}

/// <summary>
/// 单客户端会话：认证 + 命令分发。
/// </summary>
public sealed class ClientSession
{
    private readonly ServerConfig _config;
    private readonly BlockStore _blocks;
    private readonly SnapshotStore _snapshots;
    private readonly long _clientId;
    private readonly Action<string> _log;
    private bool _authenticated;
    private string? _remoteClientId;
    private uint _seq;
    private NetworkStream _stream = null!;

    public ClientSession(ServerConfig config, BlockStore blocks, SnapshotStore snapshots,
        long clientId, Action<string> log)
    {
        _config = config;
        _blocks = blocks;
        _snapshots = snapshots;
        _clientId = clientId;
        _log = log;
    }

    /// <summary>运行会话主循环。</summary>
    public async Task RunAsync(NetworkStream stream, CancellationToken ct)
    {
        _stream = stream;
        while (!ct.IsCancellationRequested)
        {
            var (header, payload) = await CsTransport.ReceiveAsync(stream, ct).ConfigureAwait(false);
            _seq = header.Seq;

            // 未认证：仅允许 Hello / Auth 流程
            if (!_authenticated && header.Cmd is not (CsCommand.Hello or CsCommand.AuthChallenge or CsCommand.AuthResponse or CsCommand.AuthResult))
            {
                await SendErrorAsync("未认证", 401).ConfigureAwait(false);
                continue;
            }

            switch (header.Cmd)
            {
                case CsCommand.Heartbeat:
                    await ReplyAsync(CsCommand.Heartbeat, new CsResult { Ok = true }).ConfigureAwait(false);
                    break;
                case CsCommand.Hello:
                    await HandleHelloAsync(payload).ConfigureAwait(false);
                    break;
                case CsCommand.AuthResponse:
                    await HandleAuthAsync(payload).ConfigureAwait(false);
                    break;
                case CsCommand.BlockExistQuery:
                    await HandleBlockExistAsync(payload).ConfigureAwait(false);
                    break;
                case CsCommand.UploadBlock:
                    await HandleUploadBlockAsync(payload).ConfigureAwait(false);
                    break;
                case CsCommand.SnapshotCreate:
                    await HandleSnapshotCreateAsync(payload).ConfigureAwait(false);
                    break;
                case CsCommand.SnapshotList:
                    await HandleSnapshotListAsync(payload).ConfigureAwait(false);
                    break;
                case CsCommand.SnapshotGet:
                    await HandleSnapshotGetAsync(payload).ConfigureAwait(false);
                    break;
                case CsCommand.DownloadBlock:
                    await HandleDownloadBlockAsync(payload).ConfigureAwait(false);
                    break;
                case CsCommand.SnapshotDelete:
                    await HandleSnapshotDeleteAsync(payload).ConfigureAwait(false);
                    break;
                case CsCommand.SnapshotCleanup:
                    await HandleSnapshotCleanupAsync(payload).ConfigureAwait(false);
                    break;
                default:
                    await SendErrorAsync($"未知命令：0x{(byte)header.Cmd:X2}", 400).ConfigureAwait(false);
                    break;
            }
        }
    }

    // ==================== 认证 ====================

    private async Task HandleHelloAsync(CsPayload payload)
    {
        var hello = CsTransport.DecodeJson<CsHello>(payload);
        _remoteClientId = string.IsNullOrWhiteSpace(hello?.ClientId) ? null : hello.ClientId;
        // 发送认证挑战（仅当配置了密码哈希）
        if (string.IsNullOrEmpty(_config.PasswordHash))
        {
            // 未配置密码：直接放行（仅用于首次部署调试；建议 setup 生成）
            _authenticated = true;
            await ReplyAsync(CsCommand.AuthResult, new CsAuthResult { Ok = true, Message = "未配置密码，直接放行（建议配置）" }).ConfigureAwait(false);
            return;
        }

        var challenge = CsTransport.NewChallenge();
        SessionChallenges[_clientId] = challenge;
        await ReplyAsync(CsCommand.AuthChallenge, new CsAuthChallenge
        {
            Challenge = challenge,
            Salt = ""
        }).ConfigureAwait(false);
        _log($"[会话#{_clientId}] 已发送认证挑战（客户端 {hello?.ClientId}）");
    }

    /// <summary>客户端认证应答：校验 HMAC(passwordHash, challenge)。</summary>
    private async Task HandleAuthAsync(CsPayload payload)
    {
        if (!SessionChallenges.TryGetValue(_clientId, out var challenge))
        {
            await SendErrorAsync("无进行中的认证挑战", 401).ConfigureAwait(false);
            return;
        }
        SessionChallenges.TryRemove(_clientId, out _);

        var resp = CsTransport.DecodeJson<CsAuthResponse>(payload);
        if (resp == null || string.IsNullOrEmpty(resp.Hmac))
        {
            await ReplyAsync(CsCommand.AuthResult, new CsAuthResult { Ok = false, Message = "认证应答为空" }).ConfigureAwait(false);
            return;
        }

        var expected = CsTransport.ComputeAuthHmac(_config.PasswordHash, challenge);
        if (CsTransport.ConstantTimeEquals(expected, resp.Hmac))
        {
            _authenticated = true;
            _log($"[会话#{_clientId}] 认证通过");
            await ReplyAsync(CsCommand.AuthResult, new CsAuthResult { Ok = true, Message = "认证通过" }).ConfigureAwait(false);
        }
        else
        {
            _log($"[会话#{_clientId}] 认证失败（密码不匹配）");
            await ReplyAsync(CsCommand.AuthResult, new CsAuthResult { Ok = false, Message = "认证失败" }).ConfigureAwait(false);
        }
    }

    /// <summary>会话挑战缓存（clientId → challenge）。</summary>
    private static readonly ConcurrentDictionary<long, string> SessionChallenges = new();

    // ==================== 块操作 ====================

    /// <summary>块存在性查询：返回缺失列表（本地索引查询，无远端读取）。</summary>
    private async Task HandleBlockExistAsync(CsPayload payload)
    {
        var query = CsTransport.DecodeJson<CsBlockExistQuery>(payload);
        if (query?.Hashes == null)
        {
            await SendErrorAsync("块查询负载无效", 400).ConfigureAwait(false);
            return;
        }

        var missing = _blocks.FindMissing(query.Hashes);
        await ReplyAsync(CsCommand.BlockExistResult, new CsBlockExistResult { Missing = missing }).ConfigureAwait(false);
    }

    /// <summary>上传加密块（分片断点续传）。</summary>
    private async Task HandleUploadBlockAsync(CsPayload payload)
    {
        var req = CsTransport.DecodeJson<CsUploadBlock>(payload);
        if (req == null || string.IsNullOrEmpty(req.Hash))
        {
            await SendErrorAsync("上传块负载无效", 400).ConfigureAwait(false);
            return;
        }

        // 块已完整存在：幂等确认
        var existingLen = _blocks.GetBlockLength(req.Hash);
        if (existingLen >= 0)
        {
            await ReplyAsync(CsCommand.UploadBlockAck, new CsUploadBlockAck
            {
                Ok = true,
                ReceivedBytes = existingLen,
                Message = "块已存在"
            }).ConfigureAwait(false);
            return;
        }

        var raw = payload.Raw ?? Array.Empty<byte>();
        var received = _blocks.AppendBlock(req.Hash, raw, req.Offset, req.IsFinal);

        await ReplyAsync(CsCommand.UploadBlockAck, new CsUploadBlockAck
        {
            Ok = true,
            ReceivedBytes = received,
            Message = req.IsFinal ? "块上传完成" : "分片已接收"
        }).ConfigureAwait(false);
    }

    /// <summary>下载加密块（恢复：分片下发）。</summary>
    private async Task HandleDownloadBlockAsync(CsPayload payload)
    {
        var req = CsTransport.DecodeJson<CsDownloadBlock>(payload);
        if (req == null || string.IsNullOrEmpty(req.Hash))
        {
            await SendErrorAsync("下载块负载无效", 400).ConfigureAwait(false);
            return;
        }

        var totalLen = _blocks.GetBlockLength(req.Hash);
        if (totalLen < 0)
        {
            await SendErrorAsync($"块不存在：{req.Hash}", 404).ConfigureAwait(false);
            return;
        }

        var len = req.Length <= 0 ? (int)totalLen : Math.Min(req.Length, (int)totalLen);
        var data = _blocks.ReadBlock(req.Hash, req.Offset, len);
        var isFinal = req.Offset + data.Length >= totalLen;

        await SendRawAsync(CsCommand.DownloadBlockData, new CsDownloadBlockData
        {
            Hash = req.Hash,
            Offset = req.Offset,
            Length = data.Length,
            TotalCipherLength = (int)totalLen,
            PlainLength = 0, // 明文长度由快照条目携带（服务端不解析密文）
            IsFinal = isFinal
        }, data).ConfigureAwait(false);
    }

    // ==================== 快照操作 ====================

    private async Task HandleSnapshotCreateAsync(CsPayload payload)
    {
        var req = CsTransport.DecodeJson<CsSnapshotCreate>(payload);
        if (req == null || req.Entries == null)
        {
            await SendErrorAsync("快照创建负载无效", 400).ConfigureAwait(false);
            return;
        }

        var meta = new CsSnapshotMeta
        {
            SnapshotId = $"snap_{DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()}_{Guid.NewGuid().ToString("N")[..8]}",
            Name = req.Name,
            SourcePath = req.SourcePath,
            CreatedUtc = req.CreatedUtc,
            Entries = req.Entries,
            AllBlockHashes = req.AllBlockHashes,
            Cipher = req.Cipher,
            TotalBytes = req.Entries.Sum(e => e.Size)
        };

        // 客户端标识取自握手 Hello（用于按客户端过滤/保留策略）
        meta.ClientId = _remoteClientId ?? "client";

        _snapshots.Create(meta);
        _log($"[会话#{_clientId}] 快照已创建：{meta.SnapshotId}（{meta.Entries.Count} 条目，{meta.TotalBytes} 字节）");
        await ReplyAsync(CsCommand.SnapshotCreateResult, new CsSnapshotCreateResult
        {
            Ok = true,
            SnapshotId = meta.SnapshotId,
            Message = $"快照创建成功：{meta.SnapshotId}"
        }).ConfigureAwait(false);
    }

    private async Task HandleSnapshotListAsync(CsPayload payload)
    {
        var query = CsTransport.DecodeJson<CsSnapshotListQuery>(payload);
        var list = _snapshots.List(query?.ClientId);
        await ReplyAsync(CsCommand.SnapshotListResult, new CsSnapshotListResult { Snapshots = list }).ConfigureAwait(false);
    }

    private async Task HandleSnapshotGetAsync(CsPayload payload)
    {
        var query = CsTransport.DecodeJson<CsSnapshotGetQuery>(payload);
        if (query == null || string.IsNullOrEmpty(query.SnapshotId))
        {
            await SendErrorAsync("快照 ID 无效", 400).ConfigureAwait(false);
            return;
        }
        var meta = _snapshots.Get(query.SnapshotId);
        if (meta == null)
        {
            await SendErrorAsync($"快照不存在：{query.SnapshotId}", 404).ConfigureAwait(false);
            return;
        }
        await ReplyAsync(CsCommand.SnapshotGetResult, meta).ConfigureAwait(false);
    }

    private async Task HandleSnapshotDeleteAsync(CsPayload payload)
    {
        var query = CsTransport.DecodeJson<CsSnapshotDeleteQuery>(payload);
        if (query == null || string.IsNullOrEmpty(query.SnapshotId))
        {
            await SendErrorAsync("快照 ID 无效", 400).ConfigureAwait(false);
            return;
        }
        var ok = _snapshots.Delete(query.SnapshotId);
        await ReplyAsync(CsCommand.SnapshotDeleteResult, new CsResult { Ok = ok, Message = ok ? "已删除" : "快照不存在" }).ConfigureAwait(false);
    }

    private async Task HandleSnapshotCleanupAsync(CsPayload payload)
    {
        var query = CsTransport.DecodeJson<CsSnapshotCleanupQuery>(payload) ?? new CsSnapshotCleanupQuery { MaxSnapshotsPerClient = _config.MaxSnapshotsPerClient };
        var (removed, freed) = _snapshots.Cleanup(query.MaxSnapshotsPerClient, query.ClientId);
        await ReplyAsync(CsCommand.SnapshotCleanupResult, new CsSnapshotCleanupResult
        {
            Ok = true,
            RemovedCount = removed,
            FreedBlocks = freed,
            Message = $"清理完成：删除 {removed} 个快照"
        }).ConfigureAwait(false);
    }

    // ==================== 应答辅助 ====================

    private async Task ReplyAsync(CsCommand cmd, object? json) =>
        await CsTransport.SendAsync(_stream, cmd, _seq, json, null, CancellationToken.None).ConfigureAwait(false);

    private async Task SendRawAsync(CsCommand cmd, object? json, byte[] raw) =>
        await CsTransport.SendAsync(_stream, cmd, _seq, json, raw, CancellationToken.None).ConfigureAwait(false);

    private async Task SendErrorAsync(string message, int code) =>
        await ReplyAsync(CsCommand.Error, new CsError { Code = code, Message = message }).ConfigureAwait(false);
}
