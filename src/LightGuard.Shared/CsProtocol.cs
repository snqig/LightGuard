// © 2026 落尘（Luochen） 原创开发 - 保留所有权利
//
// LightGuard C/S 自定义二进制协议（v3.6 Client-Server 备份）
//   - 报文头定长二进制（20 字节：Magic + Version + Cmd + Flags + Seq + PayloadLen + CRC）
//   - 负载 = [int32 jsonLen][JSON 消息体][可选原始二进制段（块密文 / 上传流分片）]
//   - 客户端与服务端共用本库，保证报文编解码一致

using System.Text;
using System.Text.Json;

namespace LightGuard.Shared;

/// <summary>协议魔数 "LGBS" = 0x4C474253。</summary>
public static class CsProtocol
{
    /// <summary>协议魔数（4 字节）。</summary>
    public const uint Magic = 0x4C474253;

    /// <summary>协议版本。</summary>
    public const ushort Version = 1;

    /// <summary>报文头定长（字节）。</summary>
    public const int HeaderSize = 20;

    /// <summary>默认 TCP 端口（可配置覆盖）。</summary>
    public const int DefaultPort = 17621;

    /// <summary>默认块大小（256KB，与块级增量引擎一致）。</summary>
    public const int DefaultBlockSize = 256 * 1024;

    /// <summary>最大消息体长度（512MB，防恶意超大包）。</summary>
    public const int MaxPayloadSize = 512 * 1024 * 1024;

    /// <summary>最大单次网络读写分片（1MB，流式分片上传/下载）。</summary>
    public const int NetworkChunkSize = 1024 * 1024;
}

/// <summary>协议命令码。</summary>
public enum CsCommand : byte
{
    /// <summary>心跳保活。</summary>
    Heartbeat = 0x00,

    /// <summary>握手：客户端 → 服务端（版本 + 客户端标识）。</summary>
    Hello = 0x01,

    /// <summary>认证挑战：服务端 → 客户端（随机 challenge + salt）。</summary>
    AuthChallenge = 0x02,

    /// <summary>认证应答：客户端 → 服务端（HMAC(passwordHash, challenge)）。</summary>
    AuthResponse = 0x03,

    /// <summary>认证结果：服务端 → 客户端。</summary>
    AuthResult = 0x04,

    /// <summary>块存在性查询：客户端发送 hash 列表 → 服务端返回缺失列表。</summary>
    BlockExistQuery = 0x10,

    /// <summary>块存在性结果：服务端 → 客户端（缺失 hash 列表）。</summary>
    BlockExistResult = 0x11,

    /// <summary>上传加密块（分片，带 offset 断点续传）。</summary>
    UploadBlock = 0x20,

    /// <summary>上传块确认（服务端 → 客户端）。</summary>
    UploadBlockAck = 0x21,

    /// <summary>创建快照（快照元数据 + 块引用列表）。</summary>
    SnapshotCreate = 0x30,

    /// <summary>快照创建结果（服务端 → 客户端，含快照 ID）。</summary>
    SnapshotCreateResult = 0x31,

    /// <summary>列出快照（客户端 → 服务端）。</summary>
    SnapshotList = 0x32,

    /// <summary>快照列表（服务端 → 客户端）。</summary>
    SnapshotListResult = 0x33,

    /// <summary>获取快照元数据（恢复：客户端 → 服务端）。</summary>
    SnapshotGet = 0x34,

    /// <summary>快照元数据（服务端 → 客户端）。</summary>
    SnapshotGetResult = 0x35,

    /// <summary>下载加密块（恢复：客户端请求 hash → 服务端返回密文）。</summary>
    DownloadBlock = 0x40,

    /// <summary>下载块数据（服务端 → 客户端，原始段为密文）。</summary>
    DownloadBlockData = 0x41,

    /// <summary>删除快照。</summary>
    SnapshotDelete = 0x50,

    /// <summary>删除结果。</summary>
    SnapshotDeleteResult = 0x51,

    /// <summary>快照回收清理（按保留策略）。</summary>
    SnapshotCleanup = 0x52,

    /// <summary>清理结果。</summary>
    SnapshotCleanupResult = 0x53,

    /// <summary>错误响应。</summary>
    Error = 0x7F
}

/// <summary>报文标志位。</summary>
[Flags]
public enum CsFlags : byte
{
    /// <summary>无标志。</summary>
    None = 0x00,

    /// <summary>负载携带原始二进制段（块密文 / 流分片）。</summary>
    HasRawData = 0x01,

    /// <summary>分片续传（Offset &gt; 0）。</summary>
    Resume = 0x02
}

/// <summary>
/// 定长报文头（20 字节）。
/// <para>布局：Magic(4) + Version(2) + Cmd(1) + Flags(1) + Seq(4) + PayloadLen(4) + Crc(4)，大端序。</para>
/// </summary>
public struct CsHeader
{
    /// <summary>魔数。</summary>
    public uint Magic;

    /// <summary>协议版本。</summary>
    public ushort Version;

    /// <summary>命令码。</summary>
    public CsCommand Cmd;

    /// <summary>标志位。</summary>
    public CsFlags Flags;

    /// <summary>请求序号（应答回填）。</summary>
    public uint Seq;

    /// <summary>负载总长度（JSON 段 + 原始段）。</summary>
    public int PayloadLen;

    /// <summary>校验和（头 16 字节 + 负载的 CRC32）。</summary>
    public uint Crc;

    /// <summary>序列化为 20 字节大端字节数组。</summary>
    public byte[] Serialize()
    {
        var buf = new byte[CsProtocol.HeaderSize];
        WriteU32(buf, 0, Magic);
        WriteU16(buf, 4, Version);
        buf[6] = (byte)Cmd;
        buf[7] = (byte)Flags;
        WriteU32(buf, 8, Seq);
        WriteI32(buf, 12, PayloadLen);
        // CRC 在 16..19，由 BuildHeader 填充
        return buf;
    }

    /// <summary>从 20 字节解析。</summary>
    public static CsHeader Deserialize(byte[] buf, int offset = 0)
    {
        return new CsHeader
        {
            Magic = ReadU32(buf, offset),
            Version = ReadU16(buf, offset + 4),
            Cmd = (CsCommand)buf[offset + 6],
            Flags = (CsFlags)buf[offset + 7],
            Seq = ReadU32(buf, offset + 8),
            PayloadLen = ReadI32(buf, offset + 12),
            Crc = ReadU32(buf, offset + 16)
        };
    }

    /// <summary>构建完整报文头并计算 CRC（头 16 字节 + 负载）。</summary>
    public static CsHeader Build(CsCommand cmd, CsFlags flags, uint seq, byte[] payload)
    {
        var h = new CsHeader
        {
            Magic = CsProtocol.Magic,
            Version = CsProtocol.Version,
            Cmd = cmd,
            Flags = flags,
            Seq = seq,
            PayloadLen = payload?.Length ?? 0
        };
        var head = h.Serialize();
        h.Crc = ComputeCrc(head, 0, 16, payload);
        return h;
    }

    /// <summary>校验头 CRC（头 16 字节 + 负载）。</summary>
    public bool VerifyCrc(byte[] payload)
    {
        var head = Serialize();
        var expected = ComputeCrc(head, 0, 16, payload);
        return expected == Crc;
    }

    // ==================== 字节序工具（大端） ====================

    public static void WriteU32(byte[] buf, int off, uint v)
    {
        buf[off] = (byte)(v >> 24);
        buf[off + 1] = (byte)(v >> 16);
        buf[off + 2] = (byte)(v >> 8);
        buf[off + 3] = (byte)v;
    }

    public static void WriteI32(byte[] buf, int off, int v) => WriteU32(buf, off, unchecked((uint)v));

    public static void WriteU16(byte[] buf, int off, ushort v)
    {
        buf[off] = (byte)(v >> 8);
        buf[off + 1] = (byte)v;
    }

    public static uint ReadU32(byte[] buf, int off)
        => ((uint)buf[off] << 24) | ((uint)buf[off + 1] << 16) | ((uint)buf[off + 2] << 8) | buf[off + 3];

    public static int ReadI32(byte[] buf, int off) => unchecked((int)ReadU32(buf, off));

    public static ushort ReadU16(byte[] buf, int off) => (ushort)((buf[off] << 8) | buf[off + 1]);

    /// <summary>CRC32（多项式 0xEDB88320，与 zip 一致）。</summary>
    public static uint ComputeCrc(byte[] data, int offset, int count, byte[]? tail)
    {
        uint crc = 0xFFFFFFFF;
        for (int i = offset; i < offset + count; i++)
            crc = (crc >> 8) ^ CrcTable[(crc ^ data[i]) & 0xFF];
        if (tail != null)
        {
            foreach (var b in tail)
                crc = (crc >> 8) ^ CrcTable[(crc ^ b) & 0xFF];
        }
        return crc ^ 0xFFFFFFFF;
    }

    private static readonly uint[] CrcTable = BuildCrcTable();

    private static uint[] BuildCrcTable()
    {
        var table = new uint[256];
        for (uint i = 0; i < 256; i++)
        {
            var c = i;
            for (int k = 0; k < 8; k++)
                c = (c & 1) != 0 ? 0xEDB88320 ^ (c >> 1) : c >> 1;
            table[i] = c;
        }
        return table;
    }
}

/// <summary>
/// 协议消息负载：JSON 消息体 + 可选原始二进制段。
/// </summary>
public sealed class CsPayload
{
    /// <summary>JSON 消息体（对象或 null）。</summary>
    public object? Json;

    /// <summary>原始二进制段（块密文 / 流分片数据）。</summary>
    public byte[]? Raw;

    /// <summary>编码为完整负载字节：[int32 jsonLen][json utf8][raw]。</summary>
    public byte[] Encode()
    {
        var jsonBytes = Json == null ? Array.Empty<byte>() : JsonSerializer.SerializeToUtf8Bytes(Json, JsonOptions);
        var rawLen = Raw?.Length ?? 0;
        var buf = new byte[4 + jsonBytes.Length + rawLen];
        buf[0] = (byte)(jsonBytes.Length >> 24);
        buf[1] = (byte)(jsonBytes.Length >> 16);
        buf[2] = (byte)(jsonBytes.Length >> 8);
        buf[3] = (byte)jsonBytes.Length;
        if (jsonBytes.Length > 0) Buffer.BlockCopy(jsonBytes, 0, buf, 4, jsonBytes.Length);
        if (rawLen > 0) Buffer.BlockCopy(Raw!, 0, buf, 4 + jsonBytes.Length, rawLen);
        return buf;
    }

    /// <summary>从完整负载字节解码。</summary>
    public static CsPayload Decode(byte[] buf)
    {
        if (buf.Length < 4) return new CsPayload();
        var jsonLen = (buf[0] << 24) | (buf[1] << 16) | (buf[2] << 8) | buf[3];
        if (jsonLen < 0 || jsonLen > buf.Length - 4) jsonLen = 0;
        var json = jsonLen > 0 ? JsonSerializer.Deserialize<JsonElement>(buf.AsSpan(4, jsonLen)) : default;
        var raw = buf.Length > 4 + jsonLen ? buf[(4 + jsonLen)..] : null;
        return new CsPayload { Json = json.ValueKind == JsonValueKind.Undefined ? null : json, Raw = raw };
    }

    private static readonly JsonSerializerOptions JsonOptions = new() { DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull };
}

/// <summary>通用响应体。</summary>
public sealed class CsResult
{
    /// <summary>是否成功。</summary>
    public bool Ok { get; set; }

    /// <summary>消息。</summary>
    public string? Message { get; set; }

    /// <summary>错误码（可选）。</summary>
    public int ErrorCode { get; set; }
}

/// <summary>错误响应体。</summary>
public sealed class CsError
{
    /// <summary>错误码。</summary>
    public int Code { get; set; }

    /// <summary>错误消息。</summary>
    public string? Message { get; set; }
}

/// <summary>握手请求体。</summary>
public sealed class CsHello
{
    /// <summary>客户端标识（机器名 + 实例名）。</summary>
    public string? ClientId { get; set; }

    /// <summary>客户端协议版本。</summary>
    public ushort Version { get; set; }

    /// <summary>客户端密码哈希（SHA256(密码)，配合 challenge 做 HMAC 认证）。</summary>
    public string? PasswordHash { get; set; }
}

/// <summary>认证挑战体（服务端 → 客户端）。</summary>
public sealed class CsAuthChallenge
{
    /// <summary>随机 challenge（Base64，16 字节）。</summary>
    public string? Challenge { get; set; }

    /// <summary>服务端会话盐（Base64）。</summary>
    public string? Salt { get; set; }
}

/// <summary>认证应答体（客户端 → 服务端）。</summary>
public sealed class CsAuthResponse
{
    /// <summary>HMAC-SHA256(passwordHash, challenge) 的 Base64。</summary>
    public string? Hmac { get; set; }
}

/// <summary>认证结果体。</summary>
public sealed class CsAuthResult
{
    /// <summary>是否认证通过。</summary>
    public bool Ok { get; set; }

    /// <summary>消息。</summary>
    public string? Message { get; set; }
}

/// <summary>块存在性查询（客户端 → 服务端）：发送本地块 hash 摘要列表。</summary>
public sealed class CsBlockExistQuery
{
    /// <summary>块 SHA256 hash 列表（hex 小写）。</summary>
    public List<string>? Hashes { get; set; }
}

/// <summary>块存在性结果（服务端 → 客户端）：返回缺失列表。</summary>
public sealed class CsBlockExistResult
{
    /// <summary>服务端缺失的块 hash 列表。</summary>
    public List<string>? Missing { get; set; }
}

/// <summary>上传块请求体（客户端 → 服务端），原始段为密文分片。</summary>
public sealed class CsUploadBlock
{
    /// <summary>块 SHA256 hash（hex）。</summary>
    public string? Hash { get; set; }

    /// <summary>块明文长度。</summary>
    public int PlainLength { get; set; }

    /// <summary>分片偏移（断点续传：上次已接收字节）。</summary>
    public int Offset { get; set; }

    /// <summary>本分片密文长度（原始段长度）。</summary>
    public int RawLength { get; set; }

    /// <summary>是否最后一片。</summary>
    public bool IsFinal { get; set; }

    /// <summary>分片序号（从 0 开始）。</summary>
    public int ChunkIndex { get; set; }
}

/// <summary>上传块确认（服务端 → 客户端）。</summary>
public sealed class CsUploadBlockAck
{
    /// <summary>是否成功。</summary>
    public bool Ok { get; set; }

    /// <summary>当前已接收字节数（续传游标）。</summary>
    public long ReceivedBytes { get; set; }

    /// <summary>消息。</summary>
    public string? Message { get; set; }
}

/// <summary>快照条目（一个文件或一个数据库分片流）。</summary>
public sealed class CsSnapshotEntry
{
    /// <summary>相对路径 / 逻辑名。</summary>
    public string? Path { get; set; }

    /// <summary>条目大小（明文字节）。</summary>
    public long Size { get; set; }

    /// <summary>修改时间（Unix 秒）。</summary>
    public long ModifiedUtc { get; set; }

    /// <summary>组成该条目的块 hash 序列（顺序）。</summary>
    public List<string>? BlockHashes { get; set; }

    /// <summary>是否数据库备份流。</summary>
    public bool IsDbStream { get; set; }

    /// <summary>数据库类型（DbStream 时有效）。</summary>
    public string? DbType { get; set; }

    /// <summary>数据库实例名（DbStream 时有效）。</summary>
    public string? DbName { get; set; }
}

/// <summary>创建快照请求（客户端 → 服务端）。</summary>
public sealed class CsSnapshotCreate
{
    /// <summary>快照名称（自动生成如 File_20260808_120000）。</summary>
    public string? Name { get; set; }

    /// <summary>源路径描述。</summary>
    public string? SourcePath { get; set; }

    /// <summary>条目列表。</summary>
    public List<CsSnapshotEntry>? Entries { get; set; }

    /// <summary>全部块 hash 去重列表（供服务端校验引用完整性）。</summary>
    public List<string>? AllBlockHashes { get; set; }

    /// <summary>加密算法（客户端完成，服务端仅存储）。</summary>
    public string? Cipher { get; set; }

    /// <summary>创建时间（Unix 秒）。</summary>
    public long CreatedUtc { get; set; }
}

/// <summary>快照创建结果。</summary>
public sealed class CsSnapshotCreateResult
{
    /// <summary>是否成功。</summary>
    public bool Ok { get; set; }

    /// <summary>快照 ID。</summary>
    public string? SnapshotId { get; set; }

    /// <summary>消息。</summary>
    public string? Message { get; set; }
}

/// <summary>快照元数据（服务端存储 / 下发）。</summary>
public sealed class CsSnapshotMeta
{
    /// <summary>快照 ID。</summary>
    public string? SnapshotId { get; set; }

    /// <summary>名称。</summary>
    public string? Name { get; set; }

    /// <summary>客户端标识。</summary>
    public string? ClientId { get; set; }

    /// <summary>源路径描述。</summary>
    public string? SourcePath { get; set; }

    /// <summary>创建时间（Unix 秒）。</summary>
    public long CreatedUtc { get; set; }

    /// <summary>条目列表。</summary>
    public List<CsSnapshotEntry>? Entries { get; set; }

    /// <summary>全部块 hash。</summary>
    public List<string>? AllBlockHashes { get; set; }

    /// <summary>加密算法（客户端负责解密）。</summary>
    public string? Cipher { get; set; }

    /// <summary>总字节数。</summary>
    public long TotalBytes { get; set; }
}

/// <summary>快照列表请求体（可带客户端过滤）。</summary>
public sealed class CsSnapshotListQuery
{
    /// <summary>按客户端过滤（可选）。</summary>
    public string? ClientId { get; set; }
}

/// <summary>快照列表结果。</summary>
public sealed class CsSnapshotListResult
{
    /// <summary>快照元数据列表（不含块明细，仅概要）。</summary>
    public List<CsSnapshotSummary>? Snapshots { get; set; }
}

/// <summary>快照概要。</summary>
public sealed class CsSnapshotSummary
{
    /// <summary>快照 ID。</summary>
    public string? SnapshotId { get; set; }

    /// <summary>名称。</summary>
    public string? Name { get; set; }

    /// <summary>客户端标识。</summary>
    public string? ClientId { get; set; }

    /// <summary>创建时间（Unix 秒）。</summary>
    public long CreatedUtc { get; set; }

    /// <summary>条目数。</summary>
    public int EntryCount { get; set; }

    /// <summary>总字节数。</summary>
    public long TotalBytes { get; set; }

    /// <summary>源路径。</summary>
    public string? SourcePath { get; set; }
}

/// <summary>获取快照请求体。</summary>
public sealed class CsSnapshotGetQuery
{
    /// <summary>快照 ID。</summary>
    public string? SnapshotId { get; set; }
}

/// <summary>下载块请求体（恢复：客户端请求指定 hash 的密文）。</summary>
public sealed class CsDownloadBlock
{
    /// <summary>块 hash。</summary>
    public string? Hash { get; set; }

    /// <summary>分片偏移（大块分片下载）。</summary>
    public int Offset { get; set; }

    /// <summary>分片长度（0 = 全部剩余）。</summary>
    public int Length { get; set; }
}

/// <summary>下载块数据头（服务端 → 客户端，原始段为密文分片）。</summary>
public sealed class CsDownloadBlockData
{
    /// <summary>块 hash。</summary>
    public string? Hash { get; set; }

    /// <summary>本分片在块密文中的偏移。</summary>
    public int Offset { get; set; }

    /// <summary>本分片长度。</summary>
    public int Length { get; set; }

    /// <summary>块密文总长度。</summary>
    public int TotalCipherLength { get; set; }

    /// <summary>块明文长度。</summary>
    public int PlainLength { get; set; }

    /// <summary>是否最后一片。</summary>
    public bool IsFinal { get; set; }
}

/// <summary>删除快照请求体。</summary>
public sealed class CsSnapshotDeleteQuery
{
    /// <summary>快照 ID。</summary>
    public string? SnapshotId { get; set; }
}

/// <summary>快照回收请求体（按保留策略）。</summary>
public sealed class CsSnapshotCleanupQuery
{
    /// <summary>每客户端最大保留快照数（负数 = 不清理）。</summary>
    public int MaxSnapshotsPerClient { get; set; } = 20;

    /// <summary>客户端 ID 过滤（可选）。</summary>
    public string? ClientId { get; set; }
}

/// <summary>清理结果。</summary>
public sealed class CsSnapshotCleanupResult
{
    /// <summary>是否成功。</summary>
    public bool Ok { get; set; }

    /// <summary>删除的快照数。</summary>
    public int RemovedCount { get; set; }

    /// <summary>释放的块数（引用计数归零）。</summary>
    public int FreedBlocks { get; set; }

    /// <summary>消息。</summary>
    public string? Message { get; set; }
}
