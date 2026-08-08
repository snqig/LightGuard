// © 2026 落尘（Luochen） 原创开发 - 保留所有权利
//
// C/S 网络传输与认证辅助（客户端/服务端共用）
//   - 报文的流式读写（定长头 + 负载）
//   - 认证：服务端生成随机 challenge，客户端用 HMAC-SHA256(passwordHash, challenge) 应答
//   - 密码明文/哈希永不过网，防重放

using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace LightGuard.Shared;

/// <summary>认证与传输辅助。</summary>
public static class CsTransport
{
    /// <summary>challenge 长度（字节）。</summary>
    public const int ChallengeSize = 16;

    // ==================== 报文读写 ====================

    /// <summary>从流读取完整报文（定长头 + 负载），返回 (头, 负载)。</summary>
    public static async Task<(CsHeader Header, byte[] Payload)> ReadMessageAsync(NetworkStream stream, CancellationToken ct)
    {
        var headBuf = new byte[CsProtocol.HeaderSize];
        await ReadExactlyAsync(stream, headBuf, CsProtocol.HeaderSize, ct).ConfigureAwait(false);

        var header = CsHeader.Deserialize(headBuf);
        if (header.Magic != CsProtocol.Magic)
            throw new InvalidDataException($"协议魔数不匹配：0x{header.Magic:X8}");

        if (header.PayloadLen < 0 || header.PayloadLen > CsProtocol.MaxPayloadSize)
            throw new InvalidDataException($"负载长度非法：{header.PayloadLen}");

        var payload = new byte[header.PayloadLen];
        if (header.PayloadLen > 0)
            await ReadExactlyAsync(stream, payload, header.PayloadLen, ct).ConfigureAwait(false);

        if (!header.VerifyCrc(payload))
            throw new InvalidDataException($"报文 CRC 校验失败（cmd=0x{(byte)header.Cmd:X2}）");

        return (header, payload);
    }

    /// <summary>从流读取精确字节数。</summary>
    private static async Task ReadExactlyAsync(NetworkStream stream, byte[] buffer, int count, CancellationToken ct)
    {
        var read = 0;
        while (read < count)
        {
            ct.ThrowIfCancellationRequested();
            var n = await stream.ReadAsync(buffer.AsMemory(read, count - read), ct).ConfigureAwait(false);
            if (n <= 0)
                throw new IOException($"连接已关闭：期望 {count} 字节，仅读到 {read}（实际 {read}）");
            read += n;
        }
    }

    /// <summary>向流写入完整报文。</summary>
    public static async Task WriteMessageAsync(NetworkStream stream, CsHeader header, byte[] payload, CancellationToken ct)
    {
        var headBuf = header.Serialize();
        // CRC 写入头 16..19
        var crc = CsHeader.ComputeCrc(headBuf, 0, 16, payload);
        CsHeader.WriteU32(headBuf, 16, crc);

        await stream.WriteAsync(headBuf, ct).ConfigureAwait(false);
        if (payload.Length > 0)
            await stream.WriteAsync(payload, ct).ConfigureAwait(false);
        await stream.FlushAsync(ct).ConfigureAwait(false);
    }

    /// <summary>便捷：构建并发送 JSON+Raw 报文。</summary>
    public static async Task SendAsync(NetworkStream stream, CsCommand cmd, uint seq, object? json, byte[]? raw, CancellationToken ct)
    {
        var payload = new CsPayload { Json = json, Raw = raw }.Encode();
        var flags = raw is { Length: > 0 } ? CsFlags.HasRawData : CsFlags.None;
        var header = CsHeader.Build(cmd, flags, seq, payload);
        await WriteMessageAsync(stream, header, payload, ct).ConfigureAwait(false);
    }

    /// <summary>便捷：读取并解码 JSON+Raw 报文。</summary>
    public static async Task<(CsHeader Header, CsPayload Payload)> ReceiveAsync(NetworkStream stream, CancellationToken ct)
    {
        var (header, payloadBytes) = await ReadMessageAsync(stream, ct).ConfigureAwait(false);
        var payload = CsPayload.Decode(payloadBytes);
        return (header, payload);
    }

    /// <summary>将 JSON 负载对象解码为强类型。</summary>
    public static T? DecodeJson<T>(CsPayload payload)
        where T : class
    {
        if (payload.Json == null) return null;
        if (payload.Json is JsonElement el)
            return System.Text.Json.JsonSerializer.Deserialize<T>(el.GetRawText());
        return payload.Json as T;
    }

    // ==================== 认证 ====================

    /// <summary>生成随机 challenge（Base64）。</summary>
    public static string NewChallenge() => Convert.ToBase64String(RandomNumberGenerator.GetBytes(ChallengeSize));

    /// <summary>计算密码的 SHA256 哈希（hex 小写；服务端保存此哈希，客户端用其做 HMAC）。</summary>
    public static string HashPassword(string password)
        => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(password))).ToLowerInvariant();

    /// <summary>HMAC-SHA256(passwordHash, challenge) 的 Base64（认证应答）。</summary>
    public static string ComputeAuthHmac(string passwordHash, string challengeBase64)
    {
        var key = Convert.FromHexString(passwordHash);
        var challenge = Convert.FromBase64String(challengeBase64);
        var mac = new HMACSHA256(key);
        return Convert.ToBase64String(mac.ComputeHash(challenge));
    }

    /// <summary>常量时间比较（防时序攻击）。</summary>
    public static bool ConstantTimeEquals(string? a, string? b)
    {
        if (a == null || b == null) return false;
        var ba = Encoding.UTF8.GetBytes(a);
        var bb = Encoding.UTF8.GetBytes(b);
        if (ba.Length != bb.Length) return false;
        int diff = 0;
        for (int i = 0; i < ba.Length; i++) diff |= ba[i] ^ bb[i];
        return diff == 0;
    }
}
