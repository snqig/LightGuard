// © 2026 落尘（Luochen） 原创开发 - 保留所有权利
//
// 客户端 C/S 备份配置（v3.6 Client-Server）
//   - 工作模式：local / client_server / smb
//   - client_server：填写服务端 IP、端口、认证密码引用
//   - 原有本地/SMB 模式完全保留，C/S 为可选新增模式

namespace LightGuard.ClientServer;

/// <summary>备份工作模式。</summary>
public enum BackupWorkMode
{
    /// <summary>本地/SMB 备份（原有模式，backup_set_root 为本地路径或 SMB 挂载路径）。</summary>
    Local,

    /// <summary>Client-Server 自定义 TCP 备份（新增模式）。</summary>
    ClientServer
}

/// <summary>
/// 客户端 C/S 备份配置（存于 AppConfig.ClientServer）。
/// </summary>
public sealed class ClientServerConfig
{
    /// <summary>备份工作模式（local / client_server）。</summary>
    public BackupWorkMode WorkMode { get; set; } = BackupWorkMode.Local;

    /// <summary>服务端 IP / 主机名。</summary>
    public string ServerHost { get; set; } = "";

    /// <summary>服务端端口。</summary>
    public int ServerPort { get; set; } = LightGuard.Shared.CsProtocol.DefaultPort;

    /// <summary>认证密码（本地配置，运行时经 challenge-response 认证，密码永不过网）。</summary>
    public string AuthPassword { get; set; } = "";

    /// <summary>客户端标识（默认机器名）。</summary>
    public string ClientId { get; set; } = "";

    /// <summary>块大小（字节，默认 256KB）。</summary>
    public int BlockSize { get; set; } = LightGuard.Shared.CsProtocol.DefaultBlockSize;

    /// <summary>连接超时（秒）。</summary>
    public int ConnectTimeoutSeconds { get; set; } = 10;

    /// <summary>断线重连次数。</summary>
    public int ReconnectAttempts { get; set; } = 3;

    /// <summary>断线重连间隔（毫秒）。</summary>
    public int ReconnectDelayMs { get; set; } = 2000;

    /// <summary>服务端每客户端最大保留快照数（快照回收策略）。</summary>
    public int MaxSnapshotsPerClient { get; set; } = 20;

    /// <summary>默认备份根（local 模式仍走原 Backup.BackupPath）。</summary>
    public string BackupSetRoot { get; set; } = "";
}
