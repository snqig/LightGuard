// © 2026 落尘（Luochen） 原创开发 - 保留所有权利
//
// LightGuardServer 服务端配置
//   - 服务端持有密码的 SHA256 哈希（不存明文）
//   - 客户端认证：HMAC(passwordHash, challenge)，密码永不过网
//   - 数据目录布局：{DataDir}/meta.index、{DataDir}/blocks/{hash}.blk、{DataDir}/snapshots/{id}.json

using System.Text.Json;
using System.Text.Json.Serialization;

namespace LightGuardServer;

/// <summary>
/// 服务端配置（server.json）。
/// </summary>
public sealed class ServerConfig
{
    /// <summary>监听端口。</summary>
    public int Port { get; set; } = LightGuard.Shared.CsProtocol.DefaultPort;

    /// <summary>监听地址（默认 0.0.0.0 全接口）。</summary>
    public string BindAddress { get; set; } = "0.0.0.0";

    /// <summary>认证密码的 SHA256 哈希（hex 小写，由 setup 命令生成）。</summary>
    public string PasswordHash { get; set; } = "";

    /// <summary>数据目录（块 + 快照 + 索引）。</summary>
    public string DataDir { get; set; } = "";

    /// <summary>每客户端最大保留快照数（回收清理默认策略）。</summary>
    public int MaxSnapshotsPerClient { get; set; } = 20;

    /// <summary>并发客户端上限（防资源耗尽）。</summary>
    public int MaxClients { get; set; } = 64;

    /// <summary>配置文件路径。</summary>
    [JsonIgnore]
    public string ConfigPath { get; set; } = "";

    /// <summary>块文件扩展名。</summary>
    public const string BlockExtension = ".blk";

    /// <summary>快照元数据扩展名。</summary>
    public const string SnapshotExtension = ".json";

    /// <summary>默认配置路径。</summary>
    public static string DefaultConfigPath =>
        Path.Combine(AppContext.BaseDirectory, "server.json");

    /// <summary>默认数据目录。</summary>
    public static string DefaultDataDir =>
        Path.Combine(AppContext.BaseDirectory, "data");

    /// <summary>加载配置（不存在返回默认）。</summary>
    public static ServerConfig Load(string? path = null)
    {
        var configPath = string.IsNullOrEmpty(path) ? DefaultConfigPath : path;
        try
        {
            if (File.Exists(configPath))
            {
                var json = File.ReadAllText(configPath);
                var cfg = JsonSerializer.Deserialize<ServerConfig>(json);
                if (cfg != null)
                {
                    cfg.ConfigPath = configPath;
                    if (string.IsNullOrEmpty(cfg.DataDir))
                        cfg.DataDir = Path.Combine(Path.GetDirectoryName(configPath) ?? AppContext.BaseDirectory, "data");
                    return cfg;
                }
            }
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[配置] 加载失败，使用默认配置：{ex.Message}");
        }

        return new ServerConfig
        {
            ConfigPath = configPath,
            DataDir = string.IsNullOrEmpty(Path.GetDirectoryName(configPath))
                ? DefaultDataDir
                : Path.Combine(Path.GetDirectoryName(configPath)!, "data")
        };
    }

    /// <summary>保存配置。</summary>
    public void Save()
    {
        var dir = Path.GetDirectoryName(ConfigPath);
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
        var json = JsonSerializer.Serialize(this, new JsonSerializerOptions { WriteIndented = true });
        File.WriteAllText(ConfigPath, json);
    }

    /// <summary>确保数据目录结构存在。</summary>
    public void EnsureDirectories()
    {
        Directory.CreateDirectory(DataDir);
        Directory.CreateDirectory(Path.Combine(DataDir, "blocks"));
        Directory.CreateDirectory(Path.Combine(DataDir, "snapshots"));
    }

    /// <summary>块文件路径。</summary>
    public string BlockPath(string hash) => Path.Combine(DataDir, "blocks", hash + BlockExtension);

    /// <summary>快照文件路径。</summary>
    public string SnapshotPath(string snapshotId) => Path.Combine(DataDir, "snapshots", snapshotId + SnapshotExtension);

    /// <summary>meta.index 路径。</summary>
    public string MetaIndexPath => Path.Combine(DataDir, "meta.index");
}
