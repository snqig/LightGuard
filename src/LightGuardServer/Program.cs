// © 2026 落尘（Luochen） 原创开发 - 保留所有权利
//
// LightGuardServer 入口
//   - 用法：
//     LightGuardServer setup           生成配置文件（交互设置端口 + 认证密码）
//     LightGuardServer hashset <pass>  打印指定密码的 SHA256 哈希（供手动写入配置）
//     LightGuardServer                 以默认/现有配置启动服务
//   - 数据目录：{exe}/data（块 blocks/、快照 snapshots/、索引 meta.index）

using LightGuardServer;

Console.OutputEncoding = System.Text.Encoding.UTF8;
try
{
    if (args.Length > 0 && args[0].Equals("setup", StringComparison.OrdinalIgnoreCase))
    {
        RunSetup();
        return;
    }

    if (args.Length > 0 && args[0].Equals("hashset", StringComparison.OrdinalIgnoreCase))
    {
        if (args.Length < 2) { Console.Error.WriteLine("用法：LightGuardServer hashset <密码>"); return; }
        Console.WriteLine(LightGuard.Shared.CsTransport.HashPassword(args[1]));
        return;
    }

    var config = ServerConfig.Load();
    if (string.IsNullOrEmpty(config.PasswordHash))
    {
        Console.WriteLine("[警告] 未配置认证密码，建议运行：LightGuardServer setup");
        Console.WriteLine("       无密码时任何客户端均可连接（不推荐生产环境）。");
    }

    config.EnsureDirectories();
    using var blocks = new BlockStore(config);
    using var snapshots = new SnapshotStore(config, blocks);
    using var server = new CsBackupServer(config, blocks, snapshots);

    // 定时落盘索引（避免异常退出丢失引用计数）
    using var flushTimer = new System.Threading.Timer(
        _ => blocks.Flush(), null, TimeSpan.FromMinutes(5), TimeSpan.FromMinutes(5));

    var shutdown = new ManualResetEventSlim(false);
    Console.CancelKeyPress += (_, e) => { e.Cancel = true; Console.WriteLine("[LightGuardServer] 正在退出..."); shutdown.Set(); };

    _ = server.StartAsync();
    shutdown.Wait();
    Console.WriteLine("[LightGuardServer] 已停止");
}
catch (Exception ex)
{
    Console.Error.WriteLine($"[LightGuardServer] 启动失败：{ex}");
    Environment.ExitCode = 1;
}

static void RunSetup()
{
    Console.WriteLine("========== LightGuardServer 初始化 ==========");
    Console.Write("监听端口（默认 17621）：");
    var portStr = Console.ReadLine()?.Trim();
    var port = int.TryParse(portStr, out var p) && p > 0 && p < 65536 ? p : LightGuard.Shared.CsProtocol.DefaultPort;

    Console.Write("认证密码（至少 8 位，用于客户端连接认证）：");
    var password = ReadPassword();
    if (string.IsNullOrEmpty(password) || password.Length < 8)
    {
        Console.Error.WriteLine("密码过短，已取消。");
        return;
    }

    var config = ServerConfig.Load();
    config.Port = port;
    config.PasswordHash = LightGuard.Shared.CsTransport.HashPassword(password);
    config.Save();

    Console.WriteLine("==============================================");
    Console.WriteLine($"配置已保存：{config.ConfigPath}");
    Console.WriteLine($"  端口：{config.Port}");
    Console.WriteLine($"  认证：已启用（密码哈希 {config.PasswordHash[..Math.Min(8, config.PasswordHash.Length)]}...）");
    Console.WriteLine($"  数据目录：{config.DataDir}");
    Console.WriteLine("启动：LightGuardServer");
}

/// <summary>读取密码（不回显）。</summary>
static string ReadPassword()
{
    var sb = new System.Text.StringBuilder();
    while (true)
    {
        var key = Console.ReadKey(intercept: true);
        if (key.Key == ConsoleKey.Enter) break;
        if (key.Key == ConsoleKey.Backspace && sb.Length > 0) { sb.Length--; continue; }
        if (!char.IsControl(key.KeyChar)) sb.Append(key.KeyChar);
    }
    Console.WriteLine();
    return sb.ToString();
}
