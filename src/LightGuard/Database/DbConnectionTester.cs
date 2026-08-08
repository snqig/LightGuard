// © 2026 落尘（Luochen） 原创开发 - 保留所有权利
//
// 数据库连接连通性测试（v3.5 P2-1）
//   - MySQL / MariaDB / PostgreSQL / SqlServer：TCP 连接 + 认证测试
//   - SQLite：db 文件存在性 + 文件头魔数校验（"SQLite format 3"）
//   - Access：文件存在性 + 扩展名校验
//   - 供 dbconfig 引导配置"保存前连接/文件有效性测试"使用

using System.Text;

namespace LightGuard.Database;

/// <summary>连接测试结果。</summary>
public sealed class DbConnectionTestResult
{
    /// <summary>是否通过。</summary>
    public bool Success { get; set; }

    /// <summary>结果消息。</summary>
    public string Message { get; set; } = "";
}

/// <summary>
/// 数据库连接/文件有效性测试器。
/// </summary>
public static class DbConnectionTester
{
    /// <summary>
    /// 测试连接（dbconfig 保存前调用）。
    /// </summary>
    /// <param name="dbType">数据库类型。</param>
    /// <param name="host">主机（SQLite 忽略）。</param>
    /// <param name="port">端口（SQLite 忽略）。</param>
    /// <param name="database">数据库名（SQLite 忽略）。</param>
    /// <param name="user">用户名（SQLite 忽略）。</param>
    /// <param name="password">密码（SQLite 忽略）。</param>
    /// <param name="dbFilePath">SQLite/Access 文件路径。</param>
    /// <returns>测试结果。</returns>
    public static DbConnectionTestResult Test(
        DatabaseType dbType,
        string host,
        int port,
        string database,
        string user,
        string password,
        string dbFilePath)
    {
        // SQLite / Access：本地文件有效性测试
        if (dbType is DatabaseType.SQLite or DatabaseType.Access)
        {
            return TestLocalFile(dbType, dbFilePath);
        }

        // 网络数据库：构建连接字符串 + 连通性测试
        try
        {
            var connStr = DatabaseConnectionHelper.BuildConnectionString(
                dbType, host, port, database, user, password);
            var (ok, msg) = DatabaseConnectionHelper.TestConnection(dbType, connStr);
            return new DbConnectionTestResult { Success = ok, Message = msg };
        }
        catch (Exception ex)
        {
            return new DbConnectionTestResult { Success = false, Message = $"连接参数无效：{ex.Message}" };
        }
    }

    /// <summary>本地文件有效性测试（SQLite 魔数 / Access 扩展名）。</summary>
    private static DbConnectionTestResult TestLocalFile(DatabaseType dbType, string dbFilePath)
    {
        if (string.IsNullOrWhiteSpace(dbFilePath))
            return new DbConnectionTestResult { Success = false, Message = "未填写数据库文件路径" };

        if (!File.Exists(dbFilePath))
            return new DbConnectionTestResult { Success = false, Message = $"数据库文件不存在：{dbFilePath}" };

        if (dbType == DatabaseType.SQLite)
        {
            // SQLite 文件头：前 16 字节 "SQLite format 3\0"
            try
            {
                using var fs = File.OpenRead(dbFilePath);
                var header = new byte[16];
                if (fs.Read(header, 0, 16) < 16)
                    return new DbConnectionTestResult { Success = false, Message = "文件太小，不是有效的 SQLite 数据库" };
                var magic = Encoding.ASCII.GetString(header, 0, 15);
                if (magic != "SQLite format 3")
                    return new DbConnectionTestResult { Success = false, Message = "文件头不匹配，不是有效的 SQLite 数据库" };
                return new DbConnectionTestResult { Success = true, Message = "SQLite 文件有效" };
            }
            catch (Exception ex)
            {
                return new DbConnectionTestResult { Success = false, Message = $"读取文件失败：{ex.Message}" };
            }
        }

        // Access
        var ext = Path.GetExtension(dbFilePath).ToLowerInvariant();
        if (ext is not (".mdb" or ".accdb"))
            return new DbConnectionTestResult { Success = false, Message = $"不支持的 Access 文件扩展名：{ext}（仅支持 .mdb / .accdb）" };
        return new DbConnectionTestResult { Success = true, Message = "Access 文件有效" };
    }
}
