// © 2026 落尘（Luochen） 原创开发 - 保留所有权利

using System.Data.Common;
using System.Diagnostics;
using System.Reflection;
using System.Text;
using LightGuard.Core;

namespace LightGuard.Database;

/// <summary>
/// 数据库连接辅助工具
/// <para>提供连接字符串构建、连接测试、数据库列表和表列表获取等功能，</para>
/// <para>支持 MySQL / MariaDB / SqlServer / SQLite / Access 五种数据库类型。</para>
/// <para>ADO.NET 提供程序通过反射动态加载，无需编译期依赖 NuGet 包。</para>
/// </summary>
public static class DatabaseConnectionHelper
{
    #region 连接字符串构建

    /// <summary>
    /// 构建指定数据库类型的连接字符串
    /// </summary>
    /// <param name="dbType">数据库类型</param>
    /// <param name="server">服务器地址（SQLite/Access 为文件路径所在目录，可留空）</param>
    /// <param name="port">端口号（SQLite/Access 不适用，可传 0）</param>
    /// <param name="database">数据库名称（SQLite/Access 为文件路径）</param>
    /// <param name="user">用户名</param>
    /// <param name="password">密码</param>
    /// <returns>连接字符串</returns>
    public static string BuildConnectionString(
        DatabaseType dbType,
        string server,
        int port,
        string database,
        string user,
        string password)
    {
        return dbType switch
        {
            DatabaseType.MySQL or DatabaseType.MariaDB =>
                $"Server={server};Port={port};Database={database};Uid={user};Pwd={password};Charset=utf8mb4;AllowUserVariables=true;",

            DatabaseType.SqlServer =>
                $"Server={server},{port};Database={database};User Id={user};Password={password};TrustServerCertificate=True;Encrypt=False;",

            DatabaseType.SQLite =>
                $"Data Source={database};Version=3;",

            DatabaseType.Access =>
                BuildAccessConnectionString(database, password),

            DatabaseType.PostgreSQL =>
                $"Host={server};Port={port};Database={database};Username={user};Password={password};",

            _ => throw new ArgumentException($"不支持的数据库类型：{dbType}", nameof(dbType))
        };
    }

    /// <summary>
    /// 根据 Access 文件扩展名构建 OLE DB 连接字符串
    /// </summary>
    private static string BuildAccessConnectionString(string filePath, string password)
    {
        var ext = Path.GetExtension(filePath).ToLowerInvariant();
        var provider = ext == ".mdb"
            ? "Microsoft.Jet.OLEDB.4.0"
            : "Microsoft.ACE.OLEDB.12.0";

        var sb = new StringBuilder();
        sb.Append($"Provider={provider};Data Source={filePath};");
        if (!string.IsNullOrEmpty(password))
            sb.Append($"Jet OLEDB:Database Password={password};");
        return sb.ToString();
    }

    #endregion

    #region 连接测试

    /// <summary>
    /// 测试数据库连接是否可用
    /// </summary>
    /// <param name="dbType">数据库类型</param>
    /// <param name="connStr">连接字符串</param>
    /// <returns>(是否成功, 消息)</returns>
    public static (bool success, string message) TestConnection(DatabaseType dbType, string connStr)
    {
        // 优先尝试 ADO.NET 提供程序
        var factory = TryGetFactory(dbType);
        if (factory != null)
        {
            return TestConnectionAdoNet(factory, connStr);
        }

        // ADO.NET 提供程序不可用时，回退到命令行工具测试
        return dbType switch
        {
            DatabaseType.MySQL or DatabaseType.MariaDB => TestMySqlConnection(dbType, connStr),
            DatabaseType.SqlServer => TestSqlServerConnection(connStr),
            DatabaseType.SQLite => TestSqliteConnection(connStr),
            DatabaseType.Access => TestAccessConnection(connStr),
            DatabaseType.PostgreSQL => TestPostgreSqlConnection(connStr),
            _ => (false, $"不支持的数据库类型：{dbType}")
        };
    }

    /// <summary>PostgreSQL 命令行连接测试（PGPASSWORD 环境变量传密码，不暴露命令行）。</summary>
    private static (bool success, string message) TestPostgreSqlConnection(string connStr)
    {
        var server = ExtractValue(connStr, "Host", ExtractValue(connStr, "Server", "localhost"));
        var port = ExtractValue(connStr, "Port", "5432");
        var db = ExtractValue(connStr, "Database", "postgres");
        var user = ExtractValue(connStr, "Username", ExtractValue(connStr, "User Id", "postgres"));
        var pwd = ExtractValue(connStr, "Password", "");

        var args = $"--host={server} --port={port} --username={user} --dbname={db} --tuples-only --no-align --command=\"SELECT 1\"";
        var (code, _, error) = RunProcessWithEnv("psql", args, ("PGPASSWORD", pwd));
        return code == 0 ? (true, "连接成功") : (false, $"连接失败：{error}");
    }

    /// <summary>使用 ADO.NET 提供程序测试连接</summary>
    private static (bool success, string message) TestConnectionAdoNet(DbProviderFactory factory, string connStr)
    {
        try
        {
            using var conn = factory.CreateConnection();
            if (conn == null) return (false, "无法创建数据库连接对象");

            conn.ConnectionString = connStr;
            conn.Open();

            return (true, "连接成功");
        }
        catch (Exception ex)
        {
            return (false, ex.Message);
        }
    }

    /// <summary>MySQL/MariaDB 命令行连接测试</summary>
    private static (bool success, string message) TestMySqlConnection(DatabaseType dbType, string connStr)
    {
        var p = ParseConnStr(connStr, "Server", "Host");
        var port = ExtractValue(connStr, "Port", "3306");
        var user = ExtractValue(connStr, "Uid", ExtractValue(connStr, "User Id", "root"));
        var pwd = ExtractValue(connStr, "Pwd", ExtractValue(connStr, "Password", ""));

        var toolName = dbType == DatabaseType.MariaDB ? "mariadb" : "mysql";
        var args = $"--host={p} --port={port} --user={user} --password={pwd} --execute=\"SELECT 1\"";

        var (code, _, error) = RunProcess(toolName, args);
        return code == 0 ? (true, "连接成功") : (false, $"连接失败：{error}");
    }

    /// <summary>SqlServer 命令行连接测试</summary>
    private static (bool success, string message) TestSqlServerConnection(string connStr)
    {
        var server = ExtractValue(connStr, "Server", ExtractValue(connStr, "Data Source", "localhost"));
        var user = ExtractValue(connStr, "User Id", ExtractValue(connStr, "Uid", "sa"));
        var pwd = ExtractValue(connStr, "Password", ExtractValue(connStr, "Pwd", ""));

        var args = $"-S \"{server}\" -U \"{user}\" -P \"{pwd}\" -Q \"SELECT 1\" -b";

        var (code, _, error) = RunProcess("sqlcmd", args);
        return code == 0 ? (true, "连接成功") : (false, $"连接失败：{error}");
    }

    /// <summary>SQLite 连接测试（检查文件是否存在且有效）</summary>
    private static (bool success, string message) TestSqliteConnection(string connStr)
    {
        var dbPath = ExtractValue(connStr, "Data Source", "");
        if (string.IsNullOrEmpty(dbPath))
            return (false, "连接字符串中缺少 Data Source");

        if (!File.Exists(dbPath))
            return (false, $"数据库文件不存在：{dbPath}");

        // 检查 SQLite 文件头魔数（前 16 字节包含 "SQLite format 3\0"）
        try
        {
            using var fs = File.OpenRead(dbPath);
            var header = new byte[16];
            if (fs.Read(header, 0, 16) < 16)
                return (false, "文件太小，不是有效的 SQLite 数据库");

            var magic = Encoding.ASCII.GetString(header);
            if (!magic.StartsWith("SQLite format 3"))
                return (false, "文件头不匹配，不是有效的 SQLite 数据库");

            return (true, "连接成功");
        }
        catch (Exception ex)
        {
            return (false, ex.Message);
        }
    }

    /// <summary>Access 连接测试（检查文件是否存在）</summary>
    private static (bool success, string message) TestAccessConnection(string connStr)
    {
        var dbPath = ExtractValue(connStr, "Data Source", "");
        if (string.IsNullOrEmpty(dbPath))
            return (false, "连接字符串中缺少 Data Source");

        if (!File.Exists(dbPath))
            return (false, $"数据库文件不存在：{dbPath}");

        var ext = Path.GetExtension(dbPath).ToLowerInvariant();
        if (ext != ".mdb" && ext != ".accdb")
            return (false, $"不支持的 Access 文件扩展名：{ext}（仅支持 .mdb / .accdb）");

        return (true, "连接成功");
    }

    #endregion

    #region 获取数据库列表

    /// <summary>
    /// 列出可备份的数据库
    /// </summary>
    /// <param name="dbType">数据库类型</param>
    /// <param name="connStr">连接字符串</param>
    /// <returns>数据库名称列表</returns>
    public static List<string> GetDatabases(DatabaseType dbType, string connStr)
    {
        var factory = TryGetFactory(dbType);
        if (factory == null)
        {
            // 提供程序不可用时，对 SQLite/Access 返回文件名作为"数据库"
            if (dbType is DatabaseType.SQLite or DatabaseType.Access)
            {
                var dbPath = ExtractValue(connStr, "Data Source", "");
                if (!string.IsNullOrEmpty(dbPath) && File.Exists(dbPath))
                    return new List<string> { Path.GetFileName(dbPath) };
            }
            return new List<string>();
        }

        var sql = dbType switch
        {
            DatabaseType.MySQL or DatabaseType.MariaDB =>
                "SELECT SCHEMA_NAME FROM INFORMATION_SCHEMA.SCHEMATA " +
                "WHERE SCHEMA_NAME NOT IN ('information_schema','mysql','performance_schema','sys') " +
                "ORDER BY SCHEMA_NAME",
            DatabaseType.SqlServer =>
                "SELECT name FROM sys.databases " +
                "WHERE state_desc = 'ONLINE' AND name NOT IN ('master','tempdb','model','msdb') " +
                "ORDER BY name",
            DatabaseType.SQLite =>
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name",
            DatabaseType.Access =>
                "SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_TYPE='BASE TABLE' ORDER BY TABLE_NAME",
            _ => null
        };

        if (sql == null) return new List<string>();

        try
        {
            using var conn = factory.CreateConnection();
            if (conn == null) return new List<string>();
            conn.ConnectionString = connStr;
            conn.Open();

            using var cmd = conn.CreateCommand();
            cmd.CommandText = sql;
            using var reader = cmd.ExecuteReader();

            var list = new List<string>();
            while (reader.Read())
            {
                list.Add(reader.GetString(0));
            }
            return list;
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, $"获取数据库列表失败（{dbType}）");
            return new List<string>();
        }
    }

    #endregion

    #region 获取表列表

    /// <summary>
    /// 列出指定数据库中的表
    /// </summary>
    /// <param name="dbType">数据库类型</param>
    /// <param name="connStr">连接字符串</param>
    /// <param name="database">数据库名称（SQLite/Access 可留空）</param>
    /// <returns>表名列表</returns>
    public static List<string> GetTables(DatabaseType dbType, string connStr, string? database = null)
    {
        var factory = TryGetFactory(dbType);
        if (factory == null) return new List<string>();

        var sql = dbType switch
        {
            DatabaseType.MySQL or DatabaseType.MariaDB =>
                database != null
                    ? $"SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA='{EscapeSql(database)}' AND TABLE_TYPE='BASE TABLE' ORDER BY TABLE_NAME"
                    : "SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_TYPE='BASE TABLE' ORDER BY TABLE_NAME",
            DatabaseType.SqlServer =>
                "SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_TYPE='BASE TABLE' ORDER BY TABLE_NAME",
            DatabaseType.SQLite =>
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name",
            DatabaseType.Access =>
                "SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_TYPE='BASE TABLE' ORDER BY TABLE_NAME",
            _ => null
        };

        if (sql == null) return new List<string>();

        try
        {
            using var conn = factory.CreateConnection();
            if (conn == null) return new List<string>();

            // MySQL/MariaDB 需要切换到目标数据库
            var effectiveConnStr = connStr;
            if ((dbType is DatabaseType.MySQL or DatabaseType.MariaDB) && !string.IsNullOrEmpty(database))
            {
                // 确保连接字符串中包含正确的 Database
                if (!connStr.Contains("Database=", StringComparison.OrdinalIgnoreCase))
                    effectiveConnStr = connStr.TrimEnd(';') + $";Database={database};";
            }

            conn.ConnectionString = effectiveConnStr;
            conn.Open();

            using var cmd = conn.CreateCommand();
            cmd.CommandText = sql;
            using var reader = cmd.ExecuteReader();

            var list = new List<string>();
            while (reader.Read())
            {
                list.Add(reader.GetString(0));
            }
            return list;
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, $"获取表列表失败（{dbType}, db={database}）");
            return new List<string>();
        }
    }

    #endregion

    #region ADO.NET 提供程序动态加载

    /// <summary>
    /// 尝试获取指定数据库类型的 ADO.NET 提供程序工厂
    /// <para>通过反射动态加载已安装的 NuGet 包提供程序，无需编译期依赖。</para>
    /// </summary>
    /// <param name="dbType">数据库类型</param>
    /// <returns>DbProviderFactory 实例（未安装对应提供程序时返回 null）</returns>
    public static DbProviderFactory? TryGetFactory(DatabaseType dbType)
    {
        return dbType switch
        {
            DatabaseType.MySQL or DatabaseType.MariaDB =>
                TryLoadFactory(
                    ("MySqlConnector", "MySqlConnector.MySqlConnectorFactory"),
                    ("MySql.Data", "MySql.Data.MySqlClient.MySqlClientFactory")
                ),
            DatabaseType.SqlServer =>
                TryLoadFactory(
                    ("Microsoft.Data.SqlClient", "Microsoft.Data.SqlClient.SqlClientFactory"),
                    ("System.Data.SqlClient", "System.Data.SqlClient.SqlClientFactory")
                ),
            DatabaseType.SQLite =>
                TryLoadFactory(
                    ("Microsoft.Data.Sqlite", "Microsoft.Data.Sqlite.SqliteFactory"),
                    ("System.Data.SQLite", "System.Data.SQLite.SQLiteFactory")
                ),
            DatabaseType.Access =>
                TryLoadFactory(
                    ("System.Data.OleDb", "System.Data.OleDb.OleDbFactory")
                ),
            _ => null
        };
    }

    /// <summary>
    /// 按候选程序集列表尝试加载 DbProviderFactory
    /// </summary>
    private static DbProviderFactory? TryLoadFactory(params (string assemblyName, string factoryTypeName)[] candidates)
    {
        foreach (var (assemblyName, factoryTypeName) in candidates)
        {
            try
            {
                // 优先在已加载的程序集中查找
                var asm = AppDomain.CurrentDomain.GetAssemblies()
                    .FirstOrDefault(a => a.GetName().Name == assemblyName);

                if (asm == null)
                {
                    // 尝试按名称加载程序集
                    asm = Assembly.Load(assemblyName);
                }

                if (asm == null) continue;

                var type = asm.GetType(factoryTypeName);
                if (type == null) continue;

                // 大多数 DbProviderFactory 实现通过静态 "Instance" 字段暴露单例
                var field = type.GetField("Instance", BindingFlags.Public | BindingFlags.Static);
                if (field?.GetValue(null) is DbProviderFactory factory)
                    return factory;

                // 兼容部分实现使用属性暴露
                var prop = type.GetProperty("Instance", BindingFlags.Public | BindingFlags.Static);
                if (prop?.GetValue(null) is DbProviderFactory factoryProp)
                    return factoryProp;
            }
            catch
            {
                // 加载失败，继续尝试下一个候选
            }
        }
        return null;
    }

    #endregion

    #region 辅助方法

    /// <summary>从连接字符串中提取指定键的值</summary>
    private static string ExtractValue(string connStr, string key, string defaultValue = "")
    {
        var pairs = connStr.Split(';', StringSplitOptions.RemoveEmptyEntries);
        foreach (var pair in pairs)
        {
            var idx = pair.IndexOf('=');
            if (idx > 0)
            {
                var k = pair.Substring(0, idx).Trim();
                var v = pair.Substring(idx + 1).Trim();
                if (string.Equals(k, key, StringComparison.OrdinalIgnoreCase))
                    return v.Trim('"', '\'');
            }
        }
        return defaultValue;
    }

    /// <summary>从连接字符串中提取第一个匹配键的值</summary>
    private static string ParseConnStr(string connStr, string key1, string key2)
    {
        var val = ExtractValue(connStr, key1);
        if (string.IsNullOrEmpty(val)) val = ExtractValue(connStr, key2);
        return string.IsNullOrEmpty(val) ? "localhost" : val;
    }

    /// <summary>转义 SQL 字符串中的单引号（防注入）</summary>
    private static string EscapeSql(string? input)
    {
        if (string.IsNullOrEmpty(input)) return string.Empty;
        return input.Replace("'", "''");
    }

    /// <summary>运行外部进程并捕获结果</summary>
    private static (int ExitCode, string Output, string Error) RunProcess(string fileName, string args)
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = fileName,
                Arguments = args,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
                StandardOutputEncoding = Encoding.UTF8,
                StandardErrorEncoding = Encoding.UTF8
            };

            using var proc = Process.Start(psi);
            if (proc == null) return (-1, string.Empty, "无法启动进程");

            var output = proc.StandardOutput.ReadToEnd();
            var error = proc.StandardError.ReadToEnd();
            proc.WaitForExit();

            return (proc.ExitCode, output, error);
        }
        catch (Exception ex)
        {
            return (-1, string.Empty, ex.Message);
        }
    }

    /// <summary>运行外部进程并捕获结果（附加环境变量，如 PGPASSWORD 传递密码）</summary>
    private static (int ExitCode, string Output, string Error) RunProcessWithEnv(
        string fileName, string args, (string Key, string Value) envVar)
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = fileName,
                Arguments = args,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
                StandardOutputEncoding = Encoding.UTF8,
                StandardErrorEncoding = Encoding.UTF8
            };
            psi.Environment[envVar.Key] = envVar.Value;

            using var proc = Process.Start(psi);
            if (proc == null) return (-1, string.Empty, "无法启动进程");

            var output = proc.StandardOutput.ReadToEnd();
            var error = proc.StandardError.ReadToEnd();
            proc.WaitForExit();

            return (proc.ExitCode, output, error);
        }
        catch (Exception ex)
        {
            return (-1, string.Empty, ex.Message);
        }
    }

    #endregion
}
