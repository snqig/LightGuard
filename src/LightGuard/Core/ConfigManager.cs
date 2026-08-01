using System.Text.Json;

namespace LightGuard.Core;

/// <summary>
/// 配置管理器 - 负责加载和保存应用配置
/// 配置文件存储在：%APPDATA%\LightGuard\config.json
/// </summary>
public static class ConfigManager
{
    private static readonly string ConfigDir = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
        "LightGuard");

    private static readonly string ConfigPath = Path.Combine(ConfigDir, "config.json");

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = null,
        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull
    };

    public static AppConfig Load()
    {
        try
        {
            if (!File.Exists(ConfigPath))
                return CreateDefault();

            var json = File.ReadAllText(ConfigPath);
            var config = JsonSerializer.Deserialize<AppConfig>(json, JsonOptions);
            return config ?? CreateDefault();
        }
        catch
        {
            return CreateDefault();
        }
    }

    public static void Save(AppConfig config)
    {
        try
        {
            Directory.CreateDirectory(ConfigDir);
            var json = JsonSerializer.Serialize(config, JsonOptions);
            File.WriteAllText(ConfigPath, json);
        }
        catch
        {
            // 静默失败，不打扰用户
        }
    }

    public static AppConfig CreateDefault()
    {
        var config = new AppConfig
        {
            FirstRunCompleted = false,
            CurrentScene = SceneMode.Home,
            BackgroundSchedulingEnabled = true,
            AutoMaintenanceHour = 3
        };

        // 默认保护文档文件夹
        config.Backup.ProtectedFolders.AddRange(new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Desktop")
        });

        return config;
    }

    public static string GetConfigDir() => ConfigDir;

    /// <summary>
    /// 获取数据目录（备份、日志等）
    /// </summary>
    public static string GetDataDir()
    {
        var dir = Path.Combine(ConfigDir, "data");
        Directory.CreateDirectory(dir);
        return dir;
    }

    /// <summary>
    /// 获取备份目录（优化前的注册表/Hosts备份）
    /// </summary>
    public static string GetBackupDir()
    {
        var dir = Path.Combine(ConfigDir, "backups");
        Directory.CreateDirectory(dir);
        return dir;
    }

    /// <summary>
    /// 获取日志目录
    /// </summary>
    public static string GetLogDir()
    {
        var dir = Path.Combine(ConfigDir, "logs");
        Directory.CreateDirectory(dir);
        return dir;
    }
}
