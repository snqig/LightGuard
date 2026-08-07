// © 2026 落尘（Luochen） 原创开发 - 保留所有权利

using System.Text.Json;
using System.Text.Json.Serialization;

namespace LightGuard.Core;

/// <summary>
/// 资源类别枚举。
/// </summary>
public enum ResourceCategory
{
    /// <summary>语言包</summary>
    Language,

    /// <summary>YARA 规则</summary>
    YaraRule,

    /// <summary>广告拦截规则</summary>
    AdBlockRule,

    /// <summary>解密工具索引</summary>
    DecryptorIndex,

    /// <summary>工具（Defender 等）</summary>
    Tool,

    /// <summary>配置文件</summary>
    Config
}

/// <summary>
/// 资源清单条目 — 描述一个外部资源文件或目录。
/// </summary>
public sealed class ResourceEntry
{
    /// <summary>资源名称（唯一标识）</summary>
    public string Name { get; set; } = string.Empty;

    /// <summary>资源类别</summary>
    public ResourceCategory Category { get; set; }

    /// <summary>相对路径（相对于应用基目录）</summary>
    public string Path { get; set; } = string.Empty;

    /// <summary>是否为必需资源（缺失时阻止启动）</summary>
    public bool Required { get; set; }

    /// <summary>最大允许大小（MB），超出时发出警告</summary>
    public int MaxSizeMB { get; set; }
}

/// <summary>
/// 资源清单 — 管理所有外部资源的元数据。
/// <para>P1-1：用于构建脚本（便携版/MSI）决定打包哪些资源，</para>
/// <para>以及运行时验证资源完整性和大小。</para>
/// </summary>
public sealed class ResourceManifest
{
    /// <summary>资源清单文件路径（相对于应用基目录）</summary>
    private static readonly string ManifestFilePath = Path.Combine(
        AppDomain.CurrentDomain.BaseDirectory, "Resources", "resources.json");

    /// <summary>JSON 序列化选项</summary>
    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true,
        PropertyNameCaseInsensitive = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Converters = { new JsonStringEnumConverter() }
    };

    /// <summary>所有外部资源列表</summary>
    public List<ResourceEntry> Resources { get; set; } = new();

    /// <summary>
    /// 从 resources.json 加载资源清单。文件不存在时返回默认清单。
    /// </summary>
    public static ResourceManifest Load()
    {
        try
        {
            if (File.Exists(ManifestFilePath))
            {
                var json = File.ReadAllText(ManifestFilePath);
                var manifest = JsonSerializer.Deserialize<ResourceManifest>(json, JsonOpts);
                if (manifest != null && manifest.Resources.Count > 0)
                    return manifest;
            }
        }
        catch (Exception ex)
        {
            ErrorReporter.Log($"加载资源清单失败: {ex.Message}", "WARN");
        }

        // 回退到默认清单
        var defaultManifest = CreateDefault();
        ErrorReporter.Log("使用默认资源清单（resources.json 未找到或无效）", "INFO");
        return defaultManifest;
    }

    /// <summary>
    /// 保存资源清单到文件。
    /// </summary>
    public void Save()
    {
        try
        {
            var dir = Path.GetDirectoryName(ManifestFilePath);
            if (!string.IsNullOrEmpty(dir))
                Directory.CreateDirectory(dir);

            var json = JsonSerializer.Serialize(this, JsonOpts);
            File.WriteAllText(ManifestFilePath, json);
        }
        catch (Exception ex)
        {
            ErrorReporter.Log($"保存资源清单失败: {ex.Message}", "WARN");
        }
    }

    /// <summary>
    /// 按类别获取资源列表。
    /// </summary>
    public List<ResourceEntry> GetByCategory(ResourceCategory category)
    {
        return Resources.Where(r => r.Category == category).ToList();
    }

    /// <summary>
    /// 计算所有已存在资源的总大小（字节）。
    /// </summary>
    public long GetTotalSize()
    {
        long total = 0;
        var baseDir = AppDomain.CurrentDomain.BaseDirectory;

        foreach (var entry in Resources)
        {
            var fullPath = System.IO.Path.Combine(baseDir, entry.Path);
            if (File.Exists(fullPath))
            {
                total += new FileInfo(fullPath).Length;
            }
            else if (Directory.Exists(fullPath))
            {
                total += GetDirectorySize(fullPath);
            }
        }

        return total;
    }

    /// <summary>
    /// 创建默认资源清单，包含所有已知外部资源。
    /// </summary>
    public static ResourceManifest CreateDefault()
    {
        return new ResourceManifest
        {
            Resources = new List<ResourceEntry>
            {
                // ===== 语言包 =====
                new()
                {
                    Name = "lang-zh-CN",
                    Category = ResourceCategory.Language,
                    Path = "Resources/lang/lang_zh-CN.json",
                    Required = false,
                    MaxSizeMB = 1
                },
                new()
                {
                    Name = "lang-en-US",
                    Category = ResourceCategory.Language,
                    Path = "Resources/lang/lang_en-US.json",
                    Required = true,  // 服务器版本必需
                    MaxSizeMB = 1
                },
                new()
                {
                    Name = "lang-zh-TW",
                    Category = ResourceCategory.Language,
                    Path = "Resources/lang/lang_zh-TW.json",
                    Required = false,
                    MaxSizeMB = 1
                },

                // ===== YARA 规则 =====
                new()
                {
                    Name = "yara-rules",
                    Category = ResourceCategory.YaraRule,
                    Path = "Resources/yara-rules/",
                    Required = true,
                    MaxSizeMB = 5
                },

                // ===== 广告拦截规则 =====
                new()
                {
                    Name = "adblock-rules",
                    Category = ResourceCategory.AdBlockRule,
                    Path = "Resources/adblock/",
                    Required = false,
                    MaxSizeMB = 2
                },

                // ===== 解密工具索引 =====
                new()
                {
                    Name = "decryptor-index",
                    Category = ResourceCategory.DecryptorIndex,
                    Path = "Decryption/DecryptionToolIndex.json",
                    Required = false,
                    MaxSizeMB = 1
                },

                // ===== Defender 工具 =====
                new()
                {
                    Name = "defender-tools",
                    Category = ResourceCategory.Tool,
                    Path = "Resources/tools/defender/",
                    Required = false,
                    MaxSizeMB = 50
                },

                // ===== 服务器配置 =====
                new()
                {
                    Name = "server-config",
                    Category = ResourceCategory.Config,
                    Path = "Resources/config/server.json",
                    Required = false,
                    MaxSizeMB = 1
                }
            }
        };
    }

    /// <summary>
    /// 递归计算目录大小。
    /// </summary>
    private static long GetDirectorySize(string path)
    {
        long size = 0;
        try
        {
            var dir = new DirectoryInfo(path);
            foreach (var file in dir.GetFiles("*", SearchOption.AllDirectories))
                size += file.Length;
        }
        catch
        {
            // 权限或访问错误，返回已累计大小
        }
        return size;
    }
}
