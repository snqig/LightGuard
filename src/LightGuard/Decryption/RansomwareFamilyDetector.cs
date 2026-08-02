using System.Text;
using LightGuard.Core;

namespace LightGuard.Decryption;

/// <summary>
/// 勒索软件家族检测器
/// 通过文件扩展名、文件头魔数、勒索说明文件等多维度识别勒索家族
/// </summary>
public sealed class RansomwareFamilyDetector
{
    /// <summary>读取文件头的最大字节数</summary>
    private const int HeaderReadBytes = 512;

    /// <summary>读取勒索说明文件的最大字节数</summary>
    private const int RansomNoteReadBytes = 8 * 1024;

    #region 内置家族知识库

    /// <summary>
    /// 已知勒索家族知识库（约 15 个家族）
    /// 包含扩展名、描述、解密器可用性、检测模式、勒索说明文件名
    /// </summary>
    private static readonly List<RansomwareFamilyInfo> KnownFamilies = new()
    {
        new RansomwareFamilyInfo
        {
            Family = RansomwareFamily.WannaCry,
            Name = "WannaCry",
            Extension = ".wcry",
            Description = "永恒之蓝勒索蠕虫，利用 SMB 漏洞 MS17-010 横向传播，2017 年全球爆发",
            HasDecryptor = true,
            DecryptorUrl = "https://download.bleepingcomputer.com/demalware-tool/WanakiDecryptor.exe",
            DecryptorSha256 = "0000000000000000000000000000000000000000000000000000000000000000",
            DecryptorFileName = "WanakiDecryptor.exe",
            ToolSizeBytes = 0,
            DetectionPatterns = new List<string> { "*.wcry", "*.wnry", "*.wncry" },
            RansomNoteNames = new List<string> { "@WanaDecryptor@.bmp.txt", "!WannaDecryptor!.exe.lnk", "README.wnry" }
        },
        new RansomwareFamilyInfo
        {
            Family = RansomwareFamily.Petya,
            Name = "Petya / NotPetya",
            Extension = ".petya",
            Description = "主引导记录（MBR）加密勒索，NotPetya 变种以破坏为目的，无解密器",
            HasDecryptor = false,
            DecryptorUrl = "",
            DecryptorSha256 = "",
            DecryptorFileName = "",
            DetectionPatterns = new List<string> { "*.petya", "*.encrypted" },
            RansomNoteNames = new List<string> { "README.txt", "YOUR_FILES_ARE_ENCRYPTED.txt" }
        },
        new RansomwareFamilyInfo
        {
            Family = RansomwareFamily.GandCrab,
            Name = "GandCrab",
            Extension = ".gandcrab",
            Description = "勒索即服务（RaaS）家族，REvil 前身，已有 Bitdefender 官方解密器",
            HasDecryptor = true,
            DecryptorUrl = "https://download.bleepingcomputer.com/demalware-tool/GandCrabDecryptor.exe",
            DecryptorSha256 = "0000000000000000000000000000000000000000000000000000000000000000",
            DecryptorFileName = "GandCrabDecryptor.exe",
            DetectionPatterns = new List<string> { "*.gandcrab", "*.krab" },
            RansomNoteNames = new List<string> { "KRAB-DECRYPT.txt", "GANDCRAB.txt" }
        },
        new RansomwareFamilyInfo
        {
            Family = RansomwareFamily.STOP,
            Name = "STOP / Djvu",
            Extension = ".stop",
            Description = "变种极多的勒索家族，部分离线密钥可通过 Emsisoft 解密器恢复",
            HasDecryptor = true,
            DecryptorUrl = "https://download.bleepingcomputer.com/demalware-tool/STOPDecryptor.exe",
            DecryptorSha256 = "0000000000000000000000000000000000000000000000000000000000000000",
            DecryptorFileName = "STOPDecryptor.exe",
            DetectionPatterns = new List<string> { "*.stop", "*.locked", "*.djvu", "*.djvuu", "*.djvq", "*.udjvu", "*.uudjvu" },
            RansomNoteNames = new List<string> { "_readme.txt", "openme.txt" }
        },
        new RansomwareFamilyInfo
        {
            Family = RansomwareFamily.Maze,
            Name = "Maze",
            Extension = ".maze",
            Description = "双重勒索鼻祖，先窃取数据再加密，威胁公开泄露",
            HasDecryptor = false,
            DecryptorUrl = "",
            DecryptorSha256 = "",
            DecryptorFileName = "",
            DetectionPatterns = new List<string> { "*.maze", "*.maze1" },
            RansomNoteNames = new List<string> { "DECRYPT-FILES.html", "README.txt" }
        },
        new RansomwareFamilyInfo
        {
            Family = RansomwareFamily.Ryuk,
            Name = "Ryuk",
            Extension = ".ryk",
            Description = "定向攻击大型机构的勒索软件，无公开解密器",
            HasDecryptor = false,
            DecryptorUrl = "",
            DecryptorSha256 = "",
            DecryptorFileName = "",
            DetectionPatterns = new List<string> { "*.ryk", "*.RYK" },
            RansomNoteNames = new List<string> { "RyukReadMe.txt", "RyukReadMe.html" }
        },
        new RansomwareFamilyInfo
        {
            Family = RansomwareFamily.Sodinokibi,
            Name = "Sodinokibi / REvil",
            Extension = ".sodinokibi",
            Description = "Maze 继任者，勒索即服务平台，部分旧版本可解密",
            HasDecryptor = false,
            DecryptorUrl = "",
            DecryptorSha256 = "",
            DecryptorFileName = "",
            DetectionPatterns = new List<string> { "*.sodinokibi", "*.revil", "*.SODIN" },
            RansomNoteNames = new List<string> { "how-to-decrypt.txt", "README.txt" }
        },
        new RansomwareFamilyInfo
        {
            Family = RansomwareFamily.Conti,
            Name = "Conti",
            Extension = ".conti",
            Description = "Ryuk 继任者，源码泄露后衍生大量变种，无公开解密器",
            HasDecryptor = false,
            DecryptorUrl = "",
            DecryptorSha256 = "",
            DecryptorFileName = "",
            DetectionPatterns = new List<string> { "*.conti", "*.CONTI" },
            RansomNoteNames = new List<string> { "readme.txt", "CONTI_README.txt" }
        },
        new RansomwareFamilyInfo
        {
            Family = RansomwareFamily.LockBit,
            Name = "LockBit",
            Extension = ".lockbit",
            Description = "高度自动化的勒索即服务家族，2023 年最活跃家族之一",
            HasDecryptor = false,
            DecryptorUrl = "",
            DecryptorSha256 = "",
            DecryptorFileName = "",
            DetectionPatterns = new List<string> { "*.lockbit", "*.lockbit2" },
            RansomNoteNames = new List<string> { "Restore-My-Files.txt", "README.txt" }
        },
        new RansomwareFamilyInfo
        {
            Family = RansomwareFamily.BlackBasta,
            Name = "BlackBasta",
            Extension = ".blackbasta",
            Description = "2022 年崛起的双重勒索家族，Conti 成员重组而成",
            HasDecryptor = false,
            DecryptorUrl = "",
            DecryptorSha256 = "",
            DecryptorFileName = "",
            DetectionPatterns = new List<string> { "*.blackbasta", "*.basta" },
            RansomNoteNames = new List<string> { "readme.txt", "README.txt" }
        },
        new RansomwareFamilyInfo
        {
            Family = RansomwareFamily.AvosLocker,
            Name = "AvosLocker",
            Extension = ".avos",
            Description = "支持 Windows 和 Linux 双平台的勒索即服务家族",
            HasDecryptor = false,
            DecryptorUrl = "",
            DecryptorSha256 = "",
            DecryptorFileName = "",
            DetectionPatterns = new List<string> { "*.avos", "*.avos2" },
            RansomNoteNames = new List<string> { "HOW_TO_DECRYPT.txt", "README.txt" }
        },
        // 补充常见家族（虽不在枚举中，但在扩展名映射里提供参考）
        new RansomwareFamilyInfo
        {
            Family = RansomwareFamily.WannaCry,
            Name = "WannaCry (WNRY)",
            Extension = ".wnry",
            Description = "WannaCry 蠕虫的另一种加密后缀标记",
            HasDecryptor = true,
            DecryptorUrl = "https://download.bleepingcomputer.com/demalware-tool/WanakiDecryptor.exe",
            DecryptorSha256 = "0000000000000000000000000000000000000000000000000000000000000000",
            DecryptorFileName = "WanakiDecryptor.exe",
            DetectionPatterns = new List<string> { "*.wnry" },
            RansomNoteNames = new List<string> { "@WanaDecryptor@.bmp.txt" }
        },
        new RansomwareFamilyInfo
        {
            Family = RansomwareFamily.STOP,
            Name = "STOP (Locked)",
            Extension = ".locked",
            Description = "STOP/Djvu 家族的 .locked 变种，部分离线密钥可解密",
            HasDecryptor = true,
            DecryptorUrl = "https://download.bleepingcomputer.com/demalware-tool/STOPDecryptor.exe",
            DecryptorSha256 = "0000000000000000000000000000000000000000000000000000000000000000",
            DecryptorFileName = "STOPDecryptor.exe",
            DetectionPatterns = new List<string> { "*.locked" },
            RansomNoteNames = new List<string> { "_readme.txt" }
        },
        new RansomwareFamilyInfo
        {
            Family = RansomwareFamily.Petya,
            Name = "Petya (Encrypted)",
            Extension = ".encrypted",
            Description = "Petya/NotPetya 家族的通用加密标记",
            HasDecryptor = false,
            DecryptorUrl = "",
            DecryptorSha256 = "",
            DecryptorFileName = "",
            DetectionPatterns = new List<string> { "*.encrypted" },
            RansomNoteNames = new List<string> { "README.txt" }
        }
    };

    /// <summary>
    /// 文件头魔数特征映射表
    /// Key = 魔数（字节序列），Value = 对应家族
    /// </summary>
    private static readonly (byte[] Magic, RansomwareFamily Family)[] HeaderMagicPatterns =
    {
        // WannaCry: 文件头部常含 "WANADECRYPT" 或 "WanaDecryptor" 标记
        (Encoding.ASCII.GetBytes("WANADECRYPT"), RansomwareFamily.WannaCry),
        (Encoding.ASCII.GetBytes("WanaDecryptor"), RansomwareFamily.WannaCry),

        // Petya/NotPetya: MBR 覆盖后磁盘头部含特定扇区标记
        (Encoding.ASCII.GetBytes("GRUB"), RansomwareFamily.Petya),

        // GandCrab: 加密文件头部含 "GANDCRAB" 标记
        (Encoding.ASCII.GetBytes("GANDCRAB"), RansomwareFamily.GandCrab),
    };

    /// <summary>
    /// 勒索说明文件关键词映射表
    /// Key = 关键词（小写），Value = 对应家族
    /// </summary>
    private static readonly (string Keyword, RansomwareFamily Family)[] RansomNoteKeywords =
    {
        ("wanadecrypt", RansomwareFamily.WannaCry),
        ("wannacry", RansomwareFamily.WannaCry),
        ("wanacrypt", RansomwareFamily.WannaCry),
        ("bitcoin", RansomwareFamily.Unknown),    // 通用关键词，仅辅助
        (".onion", RansomwareFamily.Unknown),     // 通用关键词，仅辅助
        ("gandcrab", RansomwareFamily.GandCrab),
        ("krab", RansomwareFamily.GandCrab),
        ("petya", RansomwareFamily.Petya),
        ("notpetya", RansomwareFamily.Petya),
        ("stop/djvu", RansomwareFamily.STOP),
        ("djvu", RansomwareFamily.STOP),
        ("_readme.txt", RansomwareFamily.STOP),
        ("maze", RansomwareFamily.Maze),
        ("ryuk", RansomwareFamily.Ryuk),
        ("sodinokibi", RansomwareFamily.Sodinokibi),
        ("revil", RansomwareFamily.Sodinokibi),
        ("conti", RansomwareFamily.Conti),
        ("lockbit", RansomwareFamily.LockBit),
        ("blackbasta", RansomwareFamily.BlackBasta),
        ("avoslocker", RansomwareFamily.AvosLocker),
        ("avos", RansomwareFamily.AvosLocker),
    };

    /// <summary>
    /// 常见勒索说明文件名列表
    /// </summary>
    private static readonly string[] CommonRansomNoteNames =
    {
        "README.txt", "readme.txt", "README.md",
        "HOW_TO_DECRYPT.txt", "how_to_decrypt.txt",
        "DECRYPT.txt", "decrypt.txt",
        "DECRYPT-FILES.html", "DECRYPT-FILES.txt",
        "_readme.txt", "openme.txt",
        "RESTORE_FILES.txt", "restore_files.txt",
        "YOUR_FILES_ARE_ENCRYPTED.txt", "your_files_are_encrypted.txt",
        "help_decrypt.txt", "HELP_DECRYPT.txt",
        "ransomnote.txt", "ransom_note.txt",
        "HOW_TO_RECOVER_FILES.txt",
        "@WanaDecryptor@.bmp.txt",
        "RyukReadMe.txt", "RyukReadMe.html",
        "KRAB-DECRYPT.txt", "GANDCRAB.txt",
        "Restore-My-Files.txt"
    };

    #endregion

    /// <summary>
    /// 从加密文件检测勒索家族（综合扩展名 + 文件头 + 勒索说明文件）
    /// </summary>
    /// <param name="filePath">加密文件路径</param>
    /// <returns>检测到的家族，无法识别返回 Unknown</returns>
    public RansomwareFamily DetectFamily(string filePath)
    {
        try
        {
            if (!File.Exists(filePath))
            {
                ErrorReporter.Log($"[家族检测] 文件不存在: {filePath}", "WARN");
                return RansomwareFamily.Unknown;
            }

            // 1. 首先检查文件扩展名
            var ext = Path.GetExtension(filePath);
            var familyByExt = DetectFamilyByExtension(ext);
            if (familyByExt != RansomwareFamily.Unknown)
            {
                ErrorReporter.Log($"[家族检测] 通过扩展名 {ext} 识别为 {familyByExt}: {filePath}");
                return familyByExt;
            }

            // 2. 读取文件头魔数（前 512 字节）
            var familyByHeader = DetectFamilyByHeader(filePath);
            if (familyByHeader != RansomwareFamily.Unknown)
            {
                ErrorReporter.Log($"[家族检测] 通过文件头魔数识别为 {familyByHeader}: {filePath}");
                return familyByHeader;
            }

            // 3. 检查同目录下的勒索说明文件
            var dir = Path.GetDirectoryName(filePath);
            if (!string.IsNullOrEmpty(dir))
            {
                var familyByNote = DetectFamilyByRansomNote(dir);
                if (familyByNote != RansomwareFamily.Unknown)
                {
                    ErrorReporter.Log($"[家族检测] 通过勒索说明文件识别为 {familyByNote}: {dir}");
                    return familyByNote;
                }
            }

            ErrorReporter.Log($"[家族检测] 无法识别文件家族: {filePath}");
            return RansomwareFamily.Unknown;
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, $"家族检测异常: {filePath}");
            return RansomwareFamily.Unknown;
        }
    }

    /// <summary>
    /// 通过文件扩展名映射勒索家族
    /// </summary>
    /// <param name="extension">文件扩展名（如 .wcry）</param>
    /// <returns>对应家族，无匹配返回 Unknown</returns>
    public RansomwareFamily DetectFamilyByExtension(string extension)
    {
        if (string.IsNullOrWhiteSpace(extension))
            return RansomwareFamily.Unknown;

        var ext = extension.ToLowerInvariant().TrimStart('.');

        // 精确扩展名映射
        return ext switch
        {
            "wcry" or "wnry" or "wncry" => RansomwareFamily.WannaCry,
            "petya" => RansomwareFamily.Petya,
            "gandcrab" or "krab" => RansomwareFamily.GandCrab,
            "stop" or "locked" or "djvu" or "djvuu" or "djvq" or "udjvu" or "uudjvu" or "nvet" or "tro" or "pmd" => RansomwareFamily.STOP,
            "maze" or "maze1" => RansomwareFamily.Maze,
            "ryk" => RansomwareFamily.Ryuk,
            "sodinokibi" or "revil" or "sodin" => RansomwareFamily.Sodinokibi,
            "conti" => RansomwareFamily.Conti,
            "lockbit" or "lockbit2" => RansomwareFamily.LockBit,
            "blackbasta" or "basta" => RansomwareFamily.BlackBasta,
            "avos" or "avos2" => RansomwareFamily.AvosLocker,
            "encrypted" => RansomwareFamily.Petya, // Petya 常用 .encrypted
            _ => RansomwareFamily.Unknown
        };
    }

    /// <summary>
    /// 通过读取文件头魔数（前 512 字节）检测家族
    /// </summary>
    private RansomwareFamily DetectFamilyByHeader(string filePath)
    {
        try
        {
            byte[] buffer;
            using (var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
            {
                var readLen = (int)Math.Min(fs.Length, HeaderReadBytes);
                buffer = new byte[readLen];
                fs.Read(buffer, 0, readLen);
            }

            // 将头部转为小写 ASCII 字符串用于关键词匹配
            var headerText = Encoding.ASCII.GetString(buffer).ToLowerInvariant();

            foreach (var (magic, family) in HeaderMagicPatterns)
            {
                var magicText = Encoding.ASCII.GetString(magic).ToLowerInvariant();
                if (headerText.Contains(magicText))
                    return family;
            }

            return RansomwareFamily.Unknown;
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, $"文件头检测异常: {filePath}");
            return RansomwareFamily.Unknown;
        }
    }

    /// <summary>
    /// 通过读取目录中的勒索说明文件内容匹配关键词来识别家族
    /// </summary>
    /// <param name="dirPath">目录路径</param>
    /// <returns>检测到的家族，无法识别返回 Unknown</returns>
    public RansomwareFamily DetectFamilyByRansomNote(string dirPath)
    {
        try
        {
            if (!Directory.Exists(dirPath))
                return RansomwareFamily.Unknown;

            // 查找可能的勒索说明文件
            string? notePath = null;
            foreach (var name in CommonRansomNoteNames)
            {
                var path = Path.Combine(dirPath, name);
                if (File.Exists(path))
                {
                    notePath = path;
                    break;
                }
            }

            // 如果未找到已知文件名，尝试通配匹配 txt/html
            if (notePath == null)
            {
                var candidates = Directory.EnumerateFiles(dirPath, "*.*", SearchOption.TopDirectoryOnly)
                    .Where(f =>
                    {
                        var ext = Path.GetExtension(f).ToLowerInvariant();
                        return ext == ".txt" || ext == ".html" || ext == ".htm";
                    })
                    .Take(5);

                foreach (var candidate in candidates)
                {
                    if (IsLikelyRansomNote(candidate))
                    {
                        notePath = candidate;
                        break;
                    }
                }
            }

            if (notePath == null)
                return RansomwareFamily.Unknown;

            // 读取勒索说明文件内容并匹配关键词
            return MatchFamilyFromNoteContent(notePath);
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, $"勒索说明文件检测异常: {dirPath}");
            return RansomwareFamily.Unknown;
        }
    }

    /// <summary>
    /// 判断文件是否可能是勒索说明文件（简单启发式：包含加密/解密/比特币等关键词）
    /// </summary>
    private bool IsLikelyRansomNote(string filePath)
    {
        try
        {
            var content = ReadTextSafely(filePath, RansomNoteReadBytes);
            if (string.IsNullOrEmpty(content)) return false;

            var lower = content.ToLowerInvariant();
            return lower.Contains("decrypt") || lower.Contains("解密")
                   || lower.Contains("bitcoin") || lower.Contains("比特币")
                   || lower.Contains("ransom") || lower.Contains("勒索")
                   || lower.Contains("encrypted") || lower.Contains("加密");
        }
        catch { return false; }
    }

    /// <summary>
    /// 从勒索说明文件内容中匹配家族关键词
    /// </summary>
    private RansomwareFamily MatchFamilyFromNoteContent(string notePath)
    {
        try
        {
            var content = ReadTextSafely(notePath, RansomNoteReadBytes);
            if (string.IsNullOrEmpty(content))
                return RansomwareFamily.Unknown;

            var lower = content.ToLowerInvariant();

            // 优先匹配明确的家族关键词
            foreach (var (keyword, family) in RansomNoteKeywords)
            {
                if (family == RansomwareFamily.Unknown) continue; // 跳过通用关键词
                if (lower.Contains(keyword))
                    return family;
            }

            return RansomwareFamily.Unknown;
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, $"勒索说明内容匹配异常: {notePath}");
            return RansomwareFamily.Unknown;
        }
    }

    /// <summary>安全读取文本文件（自动检测编码，限制最大字节数）</summary>
    private static string ReadTextSafely(string path, int maxBytes)
    {
        try
        {
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            var readLen = (int)Math.Min(fs.Length, maxBytes);
            var buffer = new byte[readLen];
            fs.Read(buffer, 0, readLen);

            // 简单 UTF-8 BOM 检测
            if (buffer.Length >= 3 && buffer[0] == 0xEF && buffer[1] == 0xBB && buffer[2] == 0xBF)
                return Encoding.UTF8.GetString(buffer, 3, buffer.Length - 3);

            // 默认按 UTF-8 解码，失败则回退到默认编码
            try { return Encoding.UTF8.GetString(buffer); }
            catch { return Encoding.Default.GetString(buffer); }
        }
        catch { return ""; }
    }

    /// <summary>
    /// 获取所有已知家族信息列表
    /// </summary>
    public List<RansomwareFamilyInfo> GetKnownFamilies()
    {
        // 去重：同一 Family 枚举只保留第一个（以第一个出现的为准）
        var seen = new HashSet<RansomwareFamily>();
        var result = new List<RansomwareFamilyInfo>();
        foreach (var info in KnownFamilies)
        {
            if (seen.Add(info.Family))
                result.Add(info);
        }
        return result;
    }

    /// <summary>
    /// 获取指定家族的信息
    /// </summary>
    public RansomwareFamilyInfo? GetFamilyInfo(RansomwareFamily family)
    {
        return KnownFamilies.FirstOrDefault(f => f.Family == family);
    }
}
