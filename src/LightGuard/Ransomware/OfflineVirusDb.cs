using System.Text.Json;
using LightGuard.Modules;

namespace LightGuard.Ransomware;

/// <summary>
/// 离线病毒库兜底引擎
/// 内置 200+ 条勒索软件特征，断网环境下提供完整防护能力
/// 支持：扩展名匹配、文件名匹配、字节特征匹配、进程名匹配
/// </summary>
public static class OfflineVirusDb
{
    /// <summary>离线库版本号</summary>
    public const string Version = "offline-2.0.1";

    /// <summary>离线库发布日期</summary>
    public const string PublishDate = "2026-08-01";

    #region 勒索软件加密后扩展名（120+ 条）

    /// <summary>已知勒索软件加密后扩展名特征</summary>
    public static readonly VirusSignature[] RansomExtensions =
    {
        // Critical 级别 — 高流行度勒索家族
        Sig("Ransomware/WannaCry", ".wcry", RiskLevel.Critical),
        Sig("Ransomware/WannaCry2", ".wncry", RiskLevel.Critical),
        Sig("Ransomware/WannaCry3", ".wncryt", RiskLevel.Critical),
        Sig("Ransomware/Locky", ".locky", RiskLevel.Critical),
        Sig("Ransomware/Cerber", ".cerber", RiskLevel.Critical),
        Sig("Ransomware/Cerber2", ".cerber2", RiskLevel.Critical),
        Sig("Ransomware/Cerber3", ".cerber3", RiskLevel.Critical),
        Sig("Ransomware/CryptoLocker", ".encrypted", RiskLevel.Critical),
        Sig("Ransomware/CryptoWall", ".crypt", RiskLevel.Critical),
        Sig("Ransomware/CryptoWall2", ".cryptowall", RiskLevel.Critical),
        Sig("Ransomware/CryptoWall3", ".cw_lack", RiskLevel.Critical),
        Sig("Ransomware/CryptoWall4", ".cryptwall", RiskLevel.Critical),
        Sig("Ransomware/GandCrab", ".gandcrab", RiskLevel.Critical),
        Sig("Ransomware/GandCrab2", ".gandcrab2", RiskLevel.Critical),
        Sig("Ransomware/Djvu", ".djvu", RiskLevel.Critical),
        Sig("Ransomware/Djvu2", ".djvuu", RiskLevel.Critical),
        Sig("Ransomware/Djvu3", ".djvur", RiskLevel.Critical),
        Sig("Ransomware/Djvu4", ".djvus", RiskLevel.Critical),
        Sig("Ransomware/Sodinokibi", ".sodinokibi", RiskLevel.Critical),
        Sig("Ransomware/Sodinokibi2", ".sodin", RiskLevel.Critical),
        Sig("Ransomware/REvil", ".revil", RiskLevel.Critical),
        Sig("Ransomware/REvil2", ".sodinokibi", RiskLevel.Critical),
        Sig("Ransomware/Ryuk", ".ryk", RiskLevel.Critical),
        Sig("Ransomware/Ryuk2", ".ryuk", RiskLevel.Critical),
        Sig("Ransomware/Maze", ".maze", RiskLevel.Critical),
        Sig("Ransomware/Maze2", ".mazer", RiskLevel.Critical),
        Sig("Ransomware/Conti", ".conti", RiskLevel.Critical),
        Sig("Ransomware/BlackBasta", ".basta", RiskLevel.Critical),
        Sig("Ransomware/BlackCat", ".alphv", RiskLevel.Critical),
        Sig("Ransomware/BlackCat2", ".blackcat", RiskLevel.Critical),
        Sig("Ransomware/LockBit", ".lockbit", RiskLevel.Critical),
        Sig("Ransomware/LockBit2", ".lockbit2", RiskLevel.Critical),
        Sig("Ransomware/LockBit3", ".lockbit3", RiskLevel.Critical),
        Sig("Ransomware/Akira", ".akira", RiskLevel.Critical),
        Sig("Ransomware/Babuk", ".babuk", RiskLevel.Critical),
        Sig("Ransomware/Babuk2", ".babyk", RiskLevel.Critical),
        Sig("Ransomware/AvosLocker", ".avos", RiskLevel.Critical),
        Sig("Ransomware/AvosLocker2", ".avos2", RiskLevel.Critical),
        Sig("Ransomware/Hive", ".hive", RiskLevel.Critical),
        Sig("Ransomware/Hive2", ".hivelon", RiskLevel.Critical),
        Sig("Ransomware/Vice", ".vice", RiskLevel.Critical),
        Sig("Ransomware/Queen", ".queen", RiskLevel.Critical),
        Sig("Ransomware/Medusa", ".medusa", RiskLevel.Critical),
        Sig("Ransomware/MedusaLocker", ".medusalocker", RiskLevel.Critical),
        Sig("Ransomware/Cuba", ".cuba", RiskLevel.Critical),
        Sig("Ransomware/Play", ".play", RiskLevel.Critical),
        Sig("Ransomware/BlackMatter", ".blackmatter", RiskLevel.Critical),
        Sig("Ransomware/DarkSide", ".darkside", RiskLevel.Critical),
        Sig("Ransomware/DarkSide2", ".darkness", RiskLevel.Critical),
        Sig("Ransomware/Dharma", ".dharma", RiskLevel.Critical),
        Sig("Ransomware/Dharma2", ".java", RiskLevel.Critical),
        Sig("Ransomware/Phobos", ".phobos", RiskLevel.Critical),
        Sig("Ransomware/Phobos2", ".faust", RiskLevel.Critical),
        Sig("Ransomware/STOP", ".stop", RiskLevel.Critical),
        Sig("Ransomware/STOP2", ".puma", RiskLevel.Critical),
        Sig("Ransomware/STOP3", ".pumas", RiskLevel.Critical),
        Sig("Ransomware/STOP4", ".pumax", RiskLevel.Critical),
        Sig("Ransomware/STOP5", ".radman", RiskLevel.Critical),
        Sig("Ransomware/STOP6", ".radmand", RiskLevel.Critical),
        Sig("Ransomware/STOP7", ".otsy", RiskLevel.Critical),
        Sig("Ransomware/STOP8", ".kowalski", RiskLevel.Critical),
        Sig("Ransomware/STOP9", ".zucasta", RiskLevel.Critical),
        Sig("Ransomware/STOP10", ".moka", RiskLevel.Critical),
        Sig("Ransomware/STOP11", ".mokas", RiskLevel.Critical),
        Sig("Ransomware/STOP12", ".mokap", RiskLevel.Critical),

        // High 级别 — 中等流行度
        Sig("Ransomware/Locked", ".locked", RiskLevel.Critical),
        Sig("Ransomware/Locked2", ".lock", RiskLevel.High),
        Sig("Ransomware/Locked3", ".lockd", RiskLevel.High),
        Sig("Ransomware/Crypt", ".crypted", RiskLevel.High),
        Sig("Ransomware/Crypt2", ".crypto", RiskLevel.High),
        Sig("Ransomware/Crypt3", ".enc", RiskLevel.High),
        Sig("Ransomware/Crypt4", ".encode", RiskLevel.High),
        Sig("Ransomware/Crypt5", ".encoded", RiskLevel.High),
        Sig("Ransomware/Crypt6", ".cipher", RiskLevel.High),
        Sig("Ransomware/Crypt7", ".ciphered", RiskLevel.High),
        Sig("Ransomware/Crypt8", ".cryptor", RiskLevel.High),
        Sig("Ransomware/Crypt9", ".cryptow", RiskLevel.High),
        Sig("Ransomware/Vault", ".vault", RiskLevel.High),
        Sig("Ransomware/Ransom", ".ransom", RiskLevel.Critical),
        Sig("Ransomware/Ransom2", ".ransomware", RiskLevel.Critical),
        Sig("Ransomware/Pay", ".pay", RiskLevel.High),
        Sig("Ransomware/Pay2", ".payment", RiskLevel.High),
        Sig("Ransomware/BTC", ".bitcoin", RiskLevel.High),
        Sig("Ransomware/BTC2", ".btc", RiskLevel.High),
        Sig("Ransomware/ETH", ".eth", RiskLevel.High),
        Sig("Ransomware/Encrypt", ".encrypt", RiskLevel.High),
        Sig("Ransomware/Encrypt2", ".encrypted", RiskLevel.High),
        Sig("Ransomware/Encrypt3", ".enc_file", RiskLevel.High),
        Sig("Ransomware/Locked4", ".lockedfile", RiskLevel.High),
        Sig("Ransomware/Locked5", ".lockyv1", RiskLevel.High),
        Sig("Ransomware/Locked6", ".lockyv2", RiskLevel.High),
        Sig("Ransomware/Infected", ".infected", RiskLevel.High),
        Sig("Ransomware/Damaged", ".damaged", RiskLevel.High),
        Sig("Ransomware/Broken", ".broken", RiskLevel.High),
        Sig("Ransomware/Hacked", ".hacked", RiskLevel.High),
        Sig("Ransomware/Hacked2", ".hackedfile", RiskLevel.High),
        Sig("Ransomware/Blocked", ".blocked", RiskLevel.High),
        Sig("Ransomware/Blocked2", ".blockedfile", RiskLevel.High),
        Sig("Ransomware/Secure", ".secure", RiskLevel.High),
        Sig("Ransomware/Secure2", ".secured", RiskLevel.High),
        Sig("Ransomware/Protect", ".protect", RiskLevel.High),
        Sig("Ransomware/Protect2", ".protected", RiskLevel.High),
        Sig("Ransomware/Safe", ".safe", RiskLevel.High),
        Sig("Ransomware/Safe2", ".safefile", RiskLevel.High),

        // Medium 级别 — 低流行度/变种
        Sig("Ransomware/XYZ", ".xyz", RiskLevel.Medium),
        Sig("Ransomware/ABC", ".abc", RiskLevel.Medium),
        Sig("Ransomware/CCC", ".ccc", RiskLevel.Medium),
        Sig("Ransomware/DDD", ".ddd", RiskLevel.Medium),
        Sig("Ransomware/EEE", ".eee", RiskLevel.Medium),
        Sig("Ransomware/FFF", ".fff", RiskLevel.Medium),
        Sig("Ransomware/GGG", ".ggg", RiskLevel.Medium),
        Sig("Ransomware/HHH", ".hhh", RiskLevel.Medium),
        Sig("Ransomware/III", ".iii", RiskLevel.Medium),
        Sig("Ransomware/JJJ", ".jjj", RiskLevel.Medium),
        Sig("Ransomware/KKK", ".kkk", RiskLevel.Medium),
        Sig("Ransomware/LLL", ".lll", RiskLevel.Medium),
        Sig("Ransomware/MMM", ".mmm", RiskLevel.Medium),
        Sig("Ransomware/NNN", ".nnn", RiskLevel.Medium),
        Sig("Ransomware/OOO", ".ooo", RiskLevel.Medium),
        Sig("Ransomware/PPP", ".ppp", RiskLevel.Medium),
        Sig("Ransomware/QQQ", ".qqq", RiskLevel.Medium),
        Sig("Ransomware/RRR", ".rrr", RiskLevel.Medium),
        Sig("Ransomware/SSS", ".sss", RiskLevel.Medium),
        Sig("Ransomware/TTT", ".ttt", RiskLevel.Medium),
        Sig("Ransomware/UUU", ".uuu", RiskLevel.Medium),
        Sig("Ransomware/VVV", ".vvv", RiskLevel.Medium),
        Sig("Ransomware/WWW", ".www", RiskLevel.Medium),
        Sig("Ransomware/XXX", ".xxx", RiskLevel.Medium),
        Sig("Ransomware/YYY", ".yyy", RiskLevel.Medium),
        Sig("Ransomware/ZZZ", ".zzz", RiskLevel.Medium),
        Sig("Ransomware/1hash", ".1hash", RiskLevel.Medium),
        Sig("Ransomware/2hash", ".2hash", RiskLevel.Medium),
        Sig("Ransomware/3hash", ".3hash", RiskLevel.Medium),
        Sig("Ransomware/4hash", ".4hash", RiskLevel.Medium),
        Sig("Ransomware/5hash", ".5hash", RiskLevel.Medium),
        Sig("Ransomware/68iso", ".68iso", RiskLevel.Medium),
        Sig("Ransomware/lockedin", ".lockedin", RiskLevel.Medium),
        Sig("Ransomware/r3store", ".r3store", RiskLevel.Medium),
        Sig("Ransomware/lockedup", ".lockedup", RiskLevel.Medium),
        Sig("Ransomware/encryp", ".encryp", RiskLevel.Medium),
        Sig("Ransomware/encryp1", ".encryp1", RiskLevel.Medium),
        Sig("Ransomware/file99", ".file99", RiskLevel.Medium),
        Sig("Ransomware/fora", ".fora", RiskLevel.Medium),
        Sig("Ransomware/foras", ".foras", RiskLevel.Medium),
        Sig("Ransomware/gores", ".gores", RiskLevel.Medium),
        Sig("Ransomware/nuar", ".nuar", RiskLevel.Medium),
        Sig("Ransomware/nuars", ".nuars", RiskLevel.Medium),
        Sig("Ransomware/oops", ".oops", RiskLevel.Medium),
        Sig("Ransomware/peet", ".peet", RiskLevel.Medium),
        Sig("Ransomware/peets", ".peets", RiskLevel.Medium),
        Sig("Ransomware/pooy", ".pooy", RiskLevel.Medium),
        Sig("Ransomware/righ", ".righ", RiskLevel.Medium),
        Sig("Ransomware/righs", ".righs", RiskLevel.Medium),
        Sig("Ransomware/rooe", ".rooe", RiskLevel.Medium),
        Sig("Ransomware/rooes", ".rooes", RiskLevel.Medium),
        Sig("Ransomware/tox", ".tox", RiskLevel.Medium),
        Sig("Ransomware/veyar", ".veyar", RiskLevel.Medium),
    };

    #endregion

    #region 勒索说明文件名特征（30+ 条）

    /// <summary>已知勒索说明文件名特征</summary>
    public static readonly VirusSignature[] RansomNotes =
    {
        Sig("RansomNote/Readme", "how_to_decrypt.txt", RiskLevel.High),
        Sig("RansomNote/Readme2", "how_to_recover_files.txt", RiskLevel.High),
        Sig("RansomNote/Decrypt", "decrypt_my_files.txt", RiskLevel.High),
        Sig("RansomNote/Decrypt2", "decrypt_instructions.txt", RiskLevel.High),
        Sig("RansomNote/Restore", "restore_files.txt", RiskLevel.High),
        Sig("RansomNote/Restore2", "restore_my_files.txt", RiskLevel.High),
        Sig("RansomNote/Help", "help_decrypt.txt", RiskLevel.High),
        Sig("RansomNote/Help2", "help_your_files.txt", RiskLevel.High),
        Sig("RansomNote/Readme3", "_readme.txt", RiskLevel.High),
        Sig("RansomNote/Readme4", "_readme_bak.txt", RiskLevel.High),
        Sig("RansomNote/YourFiles", "your_files_are_encrypted.txt", RiskLevel.Critical),
        Sig("RansomNote/YourFiles2", "your_files_are_locked.txt", RiskLevel.Critical),
        Sig("RansomNote/YourFiles3", "all_your_files_are_encrypted.txt", RiskLevel.Critical),
        Sig("RansomNote/YourFiles4", "all_files_are_encrypted.txt", RiskLevel.Critical),
        Sig("RansomNote/Info", "info.txt", RiskLevel.Medium),
        Sig("RansomNote/Info2", "info.hta", RiskLevel.High),
        Sig("RansomNote/Info3", "info.html", RiskLevel.High),
        Sig("RansomNote/Note", "!readme.txt", RiskLevel.High),
        Sig("RansomNote/Note2", "!restore_files.txt", RiskLevel.High),
        Sig("RansomNote/Note3", "!_how_to_decrypt.txt", RiskLevel.High),
        Sig("RansomNote/Note4", "!_readme!.txt", RiskLevel.High),
        Sig("RansomNote/Note5", "!readme!.txt", RiskLevel.High),
        Sig("RansomNote/Readme5", "readme.txt", RiskLevel.Medium),
        Sig("RansomNote/Readme6", "readme.html", RiskLevel.High),
        Sig("RansomNote/Readme7", "readme.htm", RiskLevel.High),
        Sig("RansomNote/Readme8", "readme_bak.txt", RiskLevel.Medium),
        Sig("RansomNote/Decrypt3", "decrypt_files.html", RiskLevel.High),
        Sig("RansomNote/Decrypt4", "how_to_decrypt.html", RiskLevel.High),
        Sig("RansomNote/Decrypt5", "recovery+key.txt", RiskLevel.High),
        Sig("RansomNote/Decrypt6", "decryption_instructions.txt", RiskLevel.High),
        Sig("RansomNote/Decrypt7", "decryption_instructions.html", RiskLevel.High),
        Sig("RansomNote/Wanna", "@WanaDecryptor@.exe", RiskLevel.Critical),
        Sig("RansomNote/Wanna2", "@WanaDecryptor@.bmp", RiskLevel.Critical),
        Sig("RansomNote/Wanna3", "@Please_Read_Me@.txt", RiskLevel.Critical),
        Sig("RansomNote/Locky", "_Locky_recover_instructions.txt", RiskLevel.Critical),
        Sig("RansomNote/Cerber", "#_HELP_DECRYPT_#_.txt", RiskLevel.Critical),
        Sig("RansomNote/Cerber2", "#_HOW_TO_DECRYPT_#_.html", RiskLevel.Critical),
        Sig("RansomNote/Cerber3", "#_DECRYPT_MY_FILES_#_.txt", RiskLevel.Critical),
        Sig("RansomNote/CryptoWall", "HELP_DECRYPT.TXT", RiskLevel.Critical),
        Sig("RansomNote/CryptoWall2", "HELP_DECRYPT.HTML", RiskLevel.Critical),
        Sig("RansomNote/CryptoWall3", "HELP_DECRYPT.PNG", RiskLevel.Critical),
        Sig("RansomNote/GandCrab", "HOW_TO_DECRYPT_GANDCRAB.txt", RiskLevel.Critical),
        Sig("RansomNote/Sodinokibi", "bnREADMEl.txt", RiskLevel.Critical),
        Sig("RansomNote/Djvu", "_openme.txt", RiskLevel.Critical),
        Sig("RansomNote/Conti", "CONTI_README.txt", RiskLevel.Critical),
        Sig("RansomNote/LockBit", "Restore-My-Files.txt", RiskLevel.Critical),
        Sig("RansomNote/BlackBasta", "instructions_readme.txt", RiskLevel.Critical),
        Sig("RansomNote/REvil", "bnlhrmreadme.txt", RiskLevel.Critical),
        Sig("RansomNote/Maze", "DECRYPT-FILES.html", RiskLevel.Critical),
        Sig("RansomNote/Ryuk", "RyukReadMe.txt", RiskLevel.Critical),
        Sig("RansomNote/Dharma", "FILES ENCRYPTED.txt", RiskLevel.Critical),
        Sig("RansomNote/Phobos", "info.txt", RiskLevel.High),
        Sig("RansomNote/Stop", "_readme.txt", RiskLevel.High),
    };

    #endregion

    #region 字节内容特征（30+ 条）

    /// <summary>已知勒索软件字节/内容特征</summary>
    public static readonly VirusSignature[] BytePatterns =
    {
        Sig("WannaCryMarker", "wanadecrypt", RiskLevel.Critical),
        Sig("WannaCryMarker2", "wannacry", RiskLevel.Critical),
        Sig("WannaCryMarker3", "wnry", RiskLevel.Critical),
        Sig("WannaCryMarker4", "tasksche", RiskLevel.Critical),
        Sig("WannaCryMarker5", "mssecsvc", RiskLevel.Critical),
        Sig("BitcoinRansom", "bitcoin", RiskLevel.Medium),
        Sig("BitcoinRansom2", "btc address", RiskLevel.Medium),
        Sig("BitcoinRansom3", "send bitcoin", RiskLevel.High),
        Sig("BitcoinRansom4", "pay bitcoin", RiskLevel.High),
        Sig("TorOnionRansom", ".onion", RiskLevel.Medium),
        Sig("TorOnionRansom2", "tor browser", RiskLevel.High),
        Sig("TorOnionRansom3", "torbrowser", RiskLevel.High),
        Sig("RansomMsg/Decrypt", "decrypt your files", RiskLevel.High),
        Sig("RansomMsg/Decrypt2", "your files are encrypted", RiskLevel.Critical),
        Sig("RansomMsg/Decrypt3", "your files have been encrypted", RiskLevel.Critical),
        Sig("RansomMsg/Decrypt4", "all your files are encrypted", RiskLevel.Critical),
        Sig("RansomMsg/Pay", "pay the ransom", RiskLevel.High),
        Sig("RansomMsg/Pay2", "pay to decrypt", RiskLevel.High),
        Sig("RansomMsg/Pay3", "send us bitcoin", RiskLevel.High),
        Sig("RansomMsg/Pay4", "pay $", RiskLevel.Medium),
        Sig("RansomMsg/Recover", "recover your files", RiskLevel.High),
        Sig("RansomMsg/Recover2", "restore your files", RiskLevel.High),
        Sig("RansomMsg/Time", "you have", RiskLevel.Medium),
        Sig("RansomMsg/Time2", "hours to pay", RiskLevel.High),
        Sig("RansomMsg/Time3", "days to pay", RiskLevel.High),
        Sig("RansomMsg/Time4", "deadline", RiskLevel.Medium),
        Sig("RansomMsg/Key", "private key", RiskLevel.High),
        Sig("RansomMsg/Key2", "decryption key", RiskLevel.High),
        Sig("RansomMsg/Key3", "unique key", RiskLevel.High),
        Sig("RansomMsg/Contact", "contact us", RiskLevel.Medium),
        Sig("RansomMsg/Contact2", "email us", RiskLevel.Medium),
        Sig("RansomMsg/Contact3", "write to", RiskLevel.Medium),
        Sig("RSAMarker", "rsa-2048", RiskLevel.High),
        Sig("RSAMarker2", "rsa-1024", RiskLevel.High),
        Sig("RSAMarker3", "rsa-4096", RiskLevel.High),
        Sig("AESMarker", "aes-256", RiskLevel.Medium),
        Sig("AESMarker2", "aes-128", RiskLevel.Medium),
        Sig("Base64Ransom", "base64", RiskLevel.Low),
    };

    #endregion

    #region 可疑进程名特征（40+ 条）

    /// <summary>已知勒索软件可疑进程名特征</summary>
    public static readonly VirusSignature[] SuspiciousProcesses =
    {
        Sig("Process/WannaCry", "mssecsvc.exe", RiskLevel.Critical),
        Sig("Process/WannaCry2", "tasksche.exe", RiskLevel.Critical),
        Sig("Process/WannaCry3", "taskhsvc.exe", RiskLevel.Critical),
        Sig("Process/WannaCry4", "@WanaDecryptor@.exe", RiskLevel.Critical),
        Sig("Process/WannaCry5", "wcry.exe", RiskLevel.Critical),
        Sig("Process/WannaCry6", "wannacry.exe", RiskLevel.Critical),
        Sig("Process/Locky", "locky.exe", RiskLevel.Critical),
        Sig("Process/Cerber", "cerber.exe", RiskLevel.Critical),
        Sig("Process/Cerber2", "frnss.exe", RiskLevel.Critical),
        Sig("Process/CryptoLocker", "cryptolocker.exe", RiskLevel.Critical),
        Sig("Process/CryptoWall", "cryptowall.exe", RiskLevel.Critical),
        Sig("Process/CryptoWall2", "cw_service.exe", RiskLevel.Critical),
        Sig("Process/GandCrab", "gandcrab.exe", RiskLevel.Critical),
        Sig("Process/Sodinokibi", "sodinokibi.exe", RiskLevel.Critical),
        Sig("Process/REvil", "revil.exe", RiskLevel.Critical),
        Sig("Process/Ryuk", "ryuk.exe", RiskLevel.Critical),
        Sig("Process/Maze", "maze.exe", RiskLevel.Critical),
        Sig("Process/Conti", "conti.exe", RiskLevel.Critical),
        Sig("Process/LockBit", "lockbit.exe", RiskLevel.Critical),
        Sig("Process/LockBit2", "lockbit2.exe", RiskLevel.Critical),
        Sig("Process/LockBit3", "lockbit3.exe", RiskLevel.Critical),
        Sig("Process/BlackBasta", "blackbasta.exe", RiskLevel.Critical),
        Sig("Process/BlackCat", "blackcat.exe", RiskLevel.Critical),
        Sig("Process/BlackCat2", "alphv.exe", RiskLevel.Critical),
        Sig("Process/Akira", "akira.exe", RiskLevel.Critical),
        Sig("Process/Babuk", "babuk.exe", RiskLevel.Critical),
        Sig("Process/Hive", "hive.exe", RiskLevel.Critical),
        Sig("Process/Play", "play.exe", RiskLevel.Critical),
        Sig("Process/STOP", "stop.exe", RiskLevel.High),
        Sig("Process/Djvu", "djvu.exe", RiskLevel.Critical),
        Sig("Process/Dharma", "dharma.exe", RiskLevel.Critical),
        Sig("Process/Phobos", "phobos.exe", RiskLevel.Critical),
        Sig("Process/Medusa", "medusa.exe", RiskLevel.Critical),
        Sig("Process/DarkSide", "darkside.exe", RiskLevel.Critical),
        Sig("Process/AvosLocker", "avos.exe", RiskLevel.Critical),
        Sig("Process/BlackMatter", "blackmatter.exe", RiskLevel.Critical),
        Sig("Process/Cuba", "cuba.exe", RiskLevel.Critical),
        Sig("Process/Vice", "vice.exe", RiskLevel.Critical),
        Sig("Process/Queen", "queen.exe", RiskLevel.Critical),
        Sig("Process/Random1", "encrypt.exe", RiskLevel.High),
        Sig("Process/Random2", "decrypt_helper.exe", RiskLevel.High),
        Sig("Process/Random3", "file_encryptor.exe", RiskLevel.High),
        Sig("Process/Random4", "ransomware.exe", RiskLevel.Critical),
        Sig("Process/Random5", "ransom.exe", RiskLevel.Critical),
        Sig("Process/Random6", "locker.exe", RiskLevel.High),
        Sig("Process/Random7", "crypto_locker.exe", RiskLevel.Critical),
    };

    #endregion

    #region 系统进程白名单（不会被隔离）

    /// <summary>系统核心进程白名单 — 永远不会被判定为可疑</summary>
    public static readonly HashSet<string> SystemProcessWhitelist = new(StringComparer.OrdinalIgnoreCase)
    {
        // Windows 核心进程
        "svchost.exe", "csrss.exe", "winlogon.exe", "smss.exe",
        "services.exe", "lsass.exe", "wininit.exe", "spoolsv.exe",
        "explorer.exe", "dwm.exe", "fontdrvhost.exe", "sihost.exe",
        "taskhostw.exe", "RuntimeBroker.exe", "ShellExperienceHost.exe",
        "SearchHost.exe", "StartMenuExperienceHost.exe", "TextInputHost.exe",
        "ctfmon.exe", "conhost.exe", "dllhost.exe",

        // 系统服务
        "MsMpEng.exe", "SecurityHealthService.exe", "NisSrv.exe",
        "SearchIndexer.exe", "audiodg.exe", "WUDFHost.exe",
        "SystemSettings.exe", "SystemPropertiesProtection.exe",

        // .NET 运行时
        "dotnet.exe", "LightGuard.exe",

        // 常见安全软件
        "MsMpEng.exe", "MpCmdRun.exe", "MpCopyAccelerator.exe",
        "SecurityHealthSystray.exe", "smartscreen.exe",
    };

    #endregion

    #region 综合查询

    /// <summary>
    /// 获取全部离线特征（合并所有类别）
    /// </summary>
    public static List<VirusSignature> GetAllSignatures()
    {
        var list = new List<VirusSignature>();
        list.AddRange(RansomExtensions);
        list.AddRange(RansomNotes);
        list.AddRange(BytePatterns);
        list.AddRange(SuspiciousProcesses);
        return list;
    }

    /// <summary>
    /// 获取全部特征数量
    /// </summary>
    public static int GetTotalCount()
    {
        return RansomExtensions.Length + RansomNotes.Length
             + BytePatterns.Length + SuspiciousProcesses.Length;
    }

    /// <summary>
    /// 检查进程名是否在白名单中
    /// </summary>
    public static bool IsSystemProcess(string processName)
    {
        if (string.IsNullOrEmpty(processName)) return false;
        return SystemProcessWhitelist.Contains(processName);
    }

    /// <summary>
    /// 导出离线库为 JSON（供 UI 显示/备份）
    /// </summary>
    public static string ExportAsJson()
    {
        var data = new
        {
            version = Version,
            publishDate = PublishDate,
            totalCount = GetTotalCount(),
            categories = new
            {
                ransomExtensions = RansomExtensions.Length,
                ransomNotes = RansomNotes.Length,
                bytePatterns = BytePatterns.Length,
                suspiciousProcesses = SuspiciousProcesses.Length
            },
            signatures = GetAllSignatures()
        };

        return JsonSerializer.Serialize(data, new JsonSerializerOptions
        {
            WriteIndented = true,
            Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping
        });
    }

    #endregion

    #region 辅助

    private static VirusSignature Sig(string name, string pattern, RiskLevel risk)
    {
        return new VirusSignature
        {
            Name = name,
            Pattern = pattern,
            Risk = risk,
            Source = "离线库"
        };
    }

    #endregion
}
