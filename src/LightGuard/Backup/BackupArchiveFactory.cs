// © 2026 落尘（Luochen） 原创开发 - 保留所有权利

using System.Text;

namespace LightGuard.Backup;

/// <summary>
/// 备份归档统一入口（全局规范 1：所有存储读写必须经 IBackupArchive，禁止绕过私有封装）。
/// <para>v3 私有容器 → <see cref="V3PrivateContainerArchive"/>；</para>
/// <para>旧格式 v1（AES 分片）→ 只读适配器（P0-3 提供，当前 Open 抛明确提示）。</para>
/// </summary>
public static class BackupArchiveFactory
{
    /// <summary>
    /// 嗅探备份包格式（读取魔数，不加载内容）。
    /// </summary>
    public static BackupArchiveFormat DetectFormat(string path)
    {
        if (string.IsNullOrEmpty(path) || !File.Exists(path))
            throw new FileNotFoundException("备份包不存在。", path);

        using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        var head = new byte[9];
        int read = fs.Read(head, 0, head.Length);
        if (read < 6) throw new InvalidDataException("文件过短，无法识别备份格式。");

        // v3 私有容器魔数 "LGBK3\x01"
        if (head.AsSpan(0, V3PrivateContainerArchive.Magic.Length).SequenceEqual(V3PrivateContainerArchive.Magic))
            return BackupArchiveFormat.V3PrivateContainer;

        // v1 旧格式魔数 "LGBACKUP\x01"
        var v1Magic = LgBackupFormat.Magic;
        if (head.AsSpan(0, v1Magic.Length).SequenceEqual(v1Magic))
            return BackupArchiveFormat.V1LegacySharded;

        throw new InvalidDataException("无法识别的备份包格式（魔数不匹配），可能已被篡改或非 LightGuard 备份。");
    }

    /// <summary>
    /// 创建新的 v3 私有容器（新写备份）。
    /// </summary>
    /// <param name="path">目标 .lgbackup 路径。</param>
    /// <param name="password">备份口令（不允许为空）。</param>
    /// <param name="options">写入参数。</param>
    /// <param name="metadata">容器级元数据（增量游标 / 策略标记等，可选）。</param>
    /// <returns>可写归档实例。</returns>
    public static IBackupArchive Create(string path, string password, BackupArchiveOptions options,
        Dictionary<string, string>? metadata = null)
        => V3PrivateContainerArchive.Create(path, password, options, metadata);

    /// <summary>
    /// 打开既有备份包（浏览 / 校验 / 还原）。
    /// <para>v3 私有容器 → <see cref="V3PrivateContainerArchive"/>；旧格式 v1 → <see cref="V1LegacyArchiveAdapter"/>（只读）。</para>
    /// </summary>
    /// <param name="path">备份包路径。</param>
    /// <param name="password">备份口令。</param>
    /// <returns>归档实例。</returns>
    public static IBackupArchive Open(string path, string password)
    {
        var format = DetectFormat(path);
        return format switch
        {
            BackupArchiveFormat.V3PrivateContainer => V3PrivateContainerArchive.Open(path, password),
            BackupArchiveFormat.V1LegacySharded => V1LegacyArchiveAdapter.Open(path, password),
            _ => throw new NotSupportedException("未知备份格式。")
        };
    }
}
