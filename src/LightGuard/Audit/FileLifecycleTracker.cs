// © 2026 落尘（Luochen） 原创开发 - 保留所有权利

using System.Collections.Concurrent;
using System.Text.RegularExpressions;
using LightGuard.Core;

namespace LightGuard.Audit;

/// <summary>
/// 文件生命周期追踪器
/// <para>追踪文件完整生命周期：创建 → 读取 → 写入 → 重命名 → 删除。</para>
/// <para>检测文件外发行为：拷贝到 USB、网络共享、不同驱动器等外部路径。</para>
/// <para>使用 ConcurrentDictionary 线程安全内存追踪。</para>
/// </summary>
public sealed class FileLifecycleTracker
{
    #region 字段

    private readonly ConcurrentDictionary<string, FileLifecycle> _lifecycles = new();
    private readonly object _cleanupLock = new();

    #endregion

    #region 公开方法

    /// <summary>
    /// 记录审计事件，更新文件生命周期状态
    /// <para>根据事件动作（Create/Read/Write/Delete/Rename）更新对应的生命周期字段。</para>
    /// </summary>
    /// <param name="evt">SMB 审计事件</param>
    public void RecordEvent(SmbAuditEvent evt)
    {
        if (evt == null || string.IsNullOrEmpty(evt.FilePath)) return;

        var filePath = NormalizePath(evt.FilePath);
        var action = (evt.Action ?? "").Trim();

        _lifecycles.AddOrUpdate(
            filePath,
            // 新文件生命周期
            _ => CreateLifecycle(evt, filePath, action),
            // 更新已有生命周期
            (_, existing) => UpdateLifecycle(existing, evt, action));

        // 检测外发行为
        CheckExternalTransfer(filePath, evt);
    }

    /// <summary>
    /// 获取指定文件的完整生命周期
    /// </summary>
    /// <param name="filePath">文件路径</param>
    /// <returns>生命周期记录，不存在则返回 null</returns>
    public FileLifecycle? GetLifecycle(string filePath)
    {
        if (string.IsNullOrEmpty(filePath)) return null;
        var normalized = NormalizePath(filePath);
        return _lifecycles.TryGetValue(normalized, out var lifecycle) ? lifecycle : null;
    }

    /// <summary>
    /// 获取指定用户操作过的所有文件生命周期
    /// <para>匹配条件：创建者、最后访问者、修改记录中的操作者、删除者。</para>
    /// </summary>
    /// <param name="userName">用户名</param>
    /// <returns>该用户触及的所有文件生命周期列表</returns>
    public List<FileLifecycle> GetLifecyclesByUser(string userName)
    {
        if (string.IsNullOrEmpty(userName)) return new List<FileLifecycle>();

        return _lifecycles.Values
            .Where(lc => lc.CreatedBy.Equals(userName, StringComparison.OrdinalIgnoreCase) ||
                         lc.LastAccessedBy.Equals(userName, StringComparison.OrdinalIgnoreCase) ||
                         lc.ModifiedHistory.Any(m =>
                             m.UserName.Equals(userName, StringComparison.OrdinalIgnoreCase)) ||
                         (lc.DeletedBy != null &&
                          lc.DeletedBy.Equals(userName, StringComparison.OrdinalIgnoreCase)))
            .ToList();
    }

    /// <summary>
    /// 检测外发文件：被拷贝到外部路径（USB、网络共享、不同驱动器）的文件
    /// </summary>
    /// <returns>标记为外发传输的文件生命周期列表</returns>
    public List<FileLifecycle> GetExternalTransfers()
    {
        return _lifecycles.Values
            .Where(lc => lc.IsExternalTransfer)
            .ToList();
    }

    /// <summary>
    /// 清理超过指定时间的旧生命周期记录
    /// <para>清理条件：最后访问时间超过指定时长，且文件已删除（或删除时间也超时）。</para>
    /// </summary>
    /// <param name="age">最大保留时长</param>
    public void PurgeOlderThan(TimeSpan age)
    {
        var cutoff = DateTime.Now - age;

        lock (_cleanupLock)
        {
            var keysToRemove = _lifecycles
                .Where(kvp => kvp.Value.LastAccessedAt < cutoff &&
                              (kvp.Value.DeletedAt == null || kvp.Value.DeletedAt < cutoff))
                .Select(kvp => kvp.Key)
                .ToList();

            foreach (var key in keysToRemove)
            {
                _lifecycles.TryRemove(key, out _);
            }

            if (keysToRemove.Count > 0)
            {
                ErrorReporter.Log(
                    $"[FileLifecycleTracker] 清理旧记录: 删除 {keysToRemove.Count} 条, " +
                    $"剩余 {_lifecycles.Count} 条");
            }
        }
    }

    /// <summary>
    /// 获取所有追踪中的文件生命周期数量
    /// </summary>
    public int Count => _lifecycles.Count;

    /// <summary>
    /// 获取所有追踪中的文件生命周期
    /// </summary>
    public List<FileLifecycle> GetAll()
    {
        return _lifecycles.Values.ToList();
    }

    #endregion

    #region 私有方法 - 生命周期更新

    /// <summary>
    /// 创建新的文件生命周期记录
    /// </summary>
    private static FileLifecycle CreateLifecycle(SmbAuditEvent evt, string filePath, string action)
    {
        var lifecycle = new FileLifecycle
        {
            FilePath = filePath,
            CreatedAt = evt.Timestamp,
            CreatedBy = evt.UserName,
            LastAccessedAt = evt.Timestamp,
            LastAccessedBy = evt.UserName
        };

        ApplyAction(lifecycle, evt, action);
        return lifecycle;
    }

    /// <summary>
    /// 更新已有文件生命周期记录
    /// </summary>
    private static FileLifecycle UpdateLifecycle(FileLifecycle existing, SmbAuditEvent evt, string action)
    {
        existing.LastAccessedAt = evt.Timestamp;
        existing.LastAccessedBy = evt.UserName;

        ApplyAction(existing, evt, action);
        return existing;
    }

    /// <summary>
    /// 根据事件动作更新生命周期状态
    /// <para>支持：Create/创建、Write/Modify/写入/修改、Rename/Move/重命名/移动、Delete/删除</para>
    /// </summary>
    private static void ApplyAction(FileLifecycle lifecycle, SmbAuditEvent evt, string action)
    {
        var lowerAction = action.ToLowerInvariant();

        // 创建
        if (lowerAction.Contains("create") || lowerAction.Contains("创建"))
        {
            lifecycle.CreatedAt = evt.Timestamp;
            lifecycle.CreatedBy = evt.UserName;
        }

        // 写入/修改
        if (lowerAction.Contains("write") || lowerAction.Contains("modify") ||
            lowerAction.Contains("写入") || lowerAction.Contains("修改"))
        {
            var currentSize = TryGetFileSize(lifecycle.FilePath);
            lifecycle.ModifiedHistory.Add(new FileModifyRecord
            {
                Timestamp = evt.Timestamp,
                UserName = evt.UserName,
                Action = action,
                OldSize = currentSize,
                NewSize = currentSize // 实际大小需后续读取，此处简化
            });
        }

        // 重命名/移动
        if (lowerAction.Contains("rename") || lowerAction.Contains("move") ||
            lowerAction.Contains("重命名") || lowerAction.Contains("移动"))
        {
            // 从 RawEvent 中尝试提取原路径
            if (!string.IsNullOrEmpty(evt.RawEvent))
            {
                lifecycle.RenamedFrom = evt.RawEvent;
            }
        }

        // 删除
        if (lowerAction.Contains("delete") || lowerAction.Contains("删除"))
        {
            lifecycle.DeletedAt = evt.Timestamp;
            lifecycle.DeletedBy = evt.UserName;
        }
    }

    #endregion

    #region 私有方法 - 外发检测

    /// <summary>
    /// 检测外部传输行为
    /// <para>检查事件路径是否为外部路径（不同驱动器、USB、网络共享）。</para>
    /// <para>同时检查 RawEvent 中是否包含外部目标路径。</para>
    /// </summary>
    private void CheckExternalTransfer(string filePath, SmbAuditEvent evt)
    {
        try
        {
            var action = (evt.Action ?? "").ToLowerInvariant();

            // 检测写/创建/复制/传输操作到外部路径
            if (action.Contains("write") || action.Contains("create") ||
                action.Contains("copy") || action.Contains("transfer") ||
                action.Contains("写入") || action.Contains("创建") ||
                action.Contains("复制") || action.Contains("传输"))
            {
                if (IsExternalPath(evt.FilePath))
                {
                    if (_lifecycles.TryGetValue(filePath, out var lifecycle))
                    {
                        lifecycle.IsExternalTransfer = true;
                        lifecycle.TransferDestination = evt.FilePath;
                    }
                }
            }

            // 检查 RawEvent 中是否包含目标路径信息
            if (!string.IsNullOrEmpty(evt.RawEvent))
            {
                var possiblePaths = ExtractPaths(evt.RawEvent);
                foreach (var path in possiblePaths)
                {
                    if (IsExternalPath(path) &&
                        _lifecycles.TryGetValue(filePath, out var lifecycle))
                    {
                        lifecycle.IsExternalTransfer = true;
                        lifecycle.TransferDestination = path;
                        break;
                    }
                }
            }
        }
        catch (Exception ex)
        {
            ErrorReporter.Report(ex, "[FileLifecycleTracker] CheckExternalTransfer 异常");
        }
    }

    /// <summary>
    /// 判断路径是否为外部路径（不同驱动器或网络共享）
    /// <para>外部路径判定：</para>
    /// <para>1. UNC 路径（\\server\share）</para>
    /// <para>2. 可移动驱动器（USB）</para>
    /// <para>3. 网络驱动器</para>
    /// <para>4. 光驱</para>
    /// </summary>
    private static bool IsExternalPath(string path)
    {
        if (string.IsNullOrEmpty(path)) return false;

        try
        {
            // 网络共享路径（UNC 路径）
            if (path.StartsWith(@"\\", StringComparison.Ordinal))
                return true;

            // 获取路径的根目录（驱动器号）
            var root = Path.GetPathRoot(path);
            if (string.IsNullOrEmpty(root)) return false;

            // 获取系统驱动器
            var systemRoot = Path.GetPathRoot(Environment.SystemDirectory);
            if (string.IsNullOrEmpty(systemRoot)) return false;

            // 驱动器号不同时检查驱动器类型
            if (!root.Equals(systemRoot, StringComparison.OrdinalIgnoreCase))
            {
                var driveInfo = new DriveInfo(root);
                if (driveInfo.DriveType == DriveType.Removable ||
                    driveInfo.DriveType == DriveType.Network ||
                    driveInfo.DriveType == DriveType.CDRom)
                {
                    return true;
                }
            }

            return false;
        }
        catch
        {
            // 路径解析失败，保守判断：UNC 路径视为外部
            return path.StartsWith(@"\\", StringComparison.Ordinal);
        }
    }

    /// <summary>
    /// 从文本中提取可能的文件路径
    /// <para>匹配模式：驱动器路径（C:\...）和 UNC 路径（\\server\...）</para>
    /// </summary>
    private static List<string> ExtractPaths(string text)
    {
        var paths = new List<string>();
        if (string.IsNullOrEmpty(text)) return paths;

        // 匹配 Windows 路径模式
        var pattern = @"[A-Za-z]:\\[^\s""<>|*?]+|\\\\[^\s""<>|*?]+";
        var matches = Regex.Matches(text, pattern);
        foreach (Match match in matches)
        {
            paths.Add(match.Value);
        }

        return paths;
    }

    /// <summary>
    /// 尝试获取文件当前大小
    /// </summary>
    private static long? TryGetFileSize(string filePath)
    {
        try
        {
            if (File.Exists(filePath))
                return new FileInfo(filePath).Length;
        }
        catch { }

        return null;
    }

    /// <summary>
    /// 规范化文件路径（统一为全大写、去除末尾分隔符）
    /// <para>用于 ConcurrentDictionary 的键，确保同一路径只对应一条生命周期记录。</para>
    /// </summary>
    private static string NormalizePath(string path)
    {
        if (string.IsNullOrEmpty(path)) return "";

        try
        {
            var full = Path.GetFullPath(path);
            return full.TrimEnd('\\', '/').ToUpperInvariant();
        }
        catch
        {
            return path.TrimEnd('\\', '/').ToUpperInvariant();
        }
    }

    #endregion
}

#region 数据类型

/// <summary>
/// 文件生命周期记录
/// <para>记录文件从创建到删除的完整操作历史。</para>
/// </summary>
public sealed class FileLifecycle
{
    /// <summary>文件路径（规范化后的全路径）</summary>
    public string FilePath { get; set; } = "";

    /// <summary>创建时间</summary>
    public DateTime CreatedAt { get; set; }

    /// <summary>创建者用户名</summary>
    public string CreatedBy { get; set; } = "";

    /// <summary>最后访问时间</summary>
    public DateTime LastAccessedAt { get; set; }

    /// <summary>最后访问者用户名</summary>
    public string LastAccessedBy { get; set; } = "";

    /// <summary>修改历史记录列表</summary>
    public List<FileModifyRecord> ModifiedHistory { get; set; } = new();

    /// <summary>重命名前的原路径（如有）</summary>
    public string RenamedFrom { get; set; } = "";

    /// <summary>删除时间（null 表示尚未删除）</summary>
    public DateTime? DeletedAt { get; set; }

    /// <summary>删除者用户名</summary>
    public string DeletedBy { get; set; } = "";

    /// <summary>是否被标记为外部传输（拷贝到 USB/网络共享等）</summary>
    public bool IsExternalTransfer { get; set; }

    /// <summary>外发传输的目标路径</summary>
    public string TransferDestination { get; set; } = "";

    public override string ToString()
    {
        var status = DeletedAt.HasValue ? "已删除" : "活跃";
        var transfer = IsExternalTransfer ? " [外发]" : "";
        return $"[{status}{transfer}] {FilePath} | " +
               $"创建: {CreatedBy} {CreatedAt:yyyy-MM-dd HH:mm} | " +
               $"修改次数: {ModifiedHistory.Count} | " +
               $"最后访问: {LastAccessedBy} {LastAccessedAt:yyyy-MM-dd HH:mm}";
    }
}

/// <summary>
/// 文件修改记录
/// </summary>
public sealed class FileModifyRecord
{
    /// <summary>修改时间戳</summary>
    public DateTime Timestamp { get; set; }

    /// <summary>操作用户名</summary>
    public string UserName { get; set; } = "";

    /// <summary>操作动作</summary>
    public string Action { get; set; } = "";

    /// <summary>修改前文件大小（字节，null 表示未知）</summary>
    public long? OldSize { get; set; }

    /// <summary>修改后文件大小（字节，null 表示未知）</summary>
    public long? NewSize { get; set; }

    public override string ToString()
    {
        return $"[{Timestamp:HH:mm:ss}] {UserName} | {Action} | {OldSize}->{NewSize}";
    }
}

#endregion
