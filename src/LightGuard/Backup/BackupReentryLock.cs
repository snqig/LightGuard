// © 2026 落尘（Luochen） 原创开发 - 保留所有权利
//
// 任务防重入锁（v3.5 P0-1）
//   - 文件备份任务锁 + 数据库实例独立备份锁统一由本类管理
//   - 任务运行中，定时触发 TryEnter 失败 → 直接跳过（防止并发冲突）
//   - 线程安全：ConcurrentDictionary<string, int> + Interlocked

using System.Collections.Concurrent;

namespace LightGuard.Backup;

/// <summary>
/// 备份任务防重入锁。
/// <para>用法：任务执行前 TryEnter(taskKey)，执行完毕 finally 中 Exit(taskKey)。</para>
/// <para>taskKey 约定：文件任务用任务名；数据库实例用 "db:{实例名}"。</para>
/// </summary>
public sealed class BackupReentryLock
{
    private readonly ConcurrentDictionary<string, int> _running = new();

    /// <summary>
    /// 尝试获取任务锁。
    /// </summary>
    /// <param name="taskKey">任务唯一键。</param>
    /// <returns>成功获取返回 true；任务正在运行返回 false（调用方应跳过本次触发）。</returns>
    public bool TryEnter(string taskKey)
    {
        ArgumentException.ThrowIfNullOrEmpty(taskKey);
        // 原子自增：1 表示本线程持有
        var count = _running.AddOrUpdate(taskKey, 1, (_, existing) => existing + 1);
        if (count > 1)
        {
            // 已有任务在运行，回退计数并返回失败
            _running.AddOrUpdate(taskKey, 0, (_, existing) => Math.Max(0, existing - 1));
            return false;
        }
        return true;
    }

    /// <summary>释放任务锁。</summary>
    public void Exit(string taskKey)
    {
        if (string.IsNullOrEmpty(taskKey)) return;
        _running.AddOrUpdate(taskKey, 0, (_, existing) => Math.Max(0, existing - 1));
        if (_running.TryGetValue(taskKey, out var count) && count <= 0)
            _running.TryRemove(taskKey, out _);
    }

    /// <summary>任务是否正在运行。</summary>
    public bool IsRunning(string taskKey)
        => !string.IsNullOrEmpty(taskKey) && _running.TryGetValue(taskKey, out var count) && count > 0;

    /// <summary>当前运行中的任务键列表。</summary>
    public IReadOnlyCollection<string> RunningKeys => _running.Keys.ToList();
}
