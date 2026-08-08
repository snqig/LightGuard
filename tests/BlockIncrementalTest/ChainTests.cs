// © 2026 落尘（Luochen） 原创开发 - 保留所有权利
//
// 增量链合并与版本点恢复测试（P0：时间快照链）：
//   1. 链加载：乱序增量包按备份时间排序、版本编号正确
//   2. 版本点恢复：基础包(版本0) / 第1增量后 / 第2增量后 三个时间点内容一致
//   3. 时间点恢复：目标时间落在链中某区间 → 命中对应版本
//   4. 链合并：基础包 + 增量链 → 新全量包内容 == 最新版本，且可继续作为下一轮增量基准

using System.Security.Cryptography;
using System.Text;
using LightGuard.Backup;

namespace BlockIncrementalTest;

/// <summary>
/// 增量链合并与版本点恢复测试执行器。
/// </summary>
internal sealed class ChainTests
{
    private const string Password = "ChainTest@2026";
    private const int Chunk = 512;

    private static int _passed;
    private static int _failed;

    private static void Assert(bool condition, string name)
    {
        if (condition)
        {
            _passed++;
            Console.WriteLine($"  [PASS] {name}");
        }
        else
        {
            _failed++;
            Console.WriteLine($"  [FAIL] {name}");
        }
    }

    private static void Section(string title)
    {
        Console.WriteLine();
        Console.WriteLine($"===== {title} =====");
    }

    private static byte[] Rep(int value, int len) => Enumerable.Repeat((byte)value, len).ToArray();

    /// <summary>修改数据前 n 字节为指定值（返回新数组）。</summary>
    private static byte[] WithPrefix(byte[] src, int prefixBytes, byte value)
    {
        var dst = (byte[])src.Clone();
        Array.Fill(dst, value, 0, prefixBytes);
        return dst;
    }

    private static BackupArchiveOptions MakeOptions(string sourceDir)
        => new() { SourcePath = sourceDir, CompressionLevel = 1, ChunkSize = Chunk };

    /// <summary>写基础包（Chunked）。</summary>
    private static async Task<string> WriteBaseAsync(string dir, string name, IReadOnlyDictionary<string, byte[]> files)
    {
        var path = Path.Combine(dir, name);
        var options = new BackupArchiveOptions
        {
            SourcePath = dir, CompressionLevel = 1,
            CompressionMode = BackupArchiveCompressionMode.Chunked,
            ChunkSize = Chunk, EncryptFileNames = false
        };
        using var archive = BackupArchiveFactory.Create(path, Password, options);
        var now = DateTime.Now;
        await archive.WriteAsync(files.Select(kv => (kv.Key, (Stream)new MemoryStream(kv.Value), now)), options, null, CancellationToken.None);
        return path;
    }

    /// <summary>写增量包（基于基础包 + 变更清单），带指定备份时间供链排序。</summary>
    private static async Task<string> WriteDeltaAsync(string dir, string name, string basePath,
        IReadOnlyDictionary<string, byte[]> changed, DateTime backupTime)
    {
        var path = Path.Combine(dir, name);
        var metadata = new Dictionary<string, string>
        {
            ["Strategy"] = "BlockIncremental",
            ["BackupTime"] = backupTime.ToString("O"),
            ["UsnStart"] = "0",
            ["UsnEnd"] = "0"
        };
        await BlockIncrementalService.CreateIncrementalAsync(
            basePath, Password, path, Password, changed, MakeOptions(dir), CancellationToken.None, metadata);
        return path;
    }

    /// <summary>从归档读取单条目内容。</summary>
    private static async Task<byte[]> ReadEntryAsync(IBackupArchive archive, string rel)
    {
        using var s = await archive.OpenEntryAsync(rel, CancellationToken.None);
        using var ms = new MemoryStream();
        await s.CopyToAsync(ms);
        return ms.ToArray();
    }

    private async Task<Dictionary<string, byte[]>> CollectDirAsync(string dir)
    {
        var map = new Dictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase);
        foreach (var file in Directory.EnumerateFiles(dir, "*", SearchOption.AllDirectories))
        {
            var rel = Path.GetRelativePath(dir, file).Replace('\\', '/');
            map[rel] = await File.ReadAllBytesAsync(file);
        }
        return map;
    }

    public void RunAll()
    {
        Section("增量链：加载排序与版本编号");
        Chain_Load_Ordering().GetAwaiter().GetResult();

        Section("增量链：版本点恢复");
        Chain_Restore_VersionPoints().GetAwaiter().GetResult();

        Section("增量链：时间点恢复");
        Chain_Restore_ByTime().GetAwaiter().GetResult();

        Section("增量链：合并为新全量 + 可续增量");
        Chain_Merge_And_Continue().GetAwaiter().GetResult();
    }

    // ==================== 链加载 ====================

    private async Task Chain_Load_Ordering()
    {
        var dir = Path.Combine(Path.GetTempPath(), $"lg_chain_{Guid.NewGuid():N}");
        Directory.CreateDirectory(dir);
        try
        {
            var baseFiles = new Dictionary<string, byte[]> { ["f.bin"] = Rep(0x10, 2048) };
            var basePath = await WriteBaseAsync(dir, "base.lgbackup", baseFiles);

            // 乱序传入 3 个增量包，备份时间递增
            var t1 = DateTime.Now.AddMinutes(-10);
            var t2 = DateTime.Now.AddMinutes(-5);
            var t3 = DateTime.Now;
            var d1 = await WriteDeltaAsync(dir, "d1.lgbackup", basePath,
                new Dictionary<string, byte[]> { ["f.bin"] = WithPrefix(baseFiles["f.bin"], Chunk, 0x11) }, t1);
            var d2 = await WriteDeltaAsync(dir, "d2.lgbackup", basePath,
                new Dictionary<string, byte[]> { ["f.bin"] = WithPrefix(baseFiles["f.bin"], Chunk * 2, 0x12) }, t2);
            var d3 = await WriteDeltaAsync(dir, "d3.lgbackup", basePath,
                new Dictionary<string, byte[]> { ["f.bin"] = WithPrefix(baseFiles["f.bin"], Chunk * 3, 0x13) }, t3);

            var chain = await IncrementalChainService.LoadChainAsync(Password,
                new[] { d3, d1, d2 }); // 乱序

            Assert(chain.Count == 3, $"链加载 3 个版本点（实际 {chain.Count}）");
            Assert(chain[0].Path == d1 && chain[0].VersionIndex == 1, "乱序后按时间排序：版本1 = d1");
            Assert(chain[1].Path == d2 && chain[1].VersionIndex == 2, "版本2 = d2");
            Assert(chain[2].Path == d3 && chain[2].VersionIndex == 3, "版本3 = d3");
            Assert(chain.All(c => c.BackupTime != default), "各版本点备份时间已解析");
        }
        finally
        {
            try { Directory.Delete(dir, true); } catch { }
        }
    }

    // ==================== 版本点恢复 ====================

    private async Task Chain_Restore_VersionPoints()
    {
        var dir = Path.Combine(Path.GetTempPath(), $"lg_chain_{Guid.NewGuid():N}");
        Directory.CreateDirectory(dir);
        try
        {
            // 版本 0（基础包）
            var baseFiles = new Dictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase)
            {
                ["f1.bin"] = Rep(0x10, 2048),
                ["f2.bin"] = Rep(0x20, 2048),
                ["f3.bin"] = Rep(0x30, 2048)
            };
            var basePath = await WriteBaseAsync(dir, "base.lgbackup", baseFiles);

            // 版本 1：改 f1 首块 + 新增 new.txt
            var v1F1 = WithPrefix(baseFiles["f1.bin"], Chunk, 0x11);
            var v1New = Encoding.UTF8.GetBytes("version-1");
            var t1 = DateTime.Now.AddMinutes(-10);
            var d1 = await WriteDeltaAsync(dir, "d1.lgbackup", basePath,
                new Dictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase)
                {
                    ["f1.bin"] = v1F1,
                    ["new.txt"] = v1New
                }, t1);

            // 版本 2：改 f2 首 2 块 + new.txt 更新
            var v2F2 = WithPrefix(baseFiles["f2.bin"], Chunk * 2, 0x22);
            var v2New = Encoding.UTF8.GetBytes("version-2");
            var t2 = DateTime.Now.AddMinutes(-5);
            var d2 = await WriteDeltaAsync(dir, "d2.lgbackup", basePath,
                new Dictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase)
                {
                    ["f2.bin"] = v2F2,
                    ["new.txt"] = v2New
                }, t2);

            var deltas = new[] { d1, d2 };

            // 版本 0：仅基础包
            var dirV0 = Path.Combine(dir, "restore_v0");
            var r0 = await IncrementalChainService.RestoreToVersionAsync(basePath, Password, deltas, dirV0, 0);
            var m0 = await CollectDirAsync(dirV0);
            Assert(r0.VersionIndex == 0, "恢复版本 0（基础包）");
            Assert(m0.Count == 3 && !m0.ContainsKey("new.txt"), "版本0 = 3 文件（无 new.txt）");
            Assert(m0["f1.bin"].AsSpan().SequenceEqual(baseFiles["f1.bin"]), "版本0 f1 == 基础内容");

            // 版本 1：f1 变、new.txt 出现、f2/f3 未变
            var dirV1 = Path.Combine(dir, "restore_v1");
            var r1 = await IncrementalChainService.RestoreToVersionAsync(basePath, Password, deltas, dirV1, 1);
            var m1 = await CollectDirAsync(dirV1);
            Assert(r1.VersionIndex == 1, "恢复版本 1");
            Assert(m1.Count == 4, $"版本1 = 4 文件（实际 {m1.Count}）");
            Assert(m1["f1.bin"].AsSpan().SequenceEqual(v1F1), "版本1 f1 == 版本1 内容");
            Assert(m1["f2.bin"].AsSpan().SequenceEqual(baseFiles["f2.bin"]), "版本1 f2 == 基础内容");
            Assert(m1["new.txt"].AsSpan().SequenceEqual(v1New), "版本1 new.txt == version-1");

            // 版本 2：f2 变、new.txt 更新
            var dirV2 = Path.Combine(dir, "restore_v2");
            var r2 = await IncrementalChainService.RestoreToVersionAsync(basePath, Password, deltas, dirV2, 2);
            var m2 = await CollectDirAsync(dirV2);
            Assert(r2.VersionIndex == 2, "恢复版本 2（最新）");
            Assert(m2["f2.bin"].AsSpan().SequenceEqual(v2F2), "版本2 f2 == 版本2 内容");
            Assert(m2["new.txt"].AsSpan().SequenceEqual(v2New), "版本2 new.txt == version-2");
            Assert(m2["f1.bin"].AsSpan().SequenceEqual(v1F1), "版本2 f1 保持版本1 内容（链上历史保留）");
            Assert(m2["f3.bin"].AsSpan().SequenceEqual(baseFiles["f3.bin"]), "版本2 f3 == 基础内容");

            // 越界版本 → 抛异常
            bool threw = false;
            try
            {
                await IncrementalChainService.RestoreToVersionAsync(basePath, Password, deltas, dir, 9);
            }
            catch (ArgumentOutOfRangeException) { threw = true; }
            Assert(threw, "版本序号超出链长抛 ArgumentOutOfRangeException");
        }
        finally
        {
            try { Directory.Delete(dir, true); } catch { }
        }
    }

    // ==================== 时间点恢复 ====================

    private async Task Chain_Restore_ByTime()
    {
        var dir = Path.Combine(Path.GetTempPath(), $"lg_chain_{Guid.NewGuid():N}");
        Directory.CreateDirectory(dir);
        try
        {
            var baseFiles = new Dictionary<string, byte[]> { ["f.bin"] = Rep(0x40, 2048) };
            var basePath = await WriteBaseAsync(dir, "base.lgbackup", baseFiles);

            var t1 = DateTime.Now.AddMinutes(-20);
            var t2 = DateTime.Now.AddMinutes(-10);
            var d1 = await WriteDeltaAsync(dir, "d1.lgbackup", basePath,
                new Dictionary<string, byte[]> { ["f.bin"] = WithPrefix(baseFiles["f.bin"], Chunk, 0x41) }, t1);
            var d2 = await WriteDeltaAsync(dir, "d2.lgbackup", basePath,
                new Dictionary<string, byte[]> { ["f.bin"] = WithPrefix(baseFiles["f.bin"], Chunk * 2, 0x42) }, t2);
            var deltas = new[] { d1, d2 };

            // 目标时间在 t1 与 t2 之间 → 命中版本 1
            var dirMid = Path.Combine(dir, "restore_mid");
            var mid = await IncrementalChainService.RestoreToTimeAsync(basePath, Password, deltas, dirMid, t1.AddMinutes(5));
            var mMid = await CollectDirAsync(dirMid);
            Assert(mid.VersionIndex == 1, $"时间点在增量1/2 之间 → 版本 1（实际 {mid.VersionIndex}）");
            Assert(mMid["f.bin"].AsSpan().SequenceEqual(WithPrefix(baseFiles["f.bin"], Chunk, 0x41)), "时间点内容 == 版本1 f");

            // 目标时间在 t2 之后 → 版本 2（最新）
            var dirLatest = Path.Combine(dir, "restore_latest");
            var latest = await IncrementalChainService.RestoreToTimeAsync(basePath, Password, deltas, dirLatest, DateTime.Now);
            Assert(latest.VersionIndex == 2, $"时间点在链尾之后 → 版本 2（实际 {latest.VersionIndex}）");

            // 目标时间在 t1 之前 → 版本 0（仅基础包）
            var dirEarly = Path.Combine(dir, "restore_early");
            var early = await IncrementalChainService.RestoreToTimeAsync(basePath, Password, deltas, dirEarly, t1.AddMinutes(-5));
            Assert(early.VersionIndex == 0, $"时间点在链首之前 → 版本 0（实际 {early.VersionIndex}）");
        }
        finally
        {
            try { Directory.Delete(dir, true); } catch { }
        }
    }

    // ==================== 链合并 ====================

    private async Task Chain_Merge_And_Continue()
    {
        var dir = Path.Combine(Path.GetTempPath(), $"lg_chain_{Guid.NewGuid():N}");
        Directory.CreateDirectory(dir);
        try
        {
            var baseFiles = new Dictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase)
            {
                ["f1.bin"] = Rep(0x50, 2048),
                ["f2.bin"] = Rep(0x60, 2048)
            };
            var basePath = await WriteBaseAsync(dir, "base.lgbackup", baseFiles);

            var t1 = DateTime.Now.AddMinutes(-10);
            var t2 = DateTime.Now.AddMinutes(-5);
            var v1F1 = WithPrefix(baseFiles["f1.bin"], Chunk, 0x51);
            var d1 = await WriteDeltaAsync(dir, "d1.lgbackup", basePath,
                new Dictionary<string, byte[]> { ["f1.bin"] = v1F1 }, t1);
            var v2F2 = WithPrefix(baseFiles["f2.bin"], Chunk * 2, 0x62);
            var d2 = await WriteDeltaAsync(dir, "d2.lgbackup", basePath,
                new Dictionary<string, byte[]> { ["f2.bin"] = v2F2 }, t2);
            var deltas = new[] { d1, d2 };

            // 合并 → 新全量包
            var mergedPath = Path.Combine(dir, "merged.lgbackup");
            var merge = await IncrementalChainService.MergeToFullAsync(
                basePath, Password, mergedPath, deltas, MakeOptions(dir));

            Assert(merge.FileCount == 2 && merge.MergedDeltaCount == 2, $"合并 2 文件 / 2 增量（实际 {merge.FileCount}/{merge.MergedDeltaCount}）");
            Assert(File.Exists(mergedPath), "合并包已生成");

            using (var mergedArchive = BackupArchiveFactory.Open(mergedPath, Password))
            {
                Assert(mergedArchive is V3PrivateContainerArchive, "合并包为 v3 容器");
                var vr = await mergedArchive.VerifyAsync(CancellationToken.None);
                Assert(vr.Success, "合并包健康校验通过");

                var mf1 = await ReadEntryAsync(mergedArchive, "f1.bin");
                var mf2 = await ReadEntryAsync(mergedArchive, "f2.bin");
                Assert(mf1.AsSpan().SequenceEqual(v1F1), "合并包 f1 == 最新（版本1 内容）");
                Assert(mf2.AsSpan().SequenceEqual(v2F2), "合并包 f2 == 最新（版本2 内容）");
            }

            // 合并包可继续作为下一轮增量基准：再改 f1 → 增量 → 重建一致
            var v3F1 = WithPrefix(v1F1, Chunk * 2, 0x53);
            var d3Path = Path.Combine(dir, "d3.lgbackup");
            await BlockIncrementalService.CreateIncrementalAsync(mergedPath, Password, d3Path, Password,
                new Dictionary<string, byte[]> { ["f1.bin"] = v3F1 }, MakeOptions(dir));

            var rebuilt = await BlockIncrementalService.RebuildFileAsync(mergedPath, Password, d3Path, Password, "f1.bin");
            Assert(rebuilt.AsSpan().SequenceEqual(v3F1), "合并包作为新基准 → 增量 → 重建一致（链可持续）");
        }
        finally
        {
            try { Directory.Delete(dir, true); } catch { }
        }
    }

    public static (int Passed, int Failed) Summary => (_passed, _failed);
}
