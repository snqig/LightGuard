// © 2026 落尘（Luochen） 原创开发 - 保留所有权利
//
// 块级增量引擎测试（P0：USN 变更追踪 + 块级差分核心 + 增量包往返）：
//   1. 数据层：BuildIndex / ComputeDelta / Apply 块级差分正确性
//   2. 服务层：基础包（v3 Chunked）+ 增量包（PerFile）往返重建一致性
//   3. USN 门面：变更检测回退策略 + 增量包 USN 游标元数据读写

using System.Security.Cryptography;
using System.Text;
using LightGuard.Backup;

namespace BlockIncrementalTest;

/// <summary>
/// 块级增量引擎测试执行器。
/// </summary>
internal sealed class BlockIncrementalTests
{
    private const string Password = "BlockTest@2026";

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

    private static string Sha256Hex(byte[] data) => Convert.ToHexString(SHA256.HashData(data));

    /// <summary>构造确定性数据：每 512 字节一块，块 i 填充为全 i（块间内容互不相同，避免块哈希碰撞）。</summary>
    private static byte[] MakeData(int len)
    {
        var buf = new byte[len];
        for (int i = 0; i < len; i++)
            buf[i] = (byte)(i / 512 % 256);
        return buf;
    }

    /// <summary>整体写 v3 基础包（Chunked 模式，块级去重索引基础）。</summary>
    private static async Task<string> WriteBaseArchive(string dir, string name,
        IReadOnlyDictionary<string, byte[]> files, long chunkSize)
    {
        var path = Path.Combine(dir, name);
        var options = new BackupArchiveOptions
        {
            SourcePath = dir,
            CompressionLevel = 1,
            CompressionMode = BackupArchiveCompressionMode.Chunked,
            ChunkSize = chunkSize,
            EncryptFileNames = false
        };
        using var archive = BackupArchiveFactory.Create(path, Password, options);
        var now = DateTime.Now;
        await archive.WriteAsync(files.Select(kv => (kv.Key, (Stream)new MemoryStream(kv.Value), now)),
            options, null, CancellationToken.None);
        return path;
    }

    public void RunAll()
    {
        Section("数据层：块索引与差分核心");
        Engine_IndexBlocks();
        Engine_Delta_NoChange();
        Engine_Delta_PartialChange();
        Engine_Apply_RoundTrip();
        Engine_Apply_BaseNull_AllNew();

        Section("服务层：基础包 + 增量包往返重建");
        Service_Incremental_RoundTrip().GetAwaiter().GetResult();
        Service_NoBase_AllNew().GetAwaiter().GetResult();
        Service_UnchangedFile_FromBase().GetAwaiter().GetResult();
        Service_VerifyDeltaArchive().GetAwaiter().GetResult();

        Section("USN 游标元数据");
        Service_UsnMeta_RoundTrip().GetAwaiter().GetResult();
    }

    // ==================== 数据层 ====================

    private void Engine_IndexBlocks()
    {
        const int chunk = 512;
        var data = MakeData(4096); // 8 块
        var index = BlockIncrementalEngine.BuildIndex(data, chunk);
        Assert(index.Count == 8, $"BuildIndex 块数 = 8（实际 {index.Count}）");

        var hash = Sha256Hex(data.AsSpan(0, chunk).ToArray());
        Assert(index.Contains(hash), "BuildIndex 含首块哈希");
        Assert(index.TryGetLength(hash, out var len) && len == chunk, "BuildIndex 块长度正确");
    }

    private void Engine_Delta_NoChange()
    {
        const int chunk = 512;
        var data = MakeData(2048);
        var index = BlockIncrementalEngine.BuildIndex(data, chunk);
        var delta = BlockIncrementalEngine.ComputeDelta(data, data, index, chunk);
        Assert(delta.Blocks.Count == 4, $"同数据差分块数 = 4（实际 {delta.Blocks.Count}）");
        Assert(delta.ReusedCount == 4 && delta.NewCount == 0, "同数据全复用（无新增块）");
        Assert(delta.ReusedBytes == 2048 && delta.NewBytes == 0, "同数据复用量 = 2048 字节");
    }

    private void Engine_Delta_PartialChange()
    {
        const int chunk = 512;
        var baseData = MakeData(4096);
        var index = BlockIncrementalEngine.BuildIndex(baseData, chunk);

        // 修改第 2 块区域（偏移 1024..1535 写 0xFF），其余不变
        var newData = (byte[])baseData.Clone();
        Array.Fill(newData, (byte)0xFF, 1024, chunk);
        var delta = BlockIncrementalEngine.ComputeDelta(newData, baseData, index, chunk);

        Assert(delta.Blocks.Count == 8, $"变更差分块数 = 8（实际 {delta.Blocks.Count}）");
        Assert(delta.NewCount == 1 && delta.ReusedCount == 7, $"变更 1 块 / 复用 7 块（实际 {delta.NewCount}/{delta.ReusedCount}）");
        Assert(delta.NewBytes == chunk, $"新增字节 = 512（实际 {delta.NewBytes}）");
        Assert(delta.ReusedBytes == 7 * chunk, $"复用字节 = 3584（实际 {delta.ReusedBytes}）");
        Assert(delta.SavingsRatio > 0.85, $"复用率 > 0.85（实际 {delta.SavingsRatio:F4}）");

        // 空基准 → 全新增
        var allNew = BlockIncrementalEngine.ComputeDelta(newData, null, null, chunk);
        Assert(allNew.NewCount == 8 && allNew.ReusedCount == 0, "空基准全新增（8 块）");
    }

    private void Engine_Apply_RoundTrip()
    {
        const int chunk = 512;
        var baseData = MakeData(3072);
        var index = BlockIncrementalEngine.BuildIndex(baseData, chunk);

        // 修改首块 + 追加尾部 → 内容变长
        var newData = (byte[])baseData.Clone();
        Array.Fill(newData, (byte)0x11, 0, 256);
        newData = newData.Concat(MakeData(512)).ToArray();

        var delta = BlockIncrementalEngine.ComputeDelta(newData, baseData, index, chunk);
        var rebuilt = BlockIncrementalEngine.Apply(baseData, delta);
        Assert(rebuilt.Length == newData.Length, $"Apply 长度一致（{rebuilt.Length} == {newData.Length}）");
        Assert(rebuilt.AsSpan().SequenceEqual(newData), "Apply 重建内容与最新数据一致");

        // 无基准但差分全为新块 → 仍可重建
        var noBase = BlockIncrementalEngine.ComputeDelta(newData, null, null, chunk);
        var rebuiltNoBase = BlockIncrementalEngine.Apply(null, noBase);
        Assert(rebuiltNoBase.AsSpan().SequenceEqual(newData), "无基准（全新块）Apply 重建一致");

        // 有复用块却无基准 → 抛异常
        var bad = BlockIncrementalEngine.ComputeDelta(newData, baseData, index, chunk);
        bool threw = false;
        try { BlockIncrementalEngine.Apply(null, bad); }
        catch (InvalidDataException) { threw = true; }
        Assert(threw, "复用块缺基准数据时 Apply 抛 InvalidDataException");
    }

    private void Engine_Apply_BaseNull_AllNew()
    {
        const int chunk = 512;
        var data = MakeData(1024);
        var delta = BlockIncrementalEngine.ComputeDelta(data, null, null, chunk);
        var rebuilt = BlockIncrementalEngine.Apply(null, delta);
        Assert(rebuilt.AsSpan().SequenceEqual(data), "空基准 + 全新增块 Apply 重建一致");
    }

    // ==================== 服务层 ====================

    private async Task Service_Incremental_RoundTrip()
    {
        var dir = Path.Combine(Path.GetTempPath(), $"lg_inc_{Guid.NewGuid():N}");
        Directory.CreateDirectory(dir);
        const int chunk = 512;

        try
        {
            // 基础包：3 个文件，每文件 4KB（8 块）
            var baseFiles = new Dictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase)
            {
                ["f1.bin"] = MakeData(4096),
                ["f2.bin"] = Enumerable.Repeat((byte)0x41, 4096).ToArray(),
                ["f3.bin"] = Enumerable.Repeat((byte)0x42, 4096).ToArray()
            };
            var basePath = await WriteBaseArchive(dir, "base.lgbackup", baseFiles, chunk);

            // 变更：f1 首 1KB 改写、f2 整体重写、f3 未变
            var latestF1 = (byte[])baseFiles["f1.bin"].Clone();
            Array.Fill(latestF1, (byte)0xEE, 0, 1024);
            var latestF2 = Enumerable.Repeat((byte)0x43, 4096).ToArray();
            var changed = new Dictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase)
            {
                ["f1.bin"] = latestF1,
                ["f2.bin"] = latestF2
            };

            var deltaPath = Path.Combine(dir, "inc.lgbackup");
            var options = new BackupArchiveOptions { SourcePath = dir, CompressionLevel = 1, ChunkSize = chunk };
            var result = await BlockIncrementalService.CreateIncrementalAsync(
                basePath, Password, deltaPath, Password, changed, options);

            // 指标：f1 变 2 块 / 复用 6 块；f2 全变 8 块
            Assert(result.ChangedFiles == 2, $"变更文件数 = 2（实际 {result.ChangedFiles}）");
            Assert(result.NewBlocks == 10 && result.ReusedBlocks == 6,
                $"新增块 10 / 复用块 6（实际 {result.NewBlocks}/{result.ReusedBlocks}）");
            Assert(result.NewBytes == 10 * chunk && result.ReusedBytes == 6 * chunk,
                $"新增字节 5120 / 复用字节 3072（实际 {result.NewBytes}/{result.ReusedBytes}）");

            // 逐文件重建校验
            var rebuiltF1 = await BlockIncrementalService.RebuildFileAsync(basePath, Password, deltaPath, Password, "f1.bin");
            var rebuiltF2 = await BlockIncrementalService.RebuildFileAsync(basePath, Password, deltaPath, Password, "f2.bin");
            var rebuiltF3 = await BlockIncrementalService.RebuildFileAsync(basePath, Password, deltaPath, Password, "f3.bin");

            Assert(rebuiltF1.AsSpan().SequenceEqual(latestF1), "重建 f1 == 最新内容");
            Assert(rebuiltF2.AsSpan().SequenceEqual(latestF2), "重建 f2 == 最新内容");
            Assert(rebuiltF3.AsSpan().SequenceEqual(baseFiles["f3.bin"]), "重建 f3（未变）== 基础包内容");
        }
        finally
        {
            try { Directory.Delete(dir, true); } catch { }
        }
    }

    private async Task Service_NoBase_AllNew()
    {
        var dir = Path.Combine(Path.GetTempPath(), $"lg_inc_{Guid.NewGuid():N}");
        Directory.CreateDirectory(dir);
        const int chunk = 512;

        try
        {
            var files = new Dictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase)
            {
                ["a.bin"] = MakeData(2048),
                ["b.bin"] = MakeData(1024)
            };
            var deltaPath = Path.Combine(dir, "no_base.lgbackup");
            var options = new BackupArchiveOptions { SourcePath = dir, CompressionLevel = 1, ChunkSize = chunk };
            var result = await BlockIncrementalService.CreateIncrementalAsync(
                null, "", deltaPath, Password, files, options);

            Assert(result.NewBlocks == 6 && result.ReusedBlocks == 0, "无基准全新增（6 块）");
            Assert(result.ReusedBytes == 0, "无基准复用字节 = 0");

            // 直接读增量包条目校验（增量条目本身存储最新数据）
            using var archive = BackupArchiveFactory.Open(deltaPath, Password);
            foreach (var (rel, data) in files)
            {
                using var s = await archive.OpenEntryAsync(rel, CancellationToken.None);
                using var ms = new MemoryStream();
                await s.CopyToAsync(ms);
                Assert(ms.ToArray().AsSpan().SequenceEqual(data), $"增量包条目 {rel} == 最新数据");
            }
        }
        finally
        {
            try { Directory.Delete(dir, true); } catch { }
        }
    }

    private async Task Service_UnchangedFile_FromBase()
    {
        var dir = Path.Combine(Path.GetTempPath(), $"lg_inc_{Guid.NewGuid():N}");
        Directory.CreateDirectory(dir);
        const int chunk = 512;

        try
        {
            var baseFiles = new Dictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase)
            {
                ["keep.bin"] = MakeData(2048)
            };
            var basePath = await WriteBaseArchive(dir, "base2.lgbackup", baseFiles, chunk);

            // 变更清单不含 keep.bin
            var changed = new Dictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase)
            {
                ["new.bin"] = MakeData(512)
            };
            var deltaPath = Path.Combine(dir, "inc2.lgbackup");
            var options = new BackupArchiveOptions { SourcePath = dir, CompressionLevel = 1, ChunkSize = chunk };
            await BlockIncrementalService.CreateIncrementalAsync(basePath, Password, deltaPath, Password, changed, options);

            var rebuilt = await BlockIncrementalService.RebuildFileAsync(basePath, Password, deltaPath, Password, "keep.bin");
            Assert(rebuilt.AsSpan().SequenceEqual(baseFiles["keep.bin"]), "未变更文件 Rebuild == 基础包数据");

            var rebuiltNew = await BlockIncrementalService.RebuildFileAsync(basePath, Password, deltaPath, Password, "new.bin");
            Assert(rebuiltNew.AsSpan().SequenceEqual(changed["new.bin"]), "增量新增文件 Rebuild == 增量数据");
        }
        finally
        {
            try { Directory.Delete(dir, true); } catch { }
        }
    }

    private async Task Service_VerifyDeltaArchive()
    {
        var dir = Path.Combine(Path.GetTempPath(), $"lg_inc_{Guid.NewGuid():N}");
        Directory.CreateDirectory(dir);
        const int chunk = 512;

        try
        {
            var baseFiles = new Dictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase)
            {
                ["v.bin"] = MakeData(4096)
            };
            var basePath = await WriteBaseArchive(dir, "base3.lgbackup", baseFiles, chunk);

            var latest = (byte[])baseFiles["v.bin"].Clone();
            Array.Fill(latest, (byte)0x77, 2048, 1024);
            var deltaPath = Path.Combine(dir, "inc3.lgbackup");
            var options = new BackupArchiveOptions { SourcePath = dir, CompressionLevel = 1, ChunkSize = chunk };
            await BlockIncrementalService.CreateIncrementalAsync(
                basePath, Password, deltaPath, Password,
                new Dictionary<string, byte[]> { ["v.bin"] = latest }, options);

            // 基础包 + 增量包各自健康校验均通过
            using (var baseArchive = BackupArchiveFactory.Open(basePath, Password))
            {
                var vr = await baseArchive.VerifyAsync(CancellationToken.None);
                Assert(vr.Success, "基础包 VerifyAsync 通过");
            }
            using (var deltaArchive = BackupArchiveFactory.Open(deltaPath, Password))
            {
                var vr = await deltaArchive.VerifyAsync(CancellationToken.None);
                Assert(vr.Success, "增量包 VerifyAsync 通过");
            }
        }
        finally
        {
            try { Directory.Delete(dir, true); } catch { }
        }
    }

    // ==================== USN 游标元数据 ====================

    private async Task Service_UsnMeta_RoundTrip()
    {
        var dir = Path.Combine(Path.GetTempPath(), $"lg_inc_{Guid.NewGuid():N}");
        Directory.CreateDirectory(dir);

        try
        {
            // 手动构造 metadata（模拟 USN 游标），写入增量包
            var files = new Dictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase)
            {
                ["m.bin"] = MakeData(1024)
            };
            var deltaPath = Path.Combine(dir, "meta.lgbackup");
            var options = new BackupArchiveOptions { SourcePath = dir, CompressionLevel = 1, ChunkSize = 512 };
            var metadata = new Dictionary<string, string>
            {
                ["Strategy"] = "BlockIncremental",
                ["UsnStart"] = "1000",
                ["UsnEnd"] = "2048",
                ["SourcePath"] = Path.GetFullPath(dir)
            };
            await BlockIncrementalService.CreateIncrementalAsync(null, "", deltaPath, Password, files, options,
                CancellationToken.None, metadata);

            // 从包头读回游标
            Assert(BlockIncrementalService.TryReadUsnEnd(deltaPath, Password) == 2048,
                "TryReadUsnEnd 读回 UsnEnd = 2048");

            // 包不存在 / 口令错误 → -1
            Assert(BlockIncrementalService.TryReadUsnEnd(Path.Combine(dir, "none.lgbackup"), Password) == -1,
                "包不存在时 TryReadUsnEnd = -1");
            Assert(BlockIncrementalService.TryReadUsnEnd(deltaPath, "WrongPass!") == -1,
                "口令错误时 TryReadUsnEnd = -1");

            // 普通基础包（无 USN 元数据）→ -1
            var basePath = await WriteBaseArchive(dir, "base4.lgbackup", files, 512);
            Assert(BlockIncrementalService.TryReadUsnEnd(basePath, Password) == -1,
                "无 USN 元数据的包 TryReadUsnEnd = -1");
        }
        finally
        {
            try { Directory.Delete(dir, true); } catch { }
        }
    }

    public static (int Passed, int Failed) Summary => (_passed, _failed);
}
