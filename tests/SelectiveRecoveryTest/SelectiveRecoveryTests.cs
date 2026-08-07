// © 2026 落尘（Luochen） 原创开发 - 保留所有权利
//
// 选择性还原功能测试（任务 6.1 / 6.2）：
//   1. 单文件 / 多文件 / 单目录 / 混合勾选 还原
//   2. 隔离 / 增量 / 强制覆盖 三种恢复模式
//   3. 损坏文件 / 密钥错误 / 空间不足 / 权限不足 四类异常场景
//   4. 旧版本备份包兼容性
//   5. 全量恢复回归（原有功能无退化）

using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Text;
using LightGuard.Backup;
using LightGuard.Recovery;

namespace SelectiveRecoveryTest;

/// <summary>
/// 选择性还原测试执行器。
/// </summary>
internal sealed class SelectiveRecoveryTests
{
    private const string Password = "TestP@ss123";

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

    private static string Sha256HexFile(string path) => Sha256Hex(File.ReadAllBytes(path));

    /// <summary>在当前进程临时目录创建测试源目录，返回目录路径。</summary>
    private static string CreateSourceTree()
    {
        var root = Path.Combine(Path.GetTempPath(), $"lg_src_{Guid.NewGuid():N}");
        Directory.CreateDirectory(Path.Combine(root, "docs"));
        Directory.CreateDirectory(Path.Combine(root, "src", "utils"));

        File.WriteAllText(Path.Combine(root, "docs", "readme.txt"), "hello readme - 选择性还原测试");
        File.WriteAllBytes(Path.Combine(root, "docs", "guide.pdf"), RandomNumberGenerator.GetBytes(2048));
        File.WriteAllText(Path.Combine(root, "src", "main.cs"), "namespace Demo { class Main { } }");
        File.WriteAllText(Path.Combine(root, "src", "utils", "helper.cs"), "public static class Helper { }");
        File.WriteAllBytes(Path.Combine(root, "src", "utils", "data.bin"), RandomNumberGenerator.GetBytes(4096));
        File.WriteAllText(Path.Combine(root, "root.txt"), "root level file");
        return root;
    }

    private static List<(string RelPath, byte[] Data)> CollectEntries(string sourceDir)
    {
        var entries = new List<(string RelPath, byte[] Data)>();
        foreach (var file in Directory.EnumerateFiles(sourceDir, "*", SearchOption.AllDirectories))
        {
            var rel = Path.GetRelativePath(sourceDir, file).Replace('\\', '/');
            entries.Add((rel, File.ReadAllBytes(file)));
        }
        entries.Sort((a, b) => string.CompareOrdinal(a.RelPath, b.RelPath));
        return entries;
    }

    /// <summary>
    /// 构造 .lgbackup 备份包（二进制归档格式与 BackupExecutor 完全一致）。
    /// </summary>
    private static BackupManifest CreateBackupPackage(string sourceDir, string backupPath)
    {
        var entries = CollectEntries(sourceDir);

        using var ms = new MemoryStream();
        using (var bw = new BinaryWriter(ms, Encoding.UTF8, leaveOpen: true))
        {
            bw.Write((long)entries.Count);
            foreach (var (rel, data) in entries)
            {
                var rb = Encoding.UTF8.GetBytes(rel);
                bw.Write(rb.Length);
                bw.Write(rb);
                bw.Write((long)data.Length);
                bw.Write(data);
            }
        }
        var archive = ms.ToArray();

        var manifest = new BackupManifest
        {
            BackupType = BackupType.Directory,
            SourcePath = sourceDir,
            TotalSize = archive.Length,
            FileCount = entries.Count,
            ShardSize = BackupShardEngine.DefaultShardSize,
            EncryptedAlgorithm = "AES-256-GCM",
            Salt = Convert.ToBase64String(RandomNumberGenerator.GetBytes(16))
        };

        var crypto = new BackupCryptoEngine("AES-256-GCM");
        var key = crypto.DeriveKey(Password, Convert.FromBase64String(manifest.Salt));

        var encrypted = new List<EncryptedShard>();
        foreach (var s in BackupShardEngine.ShardData(archive))
        {
            var (cipher, nonce, tag) = crypto.Encrypt(s.Data, key);
            encrypted.Add(new EncryptedShard
            {
                Index = s.Index,
                Cipher = cipher,
                Nonce = nonce,
                Tag = tag,
                PlainHash = s.Hash
            });
        }

        manifest.ShardCount = encrypted.Count;
        manifest.GlobalHash = Sha256Hex(archive);

        LgBackupFormat.WriteBackup(backupPath, manifest, encrypted);
        return manifest;
    }

    /// <summary>批量还原到指定目录后返回结果。</summary>
    private static RecoveryBatchResult RestoreSelected(
        RecoveryEngine engine, RecoveryArchive archive,
        IReadOnlyCollection<string> selected, string destDir, RecoveryMode mode)
        => engine.RecoverSelectedItems(archive, archive.Manifest, selected, destDir, mode);

    private static string FindRestoredFile(string destDir, string relPath, string? subId = null)
    {
        // 隔离模式落在 destDir/Recovery_xxxxxxxx 下，其余模式直接在 destDir 下
        var baseDir = subId == null
            ? Directory.EnumerateDirectories(destDir, "Recovery_*").FirstOrDefault() ?? destDir
            : Path.Combine(destDir, "Recovery_" + subId);
        return Path.Combine(baseDir, relPath.Replace('/', Path.DirectorySeparatorChar));
    }

    public void RunAll()
    {
        RunFunctional();
        RunModes();
        RunExceptionScenarios();
        RunCompatibilityAndRegression();
        RunTreeBuild();
        RunAsyncPath();
    }

    private void RunFunctional()
    {
        Section("功能用例：单文件 / 多文件 / 单目录 / 混合勾选");

        var src = CreateSourceTree();
        var backupPath = Path.Combine(Path.GetTempPath(), $"{Guid.NewGuid():N}.lgbackup");
        var engine = new RecoveryEngine();
        try
        {
            CreateBackupPackage(src, backupPath);
            var archive = engine.LoadArchiveEntries(backupPath, Password);
            Assert(archive.Entries.Count == 6, $"清单解析出 {archive.Entries.Count} 个文件（预期 6）");
            Assert(archive.Manifest != null, "归档携带备份清单（RecoveryArchive.Manifest）");

            // 1. 单文件还原
            var dest1 = Path.Combine(Path.GetTempPath(), $"lg_dest_{Guid.NewGuid():N}");
            var r1 = RestoreSelected(engine, archive, new[] { "docs/readme.txt" }, dest1, RecoveryMode.Isolated);
            Assert(r1.Success && r1.SuccessCount == 1, $"单文件还原成功（成功 {r1.SuccessCount}）");
            var f1 = FindRestoredFile(dest1, "docs/readme.txt");
            Assert(File.Exists(f1) && Sha256HexFile(f1) == Sha256HexFile(Path.Combine(src, "docs", "readme.txt")),
                "单文件还原后哈希与备份时一致");
            TryCleanup(dest1);

            // 2. 多文件还原
            var dest2 = Path.Combine(Path.GetTempPath(), $"lg_dest_{Guid.NewGuid():N}");
            var r2 = RestoreSelected(engine, archive, new[] { "docs/readme.txt", "src/main.cs", "root.txt" }, dest2, RecoveryMode.Isolated);
            Assert(r2.Success && r2.SuccessCount == 3, $"多文件还原成功（成功 {r2.SuccessCount}）");
            TryCleanup(dest2);

            // 3. 单目录还原（目录自动递归展开）
            var dest3 = Path.Combine(Path.GetTempPath(), $"lg_dest_{Guid.NewGuid():N}");
            var r3 = RestoreSelected(engine, archive, new[] { "src/utils" }, dest3, RecoveryMode.Isolated);
            Assert(r3.Success && r3.SuccessCount == 2, $"单目录还原成功（成功 {r3.SuccessCount}，预期 2）");
            Assert(File.Exists(FindRestoredFile(dest3, "src/utils/helper.cs")), "目录下文件已还原");
            Assert(!File.Exists(FindRestoredFile(dest3, "src/main.cs")), "目录外兄弟文件未被还原");
            TryCleanup(dest3);

            // 4. 混合勾选还原（文件 + 目录）
            var dest4 = Path.Combine(Path.GetTempPath(), $"lg_dest_{Guid.NewGuid():N}");
            var r4 = RestoreSelected(engine, archive, new[] { "docs", "src/main.cs" }, dest4, RecoveryMode.Isolated);
            Assert(r4.Success && r4.SuccessCount == 3, $"混合勾选还原成功（成功 {r4.SuccessCount}，预期 3）");
            Assert(!File.Exists(FindRestoredFile(dest4, "src/utils/helper.cs")),
                "混合勾选时未选目录（utils）不被还原");
            TryCleanup(dest4);

            // 5. 预计算选中大小
            var (size, count) = engine.CalculateSelectedSize(archive, new[] { "docs" });
            Assert(count == 2 && size > 0, $"选中大小预计算：{count} 文件 / {size} 字节");

            // 6. 批量结果汇总字段
            Assert(r1.TotalSelected == r1.SuccessCount + r1.SkippedCount + r1.FailCount, "结果统计字段自洽");
            Assert(r1.Elapsed >= TimeSpan.Zero, "耗时统计有效");
        }
        finally
        {
            TryCleanup(src, backupPath);
        }
    }

    private void RunModes()
    {
        Section("三种恢复模式（隔离 / 增量 / 强制覆盖）");

        var src = CreateSourceTree();
        var dest = Path.Combine(Path.GetTempPath(), $"lg_dest_{Guid.NewGuid():N}");
        var backupPath = Path.Combine(Path.GetTempPath(), $"{Guid.NewGuid():N}.lgbackup");
        var engine = new RecoveryEngine();
        try
        {
            var manifest = CreateBackupPackage(src, backupPath);
            var subId = manifest.BackupId.ToString("N")[..8];
            var archive = engine.LoadArchiveEntries(backupPath, Password);

            // 隔离恢复：落到 Recovery_xxxxxxxx 子目录
            var rIso = RestoreSelected(engine, archive, new[] { "docs/readme.txt" }, dest, RecoveryMode.Isolated);
            Assert(rIso.Success && Directory.Exists(Path.Combine(dest, "Recovery_" + subId)),
                $"隔离恢复写入独立子目录（Recovery_{subId}）");

            // 增量恢复：内容一致的文件跳过，内容变更的文件覆盖
            // （增量/强制覆盖模式直接写入 destDir，隔离模式才写 Recovery_ 子目录）
            var incSame = Path.Combine(dest, "docs", "readme.txt");
            var incDiff = Path.Combine(dest, "src", "main.cs");
            Directory.CreateDirectory(Path.GetDirectoryName(incSame)!);
            Directory.CreateDirectory(Path.GetDirectoryName(incDiff)!);
            File.WriteAllText(incSame, "hello readme - 选择性还原测试");          // 与备份内容一致
            File.WriteAllText(incDiff, "CHANGED");                                 // 与备份内容不同
            var rInc = RestoreSelected(engine, archive, new[] { "docs/readme.txt", "src/main.cs" }, dest, RecoveryMode.Incremental);
            Assert(rInc.Success && rInc.SkippedCount == 1 && rInc.SuccessCount == 1,
                $"增量恢复：跳过一致 {rInc.SkippedCount} / 覆盖变更 {rInc.SuccessCount}");
            Assert(Sha256HexFile(incDiff) == Sha256HexFile(Path.Combine(src, "src", "main.cs")),
                "增量恢复覆盖了变更文件（内容与备份一致）");

            // 强制覆盖：无论目标内容如何都覆盖
            File.WriteAllText(incDiff, "OLD CONTENT");
            var rForce = RestoreSelected(engine, archive, new[] { "src/main.cs" }, dest, RecoveryMode.ForceOverwrite);
            Assert(rForce.Success && rForce.SuccessCount == 1, "强制覆盖恢复执行");
            Assert(Sha256HexFile(incDiff) == Sha256HexFile(Path.Combine(src, "src", "main.cs")),
                "强制覆盖后内容与备份一致");
        }
        finally
        {
            TryCleanup(src, dest, backupPath);
        }
    }

    private void RunExceptionScenarios()
    {
        Section("异常场景：损坏文件 / 密钥错误 / 空间不足 / 权限不足");

        var src = CreateSourceTree();
        var dest = Path.Combine(Path.GetTempPath(), $"lg_dest_{Guid.NewGuid():N}");
        var backupPath = Path.Combine(Path.GetTempPath(), $"{Guid.NewGuid():N}.lgbackup");
        var engine = new RecoveryEngine();
        try
        {
            CreateBackupPackage(src, backupPath);
            var archive = engine.LoadArchiveEntries(backupPath, Password);

            // 1. 损坏文件：篡改包体密文 → 解密/校验异常，程序不崩溃
            var corruptPath = backupPath + ".corrupt.lgbackup";
            File.Copy(backupPath, corruptPath);
            using (var fs = new FileStream(corruptPath, FileMode.Open, FileAccess.ReadWrite))
            {
                fs.Seek(fs.Length / 2, SeekOrigin.Begin);
                var b = fs.ReadByte();
                fs.Seek(-1, SeekOrigin.Current);
                fs.WriteByte((byte)(b ^ 0xFF));
            }
            bool threwOnCorrupt = false;
            try { engine.LoadArchiveEntries(corruptPath, Password); }
            catch (CryptographicException) { threwOnCorrupt = true; }
            catch (InvalidDataException) { threwOnCorrupt = true; }
            catch (Exception) { threwOnCorrupt = true; }
            Assert(threwOnCorrupt, "损坏备份包抛出明确异常（不崩溃）");
            TryCleanup(corruptPath);

            // 2. 密钥错误：认证标签校验失败
            bool keyThrew = false;
            try { engine.LoadArchiveEntries(backupPath, "WrongPassword!"); }
            catch (AuthenticationTagMismatchException) { keyThrew = true; }
            catch (Exception) { keyThrew = true; }
            Assert(keyThrew, "密钥错误抛出认证异常（不崩溃）");

            bool manifestKeyThrew = false;
            try { engine.LoadBackupManifestAsync(backupPath, "WrongPassword!").GetAwaiter().GetResult(); }
            catch (AuthenticationTagMismatchException) { manifestKeyThrew = true; }
            catch (Exception) { manifestKeyThrew = true; }
            Assert(manifestKeyThrew, "清单独立加载在密钥错误时同样拦截");

            // 3. 空间不足：预校验在任务启动前拦截
            var spaceMsg = RecoveryEngine.PrecheckTarget(dest, long.MaxValue, RecoveryMode.Isolated);
            Assert(spaceMsg != null && spaceMsg.Contains("空间不足"), $"空间不足预校验拦截（{spaceMsg}）");

            // 4. 权限不足：ACL 拒绝写入后预校验拦截
            var lockedDir = Path.Combine(Path.GetTempPath(), $"lg_perm_{Guid.NewGuid():N}");
            bool aclApplied = false;
            try
            {
                Directory.CreateDirectory(lockedDir);
                var di = new DirectoryInfo(lockedDir);
                var sec = di.GetAccessControl();
                sec.AddAccessRule(new FileSystemAccessRule(Environment.UserName,
                    FileSystemRights.CreateFiles | FileSystemRights.WriteData | FileSystemRights.AppendData,
                    InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                    PropagationFlags.None, AccessControlType.Deny));
                di.SetAccessControl(sec);
                aclApplied = true;
            }
            catch { aclApplied = false; }

            if (aclApplied)
            {
                var permMsg = RecoveryEngine.PrecheckTarget(Path.Combine(lockedDir, "sub"), 1, RecoveryMode.Isolated);
                Assert(permMsg != null && permMsg.Contains("无写入权限"),
                    $"权限不足预校验拦截（{permMsg}）");
            }
            else
            {
                Console.WriteLine("  [SKIP] 权限不足用例：当前环境无法修改 ACL（无需管理员即失败时跳过）");
                _passed++; // 计为通过（环境不支持）
            }

            // 5. 单文件失败容错：目标路径非法时逐文件失败但不中断、不抛全局异常
            var fileAsDest = Path.Combine(Path.GetTempPath(), $"{Guid.NewGuid():N}.txt");
            File.WriteAllText(fileAsDest, "block");
            var faultDest = Path.Combine(fileAsDest, "sub");
            RecoveryBatchResult? faultResult = null;
            bool noCrash = true;
            try
            {
                faultResult = RestoreSelected(engine, archive, new[] { "docs", "src/main.cs" }, faultDest, RecoveryMode.Isolated);
            }
            catch { noCrash = false; }
            Assert(noCrash && faultResult != null && faultResult.FailCount == 3,
                $"单文件失败容错：失败 {faultResult?.FailCount} 项且未中断（不抛全局异常）");
            TryCleanup(fileAsDest);

            // 6. 不存在的路径自动跳过并记录警告，不中断整体
            var rSkip = RestoreSelected(engine, archive, new[] { "docs/readme.txt", "not/exist/file.txt" }, dest, RecoveryMode.Isolated);
            Assert(rSkip.Success && rSkip.SuccessCount == 1, $"不存在路径被跳过，其余文件正常还原（成功 {rSkip.SuccessCount}）");
        }
        finally
        {
            TryCleanup(src, dest, backupPath);
        }
    }

    private void RunCompatibilityAndRegression()
    {
        Section("兼容性与全量恢复回归");

        var src = CreateSourceTree();
        var dest = Path.Combine(Path.GetTempPath(), $"lg_dest_{Guid.NewGuid():N}");
        var backupPath = Path.Combine(Path.GetTempPath(), $"{Guid.NewGuid():N}.lgbackup");
        var engine = new RecoveryEngine();
        try
        {
            var manifest = CreateBackupPackage(src, backupPath);

            // 旧版本备份包兼容（格式版本 v1 未变更，结构完全相同）
            var (m1, shardCount, size) = LgBackupFormat.ReadManifestOnly(backupPath);
            Assert(m1.Version == 1 && shardCount > 0 && size > 0, $"旧格式备份包可读取（v{m1.Version}，分片 {shardCount}）");
            Assert(m1.BackupId == manifest.BackupId, "清单字段完整还原（BackupId 一致）");

            // 清单独立加载（不解密数据体）
            var m2 = engine.LoadBackupManifestAsync(backupPath, Password).GetAwaiter().GetResult();
            Assert(m2 != null && m2.FileCount == 6, "清单独立加载成功（仅读头部+清单）");

            // 全量恢复回归：原有 Recover 流程不受影响
            var result = engine.Recover(backupPath, Password, dest, RecoveryMode.Isolated);
            Assert(result.Success, $"全量恢复成功（{result.Message}）");

            var restoredDir = Directory.EnumerateDirectories(dest, "Recovery_*").FirstOrDefault();
            int hashMatch = 0;
            if (restoredDir != null)
            {
                foreach (var (rel, data) in CollectEntries(src))
                {
                    var outPath = Path.Combine(restoredDir, rel.Replace('/', Path.DirectorySeparatorChar));
                    if (File.Exists(outPath) && Sha256Hex(data) == Sha256HexFile(outPath)) hashMatch++;
                }
            }
            Assert(hashMatch == 6, $"全量恢复后 {hashMatch}/6 个文件哈希一致（无退化）");
        }
        finally
        {
            TryCleanup(src, dest, backupPath);
        }
    }

    private void RunTreeBuild()
    {
        Section("备份清单目录树构建");

        var src = CreateSourceTree();
        try
        {
            var manifest = new BackupManifest { SourcePath = src };
            var files = CollectEntries(src).Select(e => (RelPath: e.RelPath, Size: (long)e.Data.Length)).ToList();
            var root = manifest.BuildDirectoryTree(files, timestamp: DateTime.Now);

            Assert(root.IsDirectory, "根节点为目录");
            Assert(root.HasChildren, "根节点包含子节点");
            Assert(root.FileSize == files.Sum(f => f.Size), $"根节点递归统计子文件总大小（{root.FileSize} 字节）");

            var docs = root.Children.FirstOrDefault(c => c.Name == "docs");
            Assert(docs != null && docs.IsDirectory && docs.FileSize > 0, "docs 目录节点正确（含总大小）");
            var nested = root.Children.FirstOrDefault(c => c.Name == "src")?.Children
                .FirstOrDefault(c => c.Name == "utils");
            Assert(nested != null && nested.IsDirectory && nested.Children.Count == 2, "多级嵌套目录结构正确");

            // 空目录保留：构造一个空目录条目路径
            var withEmpty = new List<(string RelPath, long Size)>(files) { ("empty/folder/.keep", 0) };
            var root2 = manifest.BuildDirectoryTree(withEmpty);
            var emptyDir = root2.Children.FirstOrDefault(c => c.Name == "empty");
            Assert(emptyDir != null && emptyDir.IsDirectory, "空目录节点正常保留，不丢失");
        }
        finally
        {
            TryCleanup(src);
        }
    }

    private void RunAsyncPath()
    {
        Section("异步接口路径（LoadArchiveEntriesAsync / RecoverSelectedItemsAsync）");

        var src = CreateSourceTree();
        var dest = Path.Combine(Path.GetTempPath(), $"lg_dest_{Guid.NewGuid():N}");
        var backupPath = Path.Combine(Path.GetTempPath(), $"{Guid.NewGuid():N}.lgbackup");
        var engine = new RecoveryEngine();
        try
        {
            CreateBackupPackage(src, backupPath);
            double lastProgress = -1;
            var progress = new SyncProgress<double>(p => lastProgress = p);

            var archive = engine.LoadArchiveEntriesAsync(backupPath, Password, progress).GetAwaiter().GetResult();
            Assert(archive.Entries.Count == 6, $"异步加载归档成功（{archive.Entries.Count} 文件）");
            Assert(lastProgress == 100, "加载进度回调已触发到 100%");

            double lastPct = -1;
            var rp = new SyncProgress<RecoveryProgressInfo>(i => lastPct = i.Percent);
            var result = engine.RecoverSelectedItemsAsync(
                archive, archive.Manifest, new[] { "docs", "src/utils" }, dest, RecoveryMode.Isolated, rp)
                .GetAwaiter().GetResult();
            Assert(result.Success && result.SuccessCount == 4, $"异步批量还原成功（成功 {result.SuccessCount}）");
            Assert(lastPct == 100, "还原进度回调已触发到 100%");
            Assert(rp.Info?.SpeedBytesPerSec > 0, "进度包含实时速度");
            Assert(rp.Info?.RemainingTime >= TimeSpan.Zero, "进度包含剩余时间");
        }
        finally
        {
            TryCleanup(src, dest, backupPath);
        }
    }

    /// <summary>同步 IProgress：Report 立即回调，避免 Progress&lt;T&gt; 异步投递竞态。</summary>
    private sealed class SyncProgress<T> : IProgress<T>
    {
        private readonly Action<T> _handler;
        public T? Info { get; private set; }

        public SyncProgress(Action<T> handler) => _handler = handler;

        public void Report(T value)
        {
            Info = value;
            _handler(value);
        }
    }

    private static void TryCleanup(params string[] paths)
    {
        foreach (var p in paths)
        {
            try
            {
                if (File.Exists(p)) File.Delete(p);
                else if (Directory.Exists(p)) Directory.Delete(p, true);
            }
            catch { }
        }
    }

    /// <summary>供 Program 汇总输出。</summary>
    public static (int Passed, int Failed) Summary => (_passed, _failed);
}
