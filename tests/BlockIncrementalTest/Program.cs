// © 2026 落尘（Luochen） 原创开发 - 保留所有权利

namespace BlockIncrementalTest;

/// <summary>
/// 块级增量引擎 + 增量链管理测试入口。
/// <para>用法：BlockIncrementalTest（无需参数）</para>
/// </summary>
internal static class Program
{
    private static int Main()
    {
        Console.WriteLine("==============================================");
        Console.WriteLine(" LightGuard 块级增量引擎 + 增量链测试");
        Console.WriteLine("==============================================");

        int passed = 0, failed = 0;
        try
        {
            // WORM 自动锁定：测试进程禁用（否则测试包被 ACL 锁定，临时目录无法清理）
            LightGuard.Backup.WormManager.AutoLockDisabled = true;

            var engine = new BlockIncrementalTests();
            engine.RunAll();
            var (p1, f1) = BlockIncrementalTests.Summary;
            passed += p1; failed += f1;

            var chain = new ChainTests();
            chain.RunAll();
            var (p2, f2) = ChainTests.Summary;
            passed += p2; failed += f2;
        }
        catch (Exception ex)
        {
            Console.WriteLine();
            Console.WriteLine($"[FATAL] 测试执行异常：{ex}");
            return 1;
        }

        Console.WriteLine();
        Console.WriteLine("==============================================");
        Console.WriteLine($"结果：通过 {passed} / 失败 {failed}");
        Console.WriteLine("==============================================");
        return failed == 0 ? 0 : 1;
    }
}
