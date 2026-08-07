// © 2026 落尘（Luochen） 原创开发 - 保留所有权利

namespace SelectiveRecoveryTest;

/// <summary>
/// 选择性还原测试入口。
/// <para>用法：SelectiveRecoveryTest（无需参数）</para>
/// </summary>
internal static class Program
{
    private static int Main()
    {
        Console.WriteLine("==============================================");
        Console.WriteLine(" LightGuard 选择性还原功能测试");
        Console.WriteLine("==============================================");

        try
        {
            new SelectiveRecoveryTests().RunAll();
        }
        catch (Exception ex)
        {
            Console.WriteLine();
            Console.WriteLine($"[FATAL] 测试执行异常：{ex}");
            return 1;
        }

        var (passed, failed) = SelectiveRecoveryTests.Summary;
        Console.WriteLine();
        Console.WriteLine("==============================================");
        Console.WriteLine($"结果：通过 {passed} / 失败 {failed}");
        Console.WriteLine("==============================================");
        return failed == 0 ? 0 : 1;
    }
}
