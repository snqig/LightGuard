using System.Runtime.InteropServices;

namespace LightGuard.Core;

/// <summary>
/// 单实例检测 - 使用系统互斥量确保只运行一个实例
/// </summary>
internal static class SingleInstance
{
    private const string MutexName = "Global\\LightGuard_V2_SingleInstance_Mutex";
    private static Mutex? _mutex;

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool ReleaseMutex(IntPtr hMutex);

    public static bool TryAcquire()
    {
        _mutex = new Mutex(true, MutexName, out var createdNew);
        return createdNew;
    }

    public static void Release()
    {
        try { _mutex?.ReleaseMutex(); } catch { }
        _mutex?.Dispose();
        _mutex = null;
    }
}
