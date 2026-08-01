using System.Diagnostics;
using System.ServiceProcess;

namespace LightGuard.Native;

/// <summary>
/// Windows 服务和计划任务管理助手
/// 用于禁用流氓软件的后台服务、自动更新服务
/// </summary>
public static class ServiceHelper
{
    /// <summary>
    /// 获取所有服务列表
    /// </summary>
    public static List<ServiceInfo> GetAllServices()
    {
        var list = new List<ServiceInfo>();
        try
        {
            var services = ServiceController.GetServices();
            foreach (var svc in services)
            {
                list.Add(new ServiceInfo
                {
                    Name = svc.ServiceName,
                    DisplayName = svc.DisplayName,
                    Status = svc.Status.ToString(),
                    StartType = svc.StartType.ToString()
                });
            }
        }
        catch { }
        return list;
    }

    /// <summary>
    /// 禁用服务
    /// </summary>
    public static bool DisableService(string serviceName)
    {
        try
        {
            // 先停止服务
            using var svc = new ServiceController(serviceName);
            if (svc.Status == ServiceControllerStatus.Running)
            {
                svc.Stop();
                svc.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(10));
            }

            // 设置为禁用
            RunSc($"config \"{serviceName}\" start= disabled");
            return true;
        }
        catch
        {
            // 尝试直接用 sc 命令
            try
            {
                RunSc($"stop \"{serviceName}\"");
                RunSc($"config \"{serviceName}\" start= disabled");
                return true;
            }
            catch { return false; }
        }
    }

    /// <summary>
    /// 启用服务
    /// </summary>
    public static bool EnableService(string serviceName, string startType = "auto")
    {
        try
        {
            RunSc($"config \"{serviceName}\" start= {startType}");
            using var svc = new ServiceController(serviceName);
            svc.Start();
            return true;
        }
        catch { return false; }
    }

    /// <summary>
    /// 检查服务是否存在
    /// </summary>
    public static bool ServiceExists(string serviceName)
    {
        try
        {
            using var svc = new ServiceController(serviceName);
            return true;
        }
        catch { return false; }
    }

    /// <summary>
    /// 删除服务
    /// </summary>
    public static bool DeleteService(string serviceName)
    {
        try
        {
            RunSc($"delete \"{serviceName}\"");
            return true;
        }
        catch { return false; }
    }

    /// <summary>
    /// 禁用计划任务
    /// </summary>
    public static bool DisableScheduledTask(string taskName)
    {
        try
        {
            RunSchTasks($"/Change /TN \"{taskName}\" /DISABLE");
            return true;
        }
        catch { return false; }
    }

    /// <summary>
    /// 启用计划任务
    /// </summary>
    public static bool EnableScheduledTask(string taskName)
    {
        try
        {
            RunSchTasks($"/Change /TN \"{taskName}\" /ENABLE");
            return true;
        }
        catch { return false; }
    }

    /// <summary>
    /// 删除计划任务
    /// </summary>
    public static bool DeleteScheduledTask(string taskName)
    {
        try
        {
            RunSchTasks($"/Delete /TN \"{taskName}\" /F");
            return true;
        }
        catch { return false; }
    }

    /// <summary>
    /// 获取所有计划任务
    /// </summary>
    public static List<string> GetAllScheduledTasks()
    {
        var list = new List<string>();
        try
        {
            var output = RunSchTasks("/Query /FO CSV /NH");
            var lines = output.Split('\n', StringSplitOptions.RemoveEmptyEntries);
            foreach (var line in lines)
            {
                var parts = line.Split(',');
                if (parts.Length > 0)
                {
                    var name = parts[0].Trim('"', ' ', '\r');
                    if (!string.IsNullOrEmpty(name))
                        list.Add(name);
                }
            }
        }
        catch { }
        return list;
    }

    /// <summary>
    /// 备份服务配置
    /// </summary>
    public static string BackupServices(string backupDir)
    {
        try
        {
            Directory.CreateDirectory(backupDir);
            var filePath = Path.Combine(backupDir, $"services_{DateTime.Now:yyyyMMdd_HHmmss}.txt");
            var services = GetAllServices();
            var lines = services.Select(s => $"{s.Name}\t{s.DisplayName}\t{s.Status}\t{s.StartType}");
            File.WriteAllLines(filePath, lines);
            return filePath;
        }
        catch { return ""; }
    }

    private static string RunSc(string args)
    {
        var psi = new ProcessStartInfo
        {
            FileName = "sc.exe",
            Arguments = args,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };
        using var proc = Process.Start(psi);
        var output = proc?.StandardOutput.ReadToEnd() ?? "";
        proc?.WaitForExit(10000);
        return output;
    }

    private static string RunSchTasks(string args)
    {
        var psi = new ProcessStartInfo
        {
            FileName = "schtasks.exe",
            Arguments = args,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            StandardOutputEncoding = System.Text.Encoding.Unicode
        };
        using var proc = Process.Start(psi);
        var output = proc?.StandardOutput.ReadToEnd() ?? "";
        proc?.WaitForExit(10000);
        return output;
    }
}

public sealed class ServiceInfo
{
    public string Name { get; set; } = "";
    public string DisplayName { get; set; } = "";
    public string Status { get; set; } = "";
    public string StartType { get; set; } = "";
}
