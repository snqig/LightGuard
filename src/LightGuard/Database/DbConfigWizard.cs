// © 2026 落尘（Luochen） 原创开发 - 保留所有权利
//
// dbconfig 交互式引导配置向导（v3.5 P2-2）
//   - 控制台入口：LightGuard.exe dbconfig
//   - 下拉选择数据库类型 → 分字段录入（IP/端口/用户名/密码/库名；SQLite 为文件路径）
//   - 内部拼接连接参数（不要求用户手写连接字符串）
//   - 保存前连接/文件有效性测试
//   - 快捷周期选项（不手写 cron）
//   - 密码经 HKDF 派生保存盐与凭据引用，不落盘明文

using LightGuard.Backup;
using LightGuard.Core;

namespace LightGuard.Database;

/// <summary>
/// 数据库备份配置引导向导（控制台交互）。
/// </summary>
public static class DbConfigWizard
{
    /// <summary>可配置的数据库类型列表。</summary>
    private static readonly DatabaseType[] SupportedTypes =
    {
        DatabaseType.MySQL,
        DatabaseType.PostgreSQL,
        DatabaseType.SQLite,
        DatabaseType.MariaDB,
        DatabaseType.SqlServer,
        DatabaseType.Access
    };

    /// <summary>
    /// 启动引导配置流程（阻塞直到完成）。
    /// </summary>
    /// <param name="appState">全局应用状态（读取/保存配置）。</param>
    /// <returns>0=成功，1=失败/取消。</returns>
    public static int Run(AppState appState)
    {
        try
        {
            Console.WriteLine("======================================");
            Console.WriteLine("  LightGuard 数据库备份配置向导 (dbconfig)");
            Console.WriteLine("======================================");

            // 授权联动：未授权状态仅允许查看，不允许保存启用型配置
            if (!LicenseGuard.IsBackupEnabled())
            {
                Console.WriteLine("[警告] 当前未授权，数据库备份功能将被禁用。");
                Console.WriteLine("        可录入配置但不会执行备份，激活授权后自动生效。");
            }

            var inst = new DbBackupInstance();

            // 1. 数据库类型下拉
            inst.DbType = PromptDbType();

            // 2. 分字段录入
            if (inst.DbType is DatabaseType.SQLite or DatabaseType.Access)
            {
                inst.DbFilePath = Prompt("数据库文件路径：", "");
                inst.Name = Prompt("实例名称：", Path.GetFileNameWithoutExtension(inst.DbFilePath) + "_backup");
            }
            else
            {
                inst.Host = Prompt("主机地址：", "localhost");
                var portDefault = inst.DbType switch
                {
                    DatabaseType.MySQL or DatabaseType.MariaDB => "3306",
                    DatabaseType.PostgreSQL => "5432",
                    DatabaseType.SqlServer => "1433",
                    _ => ""
                };
                inst.Port = int.TryParse(Prompt("端口：", portDefault), out var p) ? p : (portDefault != "" ? int.Parse(portDefault) : 0);
                inst.User = Prompt("用户名：", "");
                inst.Database = Prompt("数据库名：", "");
                if (inst.DbType is DatabaseType.MySQL or DatabaseType.MariaDB or DatabaseType.PostgreSQL or DatabaseType.SqlServer)
                {
                    inst.Name = Prompt("实例名称：", $"{inst.DbType}_{inst.Database}");
                }
            }

            // 3. 密码（SQLite/Access 无密码）
            var password = string.Empty;
            if (inst.DbType is not (DatabaseType.SQLite or DatabaseType.Access))
            {
                password = PromptPassword("密码（输入不显示）：");
            }

            // 4. 保存前连接/文件有效性测试
            Console.WriteLine();
            Console.Write("正在测试连接... ");
            var test = DbConnectionTester.Test(inst.DbType, inst.Host, inst.Port,
                inst.Database, inst.User, password, inst.DbFilePath);
            Console.WriteLine(test.Success ? "通过" : "失败");
            Console.WriteLine($"  -> {test.Message}");
            if (!test.Success)
            {
                var retry = Prompt("测试失败。重新输入？(y/n)：", "y");
                if (retry.Trim().ToLowerInvariant() is "y" or "yes")
                    return Run(appState);
                return 1;
            }

            // 5. 快捷周期选项（不手写 cron）
            Console.WriteLine();
            Console.WriteLine("选择备份周期：");
            var presets = new[] { CronPreset.Daily, CronPreset.Weekly, CronPreset.Every2Hours, CronPreset.Every6Hours, CronPreset.Every12Hours, CronPreset.Disabled };
            for (int i = 0; i < presets.Length; i++)
            {
                Console.WriteLine($"  [{i + 1}] {CronExpression.DescribePreset(presets[i])}");
            }
            var choice = Prompt("请输入编号（默认 1）：", "1");
            var preset = int.TryParse(choice, out var idx) && idx >= 1 && idx <= presets.Length
                ? presets[idx - 1]
                : CronPreset.Daily;

            inst.FullCron = CronExpression.FromPreset(preset);
            // 增量周期：支持增量的类型默认每 6 小时（SQLite 强制禁用由调度层拦截）
            if (DbIncrementalBackupEngine.IsIncrementalSupported(inst.DbType))
            {
                var incChoice = Prompt($"是否启用事务日志增量备份（{CronExpression.DescribePreset(CronPreset.Every6Hours)}）？(y/n)：", "y");
                inst.IncrementalCron = incChoice.Trim().ToLowerInvariant() is "y" or "yes"
                    ? CronExpression.FromPreset(CronPreset.Every6Hours)
                    : "";
            }
            else
            {
                inst.IncrementalCron = "";
                Console.WriteLine($"[提示] {inst.DbType} 不支持增量备份（SQLite 强制禁用），仅定时全量。");
            }

            // 6. 凭据与保存
            var config = appState.Config;
            if (!string.IsNullOrEmpty(password))
            {
                var salt = KeyDerivation.NewSalt();
                inst.CredentialRef = $"db_{inst.Name}";
                inst.SaltBase64 = KeyDerivation.SaltToBase64(salt);
                // 注册运行时凭据（HKDF 派生，不落盘明文）
                BackupCredentialStore.Register(inst.CredentialRef, password, inst.SaltBase64);
            }

            // 去重：同名实例覆盖
            config.DbBackupInstances.RemoveAll(x => x.Name == inst.Name);
            config.DbBackupInstances.Add(inst);
            ConfigManager.Save(config);

            Console.WriteLine();
            Console.WriteLine("======================================");
            Console.WriteLine($"  配置已保存：{inst.Name}（{inst.DbType}）");
            Console.WriteLine($"  全量周期：{CronExpression.DescribePreset(preset)}");
            Console.WriteLine($"  增量周期：{(!string.IsNullOrEmpty(inst.IncrementalCron) ? "每 6 小时" : "禁用")}");
            Console.WriteLine($"  密码：{(string.IsNullOrEmpty(password) ? "无需密码" : "已派生密钥保存（不落盘明文）")}");
            Console.WriteLine("======================================");
            return 0;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"配置失败：{ex.Message}");
            ErrorReporter.Report(ex, "dbconfig 引导配置失败");
            return 1;
        }
    }

    /// <summary>数据库类型下拉选择。</summary>
    private static DatabaseType PromptDbType()
    {
        Console.WriteLine();
        Console.WriteLine("选择数据库类型：");
        for (int i = 0; i < SupportedTypes.Length; i++)
        {
            Console.WriteLine($"  [{i + 1}] {SupportedTypes[i]}");
        }
        var choice = Prompt("请输入编号（默认 1）：", "1");
        if (int.TryParse(choice, out var idx) && idx >= 1 && idx <= SupportedTypes.Length)
            return SupportedTypes[idx - 1];
        Console.WriteLine("编号无效，默认 MySQL。");
        return DatabaseType.MySQL;
    }

    /// <summary>读取一行输入（带默认值）。</summary>
    private static string Prompt(string label, string defaultValue)
    {
        Console.Write(label);
        var input = Console.ReadLine()?.Trim();
        return string.IsNullOrEmpty(input) ? defaultValue : input;
    }

    /// <summary>读取密码（不回显）。</summary>
    private static string PromptPassword(string label)
    {
        Console.Write(label);
        var sb = new System.Text.StringBuilder();
        while (true)
        {
            var key = Console.ReadKey(intercept: true);
            if (key.Key == ConsoleKey.Enter)
                break;
            if (key.Key == ConsoleKey.Backspace && sb.Length > 0)
            {
                sb.Length--;
                continue;
            }
            if (!char.IsControl(key.KeyChar))
                sb.Append(key.KeyChar);
        }
        Console.WriteLine();
        return sb.ToString();
    }
}
