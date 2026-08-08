// © 2026 落尘（Luochen） 原创开发 - 保留所有权利
//
// DefenderScanPage UI 验证宿主（P1-5 三个修复项实测）：
//   1. ScanTime 配置为预设列表外的 "05:00" → 下拉框应显示 05:00（而非错误回退 02:30）
//   2. ThreatAction 配置为 "None" → 处置动作下拉框应显示"不处置（仅告警）"
//   3. SignatureMaxAgeDays 配置为 5 → 过期天数下拉框应显示"5 天"
// 启动后自动切到「策略配置」标签，10 秒后自动退出（供外部截图验证）。

using System.Reflection;
using LightGuard.Core;
using LightGuard.UI;
using LightGuard.UI.Pages;

namespace DefenderUiProbe;

internal static class Program
{
    [STAThread]
    private static void Main()
    {
        Application.SetHighDpiMode(HighDpiMode.PerMonitorV2);
        Application.EnableVisualStyles();
        Application.SetCompatibleTextRenderingDefault(false);

        var appState = AppState.Initialize();

        // 注入三个边界配置值（仅内存；页面策略改动会写回 config.json 的 Defender 节，
        // 验证后由外部脚本将该节恢复为默认值，不影响其它配置）
        var cfg = appState.Config.Defender;
        cfg.ScanTime = "05:00";          // 预设列表外 → 应动态加入并选中
        cfg.ThreatAction = "None";       // 第四选项 → 应显示"不处置（仅告警）"
        cfg.SignatureMaxAgeDays = 5;     // 预设 {1,3,7,14} 外 → 应动态加入并选中
        cfg.ScheduleEnabled = true;
        cfg.ScheduleScanType = "QuickScan";
        cfg.ScanPriority = 0;
        cfg.AutoUpdateSignatures = true;
        cfg.AlertOnThreat = true;
        cfg.AlertOnProtectionDisabled = true;

        Theme.InitFromMode(appState.UiMode);

        var form = new Form
        {
            Text = "DefenderScanPage UI 验证（P1-5 修复项）",
            Width = 1120,
            Height = 780,
            StartPosition = FormStartPosition.CenterScreen
        };

        var page = new DefenderScanPage(appState);
        page.Dock = DockStyle.Fill;
        form.Controls.Add(page);

        form.Shown += (_, _) =>
        {
            page.OnShown();
            // 自动切到「策略配置」标签（索引 3）
            try
            {
                var method = typeof(DefenderScanPage).GetMethod("SwitchTab",
                    BindingFlags.NonPublic | BindingFlags.Instance);
                method?.Invoke(page, new object[] { 3 });
            }
            catch { /* 反射失败不影响显示 */ }

            // 10 秒后自动退出（供外部截图）
            var timer = new System.Windows.Forms.Timer { Interval = 10_000 };
            timer.Tick += (_, _) =>
            {
                timer.Stop();
                DumpVerificationResult(page);
                form.Close();
            };
            timer.Start();
        };

        Application.Run(form);
    }

    /// <summary>把三个下拉框的实际选中值/候选集写入临时文件，供外部程序化验证。</summary>
    private static void DumpVerificationResult(DefenderScanPage page)
    {
        try
        {
            var lines = new List<string> { "DefenderScanPage 策略配置验证结果（P1-5）", "----" };
            const BindingFlags flags = BindingFlags.NonPublic | BindingFlags.Instance;

            void DumpCombo(string fieldName, string label)
            {
                var combo = typeof(DefenderScanPage).GetField(fieldName, flags)?.GetValue(page) as ComboBox;
                if (combo == null)
                {
                    lines.Add($"{label}: <控件未找到 {fieldName}>");
                    return;
                }
                var items = string.Join(",", combo.Items.Cast<object>().Select(x => x.ToString()));
                lines.Add($"{label}: Selected=\"{combo.SelectedItem}\" Items=[{items}]");
            }

            // 三个修复项对应控件
            DumpCombo("_scanTimeCombo", "扫描时间");
            DumpCombo("_remediationCombo", "处置动作");
            DumpCombo("_sigMaxAgeCombo", "过期天数");

            var resultPath = Path.Combine(Path.GetTempPath(), "lg_probe_result.txt");
            File.WriteAllLines(resultPath, lines);
            Console.WriteLine($"[Probe] 验证结果已写入 {resultPath}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[Probe] 输出验证结果失败: {ex.Message}");
        }
    }
}
