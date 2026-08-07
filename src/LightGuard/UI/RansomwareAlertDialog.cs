// © 2026 落尘（Luochen） 原创开发 - 保留所有权利

using System.Diagnostics;
using System.Drawing.Drawing2D;
using LightGuard.Core;
using LightGuard.Defender;
using LightGuard.Modules;
using LightGuard.Ransomware;

namespace LightGuard.UI;

/// <summary>
/// 勒索防御告警弹窗（P1-6 联动）。
/// <para>当 ETW+YARA 检测到勒索行为时弹出，提供：</para>
/// <list type="bullet">
///   <item>【扫描可疑进程目录】— 调用 Defender 对可疑进程所在目录执行按需查杀。</item>
///   <item>【仅记录】— 不处置，仅留存审计日志。</item>
/// </list>
/// <para>服务器模式下不弹窗，仅记录审计日志（由调用方判断）。</para>
/// </summary>
public sealed class RansomwareAlertDialog : Form
{
    private readonly DefenseAlert _alert;
    private readonly int _processId;

    /// <summary>用户是否请求执行扫描</summary>
    public bool RequestedScan { get; private set; }

    public RansomwareAlertDialog(DefenseAlert alert, int processId)
    {
        _alert = alert;
        _processId = processId;

        FormBorderStyle = FormBorderStyle.FixedDialog;
        StartPosition = FormStartPosition.CenterParent;
        MaximizeBox = false;
        MinimizeBox = false;
        ShowInTaskbar = false;
        BackColor = Theme.Background;
        ForeColor = Theme.TextPrimary;
        Font = Theme.BodyFont;
        ClientSize = new Size(560, 300);
        Text = "LightGuard 勒索防御告警";

        BuildUi();
    }

    private void BuildUi()
    {
        var topColor = _alert.RiskLevel >= RiskLevel.Critical ? Theme.Error : Theme.Warning;

        // 标题
        var title = new Label
        {
            Text = "⚠ 检测到疑似勒索行为！",
            Font = Theme.HeaderFont,
            ForeColor = topColor,
            Location = new Point(20, 14),
            Size = new Size(520, 28),
            BackColor = Color.Transparent
        };
        Controls.Add(title);

        // 摘要
        var summary = new Label
        {
            Text = Truncate(_alert.Summary, 120),
            Font = Theme.BodyFont,
            ForeColor = Theme.TextPrimary,
            Location = new Point(20, 52),
            Size = new Size(520, 60),
            BackColor = Color.Transparent,
            AutoEllipsis = true
        };
        Controls.Add(summary);

        // 进程信息
        var processName = GetProcessName(_processId);
        var processLine = new Label
        {
            Text = $"可疑进程：PID={_processId}  {processName}",
            Font = Theme.BodyFont,
            ForeColor = Theme.TextSecondary,
            Location = new Point(20, 120),
            Size = new Size(520, 24),
            BackColor = Color.Transparent
        };
        Controls.Add(processLine);

        // 已执行响应
        var actions = _alert.ResponseActions.Count > 0
            ? string.Join(" / ", _alert.ResponseActions.Select(a => a switch
            {
                ResponseAction.ProcessSuspended => "进程已挂起",
                ResponseAction.FirewallBlocked => "已断网隔离",
                ResponseAction.VssLocked => "VSS 已锁定",
                _ => "已告警"
            }))
            : "—";
        var respLine = new Label
        {
            Text = "已执行响应：" + actions,
            Font = Theme.BodyFont,
            ForeColor = Theme.Success,
            Location = new Point(20, 150),
            Size = new Size(520, 24),
            BackColor = Color.Transparent
        };
        Controls.Add(respLine);

        // 操作按钮
        var scanBtn = new Button
        {
            Text = "扫描可疑进程目录",
            Location = new Point(20, 210),
            Size = new Size(190, 44),
            FlatStyle = FlatStyle.Flat,
            BackColor = Theme.Error,
            ForeColor = Color.White,
            Font = Theme.BodyFont,
            Cursor = Cursors.Hand
        };
        scanBtn.FlatAppearance.BorderSize = 0;
        scanBtn.Click += (s, e) =>
        {
            RequestedScan = true;
            DialogResult = DialogResult.OK;
            Close();
        };

        var ignoreBtn = new Button
        {
            Text = "仅记录",
            Location = new Point(230, 210),
            Size = new Size(140, 44),
            FlatStyle = FlatStyle.Flat,
            BackColor = Theme.CardHover,
            ForeColor = Theme.TextPrimary,
            Font = Theme.BodyFont,
            Cursor = Cursors.Hand
        };
        ignoreBtn.FlatAppearance.BorderSize = 0;
        ignoreBtn.Click += (s, e) =>
        {
            DialogResult = DialogResult.Cancel;
            Close();
        };

        var cancelBtn = new Button
        {
            Text = "忽略",
            Location = new Point(390, 210),
            Size = new Size(150, 44),
            FlatStyle = FlatStyle.Flat,
            BackColor = Theme.CardHover,
            ForeColor = Theme.TextSecondary,
            Font = Theme.BodyFont,
            Cursor = Cursors.Hand
        };
        cancelBtn.FlatAppearance.BorderSize = 0;
        cancelBtn.Click += (s, e) =>
        {
            DialogResult = DialogResult.Cancel;
            Close();
        };

        Controls.Add(scanBtn);
        Controls.Add(ignoreBtn);
        Controls.Add(cancelBtn);
    }

    /// <summary>根据 PID 获取进程名</summary>
    private static string GetProcessName(int pid)
    {
        if (pid <= 0) return "（未知）";
        try
        {
            using var p = Process.GetProcessById(pid);
            return string.IsNullOrEmpty(p.ProcessName) ? $"PID {pid}" : p.ProcessName + ".exe";
        }
        catch
        {
            return $"PID {pid}（进程已退出）";
        }
    }

    private static string Truncate(string text, int maxLen)
    {
        if (string.IsNullOrEmpty(text)) return "";
        return text.Length <= maxLen ? text : text[..maxLen] + "...";
    }

    protected override void OnPaintBackground(PaintEventArgs e)
    {
        base.OnPaintBackground(e);
        var g = e.Graphics;
        g.SmoothingMode = SmoothingMode.AntiAlias;
        using var pen = new Pen(Theme.Border, 1);
        Theme.DrawRoundedBorder(g, pen, ClientRectangle, 8);
    }
}
