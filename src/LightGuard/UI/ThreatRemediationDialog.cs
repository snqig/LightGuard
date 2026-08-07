// © 2026 落尘（Luochen） 原创开发 - 保留所有权利

using System.Drawing.Drawing2D;
using LightGuard.Core;
using LightGuard.Defender;

namespace LightGuard.UI;

/// <summary>
/// 风险处置弹窗（P1-6 业务联动）。
/// <para>当 Defender 查杀发现威胁时，弹出此窗让用户选择处置策略：</para>
/// <list type="bullet">
///   <item>隔离（推荐）：将威胁文件移入 LightGuard 加密隔离区。</item>
///   <item>删除：永久删除威胁文件。</item>
///   <item>仅告警：不处置，仅记录审计日志。</item>
/// </list>
/// </summary>
public sealed class ThreatRemediationDialog : Form
{
    /// <summary>用户选择的处置动作（ShowDialog 返回 OK 后有效）</summary>
    public ThreatAction SelectedAction { get; private set; } = ThreatAction.None;

    private readonly List<DefenderThreat> _threats;
    private readonly string _source;

    public ThreatRemediationDialog(List<DefenderThreat> threats, string source)
    {
        _threats = threats ?? new List<DefenderThreat>();
        _source = source;

        FormBorderStyle = FormBorderStyle.FixedDialog;
        StartPosition = FormStartPosition.CenterParent;
        MaximizeBox = false;
        MinimizeBox = false;
        ShowInTaskbar = false;
        BackColor = Theme.Background;
        ForeColor = Theme.TextPrimary;
        Font = Theme.BodyFont;
        ClientSize = new Size(520, 320);
        Text = LangHelper.GetText("defender.remediation_title", "风险处置");

        BuildUi();
    }

    private void BuildUi()
    {
        // 标题
        var title = new Label
        {
            Text = LangHelper.GetText("defender.remediation_title", "风险处置"),
            Font = Theme.HeaderFont,
            ForeColor = Theme.Error,
            Location = new Point(20, 16),
            Size = new Size(480, 28),
            BackColor = Color.Transparent
        };
        Controls.Add(title);

        // 威胁列表说明
        var summary = new Label
        {
            Text = string.Format(LangHelper.GetText("defender.remediation_summary", "扫描（{0}）发现 {1} 个威胁，请选择处置策略："),
                _source, _threats.Count),
            Font = Theme.BodyFont,
            ForeColor = Theme.TextSecondary,
            Location = new Point(20, 52),
            Size = new Size(480, 24),
            BackColor = Color.Transparent
        };
        Controls.Add(summary);

        // 威胁明细列表（最多展示 6 条）
        var listBox = new ListBox
        {
            Location = new Point(20, 82),
            Size = new Size(480, 96),
            BorderStyle = BorderStyle.FixedSingle,
            BackColor = Theme.CardBg,
            ForeColor = Theme.TextPrimary,
            Font = Theme.SmallFont,
            IntegralHeight = false
        };
        foreach (var t in _threats.Take(6))
        {
            var path = string.IsNullOrEmpty(t.FilePath) ? "—" : t.FilePath;
            listBox.Items.Add($"{t.ThreatName}  @  {path}");
        }
        if (_threats.Count > 6)
            listBox.Items.Add($"... 另有 {_threats.Count - 6} 个威胁");
        Controls.Add(listBox);

        // 处置策略按钮（三选一）
        var quarantineBtn = new Button
        {
            Text = LangHelper.GetText("defender.action.quarantine", "隔离"),
            Location = new Point(20, 200),
            Size = new Size(140, 40),
            FlatStyle = FlatStyle.Flat,
            BackColor = Theme.Warning,
            ForeColor = Color.White,
            Font = Theme.BodyFont,
            Cursor = Cursors.Hand,
            Tag = ThreatAction.Quarantine
        };
        quarantineBtn.FlatAppearance.BorderSize = 0;
        quarantineBtn.Click += (s, e) => Finish((ThreatAction)((Button)s!).Tag!);

        var removeBtn = new Button
        {
            Text = LangHelper.GetText("defender.action.remove", "删除"),
            Location = new Point(180, 200),
            Size = new Size(140, 40),
            FlatStyle = FlatStyle.Flat,
            BackColor = Theme.Error,
            ForeColor = Color.White,
            Font = Theme.BodyFont,
            Cursor = Cursors.Hand,
            Tag = ThreatAction.Remove
        };
        removeBtn.FlatAppearance.BorderSize = 0;
        removeBtn.Click += (s, e) => Finish((ThreatAction)((Button)s!).Tag!);

        var allowBtn = new Button
        {
            Text = LangHelper.GetText("defender.action.allow", "仅告警"),
            Location = new Point(340, 200),
            Size = new Size(160, 40),
            FlatStyle = FlatStyle.Flat,
            BackColor = Theme.CardHover,
            ForeColor = Theme.TextPrimary,
            Font = Theme.BodyFont,
            Cursor = Cursors.Hand,
            Tag = ThreatAction.Allow
        };
        allowBtn.FlatAppearance.BorderSize = 0;
        allowBtn.Click += (s, e) => Finish((ThreatAction)((Button)s!).Tag!);

        Controls.Add(quarantineBtn);
        Controls.Add(removeBtn);
        Controls.Add(allowBtn);

        // 底部提示
        var tip = new Label
        {
            Text = LangHelper.GetText("defender.remediation_tip", "提示：隔离文件可通过“隔离区”恢复；删除不可恢复。"),
            Font = Theme.SmallFont,
            ForeColor = Theme.TextTertiary,
            Location = new Point(20, 258),
            Size = new Size(480, 20),
            BackColor = Color.Transparent
        };
        Controls.Add(tip);
    }

    private void Finish(ThreatAction action)
    {
        SelectedAction = action;
        DialogResult = DialogResult.OK;
        Close();
    }

    protected override void OnPaintBackground(PaintEventArgs e)
    {
        base.OnPaintBackground(e);
        // 边框圆角（视觉统一）
        var g = e.Graphics;
        g.SmoothingMode = SmoothingMode.AntiAlias;
        using var pen = new Pen(Theme.Border, 1);
        Theme.DrawRoundedBorder(g, pen, ClientRectangle, 8);
    }
}
