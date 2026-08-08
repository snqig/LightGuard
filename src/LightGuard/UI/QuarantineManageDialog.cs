// © 2026 落尘（Luochen） 原创开发 - 保留所有权利

using LightGuard.Core;
using LightGuard.Security;
using LightGuard.UI.Controls;

namespace LightGuard.UI;

/// <summary>
/// 隔离区管理弹窗（P1-5 Defender 全业务集成）。
/// <para>展示 LightGuard 加密隔离区内的全部隔离记录，支持：</para>
/// <list type="bullet">
///   <item>恢复所选：解密并恢复到原始路径（可选覆盖）。</item>
///   <item>删除所选：彻底删除隔离记录与加密文件。</item>
/// </list>
/// </summary>
public sealed class QuarantineManageDialog : Form
{
    private readonly QuarantineManager _manager = new();
    private ListView? _listView;

    public QuarantineManageDialog()
    {
        FormBorderStyle = FormBorderStyle.FixedDialog;
        StartPosition = FormStartPosition.CenterParent;
        MaximizeBox = false;
        MinimizeBox = false;
        ShowInTaskbar = false;
        BackColor = Theme.Background;
        ForeColor = Theme.TextPrimary;
        Font = Theme.BodyFont;
        ClientSize = new Size(620, 400);
        Text = "隔离区管理";

        BuildUi();
        RefreshList();
    }

    private void BuildUi()
    {
        var title = new Label
        {
            Text = "隔离区管理（AES-256-GCM 加密隔离）",
            Font = Theme.HeaderFont,
            ForeColor = Theme.Accent,
            Location = new Point(16, 12),
            Size = new Size(580, 26),
            BackColor = Color.Transparent
        };
        Controls.Add(title);

        var listCard = new Panel
        {
            Location = new Point(12, 48),
            Size = new Size(596, 296),
            BackColor = Theme.CardBg
        };
        Controls.Add(listCard);

        _listView = new ListView
        {
            Location = new Point(8, 8),
            Size = new Size(580, 280),
            View = View.Details,
            FullRowSelect = true,
            GridLines = true,
            Font = Theme.SmallFont,
            BackColor = Theme.CardBg,
            ForeColor = Theme.TextPrimary,
            BorderStyle = BorderStyle.None
        };
        _listView.Columns.Add("文件名", 150);
        _listView.Columns.Add("原始路径", 250);
        _listView.Columns.Add("隔离时间", 110);
        _listView.Columns.Add("原因", 60);
        listCard.Controls.Add(_listView);

        var restoreBtn = new AccentButton
        {
            Text = "恢复所选",
            Location = new Point(12, 356),
            Size = new Size(110, 32)
        };
        restoreBtn.Click += OnRestore;
        Controls.Add(restoreBtn);

        var deleteBtn = new AccentButton
        {
            Text = "删除所选",
            Location = new Point(132, 356),
            Size = new Size(110, 32)
        };
        deleteBtn.Click += OnDelete;
        Controls.Add(deleteBtn);

        var closeBtn = new AccentButton
        {
            Text = "关闭",
            Location = new Point(494, 356),
            Size = new Size(110, 32)
        };
        closeBtn.Click += () => Close();
        Controls.Add(closeBtn);
    }

    private void RefreshList()
    {
        _listView!.Items.Clear();
        var records = _manager.ListQuarantinedFiles();
        foreach (var r in records)
        {
            var item = new ListViewItem(r.FileName);
            item.SubItems.Add(r.OriginalPath);
            item.SubItems.Add(r.QuarantinedAt.ToString("yyyy-MM-dd HH:mm"));
            item.SubItems.Add(r.ThreatName ?? r.Reason);
            item.Tag = r.Id;
            _listView.Items.Add(item);
        }
    }

    private void OnRestore()
    {
        if (_listView!.SelectedItems.Count == 0)
        {
            MessageBoxHelper.Warn("请先选择要恢复的隔离记录。");
            return;
        }

        int ok = 0, fail = 0;
        foreach (ListViewItem item in _listView.SelectedItems)
        {
            var id = item.Tag as string;
            if (string.IsNullOrEmpty(id)) continue;

            try
            {
                ok += _manager.RestoreFile(id) ? 1 : 0;
            }
            catch (Exception ex)
            {
                fail++;
                ErrorReporter.Report(ex, $"隔离区恢复失败: {item.Text}");
            }
        }

        MessageBoxHelper.Info($"恢复完成：成功 {ok} 个，失败 {fail} 个。");
        RefreshList();
    }

    private void OnDelete()
    {
        if (_listView!.SelectedItems.Count == 0)
        {
            MessageBoxHelper.Warn("请先选择要删除的隔离记录。");
            return;
        }
        if (!MessageBoxHelper.Confirm("删除后将无法恢复，确认删除所选隔离记录？"))
            return;

        int ok = 0;
        foreach (ListViewItem item in _listView.SelectedItems)
        {
            var id = item.Tag as string;
            if (string.IsNullOrEmpty(id)) continue;

            try
            {
                ok += _manager.DeleteQuarantined(id) ? 1 : 0;
            }
            catch (Exception ex)
            {
                ErrorReporter.Report(ex, $"隔离区删除失败: {item.Text}");
            }
        }

        MessageBoxHelper.Info($"已删除 {ok} 条隔离记录。");
        RefreshList();
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing) _manager.Dispose();
        base.Dispose(disposing);
    }
}
