// © 2026 落尘（Luochen） 原创开发 - 保留所有权利

using LightGuard.Backup;
using LightGuard.Recovery;

namespace LightGuard.UI.Pages;

/// <summary>
/// 备份内容浏览对话框（选择性还原入口）。
/// <para>左侧目录树（懒加载 + 三态复选框）、右侧文件列表（搜索 / 排序 / 勾选）、
/// 底部选中统计与确定操作。勾选目录自动递归选择其下全部文件。</para>
/// </summary>
public sealed class BackupBrowserForm : Form
{
    private readonly RecoveryArchive _archive;
    private readonly BackupManifest _manifest;
    private readonly string _backupPath;

    // ===== 索引 =====
    private readonly Dictionary<string, List<RecoveryArchiveEntry>> _dirFiles = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, List<RecoveryArchiveEntry>> _dirDescFiles = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, List<string>> _dirSubs = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, RecoveryArchiveEntry> _entryByName = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _selected = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _loadedDirs = new(StringComparer.OrdinalIgnoreCase);

    // ===== 控件 =====
    private readonly TreeView _tree = new();
    private readonly ListView _list = new();
    private readonly TextBox _searchBox = new();
    private readonly ComboBox _sortCombo = new();
    private readonly Button _sortDirBtn = new();
    private readonly Label _statusLabel = new();

    private string _currentDir = "";
    private bool _searching;
    private bool _sortAsc = true;
    private int _sortField; // 0=名称 1=大小 2=修改时间

    // ===== 虚拟列表（VirtualMode） =====
    private readonly List<object> _visibleItems = new();               // string=目录行 / RecoveryArchiveEntry=文件行
    private readonly Dictionary<int, ListViewItem> _virtualCache = new();
    private readonly System.Windows.Forms.Timer _searchDebounce = new() { Interval = 250 };

    /// <summary>用户勾选的文件相对路径集合（DialogResult.OK 后读取）。</summary>
    public IReadOnlyCollection<string> SelectedRelPaths => _selected.ToList();

    public BackupBrowserForm(RecoveryArchive archive, BackupManifest manifest, string backupPath)
    {
        _archive = archive;
        _manifest = manifest;
        _backupPath = backupPath;

        Text = $"备份内容浏览 - {Path.GetFileName(backupPath)}";
        Size = new Size(960, 680);
        MinimumSize = new Size(720, 520);
        StartPosition = FormStartPosition.CenterParent;
        BackColor = Theme.Background;
        Font = Theme.BodyFont;

        BuildIndex();
        BuildUi();
        LoadRootTree();
        ShowDirectory("");
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _searchDebounce?.Dispose();
        }
        base.Dispose(disposing);
    }

    // ==================== 索引构建 ====================

    private void BuildIndex()
    {
        foreach (var e in _archive.Entries)
        {
            _entryByName[e.RelPath] = e;
            var parts = e.RelPath.Replace('\\', '/').Split('/', StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length == 0) continue;

            var parent = parts.Length == 1 ? "" : string.Join('/', parts, 0, parts.Length - 1);
            if (!_dirFiles.TryGetValue(parent, out var fl)) _dirFiles[parent] = fl = new();
            fl.Add(e);

            for (int i = 0; i < parts.Length - 1; i++)
            {
                var prefix = string.Join('/', parts, 0, i + 1);
                if (!_dirDescFiles.TryGetValue(prefix, out var dl)) _dirDescFiles[prefix] = dl = new();
                dl.Add(e);

                if (i < parts.Length - 2)
                {
                    var sub = parts[i + 1];
                    if (!_dirSubs.TryGetValue(prefix, out var subs)) _dirSubs[prefix] = subs = new();
                    if (!subs.Contains(sub, StringComparer.OrdinalIgnoreCase)) subs.Add(sub);
                }
            }

            if (!_dirDescFiles.TryGetValue("", out var rootList)) _dirDescFiles[""] = rootList = new();
            rootList.Add(e);
        }

        foreach (var kv in _dirSubs) kv.Value.Sort(StringComparer.OrdinalIgnoreCase);
    }

    // ==================== 选择状态计算 ====================

    private int DirFileCount(string dir)
        => _dirDescFiles.TryGetValue(dir, out var l) ? l.Count : 0;

    private int DirSelectedCount(string dir)
        => _dirDescFiles.TryGetValue(dir, out var l) ? l.Count(e => _selected.Contains(e.RelPath)) : 0;

    private CheckState DirState(string dir)
    {
        var total = DirFileCount(dir);
        if (total == 0) return CheckState.Unchecked;
        var sel = DirSelectedCount(dir);
        if (sel == 0) return CheckState.Unchecked;
        if (sel >= total) return CheckState.Checked;
        return CheckState.Indeterminate;
    }

    private void ToggleDirSelection(TreeNode node, bool select)
    {
        var dir = node.Tag as string ?? "";
        if (_dirDescFiles.TryGetValue(dir, out var files))
        {
            foreach (var e in files)
            {
                if (select) _selected.Add(e.RelPath);
                else _selected.Remove(e.RelPath);
            }
        }
        RefreshNodeAndAncestors(node);
        if (_currentDir == dir) ShowDirectory(dir);
        UpdateStatus();
    }

    private void RefreshNodeAndAncestors(TreeNode? node)
    {
        while (node != null)
        {
            var dir = node.Tag as string ?? "";
            node.StateImageIndex = DirState(dir) switch
            {
                CheckState.Checked => 1,
                CheckState.Indeterminate => 2,
                _ => 0
            };
            node = node.Parent;
        }
    }

    // ==================== UI 构建 ====================

    private void BuildUi()
    {
        // 顶部搜索 / 排序栏
        _searchBox.Location = new Point(12, 10);
        _searchBox.Size = new Size(360, 26);
        _searchBox.PlaceholderText = "搜索文件名（实时过滤）";
        _searchBox.TextChanged += OnSearchChanged;
        Controls.Add(_searchBox);

        _sortCombo.Location = new Point(384, 10);
        _sortCombo.Size = new Size(150, 26);
        _sortCombo.DropDownStyle = ComboBoxStyle.DropDownList;
        _sortCombo.Items.AddRange(new object[] { "按名称", "按大小", "按修改时间" });
        _sortCombo.SelectedIndex = 0;
        _sortCombo.SelectedIndexChanged += (s, e) => { _sortField = _sortCombo.SelectedIndex; RefreshList(); };
        Controls.Add(_sortCombo);

        _sortDirBtn.Text = "升序 ▲";
        _sortDirBtn.Location = new Point(542, 8);
        _sortDirBtn.Size = new Size(88, 30);
        _sortDirBtn.FlatStyle = FlatStyle.Flat;
        _sortDirBtn.BackColor = Theme.CardBg;
        _sortDirBtn.ForeColor = Theme.TextPrimary;
        _sortDirBtn.Click += (s, e) => { _sortAsc = !_sortAsc; _sortDirBtn.Text = _sortAsc ? "升序 ▲" : "降序 ▼"; RefreshList(); };
        Controls.Add(_sortDirBtn);

        // 中部：目录树 + 文件列表
        var split = new SplitContainer
        {
            Location = new Point(12, 46),
            Size = new Size(936, 560),
            SplitterDistance = 300,
            BackColor = Theme.Background,
            Anchor = AnchorStyles.Top | AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right
        };
        Controls.Add(split);

        // 目录树：三态复选框（StateImageList）
        _tree.Dock = DockStyle.Fill;
        _tree.HideSelection = false;
        _tree.BackColor = Theme.CardBg;
        _tree.ForeColor = Theme.TextPrimary;
        _tree.BorderStyle = BorderStyle.None;
        _tree.StateImageList = BuildStateImages();
        _tree.BeforeExpand += OnTreeBeforeExpand;
        _tree.AfterSelect += (s, e) => { if (e.Node != null) { _currentDir = (e.Node.Tag as string) ?? ""; if (!_searching) ShowDirectory(_currentDir); } };
        _tree.NodeMouseClick += OnTreeNodeMouseClick;
        split.Panel1.Controls.Add(_tree);

        // 文件列表
        _list.Dock = DockStyle.Fill;
        _list.View = View.Details;
        _list.FullRowSelect = true;
        _list.GridLines = false;
        _list.CheckBoxes = true;
        _list.VirtualMode = true;   // 虚拟模式：仅渲染可视区域条目，10 万文件级无卡顿
        _list.BackColor = Theme.CardBg;
        _list.ForeColor = Theme.TextPrimary;
        _list.BorderStyle = BorderStyle.None;
        _list.Columns.Add("名称", 340);
        _list.Columns.Add("大小", 100, HorizontalAlignment.Right);
        _list.Columns.Add("修改时间", 150);
        _list.RetrieveVirtualItem += OnRetrieveVirtualItem;
        _list.CacheVirtualItems += OnCacheVirtualItems;
        _list.ItemChecked += OnListItemChecked;
        _list.ItemCheck += OnListItemCheckPreventDir;
        split.Panel2.Controls.Add(_list);

        // 搜索防抖：停止输入 250ms 后再刷新，避免大数据量下逐键全量扫描卡顿
        _searchDebounce.Tick += (s, e) =>
        {
            _searchDebounce.Stop();
            RefreshList();
        };

        // 底部状态 + 操作按钮
        _statusLabel.Location = new Point(12, 616);
        _statusLabel.Size = new Size(560, 24);
        _statusLabel.ForeColor = Theme.TextSecondary;
        _statusLabel.Font = Theme.SmallFont;
        Controls.Add(_statusLabel);

        var cancelBtn = new Button
        {
            Text = "取消",
            Location = new Point(770, 612),
            Size = new Size(80, 30),
            FlatStyle = FlatStyle.Flat,
            BackColor = Theme.CardBg,
            ForeColor = Theme.TextPrimary,
            Anchor = AnchorStyles.Bottom | AnchorStyles.Right
        };
        cancelBtn.Click += (s, e) => DialogResult = DialogResult.Cancel;
        Controls.Add(cancelBtn);

        var okBtn = new Button
        {
            Text = "确定还原",
            Location = new Point(858, 612),
            Size = new Size(90, 30),
            FlatStyle = FlatStyle.Flat,
            BackColor = Theme.Accent,
            ForeColor = Color.White,
            Anchor = AnchorStyles.Bottom | AnchorStyles.Right
        };
        okBtn.Click += (s, e) => OnConfirm();
        Controls.Add(okBtn);

        UpdateStatus();
    }

    private static ImageList BuildStateImages()
    {
        var images = new ImageList { ImageSize = new Size(16, 16), ColorDepth = ColorDepth.Depth32Bit };
        images.Images.Add(DrawStateImage(CheckState.Unchecked));
        images.Images.Add(DrawStateImage(CheckState.Checked));
        images.Images.Add(DrawStateImage(CheckState.Indeterminate));
        return images;
    }

    private static Bitmap DrawStateImage(CheckState state)
    {
        var bmp = new Bitmap(16, 16);
        using var g = Graphics.FromImage(bmp);
        g.Clear(Color.Transparent);
        var rect = new Rectangle(2, 2, 12, 12);
        using var pen = new Pen(Theme.Border, 1);
        g.DrawRectangle(pen, rect);
        if (state == CheckState.Checked)
        {
            using var brush = new SolidBrush(Color.FromArgb(0x1E, 0x9E, 0x5A));
            g.FillRectangle(brush, rect);
        }
        else if (state == CheckState.Indeterminate)
        {
            using var brush = new SolidBrush(Color.FromArgb(0x3B, 0x82, 0xF6));
            g.FillRectangle(brush, rect);
        }
        return bmp;
    }

    // ==================== 目录树 ====================

    private void LoadRootTree()
    {
        _tree.BeginUpdate();
        _tree.Nodes.Clear();
        var root = new TreeNode(_manifest.SourcePath.TrimEnd('/', '\\').Length == 0
            ? "备份根目录"
            : Path.GetFileName(_manifest.SourcePath.TrimEnd('/', '\\')))
        {
            Tag = ""
        };
        _tree.Nodes.Add(root);
        _tree.EndUpdate();
        root.Expand();
    }

    private void OnTreeBeforeExpand(object? sender, TreeViewCancelEventArgs e)
    {
        var node = e.Node;
        if (node == null) return;
        var dir = node.Tag as string ?? "";
        if (!_loadedDirs.Add(dir)) return;

        node.Nodes.Clear();
        if (_dirSubs.TryGetValue(dir, out var subs))
        {
            _tree.BeginUpdate();
            foreach (var sub in subs)
            {
                var subDir = dir.Length == 0 ? sub : dir + "/" + sub;
                var child = new TreeNode(sub)
                {
                    Tag = subDir,
                    StateImageIndex = DirState(subDir) switch
                    {
                        CheckState.Checked => 1,
                        CheckState.Indeterminate => 2,
                        _ => 0
                    }
                };
                node.Nodes.Add(child);
            }
            _tree.EndUpdate();
        }
    }

    private void OnTreeNodeMouseClick(object? sender, TreeNodeMouseClickEventArgs e)
    {
        // 点击状态图标区域（约前 20px）切换该目录勾选
        if (e.Node == null || e.X > 20) return;
        ToggleDirSelection(e.Node, DirState(e.Node.Tag as string ?? "") != CheckState.Checked);
    }

    // ==================== 文件列表 ====================

    private void ShowDirectory(string dir)
    {
        _searching = false;
        _searchBox.TextChanged -= OnSearchChanged;
        _searchBox.Text = "";
        _searchBox.TextChanged += OnSearchChanged;
        _currentDir = dir;
        RefreshList();
    }

    private void OnSearchChanged(object? sender, EventArgs e)
    {
        var kw = _searchBox.Text?.Trim();
        _searching = !string.IsNullOrEmpty(kw);
        _searchDebounce.Stop();
        _searchDebounce.Start();
    }

    private void RefreshList()
    {
        _visibleItems.Clear();
        _virtualCache.Clear();

        if (_searching)
        {
            var kw = _searchBox.Text.Trim();
            var matches = _archive.Entries
                .Where(e => e.Name.Contains(kw, StringComparison.OrdinalIgnoreCase));
            foreach (var e in SortEntries(matches))
                _visibleItems.Add(e);
            _statusLabel.Text = $"搜索模式：{_visibleItems.Count} 个匹配文件";
        }
        else
        {
            // 子目录行（不可勾选）
            if (_dirSubs.TryGetValue(_currentDir, out var subs))
            {
                foreach (var sub in subs) _visibleItems.Add(sub);
            }
            // 文件行
            if (_dirFiles.TryGetValue(_currentDir, out var files))
            {
                foreach (var e in SortEntries(files)) _visibleItems.Add(e);
            }
            UpdateStatus();
        }

        _list.VirtualListSize = _visibleItems.Count;
        _list.Invalidate();
    }

    /// <summary>虚拟模式：按索引构建可视条目（优先取缓存）</summary>
    private void OnRetrieveVirtualItem(object? sender, RetrieveVirtualItemEventArgs e)
    {
        if (e.ItemIndex < 0 || e.ItemIndex >= _visibleItems.Count) return;
        if (_virtualCache.TryGetValue(e.ItemIndex, out var cached))
        {
            e.Item = cached;
            return;
        }
        var item = BuildListItem(_visibleItems[e.ItemIndex]);
        _virtualCache[e.ItemIndex] = item;
        e.Item = item;
    }

    /// <summary>虚拟模式：保留可视区附近缓存，清理远端条目限制内存线性增长</summary>
    private void OnCacheVirtualItems(object? sender, CacheVirtualItemsEventArgs e)
    {
        if (_visibleItems.Count == 0) return;
        var start = Math.Max(0, e.StartIndex - 32);
        var end = Math.Min(_visibleItems.Count - 1, e.EndIndex + 32);
        var stale = _virtualCache.Keys.Where(k => k < start || k > end).ToList();
        foreach (var k in stale) _virtualCache.Remove(k);
    }

    private ListViewItem BuildListItem(object entry)
    {
        if (entry is string subDir)
        {
            var dirItem = new ListViewItem(subDir) { Tag = subDir };
            dirItem.SubItems.Add("目录");
            dirItem.SubItems.Add("");
            return dirItem;
        }

        var fe = (RecoveryArchiveEntry)entry;
        var item = new ListViewItem(fe.Name) { Tag = fe };
        item.SubItems.Add(FormatSize(fe.Length));
        item.SubItems.Add(_manifest.BackupTime.ToString("yyyy-MM-dd HH:mm"));
        item.Checked = _selected.Contains(fe.RelPath);
        return item;
    }

    private IEnumerable<RecoveryArchiveEntry> SortEntries(IEnumerable<RecoveryArchiveEntry> source)
    {
        var list = source.ToList();
        return _sortField switch
        {
            1 => _sortAsc ? list.OrderBy(e => e.Length) : list.OrderByDescending(e => e.Length),
            2 => _sortAsc ? list.OrderBy(e => e.Name) : list.OrderByDescending(e => e.Name), // 格式无逐文件时间，按名称兜底
            _ => _sortAsc ? list.OrderBy(e => e.Name, StringComparer.OrdinalIgnoreCase)
                          : list.OrderByDescending(e => e.Name, StringComparer.OrdinalIgnoreCase)
        };
    }

    private void OnListItemCheckPreventDir(object? sender, ItemCheckEventArgs e)
    {
        // 目录行禁止勾选（仅文件可勾选）
        if (e.Index >= 0 && e.Index < _visibleItems.Count && _visibleItems[e.Index] is string)
        {
            e.NewValue = e.CurrentValue;
        }
    }

    private void OnListItemChecked(object? sender, ItemCheckedEventArgs e)
    {
        if (e.Item?.Tag is not RecoveryArchiveEntry entry) return;
        if (e.Item.Checked) _selected.Add(entry.RelPath);
        else _selected.Remove(entry.RelPath);

        // 同步父目录树节点状态（搜索模式下跳过，避免高频刷新）
        if (!_searching)
        {
            var parent = Path.GetDirectoryName(entry.RelPath.Replace('/', Path.DirectorySeparatorChar))?.Replace('\\', '/') ?? "";
            FindAndRefreshNode(parent);
        }
        UpdateStatus();
    }

    private void FindAndRefreshNode(string dir)
    {
        TreeNode? Find(TreeNodeCollection nodes)
        {
            foreach (TreeNode n in nodes)
            {
                if (string.Equals(n.Tag as string, dir, StringComparison.OrdinalIgnoreCase)) return n;
                if (n.Nodes.Count > 0) { var r = Find(n.Nodes); if (r != null) return r; }
            }
            return null;
        }
        RefreshNodeAndAncestors(Find(_tree.Nodes));
    }

    // ==================== 状态与确认 ====================

    private void UpdateStatus()
    {
        long total = 0;
        foreach (var p in _selected)
        {
            if (_entryByName.TryGetValue(p, out var e)) total += e.Length;
        }
        _statusLabel.Text = $"已选 {_selected.Count} 个文件 / 合计 {FormatSize(total)}";
    }

    private static string FormatSize(long bytes) => bytes switch
    {
        >= 1024L * 1024 * 1024 => $"{bytes / 1024.0 / 1024 / 1024:F2} GB",
        >= 1024L * 1024 => $"{bytes / 1024.0 / 1024:F1} MB",
        >= 1024L => $"{bytes / 1024.0:F1} KB",
        _ => $"{bytes} B"
    };

    private void OnConfirm()
    {
        if (_selected.Count == 0)
        {
            MessageBox.Show("请先勾选要还原的文件或目录。", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            return;
        }
        DialogResult = DialogResult.OK;
    }
}
