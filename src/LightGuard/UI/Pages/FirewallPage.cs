using LightGuard.Core;
using LightGuard.Firewall;
using LightGuard.Modules;
using LightGuard.UI.Controls;

namespace LightGuard.UI.Pages;

/// <summary>
/// 防火墙管理页面（鼠标优先 UI）
/// 所有配置参数通过下拉菜单、复选框、浏览弹窗、快捷模板按钮完成，无需键盘输入
/// </summary>
public class FirewallPage : Page
{
    private FirewallModule? _module;
    private FirewallAclManager? _acl;
    private Label? _firewallStatusLabel;
    private Label? _aclStatsLabel;
    private Label? _vpnStatusLabel;
    private AccentButton? _enableBtn;
    private AccentButton? _newRuleBtn;
    private AccentButton? _batchFolderBtn;
    private AccentButton? _exportBtn;
    private AccentButton? _importBtn;
    private AccentButton? _clearAllBtn;
    private AccentButton? _cleanDeadBtn;
    private DataGridView? _ruleGrid;
    private ComboBox? _groupFilter;
    private Label? _ruleCountLabel;

    // 预设模板按钮
    private AccentButton? _presetAdobeBtn;
    private AccentButton? _presetRogueBtn;
    private AccentButton? _presetRansomBtn;
    private AccentButton? _presetEmergencyBtn;

    // 全局语种选择
    private ComboBox? _langCombo;
    private MultilingualTemplates.Language _currentLang = MultilingualTemplates.Language.SimplifiedChinese;

    public FirewallPage(AppState appState) : base(appState, "防火墙管理", "五元组 ACL 规则、批量目录拦截、VPN 防绕过、预设模板、导出导入备份")
    {
    }

    public override void OnShown()
    {
        _module = AppState.Modules.GetModule("firewall") as FirewallModule;
        _acl = _module?.AclManager;
        BuildContent();
    }

    /// <summary>构建页面内容</summary>
    private void BuildContent()
    {
        ScrollContent.Controls.Clear();

        int y = 0;

        // ===== 防火墙状态区 =====
        y = BuildStatusSection(y);

        // ===== 预设模板区（含语种选择）=====
        y = BuildPresetSection(y);

        // ===== ACL 规则管理区 =====
        y = BuildRuleManagementSection(y);

        // ===== 快捷操作区 =====
        y = BuildQuickActionsSection(y);

        // ===== VPN 与代理状态区 =====
        y = BuildVpnSection(y);

        // ===== Windows Defender 状态区 =====
        y = BuildDefenderSection(y);

        // ===== 网络连接列表区 =====
        y = BuildConnectionsSection(y);

        y += 20;
    }

    // ===== 防火墙状态区 =====

    private int BuildStatusSection(int y)
    {
        CreateSectionTitle("防火墙状态", 0, y);
        y += 30;

        var fwEnabled = _module?.IsFirewallEnabled() ?? false;
        var statusCard = CreateCard(0, y, ContentWidth, 100);

        _firewallStatusLabel = new Label
        {
            Text = fwEnabled ? "● 防火墙已启用" : "○ 防火墙未启用",
            Font = Theme.HeaderFont,
            ForeColor = fwEnabled ? Theme.Success : Theme.Error,
            Location = new Point(16, 8),
            Size = new Size(300, 24),
            BackColor = Color.Transparent
        };
        statusCard.Controls.Add(_firewallStatusLabel);

        var aclCount = _acl?.GetAllLocalRules().Count ?? 0;
        _aclStatsLabel = new Label
        {
            Text = $"ACL 规则: {aclCount} 条",
            Font = Theme.BodyFont,
            ForeColor = Theme.TextSecondary,
            Location = new Point(16, 36),
            Size = new Size(300, 20),
            BackColor = Color.Transparent
        };
        statusCard.Controls.Add(_aclStatsLabel);

        var vpnInterfaces = VpnNetworkTool.GetAllVpnInterfaceAlias();
        _vpnStatusLabel = new Label
        {
            Text = vpnInterfaces.Count > 0
                ? $"VPN 接口: {vpnInterfaces.Count} 个 ({string.Join(", ", vpnInterfaces.Take(3))})"
                : "VPN 接口: 未检测到",
            Font = Theme.BodyFont,
            ForeColor = vpnInterfaces.Count > 0 ? Theme.Warning : Theme.TextSecondary,
            Location = new Point(16, 60),
            Size = new Size(540, 20),
            BackColor = Color.Transparent
        };
        statusCard.Controls.Add(_vpnStatusLabel);

        _enableBtn = new AccentButton
        {
            Text = fwEnabled ? "已启用" : "启用防火墙",
            Location = new Point(580, 12),
            Size = new Size(120, 36),
            Enabled = !fwEnabled
        };
        _enableBtn.Click += async () =>
        {
            if (_module == null) return;
            _enableBtn.Enabled = false;
            var ok = await Task.Run(() => _module.EnableFirewall());
            if (ok)
                MessageBoxHelper.Info("Windows 防火墙已成功启用！");
            else
                MessageBoxHelper.Error("启用防火墙失败，请以管理员身份运行。");
            RefreshData();
        };
        statusCard.Controls.Add(_enableBtn);

        y += 120;
        return y;
    }

    // ===== 预设模板区（含语种下拉选择）=====

    private int BuildPresetSection(int y)
    {
        CreateSectionTitle("预设模板（一键应用）", 0, y);
        y += 30;

        var card = CreateCard(0, y, ContentWidth, 130);

        // 语种选择行
        var langLabel = new Label
        {
            Text = "命名语种:",
            Font = Theme.BodyFont,
            ForeColor = Theme.TextPrimary,
            Location = new Point(16, 10),
            Size = new Size(70, 24),
            BackColor = Color.Transparent
        };
        card.Controls.Add(langLabel);

        _langCombo = new ComboBox
        {
            Location = new Point(90, 8),
            Size = new Size(160, 28),
            DropDownStyle = ComboBoxStyle.DropDownList,
            Font = Theme.BodyFont
        };
        foreach (var kv in MultilingualTemplates.LanguageNames)
            _langCombo.Items.Add(kv.Value);
        _langCombo.SelectedIndex = 0;
        _langCombo.SelectedIndexChanged += (s, e) =>
        {
            _currentLang = (MultilingualTemplates.Language)_langCombo.SelectedIndex;
            UpdatePresetButtonText();
        };
        card.Controls.Add(_langCombo);

        // 预设模板按钮行
        int btnX = 16;
        int btnY = 44;
        int btnW = 165;
        int btnH = 36;
        int gap = 5;

        _presetAdobeBtn = new AccentButton
        {
            Text = MultilingualTemplates.Get(_currentLang, "AdobeBlock"),
            Location = new Point(btnX, btnY),
            Size = new Size(btnW, btnH)
        };
        _presetAdobeBtn.Click += async () =>
        {
            if (_acl == null) { MessageBoxHelper.Error("ACL 管理器未初始化"); return; }
            var msg = MultilingualTemplates.Get(_currentLang, "AdobeBlock") + "\n" +
                      MultilingualTemplates.Get(_currentLang, "ConfirmExecute");
            if (!MessageBoxHelper.Confirm(msg)) return;
            _presetAdobeBtn.Enabled = false;
            var result = await Task.Run(() => FirewallPresets.ApplyAdobeBlock(_acl, null, _currentLang));
            _presetAdobeBtn.Enabled = true;
            MessageBoxHelper.Info(result.Message);
            RefreshData();
        };
        card.Controls.Add(_presetAdobeBtn);

        _presetRogueBtn = new AccentButton
        {
            Text = MultilingualTemplates.Get(_currentLang, "RogueUpdate"),
            Location = new Point(btnX + (btnW + gap), btnY),
            Size = new Size(btnW, btnH)
        };
        _presetRogueBtn.Click += async () =>
        {
            if (_acl == null) { MessageBoxHelper.Error("ACL 管理器未初始化"); return; }
            var msg = MultilingualTemplates.Get(_currentLang, "RogueUpdate") + "\n" +
                      MultilingualTemplates.Get(_currentLang, "ConfirmExecute");
            if (!MessageBoxHelper.Confirm(msg)) return;
            _presetRogueBtn.Enabled = false;
            var result = await Task.Run(() => FirewallPresets.ApplyRogueUpdateBlock(_acl, _currentLang));
            _presetRogueBtn.Enabled = true;
            MessageBoxHelper.Info(result.Message);
            RefreshData();
        };
        card.Controls.Add(_presetRogueBtn);

        _presetRansomBtn = new AccentButton
        {
            Text = MultilingualTemplates.Get(_currentLang, "RansomPort"),
            Location = new Point(btnX + (btnW + gap) * 2, btnY),
            Size = new Size(btnW, btnH)
        };
        _presetRansomBtn.Click += async () =>
        {
            if (_acl == null) { MessageBoxHelper.Error("ACL 管理器未初始化"); return; }
            var msg = MultilingualTemplates.Get(_currentLang, "RansomPort") + "\n" +
                      MultilingualTemplates.Get(_currentLang, "ConfirmExecute");
            if (!MessageBoxHelper.Confirm(msg)) return;
            _presetRansomBtn.Enabled = false;
            var result = await Task.Run(() => FirewallPresets.ApplyRansomwarePortBlock(_acl, _currentLang));
            _presetRansomBtn.Enabled = true;
            MessageBoxHelper.Info(result.Message);
            RefreshData();
        };
        card.Controls.Add(_presetRansomBtn);

        _presetEmergencyBtn = new AccentButton
        {
            Text = MultilingualTemplates.Get(_currentLang, "Emergency"),
            Location = new Point(btnX + (btnW + gap) * 3, btnY),
            Size = new Size(btnW, btnH)
        };
        _presetEmergencyBtn.Click += () =>
        {
            if (_acl == null) { MessageBoxHelper.Error("ACL 管理器未初始化"); return; }
            using var dialog = new EmergencyBlockDialog(_acl, _currentLang);
            dialog.ShowDialog();
            RefreshData();
        };
        card.Controls.Add(_presetEmergencyBtn);

        // 模板说明
        var descLabel = new Label
        {
            Text = "提示：Adobe 封锁和流氓软件拦截会同时执行防火墙规则 + Hosts 劫持 + EXE 只读锁定三层兜底\n切换语种后，模板生成的规则名称将使用对应语言",
            Font = Theme.SmallFont,
            ForeColor = Theme.TextTertiary,
            Location = new Point(16, 88),
            Size = new Size(688, 36),
            BackColor = Color.Transparent
        };
        card.Controls.Add(descLabel);

        y += 140;
        return y;
    }

    /// <summary>更新预设按钮文字（语种切换时）</summary>
    private void UpdatePresetButtonText()
    {
        if (_presetAdobeBtn != null) _presetAdobeBtn.Text = MultilingualTemplates.Get(_currentLang, "AdobeBlock");
        if (_presetRogueBtn != null) _presetRogueBtn.Text = MultilingualTemplates.Get(_currentLang, "RogueUpdate");
        if (_presetRansomBtn != null) _presetRansomBtn.Text = MultilingualTemplates.Get(_currentLang, "RansomPort");
        if (_presetEmergencyBtn != null) _presetEmergencyBtn.Text = MultilingualTemplates.Get(_currentLang, "Emergency");
    }

    // ===== ACL 规则管理区 =====

    private int BuildRuleManagementSection(int y)
    {
        CreateSectionTitle("ACL 规则管理", 0, y);
        y += 30;

        var btnCard = CreateCard(0, y, ContentWidth, 50);

        _newRuleBtn = new AccentButton
        {
            Text = MultilingualTemplates.Get(_currentLang, "NewRule"),
            Location = new Point(12, 8),
            Size = new Size(110, 34)
        };
        _newRuleBtn.Click += () =>
        {
            if (_acl == null) { MessageBoxHelper.Error("ACL 管理器未初始化"); return; }
            using var dialog = new NewRuleDialog(_acl, _currentLang);
            if (dialog.ShowDialog() == DialogResult.OK)
                RefreshData();
        };
        btnCard.Controls.Add(_newRuleBtn);

        _batchFolderBtn = new AccentButton
        {
            Text = MultilingualTemplates.Get(_currentLang, "BatchFolder"),
            Location = new Point(130, 8),
            Size = new Size(130, 34)
        };
        _batchFolderBtn.Click += () =>
        {
            if (_acl == null) { MessageBoxHelper.Error("ACL 管理器未初始化"); return; }
            using var dialog = new BatchFolderDialog(_acl, _currentLang);
            if (dialog.ShowDialog() == DialogResult.OK)
                RefreshData();
        };
        btnCard.Controls.Add(_batchFolderBtn);

        var filterLabel = new Label
        {
            Text = "筛选:",
            Font = Theme.BodyFont,
            ForeColor = Theme.TextSecondary,
            Location = new Point(280, 12),
            Size = new Size(40, 24),
            BackColor = Color.Transparent
        };
        btnCard.Controls.Add(filterLabel);

        _groupFilter = new ComboBox
        {
            Location = new Point(325, 10),
            Size = new Size(180, 28),
            DropDownStyle = ComboBoxStyle.DropDownList,
            Font = Theme.SmallFont
        };
        _groupFilter.Items.Add("全部分组");
        var groups = _acl?.GetAllLocalRules().Select(r => r.GroupTag).Distinct().ToList() ?? new List<string>();
        foreach (var g in groups)
            _groupFilter.Items.Add(g);
        _groupFilter.SelectedIndex = 0;
        _groupFilter.SelectedIndexChanged += (s, e) => RefreshRuleGrid();
        btnCard.Controls.Add(_groupFilter);

        _ruleCountLabel = new Label
        {
            Text = "",
            Font = Theme.SmallFont,
            ForeColor = Theme.TextTertiary,
            Location = new Point(520, 14),
            Size = new Size(180, 20),
            BackColor = Color.Transparent
        };
        btnCard.Controls.Add(_ruleCountLabel);

        y += 60;

        // 规则列表 DataGridView
        _ruleGrid = CreateRuleDataGridView();
        _ruleGrid.Location = new Point(0, y);
        _ruleGrid.Size = new Size(ContentWidth, 280);
        ScrollContent.Controls.Add(_ruleGrid);

        PopulateRuleGrid();

        y += 300;
        return y;
    }

    /// <summary>创建并配置规则列表 DataGridView</summary>
    private DataGridView CreateRuleDataGridView()
    {
        var grid = new DataGridView
        {
            AllowUserToAddRows = false,
            AllowUserToDeleteRows = false,
            AllowUserToResizeRows = false,
            ReadOnly = true,
            SelectionMode = DataGridViewSelectionMode.FullRowSelect,
            MultiSelect = false,
            AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.None,
            ColumnHeadersVisible = true,
            RowHeadersVisible = false,
            BackgroundColor = Theme.CardBg,
            BorderStyle = BorderStyle.None,
            CellBorderStyle = DataGridViewCellBorderStyle.SingleHorizontal,
            ColumnHeadersDefaultCellStyle = {
                Font = Theme.SmallFont,
                ForeColor = Theme.TextSecondary,
                BackColor = Theme.CardBg,
                Alignment = DataGridViewContentAlignment.MiddleLeft
            },
            DefaultCellStyle = {
                Font = Theme.SmallFont,
                ForeColor = Theme.TextSecondary,
                BackColor = Theme.CardBg,
                SelectionBackColor = Theme.AccentLight,
                SelectionForeColor = Theme.TextPrimary
            },
            GridColor = Theme.Border
        };

        typeof(Control).GetProperty("DoubleBuffered",
            System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)
            ?.SetValue(grid, true, null);

        grid.Columns.Add(new DataGridViewTextBoxColumn { Name = "RuleId", HeaderText = "RuleId", Width = 0, Visible = false });
        grid.Columns.Add(new DataGridViewTextBoxColumn { Name = "Group", HeaderText = "分组", Width = 100 });
        grid.Columns.Add(new DataGridViewTextBoxColumn { Name = "Name", HeaderText = "规则名称", Width = 130 });
        grid.Columns.Add(new DataGridViewTextBoxColumn { Name = "Action", HeaderText = "动作", Width = 50 });
        grid.Columns.Add(new DataGridViewTextBoxColumn { Name = "Direction", HeaderText = "方向", Width = 50 });
        grid.Columns.Add(new DataGridViewTextBoxColumn { Name = "Protocol", HeaderText = "协议", Width = 60 });
        grid.Columns.Add(new DataGridViewTextBoxColumn { Name = "Port", HeaderText = "端口", Width = 80 });
        grid.Columns.Add(new DataGridViewTextBoxColumn { Name = "App", HeaderText = "程序路径", Width = 120 });
        grid.Columns.Add(new DataGridViewTextBoxColumn { Name = "Interface", HeaderText = "网卡", Width = 70 });
        grid.Columns.Add(new DataGridViewCheckBoxColumn { Name = "Enabled", HeaderText = "启用", Width = 45 });

        // 右键菜单（纯鼠标操作）
        var ctxMenu = new ContextMenuStrip();
        ctxMenu.Items.Add("启用/禁用", null, (s, e) => ToggleSelectedRule());
        ctxMenu.Items.Add("-");
        ctxMenu.Items.Add("删除此规则", null, (s, e) => DeleteSelectedRule());
        ctxMenu.Items.Add("删除整组规则", null, (s, e) => DeleteSelectedGroup());
        ctxMenu.Items.Add("-");
        ctxMenu.Items.Add("导出此组规则", null, (s, e) => ExportSelectedGroup());
        ctxMenu.Items.Add("还原此组规则", null, (s, e) => RevertSelectedGroup());

        grid.CellMouseDown += (s, e) =>
        {
            if (e.Button == MouseButtons.Right && e.RowIndex >= 0)
            {
                grid.ClearSelection();
                grid.Rows[e.RowIndex].Selected = true;
                ctxMenu.Show(grid, e.Location);
            }
        };

        return grid;
    }

    /// <summary>填充规则列表数据</summary>
    private void PopulateRuleGrid()
    {
        if (_ruleGrid == null || _acl == null) return;

        _ruleGrid.Rows.Clear();

        var rules = _acl.GetAllLocalRules();

        if (_groupFilter != null && _groupFilter.SelectedIndex > 0)
        {
            var selectedGroup = _groupFilter.SelectedItem?.ToString() ?? "";
            rules = rules.Where(r => r.GroupTag == selectedGroup).ToList();
        }

        foreach (var rule in rules)
        {
            int rowIdx = _ruleGrid.Rows.Add(
                rule.RuleId,
                rule.GroupTag,
                rule.RuleName,
                rule.Action == FirewallConst.FwAction.Block ? "阻止" : "允许",
                rule.Direction == FirewallConst.FwDirection.Inbound ? "入站" : "出站",
                rule.Protocol.ToString(),
                rule.GetPortDescription(),
                string.IsNullOrEmpty(rule.ApplicationPath) ? "(纯端口)" : TruncateText(Path.GetFileName(rule.ApplicationPath), 16),
                rule.GetInterfaceDescription(),
                rule.Enabled
            );

            if (rule.Action == FirewallConst.FwAction.Block)
                _ruleGrid.Rows[rowIdx].Cells["Action"].Style.ForeColor = Theme.Error;
        }

        if (_ruleCountLabel != null)
            _ruleCountLabel.Text = $"共 {rules.Count} 条规则";
    }

    private void RefreshRuleGrid() => PopulateRuleGrid();

    private void ToggleSelectedRule()
    {
        if (_acl == null || _ruleGrid == null || _ruleGrid.SelectedRows.Count == 0) return;

        var ruleId = _ruleGrid.SelectedRows[0].Cells["RuleId"].Value?.ToString();
        if (string.IsNullOrEmpty(ruleId)) return;

        var rule = _acl.GetRuleById(ruleId);
        if (rule == null) return;

        var newStatus = !rule.Enabled;
        if (_acl.ToggleRuleStatus(ruleId, newStatus))
        {
            MessageBoxHelper.Info($"规则已{(newStatus ? "启用" : "禁用")}: {rule.RuleName}");
            RefreshRuleGrid();
        }
        else
            MessageBoxHelper.Error("切换规则状态失败");
    }

    private void DeleteSelectedRule()
    {
        if (_acl == null || _ruleGrid == null || _ruleGrid.SelectedRows.Count == 0) return;

        var ruleId = _ruleGrid.SelectedRows[0].Cells["RuleId"].Value?.ToString();
        if (string.IsNullOrEmpty(ruleId)) return;

        var rule = _acl.GetRuleById(ruleId);
        if (rule == null) return;

        if (!MessageBoxHelper.Confirm($"确认删除规则？\n\n规则名: {rule.RuleName}\n分组: {rule.GroupTag}"))
            return;

        if (_acl.DeleteRuleAndRestoreAcl(ruleId))
        {
            MessageBoxHelper.Info("规则已删除");
            RefreshRuleGrid();
        }
        else
            MessageBoxHelper.Error("删除规则失败");
    }

    private void DeleteSelectedGroup()
    {
        if (_acl == null || _ruleGrid == null || _ruleGrid.SelectedRows.Count == 0) return;

        var groupTag = _ruleGrid.SelectedRows[0].Cells["Group"].Value?.ToString();
        if (string.IsNullOrEmpty(groupTag)) return;

        var count = _acl.QueryRulesByGroup(groupTag).Count;
        if (!MessageBoxHelper.Confirm($"确认删除整组规则？\n\n分组: {groupTag}\n规则数: {count}\n\n此操作不可撤销！"))
            return;

        var removed = _acl.BatchRemoveFolderGroupRules(groupTag);
        MessageBoxHelper.Info($"已删除 {removed} 条规则");
        RefreshRuleGrid();
    }

    private void ExportSelectedGroup()
    {
        if (_acl == null || _ruleGrid == null || _ruleGrid.SelectedRows.Count == 0) return;

        var groupTag = _ruleGrid.SelectedRows[0].Cells["Group"].Value?.ToString();
        if (string.IsNullOrEmpty(groupTag)) return;

        using var sfd = new SaveFileDialog
        {
            Filter = "JSON 文件|*.json",
            FileName = $"firewall_rules_{groupTag}_{DateTime.Now:yyyyMMdd}.json"
        };

        if (sfd.ShowDialog() != DialogResult.OK) return;

        if (_acl.ExportGroupRules(groupTag, sfd.FileName))
            MessageBoxHelper.Info($"规则已导出到:\n{sfd.FileName}");
        else
            MessageBoxHelper.Error("导出失败");
    }

    private void RevertSelectedGroup()
    {
        if (_acl == null || _ruleGrid == null || _ruleGrid.SelectedRows.Count == 0) return;

        var groupTag = _ruleGrid.SelectedRows[0].Cells["Group"].Value?.ToString();
        if (string.IsNullOrEmpty(groupTag)) return;

        if (!MessageBoxHelper.Confirm($"确认还原此分组？\n\n分组: {groupTag}\n将删除所有规则并恢复 Hosts 和 EXE 权限"))
            return;

        var removed = FirewallPresets.RevertPreset(_acl, groupTag);
        MessageBoxHelper.Info($"已还原: 删除 {removed} 条规则");
        RefreshRuleGrid();
    }

    // ===== 快捷操作区 =====

    private int BuildQuickActionsSection(int y)
    {
        CreateSectionTitle("快捷操作", 0, y);
        y += 30;

        var card = CreateCard(0, y, ContentWidth, 50);

        _exportBtn = new AccentButton
        {
            Text = MultilingualTemplates.Get(_currentLang, "ExportAll"),
            Location = new Point(12, 8),
            Size = new Size(120, 34)
        };
        _exportBtn.Click += () =>
        {
            if (_acl == null) return;
            using var sfd = new SaveFileDialog
            {
                Filter = "JSON 文件|*.json",
                FileName = $"firewall_all_rules_{DateTime.Now:yyyyMMdd}.json"
            };
            if (sfd.ShowDialog() != DialogResult.OK) return;
            if (_acl.ExportAllRules(sfd.FileName))
                MessageBoxHelper.Info($"全部规则已导出到:\n{sfd.FileName}");
            else
                MessageBoxHelper.Error("导出失败");
        };
        card.Controls.Add(_exportBtn);

        _importBtn = new AccentButton
        {
            Text = MultilingualTemplates.Get(_currentLang, "ImportRules"),
            Location = new Point(140, 8),
            Size = new Size(110, 34)
        };
        _importBtn.Click += () =>
        {
            if (_acl == null) return;
            using var ofd = new OpenFileDialog
            {
                Filter = "JSON 文件|*.json",
                Title = "选择规则备份文件"
            };
            if (ofd.ShowDialog() != DialogResult.OK) return;
            var (imported, skipped) = _acl.ImportRuleSet(ofd.FileName);
            MessageBoxHelper.Info($"导入完成: 导入 {imported} 条, 跳过 {skipped} 条");
            RefreshData();
        };
        card.Controls.Add(_importBtn);

        _cleanDeadBtn = new AccentButton
        {
            Text = MultilingualTemplates.Get(_currentLang, "CleanDead"),
            Location = new Point(258, 8),
            Size = new Size(120, 34)
        };
        _cleanDeadBtn.Click += () =>
        {
            if (_acl == null) return;
            if (!MessageBoxHelper.Confirm("将自动清理 EXE 已删除、网卡已卸载的无效规则，确认执行？"))
                return;
            var cleaned = _acl.CleanDeadRules();
            MessageBoxHelper.Info($"已清理 {cleaned} 条无效规则");
            RefreshData();
        };
        card.Controls.Add(_cleanDeadBtn);

        _clearAllBtn = new AccentButton
        {
            Text = MultilingualTemplates.Get(_currentLang, "ClearAll"),
            Location = new Point(388, 8),
            Size = new Size(120, 34)
        };
        _clearAllBtn.Click += () =>
        {
            if (_acl == null) return;
            if (!MessageBoxHelper.Confirm("⚠️ 危险操作 ⚠️\n\n将清空本程序创建的全部防火墙规则！\n此操作不可撤销！\n\n确认执行？"))
                return;
            var removed = _acl.ClearAllSelfRules();
            _acl.RestoreOriginalHosts();
            MessageBoxHelper.Info($"已清空 {removed} 条规则，Hosts 已恢复");
            RefreshData();
        };
        card.Controls.Add(_clearAllBtn);

        y += 60;
        return y;
    }

    // ===== VPN 与代理状态区 =====

    private int BuildVpnSection(int y)
    {
        CreateSectionTitle("VPN 与代理状态", 0, y);
        y += 30;

        var vpnInterfaces = VpnNetworkTool.GetAllVpnInterfaceAlias();
        var vpnCidrs = VpnNetworkTool.GetAllVpnCidrList();
        var proxy = VpnNetworkTool.GetSystemProxyInfo();

        var card = CreateCard(0, y, ContentWidth, 120);

        var lines = new[]
        {
            $"VPN 虚拟网卡: {(vpnInterfaces.Count > 0 ? string.Join(", ", vpnInterfaces) : "未检测到")}",
            $"VPN 网段 CIDR: {(vpnCidrs.Count > 0 ? string.Join(", ", vpnCidrs.Take(5)) + (vpnCidrs.Count > 5 ? " ..." : "") : "无")}",
            $"系统代理: {(proxy.Enabled ? $"{proxy.Address}:{proxy.Port}" : "未启用")}",
            $"防绕过状态: {(vpnInterfaces.Count > 0 ? "● VPN 接口已纳入拦截策略" : "○ 无 VPN 接口，策略正常")}"
        };

        for (int i = 0; i < lines.Length; i++)
        {
            var label = new Label
            {
                Text = lines[i],
                Font = Theme.BodyFont,
                ForeColor = i == 3 && vpnInterfaces.Count > 0 ? Theme.Success : Theme.TextSecondary,
                Location = new Point(16, 10 + i * 24),
                Size = new Size(688, 22),
                BackColor = Color.Transparent
            };
            card.Controls.Add(label);
        }

        y += 140;
        return y;
    }

    // ===== Windows Defender 状态区 =====

    private int BuildDefenderSection(int y)
    {
        CreateSectionTitle("Windows Defender 状态", 0, y);
        y += 30;

        if (_module != null)
        {
            var defender = _module.GetDefenderStatus();
            var defenderCard = CreateCard(0, y, ContentWidth, 150);

            var defenderLines = new[]
            {
                $"Defender 已安装：{(defender.IsInstalled ? "是" : "否")}",
                $"反间谍软件：{(defender.AntiSpywareEnabled ? "已启用" : "未启用")}",
                $"实时保护：{(defender.RealTimeProtectionEnabled ? "已启用" : "未启用")}",
                $"防病毒：{(defender.AntivirusEnabled ? "已启用" : "未启用")}",
                $"运行模式：{defender.RunningMode}",
                $"引擎版本：{defender.EngineVersion}",
                $"病毒库更新：{(defender.SignatureLastUpdated.HasValue ? defender.SignatureLastUpdated.Value.ToString("yyyy-MM-dd HH:mm") : "未知")}",
                $"双杀冲突检测：{(defender.HasConflict ? "存在冲突（建议关闭 Defender 实时保护）" : "无冲突")}"
            };

            for (int i = 0; i < defenderLines.Length; i++)
            {
                var label = new Label
                {
                    Text = defenderLines[i],
                    Font = Theme.BodyFont,
                    ForeColor = Theme.TextSecondary,
                    Location = new Point(16, 10 + i * 17),
                    Size = new Size(688, 17),
                    BackColor = Color.Transparent
                };
                defenderCard.Controls.Add(label);
            }

            y += 170;
        }

        return y;
    }

    // ===== 网络连接列表区 =====

    private int BuildConnectionsSection(int y)
    {
        CreateSectionTitle("网络连接列表（前 20 条）", 0, y);
        y += 30;

        if (_module != null)
        {
            var connections = _module.GetNetworkConnections();
            var display = connections.Take(20).ToList();

            if (display.Count == 0)
            {
                var emptyLabel = new Label
                {
                    Text = "暂无网络连接",
                    Font = Theme.BodyFont,
                    ForeColor = Theme.TextTertiary,
                    Location = new Point(16, 0),
                    Size = new Size(680, 24),
                    BackColor = Color.Transparent
                };
                ScrollContent.Controls.Add(emptyLabel);
                y += 30;
            }
            else
            {
                var headerCard = CreateCard(0, y, ContentWidth, 28);
                var headers = new[] { "协议", "本地地址", "远程地址", "状态", "PID", "进程名" };
                var xPositions = new[] { 8, 60, 220, 380, 480, 540 };
                var widths = new[] { 50, 158, 158, 96, 56, 148 };

                for (int i = 0; i < headers.Length; i++)
                {
                    var hLabel = new Label
                    {
                        Text = headers[i],
                        Font = Theme.SmallFont,
                        ForeColor = Theme.TextSecondary,
                        Location = new Point(xPositions[i], 4),
                        Size = new Size(widths[i], 20),
                        BackColor = Color.Transparent
                    };
                    headerCard.Controls.Add(hLabel);
                }
                y += 34;

                foreach (var conn in display)
                {
                    var connCard = CreateCard(0, y, ContentWidth, 24);

                    var values = new[]
                    {
                        conn.Protocol,
                        TruncateText(conn.LocalAddress, 22),
                        TruncateText(conn.ForeignAddress, 22),
                        TruncateText(conn.State, 12),
                        conn.PID.ToString(),
                        TruncateText(conn.ProcessName, 20)
                    };

                    for (int i = 0; i < values.Length; i++)
                    {
                        var vLabel = new Label
                        {
                            Text = values[i],
                            Font = Theme.SmallFont,
                            ForeColor = conn.IsSuspicious ? Theme.Warning : Theme.TextSecondary,
                            Location = new Point(xPositions[i], 2),
                            Size = new Size(widths[i], 20),
                            BackColor = Color.Transparent
                        };
                        connCard.Controls.Add(vLabel);
                    }

                    y += 30;
                }
            }

            y += 10;
        }

        return y;
    }

    private static string TruncateText(string text, int maxLen)
    {
        if (string.IsNullOrEmpty(text)) return "";
        return text.Length <= maxLen ? text : text.Substring(0, maxLen - 3) + "...";
    }

    public override void RefreshData()
    {
        BuildContent();
    }
}

// ===== 对话框：新建规则（鼠标优先 - 全下拉/复选/浏览/快捷模板）=====

/// <summary>
/// 新建防火墙规则对话框
/// 严格执行鼠标优先规范：路径只读浏览、端口/地址快捷模板按钮、全部下拉选择
/// 仅备注为可选手动输入（留空自动生成）
/// </summary>
internal class NewRuleDialog : Form
{
    private readonly FirewallAclManager _acl;
    private readonly MultilingualTemplates.Language _lang;

    // 控件
    private ComboBox _groupCombo = null!;
    private TextBox _remarkBox = null!;
    private ComboBox _actionCombo = null!;
    private ComboBox _directionCombo = null!;
    private ComboBox _protocolCombo = null!;
    private ComboBox _portTemplateCombo = null!;
    private ComboBox _addrTemplateCombo = null!;
    private ComboBox _interfaceCombo = null!;
    private ComboBox _profileCombo = null!;
    private TrackBar _prioritySlider = null!;
    private Label _priorityValueLabel = null!;
    private CheckBox _enabledChk = null!;
    private CheckBox _edgeTraversalChk = null!;
    private TextBox _exePathBox = null!;
    private Button _browseExeBtn = null!;
    private Button _browseFolderBtn = null!;
    private CheckBox _recursiveChk = null!;
    private CheckBox _vpnBlockChk = null!;
    private Button _okBtn = null!;
    private Button _cancelBtn = null!;

    // 当前端口值（由模板设置，不可手动输入）
    private int _remotePortStart = 0;
    private int _remotePortEnd = 0;
    private string _remoteAddr = "*";

    public NewRuleDialog(FirewallAclManager acl, MultilingualTemplates.Language lang)
    {
        _acl = acl;
        _lang = lang;
        InitializeUI();
    }

    private void InitializeUI()
    {
        Text = MultilingualTemplates.Get(_lang, "NewRule");
        Size = new Size(600, 680);
        StartPosition = FormStartPosition.CenterParent;
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = false;
        MinimizeBox = false;
        BackColor = Theme.Background;
        Font = new Font("Segoe UI", 9F);

        int y = 16;
        int ctrlX = 110;
        int ctrlW = 460;
        int rowH = 34;

        // ===== 基础信息 =====
        // 分组（下拉选择已有分组）
        AddLabel(MultilingualTemplates.Get(_lang, "GroupTag") + ":", 16, y);
        _groupCombo = new ComboBox
        {
            Location = new Point(ctrlX, y),
            Size = new Size(350, 26),
            DropDownStyle = ComboBoxStyle.DropDown,
            Font = Theme.BodyFont
        };
        _groupCombo.Items.Add(MultilingualTemplates.Get(_lang, "CustomRule"));
        var existingGroups = _acl.GetAllLocalRules().Select(r => r.GroupTag).Distinct().ToList();
        foreach (var g in existingGroups)
            _groupCombo.Items.Add(g);
        _groupCombo.SelectedIndex = 0;
        Controls.Add(_groupCombo);
        y += rowH;

        // 备注（唯一可选输入框，留空自动生成）
        AddLabel(MultilingualTemplates.Get(_lang, "Remark") + ":", 16, y);
        _remarkBox = new TextBox
        {
            Location = new Point(ctrlX, y),
            Size = new Size(ctrlW, 26),
            Font = Theme.BodyFont,
            PlaceholderText = "(可选) 留空自动生成"
        };
        Controls.Add(_remarkBox);
        y += rowH;

        // ===== 控制字段（全下拉）=====
        AddLabel(MultilingualTemplates.Get(_lang, "Action") + ":", 16, y);
        _actionCombo = AddComboBox(ctrlX, y, ctrlW, new[] {
            MultilingualTemplates.Get(_lang, "Block"),
            MultilingualTemplates.Get(_lang, "Allow")
        });
        y += rowH;

        AddLabel(MultilingualTemplates.Get(_lang, "Direction") + ":", 16, y);
        _directionCombo = AddComboBox(ctrlX, y, ctrlW, new[] {
            MultilingualTemplates.Get(_lang, "Outbound"),
            MultilingualTemplates.Get(_lang, "Inbound"),
            MultilingualTemplates.Get(_lang, "Inbound") + "+" + MultilingualTemplates.Get(_lang, "Outbound")
        });
        y += rowH;

        AddLabel(MultilingualTemplates.Get(_lang, "Protocol") + ":", 16, y);
        _protocolCombo = AddComboBox(ctrlX, y, ctrlW, new[] { "Any", "TCP", "UDP", "ICMPv4", "ICMPv6", "IGMP" });
        y += rowH;

        // ===== 端口模板（快捷按钮一键填充，无手动输入）=====
        AddLabel(MultilingualTemplates.Get(_lang, "PortTemplate") + ":", 16, y);
        _portTemplateCombo = new ComboBox
        {
            Location = new Point(ctrlX, y),
            Size = new Size(ctrlW, 26),
            DropDownStyle = ComboBoxStyle.DropDownList,
            Font = Theme.BodyFont
        };
        _portTemplateCombo.Items.AddRange(new object[] {
            MultilingualTemplates.Get(_lang, "AllPorts"),
            MultilingualTemplates.Get(_lang, "WebPorts"),
            MultilingualTemplates.Get(_lang, "HighRiskPorts"),
            MultilingualTemplates.Get(_lang, "ProxyPorts"),
            "80", "443", "8080", "3389", "135-139", "445"
        });
        _portTemplateCombo.SelectedIndex = 0;
        _portTemplateCombo.SelectedIndexChanged += (s, e) => OnPortTemplateChanged();
        Controls.Add(_portTemplateCombo);
        y += rowH;

        // 显示当前端口值（只读标签）
        AddLabel("当前端口:", 16, y);
        var portValueLabel = new Label
        {
            Text = "全端口",
            Font = Theme.BodyFont,
            ForeColor = Theme.Accent,
            Location = new Point(ctrlX, y + 4),
            Size = new Size(300, 22),
            BackColor = Color.Transparent
        };
        _portTemplateCombo.Tag = portValueLabel; // 存储引用以便更新
        Controls.Add(portValueLabel);
        y += rowH;

        // ===== 地址模板 =====
        AddLabel(MultilingualTemplates.Get(_lang, "AddressTemplate") + ":", 16, y);
        _addrTemplateCombo = new ComboBox
        {
            Location = new Point(ctrlX, y),
            Size = new Size(ctrlW, 26),
            DropDownStyle = ComboBoxStyle.DropDownList,
            Font = Theme.BodyFont
        };
        _addrTemplateCombo.Items.AddRange(new object[] {
            "Any (*)",
            "VPN 网段 (10.0.0.0/8)",
            "私有网段 (192.168.0.0/16)",
            "私有网段 (172.16.0.0/12)",
            "本地回环 (127.0.0.0/8)"
        });
        _addrTemplateCombo.SelectedIndex = 0;
        _addrTemplateCombo.SelectedIndexChanged += (s, e) => OnAddrTemplateChanged();
        Controls.Add(_addrTemplateCombo);
        y += rowH;

        // ===== 程序绑定（路径只读，仅浏览弹窗选择）=====
        AddLabel(MultilingualTemplates.Get(_lang, "AppPath") + ":", 16, y);
        _exePathBox = new TextBox
        {
            Location = new Point(ctrlX, y),
            Size = new Size(290, 26),
            Font = Theme.BodyFont,
            ReadOnly = true,  // 只读！不可手动输入
            BackColor = Theme.CardBg
        };
        Controls.Add(_exePathBox);

        _browseExeBtn = new Button
        {
            Text = MultilingualTemplates.Get(_lang, "BrowseExe"),
            Location = new Point(ctrlX + 295, y),
            Size = new Size(75, 26),
            Font = Theme.SmallFont
        };
        _browseExeBtn.Click += (s, e) =>
        {
            using var ofd = new OpenFileDialog { Filter = "可执行文件|*.exe|所有文件|*.*" };
            if (ofd.ShowDialog() == DialogResult.OK)
                _exePathBox.Text = ofd.FileName;
        };
        Controls.Add(_browseExeBtn);

        _browseFolderBtn = new Button
        {
            Text = MultilingualTemplates.Get(_lang, "BrowseFolder"),
            Location = new Point(ctrlX + 375, y),
            Size = new Size(85, 26),
            Font = Theme.SmallFont
        };
        _browseFolderBtn.Click += (s, e) =>
        {
            using var fbd = new FolderBrowserDialog { Description = "选择程序目录" };
            if (fbd.ShowDialog() == DialogResult.OK)
                _exePathBox.Text = fbd.SelectedPath;
        };
        Controls.Add(_browseFolderBtn);
        y += rowH;

        // 递归扫描 + VPN 拦截复选框
        _recursiveChk = new CheckBox
        {
            Text = MultilingualTemplates.Get(_lang, "RecursiveScan"),
            Font = Theme.BodyFont,
            ForeColor = Theme.TextPrimary,
            Location = new Point(ctrlX, y),
            Size = new Size(200, 24),
            Checked = true
        };
        Controls.Add(_recursiveChk);

        _vpnBlockChk = new CheckBox
        {
            Text = MultilingualTemplates.Get(_lang, "VpnBlock"),
            Font = Theme.BodyFont,
            ForeColor = Theme.TextPrimary,
            Location = new Point(ctrlX + 210, y),
            Size = new Size(250, 24),
            Checked = true
        };
        Controls.Add(_vpnBlockChk);
        y += rowH;

        // ===== 网卡限制（下拉）=====
        AddLabel(MultilingualTemplates.Get(_lang, "InterfaceType") + ":", 16, y);
        _interfaceCombo = AddComboBox(ctrlX, y, ctrlW, new[] {
            MultilingualTemplates.Get(_lang, "AllInterfaces"),
            MultilingualTemplates.Get(_lang, "PhysicalOnly"),
            MultilingualTemplates.Get(_lang, "VpnOnly"),
            MultilingualTemplates.Get(_lang, "Wireless"),
            MultilingualTemplates.Get(_lang, "IPv6Tunnel")
        });
        y += rowH;

        // ===== 网络配置文件（下拉）=====
        AddLabel(MultilingualTemplates.Get(_lang, "Profile") + ":", 16, y);
        _profileCombo = AddComboBox(ctrlX, y, ctrlW, new[] { "全部", "域", "专用", "公网" });
        y += rowH;

        // ===== 优先级（滑块）=====
        AddLabel(MultilingualTemplates.Get(_lang, "Priority") + ":", 16, y);
        _prioritySlider = new TrackBar
        {
            Location = new Point(ctrlX, y),
            Size = new Size(350, 45),
            Minimum = 1,
            Maximum = 200,
            Value = 100,
            TickFrequency = 20
        };
        _priorityValueLabel = new Label
        {
            Text = "100",
            Font = Theme.BodyFont,
            ForeColor = Theme.Accent,
            Location = new Point(ctrlX + 360, y + 10),
            Size = new Size(40, 22),
            BackColor = Color.Transparent
        };
        _prioritySlider.Scroll += (s, e) => _priorityValueLabel.Text = _prioritySlider.Value.ToString();
        Controls.Add(_prioritySlider);
        Controls.Add(_priorityValueLabel);
        y += 48;

        // ===== 启用 + 边缘遍历（复选框）=====
        _enabledChk = new CheckBox
        {
            Text = MultilingualTemplates.Get(_lang, "Enabled"),
            Font = Theme.BodyFont,
            ForeColor = Theme.TextPrimary,
            Location = new Point(ctrlX, y),
            Size = new Size(120, 24),
            Checked = true
        };
        Controls.Add(_enabledChk);

        _edgeTraversalChk = new CheckBox
        {
            Text = MultilingualTemplates.Get(_lang, "EdgeTraversal"),
            Font = Theme.BodyFont,
            ForeColor = Theme.TextPrimary,
            Location = new Point(ctrlX + 130, y),
            Size = new Size(200, 24),
            Checked = false
        };
        Controls.Add(_edgeTraversalChk);
        y += rowH;

        // ===== 按钮 =====
        _okBtn = new Button
        {
            Text = MultilingualTemplates.Get(_lang, "Create"),
            Location = new Point(300, y),
            Size = new Size(130, 34),
            Font = Theme.ButtonFont,
            BackColor = Theme.Accent,
            ForeColor = Color.White,
            FlatStyle = FlatStyle.Flat
        };
        _okBtn.Click += OnCreateClick;
        Controls.Add(_okBtn);

        _cancelBtn = new Button
        {
            Text = MultilingualTemplates.Get(_lang, "Cancel"),
            Location = new Point(440, y),
            Size = new Size(130, 34),
            Font = Theme.ButtonFont,
            FlatStyle = FlatStyle.Flat
        };
        _cancelBtn.Click += (s, e) => { DialogResult = DialogResult.Cancel; Close(); };
        Controls.Add(_cancelBtn);
    }

    /// <summary>端口模板切换时更新端口值</summary>
    private void OnPortTemplateChanged()
    {
        var selected = _portTemplateCombo.SelectedItem?.ToString() ?? "";
        var allPorts = MultilingualTemplates.Get(_lang, "AllPorts");
        var webPorts = MultilingualTemplates.Get(_lang, "WebPorts");
        var highRisk = MultilingualTemplates.Get(_lang, "HighRiskPorts");
        var proxyPorts = MultilingualTemplates.Get(_lang, "ProxyPorts");

        if (selected == allPorts)
            (_remotePortStart, _remotePortEnd) = (0, 0);
        else if (selected == webPorts)
            (_remotePortStart, _remotePortEnd) = (80, 443);
        else if (selected == highRisk)
            (_remotePortStart, _remotePortEnd) = (135, 3389);
        else if (selected == proxyPorts)
            (_remotePortStart, _remotePortEnd) = (1080, 8080);
        else if (int.TryParse(selected, out var singlePort))
            (_remotePortStart, _remotePortEnd) = (singlePort, singlePort);
        else if (selected.Contains('-'))
        {
            var parts = selected.Split('-');
            if (parts.Length == 2 && int.TryParse(parts[0], out var s) && int.TryParse(parts[1], out var e))
                (_remotePortStart, _remotePortEnd) = (s, e);
        }

        // 更新显示标签
        if (_portTemplateCombo.Tag is Label lbl)
        {
            lbl.Text = _remotePortStart == 0 && _remotePortEnd == 0
                ? allPorts
                : _remotePortStart == _remotePortEnd
                    ? _remotePortStart.ToString()
                    : $"{_remotePortStart}-{_remotePortEnd}";
        }
    }

    /// <summary>地址模板切换时更新地址值</summary>
    private void OnAddrTemplateChanged()
    {
        var idx = _addrTemplateCombo.SelectedIndex;
        _remoteAddr = idx switch
        {
            0 => "*",
            1 => "10.0.0.0/8",
            2 => "192.168.0.0/16",
            3 => "172.16.0.0/12",
            4 => "127.0.0.0/8",
            _ => "*"
        };
    }

    private void OnCreateClick(object? sender, EventArgs e)
    {
        var groupTag = UnicodeTextHelper.SanitizeGroupTag(_groupCombo.Text);
        if (string.IsNullOrEmpty(groupTag))
            groupTag = MultilingualTemplates.Get(_lang, "CustomRule");

        var action = _actionCombo.SelectedIndex == 0 ? FirewallConst.FwAction.Block : FirewallConst.FwAction.Allow;
        var directionIdx = _directionCombo.SelectedIndex;
        var protocolStr = _protocolCombo.SelectedItem?.ToString() ?? "Any";
        var protocol = Enum.Parse<FirewallConst.FwProtocol>(protocolStr);

        var interfaceType = _interfaceCombo.SelectedIndex switch
        {
            0 => FirewallConst.FwInterfaceType.All,
            1 => FirewallConst.FwInterfaceType.PhysicalOnly,
            2 => FirewallConst.FwInterfaceType.VpnOnly,
            3 => FirewallConst.FwInterfaceType.Wireless,
            4 => FirewallConst.FwInterfaceType.IPv6Tunnel,
            _ => FirewallConst.FwInterfaceType.All
        };

        var exePath = _exePathBox.Text.Trim();
        var remark = UnicodeTextHelper.SanitizeRemark(_remarkBox.Text);

        // 生成规则名（基于分组 + 时间戳，避免多语言名称冲突）
        var ruleName = $"{groupTag}_{DateTime.Now:HHmmss}";

        bool success = false;

        if (!string.IsNullOrEmpty(exePath))
        {
            // 程序规则
            var directions = directionIdx switch
            {
                0 => new[] { FirewallConst.FwDirection.Outbound },
                1 => new[] { FirewallConst.FwDirection.Inbound },
                2 => new[] { FirewallConst.FwDirection.Outbound, FirewallConst.FwDirection.Inbound },
                _ => new[] { FirewallConst.FwDirection.Outbound }
            };

            foreach (var dir in directions)
            {
                success = _acl.CreateCustomExeRule(
                    ruleName: ruleName,
                    exePath: exePath,
                    action: action,
                    direction: dir,
                    protocol: protocol,
                    remotePortStart: _remotePortStart,
                    remotePortEnd: _remotePortEnd,
                    remoteAddresses: _remoteAddr,
                    interfaceType: interfaceType,
                    groupTag: groupTag,
                    remark: remark) || success;

                if (_vpnBlockChk.Checked)
                    _acl.BlockVpnCidrForApp(exePath);
            }
        }
        else
        {
            // 纯端口规则
            var dir = directionIdx == 1 ? FirewallConst.FwDirection.Inbound : FirewallConst.FwDirection.Outbound;
            success = _acl.CreatePurePortRule(
                ruleName: ruleName,
                portStart: _remotePortStart,
                portEnd: _remotePortEnd,
                direction: dir,
                action: action,
                protocol: protocol == FirewallConst.FwProtocol.Any ? FirewallConst.FwProtocol.TCP : protocol,
                remoteAddresses: _remoteAddr,
                groupTag: groupTag);
        }

        if (success)
        {
            MessageBoxHelper.Info("规则创建成功！");
            DialogResult = DialogResult.OK;
            Close();
        }
        else
            MessageBoxHelper.Error("规则创建失败，请检查权限和参数");
    }

    private Label AddLabel(string text, int x, int y)
    {
        var lbl = new Label
        {
            Text = text,
            Font = Theme.BodyFont,
            ForeColor = Theme.TextPrimary,
            Location = new Point(x, y + 4),
            Size = new Size(90, 22),
            BackColor = Color.Transparent
        };
        Controls.Add(lbl);
        return lbl;
    }

    private ComboBox AddComboBox(int x, int y, int w, string[] items)
    {
        var cb = new ComboBox
        {
            Location = new Point(x, y),
            Size = new Size(w, 26),
            DropDownStyle = ComboBoxStyle.DropDownList,
            Font = Theme.BodyFont
        };
        cb.Items.AddRange(items);
        cb.SelectedIndex = 0;
        Controls.Add(cb);
        return cb;
    }
}

// ===== 对话框：批量目录拦截（鼠标优先）=====

/// <summary>
/// 批量目录 EXE 拦截对话框
/// 路径仅弹窗选择、端口/网卡全下拉、EXE 列表勾选白名单、无文本搜索框
/// </summary>
internal class BatchFolderDialog : Form
{
    private readonly FirewallAclManager _acl;
    private readonly MultilingualTemplates.Language _lang;

    private TextBox _pathBox = null!;
    private Button _browseBtn = null!;
    private CheckBox _recursiveChk = null!;
    private CheckBox _vpnBlockChk = null!;
    private ComboBox _portModeCombo = null!;
    private ComboBox _interfaceCombo = null!;
    private CheckedListBox _exeList = null!;
    private Button _scanBtn = null!;
    private Button _okBtn = null!;
    private Button _cancelBtn = null!;
    private Label _scanResultLabel = null!;

    public BatchFolderDialog(FirewallAclManager acl, MultilingualTemplates.Language lang)
    {
        _acl = acl;
        _lang = lang;
        InitializeUI();
    }

    private void InitializeUI()
    {
        Text = MultilingualTemplates.Get(_lang, "BatchFolder");
        Size = new Size(640, 600);
        StartPosition = FormStartPosition.CenterParent;
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = false;
        MinimizeBox = false;
        BackColor = Theme.Background;
        Font = new Font("Segoe UI", 9F);

        int y = 16;

        // 目录选择（路径只读，仅弹窗）
        var pathLabel = new Label
        {
            Text = MultilingualTemplates.Get(_lang, "AppPath") + ":",
            Font = Theme.BodyFont,
            ForeColor = Theme.TextPrimary,
            Location = new Point(16, y + 4),
            Size = new Size(80, 22),
            BackColor = Color.Transparent
        };
        Controls.Add(pathLabel);

        _pathBox = new TextBox
        {
            Location = new Point(100, y),
            Size = new Size(430, 26),
            Font = Theme.BodyFont,
            ReadOnly = true,  // 只读！
            BackColor = Theme.CardBg
        };
        Controls.Add(_pathBox);

        _browseBtn = new Button
        {
            Text = MultilingualTemplates.Get(_lang, "BrowseFolder"),
            Location = new Point(540, y),
            Size = new Size(75, 26),
            Font = Theme.SmallFont
        };
        _browseBtn.Click += (s, e) =>
        {
            using var fbd = new FolderBrowserDialog { Description = "选择要拦截的软件目录" };
            if (fbd.ShowDialog() == DialogResult.OK)
                _pathBox.Text = fbd.SelectedPath;
        };
        Controls.Add(_browseBtn);
        y += 36;

        // 复选框
        _recursiveChk = new CheckBox
        {
            Text = MultilingualTemplates.Get(_lang, "RecursiveScan"),
            Font = Theme.BodyFont,
            ForeColor = Theme.TextPrimary,
            Location = new Point(16, y),
            Size = new Size(160, 24),
            Checked = true
        };
        Controls.Add(_recursiveChk);

        _vpnBlockChk = new CheckBox
        {
            Text = MultilingualTemplates.Get(_lang, "VpnBlock"),
            Font = Theme.BodyFont,
            ForeColor = Theme.TextPrimary,
            Location = new Point(190, y),
            Size = new Size(200, 24),
            Checked = true
        };
        Controls.Add(_vpnBlockChk);
        y += 32;

        // 端口策略（下拉）
        var portLabel = new Label
        {
            Text = MultilingualTemplates.Get(_lang, "PortTemplate") + ":",
            Font = Theme.BodyFont,
            ForeColor = Theme.TextPrimary,
            Location = new Point(16, y + 4),
            Size = new Size(80, 22),
            BackColor = Color.Transparent
        };
        Controls.Add(portLabel);

        _portModeCombo = new ComboBox
        {
            Location = new Point(100, y),
            Size = new Size(200, 26),
            DropDownStyle = ComboBoxStyle.DropDownList,
            Font = Theme.BodyFont
        };
        _portModeCombo.Items.AddRange(new object[] {
            MultilingualTemplates.Get(_lang, "AllPorts"),
            MultilingualTemplates.Get(_lang, "WebPorts"),
            MultilingualTemplates.Get(_lang, "HighRiskPorts"),
            MultilingualTemplates.Get(_lang, "ProxyPorts")
        });
        _portModeCombo.SelectedIndex = 1; // 默认 80/443
        Controls.Add(_portModeCombo);

        // 网卡模式（下拉）
        var ifaceLabel = new Label
        {
            Text = MultilingualTemplates.Get(_lang, "InterfaceType") + ":",
            Font = Theme.BodyFont,
            ForeColor = Theme.TextPrimary,
            Location = new Point(320, y + 4),
            Size = new Size(80, 22),
            BackColor = Color.Transparent
        };
        Controls.Add(ifaceLabel);

        _interfaceCombo = new ComboBox
        {
            Location = new Point(405, y),
            Size = new Size(210, 26),
            DropDownStyle = ComboBoxStyle.DropDownList,
            Font = Theme.BodyFont
        };
        _interfaceCombo.Items.AddRange(new object[] {
            MultilingualTemplates.Get(_lang, "AllInterfaces"),
            MultilingualTemplates.Get(_lang, "PhysicalOnly"),
            MultilingualTemplates.Get(_lang, "VpnOnly")
        });
        _interfaceCombo.SelectedIndex = 0;
        Controls.Add(_interfaceCombo);
        y += 36;

        // 扫描按钮
        _scanBtn = new Button
        {
            Text = MultilingualTemplates.Get(_lang, "Scan"),
            Location = new Point(16, y),
            Size = new Size(140, 30),
            Font = Theme.ButtonFont,
            BackColor = Theme.Accent,
            ForeColor = Color.White,
            FlatStyle = FlatStyle.Flat
        };
        _scanBtn.Click += OnScanClick;
        Controls.Add(_scanBtn);

        _scanResultLabel = new Label
        {
            Text = "",
            Font = Theme.SmallFont,
            ForeColor = Theme.TextTertiary,
            Location = new Point(170, y + 6),
            Size = new Size(440, 20),
            BackColor = Color.Transparent
        };
        Controls.Add(_scanResultLabel);
        y += 40;

        // EXE 列表说明
        var listLabel = new Label
        {
            Text = "扫描结果（取消勾选可排除不需要拦截的程序）:",
            Font = Theme.SmallFont,
            ForeColor = Theme.TextSecondary,
            Location = new Point(16, y),
            Size = new Size(500, 18),
            BackColor = Color.Transparent
        };
        Controls.Add(listLabel);
        y += 22;

        _exeList = new CheckedListBox
        {
            Location = new Point(16, y),
            Size = new Size(600, 280),
            Font = Theme.SmallFont,
            BackColor = Theme.CardBg,
            ForeColor = Theme.TextSecondary,
            BorderStyle = BorderStyle.FixedSingle,
            CheckOnClick = true
        };
        Controls.Add(_exeList);
        y += 290;

        // 按钮
        _okBtn = new Button
        {
            Text = MultilingualTemplates.Get(_lang, "Execute"),
            Location = new Point(340, y),
            Size = new Size(130, 34),
            Font = Theme.ButtonFont,
            BackColor = Theme.Accent,
            ForeColor = Color.White,
            FlatStyle = FlatStyle.Flat
        };
        _okBtn.Click += OnExecuteClick;
        Controls.Add(_okBtn);

        _cancelBtn = new Button
        {
            Text = MultilingualTemplates.Get(_lang, "Cancel"),
            Location = new Point(480, y),
            Size = new Size(130, 34),
            Font = Theme.ButtonFont,
            FlatStyle = FlatStyle.Flat
        };
        _cancelBtn.Click += (s, e) => { DialogResult = DialogResult.Cancel; Close(); };
        Controls.Add(_cancelBtn);
    }

    private void OnScanClick(object? sender, EventArgs e)
    {
        var path = _pathBox.Text.Trim();
        if (string.IsNullOrEmpty(path) || !Directory.Exists(path))
        {
            MessageBoxHelper.Error("请先选择有效的目录路径");
            return;
        }

        _exeList.Items.Clear();
        var exes = _acl.ScanRecursiveExe(path, _recursiveChk.Checked);

        foreach (var exe in exes)
            _exeList.Items.Add(exe, true);

        _scanResultLabel.Text = $"扫描完成: 发现 {exes.Count} 个 EXE 文件";
    }

    private void OnExecuteClick(object? sender, EventArgs e)
    {
        var path = _pathBox.Text.Trim();
        if (string.IsNullOrEmpty(path) || !Directory.Exists(path))
        {
            MessageBoxHelper.Error("请先选择有效的目录路径");
            return;
        }

        if (_exeList.Items.Count == 0)
        {
            MessageBoxHelper.Warn("请先扫描目录");
            return;
        }

        var selectedExes = new List<string>();
        for (int i = 0; i < _exeList.Items.Count; i++)
        {
            if (_exeList.GetItemChecked(i))
                selectedExes.Add((string)_exeList.Items[i]!);
        }

        if (selectedExes.Count == 0)
        {
            MessageBoxHelper.Warn("请至少选择一个 EXE 文件");
            return;
        }

        // 从模板获取端口
        int portStart = 0, portEnd = 0;
        var selectedPort = _portModeCombo.SelectedItem?.ToString() ?? "";
        var allPorts = MultilingualTemplates.Get(_lang, "AllPorts");
        var webPorts = MultilingualTemplates.Get(_lang, "WebPorts");
        var highRisk = MultilingualTemplates.Get(_lang, "HighRiskPorts");
        var proxyPorts = MultilingualTemplates.Get(_lang, "ProxyPorts");

        if (selectedPort == webPorts) (portStart, portEnd) = (80, 443);
        else if (selectedPort == highRisk) (portStart, portEnd) = (135, 3389);
        else if (selectedPort == proxyPorts) (portStart, portEnd) = (1080, 8080);
        else (portStart, portEnd) = (0, 0); // 全端口

        var interfaceType = _interfaceCombo.SelectedIndex switch
        {
            0 => FirewallConst.FwInterfaceType.All,
            1 => FirewallConst.FwInterfaceType.PhysicalOnly,
            2 => FirewallConst.FwInterfaceType.VpnOnly,
            _ => FirewallConst.FwInterfaceType.All
        };

        var groupTag = $"{MultilingualTemplates.Get(_lang, "BatchFolder")}_{Path.GetFileName(path.TrimEnd('\\'))}";

        if (!MessageBoxHelper.Confirm(
            $"{MultilingualTemplates.Get(_lang, "ConfirmExecute")}\n\n" +
            $"目录: {path}\n选中 EXE: {selectedExes.Count} 个\n" +
            $"端口: {selectedPort}\n网卡: {_interfaceCombo.SelectedItem}\n" +
            $"VPN 拦截: {(_vpnBlockChk.Checked ? "是" : "否")}\n分组: {groupTag}"))
            return;

        int created = 0, failed = 0;
        foreach (var exe in selectedExes)
        {
            var name = Path.GetFileNameWithoutExtension(exe);
            if (_acl.CreateCustomExeRule(
                ruleName: $"{groupTag}_{name}",
                exePath: exe,
                action: FirewallConst.FwAction.Block,
                direction: FirewallConst.FwDirection.Outbound,
                remotePortStart: portStart,
                remotePortEnd: portEnd,
                interfaceType: interfaceType,
                groupTag: groupTag,
                remark: $"批量目录拦截: {path}"))
                created++;
            else
                failed++;

            if (_vpnBlockChk.Checked)
                _acl.BlockVpnCidrForApp(exe);
        }

        MessageBoxHelper.Info($"批量拦截完成！\n\n成功: {created} 条\n失败: {failed} 条\n分组: {groupTag}");
        DialogResult = DialogResult.OK;
        Close();
    }
}

// ===== 对话框：勒索应急断网（鼠标优先）=====

/// <summary>
/// 勒索应急断网对话框
/// 选择可疑进程文件（仅弹窗），全端口阻断所有网卡流量
/// </summary>
internal class EmergencyBlockDialog : Form
{
    private readonly FirewallAclManager _acl;
    private readonly MultilingualTemplates.Language _lang;

    private TextBox _pathBox = null!;
    private Button _browseBtn = null!;
    private Button _okBtn = null!;
    private Button _cancelBtn = null!;

    public EmergencyBlockDialog(FirewallAclManager acl, MultilingualTemplates.Language lang)
    {
        _acl = acl;
        _lang = lang;
        InitializeUI();
    }

    private void InitializeUI()
    {
        Text = MultilingualTemplates.Get(_lang, "Emergency");
        Size = new Size(560, 280);
        StartPosition = FormStartPosition.CenterParent;
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = false;
        MinimizeBox = false;
        BackColor = Theme.Background;
        Font = new Font("Segoe UI", 9F);

        var warnLabel = new Label
        {
            Text = "⚠️ " + MultilingualTemplates.Get(_lang, "EmergencyWarn"),
            Font = Theme.BodyFont,
            ForeColor = Theme.Error,
            Location = new Point(16, 16),
            Size = new Size(520, 80),
            BackColor = Color.Transparent
        };
        Controls.Add(warnLabel);

        var pathLabel = new Label
        {
            Text = MultilingualTemplates.Get(_lang, "AppPath") + ":",
            Font = Theme.BodyFont,
            ForeColor = Theme.TextPrimary,
            Location = new Point(16, 110),
            Size = new Size(80, 22),
            BackColor = Color.Transparent
        };
        Controls.Add(pathLabel);

        _pathBox = new TextBox
        {
            Location = new Point(100, 106),
            Size = new Size(370, 26),
            Font = Theme.BodyFont,
            ReadOnly = true,  // 只读！
            BackColor = Theme.CardBg
        };
        Controls.Add(_pathBox);

        _browseBtn = new Button
        {
            Text = MultilingualTemplates.Get(_lang, "BrowseExe"),
            Location = new Point(480, 106),
            Size = new Size(60, 26),
            Font = Theme.SmallFont
        };
        _browseBtn.Click += (s, e) =>
        {
            using var ofd = new OpenFileDialog { Filter = "可执行文件|*.exe|所有文件|*.*" };
            if (ofd.ShowDialog() == DialogResult.OK)
                _pathBox.Text = ofd.FileName;
        };
        Controls.Add(_browseBtn);

        _okBtn = new Button
        {
            Text = MultilingualTemplates.Get(_lang, "Execute"),
            Location = new Point(300, 160),
            Size = new Size(130, 34),
            Font = Theme.ButtonFont,
            BackColor = Theme.Error,
            ForeColor = Color.White,
            FlatStyle = FlatStyle.Flat
        };
        _okBtn.Click += OnExecuteClick;
        Controls.Add(_okBtn);

        _cancelBtn = new Button
        {
            Text = MultilingualTemplates.Get(_lang, "Cancel"),
            Location = new Point(440, 160),
            Size = new Size(100, 34),
            Font = Theme.ButtonFont,
            FlatStyle = FlatStyle.Flat
        };
        _cancelBtn.Click += (s, e) => { DialogResult = DialogResult.Cancel; Close(); };
        Controls.Add(_cancelBtn);
    }

    private void OnExecuteClick(object? sender, EventArgs e)
    {
        var path = _pathBox.Text.Trim();
        if (string.IsNullOrEmpty(path) || !File.Exists(path))
        {
            MessageBoxHelper.Error("请选择有效的进程文件");
            return;
        }

        if (!MessageBoxHelper.Confirm(
            $"{MultilingualTemplates.Get(_lang, "ConfirmExecute")}\n\n" +
            $"目标: {Path.GetFileName(path)}\n{MultilingualTemplates.Get(_lang, "EmergencyWarn")}"))
            return;

        var result = FirewallPresets.ApplyEmergencyNetworkBlock(_acl, path, _lang);
        if (result.Success)
            MessageBoxHelper.Info(result.Message);
        else
            MessageBoxHelper.Error(result.Message);

        DialogResult = DialogResult.OK;
        Close();
    }
}
