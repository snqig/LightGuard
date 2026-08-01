using LightGuard.Core;
using LightGuard.Modules;
using LightGuard.UI.Controls;

namespace LightGuard.UI.Pages;

/// <summary>
/// 加密智能备份页面
/// 提供立即备份、备份列表、备份模式/计划选择、保护文件夹管理、备份报告、WebDAV/NAS配置
/// 备份在后台线程执行
/// </summary>
public class BackupPage : Page
{
    private BackupModule? _module;
    private AccentButton? _backupBtn;
    private AccentButton? _reportBtn;
    private AccentButton? _addFolderBtn;
    private ComboBox? _modeCombo;
    private ComboBox? _scheduleCombo;
    private TextBox? _backupPathBox;
    private TextBox? _nasPathBox;
    private TextBox? _webDavUrlBox;
    private TextBox? _webDavUserBox;
    private TextBox? _webDavPassBox;
    private TextBox? _addFolderBox;
    private Label? _progressLabel;
    private bool _isBackingUp;

    public BackupPage(AppState appState) : base(appState, "加密智能备份", "AES256加密、NTFS增量、伪装备份防勒索、NAS/WebDAV云端备份")
    {
    }

    public override void OnShown()
    {
        _module = AppState.Modules.GetModule("backup") as BackupModule;
        BuildContent();
    }

    /// <summary>构建页面内容</summary>
    private void BuildContent()
    {
        ScrollContent.Controls.Clear();

        int y = 0;

        // ===== 备份操作区 =====
        CreateSectionTitle("备份操作", 0, y);
        y += 30;

        var actionCard = CreateCard(0, y, ContentWidth, 60);

        _backupBtn = new AccentButton
        {
            Text = "立即备份",
            Location = new Point(16, 12),
            Size = new Size(120, 36)
        };
        _backupBtn.Click += () => StartBackup();
        actionCard.Controls.Add(_backupBtn);

        _reportBtn = new AccentButton
        {
            Text = "生成备份报告",
            Location = new Point(146, 12),
            Size = new Size(130, 36)
        };
        _reportBtn.Click += () =>
        {
            if (_module == null) return;
            var report = _module.GenerateBackupReport();
            MessageBoxHelper.Info(report);
        };
        actionCard.Controls.Add(_reportBtn);

        y += 80;

        // ===== 备份进度区 =====
        CreateSectionTitle("备份进度", 0, y);
        y += 30;

        var progressCard = CreateCard(0, y, ContentWidth, 50);
        _progressLabel = new Label
        {
            Text = _isBackingUp ? "正在执行备份，请稍候..." : "就绪",
            Font = Theme.BodyFont,
            ForeColor = _isBackingUp ? Theme.Warning : Theme.TextSecondary,
            Location = new Point(16, 14),
            Size = new Size(688, 22),
            BackColor = Color.Transparent
        };
        progressCard.Controls.Add(_progressLabel);
        y += 70;

        // ===== 备份配置区 =====
        CreateSectionTitle("备份配置", 0, y);
        y += 30;

        var configCard = CreateCard(0, y, ContentWidth, 170);

        // 备份模式
        var modeLabel = new Label
        {
            Text = "备份模式：",
            Font = Theme.BodyFont,
            ForeColor = Theme.TextSecondary,
            Location = new Point(16, 12),
            Size = new Size(80, 22),
            BackColor = Color.Transparent
        };
        configCard.Controls.Add(modeLabel);

        _modeCombo = new ComboBox
        {
            Location = new Point(100, 10),
            Size = new Size(140, 24),
            FlatStyle = FlatStyle.Flat,
            Font = Theme.BodyFont,
            DropDownStyle = ComboBoxStyle.DropDownList
        };
        _modeCombo.Items.AddRange(new object[] { "完整备份", "增量备份" });
        _modeCombo.SelectedIndex = AppState.Config.Backup.Mode == BackupMode.Full ? 0 : 1;
        _modeCombo.SelectedIndexChanged += (s, e) =>
        {
            AppState.Config.Backup.Mode = _modeCombo.SelectedIndex == 0 ? BackupMode.Full : BackupMode.Incremental;
            ConfigManager.Save(AppState.Config);
        };
        configCard.Controls.Add(_modeCombo);

        // 备份计划
        var scheduleLabel = new Label
        {
            Text = "备份计划：",
            Font = Theme.BodyFont,
            ForeColor = Theme.TextSecondary,
            Location = new Point(260, 12),
            Size = new Size(80, 22),
            BackColor = Color.Transparent
        };
        configCard.Controls.Add(scheduleLabel);

        _scheduleCombo = new ComboBox
        {
            Location = new Point(344, 10),
            Size = new Size(140, 24),
            FlatStyle = FlatStyle.Flat,
            Font = Theme.BodyFont,
            DropDownStyle = ComboBoxStyle.DropDownList
        };
        _scheduleCombo.Items.AddRange(new object[] { "每小时", "每天", "每周" });
        _scheduleCombo.SelectedIndex = (int)AppState.Config.Backup.Schedule;
        _scheduleCombo.SelectedIndexChanged += (s, e) =>
        {
            AppState.Config.Backup.Schedule = (BackupSchedule)_scheduleCombo.SelectedIndex;
            ConfigManager.Save(AppState.Config);
        };
        configCard.Controls.Add(_scheduleCombo);

        // 备份路径
        var pathLabel = new Label
        {
            Text = "备份路径：",
            Font = Theme.BodyFont,
            ForeColor = Theme.TextSecondary,
            Location = new Point(16, 46),
            Size = new Size(80, 22),
            BackColor = Color.Transparent
        };
        configCard.Controls.Add(pathLabel);

        _backupPathBox = new TextBox
        {
            Location = new Point(100, 44),
            Size = new Size(600, 24),
            Font = Theme.BodyFont,
            BackColor = Theme.CardBg,
            ForeColor = Theme.TextPrimary,
            BorderStyle = BorderStyle.FixedSingle,
            Text = AppState.Config.Backup.BackupPath ?? ""
        };
        _backupPathBox.Leave += (s, e) =>
        {
            AppState.Config.Backup.BackupPath = _backupPathBox.Text;
            ConfigManager.Save(AppState.Config);
        };
        configCard.Controls.Add(_backupPathBox);

        // NAS路径
        var nasLabel = new Label
        {
            Text = "NAS路径：",
            Font = Theme.BodyFont,
            ForeColor = Theme.TextSecondary,
            Location = new Point(16, 80),
            Size = new Size(80, 22),
            BackColor = Color.Transparent
        };
        configCard.Controls.Add(nasLabel);

        _nasPathBox = new TextBox
        {
            Location = new Point(100, 78),
            Size = new Size(600, 24),
            Font = Theme.BodyFont,
            BackColor = Theme.CardBg,
            ForeColor = Theme.TextPrimary,
            BorderStyle = BorderStyle.FixedSingle,
            Text = AppState.Config.Backup.NasPath ?? ""
        };
        _nasPathBox.Leave += (s, e) =>
        {
            AppState.Config.Backup.NasPath = _nasPathBox.Text;
            ConfigManager.Save(AppState.Config);
        };
        configCard.Controls.Add(_nasPathBox);

        // WebDAV URL
        var webDavUrlLabel = new Label
        {
            Text = "WebDAV：",
            Font = Theme.BodyFont,
            ForeColor = Theme.TextSecondary,
            Location = new Point(16, 114),
            Size = new Size(80, 22),
            BackColor = Color.Transparent
        };
        configCard.Controls.Add(webDavUrlLabel);

        _webDavUrlBox = new TextBox
        {
            Location = new Point(100, 112),
            Size = new Size(290, 24),
            Font = Theme.BodyFont,
            BackColor = Theme.CardBg,
            ForeColor = Theme.TextPrimary,
            BorderStyle = BorderStyle.FixedSingle,
            Text = AppState.Config.Backup.WebDavUrl ?? ""
        };
        _webDavUrlBox.Leave += (s, e) =>
        {
            AppState.Config.Backup.WebDavUrl = _webDavUrlBox.Text;
            ConfigManager.Save(AppState.Config);
        };
        configCard.Controls.Add(_webDavUrlBox);

        // WebDAV 用户名
        var webDavUserLabel = new Label
        {
            Text = "用户：",
            Font = Theme.BodyFont,
            ForeColor = Theme.TextSecondary,
            Location = new Point(400, 114),
            Size = new Size(50, 22),
            BackColor = Color.Transparent
        };
        configCard.Controls.Add(webDavUserLabel);

        _webDavUserBox = new TextBox
        {
            Location = new Point(454, 112),
            Size = new Size(120, 24),
            Font = Theme.BodyFont,
            BackColor = Theme.CardBg,
            ForeColor = Theme.TextPrimary,
            BorderStyle = BorderStyle.FixedSingle,
            Text = AppState.Config.Backup.WebDavUser ?? ""
        };
        _webDavUserBox.Leave += (s, e) =>
        {
            AppState.Config.Backup.WebDavUser = _webDavUserBox.Text;
            ConfigManager.Save(AppState.Config);
        };
        configCard.Controls.Add(_webDavUserBox);

        // WebDAV 密码
        var webDavPassLabel = new Label
        {
            Text = "密码：",
            Font = Theme.BodyFont,
            ForeColor = Theme.TextSecondary,
            Location = new Point(16, 148),
            Size = new Size(80, 22),
            BackColor = Color.Transparent
        };
        configCard.Controls.Add(webDavPassLabel);

        _webDavPassBox = new TextBox
        {
            Location = new Point(100, 146),
            Size = new Size(290, 24),
            Font = Theme.BodyFont,
            BackColor = Theme.CardBg,
            ForeColor = Theme.TextPrimary,
            BorderStyle = BorderStyle.FixedSingle,
            UseSystemPasswordChar = true,
            Text = AppState.Config.Backup.WebDavPassword ?? ""
        };
        _webDavPassBox.Leave += (s, e) =>
        {
            AppState.Config.Backup.WebDavPassword = _webDavPassBox.Text;
            ConfigManager.Save(AppState.Config);
        };
        configCard.Controls.Add(_webDavPassBox);

        y += 190;

        // ===== 保护文件夹管理区 =====
        CreateSectionTitle("保护文件夹", 0, y);
        y += 30;

        var folderCard = CreateCard(0, y, ContentWidth, 56);

        _addFolderBox = new TextBox
        {
            Location = new Point(16, 16),
            Size = new Size(480, 24),
            Font = Theme.BodyFont,
            BackColor = Theme.CardBg,
            ForeColor = Theme.TextPrimary,
            BorderStyle = BorderStyle.FixedSingle,
            PlaceholderText = "输入文件夹路径，如 D:\\MyDocuments"
        };
        folderCard.Controls.Add(_addFolderBox);

        _addFolderBtn = new AccentButton
        {
            Text = "添加保护文件夹",
            Location = new Point(506, 12),
            Size = new Size(160, 36)
        };
        _addFolderBtn.Click += () =>
        {
            var path = _addFolderBox.Text?.Trim();
            if (string.IsNullOrEmpty(path))
            {
                MessageBoxHelper.Warn("请输入文件夹路径。");
                return;
            }
            if (!Directory.Exists(path))
            {
                MessageBoxHelper.Warn("文件夹不存在，请检查路径。");
                return;
            }
            if (AppState.Config.Backup.ProtectedFolders.Contains(path))
            {
                MessageBoxHelper.Info("该文件夹已在保护列表中。");
                return;
            }
            AppState.Config.Backup.ProtectedFolders.Add(path);
            ConfigManager.Save(AppState.Config);
            _addFolderBox.Text = "";
            MessageBoxHelper.Info("保护文件夹已添加。");
            RefreshData();
        };
        folderCard.Controls.Add(_addFolderBtn);

        y += 76;

        // 显示保护文件夹列表
        var folders = AppState.Config.Backup.ProtectedFolders;
        foreach (var folder in folders)
        {
            var itemCard = CreateCard(0, y, ContentWidth, 30);

            var folderLabel = new Label
            {
                Text = folder,
                Font = Theme.BodyFont,
                ForeColor = Theme.TextSecondary,
                Location = new Point(16, 4),
                Size = new Size(600, 22),
                BackColor = Color.Transparent
            };
            itemCard.Controls.Add(folderLabel);

            var removeBtn = new AccentButton
            {
                Text = "移除",
                Location = new Point(624, 0),
                Size = new Size(72, 28)
            };
            var folderCopy = folder;
            removeBtn.Click += () =>
            {
                AppState.Config.Backup.ProtectedFolders.Remove(folderCopy);
                ConfigManager.Save(AppState.Config);
                MessageBoxHelper.Info("已移除保护文件夹。");
                RefreshData();
            };
            itemCard.Controls.Add(removeBtn);

            y += 38;
        }

        y += 10;

        // ===== 备份列表区 =====
        CreateSectionTitle("备份列表", 0, y);
        y += 30;

        if (_module != null)
        {
            var backups = _module.GetBackupList();

            if (backups.Count == 0)
            {
                var emptyLabel = new Label
                {
                    Text = "暂无备份记录",
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
                // 表头
                var headerCard = CreateCard(0, y, ContentWidth, 28);
                var headers = new[] { "文件名", "创建时间", "文件数", "大小", "校验" };
                var xPositions = new[] { 8, 260, 400, 480, 580 };
                var widths = new[] { 248, 136, 76, 96, 100 };

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

                foreach (var backup in backups)
                {
                    var backupCard = CreateCard(0, y, ContentWidth, 24);

                    var values = new[]
                    {
                        TruncateText(backup.FileName, 34),
                        backup.CreateTime.ToString("yyyy-MM-dd HH:mm"),
                        backup.FileCount.ToString(),
                        $"{backup.SizeBytes / 1024.0:F1} KB",
                        backup.Verified ? "通过" : "损坏"
                    };

                    for (int i = 0; i < values.Length; i++)
                    {
                        var vLabel = new Label
                        {
                            Text = values[i],
                            Font = Theme.SmallFont,
                            ForeColor = backup.Verified ? Theme.TextSecondary : Theme.Error,
                            Location = new Point(xPositions[i], 2),
                            Size = new Size(widths[i], 20),
                            BackColor = Color.Transparent
                        };
                        backupCard.Controls.Add(vLabel);
                    }

                    y += 30;
                }
            }

            y += 10;
        }

        y += 20;
    }

    /// <summary>启动备份（后台线程）</summary>
    private async void StartBackup()
    {
        if (_module == null || _isBackingUp) return;

        if (AppState.Config.Backup.ProtectedFolders.Count == 0)
        {
            MessageBoxHelper.Warn("请先添加至少一个保护文件夹。");
            return;
        }

        _isBackingUp = true;
        if (_backupBtn != null) _backupBtn.Enabled = false;

        if (_progressLabel != null)
        {
            _progressLabel.Text = "正在执行加密备份，请稍候...";
            _progressLabel.ForeColor = Theme.Warning;
        }

        var result = await Task.Run(() => _module.BackupNow());

        _isBackingUp = false;
        if (_backupBtn != null) _backupBtn.Enabled = true;

        if (_progressLabel != null)
        {
            _progressLabel.Text = result.Success ? "备份完成" : "备份失败";
            _progressLabel.ForeColor = result.Success ? Theme.Success : Theme.Error;
        }

        if (result.Success)
        {
            MessageBoxHelper.Info(
                $"{result.Message}\n\n" +
                $"备份文件数：{result.FileCount}\n" +
                $"备份大小：{result.TotalBytes / 1024.0:F1} KB\n" +
                $"耗时：{result.Duration.TotalSeconds:F1}s\n" +
                $"NAS上传：{(result.NasUploaded ? "成功" : "未配置/失败")}\n" +
                $"WebDAV上传：{(result.WebDavUploaded ? "成功" : "未配置/失败")}");
        }
        else
        {
            MessageBoxHelper.Error($"备份失败：{result.Message}");
        }

        RefreshData();
    }

    /// <summary>截断过长文本</summary>
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
