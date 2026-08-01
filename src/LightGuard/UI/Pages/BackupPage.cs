// © 2026 落尘（Luochen） 原创开发 - 保留所有权利

using System.Drawing.Drawing2D;
using System.Reflection;
using LightGuard.Backup;
using LightGuard.Core;
using LightGuard.Database;
using LightGuard.Modules;
using LightGuard.Recovery;
using LightGuard.UI.Controls;

// 消歧义：使用 Backup 命名空间的类型，而非 Modules 命名空间的旧版
using BackupProgress = LightGuard.Backup.BackupProgress;
using BackupManifest = LightGuard.Backup.BackupManifest;

namespace LightGuard.UI.Pages;

/// <summary>
/// 加密备份与灾难恢复页面（终极完整版）
/// <para>四大标签页：加密备份 | 灾难恢复 | 数据库备份 | 生命周期管理</para>
/// <para>后端引擎：EncryptedBackupModule + DisasterRecoveryModule + DatabaseBackupModule</para>
/// </summary>
public class BackupPage : Page
{
    // 模块引用
    private EncryptedBackupModule? _encBackupModule;
    private DisasterRecoveryModule? _recoveryModule;
    private DatabaseBackupModule? _dbBackupModule;

    // 标签页
    private int _activeTab; // 0=备份 1=恢复 2=数据库 3=生命周期
    private readonly string[] _tabNames = { "加密备份", "灾难恢复", "数据库备份", "生命周期" };
    private List<Panel> _tabButtons = new();

    // 备份标签页控件
    private ComboBox? _backupTypeCombo;
    private TextBox? _backupSourceBox;
    private TextBox? _backupPasswordBox;
    private TextBox? _backupDestBox;
    private ComboBox? _backupStrategyCombo;
    private AccentButton? _startBackupBtn;
    private AccentButton? _cancelBackupBtn;
    private AccentButton? _browseSourceBtn;
    private AccentButton? _browseDestBtn;
    private Panel? _backupProgressBar;
    private Label? _backupProgressLabel;
    private Label? _backupProgressDetail;
    private BackupProgress? _backupProgressTracker;

    // 恢复标签页控件
    private ComboBox? _recoveryModeCombo;
    private TextBox? _recoveryPasswordBox;
    private TextBox? _recoveryDestBox;
    private AccentButton? _browseRecoveryDestBtn;
    private Panel? _recoveryProgressBar;
    private Label? _recoveryProgressLabel;
    private Label? _recoveryProgressDetail;

    // 数据库标签页控件
    private ComboBox? _dbTypeCombo;
    private TextBox? _dbConnStrBox;
    private ComboBox? _dbBackupModeCombo;
    private TextBox? _dbTableNameBox;
    private AccentButton? _dbBackupBtn;
    private AccentButton? _dbRestoreBtn;
    private Panel? _dbProgressBar;
    private Label? _dbProgressLabel;
    private readonly DatabaseBackupEngine _dbEngine = new();

    // 生命周期标签页控件
    private NumericUpDown? _maxFullBackupsNum;
    private NumericUpDown? _maxIncrementalDaysNum;
    private NumericUpDown? _maxAgeDaysNum;
    private AccentButton? _cleanupNowBtn;

    // 状态
    private bool _isBusy;

    public BackupPage(AppState appState) : base(appState,
        "加密备份与灾难恢复",
        ".lgbackup 私有加密抗勒索 | AES-256-GCM | 五层粒度 | 三种恢复模式 | 数据库热备份")
    {
    }

    public override void OnShown()
    {
        _encBackupModule = AppState.Modules.GetModule("encrypted-backup") as EncryptedBackupModule;
        _recoveryModule = AppState.Modules.GetModule("disaster-recovery") as DisasterRecoveryModule;
        _dbBackupModule = AppState.Modules.GetModule("database-backup") as DatabaseBackupModule;
        BuildContent();
    }

    /// <summary>构建页面内容</summary>
    private void BuildContent()
    {
        ScrollContent.Controls.Clear();
        _tabButtons.Clear();

        int y = 0;
        int cw = ContentWidth;

        // ===== 标签栏 =====
        var tabBar = CreateCard(0, y, cw, 44);
        int tabW = (cw - 16) / _tabNames.Length;
        for (int i = 0; i < _tabNames.Length; i++)
        {
            var tab = new Panel
            {
                Location = new Point(8 + i * tabW, 6),
                Size = new Size(tabW - 4, 32),
                BackColor = Color.Transparent,
                Cursor = Cursors.Hand,
                Tag = i
            };
            var idx = i;
            tab.Click += (s, e) => { _activeTab = idx; BuildContent(); };
            tab.Paint += (s, e) =>
            {
                var g = e.Graphics;
                g.SmoothingMode = SmoothingMode.AntiAlias;
                var isActive = (int)tab.Tag! == _activeTab;
                using var bg = new SolidBrush(isActive ? Theme.Accent : Theme.CardHover);
                Theme.FillRoundedRect(g, bg, tab.ClientRectangle, 6);
                using var tb = new SolidBrush(isActive ? Color.White : Theme.TextSecondary);
                Theme.DrawCenteredText(g, _tabNames[idx], Theme.BodyFont, tb, tab.ClientRectangle);
            };
            tabBar.Controls.Add(tab);
            _tabButtons.Add(tab);
        }
        y += 54;

        // ===== 根据激活标签构建内容 =====
        switch (_activeTab)
        {
            case 0: BuildBackupTab(y); break;
            case 1: BuildRestoreTab(y); break;
            case 2: BuildDatabaseTab(y); break;
            case 3: BuildLifecycleTab(y); break;
        }
    }

    #region 标签页1：加密备份

    private void BuildBackupTab(int y)
    {
        int cw = ContentWidth;

        CreateSectionTitle("备份类型与源", 0, y);
        y += 30;

        var typeCard = CreateCard(0, y, cw, 100);

        // 备份类型
        var typeLabel = new Label
        {
            Text = "备份粒度：",
            Font = Theme.BodyFont,
            ForeColor = Theme.TextSecondary,
            Location = new Point(16, 12),
            Size = new Size(80, 22),
            BackColor = Color.Transparent
        };
        typeCard.Controls.Add(typeLabel);

        _backupTypeCombo = new ComboBox
        {
            Location = new Point(100, 10),
            Size = new Size(200, 24),
            FlatStyle = FlatStyle.Flat,
            Font = Theme.BodyFont,
            DropDownStyle = ComboBoxStyle.DropDownList
        };
        _backupTypeCombo.Items.AddRange(new object[]
        {
            "单文件备份",
            "整目录备份",
            "分区镜像备份 (VSS)",
            "整盘扇区镜像备份"
        });
        _backupTypeCombo.SelectedIndex = 0;
        typeCard.Controls.Add(_backupTypeCombo);

        // 备份策略
        var strategyLabel = new Label
        {
            Text = "备份策略：",
            Font = Theme.BodyFont,
            ForeColor = Theme.TextSecondary,
            Location = new Point(320, 12),
            Size = new Size(80, 22),
            BackColor = Color.Transparent
        };
        typeCard.Controls.Add(strategyLabel);

        _backupStrategyCombo = new ComboBox
        {
            Location = new Point(404, 10),
            Size = new Size(160, 24),
            FlatStyle = FlatStyle.Flat,
            Font = Theme.BodyFont,
            DropDownStyle = ComboBoxStyle.DropDownList
        };
        _backupStrategyCombo.Items.AddRange(new object[] { "全量备份", "增量备份" });
        _backupStrategyCombo.SelectedIndex = 0;
        typeCard.Controls.Add(_backupStrategyCombo);

        // 源路径
        var srcLabel = new Label
        {
            Text = "源路径：",
            Font = Theme.BodyFont,
            ForeColor = Theme.TextSecondary,
            Location = new Point(16, 46),
            Size = new Size(80, 22),
            BackColor = Color.Transparent
        };
        typeCard.Controls.Add(srcLabel);

        _backupSourceBox = new TextBox
        {
            Location = new Point(100, 44),
            Size = new Size(cw - 280, 24),
            Font = Theme.BodyFont,
            BackColor = Theme.CardBg,
            ForeColor = Theme.TextPrimary,
            BorderStyle = BorderStyle.FixedSingle,
            PlaceholderText = "选择文件/目录路径，或输入盘符（如 C）"
        };
        typeCard.Controls.Add(_backupSourceBox);

        _browseSourceBtn = new AccentButton
        {
            Text = "浏览...",
            Location = new Point(cw - 168, 40),
            Size = new Size(140, 32)
        };
        _browseSourceBtn.Click += BrowseSource;
        typeCard.Controls.Add(_browseSourceBtn);

        // 加密密码
        var pwdLabel = new Label
        {
            Text = "加密密码：",
            Font = Theme.BodyFont,
            ForeColor = Theme.TextSecondary,
            Location = new Point(16, 78),
            Size = new Size(80, 18),
            BackColor = Color.Transparent
        };
        typeCard.Controls.Add(pwdLabel);

        _backupPasswordBox = new TextBox
        {
            Location = new Point(100, 76),
            Size = new Size(cw - 280, 22),
            Font = Theme.BodyFont,
            BackColor = Theme.CardBg,
            ForeColor = Theme.TextPrimary,
            BorderStyle = BorderStyle.FixedSingle,
            UseSystemPasswordChar = true,
            PlaceholderText = "输入加密口令（PBKDF2 10万次迭代派生AES-256密钥）"
        };
        typeCard.Controls.Add(_backupPasswordBox);

        y += 110;

        // ===== 目标与操作 =====
        CreateSectionTitle("备份目标与执行", 0, y);
        y += 30;

        var destCard = CreateCard(0, y, cw, 80);

        var destLabel = new Label
        {
            Text = "目标目录：",
            Font = Theme.BodyFont,
            ForeColor = Theme.TextSecondary,
            Location = new Point(16, 12),
            Size = new Size(80, 22),
            BackColor = Color.Transparent
        };
        destCard.Controls.Add(destLabel);

        var defaultDest = _encBackupModule?.DestinationDirectory ?? "";
        _backupDestBox = new TextBox
        {
            Location = new Point(100, 10),
            Size = new Size(cw - 280, 24),
            Font = Theme.BodyFont,
            BackColor = Theme.CardBg,
            ForeColor = Theme.TextPrimary,
            BorderStyle = BorderStyle.FixedSingle,
            Text = defaultDest
        };
        destCard.Controls.Add(_backupDestBox);

        _browseDestBtn = new AccentButton
        {
            Text = "浏览...",
            Location = new Point(cw - 168, 6),
            Size = new Size(140, 32)
        };
        _browseDestBtn.Click += BrowseDest;
        destCard.Controls.Add(_browseDestBtn);

        _startBackupBtn = new AccentButton
        {
            Text = "开始加密备份",
            Location = new Point(16, 42),
            Size = new Size(160, 32)
        };
        _startBackupBtn.Click += StartEncryptBackup;
        destCard.Controls.Add(_startBackupBtn);

        _cancelBackupBtn = new AccentButton
        {
            Text = "取消备份",
            Location = new Point(186, 42),
            Size = new Size(120, 32),
            Enabled = false
        };
        _cancelBackupBtn.Click += CancelBackup;
        destCard.Controls.Add(_cancelBackupBtn);

        // 算法信息
        var algoLabel = new Label
        {
            Text = $"加密算法：{_encBackupModule?.Executor?.AlgorithmName ?? "AES-256-GCM"} | 分片：4MB | 格式：.lgbackup",
            Font = Theme.SmallFont,
            ForeColor = Theme.TextTertiary,
            Location = new Point(320, 46),
            Size = new Size(cw - 340, 22),
            BackColor = Color.Transparent
        };
        destCard.Controls.Add(algoLabel);

        y += 90;

        // ===== 进度条 =====
        CreateSectionTitle("备份进度", 0, y);
        y += 30;

        var progCard = CreateCard(0, y, cw, 70);

        _backupProgressBar = CreateProgressBar(progCard, 16, 12, cw - 32);
        _backupProgressLabel = new Label
        {
            Text = "就绪",
            Font = Theme.BodyFont,
            ForeColor = Theme.TextSecondary,
            Location = new Point(16, 38),
            Size = new Size(cw - 32, 20),
            BackColor = Color.Transparent
        };
        progCard.Controls.Add(_backupProgressLabel);

        _backupProgressDetail = new Label
        {
            Text = "",
            Font = Theme.SmallFont,
            ForeColor = Theme.TextTertiary,
            Location = new Point(16, 56),
            Size = new Size(cw - 32, 16),
            BackColor = Color.Transparent
        };
        progCard.Controls.Add(_backupProgressDetail);

        y += 80;

        // ===== 已有加密备份列表 =====
        CreateSectionTitle("加密备份列表 (.lgbackup)", 0, y);
        y += 30;

        try
        {
            var destDir = _encBackupModule?.DestinationDirectory ?? "";
            if (_encBackupModule?.Lifecycle != null && Directory.Exists(destDir))
            {
                var history = _encBackupModule.Lifecycle.GetBackupHistory(destDir);
                if (history.Count == 0)
                {
                    var empty = new Label
                    {
                        Text = "暂无加密备份记录",
                        Font = Theme.BodyFont,
                        ForeColor = Theme.TextTertiary,
                        Location = new Point(16, 0),
                        Size = new Size(cw - 32, 24),
                        BackColor = Color.Transparent
                    };
                    ScrollContent.Controls.Add(empty);
                    y += 30;
                }
                else
                {
                    // 表头
                    var headerCard = CreateCard(0, y, cw, 28);
                    var headers = new[] { "类型", "时间", "算法", "大小", "分片", "锁定", "策略" };
                    var xPos = new[] { 8, 90, 250, 390, 470, 540, 600 };
                    var widths = new[] { 78, 156, 136, 76, 66, 56, 80 };
                    for (int i = 0; i < headers.Length; i++)
                    {
                        var h = new Label
                        {
                            Text = headers[i],
                            Font = Theme.SmallFont,
                            ForeColor = Theme.TextSecondary,
                            Location = new Point(xPos[i], 4),
                            Size = new Size(widths[i], 20),
                            BackColor = Color.Transparent
                        };
                        headerCard.Controls.Add(h);
                    }
                    y += 34;

                    foreach (var m in history)
                    {
                        var itemCard = CreateCard(0, y, cw, 26);
                        var isInc = m.Metadata?.TryGetValue("Strategy", out var s) == true && s == "Incremental";
                        var vals = new[]
                        {
                            GetBackupTypeName(m.BackupType),
                            m.BackupTime.ToString("yyyy-MM-dd HH:mm"),
                            m.EncryptedAlgorithm,
                            $"{m.TotalSize / 1024.0:F1} KB",
                            m.ShardCount.ToString(),
                            m.IsLocked ? "已锁定" : "-",
                            isInc ? "增量" : "全量"
                        };
                        for (int i = 0; i < vals.Length; i++)
                        {
                            var v = new Label
                            {
                                Text = vals[i],
                                Font = Theme.SmallFont,
                                ForeColor = i == 5 && m.IsLocked ? Theme.Warning : Theme.TextSecondary,
                                Location = new Point(xPos[i], 3),
                                Size = new Size(widths[i], 20),
                                BackColor = Color.Transparent
                            };
                            itemCard.Controls.Add(v);
                        }
                        y += 30;
                    }
                }
            }
        }
        catch { }

        y += 20;
    }

    private async void StartEncryptBackup()
    {
        if (_isBusy || _encBackupModule?.Executor == null) return;

        var source = _backupSourceBox?.Text?.Trim();
        var password = _backupPasswordBox?.Text;
        var destDir = _backupDestBox?.Text?.Trim();
        var typeIdx = _backupTypeCombo?.SelectedIndex ?? 0;
        var incremental = _backupStrategyCombo?.SelectedIndex == 1;

        if (string.IsNullOrEmpty(source))
        {
            MessageBoxHelper.Warn("请输入或选择源路径。");
            return;
        }
        if (string.IsNullOrEmpty(password) || password.Length < 6)
        {
            MessageBoxHelper.Warn("请输入至少6位加密密码。");
            return;
        }
        if (string.IsNullOrEmpty(destDir))
        {
            MessageBoxHelper.Warn("请输入目标目录。");
            return;
        }

        _isBusy = true;
        SetBackupBusy(true);

        _backupProgressTracker = new BackupProgress();
        _backupProgressTracker.ProgressChanged += OnBackupProgress;

        try
        {
            var executor = _encBackupModule.Executor;
            BackupManifest? manifest = null;

            await Task.Run(() =>
            {
                manifest = typeIdx switch
                {
                    0 => executor.BackupSingleFile(source, password, destDir, _backupProgressTracker),
                    1 => executor.BackupDirectory(source, password, destDir, null, incremental, null, _backupProgressTracker),
                    2 => executor.BackupPartition(source, password, destDir, _backupProgressTracker),
                    3 => executor.BackupDisk(int.TryParse(source, out var dn) ? dn : 0, password, destDir, _backupProgressTracker),
                    _ => executor.BackupSingleFile(source, password, destDir, _backupProgressTracker)
                };
            });

            if (_backupProgressLabel != null)
            {
                _backupProgressLabel.Text = "备份完成";
                _backupProgressLabel.ForeColor = Theme.Success;
            }
            if (_backupProgressDetail != null)
            {
                _backupProgressDetail.Text = $"文件数：{manifest?.FileCount} | 大小：{manifest?.TotalSize / 1024.0:F1} KB | 分片：{manifest?.ShardCount} | 算法：{manifest?.EncryptedAlgorithm}";
            }
            UpdateProgressBar(_backupProgressBar, 100);

            MessageBoxHelper.Info(
                $"加密备份成功！\n\n" +
                $"类型：{GetBackupTypeName(manifest?.BackupType ?? BackupType.File)}\n" +
                $"算法：{manifest?.EncryptedAlgorithm}\n" +
                $"文件数：{manifest?.FileCount}\n" +
                $"分片数：{manifest?.ShardCount}\n" +
                $"大小：{manifest?.TotalSize / 1024.0:F1} KB\n" +
                $"哈希：{manifest?.GlobalHash[..16]}...");
        }
        catch (OperationCanceledException)
        {
            if (_backupProgressLabel != null)
            {
                _backupProgressLabel.Text = "备份已取消";
                _backupProgressLabel.ForeColor = Theme.Warning;
            }
        }
        catch (Exception ex)
        {
            if (_backupProgressLabel != null)
            {
                _backupProgressLabel.Text = "备份失败";
                _backupProgressLabel.ForeColor = Theme.Error;
            }
            if (_backupProgressDetail != null)
                _backupProgressDetail.Text = ex.Message;
            MessageBoxHelper.Error($"备份失败：{ex.Message}");
        }
        finally
        {
            _isBusy = false;
            SetBackupBusy(false);
            _backupProgressTracker = null;
        }
    }

    private void CancelBackup()
    {
        _backupProgressTracker?.Cancel();
    }

    private void OnBackupProgress(BackupProgressInfo info)
    {
        if (IsDisposed) return;
        try
        {
            BeginInvoke(() =>
            {
                UpdateProgressBar(_backupProgressBar, (int)info.Percent);
                if (_backupProgressLabel != null)
                {
                    var phaseText = info.Phase switch
                    {
                        BackupPhase.Backup => info.IsEncrypting ? "加密中" : "读取中",
                        BackupPhase.Verify => "校验中",
                        BackupPhase.Upload => "写入中",
                        _ => "处理中"
                    };
                    _backupProgressLabel.Text = $"{phaseText} {info.Percent:F1}% | 速度：{info.SpeedMBps:F1} MB/s | 剩余：{info.RemainingTime:mm\\:ss}";
                    _backupProgressLabel.ForeColor = Theme.Accent;
                }
                if (_backupProgressDetail != null)
                {
                    _backupProgressDetail.Text = $"文件：{info.ProcessedFiles}/{info.TotalFiles} | {info.ProcessedBytes / 1024.0:F1}/{info.TotalBytes / 1024.0:F1} KB | {info.CurrentFile}";
                }
            });
        }
        catch { }
    }

    private void SetBackupBusy(bool busy)
    {
        if (_startBackupBtn != null) _startBackupBtn.Enabled = !busy;
        if (_cancelBackupBtn != null) _cancelBackupBtn.Enabled = busy;
        if (_browseSourceBtn != null) _browseSourceBtn.Enabled = !busy;
        if (_browseDestBtn != null) _browseDestBtn.Enabled = !busy;
    }

    private void BrowseSource()
    {
        var typeIdx = _backupTypeCombo?.SelectedIndex ?? 0;
        try
        {
            if (typeIdx == 0)
            {
                using var dlg = new OpenFileDialog { Title = "选择要备份的文件" };
                if (dlg.ShowDialog() == DialogResult.OK && _backupSourceBox != null)
                    _backupSourceBox.Text = dlg.FileName;
            }
            else if (typeIdx == 1)
            {
                using var dlg = new FolderBrowserDialog { Description = "选择要备份的目录" };
                if (dlg.ShowDialog() == DialogResult.OK && _backupSourceBox != null)
                    _backupSourceBox.Text = dlg.SelectedPath;
            }
            else
            {
                // 分区/整盘：列出可用盘符供用户参考
                var drives = DriveInfo.GetDrives().Where(d => d.IsReady)
                    .Select(d => $"{d.Name[..1]}盘 ({d.TotalSize / 1024 / 1024 / 1024}GB)")
                    .ToArray();
                MessageBoxHelper.Info($"可用磁盘：\n{string.Join("\n", drives)}\n\n请在源路径中输入盘符（如 C）或磁盘编号（0=第一块磁盘）。");
            }
        }
        catch { }
    }

    private void BrowseDest()
    {
        try
        {
            using var dlg = new FolderBrowserDialog { Description = "选择备份目标目录" };
            if (dlg.ShowDialog() == DialogResult.OK && _backupDestBox != null)
                _backupDestBox.Text = dlg.SelectedPath;
        }
        catch { }
    }

    #endregion

    #region 标签页2：灾难恢复

    private void BuildRestoreTab(int y)
    {
        int cw = ContentWidth;

        CreateSectionTitle("恢复配置", 0, y);
        y += 30;

        var configCard = CreateCard(0, y, cw, 130);

        // 恢复模式
        var modeLabel = new Label
        {
            Text = "恢复模式：",
            Font = Theme.BodyFont,
            ForeColor = Theme.TextSecondary,
            Location = new Point(16, 12),
            Size = new Size(80, 22),
            BackColor = Color.Transparent
        };
        configCard.Controls.Add(modeLabel);

        _recoveryModeCombo = new ComboBox
        {
            Location = new Point(100, 10),
            Size = new Size(280, 24),
            FlatStyle = FlatStyle.Flat,
            Font = Theme.BodyFont,
            DropDownStyle = ComboBoxStyle.DropDownList
        };
        _recoveryModeCombo.Items.AddRange(new object[]
        {
            "隔离恢复（默认安全 - 恢复到新目录）",
            "增量恢复（仅恢复变更文件）",
            "强制覆盖恢复（灾难恢复专用）"
        });
        _recoveryModeCombo.SelectedIndex = 0;
        configCard.Controls.Add(_recoveryModeCombo);

        // 解密密码
        var pwdLabel = new Label
        {
            Text = "解密密码：",
            Font = Theme.BodyFont,
            ForeColor = Theme.TextSecondary,
            Location = new Point(16, 46),
            Size = new Size(80, 22),
            BackColor = Color.Transparent
        };
        configCard.Controls.Add(pwdLabel);

        _recoveryPasswordBox = new TextBox
        {
            Location = new Point(100, 44),
            Size = new Size(cw - 116, 24),
            Font = Theme.BodyFont,
            BackColor = Theme.CardBg,
            ForeColor = Theme.TextPrimary,
            BorderStyle = BorderStyle.FixedSingle,
            UseSystemPasswordChar = true,
            PlaceholderText = "输入备份时使用的加密口令"
        };
        configCard.Controls.Add(_recoveryPasswordBox);

        // 目标目录
        var destLabel = new Label
        {
            Text = "恢复目标：",
            Font = Theme.BodyFont,
            ForeColor = Theme.TextSecondary,
            Location = new Point(16, 80),
            Size = new Size(80, 22),
            BackColor = Color.Transparent
        };
        configCard.Controls.Add(destLabel);

        _recoveryDestBox = new TextBox
        {
            Location = new Point(100, 78),
            Size = new Size(cw - 280, 24),
            Font = Theme.BodyFont,
            BackColor = Theme.CardBg,
            ForeColor = Theme.TextPrimary,
            BorderStyle = BorderStyle.FixedSingle,
            PlaceholderText = "恢复目标目录"
        };
        configCard.Controls.Add(_recoveryDestBox);

        _browseRecoveryDestBtn = new AccentButton
        {
            Text = "浏览...",
            Location = new Point(cw - 168, 74),
            Size = new Size(140, 32)
        };
        _browseRecoveryDestBtn.Click += () =>
        {
            try
            {
                using var dlg = new FolderBrowserDialog { Description = "选择恢复目标目录" };
                if (dlg.ShowDialog() == DialogResult.OK && _recoveryDestBox != null)
                    _recoveryDestBox.Text = dlg.SelectedPath;
            }
            catch { }
        };
        configCard.Controls.Add(_browseRecoveryDestBtn);

        // 提示
        var hintLabel = new Label
        {
            Text = "提示：恢复流程为固定不可跳过 — 读取备份包 → 输入密钥 → 解密校验 → SHA256完整性校验 → 空间检测 → 按模式恢复",
            Font = Theme.SmallFont,
            ForeColor = Theme.TextTertiary,
            Location = new Point(16, 108),
            Size = new Size(cw - 32, 18),
            BackColor = Color.Transparent
        };
        configCard.Controls.Add(hintLabel);

        y += 140;

        // ===== 恢复进度 =====
        CreateSectionTitle("恢复进度", 0, y);
        y += 30;

        var progCard = CreateCard(0, y, cw, 70);
        _recoveryProgressBar = CreateProgressBar(progCard, 16, 12, cw - 32);
        _recoveryProgressLabel = new Label
        {
            Text = "就绪",
            Font = Theme.BodyFont,
            ForeColor = Theme.TextSecondary,
            Location = new Point(16, 38),
            Size = new Size(cw - 32, 20),
            BackColor = Color.Transparent
        };
        progCard.Controls.Add(_recoveryProgressLabel);
        _recoveryProgressDetail = new Label
        {
            Text = "",
            Font = Theme.SmallFont,
            ForeColor = Theme.TextTertiary,
            Location = new Point(16, 56),
            Size = new Size(cw - 32, 16),
            BackColor = Color.Transparent
        };
        progCard.Controls.Add(_recoveryProgressDetail);

        y += 80;

        // ===== 可恢复备份列表 =====
        CreateSectionTitle("可恢复备份列表", 0, y);
        y += 30;

        try
        {
            var destDir = _recoveryModule?.DefaultBackupDirectory ?? "";
            if (Directory.Exists(destDir))
            {
                var backupFiles = Directory.EnumerateFiles(destDir, "*.lgbackup").ToList();
                if (backupFiles.Count == 0)
                {
                    var empty = new Label
                    {
                        Text = "暂无可恢复的加密备份",
                        Font = Theme.BodyFont,
                        ForeColor = Theme.TextTertiary,
                        Location = new Point(16, 0),
                        Size = new Size(cw - 32, 24),
                        BackColor = Color.Transparent
                    };
                    ScrollContent.Controls.Add(empty);
                    y += 30;
                }
                else
                {
                    // 表头
                    var headerCard = CreateCard(0, y, cw, 28);
                    var headers = new[] { "文件名", "类型", "时间", "大小", "操作" };
                    var xPos = new[] { 8, 260, 330, 470, 570 };
                    var widths = new[] { 248, 66, 136, 96, 120 };
                    for (int i = 0; i < headers.Length; i++)
                    {
                        var h = new Label
                        {
                            Text = headers[i],
                            Font = Theme.SmallFont,
                            ForeColor = Theme.TextSecondary,
                            Location = new Point(xPos[i], 4),
                            Size = new Size(widths[i], 20),
                            BackColor = Color.Transparent
                        };
                        headerCard.Controls.Add(h);
                    }
                    y += 34;

                    foreach (var file in backupFiles)
                    {
                        BackupManifest? preview = null;
                        try
                        {
                            var (m, _, _) = LgBackupFormat.ReadManifestOnly(file);
                            preview = m;
                        }
                        catch { }

                        var itemCard = CreateCard(0, y, cw, 30);

                        var fileName = Path.GetFileName(file);
                        var vals = new[]
                        {
                            TruncateText(fileName, 32),
                            preview != null ? GetBackupTypeName(preview.BackupType) : "-",
                            preview?.BackupTime.ToString("yyyy-MM-dd HH:mm") ?? "-",
                            $"{new FileInfo(file).Length / 1024.0:F1} KB"
                        };
                        for (int i = 0; i < vals.Length; i++)
                        {
                            var v = new Label
                            {
                                Text = vals[i],
                                Font = Theme.SmallFont,
                                ForeColor = Theme.TextSecondary,
                                Location = new Point(xPos[i], 5),
                                Size = new Size(widths[i], 20),
                                BackColor = Color.Transparent
                            };
                            itemCard.Controls.Add(v);
                        }

                        // 恢复按钮
                        var restoreBtn = new AccentButton
                        {
                            Text = "恢复",
                            Location = new Point(xPos[4], 1),
                            Size = new Size(60, 26)
                        };
                        var filePath = file;
                        restoreBtn.Click += () => StartRestore(filePath);
                        itemCard.Controls.Add(restoreBtn);

                        // 预览按钮
                        var previewBtn = new AccentButton
                        {
                            Text = "预览",
                            Location = new Point(xPos[4] + 66, 1),
                            Size = new Size(50, 26)
                        };
                        var fp = file;
                        previewBtn.Click += () => PreviewBackup(fp);
                        itemCard.Controls.Add(previewBtn);

                        y += 34;
                    }
                }
            }
        }
        catch { }

        y += 20;
    }

    private async void StartRestore(string backupPath)
    {
        if (_isBusy || _recoveryModule?.Engine == null) return;

        var password = _recoveryPasswordBox?.Text;
        var destDir = _recoveryDestBox?.Text?.Trim();
        var modeIdx = _recoveryModeCombo?.SelectedIndex ?? 0;

        if (string.IsNullOrEmpty(password))
        {
            MessageBoxHelper.Warn("请输入解密密码。");
            return;
        }
        if (string.IsNullOrEmpty(destDir))
        {
            MessageBoxHelper.Warn("请输入恢复目标目录。");
            return;
        }

        var mode = modeIdx switch
        {
            0 => RecoveryMode.Isolated,
            1 => RecoveryMode.Incremental,
            2 => RecoveryMode.ForceOverwrite,
            _ => RecoveryMode.Isolated
        };

        _isBusy = true;

        var engine = _recoveryModule.Engine;
        engine.ProgressChanged += OnRecoveryProgress;

        try
        {
            if (_recoveryProgressLabel != null)
            {
                _recoveryProgressLabel.Text = "正在恢复...";
                _recoveryProgressLabel.ForeColor = Theme.Accent;
            }

            RecoveryResult? result = null;
            await Task.Run(() =>
            {
                result = engine.Recover(backupPath, password, destDir, mode);
            });

            if (result?.Success == true)
            {
                UpdateProgressBar(_recoveryProgressBar, 100);
                if (_recoveryProgressLabel != null)
                {
                    _recoveryProgressLabel.Text = "恢复完成";
                    _recoveryProgressLabel.ForeColor = Theme.Success;
                }
                if (_recoveryProgressDetail != null)
                    _recoveryProgressDetail.Text = $"文件数：{result.FileCount} | 大小：{result.TotalBytes / 1024.0:F1} KB";
                MessageBoxHelper.Info($"恢复成功！\n\n{result.Message}\n文件数：{result.FileCount}\n大小：{result.TotalBytes / 1024.0:F1} KB");
            }
            else
            {
                if (_recoveryProgressLabel != null)
                {
                    _recoveryProgressLabel.Text = "恢复失败";
                    _recoveryProgressLabel.ForeColor = Theme.Error;
                }
                MessageBoxHelper.Error($"恢复失败：{result?.Message}");
            }
        }
        catch (Exception ex)
        {
            if (_recoveryProgressLabel != null)
            {
                _recoveryProgressLabel.Text = "恢复失败";
                _recoveryProgressLabel.ForeColor = Theme.Error;
            }
            MessageBoxHelper.Error($"恢复失败：{ex.Message}");
        }
        finally
        {
            engine.ProgressChanged -= OnRecoveryProgress;
            _isBusy = false;
        }
    }

    private void OnRecoveryProgress(RecoveryProgressInfo info)
    {
        if (IsDisposed) return;
        try
        {
            BeginInvoke(() =>
            {
                UpdateProgressBar(_recoveryProgressBar, (int)info.Percent);
                if (_recoveryProgressLabel != null)
                {
                    _recoveryProgressLabel.Text = $"恢复 {info.Percent:F1}% | 解密:{info.DecryptProgress:F0}% 校验:{info.VerifyProgress:F0}% 写入:{info.WriteProgress:F0}%";
                    _recoveryProgressLabel.ForeColor = Theme.Accent;
                }
                if (_recoveryProgressDetail != null)
                    _recoveryProgressDetail.Text = info.CurrentFile;
            });
        }
        catch { }
    }

    private void PreviewBackup(string backupPath)
    {
        try
        {
            if (_recoveryModule?.Engine == null) return;
            var preview = _recoveryModule.Engine.PreviewBackup(backupPath);
            MessageBoxHelper.Info(
                $"备份预览\n\n" +
                $"类型：{GetBackupTypeName(preview.Manifest.BackupType)}\n" +
                $"时间：{preview.Manifest.BackupTime:yyyy-MM-dd HH:mm:ss}\n" +
                $"算法：{preview.Manifest.EncryptedAlgorithm}\n" +
                $"原始大小：{preview.TotalSize / 1024.0:F1} KB\n" +
                $"包体大小：{preview.PackageSize / 1024.0:F1} KB\n" +
                $"分片数：{preview.ShardCount}\n" +
                $"文件数：{preview.Manifest.FileCount}\n" +
                $"锁定：{(preview.Manifest.IsLocked ? "是" : "否")}\n" +
                $"哈希：{preview.Manifest.GlobalHash[..16]}...");
        }
        catch (Exception ex)
        {
            MessageBoxHelper.Error($"预览失败：{ex.Message}");
        }
    }

    #endregion

    #region 标签页3：数据库备份

    private void BuildDatabaseTab(int y)
    {
        int cw = ContentWidth;

        CreateSectionTitle("数据库备份配置", 0, y);
        y += 30;

        var configCard = CreateCard(0, y, cw, 150);

        // 数据库类型
        var typeLabel = new Label
        {
            Text = "数据库类型：",
            Font = Theme.BodyFont,
            ForeColor = Theme.TextSecondary,
            Location = new Point(16, 12),
            Size = new Size(90, 22),
            BackColor = Color.Transparent
        };
        configCard.Controls.Add(typeLabel);

        _dbTypeCombo = new ComboBox
        {
            Location = new Point(110, 10),
            Size = new Size(180, 24),
            FlatStyle = FlatStyle.Flat,
            Font = Theme.BodyFont,
            DropDownStyle = ComboBoxStyle.DropDownList
        };
        _dbTypeCombo.Items.AddRange(new object[] { "SQLite", "MySQL", "MariaDB", "SQL Server", "Access" });
        _dbTypeCombo.SelectedIndex = 0;
        configCard.Controls.Add(_dbTypeCombo);

        // 备份模式
        var modeLabel = new Label
        {
            Text = "备份模式：",
            Font = Theme.BodyFont,
            ForeColor = Theme.TextSecondary,
            Location = new Point(310, 12),
            Size = new Size(80, 22),
            BackColor = Color.Transparent
        };
        configCard.Controls.Add(modeLabel);

        _dbBackupModeCombo = new ComboBox
        {
            Location = new Point(394, 10),
            Size = new Size(180, 24),
            FlatStyle = FlatStyle.Flat,
            Font = Theme.BodyFont,
            DropDownStyle = ComboBoxStyle.DropDownList
        };
        _dbBackupModeCombo.Items.AddRange(new object[] { "整库备份", "单表备份", "事务日志增量备份" });
        _dbBackupModeCombo.SelectedIndex = 0;
        configCard.Controls.Add(_dbBackupModeCombo);

        // 表名
        var tableLabel = new Label
        {
            Text = "表名：",
            Font = Theme.BodyFont,
            ForeColor = Theme.TextSecondary,
            Location = new Point(16, 46),
            Size = new Size(90, 22),
            BackColor = Color.Transparent
        };
        configCard.Controls.Add(tableLabel);

        _dbTableNameBox = new TextBox
        {
            Location = new Point(110, 44),
            Size = new Size(180, 24),
            Font = Theme.BodyFont,
            BackColor = Theme.CardBg,
            ForeColor = Theme.TextPrimary,
            BorderStyle = BorderStyle.FixedSingle,
            PlaceholderText = "单表备份时填写"
        };
        configCard.Controls.Add(_dbTableNameBox);

        // 连接字符串
        var connLabel = new Label
        {
            Text = "连接字符串：",
            Font = Theme.BodyFont,
            ForeColor = Theme.TextSecondary,
            Location = new Point(16, 80),
            Size = new Size(90, 22),
            BackColor = Color.Transparent
        };
        configCard.Controls.Add(connLabel);

        _dbConnStrBox = new TextBox
        {
            Location = new Point(110, 78),
            Size = new Size(cw - 126, 24),
            Font = Theme.BodyFont,
            BackColor = Theme.CardBg,
            ForeColor = Theme.TextPrimary,
            BorderStyle = BorderStyle.FixedSingle,
            PlaceholderText = "SQLite: Data Source=C:\\app.db | MySQL: Server=localhost;Port=3306;Database=mydb;Uid=root;Pwd=123456"
        };
        configCard.Controls.Add(_dbConnStrBox);

        // 按钮
        _dbBackupBtn = new AccentButton
        {
            Text = "开始数据库备份",
            Location = new Point(16, 110),
            Size = new Size(160, 32)
        };
        _dbBackupBtn.Click += StartDbBackup;
        configCard.Controls.Add(_dbBackupBtn);

        _dbRestoreBtn = new AccentButton
        {
            Text = "还原数据库",
            Location = new Point(186, 110),
            Size = new Size(140, 32)
        };
        _dbRestoreBtn.Click += StartDbRestore;
        configCard.Controls.Add(_dbRestoreBtn);

        var infoLabel = new Label
        {
            Text = "AES-256-GCM 加密 | 支持热备份（业务无需停机）| 完整性校验 + 自动修复",
            Font = Theme.SmallFont,
            ForeColor = Theme.TextTertiary,
            Location = new Point(340, 116),
            Size = new Size(cw - 360, 18),
            BackColor = Color.Transparent
        };
        configCard.Controls.Add(infoLabel);

        y += 160;

        // ===== 进度 =====
        CreateSectionTitle("数据库备份进度", 0, y);
        y += 30;

        var progCard = CreateCard(0, y, cw, 50);
        _dbProgressBar = CreateProgressBar(progCard, 16, 12, cw - 32);
        _dbProgressLabel = new Label
        {
            Text = "就绪",
            Font = Theme.BodyFont,
            ForeColor = Theme.TextSecondary,
            Location = new Point(16, 36),
            Size = new Size(cw - 32, 12),
            BackColor = Color.Transparent
        };
        progCard.Controls.Add(_dbProgressLabel);

        y += 60;

        // ===== 数据库备份列表 =====
        CreateSectionTitle("数据库备份列表", 0, y);
        y += 30;

        try
        {
            if (_dbBackupModule != null)
            {
                var backups = _dbBackupModule.GetBackupList();
                if (backups.Count == 0)
                {
                    var empty = new Label
                    {
                        Text = "暂无数据库备份记录",
                        Font = Theme.BodyFont,
                        ForeColor = Theme.TextTertiary,
                        Location = new Point(16, 0),
                        Size = new Size(cw - 32, 24),
                        BackColor = Color.Transparent
                    };
                    ScrollContent.Controls.Add(empty);
                    y += 30;
                }
                else
                {
                    var headerCard = CreateCard(0, y, cw, 28);
                    var headers = new[] { "文件名", "数据库类型", "备份时间", "大小", "操作" };
                    var xPos = new[] { 8, 300, 400, 540, 640 };
                    var widths = new[] { 288, 96, 136, 96, 80 };
                    for (int i = 0; i < headers.Length; i++)
                    {
                        var h = new Label
                        {
                            Text = headers[i],
                            Font = Theme.SmallFont,
                            ForeColor = Theme.TextSecondary,
                            Location = new Point(xPos[i], 4),
                            Size = new Size(widths[i], 20),
                            BackColor = Color.Transparent
                        };
                        headerCard.Controls.Add(h);
                    }
                    y += 34;

                    foreach (var b in backups)
                    {
                        var itemCard = CreateCard(0, y, cw, 30);
                        var vals = new[]
                        {
                            TruncateText(b.FileName, 36),
                            b.DbType,
                            b.Timestamp.ToString("yyyy-MM-dd HH:mm"),
                            $"{b.SizeBytes / 1024.0:F1} KB"
                        };
                        for (int i = 0; i < vals.Length; i++)
                        {
                            var v = new Label
                            {
                                Text = vals[i],
                                Font = Theme.SmallFont,
                                ForeColor = Theme.TextSecondary,
                                Location = new Point(xPos[i], 5),
                                Size = new Size(widths[i], 20),
                                BackColor = Color.Transparent
                            };
                            itemCard.Controls.Add(v);
                        }

                        var verifyBtn = new AccentButton
                        {
                            Text = "校验",
                            Location = new Point(xPos[4], 1),
                            Size = new Size(60, 26)
                        };
                        var fp = b.FilePath;
                        verifyBtn.Click += () =>
                        {
                            try
                            {
                                var ok = _dbBackupModule?.VerifyBackup(fp) ?? false;
                                MessageBoxHelper.Info(ok ? "完整性校验通过" : "校验失败：文件可能已损坏");
                            }
                            catch (Exception ex) { MessageBoxHelper.Error($"校验失败：{ex.Message}"); }
                        };
                        itemCard.Controls.Add(verifyBtn);

                        y += 34;
                    }
                }
            }
        }
        catch { }

        y += 20;
    }

    private async void StartDbBackup()
    {
        if (_isBusy || _dbBackupModule == null) return;

        var connStr = _dbConnStrBox?.Text?.Trim();
        var dbTypeIdx = _dbTypeCombo?.SelectedIndex ?? 0;
        var modeIdx = _dbBackupModeCombo?.SelectedIndex ?? 0;
        var tableName = _dbTableNameBox?.Text?.Trim();

        if (string.IsNullOrEmpty(connStr))
        {
            MessageBoxHelper.Warn("请输入连接字符串或文件路径。");
            return;
        }

        var dbType = dbTypeIdx switch
        {
            0 => DatabaseType.SQLite,
            1 => DatabaseType.MySQL,
            2 => DatabaseType.MariaDB,
            3 => DatabaseType.SqlServer,
            4 => DatabaseType.Access,
            _ => DatabaseType.SQLite
        };

        var bkMode = modeIdx switch
        {
            0 => LightGuard.Database.BackupMode.Full,
            1 => LightGuard.Database.BackupMode.SingleTable,
            2 => LightGuard.Database.BackupMode.TransactionLog,
            _ => LightGuard.Database.BackupMode.Full
        };

        if (bkMode == LightGuard.Database.BackupMode.SingleTable && string.IsNullOrEmpty(tableName))
        {
            MessageBoxHelper.Warn("单表备份模式需要填写表名。");
            return;
        }

        _isBusy = true;
        if (_dbBackupBtn != null) _dbBackupBtn.Enabled = false;

        _dbEngine.ProgressChanged += OnDbProgress;

        try
        {
            if (_dbProgressLabel != null)
            {
                _dbProgressLabel.Text = "正在备份数据库...";
                _dbProgressLabel.ForeColor = Theme.Accent;
            }

            DatabaseBackupResult? result = null;
            await Task.Run(() =>
            {
                var destDir = Path.Combine(ConfigManager.GetBackupDir(), "databases", dbType.ToString());
                result = _dbEngine.BackupDatabase(dbType, connStr, destDir, bkMode, tableName);
            });

            if (result?.Success == true)
            {
                UpdateProgressBar(_dbProgressBar, 100);
                if (_dbProgressLabel != null)
                {
                    _dbProgressLabel.Text = "数据库备份完成";
                    _dbProgressLabel.ForeColor = Theme.Success;
                }
                MessageBoxHelper.Info(
                    $"数据库备份成功！\n\n{result.Message}\n大小：{result.SizeBytes / 1024.0:F1} KB\n耗时：{result.Duration.TotalSeconds:F1}s\n哈希：{result.Hash?[..16]}...");
                BuildContent();
            }
            else
            {
                if (_dbProgressLabel != null)
                {
                    _dbProgressLabel.Text = "备份失败";
                    _dbProgressLabel.ForeColor = Theme.Error;
                }
                MessageBoxHelper.Error($"数据库备份失败：{result?.Message}");
            }
        }
        catch (Exception ex)
        {
            if (_dbProgressLabel != null)
            {
                _dbProgressLabel.Text = "备份失败";
                _dbProgressLabel.ForeColor = Theme.Error;
            }
            MessageBoxHelper.Error($"数据库备份失败：{ex.Message}");
        }
        finally
        {
            try { _dbEngine.ProgressChanged -= OnDbProgress; } catch { }
            _isBusy = false;
            if (_dbBackupBtn != null) _dbBackupBtn.Enabled = true;
        }
    }

    private void OnDbProgress(DatabaseBackupProgress info)
    {
        if (IsDisposed) return;
        try
        {
            BeginInvoke(() =>
            {
                UpdateProgressBar(_dbProgressBar, info.Percent);
                if (_dbProgressLabel != null)
                {
                    _dbProgressLabel.Text = $"{info.Status} | {info.Percent}% | {info.SpeedMBps:F1} MB/s";
                    _dbProgressLabel.ForeColor = Theme.Accent;
                }
            });
        }
        catch { }
    }

    private void StartDbRestore()
    {
        var connStr = _dbConnStrBox?.Text?.Trim();
        var dbTypeIdx = _dbTypeCombo?.SelectedIndex ?? 0;

        if (string.IsNullOrEmpty(connStr))
        {
            MessageBoxHelper.Warn("请输入目标数据库连接字符串。");
            return;
        }

        try
        {
            using var dlg = new OpenFileDialog
            {
                Title = "选择数据库备份文件",
                Filter = "加密数据库备份 (*.enc)|*.enc|所有文件 (*.*)|*.*"
            };
            if (dlg.ShowDialog() != DialogResult.OK) return;

            var dbType = dbTypeIdx switch
            {
                0 => DatabaseType.SQLite,
                1 => DatabaseType.MySQL,
                2 => DatabaseType.MariaDB,
                3 => DatabaseType.SqlServer,
                4 => DatabaseType.Access,
                _ => DatabaseType.SQLite
            };

            if (_dbBackupModule == null) return;
            var ok = _dbBackupModule.RestoreFromBackup(dbType, connStr, dlg.FileName);
            if (ok)
                MessageBoxHelper.Info("数据库还原成功！");
            else
                MessageBoxHelper.Error("数据库还原失败，请检查备份文件和连接字符串。");
        }
        catch (Exception ex)
        {
            MessageBoxHelper.Error($"还原失败：{ex.Message}");
        }
    }

    #endregion

    #region 标签页4：生命周期管理

    private void BuildLifecycleTab(int y)
    {
        int cw = ContentWidth;

        CreateSectionTitle("自动清理策略", 0, y);
        y += 30;

        var policyCard = CreateCard(0, y, cw, 110);

        // 保留全量备份数
        var maxFullLabel = new Label
        {
            Text = "保留全量备份份数：",
            Font = Theme.BodyFont,
            ForeColor = Theme.TextSecondary,
            Location = new Point(16, 12),
            Size = new Size(140, 22),
            BackColor = Color.Transparent
        };
        policyCard.Controls.Add(maxFullLabel);

        _maxFullBackupsNum = new NumericUpDown
        {
            Location = new Point(160, 10),
            Size = new Size(80, 24),
            Minimum = 1,
            Maximum = 100,
            Value = 5,
            Font = Theme.BodyFont
        };
        policyCard.Controls.Add(_maxFullBackupsNum);

        // 增量保留天数
        var incDaysLabel = new Label
        {
            Text = "增量备份保留天数：",
            Font = Theme.BodyFont,
            ForeColor = Theme.TextSecondary,
            Location = new Point(260, 12),
            Size = new Size(140, 22),
            BackColor = Color.Transparent
        };
        policyCard.Controls.Add(incDaysLabel);

        _maxIncrementalDaysNum = new NumericUpDown
        {
            Location = new Point(404, 10),
            Size = new Size(80, 24),
            Minimum = 1,
            Maximum = 365,
            Value = 30,
            Font = Theme.BodyFont
        };
        policyCard.Controls.Add(_maxIncrementalDaysNum);

        // 最大年龄
        var ageLabel = new Label
        {
            Text = "最大保留天数：",
            Font = Theme.BodyFont,
            ForeColor = Theme.TextSecondary,
            Location = new Point(16, 46),
            Size = new Size(140, 22),
            BackColor = Color.Transparent
        };
        policyCard.Controls.Add(ageLabel);

        _maxAgeDaysNum = new NumericUpDown
        {
            Location = new Point(160, 44),
            Size = new Size(80, 24),
            Minimum = 7,
            Maximum = 3650,
            Value = 90,
            Font = Theme.BodyFont
        };
        policyCard.Controls.Add(_maxAgeDaysNum);

        // 立即清理按钮
        _cleanupNowBtn = new AccentButton
        {
            Text = "立即执行清理",
            Location = new Point(260, 42),
            Size = new Size(160, 32)
        };
        _cleanupNowBtn.Click += CleanupNow;
        policyCard.Controls.Add(_cleanupNowBtn);

        // 说明
        var descLabel = new Label
        {
            Text = "核心备份锁定保护：已锁定的关键全量备份不会被自动删除，防止误删。自动清理全程日志记录、统计释放空间。",
            Font = Theme.SmallFont,
            ForeColor = Theme.TextTertiary,
            Location = new Point(16, 80),
            Size = new Size(cw - 32, 24),
            BackColor = Color.Transparent
        };
        policyCard.Controls.Add(descLabel);

        y += 120;

        // ===== NAS / SMB 配置 =====
        CreateSectionTitle("NAS / SMB 局域网容灾配置", 0, y);
        y += 30;

        var nasCard = CreateCard(0, y, cw, 80);

        var nasLabel = new Label
        {
            Text = "NAS 路径：",
            Font = Theme.BodyFont,
            ForeColor = Theme.TextSecondary,
            Location = new Point(16, 12),
            Size = new Size(80, 22),
            BackColor = Color.Transparent
        };
        nasCard.Controls.Add(nasLabel);

        var nasBox = new TextBox
        {
            Location = new Point(100, 10),
            Size = new Size(cw - 116, 24),
            Font = Theme.BodyFont,
            BackColor = Theme.CardBg,
            ForeColor = Theme.TextPrimary,
            BorderStyle = BorderStyle.FixedSingle,
            Text = AppState.Config.Backup.NasPath ?? "",
            PlaceholderText = @"\\NAS-SERVER\Backups\LightGuard 或 \\192.168.1.100\share"
        };
        nasBox.Leave += (s, e) =>
        {
            AppState.Config.Backup.NasPath = nasBox.Text;
            ConfigManager.Save(AppState.Config);
        };
        nasCard.Controls.Add(nasBox);

        var webDavLabel = new Label
        {
            Text = "WebDAV：",
            Font = Theme.BodyFont,
            ForeColor = Theme.TextSecondary,
            Location = new Point(16, 46),
            Size = new Size(80, 22),
            BackColor = Color.Transparent
        };
        nasCard.Controls.Add(webDavLabel);

        var webDavBox = new TextBox
        {
            Location = new Point(100, 44),
            Size = new Size(cw - 280, 24),
            Font = Theme.BodyFont,
            BackColor = Theme.CardBg,
            ForeColor = Theme.TextPrimary,
            BorderStyle = BorderStyle.FixedSingle,
            Text = AppState.Config.Backup.WebDavUrl ?? "",
            PlaceholderText = "https://cloud.example.com/dav/LightGuard/"
        };
        webDavBox.Leave += (s, e) =>
        {
            AppState.Config.Backup.WebDavUrl = webDavBox.Text;
            ConfigManager.Save(AppState.Config);
        };
        nasCard.Controls.Add(webDavBox);

        var saveBtn = new AccentButton
        {
            Text = "保存配置",
            Location = new Point(cw - 168, 40),
            Size = new Size(140, 32)
        };
        saveBtn.Click += () => { ConfigManager.Save(AppState.Config); MessageBoxHelper.Info("配置已保存。"); };
        nasCard.Controls.Add(saveBtn);

        y += 90;

        // ===== 锁定管理 =====
        CreateSectionTitle("核心备份锁定管理", 0, y);
        y += 30;

        try
        {
            var destDir = _encBackupModule?.DestinationDirectory ?? "";
            if (_encBackupModule?.Lifecycle != null && Directory.Exists(destDir))
            {
                var history = _encBackupModule.Lifecycle.GetBackupHistory(destDir);
                if (history.Count == 0)
                {
                    var empty = new Label
                    {
                        Text = "暂无备份",
                        Font = Theme.BodyFont,
                        ForeColor = Theme.TextTertiary,
                        Location = new Point(16, 0),
                        Size = new Size(cw - 32, 24),
                        BackColor = Color.Transparent
                    };
                    ScrollContent.Controls.Add(empty);
                    y += 30;
                }
                else
                {
                    foreach (var m in history)
                    {
                        var itemCard = CreateCard(0, y, cw, 30);

                        var info = new Label
                        {
                            Text = $"{GetBackupTypeName(m.BackupType)} | {m.BackupTime:yyyy-MM-dd HH:mm} | {m.EncryptedAlgorithm} | {(m.IsLocked ? "已锁定" : "未锁定")}",
                            Font = Theme.SmallFont,
                            ForeColor = m.IsLocked ? Theme.Warning : Theme.TextSecondary,
                            Location = new Point(16, 5),
                            Size = new Size(cw - 200, 20),
                            BackColor = Color.Transparent
                        };
                        itemCard.Controls.Add(info);

                        var lockBtn = new AccentButton
                        {
                            Text = m.IsLocked ? "解锁" : "锁定",
                            Location = new Point(cw - 160, 1),
                            Size = new Size(140, 26)
                        };
                        var backupId = m.BackupId;
                        var isLocked = m.IsLocked;
                        lockBtn.Click += () => ToggleLock(backupId, !isLocked);
                        itemCard.Controls.Add(lockBtn);

                        y += 34;
                    }
                }
            }
        }
        catch { }

        y += 20;
    }

    private void CleanupNow()
    {
        try
        {
            if (_encBackupModule?.Lifecycle == null) return;
            var destDir = _encBackupModule.DestinationDirectory;
            var maxFull = (int)(_maxFullBackupsNum?.Value ?? 5);
            var maxIncDays = (int)(_maxIncrementalDaysNum?.Value ?? 30);
            var maxAge = (int)(_maxAgeDaysNum?.Value ?? 90);

            long freed = 0;
            freed += _encBackupModule.Lifecycle.CleanupByRetention(destDir, maxFull, maxIncDays);
            freed += _encBackupModule.Lifecycle.CleanupByAge(destDir, maxAge);

            MessageBoxHelper.Info($"清理完成！\n\n释放空间：{freed / 1024.0:F1} KB\n保留全量：{maxFull} 套\n增量保留：{maxIncDays} 天\n最大年龄：{maxAge} 天");
            BuildContent();
        }
        catch (Exception ex)
        {
            MessageBoxHelper.Error($"清理失败：{ex.Message}");
        }
    }

    private void ToggleLock(Guid backupId, bool lockIt)
    {
        try
        {
            if (_encBackupModule?.Lifecycle == null) return;
            var ok = lockIt
                ? _encBackupModule.Lifecycle.LockBackup(backupId)
                : _encBackupModule.Lifecycle.UnlockBackup(backupId);
            MessageBoxHelper.Info(ok ? $"已{(lockIt ? "锁定" : "解锁")}核心备份" : "操作失败");
            BuildContent();
        }
        catch (Exception ex)
        {
            MessageBoxHelper.Error($"操作失败：{ex.Message}");
        }
    }

    #endregion

    #region 辅助方法

    /// <summary>创建主题化进度条（百分比存储在 Tag 中，Paint 处理器只注册一次）</summary>
    private Panel CreateProgressBar(Panel parent, int x, int y, int width)
    {
        var bar = new Panel
        {
            Location = new Point(x, y),
            Size = new Size(width, 20),
            BackColor = Color.Transparent,
            Tag = 0
        };
        typeof(Control).GetProperty("DoubleBuffered",
            BindingFlags.NonPublic | BindingFlags.Instance)
            ?.SetValue(bar, true, null);
        bar.Paint += (s, e) =>
        {
            var g = e.Graphics;
            g.SmoothingMode = SmoothingMode.AntiAlias;
            var pct = s is Panel p && p.Tag is int v ? v : 0;
            // 背景
            using var bgBrush = new SolidBrush(Theme.Border);
            Theme.FillRoundedRect(g, bgBrush, bar.ClientRectangle, 6);
            if (pct > 0)
            {
                var fillW = Math.Max(6, (int)(bar.Width * pct / 100.0));
                var fillRect = new Rectangle(0, 0, fillW, bar.Height);
                using var fillBrush = new SolidBrush(Theme.Accent);
                Theme.FillRoundedRect(g, fillBrush, fillRect, 6);
            }
        };
        parent.Controls.Add(bar);
        return bar;
    }

    /// <summary>更新进度条</summary>
    private void UpdateProgressBar(Panel? bar, int percent)
    {
        if (bar == null) return;
        percent = Math.Max(0, Math.Min(100, percent));
        bar.Tag = percent;
        bar.Invalidate();
    }

    /// <summary>截断文本</summary>
    private static string TruncateText(string text, int maxLen)
    {
        if (string.IsNullOrEmpty(text)) return "";
        return text.Length <= maxLen ? text : text.Substring(0, maxLen - 3) + "...";
    }

    /// <summary>获取备份类型显示名</summary>
    private static string GetBackupTypeName(BackupType type) => type switch
    {
        BackupType.File => "单文件",
        BackupType.Directory => "目录",
        BackupType.Partition => "分区镜像",
        BackupType.Disk => "整盘镜像",
        BackupType.Database => "数据库",
        _ => type.ToString()
    };

    public override void RefreshData()
    {
        BuildContent();
    }

    #endregion
}
