// © 2026 落尘（Luochen） 原创开发 - 保留所有权利

using System.Drawing.Drawing2D;
using System.Reflection;
using System.Security.Cryptography;
using LightGuard.Backup;
using LightGuard.Core;
using LightGuard.Database;
using LightGuard.Defender;
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
    private int _activeTab; // 0=备份 1=恢复 2=数据库 3=生命周期 4=企业容灾 5=快照审计
    private readonly string[] _tabNames = { "加密备份", "灾难恢复", "数据库备份", "生命周期", "企业容灾", "快照审计" };
    private List<Panel> _tabButtons = new();

    // 企业容灾引擎引用
    private VssShadowCopyEngine? _vssEngine;
    private RansomwareProofBackupPool? _backupPool;
    private BackupHealthVerifier _healthVerifier = new();
    private ResumableBackupEngine _resumableEngine = new();
    private SmartFilterEngine _filterEngine = new();

    // 快照链与审计引擎引用
    private SnapshotChainManager _chainManager = new(AppState.Instance);
    private BackupAuditReporter _auditReporter = new();
    private BackupPermissionLock _permissionLock = new();
    private BackupThrottleEngine? _throttleEngine;

    // 企业容灾标签页控件
    private TextBox? _vssSourceBox;
    private TextBox? _vssDestBox;
    private TextBox? _vssPasswordBox;
    private AccentButton? _vssBackupBtn;
    private Panel? _vssProgressBar;
    private Label? _vssProgressLabel;
    private TextBox? _poolPathBox;
    private AccentButton? _poolInitBtn;
    private AccentButton? _poolLockBtn;
    private AccentButton? _poolUnlockBtn;
    private Label? _poolStatusLabel;
    private AccentButton? _healthCheckBtn;
    private Label? _healthResultLabel;
    private TextBox? _resumeFileBox;
    private AccentButton? _resumeStartBtn;
    private AccentButton? _resumeResumeBtn;
    private Label? _resumeStatusLabel;
    private TextBox? _filterExcludesBox;
    private Label? _filterStatsLabel;

    // 快照审计标签页控件
    private TextBox? _chainSourceBox;
    private TextBox? _chainDirBox;
    private AccentButton? _createChainBtn;
    private Label? _chainListLabel;
    private AccentButton? _auditCompareBtn;
    private Label? _auditResultLabel;
    private TextBox? _lockFileBox;
    private AccentButton? _lockBtn;
    private AccentButton? _unlockBtn;
    private Label? _lockStatusLabel;
    private ComboBox? _throttleModeCombo;
    private NumericUpDown? _throttleIoNum;
    private AccentButton? _throttleApplyBtn;
    private Label? _throttleStatusLabel;

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
    private TextBox? _recoveryFileBox;
    private AccentButton? _browseRecoveryDestBtn;
    private AccentButton? _browseBackupFileBtn;
    private AccentButton? _confirmRestoreBtn;
    private AccentButton? _browseSelectiveRestoreBtn;
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

    /// <summary>跨标签页传递的待恢复文件路径（从备份列表点击"恢复"时设置）</summary>
    private string? _pendingRestoreFile;

    /// <summary>跨标签页传递的恢复目标目录（与 _pendingRestoreFile 配合使用）</summary>
    private string? _pendingRestoreDest;

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
            case 4: BuildEnterpriseTab(y); break;
            case 5: BuildSnapshotAuditTab(y); break;
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

        // ===== 已有加密备份列表（扫描多目录：目标目录 + 桌面 + 文档） =====
        CreateSectionTitle("加密备份列表 (.lgbackup)  —  自动扫描: 备份目标 / 桌面 / 文档", 0, y);
        y += 30;

        try
        {
            // 扫描多个目录
            var searchDirs = new List<string>();
            var destDir = _encBackupModule?.DestinationDirectory ?? "";
            if (!string.IsNullOrEmpty(destDir) && Directory.Exists(destDir))
                searchDirs.Add(destDir);

            var desktop = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
            if (!string.IsNullOrEmpty(desktop) && Directory.Exists(desktop) && !searchDirs.Contains(desktop))
                searchDirs.Add(desktop);

            var documents = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
            if (!string.IsNullOrEmpty(documents) && Directory.Exists(documents) && !searchDirs.Contains(documents))
                searchDirs.Add(documents);

            var backupFiles = new List<string>();
            foreach (var dir in searchDirs)
            {
                try
                {
                    foreach (var f in Directory.EnumerateFiles(dir, "*.lgbackup"))
                    {
                        if (!backupFiles.Contains(f))
                            backupFiles.Add(f);
                    }
                }
                catch { }
            }

            if (backupFiles.Count == 0)
            {
                var empty = new Label
                {
                    Text = "暂无加密备份记录 — 可在上方创建新备份，或在\"灾难恢复\"标签页手动选择 .lgbackup 文件",
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
                var headers = new[] { "文件名", "位置", "类型", "时间", "大小", "算法", "操作" };
                var xPos = new[] { 8, 250, 380, 450, 560, 650, 740 };
                var widths = new[] { 238, 126, 66, 106, 86, 84, 100 };
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
                    BackupManifest? manifest = null;
                    try
                    {
                        var (m, _, _) = LgBackupFormat.ReadManifestOnly(file);
                        manifest = m;
                    }
                    catch { }

                    var itemCard = CreateCard(0, y, cw, 30);

                    var fileName = Path.GetFileName(file);
                    var dirName = Path.GetDirectoryName(file) ?? "";
                    var dirDisplay = TruncateText(dirName, 18);
                    var fileSize = new FileInfo(file).Length;
                    var vals = new[]
                    {
                        TruncateText(fileName, 30),
                        dirDisplay,
                        manifest != null ? GetBackupTypeName(manifest.BackupType) : "-",
                        manifest?.BackupTime.ToString("MM-dd HH:mm") ?? "-",
                        $"{fileSize / 1024.0:F1} KB",
                        manifest?.EncryptedAlgorithm ?? "-"
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

                    // 恢复按钮 — 跳转到恢复标签页并预填充文件路径
                    var restoreBtn = new AccentButton
                    {
                        Text = "恢复",
                        Location = new Point(xPos[6], 1),
                        Size = new Size(46, 26)
                    };
                    var filePath = file;
                    restoreBtn.Click += () =>
                    {
                        _pendingRestoreFile = filePath;
                        _pendingRestoreDest = Path.Combine(
                            Path.GetDirectoryName(filePath) ?? "", "Restored");
                        _activeTab = 1; // 切换到灾难恢复标签页
                        BuildContent();
                    };
                    itemCard.Controls.Add(restoreBtn);

                    // 预览按钮
                    var previewBtn = new AccentButton
                    {
                        Text = "预览",
                        Location = new Point(xPos[6] + 50, 1),
                        Size = new Size(46, 26)
                    };
                    var fp = file;
                    previewBtn.Click += () => PreviewBackup(fp);
                    itemCard.Controls.Add(previewBtn);

                    y += 34;
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

            // P1-6：备份前自动查杀源文件（恶意文件跳过备份）— 仅目录备份启用
            HashSet<string>? maliciousFiles = null;
            if (typeIdx == 1 && AppState.Config.Backup.ScanBeforeBackup && !string.IsNullOrEmpty(source))
            {
                if (_backupProgressLabel != null)
                {
                    _backupProgressLabel.Text = "备份前查杀源文件（Defender）...";
                    _backupProgressLabel.ForeColor = Theme.Warning;
                }
                maliciousFiles = await DefenderIntegrationService.CollectMaliciousFilesAsync(source);
                if (maliciousFiles.Count > 0)
                {
                    if (_backupProgressLabel != null)
                    {
                        _backupProgressLabel.Text = $"已跳过 {maliciousFiles.Count} 个恶意文件";
                        _backupProgressLabel.ForeColor = Theme.Warning;
                    }
                }
            }

            await Task.Run(() =>
            {
                manifest = typeIdx switch
                {
                    0 => executor.BackupSingleFile(source, password, destDir, _backupProgressTracker),
                    1 => executor.BackupDirectory(source, password, destDir, null, incremental, null, _backupProgressTracker, maliciousFiles),
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

        CreateSectionTitle("选择备份文件", 0, y);
        y += 30;

        // ===== 备份文件选择卡片 =====
        var fileCard = CreateCard(0, y, cw, 60);

        var fileLabel = new Label
        {
            Text = "备份文件：",
            Font = Theme.BodyFont,
            ForeColor = Theme.TextSecondary,
            Location = new Point(16, 14),
            Size = new Size(80, 22),
            BackColor = Color.Transparent
        };
        fileCard.Controls.Add(fileLabel);

        _recoveryFileBox = new TextBox
        {
            Location = new Point(100, 12),
            Size = new Size(cw - 280, 24),
            Font = Theme.BodyFont,
            BackColor = Theme.CardBg,
            ForeColor = Theme.TextPrimary,
            BorderStyle = BorderStyle.FixedSingle,
            PlaceholderText = "选择 .lgbackup 加密备份文件，或在下方列表中点击"
        };
        fileCard.Controls.Add(_recoveryFileBox);

        // 如果从备份列表点击"恢复"跳转过来，预填充文件路径
        if (!string.IsNullOrEmpty(_pendingRestoreFile))
        {
            _recoveryFileBox.Text = _pendingRestoreFile;
            // 自动填充恢复目标为备份文件所在目录下的 Restored 子目录
            if (string.IsNullOrEmpty(_recoveryDestBox?.Text))
            {
                var restoreDir = Path.Combine(
                    Path.GetDirectoryName(_pendingRestoreFile) ?? "", "Restored");
                // _recoveryDestBox 尚未创建，稍后创建时再填充
                _pendingRestoreDest = restoreDir;
            }
            _pendingRestoreFile = null; // 清除标记
        }

        _browseBackupFileBtn = new AccentButton
        {
            Text = "浏览选择文件...",
            Location = new Point(cw - 168, 8),
            Size = new Size(140, 32)
        };
        _browseBackupFileBtn.Click += BrowseBackupFile;
        fileCard.Controls.Add(_browseBackupFileBtn);

        y += 70;

        // ===== 恢复配置卡片 =====
        CreateSectionTitle("恢复配置", 0, y);
        y += 30;

        var configCard = CreateCard(0, y, cw, 200);

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

        // 恢复目标目录
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
            PlaceholderText = "选择恢复目标目录（留空则恢复到原始路径）"
        };
        configCard.Controls.Add(_recoveryDestBox);

        // 如果有跨标签页传递的恢复目标，预填充
        if (!string.IsNullOrEmpty(_pendingRestoreDest))
        {
            _recoveryDestBox.Text = _pendingRestoreDest;
            _pendingRestoreDest = null;
        }

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

        // 确认恢复按钮
        _confirmRestoreBtn = new AccentButton
        {
            Text = "确认恢复",
            Location = new Point(16, 112),
            Size = new Size(160, 32)
        };
        _confirmRestoreBtn.Click += ConfirmRestore;
        configCard.Controls.Add(_confirmRestoreBtn);

        // 选择性还原按钮：浏览备份内容并勾选还原
        _browseSelectiveRestoreBtn = new AccentButton
        {
            Text = "浏览并选择还原...",
            Location = new Point(186, 112),
            Size = new Size(220, 32)
        };
        _browseSelectiveRestoreBtn.Click += async () => await StartSelectiveRestoreAsync();
        configCard.Controls.Add(_browseSelectiveRestoreBtn);

        // 提示
        var hintLabel = new Label
        {
            Text = "流程：选择备份文件 → 输入解密密码 → 选择恢复目标和模式 → 确认恢复；\n" +
                   "选择性还原：点击\"浏览并选择还原...\" → 勾选文件/目录 → 自动按所选恢复",
            Font = Theme.SmallFont,
            ForeColor = Theme.TextTertiary,
            Location = new Point(16, 152),
            Size = new Size(cw - 32, 40),
            BackColor = Color.Transparent
        };
        configCard.Controls.Add(hintLabel);

        y += 210;

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

        // ===== 可恢复备份列表（扫描多个目录） =====
        CreateSectionTitle("可恢复备份列表", 0, y);
        y += 30;

        try
        {
            // 扫描多个目录：默认备份目录 + 桌面 + 用户文档
            var searchDirs = new List<string>();
            var defaultDir = _recoveryModule?.DefaultBackupDirectory ?? "";
            if (!string.IsNullOrEmpty(defaultDir) && Directory.Exists(defaultDir))
                searchDirs.Add(defaultDir);

            var desktop = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
            if (!string.IsNullOrEmpty(desktop) && Directory.Exists(desktop) && !searchDirs.Contains(desktop))
                searchDirs.Add(desktop);

            var documents = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
            if (!string.IsNullOrEmpty(documents) && Directory.Exists(documents) && !searchDirs.Contains(documents))
                searchDirs.Add(documents);

            var backupFiles = new List<string>();
            foreach (var dir in searchDirs)
            {
                try
                {
                    foreach (var f in Directory.EnumerateFiles(dir, "*.lgbackup"))
                    {
                        if (!backupFiles.Contains(f))
                            backupFiles.Add(f);
                    }
                }
                catch { }
            }

            if (backupFiles.Count == 0)
            {
                var empty = new Label
                {
                    Text = "暂无可恢复的加密备份 — 请点击上方\"浏览选择文件...\"手动选择 .lgbackup 文件",
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
                var headers = new[] { "文件名", "位置", "类型", "时间", "大小", "操作" };
                var xPos = new[] { 8, 250, 380, 450, 560, 660 };
                var widths = new[] { 238, 126, 66, 106, 96, 100 };
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
                    var dirName = Path.GetDirectoryName(file) ?? "";
                    var dirDisplay = TruncateText(dirName, 18);
                    var vals = new[]
                    {
                        TruncateText(fileName, 30),
                        dirDisplay,
                        preview != null ? GetBackupTypeName(preview.BackupType) : "-",
                        preview?.BackupTime.ToString("MM-dd HH:mm") ?? "-",
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

                    // 选择此文件按钮（填入文件路径框）
                    var selectBtn = new AccentButton
                    {
                        Text = "选择",
                        Location = new Point(xPos[5], 1),
                        Size = new Size(46, 26)
                    };
                    var filePath = file;
                    selectBtn.Click += () =>
                    {
                        if (_recoveryFileBox != null)
                        {
                            _recoveryFileBox.Text = filePath;
                            // 自动填充恢复目标为备份文件所在目录下的 Restored 子目录
                            if (string.IsNullOrEmpty(_recoveryDestBox?.Text))
                            {
                                var restoreDir = Path.Combine(Path.GetDirectoryName(filePath) ?? "", "Restored");
                                if (_recoveryDestBox != null)
                                    _recoveryDestBox.Text = restoreDir;
                            }
                        }
                    };
                    itemCard.Controls.Add(selectBtn);

                    // 预览按钮
                    var previewBtn = new AccentButton
                    {
                        Text = "预览",
                        Location = new Point(xPos[5] + 50, 1),
                        Size = new Size(46, 26)
                    };
                    var fp = file;
                    previewBtn.Click += () => PreviewBackup(fp);
                    itemCard.Controls.Add(previewBtn);

                    y += 34;
                }
            }
        }
        catch { }

        y += 20;
    }

    /// <summary>浏览选择 .lgbackup 备份文件</summary>
    private void BrowseBackupFile()
    {
        try
        {
            using var dlg = new OpenFileDialog
            {
                Title = "选择加密备份文件",
                Filter = "加密备份文件 (*.lgbackup)|*.lgbackup|所有文件 (*.*)|*.*",
                InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.Desktop)
            };
            if (dlg.ShowDialog() == DialogResult.OK && _recoveryFileBox != null)
            {
                _recoveryFileBox.Text = dlg.FileName;
                // 自动填充恢复目标为备份文件所在目录下的 Restored 子目录
                if (string.IsNullOrEmpty(_recoveryDestBox?.Text) && _recoveryDestBox != null)
                {
                    var restoreDir = Path.Combine(Path.GetDirectoryName(dlg.FileName) ?? "", "Restored");
                    _recoveryDestBox.Text = restoreDir;
                }
            }
        }
        catch { }
    }

    /// <summary>确认恢复 — 从文件选择框获取路径并执行恢复</summary>
    private async void ConfirmRestore()
    {
        var backupPath = _recoveryFileBox?.Text?.Trim();
        if (string.IsNullOrEmpty(backupPath))
        {
            MessageBoxHelper.Warn("请先选择要恢复的 .lgbackup 备份文件。\n可点击\"浏览选择文件...\"或在下方列表中点击\"选择\"。");
            return;
        }
        if (!File.Exists(backupPath))
        {
            MessageBoxHelper.Error($"备份文件不存在：{backupPath}");
            return;
        }

        await StartRestoreAsync(backupPath);
    }

    /// <summary>从列表中直接恢复指定文件</summary>
    private async void StartRestore(string backupPath)
    {
        // 填入文件选择框
        if (_recoveryFileBox != null)
            _recoveryFileBox.Text = backupPath;

        await StartRestoreAsync(backupPath);
    }

    private async Task StartRestoreAsync(string backupPath)
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

    // ==================== 选择性还原（浏览 + 批量恢复） ====================

    /// <summary>格式化字节数显示</summary>
    private static string FormatSize(long bytes) => bytes switch
    {
        >= 1024L * 1024 * 1024 => $"{bytes / 1024.0 / 1024 / 1024:F2} GB",
        >= 1024L * 1024 => $"{bytes / 1024.0 / 1024:F1} MB",
        >= 1024L => $"{bytes / 1024.0:F1} KB",
        _ => $"{bytes} B"
    };

    /// <summary>
    /// 选择性还原完整流程：解密归档 → 浏览勾选 → 预校验 → （覆盖二次确认）→ 批量还原 → 结果汇总。
    /// </summary>
    private async Task StartSelectiveRestoreAsync()
    {
        if (_isBusy || _recoveryModule?.Engine == null) return;

        var backupPath = _recoveryFileBox?.Text?.Trim();
        if (string.IsNullOrEmpty(backupPath))
        {
            MessageBoxHelper.Warn("请先选择要恢复的 .lgbackup 备份文件。\n可点击\"浏览选择文件...\"或在下方列表中点击\"选择\"。");
            return;
        }
        if (!File.Exists(backupPath))
        {
            MessageBoxHelper.Error($"备份文件不存在：{backupPath}");
            return;
        }
        var password = _recoveryPasswordBox?.Text;
        if (string.IsNullOrEmpty(password))
        {
            MessageBoxHelper.Warn("请输入解密密码。");
            return;
        }

        var engine = _recoveryModule.Engine;
        _isBusy = true;
        _recoveryModule.NotifyRecoveryState(RecoveryRunState.Running, $"选择性还原：{Path.GetFileName(backupPath)}");

        try
        {
            // 1. 解密归档并解析文件清单（进度）
            RecoveryArchive? archive = null;
            var loadProgress = new Progress<double>(p => BeginInvoke(() =>
            {
                UpdateProgressBar(_recoveryProgressBar, (int)p);
                if (_recoveryProgressLabel != null)
                {
                    _recoveryProgressLabel.Text = $"正在解密并解析备份清单... {p:F0}%";
                    _recoveryProgressLabel.ForeColor = Theme.Accent;
                }
            }));
            archive = await engine.LoadArchiveEntriesAsync(backupPath, password, loadProgress);

            // 2. 备份内容浏览对话框（目录树 + 文件列表 + 三态勾选）
            using var browser = new BackupBrowserForm(archive, archive.Manifest, backupPath);
            if (browser.ShowDialog(this) != DialogResult.OK)
                return;
            var selected = browser.SelectedRelPaths;
            if (selected.Count == 0)
            {
                MessageBoxHelper.Warn("未勾选任何文件，已取消选择性还原。");
                return;
            }

            // 3. 目标路径与恢复模式
            var destDir = _recoveryDestBox?.Text?.Trim();
            if (string.IsNullOrEmpty(destDir))
            {
                MessageBoxHelper.Warn("请输入恢复目标目录。");
                return;
            }
            var modeIdx = _recoveryModeCombo?.SelectedIndex ?? 0;
            var mode = modeIdx switch
            {
                0 => RecoveryMode.Isolated,
                1 => RecoveryMode.Incremental,
                2 => RecoveryMode.ForceOverwrite,
                _ => RecoveryMode.Isolated
            };

            // 4. 预计算选中大小（目录自动递归展开）
            var (totalSize, fileCount) = engine.CalculateSelectedSize(archive, selected);
            if (totalSize == 0 || fileCount == 0)
            {
                MessageBoxHelper.Warn("所选路径在备份包中未找到任何文件，已取消。");
                return;
            }

            // 5. 强制覆盖模式二次确认（隔离/增量无额外弹窗）
            if (mode == RecoveryMode.ForceOverwrite)
            {
                bool confirm = MessageBoxHelper.Confirm(
                    $"即将以强制覆盖模式还原 {fileCount} 个文件（合计 {FormatSize(totalSize)}）。\n\n" +
                    $"目标路径：{destDir}\n\n覆盖后原文件不可恢复，确认继续？");
                if (!confirm) return;
            }

            // 6. 执行批量选择性还原（进度含速度/剩余时间/文件计数）
            var result = await engine.RecoverSelectedItemsAsync(
                archive, archive.Manifest, selected, destDir, mode,
                new Progress<RecoveryProgressInfo>(OnSelectiveRecoveryProgress));

            // 7. 结果汇总弹窗（成功 / 失败明细）
            if (result.Success)
            {
                UpdateProgressBar(_recoveryProgressBar, 100);
                SetRecoveryUi("选择性还原完成", Theme.Success);
                _recoveryModule.NotifyRecoveryState(RecoveryRunState.Succeeded, result.Message);
                MessageBoxHelper.Info(
                    $"选择性还原成功！\n\n成功：{result.SuccessCount} 个文件\n跳过：{result.SkippedCount} 个\n" +
                    $"大小：{FormatSize(result.TotalBytes)}\n耗时：{result.Elapsed.TotalSeconds:F1}s\n\n{result.Message}");
            }
            else
            {
                SetRecoveryUi("选择性还原完成（有失败项）", Theme.Error);
                _recoveryModule.NotifyRecoveryState(RecoveryRunState.Failed, result.Message);
                var failText = string.Join("\n",
                    result.Failures.Take(20).Select(f => $"  ✗ {f.RelPath}：{f.Error}"));
                if (result.Failures.Count > 20)
                    failText += $"\n  ... 等共 {result.Failures.Count} 项失败";
                MessageBoxHelper.Error(
                    $"选择性还原完成，但有失败项。\n\n成功：{result.SuccessCount} / 失败：{result.FailCount} / 跳过：{result.SkippedCount}\n\n" +
                    $"失败明细：\n{failText}");
            }
        }
        catch (AuthenticationTagMismatchException)
        {
            _recoveryModule.NotifyRecoveryState(RecoveryRunState.Failed, "密钥错误或备份被篡改");
            SetRecoveryUi("解密认证失败", Theme.Error);
            MessageBoxHelper.Error("解密认证失败：密钥错误或备份已被篡改。");
        }
        catch (OperationCanceledException)
        {
            _recoveryModule.NotifyRecoveryState(RecoveryRunState.Failed, "操作已取消");
            MessageBoxHelper.Warn("操作已取消。");
        }
        catch (Exception ex)
        {
            _recoveryModule.NotifyRecoveryState(RecoveryRunState.Failed, ex.Message);
            SetRecoveryUi("选择性还原失败", Theme.Error);
            MessageBoxHelper.Error($"选择性还原失败：{ex.Message}");
        }
        finally
        {
            _isBusy = false;
        }
    }

    /// <summary>选择性还原进度更新（Progress&lt;T&gt; 已自动封送到 UI 线程）</summary>
    private void OnSelectiveRecoveryProgress(RecoveryProgressInfo info)
    {
        if (IsDisposed) return;
        try
        {
            UpdateProgressBar(_recoveryProgressBar, (int)info.Percent);
            if (_recoveryProgressLabel != null)
            {
                _recoveryProgressLabel.Text = $"选择性还原 {info.Percent:F1}% | {info.ProcessedFiles}/{info.TotalFiles} 文件";
                _recoveryProgressLabel.ForeColor = Theme.Accent;
            }
            if (_recoveryProgressDetail != null)
            {
                var speed = $"{FormatSize((long)info.SpeedBytesPerSec)}/s";
                _recoveryProgressDetail.Text =
                    $"{info.CurrentFile} | 速度 {speed} | 剩余 {info.RemainingTime:hh\\:mm\\:ss}";
            }
        }
        catch { }
    }

    /// <summary>设置恢复状态标签文字与颜色</summary>
    private void SetRecoveryUi(string text, Color color)
    {
        if (_recoveryProgressLabel != null)
        {
            _recoveryProgressLabel.Text = text;
            _recoveryProgressLabel.ForeColor = color;
        }
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

    #region 标签页5：企业容灾

    private void BuildEnterpriseTab(int y)
    {
        int cw = ContentWidth;

        // ===== VSS 卷影一致性备份 =====
        CreateSectionTitle("VSS 卷影快照一致性备份", 0, y);
        y += 30;

        var vssCard = CreateCard(0, y, cw, 130);
        var vssDesc = new Label
        {
            Text = "系统原生卷影服务 | 冻结文件瞬时状态 | 数据库/运行中文件/ERP 100% 无损备份",
            Font = Theme.SmallFont,
            ForeColor = Theme.TextTertiary,
            Location = new Point(16, 8),
            Size = new Size(cw - 32, 18),
            BackColor = Color.Transparent
        };
        vssCard.Controls.Add(vssDesc);

        _vssSourceBox = new TextBox
        {
            Location = new Point(100, 30),
            Size = new Size(cw - 280, 24),
            Font = Theme.BodyFont,
            BackColor = Theme.CardBg,
            ForeColor = Theme.TextPrimary,
            BorderStyle = BorderStyle.FixedSingle,
            PlaceholderText = "输入要 VSS 备份的目录路径"
        };
        vssCard.Controls.Add(_vssSourceBox);
        var vssSrcLabel = new Label { Text = "源目录：", Font = Theme.BodyFont, ForeColor = Theme.TextSecondary, Location = new Point(16, 32), Size = new Size(80, 22), BackColor = Color.Transparent };
        vssCard.Controls.Add(vssSrcLabel);

        _vssDestBox = new TextBox
        {
            Location = new Point(100, 58),
            Size = new Size(cw - 280, 24),
            Font = Theme.BodyFont,
            BackColor = Theme.CardBg,
            ForeColor = Theme.TextPrimary,
            BorderStyle = BorderStyle.FixedSingle,
            PlaceholderText = "备份目标目录"
        };
        vssCard.Controls.Add(_vssDestBox);
        var vssDestLabel = new Label { Text = "目标：", Font = Theme.BodyFont, ForeColor = Theme.TextSecondary, Location = new Point(16, 60), Size = new Size(80, 22), BackColor = Color.Transparent };
        vssCard.Controls.Add(vssDestLabel);

        _vssPasswordBox = new TextBox
        {
            Location = new Point(100, 86),
            Size = new Size(cw - 280, 24),
            Font = Theme.BodyFont,
            BackColor = Theme.CardBg,
            ForeColor = Theme.TextPrimary,
            BorderStyle = BorderStyle.FixedSingle,
            UseSystemPasswordChar = true,
            PlaceholderText = "加密口令"
        };
        vssCard.Controls.Add(_vssPasswordBox);
        var vssPwdLabel = new Label { Text = "密码：", Font = Theme.BodyFont, ForeColor = Theme.TextSecondary, Location = new Point(16, 88), Size = new Size(80, 22), BackColor = Color.Transparent };
        vssCard.Controls.Add(vssPwdLabel);

        _vssBackupBtn = new AccentButton { Text = "VSS 备份", Location = new Point(cw - 168, 28), Size = new Size(140, 32) };
        _vssBackupBtn.Click += StartVssBackup;
        vssCard.Controls.Add(_vssBackupBtn);

        _vssProgressBar = CreateProgressBar(vssCard, 100, 92, cw - 280);
        _vssProgressLabel = new Label { Text = "就绪", Font = Theme.SmallFont, ForeColor = Theme.TextTertiary, Location = new Point(100, 112), Size = new Size(cw - 280, 16), BackColor = Color.Transparent };
        vssCard.Controls.Add(_vssProgressLabel);

        y += 140;

        // ===== 防勒索隔离备份池 =====
        CreateSectionTitle("防勒索只读隔离备份池 (ACL 锁定)", 0, y);
        y += 30;

        var poolCard = CreateCard(0, y, cw, 80);
        _poolPathBox = new TextBox
        {
            Location = new Point(100, 10),
            Size = new Size(cw - 280, 24),
            Font = Theme.BodyFont,
            BackColor = Theme.CardBg,
            ForeColor = Theme.TextPrimary,
            BorderStyle = BorderStyle.FixedSingle,
            PlaceholderText = "备份池目录路径（将自动创建并 ACL 锁定）"
        };
        poolCard.Controls.Add(_poolPathBox);
        var poolPathLabel = new Label { Text = "池路径：", Font = Theme.BodyFont, ForeColor = Theme.TextSecondary, Location = new Point(16, 12), Size = new Size(80, 22), BackColor = Color.Transparent };
        poolCard.Controls.Add(poolPathLabel);

        _poolInitBtn = new AccentButton { Text = "初始化池", Location = new Point(cw - 168, 6), Size = new Size(140, 32) };
        _poolInitBtn.Click += InitBackupPool;
        poolCard.Controls.Add(_poolInitBtn);

        _poolLockBtn = new AccentButton { Text = "锁定", Location = new Point(16, 42), Size = new Size(100, 30) };
        _poolLockBtn.Click += LockPool;
        poolCard.Controls.Add(_poolLockBtn);

        _poolUnlockBtn = new AccentButton { Text = "临时解锁", Location = new Point(126, 42), Size = new Size(100, 30) };
        _poolUnlockBtn.Click += UnlockPool;
        poolCard.Controls.Add(_poolUnlockBtn);

        _poolStatusLabel = new Label { Text = "未初始化", Font = Theme.SmallFont, ForeColor = Theme.TextTertiary, Location = new Point(240, 46), Size = new Size(cw - 260, 22), BackColor = Color.Transparent };
        poolCard.Controls.Add(_poolStatusLabel);

        y += 90;

        // ===== 备份健康校验 =====
        CreateSectionTitle("全自动备份健康校验", 0, y);
        y += 30;

        var healthCard = CreateCard(0, y, cw, 60);
        _healthCheckBtn = new AccentButton { Text = "校验全部备份", Location = new Point(16, 10), Size = new Size(160, 32) };
        _healthCheckBtn.Click += RunHealthCheck;
        healthCard.Controls.Add(_healthCheckBtn);

        _healthResultLabel = new Label { Text = "点击按钮校验所有 .lgbackup 文件完整性", Font = Theme.SmallFont, ForeColor = Theme.TextTertiary, Location = new Point(190, 14), Size = new Size(cw - 210, 40), BackColor = Color.Transparent };
        healthCard.Controls.Add(_healthResultLabel);

        y += 70;

        // ===== 断点续备 =====
        CreateSectionTitle("超大文件断点续备", 0, y);
        y += 30;

        var resumeCard = CreateCard(0, y, cw, 80);
        _resumeFileBox = new TextBox
        {
            Location = new Point(100, 10),
            Size = new Size(cw - 280, 24),
            Font = Theme.BodyFont,
            BackColor = Theme.CardBg,
            ForeColor = Theme.TextPrimary,
            BorderStyle = BorderStyle.FixedSingle,
            PlaceholderText = "超大文件路径（支持几十G、上百G镜像）"
        };
        resumeCard.Controls.Add(_resumeFileBox);
        var resumeFileLabel = new Label { Text = "源文件：", Font = Theme.BodyFont, ForeColor = Theme.TextSecondary, Location = new Point(16, 12), Size = new Size(80, 22), BackColor = Color.Transparent };
        resumeCard.Controls.Add(resumeFileLabel);

        _resumeStartBtn = new AccentButton { Text = "开始续备", Location = new Point(cw - 168, 6), Size = new Size(140, 32) };
        _resumeStartBtn.Click += StartResumableBackup;
        resumeCard.Controls.Add(_resumeStartBtn);

        _resumeResumeBtn = new AccentButton { Text = "恢复中断", Location = new Point(16, 42), Size = new Size(100, 30) };
        _resumeResumeBtn.Click += ResumeInterruptedBackup;
        resumeCard.Controls.Add(_resumeResumeBtn);

        _resumeStatusLabel = new Label { Text = "支持网络/断电中断续传", Font = Theme.SmallFont, ForeColor = Theme.TextTertiary, Location = new Point(130, 46), Size = new Size(cw - 150, 22), BackColor = Color.Transparent };
        resumeCard.Controls.Add(_resumeStatusLabel);

        y += 90;

        // ===== 智能过滤引擎 =====
        CreateSectionTitle("智能备份黑白名单过滤", 0, y);
        y += 30;

        var filterCard = CreateCard(0, y, cw, 80);
        var filterDesc = new Label
        {
            Text = "默认过滤：临时文件/缓存/日志/回收站/系统文件 | 支持自定义排除扩展名、目录、模式",
            Font = Theme.SmallFont,
            ForeColor = Theme.TextTertiary,
            Location = new Point(16, 8),
            Size = new Size(cw - 32, 18),
            BackColor = Color.Transparent
        };
        filterCard.Controls.Add(filterDesc);

        _filterExcludesBox = new TextBox
        {
            Location = new Point(100, 30),
            Size = new Size(cw - 280, 24),
            Font = Theme.BodyFont,
            BackColor = Theme.CardBg,
            ForeColor = Theme.TextPrimary,
            BorderStyle = BorderStyle.FixedSingle,
            PlaceholderText = "自定义排除项，逗号分隔（如 .iso,.vmdk,node_modules）"
        };
        filterCard.Controls.Add(_filterExcludesBox);
        var filterLabel = new Label { Text = "排除项：", Font = Theme.BodyFont, ForeColor = Theme.TextSecondary, Location = new Point(16, 32), Size = new Size(80, 22), BackColor = Color.Transparent };
        filterCard.Controls.Add(filterLabel);

        var filterApplyBtn = new AccentButton { Text = "应用过滤", Location = new Point(cw - 168, 26), Size = new Size(140, 32) };
        filterApplyBtn.Click += ApplyFilter;
        filterCard.Controls.Add(filterApplyBtn);

        _filterStatsLabel = new Label { Text = $"规则数：{_filterEngine.Rules.Count} | 已过滤：{_filterEngine.TotalFiltered} 文件", Font = Theme.SmallFont, ForeColor = Theme.TextTertiary, Location = new Point(16, 58), Size = new Size(cw - 32, 18), BackColor = Color.Transparent };
        filterCard.Controls.Add(_filterStatsLabel);

        y += 90;
    }

    private async void StartVssBackup()
    {
        var source = _vssSourceBox?.Text?.Trim();
        var dest = _vssDestBox?.Text?.Trim();
        var password = _vssPasswordBox?.Text;

        if (string.IsNullOrEmpty(source) || string.IsNullOrEmpty(dest) || string.IsNullOrEmpty(password))
        {
            MessageBoxHelper.Warn("请填写源目录、目标目录和加密密码。");
            return;
        }

        _isBusy = true;
        if (_vssBackupBtn != null) _vssBackupBtn.Enabled = false;

        try
        {
            _vssEngine?.Dispose();
            _vssEngine = new VssShadowCopyEngine(AppState);

            if (_vssProgressLabel != null) { _vssProgressLabel.Text = "创建 VSS 卷影快照中..."; _vssProgressLabel.ForeColor = Theme.Accent; }
            UpdateProgressBar(_vssProgressBar, 10);

            BackupManifest? manifest = null;
            await Task.Run(() =>
            {
                manifest = _vssEngine.BackupDirectoryWithVss(source, dest, password, null);
            });

            if (manifest != null)
            {
                UpdateProgressBar(_vssProgressBar, 100);
                if (_vssProgressLabel != null) { _vssProgressLabel.Text = "VSS 备份完成"; _vssProgressLabel.ForeColor = Theme.Success; }
                MessageBoxHelper.Info($"VSS 卷影快照备份成功！\n\n文件数：{manifest.FileCount}\n大小：{manifest.TotalSize / 1024.0:F1} KB\n分片：{manifest.ShardCount}\n算法：{manifest.EncryptedAlgorithm}");
            }
            else
            {
                if (_vssProgressLabel != null) { _vssProgressLabel.Text = "VSS 不可用，请以管理员运行"; _vssProgressLabel.ForeColor = Theme.Warning; }
                MessageBoxHelper.Warn("VSS 卷影快照创建失败。\n请确保以管理员权限运行 LightGuard，且 VSS 服务已启动。");
            }
        }
        catch (Exception ex)
        {
            if (_vssProgressLabel != null) { _vssProgressLabel.Text = "VSS 备份失败"; _vssProgressLabel.ForeColor = Theme.Error; }
            MessageBoxHelper.Error($"VSS 备份失败：{ex.Message}");
        }
        finally
        {
            _isBusy = false;
            if (_vssBackupBtn != null) _vssBackupBtn.Enabled = true;
        }
    }

    private void InitBackupPool()
    {
        var path = _poolPathBox?.Text?.Trim();
        if (string.IsNullOrEmpty(path))
        {
            MessageBoxHelper.Warn("请输入备份池目录路径。");
            return;
        }

        try
        {
            _backupPool?.Dispose();
            _backupPool = new RansomwareProofBackupPool();
            _backupPool.Initialize(path);

            var info = _backupPool.GetPoolInfo();
            if (_poolStatusLabel != null)
            {
                _poolStatusLabel.Text = $"已锁定 | 文件数：{info.FileCount} | 大小：{info.TotalSizeBytes / 1024.0:F1} KB";
                _poolStatusLabel.ForeColor = Theme.Success;
            }
            MessageBoxHelper.Info($"防勒索备份池已初始化并锁定！\n\n路径：{path}\n状态：ACL 已锁定（勒索病毒无法写入/删除/加密）");
        }
        catch (Exception ex)
        {
            MessageBoxHelper.Error($"初始化失败：{ex.Message}");
        }
    }

    private void LockPool()
    {
        if (_backupPool == null) { MessageBoxHelper.Warn("请先初始化备份池。"); return; }
        try
        {
            _backupPool.LockPool();
            var info = _backupPool.GetPoolInfo();
            if (_poolStatusLabel != null) { _poolStatusLabel.Text = $"已锁定 | 文件数：{info.FileCount}"; _poolStatusLabel.ForeColor = Theme.Success; }
            MessageBoxHelper.Info("备份池已锁定。病毒/普通用户/第三方程序无权写入。");
        }
        catch (Exception ex) { MessageBoxHelper.Error($"锁定失败：{ex.Message}"); }
    }

    private void UnlockPool()
    {
        if (_backupPool == null) { MessageBoxHelper.Warn("请先初始化备份池。"); return; }
        try
        {
            using var token = _backupPool.UnlockPoolForWrite();
            if (_poolStatusLabel != null) { _poolStatusLabel.Text = "临时解锁中（写入后自动锁定）"; _poolStatusLabel.ForeColor = Theme.Warning; }
            MessageBoxHelper.Info("备份池已临时解锁。写入完成后将自动重新锁定。");
        }
        catch (Exception ex) { MessageBoxHelper.Error($"解锁失败：{ex.Message}"); }
    }

    private async void RunHealthCheck()
    {
        if (_healthCheckBtn != null) _healthCheckBtn.Enabled = false;
        if (_healthResultLabel != null) { _healthResultLabel.Text = "正在校验所有备份..."; _healthResultLabel.ForeColor = Theme.Accent; }

        try
        {
            var destDir = _encBackupModule?.DestinationDirectory ?? ConfigManager.GetBackupDir();
            BatchHealthReport? report = null;
            await Task.Run(() => report = _healthVerifier.VerifyAllBackups(destDir));

            if (_healthResultLabel != null)
            {
                _healthResultLabel.Text = report?.ToSummary() ?? "校验完成";
                _healthResultLabel.ForeColor = (report?.CorruptedCount > 0) ? Theme.Warning : Theme.Success;
            }
            MessageBoxHelper.Info(report?.ToSummary() ?? "校验完成");
        }
        catch (Exception ex)
        {
            MessageBoxHelper.Error($"健康校验失败：{ex.Message}");
        }
        finally
        {
            if (_healthCheckBtn != null) _healthCheckBtn.Enabled = true;
        }
    }

    private async void StartResumableBackup()
    {
        var file = _resumeFileBox?.Text?.Trim();
        if (string.IsNullOrEmpty(file) || !File.Exists(file))
        {
            MessageBoxHelper.Warn("请输入有效的源文件路径。");
            return;
        }

        var destDir = Path.Combine(ConfigManager.GetBackupDir(), "resumable");
        var password = _backupPasswordBox?.Text ?? _vssPasswordBox?.Text;
        if (string.IsNullOrEmpty(password))
        {
            MessageBoxHelper.Warn("请在加密备份标签页输入密码。");
            return;
        }

        if (_resumeStartBtn != null) _resumeStartBtn.Enabled = false;
        if (_resumeStatusLabel != null) { _resumeStatusLabel.Text = "开始分块加密备份..."; _resumeStatusLabel.ForeColor = Theme.Accent; }

        try
        {
            await Task.Run(() =>
            {
                _resumableEngine.StartResumableBackup(file, password, destDir, 16 * 1024 * 1024, null);
            });
            if (_resumeStatusLabel != null) { _resumeStatusLabel.Text = "断点续备完成！"; _resumeStatusLabel.ForeColor = Theme.Success; }
            MessageBoxHelper.Info("断点续备完成！\n\n分块已加密写入，支持中断后恢复。");
        }
        catch (Exception ex)
        {
            if (_resumeStatusLabel != null) { _resumeStatusLabel.Text = $"续备中断：{ex.Message}"; _resumeStatusLabel.ForeColor = Theme.Warning; }
            MessageBoxHelper.Warn($"续备中断（可点击\"恢复中断\"继续）：\n{ex.Message}");
        }
        finally
        {
            if (_resumeStartBtn != null) _resumeStartBtn.Enabled = true;
        }
    }

    private async void ResumeInterruptedBackup()
    {
        var destDir = Path.Combine(ConfigManager.GetBackupDir(), "resumable");
        var password = _backupPasswordBox?.Text ?? _vssPasswordBox?.Text;

        try
        {
            var sessions = _resumableEngine.ListPendingSessions(destDir);
            if (sessions.Count == 0)
            {
                MessageBoxHelper.Info("没有待恢复的中断备份会话。");
                return;
            }

            var sessionFile = sessions[0];
            if (_resumeStatusLabel != null) { _resumeStatusLabel.Text = "恢复中断备份中..."; _resumeStatusLabel.ForeColor = Theme.Accent; }

            await Task.Run(() =>
            {
                _resumableEngine.ResumeBackup(sessionFile, password ?? "", null);
            });

            if (_resumeStatusLabel != null) { _resumeStatusLabel.Text = "中断备份已恢复完成！"; _resumeStatusLabel.ForeColor = Theme.Success; }
            MessageBoxHelper.Info("中断备份已恢复完成！");
        }
        catch (Exception ex)
        {
            MessageBoxHelper.Error($"恢复失败：{ex.Message}");
        }
    }

    private void ApplyFilter()
    {
        var excludes = _filterExcludesBox?.Text?.Trim();
        if (!string.IsNullOrEmpty(excludes))
        {
            foreach (var item in excludes.Split(',', StringSplitOptions.RemoveEmptyEntries))
            {
                var t = item.Trim();
                if (t.StartsWith(".")) _filterEngine.AddExcludeExtension(t);
                else if (t.Contains('/') || t.Contains('\\') || t.Contains(Path.DirectorySeparatorChar)) _filterEngine.AddExcludeDirectory(t);
                else _filterEngine.AddExcludePattern(t);
            }
        }

        if (_filterStatsLabel != null)
        {
            _filterStatsLabel.Text = $"规则数：{_filterEngine.Rules.Count} | 已过滤：{_filterEngine.TotalFiltered} 文件 | 节省：{_filterEngine.TotalFilteredBytes / 1024.0:F1} KB";
        }
        MessageBoxHelper.Info($"过滤规则已应用！\n\n当前规则数：{_filterEngine.Rules.Count}\n已过滤文件：{_filterEngine.TotalFiltered}\n节省空间：{_filterEngine.TotalFilteredBytes / 1024.0:F1} KB");
    }

    #endregion

    #region 标签页6：快照链与审计

    private void BuildSnapshotAuditTab(int y)
    {
        int cw = ContentWidth;

        // ===== 多版本快照链 =====
        CreateSectionTitle("多版本快照时间链系统 (.lgchain)", 0, y);
        y += 30;

        var chainCard = CreateCard(0, y, cw, 100);
        _chainSourceBox = new TextBox
        {
            Location = new Point(100, 10),
            Size = new Size(cw - 280, 24),
            Font = Theme.BodyFont,
            BackColor = Theme.CardBg,
            ForeColor = Theme.TextPrimary,
            BorderStyle = BorderStyle.FixedSingle,
            PlaceholderText = "源路径（用于创建快照链）"
        };
        chainCard.Controls.Add(_chainSourceBox);
        var chainSrcLabel = new Label { Text = "源路径：", Font = Theme.BodyFont, ForeColor = Theme.TextSecondary, Location = new Point(16, 12), Size = new Size(80, 22), BackColor = Color.Transparent };
        chainCard.Controls.Add(chainSrcLabel);

        _chainDirBox = new TextBox
        {
            Location = new Point(100, 38),
            Size = new Size(cw - 280, 24),
            Font = Theme.BodyFont,
            BackColor = Theme.CardBg,
            ForeColor = Theme.TextPrimary,
            BorderStyle = BorderStyle.FixedSingle,
            PlaceholderText = "快照链存储目录",
            Text = ConfigManager.GetBackupDir()
        };
        chainCard.Controls.Add(_chainDirBox);
        var chainDirLabel = new Label { Text = "链目录：", Font = Theme.BodyFont, ForeColor = Theme.TextSecondary, Location = new Point(16, 40), Size = new Size(80, 22), BackColor = Color.Transparent };
        chainCard.Controls.Add(chainDirLabel);

        _createChainBtn = new AccentButton { Text = "创建快照链", Location = new Point(cw - 168, 6), Size = new Size(140, 32) };
        _createChainBtn.Click += CreateSnapshotChain;
        chainCard.Controls.Add(_createChainBtn);

        var chainListBtn = new AccentButton { Text = "列出快照链", Location = new Point(cw - 168, 38), Size = new Size(140, 32) };
        chainListBtn.Click += ListSnapshotChains;
        chainCard.Controls.Add(chainListBtn);

        _chainListLabel = new Label { Text = "点击\"列出快照链\"查看已有快照链", Font = Theme.SmallFont, ForeColor = Theme.TextTertiary, Location = new Point(16, 70), Size = new Size(cw - 32, 24), BackColor = Color.Transparent };
        chainCard.Controls.Add(_chainListLabel);

        y += 110;

        // ===== 差异审计报告 =====
        CreateSectionTitle("备份差异审计报告", 0, y);
        y += 30;

        var auditCard = CreateCard(0, y, cw, 80);
        var auditDesc = new Label
        {
            Text = "自动对比两次备份差异：新增/删除/修改/重命名 | 批量异动风险检测（勒索预判）| CSV 导出",
            Font = Theme.SmallFont,
            ForeColor = Theme.TextTertiary,
            Location = new Point(16, 8),
            Size = new Size(cw - 32, 18),
            BackColor = Color.Transparent
        };
        auditCard.Controls.Add(auditDesc);

        _auditCompareBtn = new AccentButton { Text = "生成差异报告", Location = new Point(16, 32), Size = new Size(160, 32) };
        _auditCompareBtn.Click += GenerateAuditReport;
        auditCard.Controls.Add(_auditCompareBtn);

        _auditResultLabel = new Label { Text = "选择备份目录后点击生成报告", Font = Theme.SmallFont, ForeColor = Theme.TextTertiary, Location = new Point(190, 36), Size = new Size(cw - 210, 40), BackColor = Color.Transparent };
        auditCard.Controls.Add(_auditResultLabel);

        y += 90;

        // ===== 备份防删除权限锁 =====
        CreateSectionTitle("备份防删除权限锁（三层安全）", 0, y);
        y += 30;

        var lockCard = CreateCard(0, y, cw, 80);
        _lockFileBox = new TextBox
        {
            Location = new Point(100, 10),
            Size = new Size(cw - 280, 24),
            Font = Theme.BodyFont,
            BackColor = Theme.CardBg,
            ForeColor = Theme.TextPrimary,
            BorderStyle = BorderStyle.FixedSingle,
            PlaceholderText = "要锁定的 .lgbackup 文件路径"
        };
        lockCard.Controls.Add(_lockFileBox);
        var lockFileLabel = new Label { Text = "文件：", Font = Theme.BodyFont, ForeColor = Theme.TextSecondary, Location = new Point(16, 12), Size = new Size(80, 22), BackColor = Color.Transparent };
        lockCard.Controls.Add(lockFileLabel);

        _lockBtn = new AccentButton { Text = "三层锁定", Location = new Point(cw - 168, 6), Size = new Size(140, 32) };
        _lockBtn.Click += LockBackupFile;
        lockCard.Controls.Add(_lockBtn);

        _unlockBtn = new AccentButton { Text = "解锁", Location = new Point(16, 42), Size = new Size(100, 30) };
        _unlockBtn.Click += UnlockBackupFile;
        lockCard.Controls.Add(_unlockBtn);

        _lockStatusLabel = new Label { Text = "ACL + 只读属性 + 锁定标记 = 三层防护", Font = Theme.SmallFont, ForeColor = Theme.TextTertiary, Location = new Point(130, 46), Size = new Size(cw - 150, 22), BackColor = Color.Transparent };
        lockCard.Controls.Add(_lockStatusLabel);

        y += 90;

        // ===== 智能节流错峰备份 =====
        CreateSectionTitle("智能节流错峰备份策略", 0, y);
        y += 30;

        var throttleCard = CreateCard(0, y, cw, 100);
        var throttleDesc = new Label
        {
            Text = "空闲全速 | 前台降速 | 夜间高速 | 不卡顿办公、不影响服务器业务",
            Font = Theme.SmallFont,
            ForeColor = Theme.TextTertiary,
            Location = new Point(16, 8),
            Size = new Size(cw - 32, 18),
            BackColor = Color.Transparent
        };
        throttleCard.Controls.Add(throttleDesc);

        var modeLabel = new Label { Text = "节流模式：", Font = Theme.BodyFont, ForeColor = Theme.TextSecondary, Location = new Point(16, 32), Size = new Size(80, 22), BackColor = Color.Transparent };
        throttleCard.Controls.Add(modeLabel);

        _throttleModeCombo = new ComboBox
        {
            Location = new Point(100, 30),
            Size = new Size(180, 24),
            FlatStyle = FlatStyle.Flat,
            Font = Theme.BodyFont,
            DropDownStyle = ComboBoxStyle.DropDownList
        };
        _throttleModeCombo.Items.AddRange(new object[] { "全速备份（空闲）", "降速备份（前台）", "夜间高速（22:00-06:00）", "自定义" });
        _throttleModeCombo.SelectedIndex = 2;
        throttleCard.Controls.Add(_throttleModeCombo);

        var ioLabel = new Label { Text = "IO上限(MB/s)：", Font = Theme.BodyFont, ForeColor = Theme.TextSecondary, Location = new Point(300, 32), Size = new Size(100, 22), BackColor = Color.Transparent };
        throttleCard.Controls.Add(ioLabel);

        _throttleIoNum = new NumericUpDown
        {
            Location = new Point(404, 30),
            Size = new Size(80, 24),
            Minimum = 1,
            Maximum = 1000,
            Value = 50,
            Font = Theme.BodyFont
        };
        throttleCard.Controls.Add(_throttleIoNum);

        _throttleApplyBtn = new AccentButton { Text = "应用策略", Location = new Point(cw - 168, 26), Size = new Size(140, 32) };
        _throttleApplyBtn.Click += ApplyThrottle;
        throttleCard.Controls.Add(_throttleApplyBtn);

        _throttleStatusLabel = new Label { Text = "当前模式：夜间高速 | IO上限：50 MB/s", Font = Theme.SmallFont, ForeColor = Theme.TextTertiary, Location = new Point(16, 68), Size = new Size(cw - 32, 22), BackColor = Color.Transparent };
        throttleCard.Controls.Add(_throttleStatusLabel);

        y += 110;
    }

    private void CreateSnapshotChain()
    {
        var source = _chainSourceBox?.Text?.Trim();
        var chainDir = _chainDirBox?.Text?.Trim();
        if (string.IsNullOrEmpty(source) || string.IsNullOrEmpty(chainDir))
        {
            MessageBoxHelper.Warn("请填写源路径和快照链存储目录。");
            return;
        }

        try
        {
            var chain = _chainManager.CreateChain(source, chainDir);
            if (_chainListLabel != null)
            {
                _chainListLabel.Text = $"快照链已创建 | ID：{chain.ChainId[..8]} | 节点数：{chain.NodeCount}";
                _chainListLabel.ForeColor = Theme.Success;
            }
            MessageBoxHelper.Info($"快照链创建成功！\n\n链 ID：{chain.ChainId}\n源路径：{chain.SourcePath}\n后续备份可自动追加到此链。");
        }
        catch (Exception ex)
        {
            MessageBoxHelper.Error($"创建快照链失败：{ex.Message}");
        }
    }

    private void ListSnapshotChains()
    {
        try
        {
            var chainDir = _chainDirBox?.Text?.Trim() ?? ConfigManager.GetBackupDir();
            var chains = _chainManager.ListChains(chainDir);

            if (chains.Count == 0)
            {
                if (_chainListLabel != null) _chainListLabel.Text = "暂无快照链记录";
                MessageBoxHelper.Info("暂无快照链记录。");
                return;
            }

            var sb = new System.Text.StringBuilder();
            sb.AppendLine($"共 {chains.Count} 条快照链：\n");
            foreach (var c in chains)
            {
                sb.AppendLine($"链ID：{c.ChainId[..8]}... | 源：{c.SourcePath} | 节点：{c.NodeCount} | 总大小：{c.TotalSizeBytes / 1024.0:F1} KB | 创建：{c.CreatedAt:MM-dd HH:mm}");
            }

            if (_chainListLabel != null)
            {
                _chainListLabel.Text = $"共 {chains.Count} 条快照链 | 总节点：{chains.Sum(c => c.NodeCount)}";
                _chainListLabel.ForeColor = Theme.Success;
            }
            MessageBoxHelper.Info(sb.ToString());
        }
        catch (Exception ex)
        {
            MessageBoxHelper.Error($"列出快照链失败：{ex.Message}");
        }
    }

    private async void GenerateAuditReport()
    {
        if (_auditCompareBtn != null) _auditCompareBtn.Enabled = false;
        if (_auditResultLabel != null) { _auditResultLabel.Text = "正在生成差异审计报告..."; _auditResultLabel.ForeColor = Theme.Accent; }

        try
        {
            var destDir = _encBackupModule?.DestinationDirectory ?? ConfigManager.GetBackupDir();
            string? summary = null;
            await Task.Run(() =>
            {
                var report = _healthVerifier.GenerateHealthReport(destDir);
                summary = report;
            });

            if (_auditResultLabel != null)
            {
                _auditResultLabel.Text = summary ?? "报告已生成";
                _auditResultLabel.ForeColor = Theme.Success;
            }
            MessageBoxHelper.Info($"差异审计报告\n\n{summary}");
        }
        catch (Exception ex)
        {
            MessageBoxHelper.Error($"生成报告失败：{ex.Message}");
        }
        finally
        {
            if (_auditCompareBtn != null) _auditCompareBtn.Enabled = true;
        }
    }

    private void LockBackupFile()
    {
        var file = _lockFileBox?.Text?.Trim();
        if (string.IsNullOrEmpty(file) || !File.Exists(file))
        {
            MessageBoxHelper.Warn("请输入有效的 .lgbackup 文件路径。");
            return;
        }

        try
        {
            _permissionLock.LockBackupFile(file);
            var status = _permissionLock.GetLockStatus(file);
            if (_lockStatusLabel != null)
            {
                _lockStatusLabel.Text = $"ACL：{(status.AclLocked ? "已锁" : "未锁")} | 属性：{(status.AttributeLocked ? "只读" : "可写")} | 标记：{(status.MarkerLocked ? "已标记" : "无")}";
                _lockStatusLabel.ForeColor = Theme.Success;
            }
            MessageBoxHelper.Info("三层防删除权限锁已应用！\n\n第一层：NTFS ACL 权限锁\n第二层：只读+隐藏属性\n第三层：锁定标记文件");
        }
        catch (Exception ex)
        {
            MessageBoxHelper.Error($"锁定失败：{ex.Message}");
        }
    }

    private void UnlockBackupFile()
    {
        var file = _lockFileBox?.Text?.Trim();
        if (string.IsNullOrEmpty(file))
        {
            MessageBoxHelper.Warn("请输入文件路径。");
            return;
        }

        try
        {
            _permissionLock.UnlockBackupFile(file);
            if (_lockStatusLabel != null)
            {
                _lockStatusLabel.Text = "已解除三层锁定";
                _lockStatusLabel.ForeColor = Theme.TextSecondary;
            }
            MessageBoxHelper.Info("已解除三层防删除锁定。");
        }
        catch (Exception ex)
        {
            MessageBoxHelper.Error($"解锁失败：{ex.Message}");
        }
    }

    private void ApplyThrottle()
    {
        var modeIdx = _throttleModeCombo?.SelectedIndex ?? 2;
        var maxIo = (int)(_throttleIoNum?.Value ?? 50);

        var mode = modeIdx switch
        {
            0 => ThrottleMode.FullSpeed,
            1 => ThrottleMode.ReducedSpeed,
            2 => ThrottleMode.NightBoost,
            3 => ThrottleMode.Custom,
            _ => ThrottleMode.NightBoost
        };

        var config = new ThrottleConfig
        {
            Mode = mode,
            MaxIoMBps = maxIo,
            MaxNetworkMBps = Math.Max(10, maxIo / 2),
            NightStart = TimeSpan.FromHours(22),
            NightEnd = TimeSpan.FromHours(6),
            PauseOnForeground = mode == ThrottleMode.ReducedSpeed,
            PauseOnFullscreen = true
        };

        _throttleEngine?.Dispose();
        _throttleEngine = new BackupThrottleEngine(config);
        _throttleEngine.StartMonitoring();

        var modeText = mode switch
        {
            ThrottleMode.FullSpeed => "全速备份",
            ThrottleMode.ReducedSpeed => "降速备份",
            ThrottleMode.NightBoost => "夜间高速",
            ThrottleMode.Custom => "自定义",
            _ => "未知"
        };

        if (_throttleStatusLabel != null)
        {
            _throttleStatusLabel.Text = $"当前模式：{modeText} | IO上限：{maxIo} MB/s | 网络上限：{config.MaxNetworkMBps} MB/s";
            _throttleStatusLabel.ForeColor = Theme.Success;
        }
        MessageBoxHelper.Info($"节流策略已应用！\n\n模式：{modeText}\nIO上限：{maxIo} MB/s\n网络上限：{config.MaxNetworkMBps} MB/s\n前台暂停：{config.PauseOnForeground}\n全屏暂停：{config.PauseOnFullscreen}");
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
