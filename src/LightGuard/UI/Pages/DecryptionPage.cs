using System.ComponentModel;
using LightGuard.Core;
using LightGuard.Decryption;
using LightGuard.Modules;
using LightGuard.UI.Controls;

namespace LightGuard.UI.Pages;

/// <summary>
/// 勒索解密页面（P0-1）
/// 提供应急解密、工具库管理、解密历史三大功能标签页
/// </summary>
public class DecryptionPage : Page
{
    private RansomwareDecryptionModule? _module;
    private RansomwareDecryptor? _decryptor;
    private DecryptionToolManager? _toolManager;

    // 标签页状态
    private int _currentTab;
    private readonly string[] _tabNames = { "应急解密", "工具库", "解密历史" };

    // 应急解密页控件
    private string _selectedPath = "";
    private bool _isFolderMode;
    private RansomwareFamily _detectedFamily = RansomwareFamily.Unknown;
    private RansomwareFamilyInfo? _detectedFamilyInfo;
    private Label? _pathLabel;
    private Label? _familyNameLabel;
    private Label? _familyDescLabel;
    private Label? _familyExtLabel;
    private Label? _familyDecryptorLabel;
    private AccentButton? _decryptBtn;
    private ProgressBar? _progressBar;
    private Label? _progressLabel;
    private Label? _resultLabel;
    private CancellationTokenSource? _cts;
    private bool _isDecrypting;

    // 工具库页控件
    private ListView? _toolListView;
    private AccentButton? _downloadBtn;
    private AccentButton? _updateIndexBtn;
    private AccentButton? _verifyBtn;

    // 历史页控件
    private ListView? _historyListView;

    public DecryptionPage(AppState appState) : base(appState, "勒索解密", "自动识别勒索家族 · 匹配官方解密工具")
    {
    }

    public override void OnShown()
    {
        _module = AppState.Modules.GetModule("ransomware-decrypt") as RansomwareDecryptionModule;
        _decryptor = _module?.Decryptor;
        _toolManager = _module?.ToolManager;

        // 订阅解密进度事件
        if (_decryptor != null)
        {
            _decryptor.ProgressChanged -= OnDecryptionProgress;
            _decryptor.ProgressChanged += OnDecryptionProgress;
        }

        _currentTab = 0;
        BuildContent();
    }

    /// <summary>构建页面内容（标签栏 + 当前标签内容）</summary>
    private void BuildContent()
    {
        ScrollContent.Controls.Clear();
        int y = 0;

        // ===== 标签栏 =====
        var tabCard = CreateCard(0, y, ContentWidth, 44);
        int tabX = 8;
        for (int i = 0; i < _tabNames.Length; i++)
        {
            var tabBtn = new Label
            {
                Text = _tabNames[i],
                Font = i == _currentTab ? Theme.HeaderFont : Theme.BodyFont,
                ForeColor = i == _currentTab ? Theme.Accent : Theme.TextSecondary,
                Location = new Point(tabX, 8),
                Size = new Size(120, 28),
                BackColor = Color.Transparent,
                Cursor = Cursors.Hand,
                TextAlign = ContentAlignment.MiddleCenter
            };
            int capturedIndex = i;
            tabBtn.Click += (s, e) =>
            {
                _currentTab = capturedIndex;
                BuildContent();
            };

            // 激活标签下方画一条线（用分隔线 Label 模拟）
            if (i == _currentTab)
            {
                var underline = new Label
                {
                    BackColor = Theme.Accent,
                    Location = new Point(tabX + 30, 36),
                    Size = new Size(60, 2)
                };
                tabCard.Controls.Add(underline);
            }

            tabCard.Controls.Add(tabBtn);
            tabX += 130;
        }
        y += 54;

        // ===== 标签内容 =====
        switch (_currentTab)
        {
            case 0:
                BuildEmergencyDecryptTab(y);
                break;
            case 1:
                BuildToolLibraryTab(y);
                break;
            case 2:
                BuildHistoryTab(y);
                break;
        }
    }

    #region 标签页一：应急解密

    private void BuildEmergencyDecryptTab(int y)
    {
        // ===== 文件/目录选择区 =====
        CreateSectionTitle("选择加密文件或目录", 0, y);
        y += 30;

        var selectCard = CreateCard(0, y, ContentWidth, 70);

        var fileBtn = new AccentButton
        {
            Text = "选择文件",
            Location = new Point(16, 12),
            Size = new Size(110, 36)
        };
        fileBtn.Click += () =>
        {
            using var dialog = new OpenFileDialog
            {
                Title = "选择加密文件",
                Filter = "所有文件|*.*"
            };
            if (dialog.ShowDialog() == DialogResult.OK)
            {
                _selectedPath = dialog.FileName;
                _isFolderMode = false;
                _detectedFamily = RansomwareFamily.Unknown;
                _detectedFamilyInfo = null;
                BuildContent();
            }
        };
        selectCard.Controls.Add(fileBtn);

        var folderBtn = new AccentButton
        {
            Text = "选择目录",
            Location = new Point(136, 12),
            Size = new Size(110, 36)
        };
        folderBtn.Click += () =>
        {
            using var dialog = new FolderBrowserDialog
            {
                Description = "选择包含加密文件的目录",
                ShowNewFolderButton = false
            };
            if (dialog.ShowDialog() == DialogResult.OK)
            {
                _selectedPath = dialog.SelectedPath;
                _isFolderMode = true;
                _detectedFamily = RansomwareFamily.Unknown;
                _detectedFamilyInfo = null;
                BuildContent();
            }
        };
        selectCard.Controls.Add(folderBtn);

        _pathLabel = new Label
        {
            Text = string.IsNullOrEmpty(_selectedPath)
                ? "尚未选择文件或目录"
                : (_isFolderMode ? "目录: " : "文件: ") + _selectedPath,
            Font = Theme.SmallFont,
            ForeColor = string.IsNullOrEmpty(_selectedPath) ? Theme.TextTertiary : Theme.TextPrimary,
            Location = new Point(16, 50),
            Size = new Size(ContentWidth - 32, 16),
            BackColor = Color.Transparent
        };
        selectCard.Controls.Add(_pathLabel);

        y += 80;

        // ===== 家族检测区 =====
        CreateSectionTitle("勒索家族检测", 0, y);
        y += 30;

        var detectCard = CreateCard(0, y, ContentWidth, 60);

        var detectBtn = new AccentButton
        {
            Text = "检测勒索家族",
            Location = new Point(16, 12),
            Size = new Size(140, 36)
        };
        detectBtn.Enabled = !string.IsNullOrEmpty(_selectedPath);
        detectBtn.Click += () => DetectFamily();
        detectCard.Controls.Add(detectBtn);

        var detectHint = new Label
        {
            Text = "点击自动分析文件扩展名、文件头特征和勒索说明文件",
            Font = Theme.SmallFont,
            ForeColor = Theme.TextTertiary,
            Location = new Point(166, 18),
            Size = new Size(400, 20),
            BackColor = Color.Transparent
        };
        detectCard.Controls.Add(detectHint);

        y += 70;

        // ===== 家族信息面板 =====
        if (_detectedFamily != RansomwareFamily.Unknown || _detectedFamily == RansomwareFamily.Unknown && !string.IsNullOrEmpty(_selectedPath))
        {
            CreateSectionTitle("家族信息", 0, y);
            y += 30;

            var infoCard = CreateCard(0, y, ContentWidth, 110);

            _familyNameLabel = new Label
            {
                Text = _detectedFamily == RansomwareFamily.Unknown
                    ? (string.IsNullOrEmpty(_selectedPath) ? "请先选择文件" : "尚未检测，点击上方按钮")
                    : $"家族: {_detectedFamilyInfo?.Name ?? _detectedFamily.ToString()}",
                Font = Theme.HeaderFont,
                ForeColor = _detectedFamily == RansomwareFamily.Unknown ? Theme.TextTertiary : Theme.Accent,
                Location = new Point(16, 10),
                Size = new Size(ContentWidth - 32, 22),
                BackColor = Color.Transparent
            };
            infoCard.Controls.Add(_familyNameLabel);

            _familyDescLabel = new Label
            {
                Text = _detectedFamilyInfo?.Description ?? "暂无描述",
                Font = Theme.SmallFont,
                ForeColor = Theme.TextSecondary,
                Location = new Point(16, 34),
                Size = new Size(ContentWidth - 32, 32),
                BackColor = Color.Transparent
            };
            infoCard.Controls.Add(_familyDescLabel);

            _familyExtLabel = new Label
            {
                Text = $"加密后缀: {_detectedFamilyInfo?.Extension ?? "未知"}",
                Font = Theme.SmallFont,
                ForeColor = Theme.Warning,
                Location = new Point(16, 68),
                Size = new Size(200, 18),
                BackColor = Color.Transparent
            };
            infoCard.Controls.Add(_familyExtLabel);

            _familyDecryptorLabel = new Label
            {
                Text = _detectedFamilyInfo == null
                    ? "解密器: 未知"
                    : (_detectedFamilyInfo.HasDecryptor
                        ? "解密器: 可用"
                        : "解密器: 暂无"),
                Font = Theme.SmallFont,
                ForeColor = _detectedFamilyInfo?.HasDecryptor == true ? Theme.Success : Theme.Error,
                Location = new Point(230, 68),
                Size = new Size(200, 18),
                BackColor = Color.Transparent
            };
            infoCard.Controls.Add(_familyDecryptorLabel);

            y += 120;
        }

        // ===== 解密操作区 =====
        CreateSectionTitle("解密操作", 0, y);
        y += 30;

        var actionCard = CreateCard(0, y, ContentWidth, 100);

        _decryptBtn = new AccentButton
        {
            Text = "开始解密",
            Location = new Point(16, 12),
            Size = new Size(120, 36)
        };
        _decryptBtn.Enabled = _detectedFamilyInfo?.HasDecryptor == true && !_isDecrypting;
        _decryptBtn.Click += () => StartDecryption();
        actionCard.Controls.Add(_decryptBtn);

        var cancelBtn = new AccentButton
        {
            Text = "取消",
            Location = new Point(146, 12),
            Size = new Size(100, 36)
        };
        cancelBtn.Enabled = _isDecrypting;
        cancelBtn.Click += () => CancelDecryption();
        actionCard.Controls.Add(cancelBtn);

        // 备份后解密复选框
        var backupCheckbox = new CheckBox
        {
            Text = "备份后解密（推荐）",
            Font = Theme.BodyFont,
            ForeColor = Theme.TextSecondary,
            Location = new Point(260, 16),
            Size = new Size(160, 28),
            Checked = true,
            FlatStyle = FlatStyle.Flat,
            BackColor = Color.Transparent
        };
        actionCard.Controls.Add(backupCheckbox);

        // 进度条
        _progressBar = new ProgressBar
        {
            Location = new Point(16, 54),
            Size = new Size(ContentWidth - 32, 16),
            Minimum = 0,
            Maximum = 100,
            Value = 0,
            Style = ProgressBarStyle.Continuous
        };
        actionCard.Controls.Add(_progressBar);

        _progressLabel = new Label
        {
            Text = _isDecrypting ? "正在解密..." : "就绪",
            Font = Theme.SmallFont,
            ForeColor = _isDecrypting ? Theme.Warning : Theme.TextTertiary,
            Location = new Point(16, 74),
            Size = new Size(ContentWidth - 32, 18),
            BackColor = Color.Transparent
        };
        actionCard.Controls.Add(_progressLabel);

        y += 110;

        // ===== 结果区 =====
        CreateSectionTitle("解密结果", 0, y);
        y += 30;

        var resultCard = CreateCard(0, y, ContentWidth, 50);
        _resultLabel = new Label
        {
            Text = "尚未执行解密",
            Font = Theme.BodyFont,
            ForeColor = Theme.TextTertiary,
            Location = new Point(16, 14),
            Size = new Size(ContentWidth - 32, 22),
            BackColor = Color.Transparent
        };
        resultCard.Controls.Add(_resultLabel);
        y += 70;

        y += 20;
    }

    /// <summary>检测勒索家族</summary>
    private void DetectFamily()
    {
        if (string.IsNullOrEmpty(_selectedPath) || _decryptor == null) return;

        var detector = _decryptor.GetDetector();

        if (_isFolderMode)
        {
            // 目录模式：从目录中查找第一个可识别的文件
            _detectedFamily = detector.DetectFamilyByRansomNote(_selectedPath);
            if (_detectedFamily == RansomwareFamily.Unknown)
            {
                // 尝试遍历文件
                try
                {
                    foreach (var file in Directory.EnumerateFiles(_selectedPath, "*.*", SearchOption.TopDirectoryOnly))
                    {
                        var family = detector.DetectFamily(file);
                        if (family != RansomwareFamily.Unknown)
                        {
                            _detectedFamily = family;
                            break;
                        }
                    }
                }
                catch { }
            }
        }
        else
        {
            _detectedFamily = detector.DetectFamily(_selectedPath);
        }

        _detectedFamilyInfo = _detectedFamily != RansomwareFamily.Unknown
            ? detector.GetFamilyInfo(_detectedFamily)
            : null;

        if (_detectedFamily == RansomwareFamily.Unknown)
        {
            MessageBoxHelper.Warn("未能识别该文件/目录的勒索家族。可能是未知变种或文件未被加密。");
        }
        else
        {
            MessageBoxHelper.Info($"检测到勒索家族: {_detectedFamilyInfo?.Name ?? _detectedFamily.ToString()}\n\n" +
                                  $"{_detectedFamilyInfo?.Description}\n\n" +
                                  $"加密后缀: {_detectedFamilyInfo?.Extension}\n" +
                                  $"解密器: {(_detectedFamilyInfo?.HasDecryptor == true ? "可用" : "暂无")}");
        }

        BuildContent();
    }

    /// <summary>开始解密</summary>
    private async void StartDecryption()
    {
        if (_decryptor == null || string.IsNullOrEmpty(_selectedPath)) return;
        if (_detectedFamilyInfo?.HasDecryptor != true) return;

        _isDecrypting = true;
        _cts = new CancellationTokenSource();

        if (_decryptBtn != null) _decryptBtn.Enabled = false;
        if (_progressBar != null) _progressBar.Value = 0;
        if (_progressLabel != null)
        {
            _progressLabel.Text = "正在准备解密...";
            _progressLabel.ForeColor = Theme.Warning;
        }
        if (_resultLabel != null)
        {
            _resultLabel.Text = "解密进行中...";
            _resultLabel.ForeColor = Theme.Warning;
        }

        DecryptionResult result;
        if (_isFolderMode)
        {
            result = await _decryptor.DecryptDirectoryAsync(_selectedPath, _cts.Token);
        }
        else
        {
            result = await _decryptor.DecryptFileAsync(_selectedPath, _cts.Token);
        }

        _isDecrypting = false;
        if (_decryptBtn != null) _decryptBtn.Enabled = true;

        // 显示结果
        if (_resultLabel != null)
        {
            _resultLabel.Text = $"解密完成 | 成功: {result.DecryptedFiles} | 失败: {result.FailedFiles} | " +
                                $"跳过: {result.SkippedFiles} | 耗时: {result.Duration.TotalSeconds:F1}s";
            _resultLabel.ForeColor = result.Success ? Theme.Success : (result.DecryptedFiles > 0 ? Theme.Warning : Theme.Error);
        }

        if (_progressBar != null) _progressBar.Value = 100;
        if (_progressLabel != null)
        {
            _progressLabel.Text = "解密完成";
            _progressLabel.ForeColor = Theme.Success;
        }

        // 弹窗提示
        if (result.Success && result.FailedFiles == 0)
        {
            MessageBoxHelper.Info($"解密成功！共解密 {result.DecryptedFiles} 个文件。\n" +
                                  $"备份位置: {result.BackupPath}");
        }
        else if (result.DecryptedFiles > 0)
        {
            MessageBoxHelper.Warn($"部分解密成功。成功 {result.DecryptedFiles} 个，失败 {result.FailedFiles} 个。\n" +
                                  (string.IsNullOrEmpty(result.ErrorMessage) ? "" : $"错误: {result.ErrorMessage}"));
        }
        else
        {
            MessageBoxHelper.Error($"解密失败。{result.ErrorMessage}\n" +
                                   $"失败原因: {GetFailureReasonText(result.FailureReason)}");
        }
    }

    /// <summary>取消解密</summary>
    private void CancelDecryption()
    {
        _cts?.Cancel();
        if (_progressLabel != null)
        {
            _progressLabel.Text = "正在取消...";
            _progressLabel.ForeColor = Theme.Warning;
        }
    }

    /// <summary>解密进度回调</summary>
    private void OnDecryptionProgress(DecryptionProgress progress)
    {
        // 在 UI 线程更新
        if (IsDisposed || !IsHandleCreated) return;

        try
        {
            Invoke(() =>
            {
                if (_progressBar != null)
                {
                    _progressBar.Value = Math.Min((int)Math.Round(progress.PercentComplete), 100);
                }
                if (_progressLabel != null)
                {
                    _progressLabel.Text = progress.IsRunning
                        ? $"[{progress.FilesProcessed}/{progress.TotalFiles}] {Path.GetFileName(progress.CurrentFile)} | " +
                          $"已解密 {progress.DecryptedCount} | 失败 {progress.FailedCount}"
                        : "就绪";
                    _progressLabel.ForeColor = progress.IsRunning ? Theme.Warning : Theme.TextSecondary;
                }
            });
        }
        catch { }
    }

    /// <summary>获取失败原因中文描述</summary>
    private static string GetFailureReasonText(DecryptionFailureReason reason) => reason switch
    {
        DecryptionFailureReason.UnknownFamily => "未知家族",
        DecryptionFailureReason.NoDecryptorAvailable => "无可用解密器",
        DecryptionFailureReason.ToolDownloadFailed => "工具下载失败",
        DecryptionFailureReason.HashMismatch => "工具哈希校验不匹配",
        DecryptionFailureReason.ToolExecutionFailed => "工具执行失败",
        DecryptionFailureReason.FileAccessDenied => "文件访问被拒绝",
        DecryptionFailureReason.InsufficientDiskSpace => "磁盘空间不足",
        DecryptionFailureReason.BackupFailed => "备份失败",
        DecryptionFailureReason.AlreadyDecrypted => "文件已被解密",
        _ => "未知原因"
    };

    #endregion

    #region 标签页二：工具库

    private void BuildToolLibraryTab(int y)
    {
        // ===== 操作按钮区 =====
        CreateSectionTitle("工具库管理", 0, y);
        y += 30;

        var actionCard = CreateCard(0, y, ContentWidth, 56);

        _downloadBtn = new AccentButton
        {
            Text = "下载工具",
            Location = new Point(16, 10),
            Size = new Size(120, 36)
        };
        _downloadBtn.Click += () => DownloadSelectedTool();
        actionCard.Controls.Add(_downloadBtn);

        _verifyBtn = new AccentButton
        {
            Text = "校验工具",
            Location = new Point(146, 10),
            Size = new Size(120, 36)
        };
        _verifyBtn.Click += () => VerifySelectedTool();
        actionCard.Controls.Add(_verifyBtn);

        _updateIndexBtn = new AccentButton
        {
            Text = "更新索引",
            Location = new Point(276, 10),
            Size = new Size(120, 36)
        };
        _updateIndexBtn.Click += async () =>
        {
            if (_toolManager == null) return;
            _updateIndexBtn.Enabled = false;
            MessageBoxHelper.Info("正在从服务器更新工具索引...");
            await _toolManager.UpdateToolIndexAsync();
            _module?.RefreshIndex();
            _updateIndexBtn.Enabled = true;
            MessageBoxHelper.Info("工具索引更新完成。");
            BuildContent();
        };
        actionCard.Controls.Add(_updateIndexBtn);

        y += 66;

        // ===== 家族列表 =====
        CreateSectionTitle("已知勒索家族", 0, y);
        y += 30;

        var listCard = CreateCard(0, y, ContentWidth, 360);

        _toolListView = new ListView
        {
            Location = new Point(8, 8),
            Size = new Size(ContentWidth - 16, 344),
            View = View.Details,
            FullRowSelect = true,
            GridLines = true,
            Font = Theme.SmallFont,
            BackColor = Theme.CardBg,
            ForeColor = Theme.TextPrimary,
            BorderStyle = BorderStyle.None
        };

        _toolListView.Columns.Add("家族名称", 140);
        _toolListView.Columns.Add("加密后缀", 100);
        _toolListView.Columns.Add("解密工具", 120);
        _toolListView.Columns.Add("工具大小", 100);
        _toolListView.Columns.Add("已下载", 80);

        LoadToolLibraryData();
        listCard.Controls.Add(_toolListView);

        y += 370;
        y += 20;
    }

    /// <summary>加载工具库数据</summary>
    private void LoadToolLibraryData()
    {
        if (_toolListView == null) return;
        _toolListView.Items.Clear();

        var families = _module?.GetKnownFamilies() ?? new List<RansomwareFamilyInfo>();
        foreach (var family in families)
        {
            var item = new ListViewItem(family.Name);
            item.SubItems.Add(family.Extension);
            item.SubItems.Add(family.HasDecryptor ? "有" : "无");

            var size = _toolManager?.GetToolSize(family.Family) ?? 0;
            item.SubItems.Add(size > 0 ? FormatSize(size) : "-");

            var downloaded = family.HasDecryptor && (_toolManager?.IsToolAvailable(family.Family) ?? false);
            item.SubItems.Add(downloaded ? "是" : "否");

            item.ForeColor = family.HasDecryptor ? Theme.Success : Theme.TextSecondary;
            item.Tag = family;

            _toolListView.Items.Add(item);
        }
    }

    /// <summary>下载选中的工具</summary>
    private async void DownloadSelectedTool()
    {
        if (_toolListView == null || _toolListView.SelectedItems.Count == 0 || _toolManager == null)
        {
            MessageBoxHelper.Warn("请先选择一个家族。");
            return;
        }

        var family = _toolListView.SelectedItems[0].Tag as RansomwareFamilyInfo;
        if (family == null || !family.HasDecryptor)
        {
            MessageBoxHelper.Warn("该家族暂无可用解密工具。");
            return;
        }

        if (_downloadBtn != null) _downloadBtn.Enabled = false;

        var progress = new Progress<double>(p =>
        {
            if (_progressLabel != null && _progressLabel.IsHandleCreated)
            {
                Invoke(() => _progressLabel.Text = $"下载中... {p:F0}%");
            }
        });

        var toolPath = await _toolManager.DownloadToolAsync(family, progress);

        if (_downloadBtn != null) _downloadBtn.Enabled = true;

        if (!string.IsNullOrEmpty(toolPath))
        {
            MessageBoxHelper.Info($"工具下载成功！\n路径: {toolPath}");
        }
        else
        {
            MessageBoxHelper.Error("工具下载失败，请检查网络连接。");
        }

        _module?.RefreshIndex();
        BuildContent();
    }

    /// <summary>校验选中的工具</summary>
    private async void VerifySelectedTool()
    {
        if (_toolListView == null || _toolListView.SelectedItems.Count == 0 || _toolManager == null)
        {
            MessageBoxHelper.Warn("请先选择一个家族。");
            return;
        }

        var family = _toolListView.SelectedItems[0].Tag as RansomwareFamilyInfo;
        if (family == null || !family.HasDecryptor)
        {
            MessageBoxHelper.Warn("该家族暂无解密工具。");
            return;
        }

        var toolPath = _toolManager.GetToolPath(family.Family);
        if (!File.Exists(toolPath))
        {
            MessageBoxHelper.Warn("工具尚未下载，请先下载。");
            return;
        }

        var valid = await _toolManager.VerifyToolAsync(toolPath, family.DecryptorSha256);
        if (valid)
        {
            MessageBoxHelper.Info($"SHA256 校验通过！\n工具: {toolPath}");
        }
        else
        {
            MessageBoxHelper.Error("SHA256 校验失败！工具文件可能已被篡改，建议重新下载。");
        }
    }

    #endregion

    #region 标签页三：解密历史

    private void BuildHistoryTab(int y)
    {
        CreateSectionTitle("解密历史记录", 0, y);
        y += 30;

        var actionCard = CreateCard(0, y, ContentWidth, 50);

        var clearBtn = new AccentButton
        {
            Text = "清空历史",
            Location = new Point(16, 8),
            Size = new Size(120, 34)
        };
        clearBtn.Click += () =>
        {
            if (_decryptor == null) return;
            if (MessageBoxHelper.Confirm("确定要清空所有解密历史记录吗？"))
            {
                _decryptor.ClearHistory();
                BuildContent();
            }
        };
        actionCard.Controls.Add(clearBtn);

        y += 60;

        // 历史列表
        var listCard = CreateCard(0, y, ContentWidth, 400);

        _historyListView = new ListView
        {
            Location = new Point(8, 8),
            Size = new Size(ContentWidth - 16, 384),
            View = View.Details,
            FullRowSelect = true,
            GridLines = true,
            Font = Theme.SmallFont,
            BackColor = Theme.CardBg,
            ForeColor = Theme.TextPrimary,
            BorderStyle = BorderStyle.None
        };

        _historyListView.Columns.Add("时间", 140);
        _historyListView.Columns.Add("家族", 120);
        _historyListView.Columns.Add("文件数", 70);
        _historyListView.Columns.Add("成功数", 70);
        _historyListView.Columns.Add("失败数", 70);
        _historyListView.Columns.Add("耗时", 80);
        _historyListView.Columns.Add("结果", 60);

        LoadHistoryData();
        listCard.Controls.Add(_historyListView);

        y += 410;
        y += 20;
    }

    /// <summary>加载历史数据</summary>
    private void LoadHistoryData()
    {
        if (_historyListView == null || _decryptor == null) return;
        _historyListView.Items.Clear();

        var history = _decryptor.GetHistory();
        // 按时间倒序（最新在前）
        history.Reverse();

        foreach (var entry in history.Take(200))
        {
            var item = new ListViewItem(entry.Timestamp.ToString("yyyy-MM-dd HH:mm:ss"));
            item.SubItems.Add(entry.Family.ToString());
            item.SubItems.Add(entry.TotalFiles.ToString());
            item.SubItems.Add(entry.DecryptedFiles.ToString());
            item.SubItems.Add(entry.FailedFiles.ToString());
            item.SubItems.Add($"{entry.DurationSeconds:F1}s");
            item.SubItems.Add(entry.Success ? "成功" : "失败");

            item.ForeColor = entry.Success ? Theme.Success : (entry.DecryptedFiles > 0 ? Theme.Warning : Theme.Error);

            _historyListView.Items.Add(item);
        }

        if (_historyListView.Items.Count == 0)
        {
            var emptyItem = new ListViewItem("暂无解密历史记录");
            emptyItem.ForeColor = Theme.TextTertiary;
            _historyListView.Items.Add(emptyItem);
        }
    }

    #endregion

    #region 辅助方法

    /// <summary>格式化文件大小</summary>
    private static string FormatSize(long bytes)
    {
        return bytes switch
        {
            < 1024 => $"{bytes} B",
            < 1024 * 1024 => $"{bytes / 1024.0:F1} KB",
            < 1024 * 1024 * 1024 => $"{bytes / (1024.0 * 1024):F1} MB",
            _ => $"{bytes / (1024.0 * 1024 * 1024):F2} GB"
        };
    }

    #endregion

    public override void RefreshData()
    {
        BuildContent();
    }
}
