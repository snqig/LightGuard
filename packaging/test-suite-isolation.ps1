# ============================================================
# LightGuard 商业软件联网隔离 - 本地调试/验证脚本
# 验证核心原则：
#   1. 只创建「出站阻止」规则（绝不创建入站阻止，保护 127.0.0.1 本地 IPC）
#   2. 规则统一前缀命名，可按前缀一键批量清除，不污染用户防火墙
#   3. 扫描逻辑：递归目录 + 环境变量展开 + 跳过 0 字节 + 排除指定 exe
#   4. hosts 标记块增删（只删本工具标记行，不清空整个 hosts）
#
# 用法（创建防火墙规则需要管理员权限）：
#   .\test-suite-isolation.ps1                 # 临时目录模拟测试（推荐，不触碰真实软件）
#   .\test-suite-isolation.ps1 -UseRealDirs    # 追加扫描真实安装目录（需已安装 Adobe/CorelDRAW）
# ============================================================
param(
    [switch]$UseRealDirs,       # 追加扫描真实安装目录
    [switch]$KeepOnFailure      # 失败/完成时保留临时文件
)

$ErrorActionPreference = 'Stop'
$suitePrefixes = @('LightGuard-Suite-Adobe-', 'LightGuard-Suite-Corel-')
$testRoot = Join-Path $env:TEMP 'lg-suite-test'
$failed = 0
$passed = 0

function Write-Step($msg) {
    Write-Host "`n==============================================" -ForegroundColor Cyan
    Write-Host " $msg" -ForegroundColor Cyan
    Write-Host "==============================================" -ForegroundColor Cyan
}

function Assert-True($condition, $name) {
    if ($condition) {
        $script:passed++
        Write-Host "  [PASS] $name" -ForegroundColor Green
    } else {
        $script:failed++
        Write-Host "  [FAIL] $name" -ForegroundColor Red
    }
}

function New-TestFile($path, $content) {
    New-Item -ItemType Directory -Path (Split-Path $path) -Force | Out-Null
    [System.IO.File]::WriteAllText($path, $content)
}

# ===== 与 C# SuiteIsolationService.ComputeShortHash 一致的路径短哈希 =====
function Get-PathShortHash([string]$path) {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($path.ToLowerInvariant())
        $hash = ([BitConverter]::ToString($sha.ComputeHash($bytes)) -replace '-', '').Substring(0, 10).ToLowerInvariant()
        return $hash
    } finally { $sha.Dispose() }
}

# ===== 与 C# SuiteIsolationService.ScanExecutables 一致的扫描逻辑 =====
function Get-SuiteExes([string[]]$ScanDirs, [string[]]$ExcludeExe) {
    $exes = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $exclude = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($e in $ExcludeExe) { [void]$exclude.Add($e) }

    foreach ($template in $ScanDirs) {
        $dir = [System.Environment]::ExpandEnvironmentVariables($template)
        if ([string]::IsNullOrWhiteSpace($dir) -or -not (Test-Path $dir)) { continue }
        Get-ChildItem -Path $dir -Filter '*.exe' -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object {
            if ($_.Length -eq 0) { return }
            if ($exclude.Contains($_.Name)) { return }
            [void]$exes.Add($_.FullName)
        }
    }
    return $exes | Sort-Object
}

try {
    # ==================== 0. 权限检查 ====================
    Write-Step "[0/5] 环境检查"
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if ($isAdmin) {
        Write-Host "  [PASS] 当前以管理员身份运行" -ForegroundColor Green
    } else {
        Write-Host "  [WARN] 非管理员：防火墙规则增删验证将跳过（请以管理员身份运行本脚本进行完整验证）" -ForegroundColor Yellow
    }

    # ==================== 1. 构造模拟套件目录 ====================
    Write-Step "[1/5] 构造模拟 Adobe/CorelDRAW 目录（含 0 字节、子目录、排除项）"
    if (Test-Path $testRoot) { [System.IO.Directory]::Delete($testRoot, $true) }

    # 模拟 Adobe
    New-TestFile (Join-Path $testRoot 'Program Files\Adobe\Photoshop 2026\Photoshop.exe') 'fake'
    New-TestFile (Join-Path $testRoot 'Program Files\Adobe\Photoshop 2026\Bridge.exe') 'fake'
    New-TestFile (Join-Path $testRoot 'Program Files (x86)\Adobe\Common\Helper.exe') 'fake'
    New-TestFile (Join-Path $testRoot 'Program Files (x86)\Adobe\Common\zero.exe') ''  # 0 字节应被跳过

    # 模拟 CorelDRAW
    New-TestFile (Join-Path $testRoot 'Program Files\CorelDRAW Graphics Suite 2024\Programs\CorelDRW.exe') 'fake'
    New-TestFile (Join-Path $testRoot 'Program Files\CorelDRAW Graphics Suite 2024\Programs\PHOTO-PAINT.exe') 'fake'
    New-TestFile (Join-Path $testRoot 'Program Files\CorelDRAW Graphics Suite 2024\Programs\Capture.exe') 'fake'
    New-TestFile (Join-Path $testRoot 'Program Files\CorelDRAW Graphics Suite 2024\Programs\CorelFontManager.exe') 'fake'
    New-TestFile (Join-Path $testRoot 'Program Files\Corel\Corel Update\UpdateHelper.exe') 'fake'
    Write-Host "  模拟目录已创建: $testRoot"

    # ==================== 2. 验证扫描逻辑 ====================
    Write-Step "[2/5] 验证扫描逻辑（环境变量展开 + 递归 + 过滤）"
    $scanDirs = @(
        (Join-Path $testRoot 'Program Files'),
        (Join-Path $testRoot 'Program Files (x86)')
    )
    $adobeExes = Get-SuiteExes -ScanDirs $scanDirs -ExcludeExe @()
    Assert-True ($adobeExes.Count -eq 8) "扫描到 8 个非空 exe（实际 $($adobeExes.Count)；0 字节 zero.exe 已跳过）"

    $withExclude = Get-SuiteExes -ScanDirs $scanDirs -ExcludeExe @('Bridge.exe', 'Capture.exe')
    Assert-True ($withExclude.Count -eq 6) "排除 Bridge.exe/Capture.exe 后剩 6 个（实际 $($withExclude.Count)）"

    # 环境变量展开验证
    $env:TEST_LG_DIR = Join-Path $testRoot 'Program Files (x86)'
    $envExes = Get-SuiteExes -ScanDirs @('%TEST_LG_DIR%') -ExcludeExe @()
    Assert-True ($envExes.Count -ge 1) '环境变量 %TEST_LG_DIR% 展开成功'

    # ==================== 3. 创建出站阻断规则 ====================
    Write-Step "[3/5] 创建「仅出站」阻断规则（模拟服务端命名方案）"
    if (-not $isAdmin) {
        Write-Host "  [SKIP] 非管理员，跳过防火墙规则创建验证（请以管理员身份运行）" -ForegroundColor Yellow
    } else {
        $createdCount = 0
        foreach ($exe in $adobeExes) {
            $name = "LightGuard-Suite-Adobe-" + (Get-PathShortHash $exe)
            New-NetFirewallRule -DisplayName $name -Direction Outbound -Program $exe -Action Block -Profile Any -Enabled True | Out-Null
            $createdCount++
        }
        Assert-True ($createdCount -eq 8) "创建 8 条出站阻断规则（实际 $createdCount）"

        $rules = @(Get-NetFirewallRule -DisplayName 'LightGuard-Suite-Adobe-*' -ErrorAction SilentlyContinue)
        Assert-True ($rules.Count -eq 8) "按前缀查询到 8 条规则（实际 $($rules.Count)）"
        $outboundOnly = @($rules | Where-Object { $_.Direction -eq 'Outbound' -and $_.Action -eq 'Block' })
        Assert-True ($outboundOnly.Count -eq $rules.Count) '全部为 Outbound + Block（无入站规则）'
        $inbound = @($rules | Where-Object { $_.Direction -eq 'Inbound' })
        Assert-True ($inbound.Count -eq 0) '未创建任何入站规则（保护 127.0.0.1 本地 IPC）'
        if ($rules.Count -gt 0) {
            Write-Host "  示例规则: $($rules[0].DisplayName) | $($rules[0].Direction) | $($rules[0].Action)"
        }
    }

    # ==================== 4. 批量清除规则 ====================
    Write-Step "[4/5] 按前缀批量清除规则"
    if ($isAdmin) {
        Get-NetFirewallRule -DisplayName 'LightGuard-Suite-Adobe-*' -ErrorAction SilentlyContinue | Remove-NetFirewallRule
        $remaining = @(Get-NetFirewallRule -DisplayName 'LightGuard-Suite-Adobe-*' -ErrorAction SilentlyContinue)
        Assert-True ($remaining.Count -eq 0) "前缀规则已全部清除（剩余 $($remaining.Count)）"
    } else {
        Write-Host "  [SKIP] 非管理员，跳过防火墙规则清除验证" -ForegroundColor Yellow
    }

    # ==================== 5. hosts 标记块增删（临时文件模拟） ====================
    Write-Step "[5/5] hosts 标记块增删验证（临时文件模拟，不触碰真实 hosts）"
    $hostsFile = Join-Path $testRoot 'hosts.sim'
    [System.IO.File]::WriteAllText($hostsFile, "127.0.0.1 localhost`n`n# user own line`n", [System.Text.Encoding]::UTF8)
    $startMarker = '# LightGuard Suite Block Start '
    $endMarker = '# LightGuard Suite Block End '

    # 追加标记块
    $domains = @('activation.corel.com', 'update.corel.com')
    $lines = [System.Collections.Generic.List[string]]::new([System.IO.File]::ReadAllLines($hostsFile))
    $lines.Add("$startMarker`coreldraw")
    foreach ($d in $domains) { $lines.Add("127.0.0.1 $d"); $lines.Add("::1 $d") }
    $lines.Add("$endMarker`coreldraw")
    [System.IO.File]::WriteAllLines($hostsFile, $lines)

    $after = [System.IO.File]::ReadAllLines($hostsFile)
    $blockLines = @($after | Where-Object { $_ -like '*127.0.0.1 activation.corel.com*' -or $_ -like '*::1 update.corel.com*' })
    Assert-True ($blockLines.Count -eq 2) "hosts 标记块已追加（$($blockLines.Count) 条域名行）"
    Assert-True (@($after | Where-Object { $_ -eq '# user own line' }).Count -eq 1) '用户原有 hosts 行未被改动'

    # 移除标记块（只删本工具标记行）
    $startIdx = -1; $endIdx = -1
    for ($i = 0; $i -lt $after.Count; $i++) {
        $t = $after[$i].Trim()
        if ($startIdx -lt 0 -and $t -eq "$startMarker`coreldraw") { $startIdx = $i }
        elseif ($startIdx -ge 0 -and $t -eq "$endMarker`coreldraw") { $endIdx = $i; break }
    }
    if ($startIdx -ge 0) {
        if ($endIdx -lt 0) { $endIdx = $after.Count - 1 }
        $remainingLines = @($after[0..($startIdx - 1)]) + @($after[($endIdx + 1)..($after.Count - 1)])
        [System.IO.File]::WriteAllLines($hostsFile, $remainingLines)
    }
    $final = [System.IO.File]::ReadAllLines($hostsFile)
    $stillThere = @($final | Where-Object { $_ -like '*corel.com*' })
    Assert-True ($stillThere.Count -eq 0) "hosts 标记块已清除（剩余 $($stillThere.Count) 条）"
    Assert-True (@($final | Where-Object { $_ -eq '# user own line' }).Count -eq 1) '清除后用户原有行保留'

    # ==================== 可选：真实目录扫描 ====================
    if ($UseRealDirs) {
        Write-Step "[附加] 扫描真实安装目录"
        foreach ($dir in @('C:\Program Files\Adobe', 'C:\Program Files\Corel', 'C:\Program Files\CorelDRAW Graphics Suite', 'C:\Program Files (x86)\Adobe')) {
            if (Test-Path $dir) {
                $count = (Get-ChildItem -Path $dir -Filter '*.exe' -Recurse -File -ErrorAction SilentlyContinue | Where-Object { $_.Length -gt 0 }).Count
                Write-Host "  [INFO] $dir → $count 个可执行文件"
            }
        }
    }

    # ==================== 汇总 ====================
    Write-Host "`n==============================================" -ForegroundColor Green
    if ($failed -eq 0) {
        Write-Host " 网络隔离逻辑验证全部通过：$passed 通过 / $failed 失败" -ForegroundColor Green
    } else {
        Write-Host " 验证结果：$passed 通过 / $failed 失败" -ForegroundColor Red
    }
    Write-Host "==============================================" -ForegroundColor Green

    if (-not $KeepOnFailure) {
        Write-Host "`n清理临时目录（-KeepOnFailure 可保留）..."
        if (Test-Path $testRoot) { [System.IO.Directory]::Delete($testRoot, $true) }
    }
    exit $(if ($failed -eq 0) { 0 } else { 1 })
}
catch {
    Write-Host "`n[错误] $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
