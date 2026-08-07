# ============================================================
# LightGuard 增量更新端到端测试脚本
# 模拟完整流程：v3.0.0 → v3.1.0
#   1. 构造模拟 v3.0.0 / v3.1.0 应用目录（含新增/修改/删除文件）
#   2. 调用真实 build-diff.ps1 生成差分包（update.zip + changelog.json + delete.list）
#   3. 调用真实 build-update-manifest.ps1 生成 update-manifest.json
#   4. 运行真实客户端代码（tests/IncrementalUpdateTest）执行 检查→下载→应用
#      HTTP 服务器由客户端进程自托管（System.Net.HttpListener），
#      避免 PowerShell 后台任务承载 HttpListener 不响应请求的问题
#   5. 逐文件哈希比对：应用后目录应与 v3.1.0 完全一致
#
# 用法（测试客户端引用 LightGuard 需 Windows）：
#   .\test-incremental-update.ps1
#   .\test-incremental-update.ps1 -Port 18888 -KeepOnFailure
# ============================================================
param(
    [int]$Port = 18887,
    [switch]$KeepOnFailure   # 失败时保留临时目录便于排查
)

$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$testRoot = Join-Path $root 'build\inc-test'
$oldDir = Join-Path $testRoot 'app-v3.0.0'
$newDir = Join-Path $testRoot 'app-v3.1.0'
$diffDir = Join-Path $testRoot 'diff'
$serverDir = Join-Path $testRoot 'server'
$applyDir = Join-Path $testRoot 'app-apply'      # 应用差分包的目标目录（v3.0.0 副本）
$workDir = Join-Path $testRoot 'client-work'
$manifestUrl = "http://127.0.0.1:$Port/update-manifest.json"

function Write-Step($msg) {
    Write-Host "`n==============================================" -ForegroundColor Cyan
    Write-Host " $msg" -ForegroundColor Cyan
    Write-Host "==============================================" -ForegroundColor Cyan
}

function New-TestFile($path, $content) {
    New-Item -ItemType Directory -Path (Split-Path $path) -Force | Out-Null
    [System.IO.File]::WriteAllText($path, $content)
}

function Assert-True($condition, $name) {
    if ($condition) {
        Write-Host "  [PASS] $name" -ForegroundColor Green
    } else {
        Write-Host "  [FAIL] $name" -ForegroundColor Red
        throw "断言失败: $name"
    }
}

# 带重试的文件哈希（客户端进程新写入的文件可能被本机杀软瞬时锁定）
function Get-HashWithRetry($file) {
    for ($i = 0; $i -lt 12; $i++) {
        try { return (Get-FileHash $file -Algorithm SHA256).Hash } catch {
            Start-Sleep -Milliseconds 500
        }
    }
    throw "无法读取文件哈希（持续被占用）: $file"
}

# 目录清理（使用 .NET API + 重试，规避 Remove-Item 回收站异常与瞬时文件锁）
function Remove-DirectoryForce($path) {
    if (-not (Test-Path $path)) { return }
    for ($i = 0; $i -lt 8; $i++) {
        try { [System.IO.Directory]::Delete($path, $true); return }
        catch { Start-Sleep -Milliseconds 1000 }
    }
    Write-Warning "清理目录失败（请手动删除）: $path"
}

try {
    # ==================== 0. 清理并准备目录 ====================
    Write-Step "准备测试目录"
    Remove-DirectoryForce $testRoot
    New-Item -ItemType Directory -Path $oldDir, $newDir, $serverDir -Force | Out-Null

    # ==================== 1. 构造模拟 v3.0.0 应用目录 ====================
    Write-Step "[1/6] 构造模拟 v3.0.0 应用目录"
    New-TestFile (Join-Path $oldDir 'LightGuard.exe') 'MZ-simulated-exe-v3.0.0'
    New-TestFile (Join-Path $oldDir 'LightGuard.dll') 'managed-dll-v3.0.0'
    New-TestFile (Join-Path $oldDir 'LightGuard.deps.json') '{"version":"3.0.0","deps":[]}'
    New-TestFile (Join-Path $oldDir 'LightGuard.runtimeconfig.json') '{"tfm":"net8.0","version":"3.0.0"}'
    New-TestFile (Join-Path $oldDir 'System.Management.dll') 'sys-manage-v3.0.0'
    New-TestFile (Join-Path $oldDir 'System.ServiceProcess.ServiceController.dll') 'sys-service-v3.0.0'
    New-TestFile (Join-Path $oldDir 'assets\lightguard.ico') 'icon-bytes-v3.0.0'
    New-TestFile (Join-Path $oldDir 'Resources\lang\lang_zh-CN.json') '{"name":"lightguard","lang":"zh-CN","v":"3.0.0"}'
    New-TestFile (Join-Path $oldDir 'Resources\lang\lang_en-US.json') '{"name":"lightguard","lang":"en-US","v":"3.0.0"}'
    New-TestFile (Join-Path $oldDir 'Resources\lang\lang_zh-TW.json') '{"name":"lightguard","lang":"zh-TW","v":"3.0.0"}'
    New-TestFile (Join-Path $oldDir 'Decryption\DecryptionToolIndex.json') '{"version":1,"families":[]}'
    Write-Host "  已创建 v3.0.0 文件: $((Get-ChildItem $oldDir -Recurse -File).Count) 个"

    # ==================== 2. 构造模拟 v3.1.0 应用目录 ====================
    Write-Step "[2/6] 构造模拟 v3.1.0 应用目录（修改 5 / 新增 2 / 删除 2）"
    # 修改（内容变化）
    New-TestFile (Join-Path $newDir 'LightGuard.exe') 'MZ-simulated-exe-v3.1.0'
    New-TestFile (Join-Path $newDir 'LightGuard.dll') 'managed-dll-v3.1.0'
    New-TestFile (Join-Path $newDir 'LightGuard.deps.json') '{"version":"3.1.0","deps":["defender-integration"]}'
    New-TestFile (Join-Path $newDir 'LightGuard.runtimeconfig.json') '{"tfm":"net8.0","version":"3.1.0"}'
    New-TestFile (Join-Path $newDir 'Resources\lang\lang_zh-CN.json') '{"name":"lightguard","lang":"zh-CN","v":"3.1.0"}'
    # 新增
    New-TestFile (Join-Path $newDir 'NEW_FILE.txt') 'incremental-update-added-file-v3.1.0'
    New-TestFile (Join-Path $newDir 'Resources\adblock\rules.json') '{"rules":["ads.example.com"]}'
    # 未变（沿用 v3.0.0 内容）
    foreach ($keep in @(
        'System.Management.dll',
        'System.ServiceProcess.ServiceController.dll',
        'Resources\lang\lang_en-US.json',
        'Decryption\DecryptionToolIndex.json')) {
        $src = Join-Path $oldDir $keep
        $dest = Join-Path $newDir $keep
        New-Item -ItemType Directory -Path (Split-Path $dest) -Force | Out-Null
        [System.IO.File]::Copy($src, $dest, $true)
    }
    # 删除：assets\lightguard.ico、Resources\lang\lang_zh-TW.json（不复制）
    Write-Host "  已创建 v3.1.0 文件: $((Get-ChildItem $newDir -Recurse -File).Count) 个（v3.0.0 为 $((Get-ChildItem $oldDir -Recurse -File).Count) 个）"

    # ==================== 3. 生成差分包 ====================
    Write-Step "[3/6] 生成差分包（build-diff.ps1）"
    & (Join-Path $PSScriptRoot 'build-diff.ps1') -OldDir $oldDir -NewDir $newDir -OutDir $diffDir | Out-Null
    Assert-True (Test-Path (Join-Path $diffDir 'update.zip')) 'update.zip 已生成'
    Assert-True (Test-Path (Join-Path $diffDir 'changelog.json')) 'changelog.json 已生成'
    Assert-True (Test-Path (Join-Path $diffDir 'delete.list')) 'delete.list 已生成'

    $changelog = Get-Content (Join-Path $diffDir 'changelog.json') -Raw -Encoding UTF8 | ConvertFrom-Json
    $added = @($changelog.added).Count
    $modified = @($changelog.modified).Count
    $deleted = @($changelog.deleted).Count
    Assert-True ($added -eq 2) "新增文件数=2（实际 $added）"
    Assert-True ($modified -eq 5) "修改文件数=5（实际 $modified）"
    Assert-True ($deleted -eq 2) "删除文件数=2（实际 $deleted）"

    # ==================== 4. 生成更新清单 ====================
    Write-Step "[4/6] 生成 update-manifest.json（build-update-manifest.ps1）"
    & (Join-Path $PSScriptRoot 'build-update-manifest.ps1') `
        -DiffDir $diffDir `
        -TargetVersion '3.1.0' `
        -BaseVersion '3.0.0' `
        -DownloadBaseUrl "http://127.0.0.1:$Port" `
        -ReleaseNotes '增量更新端到端测试' | Out-Null

    $manifestPath = Join-Path $diffDir 'update-manifest.json'
    Assert-True (Test-Path $manifestPath) 'update-manifest.json 已生成'
    $manifest = Get-Content $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
    Assert-True ($manifest.version -eq '3.1.0') "清单版本=3.1.0（实际 $($manifest.version)）"
    Assert-True ($manifest.baseVersion -eq '3.0.0') "基准版本=3.0.0（实际 $($manifest.baseVersion)）"

    # 部署到服务器目录
    Copy-Item (Join-Path $diffDir 'update.zip') $serverDir -Force
    Copy-Item $manifestPath $serverDir -Force

    # ==================== 5. 运行真实客户端 ====================
    Write-Step "[5/6] 运行真实客户端（自托管 HTTP 服务器 + 真实 IncrementalUpdateService）"
    # HTTP 服务器由客户端在自身进程内启动（System.Net.HttpListener），
    # 避免 PowerShell 后台任务承载 HttpListener 不响应请求的问题。

    # 准备应用目标目录（v3.0.0 的副本，模拟已安装的旧版本）
    New-Item -ItemType Directory -Path $applyDir -Force | Out-Null
    Get-ChildItem $oldDir -Recurse -File | ForEach-Object {
        $rel = $_.FullName.Substring($oldDir.Length).TrimStart('\')
        $dest = Join-Path $applyDir $rel
        New-Item -ItemType Directory -Path (Split-Path $dest) -Force | Out-Null
        [System.IO.File]::Copy($_.FullName, $dest, $true)
    }

    # 编译并运行客户端（引用真实 LightGuard 代码）
    Write-Host "`n正在编译并运行测试客户端（引用真实 IncrementalUpdateService）..."
    $proj = Join-Path $root 'tests\IncrementalUpdateTest\IncrementalUpdateTest.csproj'
    & dotnet run --project $proj -c Release -- $manifestUrl $applyDir $workDir '3.1.0' $serverDir $Port
    if ($LASTEXITCODE -ne 0) {
        throw "测试客户端执行失败，退出码 $LASTEXITCODE"
    }

    # ==================== 6. 逐文件验证应用结果 ====================
    Write-Step "[6/6] 逐文件验证：应用后目录应与 v3.1.0 完全一致"
    $mismatch = 0
    $checked = 0

    # 1) 应用目录应包含 v3.1.0 的所有文件且内容一致
    Get-ChildItem $newDir -Recurse -File | ForEach-Object {
        $rel = $_.FullName.Substring($newDir.Length).TrimStart('\')
        $applied = Join-Path $applyDir $rel
        if (-not (Test-Path $applied)) {
            Write-Host "  [FAIL] 缺失文件: $rel" -ForegroundColor Red
            $mismatch++
            return
        }
        $h1 = (Get-FileHash $_.FullName -Algorithm SHA256).Hash
        $h2 = Get-HashWithRetry $applied
        $checked++
        if ($h1 -ne $h2) {
            Write-Host "  [FAIL] 内容不一致: $rel" -ForegroundColor Red
            $mismatch++
        }
    }

    # 2) 已删除的文件不应存在
    @('assets\lightguard.ico', 'Resources\lang\lang_zh-TW.json') | ForEach-Object {
        if (Test-Path (Join-Path $applyDir $_)) {
            Write-Host "  [FAIL] 应删除但仍存在: $_" -ForegroundColor Red
            $mismatch++
        }
    }

    # 3) 备份目录应存在（可回滚）
    $backupDir = Get-ChildItem $workDir -Recurse -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -eq '3.1.0' } | Select-Object -First 1
    Assert-True ($null -ne $backupDir) '备份目录已创建（支持回滚）'

    Assert-True ($mismatch -eq 0) "所有文件一致（校验 $checked 个文件）"

    # ==================== 汇总 ====================
    Write-Host "`n==============================================" -ForegroundColor Green
    Write-Host " 端到端测试全部通过：v3.0.0 → v3.1.0 增量更新验证成功" -ForegroundColor Green
    Write-Host "==============================================" -ForegroundColor Green
    Write-Host "  测试目录: $testRoot"
    Write-Host "  差分包:   $diffDir\update.zip"
    Write-Host "  清单:     $diffDir\update-manifest.json"
    Write-Host "  客户端工作目录: $workDir"

    if (-not $KeepOnFailure) {
        Write-Host "`n清理测试临时目录（-KeepOnFailure 可保留）..."
        Remove-DirectoryForce $testRoot
    }
    exit 0
}
catch {
    Write-Host "`n[错误] $($_.Exception.Message)" -ForegroundColor Red
    if (-not $KeepOnFailure) {
        Write-Host "测试临时目录已保留在 $testRoot 便于排查（-KeepOnFailure 等价）"
    }
    exit 1
}
finally {
    # HTTP 服务器由测试客户端进程托管，此处无需清理
}
