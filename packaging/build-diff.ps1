# ============================================================
# LightGuard 增量差分更新包生成脚本（P1-1 双版本分发架构）
#
# 对比新旧版本发布目录，仅打包变更文件，生成：
#   - changelog.json  变更清单（新增/修改/删除/未变）
#   - update.zip      仅含新增+修改文件的差分包
#   - delete.list     需要删除的旧文件清单
#
# 用法：
#   .\build-diff.ps1 -OldDir .\dist\v3.0.0 -NewDir .\dist\v3.1.0 -OutDir .\dist\diff
# ============================================================
param(
    [Parameter(Mandatory)][string]$OldDir,
    [Parameter(Mandatory)][string]$NewDir,
    [string]$OutDir = ''
)

$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
if ([string]::IsNullOrEmpty($OutDir)) {
    $OutDir = Join-Path $root 'dist\diff'
}

if (-not (Test-Path $OldDir)) { throw "旧版本目录不存在: $OldDir" }
if (-not (Test-Path $NewDir)) { throw "新版本目录不存在: $NewDir" }

# 计算目录内所有文件的相对路径 + 哈希
function Get-FileHashMap {
    param([string]$Dir)
    $map = @{}
    $base = (Resolve-Path $Dir).Path
    foreach ($f in Get-ChildItem $Dir -Recurse -File) {
        $rel = $f.FullName.Substring($base.Length).TrimStart('\', '/')
        $hash = (Get-FileHash $f.FullName -Algorithm SHA256).Hash
        $map[$rel] = $hash
    }
    return $map
}

Write-Host "==============================================" -ForegroundColor Cyan
Write-Host " LightGuard 增量差分更新包生成" -ForegroundColor Cyan
Write-Host "  旧版: $OldDir"
Write-Host "  新版: $NewDir"
Write-Host "  输出: $OutDir"
Write-Host "==============================================" -ForegroundColor Cyan

Write-Host "`n[1/3] 计算文件哈希 ..."
$oldMap = Get-FileHashMap $OldDir
$newMap = Get-FileHashMap $NewDir
Write-Host "  旧版文件数: $($oldMap.Count) | 新版文件数: $($newMap.Count)"

Write-Host "`n[2/3] 对比变更 ..."
$added = @()      # 新增
$modified = @()   # 修改
$deleted = @()    # 删除
$unchanged = 0

foreach ($rel in $newMap.Keys) {
    if (-not $oldMap.ContainsKey($rel)) {
        $added += $rel
    }
    elseif ($oldMap[$rel] -ne $newMap[$rel]) {
        $modified += $rel
    }
    else {
        $unchanged++
    }
}

foreach ($rel in $oldMap.Keys) {
    if (-not $newMap.ContainsKey($rel)) {
        $deleted += $rel
    }
}

Write-Host "  新增: $($added.Count) | 修改: $($modified.Count) | 删除: $($deleted.Count) | 未变: $unchanged"

if (($added.Count + $modified.Count + $deleted.Count) -eq 0) {
    Write-Host "`n两版本完全一致，无需生成差分包。" -ForegroundColor Green
    exit 0
}

Write-Host "`n[3/3] 生成差分包 ..."
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null

# 1. 打包变更文件（新增 + 修改）
$updateRoot = Join-Path $OutDir 'update_root'
if (Test-Path $updateRoot) { Remove-Item $updateRoot -Recurse -Force }
$updateFiles = $added + $modified
$newBase = (Resolve-Path $NewDir).Path

foreach ($rel in $updateFiles) {
    $src = Join-Path $newBase $rel
    $dst = Join-Path $updateRoot $rel
    New-Item -ItemType Directory -Path (Split-Path $dst) -Force | Out-Null
    [System.IO.File]::Copy($src, $dst, $true)
}

$zipPath = Join-Path $OutDir 'update.zip'
if (Test-Path $zipPath) { Remove-Item $zipPath -Force }
if ($updateFiles.Count -gt 0) {
    Compress-Archive -Path (Join-Path $updateRoot '*') -DestinationPath $zipPath -CompressionLevel Optimal
}

# 2. 生成变更清单 JSON
$changelog = [ordered]@{
    generatedAt = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
    added = $added
    modified = $modified
    deleted = $deleted
    totalChanged = $added.Count + $modified.Count + $deleted.Count
}
$changelog | ConvertTo-Json -Depth 3 | Set-Content (Join-Path $OutDir 'changelog.json') -Encoding UTF8

# 3. 生成删除清单
$deleted | Set-Content (Join-Path $OutDir 'delete.list') -Encoding UTF8

Write-Host "`n============ 差分更新包生成完成 ============" -ForegroundColor Green
Write-Host "  变更文件: $($updateFiles.Count) 个"
Write-Host "  差分包: $zipPath ($([math]::Round((Get-Item $zipPath).Length/1KB,1)) KB)"
Write-Host "  变更清单: $(Join-Path $OutDir 'changelog.json')"
Write-Host "  删除清单: $(Join-Path $OutDir 'delete.list')"
