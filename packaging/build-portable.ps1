# ============================================================
# LightGuard 绿色便携版打包脚本（P1-1 双版本分发架构 - B版）
#
# 特性：
#   - 单 EXE 免安装即开即用
#   - framework-dependent 单文件（约 1.6MB，目标机需 .NET 8 Desktop Runtime）
#   - 可选 -SelfContained 生成自包含完整版（免运行时，>20MB）
#   - 自动剔除冗余资源（服务器版仅保留英文语言包）
#   - 外置 Resources 资源包（语言包/解密索引），不内嵌 EXE
#   - 输出 .zip 便于 U 盘分发
#
# 用法：
#   .\build-portable.ps1                 # 客户端便携版（framework-dependent）
#   .\build-portable.ps1 -Edition Server # 服务器精简版
#   .\build-portable.ps1 -SelfContained  # 自包含完整版（免运行时）
#   .\build-portable.ps1 -Rid win-arm64  # 指定架构
# ============================================================
param(
    [ValidateSet('Client', 'Server')][string]$Edition = 'Client',
    [ValidateSet('win-x64', 'win-x86', 'win-arm64')][string]$Rid = 'win-x64',
    [switch]$SelfContained,
    [string]$OutputDir = ''
)

$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$csproj = Join-Path $root 'src\LightGuard\LightGuard.csproj'
$common = Join-Path $PSScriptRoot 'packaging-common.ps1'
. $common

$version = Get-VersionFromCsproj $csproj
$numVersion = Get-NormalizedVersion $version

if ([string]::IsNullOrEmpty($OutputDir)) {
    $OutputDir = Join-Path $root 'dist'
}
$staging = Join-Path $root 'build\portable-staging'
$exeName = "LightGuard-portable-${numVersion}-${Rid}.exe"
$zipName = "LightGuard-portable-${numVersion}-${Rid}.zip"
$mode = if ($SelfContained) { '自包含（免运行时）' } else { 'framework-dependent（需 .NET 8 Desktop Runtime）' }

Write-Host "==============================================" -ForegroundColor Cyan
Write-Host " LightGuard 便携版打包 v${numVersion} [$Edition / ${Rid}]" -ForegroundColor Cyan
Write-Host " 模式: $mode" -ForegroundColor Cyan
Write-Host "==============================================" -ForegroundColor Cyan

# ---- 1. 清理并发布 ----
Clear-Directory $staging
New-Item -ItemType Directory -Path $staging -Force | Out-Null

$publishArgs = @(
    'publish', $csproj,
    '-c', 'Release',
    '-r', $Rid,
    '-o', $staging,
    '-p:PublishSingleFile=true',
    '-p:IncludeNativeLibrariesForSelfExtract=true'
)

if ($SelfContained) {
    $publishArgs += @('-p:SelfContained=true', '-p:EnableCompressionInSingleFile=true')
}
else {
    # framework-dependent：单文件压缩仅支持自包含，需关闭
    $publishArgs += @('-p:SelfContained=false', '-p:EnableCompressionInSingleFile=false')
}

Write-Host "`n[1/4] dotnet publish (single-file) ..."
& dotnet $publishArgs --nologo -v q
if ($LASTEXITCODE -ne 0) { throw "dotnet publish 失败，退出码 $LASTEXITCODE" }

# ---- 2. 精简资源（按版本） ----
Write-Host "`n[2/4] 精简外部资源 (Edition=$Edition) ..."
Apply-EditionTrim -StagingDir $staging -Edition $Edition

# ---- 3. 重命名 EXE 并打包 ----
Write-Host "`n[3/4] 生成发布产物 ..."
New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null

$srcExe = Join-Path $staging 'LightGuard.exe'
$dstExe = Join-Path $staging $exeName
if (Test-Path $srcExe) {
    [System.IO.File]::Copy($srcExe, $dstExe, $true)
    Remove-Item $srcExe -Force
    # 便携版不携带 pdb
    $pdb = Join-Path $staging 'LightGuard.pdb'
    if (Test-Path $pdb) { Remove-Item $pdb -Force }
}

$zipPath = Join-Path $OutputDir $zipName
New-ZipPackage -SourceDir $staging -ZipPath $zipPath -EntryRootName 'LightGuard-portable'

# ---- 4. 输出结果 ----
Write-Host "`n[4/4] 打包完成" -ForegroundColor Green
Write-Host "  EXE: $dstExe ($(Get-FileSizeMB $dstExe) MB)"
Write-Host "  目录内容:"
Get-ChildItem $staging -Recurse -File | ForEach-Object {
    Write-Host "    $($_.FullName.Substring($staging.Length)) ($([math]::Round($_.Length/1KB,1)) KB)"
}
Write-Host "  Zip: $zipPath ($(Get-FileSizeMB $zipPath) MB)"
$totalMB = Get-DirectorySizeMB $staging
Write-Host "  总大小: $totalMB MB"

if (-not $SelfContained) {
    Write-Host "`n  ⚠ framework-dependent 版需目标机安装 .NET 8 Desktop Runtime：" -ForegroundColor Yellow
    Write-Host "    https://dotnet.microsoft.com/download/dotnet/8.0" -ForegroundColor Yellow
}
